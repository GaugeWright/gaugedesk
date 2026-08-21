//! Home identity/admission HTTP seam (`HOME-1`).
//!
//! Hosted compositions mount [`routes`] beside the work routes and apply
//! [`require_home_admission`] to the work router. `/home/admissions` performs
//! the target-admission act after authenticating the account identity; every
//! later work request must present both the account bearer and the minted Home
//! credential.

use axum::{
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    middleware::Next,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use gaugedesk_core::ids::AuthorityId;
use serde_json::json;

use crate::home_admission::{HomeAdmissionToken, HOME_ADMISSION_HEADER};
use crate::{net_http, LockUnpoisoned, SharedWorkbench};

pub fn routes() -> Router<SharedWorkbench> {
    Router::new()
        .route(
            "/home/admissions",
            post(post_admission).delete(delete_admission),
        )
        .route(
            "/home/invitations",
            post(crate::home_invitation::post_invitation),
        )
        .route(
            "/home/invitations/accept",
            post(crate::home_invitation::post_accept_invitation),
        )
}

async fn post_admission(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> axum::response::Response {
    let mut wb = wb.lock_unpoisoned();
    let actor = match wb.admit_data_request(net_http::bearer(&headers), None) {
        Ok(actor) => AuthorityId::new(actor),
        Err((code, message)) => return (code, Json(json!({ "error": message }))).into_response(),
    };
    let home = wb.home_id().clone();
    let token = wb.home_admissions.open(home.clone(), actor);
    (
        StatusCode::CREATED,
        Json(json!({
            "home": home.as_str(),
            "admission": token.encode(),
        })),
    )
        .into_response()
}

async fn delete_admission(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> axum::response::Response {
    let Some(token) = admission_token(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "present the Home admission to revoke" })),
        )
            .into_response();
    };
    let mut wb = wb.lock_unpoisoned();
    let actor = match wb.admit_data_request(net_http::bearer(&headers), None) {
        Ok(actor) => AuthorityId::new(actor),
        Err((code, message)) => return (code, Json(json!({ "error": message }))).into_response(),
    };
    let home = wb.home_id().clone();
    if wb.home_admissions.authorize(&home, &actor, &token).is_err() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Home admission does not match this identity" })),
        )
            .into_response();
    }
    wb.home_admissions.revoke(&home, &actor);
    StatusCode::NO_CONTENT.into_response()
}

fn admission_token(headers: &HeaderMap) -> Option<HomeAdmissionToken> {
    headers
        .get(HOME_ADMISSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(HomeAdmissionToken::parse)
}

/// Require the target Home's admission credential on work routes. Health and
/// the admission ceremony are the only exemptions; a login bearer by itself is
/// deliberately insufficient (`HOME-1`).
pub async fn require_home_admission(
    State(wb): State<SharedWorkbench>,
    mut req: axum::extract::Request,
    next: Next,
) -> axum::response::Response {
    let path = req.uri().path();
    if req.method() == Method::OPTIONS
        || path == "/health"
        || path == "/home/admissions"
        || path == "/home/invitations/accept"
        || path == "/mobile/enrollment/claim"
        || path == "/mobile/enrollment/prove"
        || path == "/mobile/enrollment/status"
        || path == "/mobile/sessions/challenge"
        || path == "/mobile/sessions"
    {
        return next.run(req).await;
    }

    // ADR 0109: a proved, approved device may authenticate the exact same work
    // routes through its short-lived Machine session. This is an alternative to
    // account-bearer + Home admission, not a parallel mobile API.
    if !path.starts_with("/mobile/")
        && !path.starts_with("/account/")
        && !path.starts_with("/auth/")
        && !path.starts_with("/home/")
    {
        if let Some(session) = crate::mobile_machine_session::session_token(req.headers()) {
            let grant = {
                let mut wb = wb.lock_unpoisoned();
                crate::mobile_machine_session::authorize_session(&mut wb, session)
            };
            if let Some(grant) = grant {
                req.extensions_mut()
                    .insert(crate::identity::AuthenticatedActor(AuthorityId::new(
                        grant.device.as_str(),
                    )));
                return next.run(req).await;
            }
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Machine controller session is expired or revoked" })),
            )
                .into_response();
        }
    }

    // A controller may revoke only its own exact durable grant. This is the one
    // controller-management command available to the phone itself; listing or
    // revoking any sibling grant remains an owner/Home-admitted operation.
    if req.method() == Method::POST {
        if let Some(grant_id) = path
            .strip_prefix("/mobile/controllers/")
            .and_then(|rest| rest.strip_suffix("/revoke"))
        {
            if let Some(session) = crate::mobile_machine_session::session_token(req.headers()) {
                let grant = {
                    let mut wb = wb.lock_unpoisoned();
                    crate::mobile_machine_session::authorize_session(&mut wb, session)
                };
                if let Some(grant) = grant.filter(|grant| grant.id == grant_id) {
                    req.extensions_mut()
                        .insert(crate::identity::AuthenticatedActor(AuthorityId::new(
                            grant.device.as_str(),
                        )));
                    return next.run(req).await;
                }
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "controller session cannot revoke this grant" })),
                )
                    .into_response();
            }
        }
    }

    let Some(token) = admission_token(req.headers()) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "target Home admission required" })),
        )
            .into_response();
    };
    let rejection = {
        let bearer = net_http::bearer(req.headers());
        let wb = wb.lock_unpoisoned();
        match wb.admit_data_request(bearer, None) {
            Err((code, message)) => Some((code, message)),
            Ok(actor) => {
                let actor = AuthorityId::new(actor);
                if wb
                    .home_admissions
                    .authorize(wb.home_id(), &actor, &token)
                    .is_err()
                {
                    Some((
                        StatusCode::FORBIDDEN,
                        "Home admission does not match this Home and identity",
                    ))
                } else if wb
                    .scope_project_of_path(req.uri().path())
                    .is_some_and(|project| !wb.owns_project(&project))
                {
                    Some((
                        StatusCode::MISDIRECTED_REQUEST,
                        "project is authoritative on another Home",
                    ))
                } else {
                    None
                }
            }
        }
    };
    if let Some((code, message)) = rejection {
        return (code, Json(json!({ "error": message }))).into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use gaugedesk_core::abac::AuthorityAttributes;
    use gaugedesk_core::ids::AuthorityId;

    use crate::identity::LoopbackIdentityProvider;
    use crate::library::{
        Admission, ChatRecord, InstanceKind, InstanceRecord, ProjectRecord, RecordOp,
        WorkstreamRecord,
    };
    use crate::org::{MembershipRecord, MembershipStatus, ORG_ID, ORG_SCOPE};
    use crate::{local_routes, open_workbench, LockUnpoisoned};

    async fn response(
        app: &Router,
        method: &str,
        uri: &str,
        bearer: Option<&str>,
        admission: Option<&str>,
    ) -> (StatusCode, String) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(bearer) = bearer {
            request = request.header("authorization", format!("Bearer {bearer}"));
        }
        if let Some(admission) = admission {
            request = request.header(HOME_ADMISSION_HEADER, admission);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn account_login_alone_cannot_call_home_work_routes() {
        let dir = tempfile::tempdir().unwrap();
        let wb = open_workbench(dir.path()).unwrap();
        {
            let mut guard = wb.lock_unpoisoned();
            guard.set_identity_provider(Some(Arc::new(LoopbackIdentityProvider::new().enroll(
                "alice-login",
                AuthorityId::new("alice"),
                AuthorityAttributes::default(),
            ))));
            let membership = MembershipRecord {
                id: "alice".into(),
                op: RecordOp::Upsert,
                org_id: ORG_ID.into(),
                authority: "alice".into(),
                email: "alice@example.test".into(),
                role: "owner".into(),
                status: MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            };
            guard
                .store_mut()
                .append_record(
                    ORG_SCOPE,
                    "membership",
                    &serde_json::to_string(&membership).unwrap(),
                )
                .unwrap();
        }
        let inspect = wb.clone();
        let app = Router::new()
            .merge(local_routes::routes(false))
            .merge(routes())
            .route_layer(axum::middleware::from_fn_with_state(
                wb.clone(),
                require_home_admission,
            ))
            .with_state(wb);

        let (status, _) = response(&app, "GET", "/workspace", Some("alice-login"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, body) =
            response(&app, "POST", "/home/admissions", Some("alice-login"), None).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let admission = serde_json::from_str::<serde_json::Value>(&body).unwrap()["admission"]
            .as_str()
            .unwrap()
            .to_string();

        let (status, _) = response(
            &app,
            "GET",
            "/workspace",
            Some("alice-login"),
            Some(&admission),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Home identity is already returned by the admission ceremony and the
        // relay runtime owns its locator directly. No production client used
        // these duplicate reads, so keep both former façades absent.
        for path in ["/home", "/home/relay-locator"] {
            let (status, body) =
                response(&app, "GET", path, Some("alice-login"), Some(&admission)).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "retired {path}: {body}");
        }

        let (status, _) = response(&app, "GET", "/workspace", None, Some(&admission)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        {
            let mut guard = inspect.lock_unpoisoned();
            guard.write_project_record(ProjectRecord {
                schema: crate::library::LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                id: "foreign".into(),
                op: RecordOp::Upsert,
                name: "Foreign".into(),
                is_default: false,
                home_id: gaugedesk_core::ids::HomeId::new("home:somewhere-else"),
                network_isolated: false,
                run_purpose: None,
                deployment_mode: None,
            });
            guard.write_instance_record(InstanceRecord {
                schema: crate::library::LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                id: "foreign-placement".into(),
                op: RecordOp::Upsert,
                kind: InstanceKind::Using,
                placement_kind: crate::library::PlacementKind::Work,
                agent_id: crate::DEFAULT_AGENT.into(),
                project_id: Some("foreign".into()),
                version: 1,
                admission: Admission::Active,
                collection_recipient: None,
            });
            guard.write_workstream_record(WorkstreamRecord {
                schema: crate::library::LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                id: "foreign-workstream".into(),
                op: RecordOp::Upsert,
                instance_id: "foreign-placement".into(),
                name: "Foreign line".into(),
                created_position: 0,
            });
            guard.write_chat_record(ChatRecord {
                schema: crate::library::LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                id: "foreign-chat".into(),
                op: RecordOp::Upsert,
                instance_id: "foreign-placement".into(),
                title: "Foreign chat".into(),
                created_position: 0,
                forked_from: None,
                forked_from_entry: None,
                forked_from_cut: None,
            });
        }
        let wrong_admission = "0".repeat(64);
        let (status, _) = response(
            &app,
            "GET",
            "/projects/foreign/home",
            Some("alice-login"),
            Some(&wrong_admission),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = response(
            &app,
            "GET",
            "/projects/foreign/home",
            Some("alice-login"),
            Some(&admission),
        )
        .await;
        assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);

        let (status, _) = response(
            &app,
            "POST",
            "/workstreams/foreign-workstream/archive",
            Some("alice-login"),
            Some(&wrong_admission),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = response(
            &app,
            "POST",
            "/workstreams/foreign-workstream/archive",
            Some("alice-login"),
            Some(&admission),
        )
        .await;
        assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);

        let (status, _) = response(
            &app,
            "DELETE",
            "/chats/foreign-chat",
            Some("alice-login"),
            Some(&wrong_admission),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = response(
            &app,
            "DELETE",
            "/chats/foreign-chat",
            Some("alice-login"),
            Some(&admission),
        )
        .await;
        assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    }
}
