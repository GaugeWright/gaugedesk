//! Ordinary person-to-project Home invitations (`HOME-4`, ADR 0084).
//!
//! This is deliberately not peer federation. A Home owner creates an opaque,
//! authority-bound capability for one project. The invited person authenticates
//! with their free account directly to that Home; acceptance atomically activates
//! the Home-local member and project grant, then mints the replaceable Home
//! admission used by ordinary work routes. The Hub receives only the resulting
//! opaque `{project, home_id, endpoint}` route from the browser.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use gaugewright_core::rbac::Capability;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::account::RecordOp;
use crate::org::{
    is_valid_role, MemberGrantRecord, MembershipRecord, MembershipStatus, Org, ORG_ID, ORG_SCOPE,
};
use crate::{library, net_http, LockUnpoisoned, SharedWorkbench};

const INVITATION_KIND: &str = "home_invitation";
const INVITATION_VERSION: u32 = 1;
const DEFAULT_TTL_SECS: u64 = 7 * 24 * 60 * 60;
const MAX_TTL_SECS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InvitationStatus {
    Pending,
    Accepted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HomeInvitationRecord {
    id: String,
    #[serde(default)]
    op: RecordOp,
    invited_authority: String,
    project: String,
    home_id: String,
    endpoint: String,
    role: String,
    expires_at: u64,
    token_sha256: String,
    status: InvitationStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InvitationEnvelope {
    version: u32,
    invitation: String,
    invited_authority: String,
    project: String,
    home_id: String,
    endpoint: String,
    secret: String,
}

#[derive(Deserialize)]
pub struct CreateInvitationBody {
    authority: String,
    project: String,
    #[serde(default = "member_role")]
    role: String,
    endpoint: String,
    #[serde(default)]
    expires_in_secs: Option<u64>,
}

fn member_role() -> String {
    "member".to_owned()
}

#[derive(Deserialize)]
pub struct AcceptInvitationBody {
    invite: String,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn token_hash(secret: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, secret.as_bytes());
    hex::encode(digest.as_ref())
}

fn encode_envelope(envelope: &InvitationEnvelope) -> Result<String, serde_json::Error> {
    serde_json::to_vec(envelope).map(hex::encode)
}

fn decode_envelope(encoded: &str) -> Option<InvitationEnvelope> {
    let bytes = hex::decode(encoded).ok()?;
    let envelope: InvitationEnvelope = serde_json::from_slice(&bytes).ok()?;
    (envelope.version == INVITATION_VERSION).then_some(envelope)
}

fn invitation_url(encoded: &str) -> String {
    let console = std::env::var("GAUGEWRIGHT_CONSOLE_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| "https://app.gaugewright.com".to_owned());
    format!("{}/invite?d={encoded}", console.trim_end_matches('/'))
}

fn latest_invitation(store: &gaugewright_store::Store, id: &str) -> Option<HomeInvitationRecord> {
    store
        .records(ORG_SCOPE, INVITATION_KIND)
        .ok()?
        .into_iter()
        .filter_map(|payload| serde_json::from_str::<HomeInvitationRecord>(&payload).ok())
        .rfind(|record| record.id == id)
}

fn json_error(status: StatusCode, message: &'static str) -> axum::response::Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// Owner/admin: mint and durably hash an authority-bound invitation. Membership
/// and project access remain unchanged until acceptance commits all three facts.
/// No content, project name, or provider credential leaves the Home.
pub async fn post_invitation(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<CreateInvitationBody>,
) -> axum::response::Response {
    if body.authority.trim().is_empty()
        || body.project.trim().is_empty()
        || !crate::account_routes::secure_home_endpoint(&body.endpoint)
        || !is_valid_role(&body.role)
        || matches!(body.role.as_str(), "owner" | "admin" | "billing")
    {
        return json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "valid invite fields required",
        );
    }
    let ttl = body.expires_in_secs.unwrap_or(DEFAULT_TTL_SECS);
    if ttl == 0 || ttl > MAX_TTL_SECS {
        return json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid invitation lifetime",
        );
    }

    let authority = body.authority.trim().to_owned();
    let mut wb = wb.lock_unpoisoned();
    if let Err((status, message)) =
        wb.authorize(net_http::bearer(&headers), Some(Capability::ManageMembers))
    {
        return json_error(status, message);
    }
    if !wb.owns_project(&body.project) {
        return json_error(StatusCode::NOT_FOUND, "project is not on this Home");
    }

    let id = library::gen_id("hinv");
    let secret = hex::encode(crate::session::random_bytes::<32>());
    let endpoint = body.endpoint.trim_end_matches('/').to_owned();
    let home_id = wb.home_id().as_str().to_owned();
    let record = HomeInvitationRecord {
        id: id.clone(),
        op: RecordOp::Upsert,
        invited_authority: authority.clone(),
        project: body.project.clone(),
        home_id: home_id.clone(),
        endpoint: endpoint.clone(),
        role: body.role.clone(),
        expires_at: now_secs().saturating_add(ttl),
        token_sha256: token_hash(&secret),
        status: InvitationStatus::Pending,
    };
    let record_json = serde_json::to_string(&record).expect("invitation serializes");
    if let Err(error) =
        wb.store_mut()
            .append_records_atomically(&[(ORG_SCOPE, INVITATION_KIND, &record_json)])
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("could not persist invitation: {error:?}") })),
        )
            .into_response();
    }
    let envelope = InvitationEnvelope {
        version: INVITATION_VERSION,
        invitation: id,
        invited_authority: authority,
        project: body.project,
        home_id,
        endpoint,
        secret,
    };
    let encoded = match encode_envelope(&envelope) {
        Ok(encoded) => encoded,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "could not encode invite"),
    };
    (
        StatusCode::CREATED,
        Json(json!({
            "invite": encoded,
            "url": invitation_url(&encoded),
            "home_id": envelope.home_id,
            "project": envelope.project,
            "endpoint": envelope.endpoint,
            "expires_at": record.expires_at,
        })),
    )
        .into_response()
}

/// Invitee: authenticate ordinary account identity, validate the exact
/// authority-bound capability, atomically activate membership+grant+invite, and
/// mint a replaceable Home session. Repeating a completed acceptance is
/// idempotent and mints a fresh session so a lost HTTP response is recoverable.
pub async fn post_accept_invitation(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<AcceptInvitationBody>,
) -> axum::response::Response {
    let Some(envelope) = decode_envelope(&body.invite) else {
        return json_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid Home invitation");
    };
    let mut wb = wb.lock_unpoisoned();
    let actor = match wb.authenticate_identity(net_http::bearer(&headers)) {
        Ok(actor) => actor,
        Err((status, message)) => return json_error(status, message),
    };
    let Some(record) = latest_invitation(wb.store_ref(), &envelope.invitation) else {
        return json_error(StatusCode::NOT_FOUND, "invitation is unknown");
    };
    let expected_hash = token_hash(&envelope.secret);
    // Comparing fixed-size SHA-256 digests leaks no useful prefix of the random
    // capability (the digest is not itself accepted and has 256-bit preimage work).
    let hash_matches = expected_hash == record.token_sha256;
    if !hash_matches
        || record.invited_authority != actor.as_str()
        || envelope.invited_authority != actor.as_str()
        || envelope.project != record.project
        || envelope.home_id != record.home_id
        || envelope.endpoint != record.endpoint
        || envelope.home_id != wb.home_id().as_str()
    {
        return json_error(
            StatusCode::FORBIDDEN,
            "invitation does not match this identity and Home",
        );
    }
    if record.status == InvitationStatus::Pending && record.expires_at <= now_secs() {
        return json_error(StatusCode::GONE, "invitation has expired");
    }
    if record.status == InvitationStatus::Pending {
        let mut accepted = record.clone();
        accepted.status = InvitationStatus::Accepted;
        let org = match Org::rebuild(wb.store_ref()) {
            Ok(org) => org,
            Err(_) => {
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "directory unavailable")
            }
        };
        // A project invitation must never demote an existing active owner/admin.
        // New people receive the invitation's narrow role; existing active people
        // retain their directory identity and gain only the explicit project grant.
        let member = org
            .member_by_authority(actor.as_str())
            .filter(|member| member.status == MembershipStatus::Active)
            .cloned()
            .unwrap_or_else(|| MembershipRecord {
                id: actor.as_str().to_owned(),
                op: RecordOp::Upsert,
                org_id: ORG_ID.to_owned(),
                authority: actor.as_str().to_owned(),
                email: String::new(),
                role: record.role.clone(),
                status: MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            });
        let grant = MemberGrantRecord {
            id: MemberGrantRecord::make_id(actor.as_str(), &record.project),
            op: RecordOp::Upsert,
            authority: actor.as_str().to_owned(),
            project_id: record.project.clone(),
        };
        let accepted_json = serde_json::to_string(&accepted).expect("invitation serializes");
        let member_json = serde_json::to_string(&member).expect("membership serializes");
        let grant_json = serde_json::to_string(&grant).expect("grant serializes");
        if let Err(error) = wb.store_mut().append_records_atomically(&[
            (ORG_SCOPE, INVITATION_KIND, &accepted_json),
            (ORG_SCOPE, "membership", &member_json),
            (ORG_SCOPE, "member_grant", &grant_json),
        ]) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("could not accept invitation: {error:?}") })),
            )
                .into_response();
        }
    }
    let home = wb.home_id().clone();
    let admission = wb.home_admissions.open(home.clone(), actor);
    (
        StatusCode::OK,
        Json(json!({
            "home_id": home.as_str(),
            "project": record.project,
            "endpoint": record.endpoint,
            "admission": admission.encode(),
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use axum::middleware;
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use gaugewright_core::abac::AuthorityAttributes;
    use gaugewright_core::ids::AuthorityId;

    use crate::home_admission::HOME_ADMISSION_HEADER;
    use crate::identity::LoopbackIdentityProvider;
    use crate::{home_routes, local_routes, open_workbench};

    async fn call(
        app: &Router,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        admission: Option<&str>,
        body: Option<&str>,
    ) -> (StatusCode, String) {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(bearer) = bearer {
            request = request.header("authorization", format!("Bearer {bearer}"));
        }
        if let Some(admission) = admission {
            request = request.header(HOME_ADMISSION_HEADER, admission);
        }
        if body.is_some() {
            request = request.header("content-type", "application/json");
        }
        let response = app
            .clone()
            .oneshot(
                request
                    .body(body.map_or_else(Body::empty, |value| Body::from(value.to_owned())))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[test]
    fn invitation_envelope_round_trips_and_rejects_garbage() {
        let envelope = InvitationEnvelope {
            version: INVITATION_VERSION,
            invitation: "hinv-1".to_owned(),
            invited_authority: "alice".to_owned(),
            project: "proj-1".to_owned(),
            home_id: "home:owner".to_owned(),
            endpoint: "https://home.example".to_owned(),
            secret: "redacted-capability".to_owned(),
        };
        let encoded = encode_envelope(&envelope).unwrap();
        let decoded = decode_envelope(&encoded).unwrap();
        assert_eq!(decoded.invitation, envelope.invitation);
        assert_eq!(decoded.home_id, envelope.home_id);
        assert!(decode_envelope("not-an-invite").is_none());
    }

    #[tokio::test]
    async fn free_account_accepts_on_owner_home_revokes_and_resumes_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let wb = open_workbench(dir.path()).unwrap();
        let owner = AuthorityId::new("owner");
        let invitee = AuthorityId::new("invitee");
        let owner_admission = {
            let mut guard = wb.lock_unpoisoned();
            guard.set_identity_provider(Some(Arc::new(
                LoopbackIdentityProvider::new()
                    .enroll("owner-login", owner.clone(), AuthorityAttributes::default())
                    .enroll(
                        "invitee-login",
                        invitee.clone(),
                        AuthorityAttributes::default(),
                    )
                    .enroll(
                        "wrong-login",
                        AuthorityId::new("wrong"),
                        AuthorityAttributes::default(),
                    ),
            )));
            let owner_member = MembershipRecord {
                id: owner.as_str().to_owned(),
                op: RecordOp::Upsert,
                org_id: ORG_ID.to_owned(),
                authority: owner.as_str().to_owned(),
                email: "owner@example.test".to_owned(),
                role: "owner".to_owned(),
                status: MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            };
            guard
                .store_mut()
                .append_record(
                    ORG_SCOPE,
                    "membership",
                    &serde_json::to_string(&owner_member).unwrap(),
                )
                .unwrap();
            let home = guard.home_id().clone();
            guard.home_admissions.open(home, owner.clone()).encode()
        };
        let auth_wb = wb.clone();
        let app = local_routes::routes(false)
            .merge(home_routes::routes())
            .route_layer(middleware::from_fn_with_state(
                auth_wb,
                home_routes::require_home_admission,
            ))
            .with_state(wb.clone());

        let create_body = json!({
            "authority": invitee.as_str(),
            "project": crate::DEFAULT_PROJECT,
            "role": "member",
            "endpoint": "https://owner-home.example",
        })
        .to_string();
        let (status, created) = call(
            &app,
            "POST",
            "/home/invitations",
            Some("owner-login"),
            Some(&owner_admission),
            Some(&create_body),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let created: serde_json::Value = serde_json::from_str(&created).unwrap();
        let encoded = created["invite"].as_str().unwrap();
        let envelope = decode_envelope(encoded).unwrap();
        let stored = wb
            .lock_unpoisoned()
            .store_ref()
            .records(ORG_SCOPE, INVITATION_KIND)
            .unwrap();
        assert!(!stored.join("").contains(&envelope.secret));
        let staged_org = Org::rebuild(wb.lock_unpoisoned().store_ref()).unwrap();
        assert!(staged_org.role_of(invitee.as_str()).is_none());
        assert!(!staged_org.can_access_project(invitee.as_str(), crate::DEFAULT_PROJECT));

        let accept_body = json!({ "invite": encoded }).to_string();
        let (wrong, _) = call(
            &app,
            "POST",
            "/home/invitations/accept",
            Some("wrong-login"),
            None,
            Some(&accept_body),
        )
        .await;
        assert_eq!(wrong, StatusCode::FORBIDDEN);

        let (accepted, body) = call(
            &app,
            "POST",
            "/home/invitations/accept",
            Some("invitee-login"),
            None,
            Some(&accept_body),
        )
        .await;
        assert_eq!(accepted, StatusCode::OK, "{body}");
        let accepted: serde_json::Value = serde_json::from_str(&body).unwrap();
        let first_admission = accepted["admission"].as_str().unwrap().to_owned();
        {
            let guard = wb.lock_unpoisoned();
            let org = Org::rebuild(guard.store_ref()).unwrap();
            assert_eq!(org.role_of(invitee.as_str()).unwrap().as_str(), "member");
            assert!(org.can_access_project(invitee.as_str(), crate::DEFAULT_PROJECT));
            assert!(guard
                .admit_data_request(Some("invitee-login"), Some(crate::DEFAULT_PROJECT))
                .is_ok());
            assert!(guard
                .admit_data_request(Some("invitee-login"), Some("proj-not-granted"))
                .is_err());
        }

        let (home_ok, _) = call(
            &app,
            "GET",
            "/workspace",
            Some("invitee-login"),
            Some(&first_admission),
            None,
        )
        .await;
        assert_eq!(home_ok, StatusCode::OK);
        let (revoked, _) = call(
            &app,
            "DELETE",
            "/home/admissions",
            Some("invitee-login"),
            Some(&first_admission),
            None,
        )
        .await;
        assert_eq!(revoked, StatusCode::NO_CONTENT);
        let (old, _) = call(
            &app,
            "GET",
            "/workspace",
            Some("invitee-login"),
            Some(&first_admission),
            None,
        )
        .await;
        assert_eq!(old, StatusCode::FORBIDDEN);

        drop(app);
        drop(wb);
        let reopened = open_workbench(dir.path()).unwrap();
        reopened
            .lock_unpoisoned()
            .set_identity_provider(Some(Arc::new(LoopbackIdentityProvider::new().enroll(
                "invitee-login",
                invitee,
                AuthorityAttributes::default(),
            ))));
        let reopened_app = home_routes::routes().with_state(reopened.clone());
        let (resumed, body) = call(
            &reopened_app,
            "POST",
            "/home/admissions",
            Some("invitee-login"),
            None,
            None,
        )
        .await;
        assert_eq!(resumed, StatusCode::CREATED, "{body}");
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_ne!(body["admission"].as_str().unwrap(), first_admission);
        assert!(reopened
            .lock_unpoisoned()
            .admit_data_request(Some("invitee-login"), Some(crate::DEFAULT_PROJECT))
            .is_ok());
    }
}
