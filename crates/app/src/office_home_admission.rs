//! Strict staff admission for the office Home (DR-0259, WS-545).
//!
//! This boundary is separate from the desktop operator and relay channels.
//! It deliberately has no local-operator, bootstrap, cookie, or machine-session
//! fallback. It is not mounted by the runtime until the office listener and
//! its route surface have been qualified.

#[path = "office_staff_authentication.rs"]
pub(crate) mod authentication;
#[path = "office_chat_stream.rs"]
pub(crate) mod chat_stream;
#[path = "office_staff_lease.rs"]
pub mod lease;
#[path = "office_staff_source.rs"]
pub mod source;
#[path = "office_workspace_stream.rs"]
pub(crate) mod workspace_stream;

use axum::{
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::{identity::AuthenticatedActionContext, LockUnpoisoned, SharedWorkbench};

pub async fn require_office_home_admission(
    State(wb): State<SharedWorkbench>,
    mut request: Request,
    next: Next,
) -> Response {
    request
        .extensions_mut()
        .remove::<crate::identity::AuthenticatedActor>();
    request
        .extensions_mut()
        .remove::<AuthenticatedActionContext>();
    request
        .extensions_mut()
        .remove::<crate::account_signin::DesktopOperatorPlane>();
    // This channel belongs to this office. A caller cannot select another
    // tenant, inherit an operator channel, or supply the trusted proxy's peer.
    // Only the explicit bearer can identify staff.
    for header in [
        "cookie",
        "x-gaugewright-machine-session",
        "x-gaugewright-tenant",
        "cf-connecting-ip",
        "x-forwarded-for",
        "forwarded",
        "x-real-ip",
    ] {
        request.headers_mut().remove(header);
    }
    if request.uri().path() == "/health" && request.method() == Method::GET {
        return next.run(request).await;
    }
    // The channel serves only the Project Host its organization enrolled in the
    // office-controlled profile (WS-424). This is decided from the Home's own
    // store before any credential is checked or any body is read.
    if let Some((status, error)) = wb.lock_unpoisoned().office_profile_channel_refusal() {
        return (status, Json(json!({ "error": error }))).into_response();
    }
    // Verify only workforce authentication outside the Home mutex. Neither the
    // source verifier nor its worker receives a route, project or work payload.
    let source = wb.lock_unpoisoned().office_staff_verifier();
    let verification = if let Some(source) = source {
        let Some(bearer) = crate::net_http::bearer(request.headers()) else {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "sign in to reach this office Home"})),
            )
                .into_response();
        };
        let bearer = bearer.to_owned();
        let reference = crate::account_session::session_id(&bearer);
        let worker_source = std::sync::Arc::clone(&source);
        match tokio::task::spawn_blocking(move || worker_source.check(&bearer)).await {
            Ok(check) => Some((source, reference, check)),
            Err(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "office source verification unavailable"})),
                )
                    .into_response()
            }
        }
    } else {
        None
    };
    let result = {
        let mut guard = wb.lock_unpoisoned();
        let source_result = match verification {
            Some((source, reference, check)) => guard
                .observe_office_staff_check(&source, &reference, check)
                .map(|_| ()),
            None => Ok(()),
        };
        source_result
            .and_then(|()| authenticate_staff_request(&mut guard, &request))
            .and_then(|(actor, context)| {
                // The generic sink can send audit references to an arbitrary
                // collector. It has no office-destination admission contract yet.
                if guard.audit_sink().is_some() {
                    return Err((
                        StatusCode::FORBIDDEN,
                        "office audit streaming destination has not been admitted",
                    ));
                }
                let route = request
                    .extensions()
                    .get::<axum::extract::MatchedPath>()
                    .map(|path| path.as_str())
                    .unwrap_or("unmatched");
                let operation = match *request.method() {
                    Method::GET | Method::HEAD => "read",
                    Method::POST | Method::PUT | Method::PATCH | Method::DELETE => "write",
                    _ => "request",
                };
                // An admitted attempt, not a claim that the handler succeeded. The
                // router's template is trusted; raw paths, queries and bodies are not
                // audit fields. Refuse before work if the durable append fails.
                let action = format!("home.{operation}.admitted:{route}");
                let target = guard
                    .scope_project_of_path(request.uri().path())
                    .unwrap_or_else(|| guard.home_id().as_str().to_owned());
                crate::audit::record_required_in(
                    &mut guard,
                    crate::org::ORG_SCOPE,
                    actor.as_str(),
                    &action,
                    &target,
                )
                .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "office audit unavailable"))?;
                Ok((actor, context))
            })
    };
    let (actor, context) = match result {
        Ok(admitted) => admitted,
        Err((status, error)) => return (status, Json(json!({ "error": error }))).into_response(),
    };
    request
        .extensions_mut()
        .insert(crate::identity::AuthenticatedActor(actor));
    let verified = context.is_some();
    if let Some(context) = context {
        request.extensions_mut().insert(context);
    }
    let (method, path) = (request.method().clone(), request.uri().path().to_owned());
    let holds = if verified {
        crate::key_delegation::session_holds(&wb, request.headers(), &method, &path)
    } else {
        Vec::new()
    };
    let member_use = wb.lock_unpoisoned().member_use.clone();
    let response = next.run(request).await;
    if verified {
        crate::key_delegation::count_member_use(
            &wb,
            &member_use,
            &method,
            &path,
            response.status(),
        )
        .await;
    }
    crate::key_delegation::hold_while_sent(response, holds)
}

fn authenticate_staff_request(
    wb: &mut crate::Workbench,
    request: &Request,
) -> Result<
    (
        gaugedesk_core::ids::AuthorityId,
        Option<AuthenticatedActionContext>,
    ),
    (StatusCode, &'static str),
> {
    let bearer = crate::net_http::bearer(request.headers()).ok_or((
        StatusCode::UNAUTHORIZED,
        "sign in to reach this office Home",
    ))?;
    if wb.office_staff_auth.is_some() {
        let project = wb.scope_project_of_path(request.uri().path());
        let actor = gaugedesk_core::ids::AuthorityId::new(wb.admit_office_staff_identity(
            bearer,
            project.as_deref(),
            crate::org::ORG_SCOPE,
            crate::client_admission::ClientBuild::from_headers(request.headers()),
            true,
        )?);
        // Sign-in identity at the admission ceremony is not work authority.
        if request.uri().path() == "/home/admissions" && request.method() == Method::POST {
            return Ok((actor, None));
        }
        let context = crate::home_routes::authenticate_home_work_request(
            wb,
            request.headers(),
            request.method(),
            request.uri().path(),
        )?
        .filter(|context| {
            context.actor() == &actor
                && matches!(
                    context.authentication(),
                    crate::identity::ActorAuthentication::OfficeStaff { .. }
                )
        })
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "office identity could not be admitted",
        ))?;
        return Ok((actor, Some(context)));
    }
    // Resolve device binding and credential expiry before any legacy admission
    // function can choose an operator or anonymous bootstrap default.
    let actor = wb.authenticate_bearer(bearer).ok_or((
        StatusCode::UNAUTHORIZED,
        "sign in to reach this office Home",
    ))?;
    let org = crate::org::Org::rebuild_in(wb.store_ref(), crate::org::ORG_SCOPE)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "directory unavailable"))?;
    if org.role_of(actor.as_str()).is_none() {
        return Err((StatusCode::FORBIDDEN, "not an active office member"));
    }
    let project = wb.scope_project_of_path(request.uri().path());
    let admitted = wb.admit_data_request_with_client(
        Some(bearer),
        project.as_deref(),
        crate::org::ORG_SCOPE,
        crate::client_admission::ClientBuild::from_headers(request.headers()),
        true,
    )?;
    if admitted != actor.as_str() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "office identity could not be admitted",
        ));
    }
    let context = wb
        .authenticate_action_context(bearer)
        .filter(|context| context.actor() == &actor)
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "office identity could not be admitted",
        ))?;
    // Admission creation still requires verified, current office standing. All
    // other methods, including revocation, must prove the exact Home binding.
    if request.uri().path() == "/home/admissions" && request.method() == Method::POST {
        return Ok((actor, Some(context)));
    }
    crate::home_routes::authenticate_home_work_request(
        wb,
        request.headers(),
        request.method(),
        request.uri().path(),
    )?
    .filter(|admitted| admitted.actor() == &actor)
    .map(|context| (actor, Some(context)))
    .ok_or((
        StatusCode::UNAUTHORIZED,
        "office identity could not be admitted",
    ))
}

#[cfg(test)]
#[path = "office_home_admission_tests.rs"]
mod tests;
