//! Strict staff admission for the office Home (DR-0259, WS-545).
//!
//! This boundary is separate from the desktop operator and relay channels.
//! It deliberately has no local-operator, bootstrap, cookie, or machine-session
//! fallback. It is not mounted by the runtime until the office listener and
//! its route surface have been qualified.

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
    let result = {
        let mut guard = wb.lock_unpoisoned();
        authenticate_staff_request(&mut guard, &request).and_then(|context| {
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
                context.actor().as_str(),
                &action,
                &target,
            )
            .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "office audit unavailable"))?;
            Ok(context)
        })
    };
    let context = match result {
        Ok(context) => context,
        Err((status, error)) => return (status, Json(json!({ "error": error }))).into_response(),
    };
    request
        .extensions_mut()
        .insert(crate::identity::AuthenticatedActor(context.actor().clone()));
    request.extensions_mut().insert(context);
    next.run(request).await
}

fn authenticate_staff_request(
    wb: &mut crate::Workbench,
    request: &Request,
) -> Result<AuthenticatedActionContext, (StatusCode, &'static str)> {
    let bearer = crate::net_http::bearer(request.headers()).ok_or((
        StatusCode::UNAUTHORIZED,
        "sign in to reach this office Home",
    ))?;
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
        return Ok(context);
    }
    crate::home_routes::authenticate_home_work_request(wb, request.headers(), request.uri().path())?
        .filter(|admitted| admitted.actor() == &actor)
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "office identity could not be admitted",
        ))
}

#[cfg(test)]
#[path = "office_home_admission_tests.rs"]
mod tests;
