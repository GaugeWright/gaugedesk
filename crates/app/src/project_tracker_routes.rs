//! Authenticated backlog reads and the native, retryable human completion command.
use crate::{
    identity::AuthenticatedActionContext,
    project_tracker::{CompleteTrackerIssue, TrackerCompletionClaim, TrackerPermission},
    project_workflow::ProjectWorkflowLimits,
    LockUnpoisoned, SharedWorkbench, Workbench,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;

fn problem(status: StatusCode, error: &'static str) -> Response {
    (status, Json(serde_json::json!({"error": error}))).into_response()
}
fn context(
    wb: &mut Workbench,
    headers: &HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
) -> Option<AuthenticatedActionContext> {
    // Hosted admission already authenticated this source. The standalone
    // desktop composition has no Home middleware, so its boundary verifies the
    // credential here. Neither path promotes a local/bootstrap default.
    if let Some(Extension(context)) = authenticated {
        return Some(context);
    }
    if let Some(token) = crate::mobile_machine_session::session_token(headers) {
        return crate::mobile_machine_session::authorize_session(wb, token)
            .as_ref()
            .map(AuthenticatedActionContext::machine_controller);
    }
    crate::net_http::bearer(headers).and_then(|token| wb.authenticate_action_context(token))
}

pub async fn list_trackers(
    State(wb): State<SharedWorkbench>,
    Path(project): Path<String>,
    headers: HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
) -> Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(context) = context(&mut wb, &headers, authenticated) else {
        return problem(StatusCode::UNAUTHORIZED, "Sign in to read project tasks");
    };
    match wb.list_project_trackers(&context, &project) {
        Ok(trackers) => Json(serde_json::json!({"trackers": trackers})).into_response(),
        Err(_) => problem(StatusCode::FORBIDDEN, "Project trackers are not readable"),
    }
}

pub async fn read_backlog(
    State(wb): State<SharedWorkbench>,
    Path((project, queue)): Path<(String, String)>,
    headers: HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
) -> Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(context) = context(&mut wb, &headers, authenticated) else {
        return problem(StatusCode::UNAUTHORIZED, "Sign in to read project tasks");
    };
    if wb
        .read_project_tracker(&context, &project, &queue, TrackerPermission::Read)
        .is_err()
    {
        return problem(StatusCode::FORBIDDEN, "Tracker is not readable");
    }
    match wb.read_project_tracker_backlog(&context, &project, &queue) {
        Ok(backlog) => Json(backlog).into_response(),
        Err(_) => problem(StatusCode::SERVICE_UNAVAILABLE, "Tracker is unavailable"),
    }
}

pub async fn read_tasks(
    State(wb): State<SharedWorkbench>,
    Path((project, queue)): Path<(String, String)>,
    headers: HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
) -> Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(context) = context(&mut wb, &headers, authenticated) else {
        return problem(StatusCode::UNAUTHORIZED, "Sign in to read project tasks");
    };
    if wb
        .read_project_tracker(&context, &project, &queue, TrackerPermission::Read)
        .is_err()
    {
        return problem(StatusCode::FORBIDDEN, "Tracker is not readable");
    }
    match wb.read_project_tracker_tasks(&context, &project, &queue) {
        Ok(tasks) => Json(tasks).into_response(),
        Err(_) => problem(StatusCode::SERVICE_UNAVAILABLE, "Tracker is unavailable"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionBody {
    subject_id: String,
    summary: String,
    claim: TrackerCompletionClaim,
}

pub async fn complete_issue(
    State(wb): State<SharedWorkbench>,
    Path((project, queue, item_id)): Path<(String, String, String)>,
    headers: HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
    Json(body): Json<CompletionBody>,
) -> Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(context) = context(&mut wb, &headers, authenticated) else {
        return problem(
            StatusCode::UNAUTHORIZED,
            "Sign in to complete project tasks",
        );
    };
    let request_id = match crate::command_idempotency::caller_idempotency_key(&headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    if wb
        .read_project_tracker(&context, &project, &queue, TrackerPermission::Contribute)
        .is_err()
    {
        return problem(
            StatusCode::FORBIDDEN,
            "Tracker contribution is not permitted",
        );
    }
    let request = CompleteTrackerIssue {
        project: project.clone(),
        queue,
        item_id,
        subject_id: body.subject_id,
        request_id,
        summary: body.summary,
        claim: body.claim,
    };
    match wb.complete_project_tracker_issue(
        &context,
        &request,
        ProjectWorkflowLimits {
            source_bytes: 256 * 1024,
            input_bytes: 64 * 1024,
        },
    ) {
        Ok(result) => {
            if result.executed_effect.is_some() || result.recovered_effect.is_some() {
                // A reference wakes other clients; issue bodies stay behind their
                // own authenticated backlog read.
                wb.notify_library_changed("project_tracker", &project, "upsert");
            }
            Json(result).into_response()
        }
        Err(_) => problem(
            StatusCode::CONFLICT,
            "Task completion could not be confirmed",
        ),
    }
}
