//! Project backlog reads and the native, retryable human completion command.
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
pub(crate) fn context(
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
    operator: Option<Extension<crate::account_signin::DesktopOperatorPlane>>,
) -> Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(context) = context(&mut wb, &headers, authenticated).or_else(|| {
        (operator.is_some()
            && crate::net_http::bearer(&headers).is_none()
            && crate::mobile_machine_session::session_token(&headers).is_none())
        .then(|| wb.local_personal_tracker_context(&project))
        .flatten()
    }) else {
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
    operator: Option<Extension<crate::account_signin::DesktopOperatorPlane>>,
) -> Response {
    let (_, read) = match prepare_backlog(&wb, &project, &queue, &headers, authenticated, operator)
    {
        Ok(prepared) => prepared,
        Err(refused) => return *refused,
    };
    match read.read() {
        Ok(backlog) => Json(backlog).into_response(),
        Err(error) => unavailable(&project, &queue, "backlog", error.as_str()),
    }
}

/// Admit a tracker read and prepare it under the Workbench lock, which is
/// released before the native read: on a Home with a long task history that
/// read took most of a second, and every other request — a new chat's actor
/// proof and event stream among them — waited behind it (WS-926).
fn prepare_backlog(
    wb: &SharedWorkbench,
    project: &str,
    queue: &str,
    headers: &HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
    operator: Option<Extension<crate::account_signin::DesktopOperatorPlane>>,
) -> Result<
    (
        AuthenticatedActionContext,
        crate::project_tracker::PreparedTrackerBacklog,
    ),
    Box<Response>,
> {
    let mut wb = wb.lock_unpoisoned();
    let Some(context) = context(&mut wb, headers, authenticated).or_else(|| {
        (operator.is_some()
            && crate::net_http::bearer(headers).is_none()
            && crate::mobile_machine_session::session_token(headers).is_none())
        .then(|| wb.local_personal_tracker_context(project))
        .flatten()
    }) else {
        return Err(Box::new(problem(
            StatusCode::UNAUTHORIZED,
            "Sign in to read project tasks",
        )));
    };
    if wb
        .read_project_tracker(&context, project, queue, TrackerPermission::Read)
        .is_err()
    {
        return Err(Box::new(problem(
            StatusCode::FORBIDDEN,
            "Tracker is not readable",
        )));
    }
    match wb.prepare_project_tracker_backlog(&context, project, queue) {
        Ok(prepared) => Ok((context, prepared)),
        Err(error) => Err(Box::new(unavailable(
            project,
            queue,
            "backlog",
            error.as_str(),
        ))),
    }
}

/// Said here because the person sees only "some tasks could not be read",
/// and the reason is otherwise nowhere (2026-10-07).
fn unavailable(project: &str, queue: &str, read: &str, error: &str) -> Response {
    tracing::warn!(project, queue, read, %error, "project tracker could not be read");
    problem(StatusCode::SERVICE_UNAVAILABLE, "Tracker is unavailable")
}

pub async fn read_tasks(
    State(wb): State<SharedWorkbench>,
    Path((project, queue)): Path<(String, String)>,
    headers: HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
    operator: Option<Extension<crate::account_signin::DesktopOperatorPlane>>,
) -> Response {
    let (context, read) =
        match prepare_backlog(&wb, &project, &queue, &headers, authenticated, operator) {
            Ok(prepared) => prepared,
            Err(refused) => return *refused,
        };
    match read.read() {
        Ok(backlog) => Json(crate::project_tracker::ProjectTrackerTasks::of(
            &context, backlog,
        ))
        .into_response(),
        Err(error) => unavailable(&project, &queue, "tasks", error.as_str()),
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
    match wb.complete_project_tracker_issue(&context, &request, ProjectWorkflowLimits::PRODUCT) {
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBody {
    subject_id: String,
    control: crate::project_tracker::TrackerIssueControl,
}

/// `POST /projects/:project/trackers/:queue/issues/:item_id/control` — claim,
/// renew, release or reassign one issue as the signed-in person (WHIP-4).
/// Keyed by the caller's `Idempotency-Key`; a retry replays the same act.
pub async fn control_issue(
    State(wb): State<SharedWorkbench>,
    Path((project, queue, item_id)): Path<(String, String, String)>,
    headers: HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
    Json(body): Json<ControlBody>,
) -> Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(context) = context(&mut wb, &headers, authenticated) else {
        return problem(StatusCode::UNAUTHORIZED, "Sign in to take or assign tasks");
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
    let request = crate::project_tracker::ControlTrackerIssue {
        project: project.clone(),
        queue,
        item_id,
        subject_id: body.subject_id,
        request_id,
        control: body.control,
    };
    match wb.control_project_tracker_issue(&context, &request, ProjectWorkflowLimits::PRODUCT) {
        Ok(result) => {
            if result.executed_effect.is_some() || result.recovered_effect.is_some() {
                wb.notify_library_changed("project_tracker", &project, "upsert");
            }
            Json(result).into_response()
        }
        Err(error) => {
            tracing::info!(%error, "tracker control not confirmed");
            problem(
                StatusCode::CONFLICT,
                "The task change could not be confirmed",
            )
        }
    }
}
