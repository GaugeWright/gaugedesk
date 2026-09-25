//! Launching an ordinary folder whip (DR-0191). The route admits a launch and
//! wakes the Home's supervisor; no client ever steps a run.
use crate::{
    identity::AuthenticatedActionContext,
    project_workflow::{ProjectWorkflowLaunch, ProjectWorkflowLimits},
    LockUnpoisoned, SharedWorkbench,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;
use std::collections::BTreeMap;

fn problem(status: StatusCode, error: &'static str) -> Response {
    (status, Json(serde_json::json!({"error": error}))).into_response()
}

/// The saved source to run and its typed inputs. The request id is the
/// caller's `Idempotency-Key`, so a retry recovers the same invocation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchBody {
    target: String,
    path: String,
    cut: String,
    #[serde(default)]
    inputs: BTreeMap<String, serde_json::Value>,
}

pub async fn launch(
    State(wb): State<SharedWorkbench>,
    Path(project): Path<String>,
    headers: HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
    Json(body): Json<LaunchBody>,
) -> Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(context) = crate::project_tracker_routes::context(&mut wb, &headers, authenticated)
    else {
        return problem(StatusCode::UNAUTHORIZED, "Sign in to run a workflow");
    };
    let request_id = match crate::command_idempotency::caller_idempotency_key(&headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let request = ProjectWorkflowLaunch {
        project,
        target: body.target,
        path: body.path,
        cut: body.cut,
        request_id,
        inputs: body.inputs,
    };
    match wb.launch_project_workflow(&context, &request, ProjectWorkflowLimits::PRODUCT) {
        Ok(invocation) => Json(invocation).into_response(),
        Err(error) => {
            tracing::info!(project = %request.project, %error, "workflow launch refused");
            problem(StatusCode::CONFLICT, "The workflow could not be launched")
        }
    }
}

/// `POST /tutorials/:name/start` — start, or find, the learner's run of
/// a tutorial GaugeDesk ships (WHIP-5, DR-0225). The Home supplies the source,
/// revision and learner; the request carries nothing but who is asking. Asked
/// again, it answers with the run that exists.
pub async fn start_shipped_tutorial(
    State(wb): State<SharedWorkbench>,
    Path(name): Path<String>,
    headers: HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
) -> Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(context) = crate::project_tracker_routes::context(&mut wb, &headers, authenticated)
    else {
        return problem(StatusCode::UNAUTHORIZED, "Sign in to start a tutorial");
    };
    match wb.start_shipped_tutorial(&context, &name) {
        Ok(invocation) => Json(invocation).into_response(),
        Err(error) => {
            tracing::info!(tutorial = %name, %error, "tutorial start refused");
            problem(StatusCode::CONFLICT, "The tutorial could not be started")
        }
    }
}

/// `GET /tutorials/:name` — the authenticated learner's installed source and
/// ordinary workflow/tracker status for the Tutorials project surface.
pub async fn shipped_tutorial_info(
    State(wb): State<SharedWorkbench>,
    Path(name): Path<String>,
    headers: HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
) -> Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(context) = crate::project_tracker_routes::context(&mut wb, &headers, authenticated)
    else {
        return problem(StatusCode::UNAUTHORIZED, "Sign in to view tutorials");
    };
    match wb.shipped_tutorial_info(&context, &name) {
        Ok(info) => Json(info).into_response(),
        Err(error) => {
            tracing::info!(tutorial = %name, %error, "tutorial view unavailable");
            problem(StatusCode::NOT_FOUND, "Tutorial is unavailable")
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatWhipQuery {
    path: String,
}

/// `GET /chats/:chat/whips/inputs?path=` — the inputs the kept version of a
/// chat's `.whip` file declares, and the revision a Run would launch. Read
/// under the authority that launch would need.
pub async fn describe_chat_whip(
    State(wb): State<SharedWorkbench>,
    Path(chat): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ChatWhipQuery>,
    headers: HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
) -> Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(context) = crate::project_tracker_routes::context(&mut wb, &headers, authenticated)
    else {
        return problem(StatusCode::UNAUTHORIZED, "Sign in to run a workflow");
    };
    let source = match wb.chat_workflow_source(&chat, &query.path) {
        Ok(source) => source,
        Err(error) => {
            tracing::info!(%chat, %error, "workflow source not resolved");
            return problem(StatusCode::CONFLICT, "This file cannot be run from here");
        }
    };
    match wb.describe_project_workflow(&context, &source, ProjectWorkflowLimits::PRODUCT) {
        Ok(described) => Json(serde_json::json!({
            "project": source.project,
            "target": source.target,
            "path": source.path,
            "cut": source.cut,
            "workflow": described["workflow"],
            "inputs": described["inputs"],
            // Who is asking, so a person input can default to them.
            "actor": context.actor().as_str(),
        }))
        .into_response(),
        Err(error) => {
            tracing::info!(%chat, %error, "workflow not described");
            problem(StatusCode::CONFLICT, "This workflow cannot be run")
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatWhipRunsQuery {
    #[serde(default)]
    path: Option<String>,
}

/// `GET /chats/:chat/whips/runs[?path=]` — the runs of this chat's `.whip`
/// files, or of one of them, newest first: the Run button's status, a file's
/// status dot and its Runs history. A run of a project's shared files shows to
/// everyone with access to the project; a run of a person's own files only to
/// whoever launched it (DR-0199).
pub async fn list_chat_whip_runs(
    State(wb): State<SharedWorkbench>,
    Path(chat): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ChatWhipRunsQuery>,
    headers: HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
) -> Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(context) = crate::project_tracker_routes::context(&mut wb, &headers, authenticated)
    else {
        return problem(StatusCode::UNAUTHORIZED, "Sign in to see workflow runs");
    };
    match wb.chat_whip_runs(&context, &chat, query.path.as_deref()) {
        Ok(runs) => Json(serde_json::json!({ "runs": runs })).into_response(),
        Err(error) => {
            tracing::info!(%chat, %error, "workflow runs not listed");
            problem(
                StatusCode::CONFLICT,
                "This chat's workflow runs cannot be read",
            )
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatWhipStop {
    path: String,
    launched_by: String,
    request_id: String,
}

/// `POST /chats/:chat/whips/stop` — stop one run of a chat's `.whip` file.
/// Its launcher or a Home owner/admin may; tasks it filed stay. Keyed by the
/// caller's `Idempotency-Key`; stopping a finished run changes nothing.
pub async fn stop_chat_whip(
    State(wb): State<SharedWorkbench>,
    Path(chat): Path<String>,
    headers: HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
    Json(body): Json<ChatWhipStop>,
) -> Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(context) = crate::project_tracker_routes::context(&mut wb, &headers, authenticated)
    else {
        return problem(StatusCode::UNAUTHORIZED, "Sign in to stop a workflow");
    };
    let key = match crate::command_idempotency::caller_idempotency_key(&headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    match wb.stop_chat_whip_run(
        &context,
        &chat,
        &body.path,
        &body.launched_by,
        &body.request_id,
        &key,
    ) {
        Ok(run) => Json(serde_json::json!({ "run": run })).into_response(),
        Err(error) => {
            tracing::info!(%chat, %error, "workflow run not stopped");
            problem(StatusCode::CONFLICT, "This run could not be stopped")
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatWhipRun {
    path: String,
    cut: String,
    #[serde(default)]
    inputs: BTreeMap<String, serde_json::Value>,
}

/// `POST /chats/:chat/whips/run` — launch the kept version of a chat's
/// `.whip` file at the revision it was described at. Keyed by the caller's
/// `Idempotency-Key`; the Home steps what it launches.
pub async fn run_chat_whip(
    State(wb): State<SharedWorkbench>,
    Path(chat): Path<String>,
    headers: HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
    Json(body): Json<ChatWhipRun>,
) -> Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(context) = crate::project_tracker_routes::context(&mut wb, &headers, authenticated)
    else {
        return problem(StatusCode::UNAUTHORIZED, "Sign in to run a workflow");
    };
    let request_id = match crate::command_idempotency::caller_idempotency_key(&headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let source = match wb.chat_workflow_source(&chat, &body.path) {
        Ok(source) => source,
        Err(error) => {
            tracing::info!(%chat, %error, "workflow source not resolved");
            return problem(StatusCode::CONFLICT, "This file cannot be run from here");
        }
    };
    // A project workflow files into the project's `tasks` tracker, which a
    // project created since the last wake may not have yet (DR-0199 §3).
    if let Err(error) = wb.ensure_project_tasks_tracker(&source.project) {
        tracing::warn!(%chat, %error, "project tasks tracker not ensured");
    }
    let request = ProjectWorkflowLaunch {
        project: source.project,
        target: source.target,
        path: source.path,
        // The revision the person saw described. The launch admits it only
        // while it is still in Main's history.
        cut: body.cut,
        request_id,
        inputs: body.inputs,
    };
    match wb.launch_project_workflow(&context, &request, ProjectWorkflowLimits::PRODUCT) {
        Ok(invocation) => Json(invocation).into_response(),
        Err(error) => {
            tracing::info!(%chat, %error, "workflow launch refused");
            problem(StatusCode::CONFLICT, "The workflow could not be launched")
        }
    }
}
