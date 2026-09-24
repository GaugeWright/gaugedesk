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

/// `POST /tutorials/:name/start` — start, or find, the signed-in owner's run of
/// a tutorial GaugeDesk ships (WHIP-5, DR-0192). The Home supplies the source,
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
