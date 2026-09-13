//! Typed submission into the native command/outbox and dispatch-grant path.
//! The host opts in with trusted storage configuration; production activation
//! requires the runtime specification's rollout qualification.
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    file_action_factory::{
        EditorFileSave, EditorFileSaveRequestIdentity, NativeActionStorageConfig,
    },
    identity::ActorAuthentication,
    LockUnpoisoned, SharedWorkbench,
};

#[derive(Clone)]
struct SubmissionState {
    workbench: SharedWorkbench,
    storage: NativeActionStorageConfig,
}

/// Host-owned route composition, shared by native and hosted Home servers.
/// Request extensions cannot substitute the Workbench or storage configuration.
pub fn routes(workbench: SharedWorkbench, storage: NativeActionStorageConfig) -> Router {
    Router::new()
        .route("/chats/{id}/file-actions/save", post(submit_file_save))
        .layer(axum::middleware::map_response(
            crate::file_action_routes::no_store,
        ))
        .with_state(SubmissionState { workbench, storage })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitFileSave {
    expected_actor: String,
    identity: EditorFileSaveRequestIdentity,
    path: String,
    base_cut: String,
    content: String,
    dispatch_request_id: String,
}

fn refusal(status: StatusCode, message: &'static str) -> Response {
    (status, Json(json!({"error": message}))).into_response()
}

async fn submit_file_save(
    State(state): State<SubmissionState>,
    Path(chat): Path<String>,
    headers: HeaderMap,
    Json(intent): Json<SubmitFileSave>,
) -> Response {
    // Admission performs blocking, fenced storage operations. A disconnected
    // HTTP caller does not cancel a worker that may already have admitted intent.
    tokio::task::spawn_blocking(move || submit(state, chat, headers, intent))
        .await
        .unwrap_or_else(|_| {
            refusal(
                StatusCode::INTERNAL_SERVER_ERROR,
                "save submission is unavailable; inspect the original request",
            )
        })
}

fn submit(
    state: SubmissionState,
    chat: String,
    headers: HeaderMap,
    intent: SubmitFileSave,
) -> Response {
    let mut wb = state.workbench.lock_unpoisoned();
    let context = match crate::home_routes::authenticate_home_work_request(
        &mut wb,
        &headers,
        &format!("/chats/{chat}/file-actions/save"),
    ) {
        Ok(Some(context)) => context,
        Ok(None) => {
            return refusal(
                StatusCode::UNAUTHORIZED,
                "verified Home action credentials required",
            )
        }
        Err((status, message)) => return refusal(status, message),
    };
    if intent.expected_actor != context.actor().as_str() {
        return refusal(
            StatusCode::FORBIDDEN,
            "save actor changed; inspect the original request",
        );
    }
    if !matches!(
        context.authentication(),
        ActorAuthentication::AccountSession { .. } | ActorAuthentication::MachineController { .. }
    ) {
        return refusal(
            StatusCode::FORBIDDEN,
            "save dispatch requires durable revocable authentication",
        );
    }
    if headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        != Some(intent.identity.request_id.as_str())
        || intent.dispatch_request_id.trim().is_empty()
    {
        return refusal(
            StatusCode::BAD_REQUEST,
            "retained save and dispatch request identities are required",
        );
    }
    if intent.content.len() > state.storage.input_byte_limit {
        return refusal(
            StatusCode::PAYLOAD_TOO_LARGE,
            "save content exceeds the Home input limit",
        );
    }
    let original = wb.prepare_editor_file_save_request(
        &context,
        &chat,
        &intent.path,
        &intent.identity.request_id,
    );
    if original.as_ref() != Ok(&intent.identity) {
        return refusal(
            StatusCode::FORBIDDEN,
            "original save coordinates are unavailable",
        );
    }
    let storage = match wb.open_native_action_storage(state.storage) {
        Ok(storage) => storage,
        Err(_) => {
            return refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "save storage is unavailable; inspect the original request",
            )
        }
    };
    let admitted = match wb.admit_editor_file_save(
        &context,
        storage.inputs(),
        &intent.identity,
        &EditorFileSave {
            chat_id: &chat,
            request_id: &intent.identity.request_id,
            path: &intent.path,
            base_cut: &intent.base_cut,
            content: &intent.content,
        },
    ) {
        Ok(admitted) => admitted,
        Err(_) => {
            return refusal(
                StatusCode::CONFLICT,
                "save admission is unavailable; inspect the original request",
            )
        }
    };
    // A refusal here can follow committed command admission. Keep that fact
    // visible, and never mint a replacement grant key or dispatch directly.
    let dispatch = match wb.authorize_editor_file_save_dispatch(
        &context,
        storage.inputs(),
        &admitted.command,
        &intent.dispatch_request_id,
    ) {
        Ok(grant) => json!({"state": "authorized", "grant_ref": grant.grant_ref,
            "replayed": grant.replayed}),
        Err(_) => json!({"state": "unavailable"}),
    };
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "identity": intent.identity, "actor": context.actor().as_str(),
            "admission": "admitted", "replayed": admitted.replayed,
            "dispatch_request_id": intent.dispatch_request_id, "dispatch": dispatch,
        })),
    )
        .into_response()
}
