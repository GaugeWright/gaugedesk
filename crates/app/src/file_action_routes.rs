//! Home-authenticated preparation and independent request evidence views.
use axum::{
    extract::{Path, Query, State},
    http::{header::CACHE_CONTROL, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    file_action_factory::EditorFileSaveRequestIdentity, identity::AuthenticatedActionContext,
    LockUnpoisoned, SharedWorkbench, Workbench,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareFileRequest {
    path: String,
    request_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadSavedContent {
    home: String,
    issuer: String,
    scope: String,
    request_id: String,
    cut: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadNativeContent {
    expected_actor: String,
    path: String,
}

pub async fn inspect_native_content(
    State(shared): State<SharedWorkbench>,
    Path(chat): Path<String>,
    headers: HeaderMap,
    Query(query): Query<ReadNativeContent>,
) -> Response {
    tokio::task::spawn_blocking(move || {
        let mut wb = shared.lock_unpoisoned();
        let context = match context(
            &mut wb,
            &headers,
            &format!("/chats/{chat}/file-actions/content"),
        ) {
            Ok(context) => context,
            Err((status, message)) => return response(status, json!({"error": message})),
        };
        if context.actor().as_str() != query.expected_actor {
            return response(
                StatusCode::FORBIDDEN,
                json!({"error": "file reader changed"}),
            );
        }
        match wb.observe_native_file_content(&context, &chat, &query.path) {
            Ok(observed) => response(StatusCode::OK, json!(observed)),
            Err(_) => response(
                StatusCode::NOT_FOUND,
                json!({"error": "retained native file content is unavailable"}),
            ),
        }
    })
    .await
    .unwrap_or_else(|_| {
        response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": "retained native file content is unavailable"}),
        )
    })
}

pub async fn inspect_saved_content(
    State(shared): State<SharedWorkbench>,
    headers: HeaderMap,
    Query(query): Query<ReadSavedContent>,
) -> Response {
    tokio::task::spawn_blocking(move || {
        let mut wb = shared.lock_unpoisoned();
        let context = match context(&mut wb, &headers, "/file-actions/saved-content") {
            Ok(context) => context,
            Err((status, message)) => return response(status, json!({"error": message})),
        };
        let unavailable = || {
            response(
                StatusCode::NOT_FOUND,
                json!({"error": "native saved content is unavailable"}),
            )
        };
        if query.home != wb.home_id().as_str() {
            return unavailable();
        }
        let identity = EditorFileSaveRequestIdentity {
            home: query.home,
            issuer: query.issuer,
            scope: query.scope,
            request_id: query.request_id,
        };
        let observed = match wb.observe_editor_file_saved_content_by_request(
            &context,
            identity.as_request(),
            &query.cut,
        ) {
            Ok(observed) => observed,
            Err(_) => return unavailable(),
        };
        if observed.content().len() > crate::engagement_routes::MAX_VIEWABLE_FILE_BYTES {
            return response(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"error": "saved content exceeds the viewer limit"}),
            );
        }
        response(
            StatusCode::OK,
            json!({"identity": identity, "cut": observed.result().cut_id,
            "content": observed.content(), "content_hash": observed.result().content_hash,
            "merged": observed.result().merged, "observer": observed.observer(),
            "restrictions": observed.restrictions()}),
        )
    })
    .await
    .unwrap_or_else(|_| {
        response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": "native saved content is unavailable"}),
        )
    })
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileRequestView {
    Command,
    Execution,
    Saved,
}

fn response(status: StatusCode, value: Value) -> Response {
    (status, Json(value)).into_response()
}

// Covers extractor refusals too, before a handler has a parsed identity.
pub(crate) async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn context(
    wb: &mut Workbench,
    headers: &HeaderMap,
    path: &str,
) -> Result<AuthenticatedActionContext, (StatusCode, &'static str)> {
    match crate::home_routes::authenticate_home_work_request(wb, headers, path) {
        Ok(Some(context)) => Ok(context),
        Ok(None) => Err((
            StatusCode::UNAUTHORIZED,
            "verified Home action credentials required",
        )),
        Err(refusal) => Err(refusal),
    }
}

pub async fn prepare_file_request(
    State(shared): State<SharedWorkbench>,
    Path(chat): Path<String>,
    headers: HeaderMap,
    Query(query): Query<PrepareFileRequest>,
) -> Response {
    let mut wb = shared.lock_unpoisoned();
    let context = match context(
        &mut wb,
        &headers,
        &format!("/chats/{chat}/file-actions/request"),
    ) {
        Ok(context) => context,
        Err((status, message)) => return response(status, json!({"error": message})),
    };
    match wb.prepare_editor_file_save_request(&context, &chat, &query.path, &query.request_id) {
        Ok(identity) => response(StatusCode::OK, json!(identity)),
        Err(_) => response(
            StatusCode::FORBIDDEN,
            json!({"error": "native file request coordinates are unavailable"}),
        ),
    }
}

pub async fn inspect_file_actor(
    State(shared): State<SharedWorkbench>,
    headers: HeaderMap,
) -> Response {
    let mut wb = shared.lock_unpoisoned();
    match context(&mut wb, &headers, "/file-actions/actor") {
        Ok(context) => response(
            StatusCode::OK,
            json!({"home": wb.home_id().as_str(), "actor": context.actor().as_str()}),
        ),
        Err((status, message)) => response(status, json!({"error": message})),
    }
}

pub async fn inspect_file_request(
    State(shared): State<SharedWorkbench>,
    Path(view): Path<FileRequestView>,
    headers: HeaderMap,
    Query(identity): Query<EditorFileSaveRequestIdentity>,
) -> Response {
    let mut wb = shared.lock_unpoisoned();
    let context = match context(&mut wb, &headers, "/file-actions/requests") {
        Ok(context) => context,
        Err((status, message)) => return response(status, json!({"error": message})),
    };
    let unavailable = || {
        response(
            StatusCode::NOT_FOUND,
            json!({"error": "native file request evidence is unavailable"}),
        )
    };
    if identity.home != wb.home_id().as_str() {
        return unavailable();
    }
    let request = identity.as_request();
    let observed = match view {
        FileRequestView::Command => {
            wb.observe_editor_file_save_request(&context, request)
                .map(|value| {
                    json!({
                        "identity": identity, "view": "command", "observer": value.observer(),
                        "restrictions": value.restrictions(), "evidence": value.command(),
                    })
                })
        }
        FileRequestView::Execution => wb
            .observe_editor_file_save_execution_by_request(&context, request)
            .map(|value| {
                json!({
                    "identity": identity, "view": "execution", "observer": value.observer(),
                    "restrictions": value.restrictions(),
                    "evidence": {"command": value.command(), "runtime": value.runtime()},
                })
            }),
        FileRequestView::Saved => wb
            .observe_editor_file_saved_results_by_request(&context, request)
            .map(|value| {
                let results: Vec<_> = value
                    .results()
                    .iter()
                    .map(|fact| {
                        json!({
                            "effect_id": fact.effect_id, "run_id": fact.run_id,
                            "position": fact.position, "result": fact.result,
                        })
                    })
                    .collect();
                json!({"identity": identity, "view": "saved", "observer": value.observer(),
                "restrictions": value.restrictions(), "evidence": results})
            }),
    };
    match observed {
        Ok(value) => response(StatusCode::OK, value),
        Err(_) => unavailable(),
    }
}
