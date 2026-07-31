//! HTTP command envelope guard (CORE-2 / INV-19).
//!
//! Reducer-specific `/command` routes use `Store::admit_materialized`, which can
//! atomically pair a receipt with admitted events. The rest of the local API has
//! heterogeneous record/filesystem effects, so this outer shell takes the safe
//! crash posture: materialize a secret-free hash snapshot before dispatch, run a
//! key once, and refuse an uncertain replay rather than risk applying it twice.

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use sha2::{Digest, Sha256};

use crate::{LockUnpoisoned, SharedWorkbench};

const IDEMPOTENCY_KEY: &str = "idempotency-key";
const MAX_COMMAND_BODY_BYTES: usize = 64 * 1024 * 1024;

// Axum handlers consume `Response` directly on the error path; boxing it here
// would only push allocation/unboxing through every command route.
#[allow(clippy::result_large_err)]
pub fn caller_idempotency_key(headers: &HeaderMap) -> Result<String, Response> {
    let Some(value) = headers.get(IDEMPOTENCY_KEY) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "missing Idempotency-Key header" })),
        )
            .into_response());
    };
    let key = value.to_str().unwrap_or_default().trim();
    if key.is_empty() || key.len() > 200 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Idempotency-Key must be 1..200 characters" })),
        )
            .into_response());
    }
    Ok(key.to_string())
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn reducer_command_path(path: &str) -> bool {
    let parts: Vec<_> = path.split('/').filter(|part| !part.is_empty()).collect();
    matches!(parts.as_slice(), ["placements", _, "command"])
        || matches!(parts.as_slice(), ["scopes", _, "run", "command"])
        || matches!(
            parts.as_slice(),
            ["chats", _, "resources", _, "review" | "export", "command"]
        )
}

fn environment_command_path(path: &str) -> bool {
    let parts: Vec<_> = path.split('/').filter(|part| !part.is_empty()).collect();
    matches!(parts.as_slice(), ["environments", _, "sessions"])
        || matches!(parts.as_slice(), ["environments", _, "commands"])
        || matches!(parts.as_slice(), ["environments", _, "changes"])
        || matches!(
            parts.as_slice(),
            ["environments", _, "changes", _, "review"]
        )
}

fn status_response(status: StatusCode, command_id: &str, command_status: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": format!("command already {command_status}; refresh its projection"),
            "rejected": format!("command already {command_status}; refresh its projection"),
            "command_id": command_id,
            "command_status": command_status,
        })),
    )
        .into_response()
}

/// Require and materialize a caller key for every mutating local API request.
/// Explicit reducer command routes are skipped because their inner shell can
/// atomically bind the receipt to lifecycle events and return a successful replay.
pub async fn guard(State(wb): State<SharedWorkbench>, request: Request, next: Next) -> Response {
    let method = request.method().clone();
    if matches!(method, Method::GET | Method::HEAD | Method::OPTIONS)
        || reducer_command_path(request.uri().path())
        || environment_command_path(request.uri().path())
    {
        return next.run(request).await;
    }

    let key = match caller_idempotency_key(request.headers()) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let uri = request.uri().to_string();
    let caller_material = format!(
        "{}\n{}\n{}",
        request
            .headers()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or(""),
        request
            .headers()
            .get("cookie")
            .and_then(|value| value.to_str().ok())
            .unwrap_or(""),
        request
            .headers()
            .get("x-gw-publishable-key")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
    );
    let caller_hash = digest(caller_material.as_bytes());
    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, MAX_COMMAND_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({ "error": "command body exceeds 64 MiB" })),
            )
                .into_response()
        }
    };
    let snapshot = serde_json::json!({
        "method": method.as_str(),
        "path": parts.uri.path(),
        "uri_sha256": digest(uri.as_bytes()),
        "caller_sha256": caller_hash,
        "body_sha256": digest(&bytes),
    })
    .to_string();
    let scope = format!("http-command:{}:{}:{caller_hash}", method, parts.uri.path());
    let command_id = format!(
        "http-command-{}",
        digest(format!("{scope}\n{key}").as_bytes())
    );

    {
        let mut guard = wb.lock_unpoisoned();
        let (receipt, claimed) =
            match guard
                .store_mut()
                .claim_command(&command_id, &scope, &key, &snapshot)
            {
                Ok(receipt) => receipt,
                Err(error) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({ "error": format!("command receipt: {error:?}") })),
                    )
                        .into_response()
                }
            };
        if receipt.snapshot_json != snapshot {
            return status_response(
                StatusCode::CONFLICT,
                &command_id,
                "key-reused-with-different-input",
            );
        }
        if !claimed {
            return status_response(StatusCode::CONFLICT, &command_id, &receipt.status);
        }
    }

    let request = Request::from_parts(parts, Body::from(bytes));
    let response = next.run(request).await;
    let command_status = if response.status().is_success() || response.status().is_redirection() {
        "applied"
    } else if response.status().is_client_error() {
        "rejected"
    } else {
        "expired"
    };
    let _ = wb
        .lock_unpoisoned()
        .store_mut()
        .set_command_status(&command_id, command_status);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_atomic_reducer_command_routes_bypass_the_outer_guard() {
        assert!(reducer_command_path("/placements/i/command"));
        assert!(reducer_command_path("/scopes/s/run/command"));
        assert!(reducer_command_path("/chats/c/resources/r/review/command"));
        assert!(reducer_command_path("/chats/c/resources/r/export/command"));
        assert!(!reducer_command_path("/scopes/s/review/command"));
        assert!(!reducer_command_path("/scopes/s/export/command"));
        assert!(!reducer_command_path("/chats/c/merge/command"));
        assert!(!reducer_command_path("/projects"));
    }

    #[test]
    fn environment_sessions_and_atomic_changes_bypass_the_outer_guard() {
        assert!(environment_command_path(
            "/environments/administration/sessions"
        ));
        assert!(environment_command_path(
            "/environments/administration/commands"
        ));
        assert!(environment_command_path(
            "/environments/administration/changes"
        ));
        assert!(environment_command_path(
            "/environments/administration/changes/change-1/review"
        ));
        assert!(!environment_command_path(
            "/environments/administration/documents/access"
        ));
    }
}
