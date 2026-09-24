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

pub(crate) fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The caller this request speaks for, as a hash of the credentials it carried.
///
/// Shared with the streamed upload route rather than reimplemented there: two
/// spellings of "who is this" would let one key claim two commands, which is
/// exactly what the guard exists to prevent.
pub(crate) fn caller_hash(headers: &HeaderMap) -> String {
    let material = format!(
        "{}\n{}\n{}",
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or(""),
        headers
            .get("cookie")
            .and_then(|value| value.to_str().ok())
            .unwrap_or(""),
        headers
            .get("x-gw-publishable-key")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
    );
    digest(material.as_bytes())
}

/// `(scope, command_id)` for one caller's key against one route.
pub(crate) fn command_identity(
    method: &Method,
    path: &str,
    caller_hash: &str,
    key: &str,
) -> (String, String) {
    let scope = format!("http-command:{method}:{path}:{caller_hash}");
    let command_id = format!(
        "http-command-{}",
        digest(format!("{scope}\n{key}").as_bytes())
    );
    (scope, command_id)
}

/// The replay snapshot. The guard hashes a buffered body; the streamed route
/// hashes the same bytes as they arrive. Same field, same meaning, so a key
/// reused with different input is refused on either path.
pub(crate) fn command_snapshot(
    method: &Method,
    uri: &str,
    path: &str,
    caller_hash: &str,
    body_sha256: &str,
) -> String {
    serde_json::json!({
        "method": method.as_str(),
        "path": path,
        "uri_sha256": digest(uri.as_bytes()),
        "caller_sha256": caller_hash,
        "body_sha256": body_sha256,
    })
    .to_string()
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

fn native_tracker_command_path(path: &str) -> bool {
    let parts: Vec<_> = path.split('/').filter(|part| !part.is_empty()).collect();
    matches!(
        parts.as_slice(),
        ["projects", _, "trackers", _, "issues", _, "complete"]
    )
}

// A folder-whip launch keys its retained command by the caller's header key and
// returns the same invocation on replay (DR-0191); a second claim here would
// answer a retry with a status instead of the run it launched.
fn native_workflow_launch_command(method: &Method, path: &str) -> bool {
    let parts: Vec<_> = path.split('/').collect();
    method == Method::POST
        && matches!(parts.as_slice(),
        ["", "projects", project, "workflows"] if !project.is_empty())
}

// Starting a shipped tutorial keys its launch by the tutorial itself, so every
// ask answers with the one run (WHIP-5); it needs no caller key to be safe.
fn shipped_tutorial_start_command(method: &Method, path: &str) -> bool {
    let parts: Vec<_> = path.split('/').collect();
    method == Method::POST
        && matches!(parts.as_slice(),
        ["", "tutorials", name, "start"] if !name.is_empty())
}

// Running a chat's `.whip` file is the folder-whip launch under another
// address, keyed the same way by the caller's header key.
fn chat_whip_run_command(method: &Method, path: &str) -> bool {
    let parts: Vec<_> = path.split('/').collect();
    method == Method::POST
        && matches!(parts.as_slice(),
        ["", "chats", chat, "whips", "run"] if !chat.is_empty())
}

// This exact typed command owns its receipted outbox and replay. Wrapping it in
// the legacy HTTP claim would hide its admitted result behind a second status
// and reject a safe replay before the command's current authority checks run.
fn native_file_save_command(method: &Method, path: &str) -> bool {
    let parts: Vec<_> = path.split('/').collect();
    method == Method::POST
        && matches!(parts.as_slice(),
        ["", "chats", chat, "file-actions", "save"] if !chat.is_empty())
}

// A streamed upload cannot be hashed before it is read, and this guard hashes
// by buffering. Leaving the route inside it would cap an upload at the buffer
// and spend the file's size in memory — which is the whole reason the streaming
// route exists. So it is exempted here and carries the guarantee itself: the
// handler requires the same `Idempotency-Key`, hashes the bytes as they arrive,
// and claims the command on that hash before anything is admitted. The claim
// happens after the transfer instead of before it; what it refuses is the same.
fn streamed_upload_path(method: &Method, path: &str) -> bool {
    let parts: Vec<_> = path.split('/').collect();
    method == Method::POST
        && matches!(parts.as_slice(),
        ["", "chats", chat, "context", "stream"] if !chat.is_empty())
}

fn gaugeapp_command_path(path: &str) -> bool {
    let parts: Vec<_> = path.split('/').filter(|part| !part.is_empty()).collect();
    matches!(parts.as_slice(), ["gaugeapps", _, "sessions"])
        || matches!(parts.as_slice(), ["gaugeapps", _, "commands"])
        || matches!(parts.as_slice(), ["gaugeapps", _, "proposals"])
        || matches!(parts.as_slice(), ["gaugeapps", _, "proposals", _, "review"])
}

/// Authentication ceremonies own replay protection at their protocol boundary:
/// OIDC state, SAML RelayState + InResponseTo, WebAuthn challenges, one-time
/// native handoff codes, and session revocation. Some of their POSTs are made
/// by an external IdP or a plain browser form, neither of which can supply our
/// application-specific `Idempotency-Key` header. Wrapping them in the generic
/// command receipt guard makes the protocol unreachable before its own verifier
/// can run.
fn authentication_ceremony_path(path: &str) -> bool {
    path == "/auth" || path.starts_with("/auth/")
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
        || gaugeapp_command_path(request.uri().path())
        || authentication_ceremony_path(request.uri().path())
        // This handler binds the header key to an authenticated native action
        // and recovers its actual receipt. The generic uncertain-command cache
        // must not prevent delivery of that original result.
        || native_tracker_command_path(request.uri().path())
        || native_workflow_launch_command(&method, request.uri().path())
        || shipped_tutorial_start_command(&method, request.uri().path())
        || chat_whip_run_command(&method, request.uri().path())
        || native_file_save_command(&method, request.uri().path())
        || streamed_upload_path(&method, request.uri().path())
    {
        return next.run(request).await;
    }

    let key = match caller_idempotency_key(request.headers()) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let uri = request.uri().to_string();
    let caller_hash = caller_hash(request.headers());
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
    let snapshot = command_snapshot(
        &method,
        &uri,
        parts.uri.path(),
        &caller_hash,
        &digest(&bytes),
    );
    let (scope, command_id) = command_identity(&method, parts.uri.path(), &caller_hash, &key);

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
    fn only_the_exact_workflow_launch_post_uses_its_own_idempotency() {
        assert!(native_workflow_launch_command(
            &Method::POST,
            "/projects/p/workflows"
        ));
        for method in [Method::GET, Method::PUT, Method::DELETE] {
            assert!(!native_workflow_launch_command(
                &method,
                "/projects/p/workflows"
            ));
        }
        for path in [
            "/projects//workflows",
            "/projects/p/workflows/",
            "/projects/p/workflows/x",
            "//projects/p/workflows",
            "/chats/p/workflows",
        ] {
            assert!(
                !native_workflow_launch_command(&Method::POST, path),
                "{path}"
            );
        }
    }

    #[test]
    fn only_the_exact_native_save_post_uses_atomic_action_idempotency() {
        assert!(native_file_save_command(
            &Method::POST,
            "/chats/c/file-actions/save"
        ));
        for method in [Method::GET, Method::PUT, Method::DELETE] {
            assert!(!native_file_save_command(
                &method,
                "/chats/c/file-actions/save"
            ));
        }
        for path in [
            "/chats/c/file",
            "/chats/c/file-actions/save/",
            "/chats//file-actions/save",
            "/chats/c/file-actions/save/extra",
            "//chats/c/file-actions/save",
            "/projects/c/file-actions/save",
        ] {
            assert!(!native_file_save_command(&Method::POST, path));
        }
    }

    /// The exemption is a hole in the replay guard, so its shape is pinned:
    /// one method, one exact path, and nothing that merely looks like it.
    #[test]
    fn only_the_exact_streamed_upload_post_leaves_the_outer_guard() {
        assert!(streamed_upload_path(
            &Method::POST,
            "/chats/c/context/stream"
        ));
        for method in [Method::GET, Method::PUT, Method::DELETE] {
            assert!(!streamed_upload_path(&method, "/chats/c/context/stream"));
        }
        for path in [
            // the buffered sibling keeps the guard
            "/chats/c/context/upload",
            "/chats/c/context",
            "/chats/c/context/stream/",
            "/chats//context/stream",
            "/chats/c/context/stream/extra",
            "//chats/c/context/stream",
            "/projects/c/context/stream",
        ] {
            assert!(
                !streamed_upload_path(&Method::POST, path),
                "must not exempt {path}"
            );
        }
    }

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
    fn gaugeapp_sessions_and_atomic_changes_bypass_the_outer_guard() {
        assert!(gaugeapp_command_path("/gaugeapps/administration/sessions"));
        assert!(gaugeapp_command_path("/gaugeapps/administration/commands"));
        assert!(gaugeapp_command_path("/gaugeapps/administration/proposals"));
        assert!(gaugeapp_command_path(
            "/gaugeapps/administration/proposals/change-1/review"
        ));
        assert!(!gaugeapp_command_path(
            "/gaugeapps/administration/pages/people"
        ));
    }

    #[test]
    fn provider_and_browser_authentication_posts_reach_their_own_replay_guards() {
        for path in [
            "/auth/work-email",
            "/auth/saml/acs",
            "/auth/account/authenticate/finish",
            "/auth/mobile/exchange",
            "/auth/logout",
        ] {
            assert!(authentication_ceremony_path(path), "{path}");
        }
        assert!(!authentication_ceremony_path("/account/tenants"));
        assert!(!authentication_ceremony_path("/authorization/policy"));
    }
}
