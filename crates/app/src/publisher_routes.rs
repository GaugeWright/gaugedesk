use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::agent_release::{
    ControlDeploymentRequest, ErasePublicSessionRequest, InspectDeploymentRequest,
    ListPublicCredentialsRequest, ProvisionPublicCredentialRequest, PublishDeploymentRequest,
    RevokePublicCredentialRequest,
};
use crate::{LockUnpoisoned, SharedWorkbench};

pub async fn publish_deployment(
    State(workbench): State<SharedWorkbench>,
    Json(request): Json<PublishDeploymentRequest>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        workbench
            .lock_unpoisoned()
            .publish_agent_deployment(request)
    })
    .await;
    match result {
        Ok(Ok(outcome)) => (StatusCode::OK, Json(json!({ "deployment": outcome }))).into_response(),
        Ok(Err(error)) => {
            let status = match error.kind() {
                std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput => {
                    StatusCode::BAD_REQUEST
                }
                std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
                _ => StatusCode::BAD_GATEWAY,
            };
            (status, Json(json!({ "error": error.to_string() }))).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "publisher task failed" })),
        )
            .into_response(),
    }
}

pub async fn inspect_deployment(
    State(workbench): State<SharedWorkbench>,
    Json(request): Json<InspectDeploymentRequest>,
) -> Response {
    publisher_task(workbench, move |workbench| {
        workbench.inspect_public_deployment(request)
    })
    .await
}

pub async fn control_deployment(
    State(workbench): State<SharedWorkbench>,
    Json(request): Json<ControlDeploymentRequest>,
) -> Response {
    publisher_task(workbench, move |workbench| {
        workbench.control_public_deployment(request)
    })
    .await
}

pub async fn erase_session(
    State(workbench): State<SharedWorkbench>,
    Json(request): Json<ErasePublicSessionRequest>,
) -> Response {
    publisher_task(workbench, move |workbench| {
        workbench.erase_public_session(request)
    })
    .await
}

pub async fn list_credentials(
    State(workbench): State<SharedWorkbench>,
    Json(request): Json<ListPublicCredentialsRequest>,
) -> Response {
    publisher_task(workbench, move |workbench| {
        workbench.list_public_credentials(request)
    })
    .await
}

pub async fn provision_credential(
    State(workbench): State<SharedWorkbench>,
    Json(request): Json<ProvisionPublicCredentialRequest>,
) -> Response {
    publisher_task(workbench, move |workbench| {
        workbench.provision_public_credential(request)
    })
    .await
}

pub async fn revoke_credential(
    State(workbench): State<SharedWorkbench>,
    Json(request): Json<RevokePublicCredentialRequest>,
) -> Response {
    publisher_task(workbench, move |workbench| {
        workbench.revoke_public_credential(request)
    })
    .await
}

/// The collection recipient keyrings this Home holds (ADR 0109 §7).
///
/// Public halves and ids only. The private seed never leaves the Home — it is
/// what opens a drained artifact, and the session host is handed the public half
/// alone, which is the whole shape of the collection contract.
pub async fn list_collection_recipients(State(workbench): State<SharedWorkbench>) -> Response {
    let workbench = workbench.lock_unpoisoned();
    let store = workbench.collection_recipients();
    let people: Vec<serde_json::Value> = store
        .list()
        .into_iter()
        .filter_map(|id| {
            let recipient = store.ensure(&id).ok()?;
            Some(json!({
                "recipient_id": id,
                "recipient_ref": recipient.recipient_ref,
                "public_key_hex": recipient.public_key_hex,
            }))
        })
        .collect();
    (StatusCode::OK, Json(json!({ "recipients": people }))).into_response()
}

#[derive(serde::Deserialize)]
pub struct EnsureCollectionRecipient {
    pub recipient_id: String,
}

/// Load or create a recipient keyring, returning its publishable half.
///
/// Idempotent by design: republishing a deployment must reuse the same keyring
/// rather than minting a second one, because artifacts already sealed to the
/// first would otherwise become unopenable.
pub async fn ensure_collection_recipient(
    State(workbench): State<SharedWorkbench>,
    Json(request): Json<EnsureCollectionRecipient>,
) -> Response {
    let workbench = workbench.lock_unpoisoned();
    match workbench.ensure_collection_recipient(&request.recipient_id) {
        Ok(recipient) => (
            StatusCode::OK,
            Json(json!({
                "recipient_id": request.recipient_id,
                "recipient_ref": recipient.recipient_ref,
                "public_key_hex": recipient.public_key_hex,
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

/// Drain a deployment's collections into a project's quarantine.
///
/// Takes the whole `SharedWorkbench` rather than a guard: the drain checks out
/// what it needs under a brief lock and then runs the network round trip and the
/// per-artifact crypto holding none of it (ADR 0115 §5). `spawn_blocking` keeps
/// the async runtime free; it never made the lock hold acceptable.
pub async fn collect_into_project(
    State(workbench): State<SharedWorkbench>,
    Json(request): Json<crate::agent_release::CollectIntoProjectRequest>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        crate::agent_release::collect_into_project(&workbench, request)
    })
    .await;
    match result {
        Ok(Ok(outcome)) => (StatusCode::OK, Json(json!({ "collected": outcome }))).into_response(),
        Ok(Err(error)) => {
            let status = collection_status(&error);
            // `collection_status` sends every unclassified kind to `502`, so the
            // status alone cannot say whether an upstream really failed or the
            // catch-all fired. The canary retries `502` as transient and the
            // Home logged 66 of these over three days without once saying why.
            //
            // The kind, not the message: an `ErrorKind` is a closed enum that
            // carries no path, identifier, or customer payload, and it is the
            // one fact that distinguishes the buckets.
            tracing::warn!(
                status = status.as_u16(),
                kind = ?error.kind(),
                "collection into project failed"
            );
            (status, Json(json!({ "error": error.to_string() }))).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "publisher task failed" })),
        )
            .into_response(),
    }
}

/// A project's quarantine index: what has arrived, what the gate has ruled on,
/// and the count the top bar shows.
///
/// Provenance only. Reading an item's content is the gate's path and the review
/// surface's, never an agent's — no file store root resolves into quarantine
/// (ADR 0110 §1).
pub async fn list_project_quarantine(
    State(workbench): State<SharedWorkbench>,
    axum::extract::Path(project_id): axum::extract::Path<String>,
) -> Response {
    let workbench = workbench.lock_unpoisoned();
    let items = match crate::quarantine::list(workbench.store_ref(), &project_id) {
        Ok(items) => items,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("{error:?}") })),
            )
                .into_response()
        }
    };
    let pending = items
        .iter()
        .filter(|item| matches!(item.status, crate::quarantine::ItemStatus::Pending))
        .count();
    (
        StatusCode::OK,
        Json(json!({
            "project_id": project_id,
            "pending": pending,
            "items": items,
        })),
    )
        .into_response()
}

/// Read one quarantined item so a person can review it.
///
/// Returned as text for the content viewer. This is the reviewer's path, not an
/// agent's — no file store resolves into quarantine, so an agent cannot reach
/// these bytes by any route including this one.
pub async fn get_quarantined_item(
    State(workbench): State<SharedWorkbench>,
    axum::extract::Path((project_id, item_id)): axum::extract::Path<(String, String)>,
) -> Response {
    let workbench = workbench.lock_unpoisoned();
    match workbench.read_quarantined_item(&project_id, &item_id) {
        Ok(bytes) => (
            StatusCode::OK,
            [("content-type", "application/json")],
            String::from_utf8_lossy(&bytes).into_owned(),
        )
            .into_response(),
        Err(error) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct ReviewQuarantinedItem {
    pub chat_id: String,
    /// `keep` or `flag`.
    pub verdict: String,
}

#[derive(serde::Deserialize)]
pub struct ScreenQuarantinedItem {
    pub chat_id: String,
}

/// Run this project's gate over one quarantined item (ADR 0117 §1).
///
/// This is the gate's *first* pass and the entry to everything downstream: the
/// program either rules on the item outright or parks on a person, and only a
/// parked question makes the review route meaningful — a verdict delivered to a
/// gate that was never run has no queue to be filed against, so it settles
/// nothing and the item stays pending.
///
/// `run_project_gate` existed and was tested from the day `GATE-3` landed, but
/// nothing routed to it, so the screening pass could not be reached from the
/// running product at all.
pub async fn screen_quarantined_item(
    State(workbench): State<SharedWorkbench>,
    axum::extract::Path((project_id, item_id)): axum::extract::Path<(String, String)>,
    Json(request): Json<ScreenQuarantinedItem>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        // Whether this pass needs a model is the *gate program's* business, not
        // the route's. The default gate is review-by-hand: it reads the item,
        // files a question, and parks, coercing nowhere — so demanding a
        // credential here would lock every review-by-hand project out of the
        // only pass that can park a question for it to answer. A project that
        // installs the screening gate genuinely does need one, and gets an
        // obvious refusal from an unreachable host rather than a silent call
        // somewhere real.
        let coerce =
            crate::gate_service::gate_coercion_config(&workbench, &request.chat_id, "gpt-4.1-mini")
                .unwrap_or_else(|_| crate::gate_service::unusable_coercion_config());
        workbench.lock_unpoisoned().run_project_gate(
            &project_id,
            &item_id,
            &request.chat_id,
            &coerce,
            &crate::gate_service::HttpGateTransport,
        )
    })
    .await;
    match result {
        // `None` is the gate parking on a person, which is the ordinary
        // review-by-hand case and not a failure.
        Ok(Ok(landed)) => (
            StatusCode::OK,
            Json(json!({ "workspace_path": landed, "parked": landed.is_none() })),
        )
            .into_response(),
        Ok(Err(error)) => (
            collection_status(&error),
            Json(json!({ "error": error.to_string() })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "screening task failed" })),
        )
            .into_response(),
    }
}

/// A human reviewer's verdict on one quarantined item (ADR 0110 §3, §6).
///
/// The route is the *transport* for the answer, never the decider: it hands the
/// verdict to the project's gate, which files it into the queue it is parked
/// against and rules. Before `GATE-3h` this called `apply_verdict` directly,
/// which made it exactly the "privileged runtime service" ADR 0110 §2 rules out.
pub async fn review_quarantined_item(
    State(workbench): State<SharedWorkbench>,
    axum::extract::Path((project_id, item_id)): axum::extract::Path<(String, String)>,
    Json(request): Json<ReviewQuarantinedItem>,
) -> Response {
    let verdict = match request.verdict.as_str() {
        "keep" => crate::gate::Verdict::Keep,
        "flag" => crate::gate::Verdict::Flag,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("unknown verdict: {other}") })),
            )
                .into_response()
        }
    };
    let result = tokio::task::spawn_blocking(move || {
        // Screening needs a provider; review-by-hand asks a person and calls no
        // model. Not having a credential must therefore not stop a human review,
        // so an absent one degrades to a config the human path never reaches
        // rather than refusing the request.
        let coerce =
            crate::gate_service::gate_coercion_config(&workbench, &request.chat_id, "gpt-4.1-mini")
                .unwrap_or_else(|_| crate::gate_service::unusable_coercion_config());
        workbench.lock_unpoisoned().review_through_gate(
            &project_id,
            &item_id,
            &request.chat_id,
            verdict,
            &coerce,
            &crate::gate_service::HttpGateTransport,
        )
    })
    .await;
    match result {
        Ok(Ok(landed)) => {
            (StatusCode::OK, Json(json!({ "workspace_path": landed }))).into_response()
        }
        Ok(Err(error)) => (
            collection_status(&error),
            Json(json!({ "error": error.to_string() })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "review task failed" })),
        )
            .into_response(),
    }
}

fn collection_status(error: &std::io::Error) -> StatusCode {
    // An edge refusal knows the status the edge gave. Reporting a `422` as
    // `502` told every caller the upstream had failed when it had in fact
    // declined the request, and a `502` is what `drainUntilLanded` retries — so
    // a client error was retried a hundred and twenty times as though a service
    // were down, then reported as an overloaded origin.
    if let Some(rejection) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<crate::agent_release::EdgeRejection>())
    {
        let mapped = crate::agent_release::edge_rejection_status(rejection.status);
        return StatusCode::from_u16(mapped).unwrap_or(StatusCode::BAD_GATEWAY);
    }
    match error.kind() {
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput => {
            StatusCode::BAD_REQUEST
        }
        std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
        _ => StatusCode::BAD_GATEWAY,
    }
}

async fn publisher_task(
    workbench: SharedWorkbench,
    command: impl FnOnce(&crate::Workbench) -> std::io::Result<serde_json::Value> + Send + 'static,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let workbench = workbench.lock_unpoisoned();
        command(&workbench)
    })
    .await;
    match result {
        Ok(Ok(value)) => (StatusCode::OK, Json(value)).into_response(),
        Ok(Err(error)) => {
            let status = match error.kind() {
                std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput => {
                    StatusCode::BAD_REQUEST
                }
                std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
                _ => StatusCode::BAD_GATEWAY,
            };
            (status, Json(json!({ "error": error.to_string() }))).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "publisher task failed" })),
        )
            .into_response(),
    }
}
