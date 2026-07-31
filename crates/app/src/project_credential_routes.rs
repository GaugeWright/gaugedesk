//! Per-project LLM-access credential overrides (`LLM-2`, [ADR 0062]). A project may pin
//! its own sealed BYOK credential in its coordination scope, overriding the account
//! default for chats in that project (nearest-scope-wins at run time — see
//! [`crate::account::resolved_credential_envs`]). Same discipline as
//! [`crate::account_routes`]: the **plaintext** token is never returned over HTTP — only
//! the sealed ciphertext lives at rest (`SEC-4`/`INV-10`), and the surface lists provider
//! names + a linked flag, never the secret.
//!
//! "Or a managed plan" (ADR 0062) is the LLM-3 managed-execution axis and rides that
//! item; this surface covers the buildable BYOK-credential override.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::{err_response, LockUnpoisoned, SharedWorkbench};

/// `GET /projects/:id/credentials` — the providers this project pins (names + linked
/// flag only; never the token).
pub async fn get_project_credentials(
    State(wb): State<SharedWorkbench>,
    Path(project): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let providers: Vec<serde_json::Value> = wb
        .project_credential_providers(&project)
        .iter()
        .map(|p| json!({ "provider": p, "linked": true }))
        .collect();
    (StatusCode::OK, Json(json!({ "credentials": providers }))).into_response()
}

#[derive(Deserialize)]
pub struct LinkBody {
    provider: String,
    token: String,
    /// OpenAI-compatible endpoint base URL — required for `openai-generic`,
    /// ignored otherwise (ADR 0083). Non-secret.
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    execution_classes: Option<std::collections::BTreeSet<crate::account::ModelExecutionClass>>,
}

/// `POST /projects/:id/credentials` — pin a provider for this project: seal the token
/// (`SEC-4`) and store the ciphertext in the project's coordination scope.
pub async fn post_project_credential(
    State(wb): State<SharedWorkbench>,
    Path(project): Path<String>,
    Json(body): Json<LinkBody>,
) -> impl IntoResponse {
    if body.provider.trim().is_empty() || body.token.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "provider and token are required",
        )
            .into_response();
    }
    let provider = body.provider;
    let base_url = match crate::account::link_base_url_for(&provider, body.base_url.as_deref()) {
        Ok(base_url) => base_url,
        Err(reason) => return (StatusCode::UNPROCESSABLE_ENTITY, reason).into_response(),
    };
    let mut wb = wb.lock_unpoisoned();
    let Some(sealed) = wb.seal_project_secret(&project, &body.token) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "seal failed").into_response();
    };
    let execution_classes = body
        .execution_classes
        .unwrap_or_else(|| wb.default_model_execution_classes());
    if let Err(e) = wb.upsert_project_credential_with_policy(
        &project,
        provider.clone(),
        sealed,
        base_url,
        execution_classes.clone(),
    ) {
        return err_response(e);
    }
    (
        StatusCode::OK,
        Json(json!({
            "provider": provider,
            "linked": true,
            "execution_classes": execution_classes,
        })),
    )
        .into_response()
}

/// `DELETE /projects/:id/credentials/:provider` — drop this project's pin (tombstone),
/// so the project falls back to the account default again.
pub async fn delete_project_credential(
    State(wb): State<SharedWorkbench>,
    Path((project, provider)): Path<(String, String)>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Err(e) = wb.tombstone_project_credential(&project, provider.clone()) {
        return err_response(e);
    }
    (
        StatusCode::OK,
        Json(json!({ "provider": provider, "linked": false })),
    )
        .into_response()
}
