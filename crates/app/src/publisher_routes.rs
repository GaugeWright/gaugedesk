use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::agent_release::{
    ControlDeploymentRequest, DeploymentFundingSelection, ErasePublicSessionRequest,
    ImportLegacyDeploymentRequest, InspectDeploymentRequest, ListPublicCredentialsRequest,
    ProvisionPublicCredentialRequest, PublishDeploymentRequest, RevokePublicCredentialRequest,
};
use crate::{LockUnpoisoned, SharedWorkbench};

pub async fn publish_deployment(
    State(workbench): State<SharedWorkbench>,
    headers: axum::http::HeaderMap,
    Json(mut request): Json<PublishDeploymentRequest>,
) -> Response {
    // Publishing from a project is its owner's act (DR-0328 §5), which a
    // member of the project may ask for: the deployment stays the owner's and
    // is signed by the owner's key, and its binding records who asked
    // (DR-0453).
    let requested_by = {
        let workbench = workbench.lock_unpoisoned();
        if let Some(refusal) = workbench.placement_deployer_refusal(&headers, &request.placement_id)
        {
            return refusal;
        }
        workbench
            .library
            .project_of_instance(&request.placement_id)
            .and_then(|project| workbench.project_member_requester(&headers, project))
    };
    let structured = request.funding.clone();
    if structured.is_some()
        && (!request.funding_ref.trim().is_empty()
            || !request.credential_ref.trim().is_empty()
            || request.managed_tenant_id.is_some()
            || request.funding_entitlement.is_some())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "funding selection may not also carry legacy funding fields" })),
        )
            .into_response();
    }
    match structured {
        Some(DeploymentFundingSelection::Byok { credential_ref }) => {
            request.funding_ref = credential_ref.clone();
            request.credential_ref = credential_ref;
        }
        Some(DeploymentFundingSelection::Managed {
            tenant_id,
            entitlement,
        }) => {
            request.managed_tenant_id = Some(tenant_id);
            request.funding_entitlement = entitlement;
            if let Some(entitlement) = &request.funding_entitlement {
                request.funding_ref = entitlement.claims.funding_ref.clone();
            }
        }
        None => {}
    }
    let managed_selection =
        matches!(
            request.funding,
            Some(DeploymentFundingSelection::Managed { .. })
        ) || crate::managed_inference::is_managed_funding_ref(&request.funding_ref);
    if managed_selection && request.funding_entitlement.is_none() {
        // Minting here would spend this computer's own account session. A
        // member brings an entitlement its own account minted (DR-0453).
        if requested_by.is_some() {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "a project member's managed deployment carries an entitlement from its own account"
                })),
            )
                .into_response();
        }
        let Some(tenant) = request
            .managed_tenant_id
            .as_deref()
            .map(str::trim)
            .filter(|tenant| !tenant.is_empty())
            .map(str::to_owned)
        else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "managed funding requires an authenticated tenant" })),
            )
                .into_response();
        };
        // Bound to the key this publication will be signed with (DR-0328 §5).
        let publisher_key = match workbench.lock_unpoisoned().publication_publisher_key(
            &request.placement_id,
            &request.edge_origin,
            &request.deployment_id,
        ) {
            Ok(key) => key,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": error.to_string() })),
                )
                    .into_response()
            }
        };
        match crate::account_signin::mint_managed_entitlement(&workbench, &tenant, &publisher_key)
            .await
        {
            Ok(entitlement) => {
                request.funding_ref = entitlement.claims.funding_ref.clone();
                request.funding_entitlement = Some(entitlement);
            }
            Err((status, message)) => {
                return (status, Json(json!({ "error": message }))).into_response()
            }
        }
    }
    let result = tokio::task::spawn_blocking(move || {
        let mut workbench = workbench.lock_unpoisoned();
        request.work_chat_default_model = work_chat_default_model(
            &workbench,
            &headers,
            &request.placement_id,
            requested_by.is_some(),
        );
        request.requested_by = requested_by.clone();
        let published = workbench.publish_agent_deployment(request);
        if let (Ok(outcome), Some(member)) = (&published, &requested_by) {
            crate::audit::record(
                &mut workbench,
                member,
                "deployment.publish",
                &outcome.binding_id,
            );
        }
        published
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

/// The publisher's work-chat default model, which an unpinned Panel version
/// publishes with (DR-0272): the caller's, or, when a member of the project
/// asks, its owner's, whose key publishes it (DR-0453).
fn work_chat_default_model(
    workbench: &crate::Workbench,
    headers: &axum::http::HeaderMap,
    placement: &str,
    member: bool,
) -> Option<String> {
    let scope = if member {
        match workbench
            .library
            .project_of_instance(placement)
            .and_then(|project| workbench.project_owner(project))
        {
            Some(crate::project_owner::ProjectOwner::Account(owner)) => {
                workbench.desktop_account_store_scope(&owner)
            }
            _ => crate::account::ACCOUNT_SCOPE.to_owned(),
        }
    } else {
        workbench.credential_scope_for(crate::net_http::bearer(headers))
    };
    workbench.work_chat_default_model_in(&scope).1
}

/// Refuse what would give a project member reached over the relay a
/// publisher key of its own on this computer, which keeps nothing of a
/// member's (DR-0451 §2): naming no publication, it has no key here to name.
fn member_session_refusal(
    workbench: &crate::Workbench,
    headers: &axum::http::HeaderMap,
) -> Option<Response> {
    let member = crate::net_http::bearer(headers)
        .and_then(|token| workbench.resolve_account_session(token))
        .is_some_and(|(_, method)| method == crate::desktop_session::MEMBER_METHOD);
    member.then(|| {
        (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "a project member publishes from its project's placement, under its owner's key"
            })),
        )
            .into_response()
    })
}

/// The account a request publishes as (DR-0328 §5): a desktop account
/// session's own. `None` — the install's key — for the credential-free local
/// channel, which is the local account, and for every hosted composition.
fn publisher_account(
    workbench: &crate::Workbench,
    headers: &axum::http::HeaderMap,
) -> Option<String> {
    if !workbench.desktop_account_mode() {
        return None;
    }
    crate::net_http::bearer(headers)
        .and_then(|token| workbench.resolve_account_session(token))
        .map(|(account, _)| account)
}

/// Names the publication a key is asked for: the placement it is published
/// from and the deployment on the edge it updates or creates.
#[derive(Debug, Default, serde::Deserialize)]
pub struct PublisherAuthorityQuery {
    placement_id: Option<String>,
    edge_origin: Option<String>,
    deployment_id: Option<String>,
}

/// Public half of a publisher key, which signs the commands it publishes
/// with. Hosted account planes use this to mint an entitlement before the
/// Home publishes; no private key or bearer crosses this route.
///
/// Named a publication (`placement_id`, `edge_origin`, `deployment_id`), it
/// answers with the key that publication will be signed with — the existing
/// deployment's, else the project owner's (DR-0328 §5) — which is the key an
/// entitlement minted for it must name. Reading it is the placement owner's,
/// as publishing is. Unnamed, it answers with the caller's own key.
pub async fn publisher_authority(
    State(workbench): State<SharedWorkbench>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<PublisherAuthorityQuery>,
) -> Response {
    let workbench = workbench.lock_unpoisoned();
    let key = match (query.placement_id, query.edge_origin, query.deployment_id) {
        (None, None, None) => {
            if let Some(refusal) = member_session_refusal(&workbench, &headers) {
                return refusal;
            }
            let account = publisher_account(&workbench, &headers);
            workbench.public_publisher_key_as(account.as_deref())
        }
        (Some(placement), Some(edge), Some(deployment))
            if !placement.trim().is_empty() && !deployment.trim().is_empty() =>
        {
            if let Some(refusal) = workbench.placement_deployer_refusal(&headers, &placement) {
                return refusal;
            }
            match workbench.publication_publisher_key(&placement, &edge, &deployment) {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput
                    ) =>
                {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": error.to_string() })),
                    )
                        .into_response()
                }
                answer => answer,
            }
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "a publication is named by placement_id, edge_origin and deployment_id together"
                })),
            )
                .into_response()
        }
    };
    match key {
        Ok(public_key) => {
            (StatusCode::OK, Json(json!({ "public_key": public_key }))).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

pub async fn import_legacy_deployment(
    State(workbench): State<SharedWorkbench>,
    headers: axum::http::HeaderMap,
    Json(request): Json<ImportLegacyDeploymentRequest>,
) -> Response {
    if let Some(refusal) = workbench
        .lock_unpoisoned()
        .placement_owner_refusal(&headers, &request.placement_id)
    {
        return refusal;
    }
    let result = tokio::task::spawn_blocking(move || {
        workbench
            .lock_unpoisoned()
            .import_legacy_public_deployment(request)
    })
    .await;
    match result {
        Ok(Ok(value)) => (StatusCode::CREATED, Json(value)).into_response(),
        Ok(Err(error)) => (
            collection_status(&error),
            Json(json!({ "error": error.to_string() })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "publisher task failed" })),
        )
            .into_response(),
    }
}

pub async fn inspect_deployment(
    State(workbench): State<SharedWorkbench>,
    headers: axum::http::HeaderMap,
    Json(request): Json<InspectDeploymentRequest>,
) -> Response {
    // Reading a deployment's live state is part of deploying it, which a
    // member of its project may do (DR-0453).
    if let Some(refusal) = workbench
        .lock_unpoisoned()
        .deployment_deployer_refusal(&headers, &request.deployment_id)
    {
        return refusal;
    }
    publisher_task(workbench, move |workbench| {
        workbench.inspect_public_deployment(request)
    })
    .await
}

pub async fn control_deployment(
    State(workbench): State<SharedWorkbench>,
    headers: axum::http::HeaderMap,
    Json(request): Json<ControlDeploymentRequest>,
) -> Response {
    if let Some(refusal) = workbench
        .lock_unpoisoned()
        .deployment_owner_refusal(&headers, &request.deployment_id)
    {
        return refusal;
    }
    publisher_task(workbench, move |workbench| {
        workbench.control_public_deployment(request)
    })
    .await
}

pub async fn erase_session(
    State(workbench): State<SharedWorkbench>,
    headers: axum::http::HeaderMap,
    Json(request): Json<ErasePublicSessionRequest>,
) -> Response {
    if let Some(refusal) = workbench
        .lock_unpoisoned()
        .deployment_owner_refusal(&headers, &request.deployment_id)
    {
        return refusal;
    }
    publisher_task(workbench, move |workbench| {
        workbench.erase_public_session(request)
    })
    .await
}

pub async fn list_credentials(
    State(workbench): State<SharedWorkbench>,
    headers: axum::http::HeaderMap,
    Json(request): Json<ListPublicCredentialsRequest>,
) -> Response {
    {
        let guard = workbench.lock_unpoisoned();
        // Named a placement, the list is of the key deploying from it signs
        // with, which a member of its project may choose among (DR-0453).
        let refusal = match request.placement_id.as_deref() {
            Some(placement) => guard.placement_deployer_refusal(&headers, placement),
            None => member_session_refusal(&guard, &headers),
        };
        if let Some(refusal) = refusal {
            return refusal;
        }
    }
    publisher_task(workbench, move |workbench| {
        let account = publisher_account(workbench, &headers);
        workbench.list_public_credentials(request, account.as_deref())
    })
    .await
}

pub async fn provision_credential(
    State(workbench): State<SharedWorkbench>,
    headers: axum::http::HeaderMap,
    Json(request): Json<ProvisionPublicCredentialRequest>,
) -> Response {
    if let Some(refusal) = member_session_refusal(&workbench.lock_unpoisoned(), &headers) {
        return refusal;
    }
    publisher_task(workbench, move |workbench| {
        let account = publisher_account(workbench, &headers);
        workbench.provision_public_credential(request, account.as_deref())
    })
    .await
}

pub async fn revoke_credential(
    State(workbench): State<SharedWorkbench>,
    headers: axum::http::HeaderMap,
    Json(request): Json<RevokePublicCredentialRequest>,
) -> Response {
    if let Some(refusal) = member_session_refusal(&workbench.lock_unpoisoned(), &headers) {
        return refusal;
    }
    publisher_task(workbench, move |workbench| {
        let account = publisher_account(workbench, &headers);
        workbench.revoke_public_credential(request, account.as_deref())
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
    headers: axum::http::HeaderMap,
    Json(request): Json<crate::agent_release::CollectIntoProjectRequest>,
) -> Response {
    if let Some(refusal) = workbench
        .lock_unpoisoned()
        .deployment_owner_refusal(&headers, &request.binding_id)
    {
        return refusal;
    }
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
    /// `keep` or `flag`.
    pub verdict: String,
}

#[derive(serde::Deserialize)]
pub struct ScreenQuarantinedItem {}

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
    headers: axum::http::HeaderMap,
    axum::extract::Path((project_id, item_id)): axum::extract::Path<(String, String)>,
    Json(_request): Json<ScreenQuarantinedItem>,
) -> Response {
    let bearer = crate::net_http::bearer(&headers).map(str::to_owned);
    let result = tokio::task::spawn_blocking(move || {
        // A screening gate coerces with the credential of the person running
        // the pass (or the project's own pin), never one keyed by the project.
        let mut workbench = workbench.lock_unpoisoned();
        let actor = workbench.actor(bearer.as_deref());
        workbench.screen_quarantined_as(
            &actor,
            &project_id,
            &item_id,
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
    headers: axum::http::HeaderMap,
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
    let bearer = crate::net_http::bearer(&headers).map(str::to_owned);
    let result = tokio::task::spawn_blocking(move || {
        // Screening needs a provider; review-by-hand asks a person and calls no
        // model. Not having a credential must therefore not stop a human review,
        // so an absent one degrades to a config the human path never reaches
        // rather than refusing the request.
        let mut workbench = workbench.lock_unpoisoned();
        let actor = workbench.actor(bearer.as_deref());
        workbench.review_quarantined_as(
            &actor,
            &project_id,
            &item_id,
            verdict,
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
