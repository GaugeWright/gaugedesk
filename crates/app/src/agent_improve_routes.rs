//! Authenticated Home entrypoint for a metered Agent improve campaign.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    identity::{ActorAuthentication, AuthenticatedActionContext},
    managed_funding::FundingAuthority,
    LockUnpoisoned, SharedWorkbench,
};

/// Only a hosted Home with a durable campaign queue may install this request
/// extension. Enqueue persists the exact human, tenant, Agent, edit chat, and
/// campaign before the HTTP request ends. The Home's worker later installs
/// the admitted pair factory; a generic DO bearer is never an authority.
#[derive(Clone)]
pub struct HostedImproveCampaignQueue(pub Arc<dyn HostedImproveJobQueue>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostedImproveJobInput {
    pub operation_id: String,
    pub tenant_scope: String,
    pub actor: String,
    pub agent_id: String,
    pub edit_chat_id: String,
    pub campaign_ref: String,
}

#[derive(Serialize)]
pub struct HostedImproveQueued {
    pub operation_id: String,
    pub phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
}

pub trait HostedImproveJobQueue: Send + Sync {
    fn enqueue(&self, input: HostedImproveJobInput) -> Result<HostedImproveQueued, String>;
    fn status(
        &self,
        operation_id: &str,
        tenant_scope: &str,
        actor: &str,
        agent_id: &str,
    ) -> Result<Option<HostedImproveQueued>, String>;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateAgentImprove {
    edit_chat_id: String,
    campaign_ref: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewAgentImprove {
    campaign_ref: String,
}

#[derive(Serialize)]
pub struct AdoptAgentImproveResult {
    changed_paths: Vec<String>,
}

fn problem(status: StatusCode, message: &'static str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

fn hosted_owner(
    wb: &SharedWorkbench,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
) -> Result<String, (StatusCode, &'static str)> {
    let Some(Extension(context)) = authenticated else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Authenticated Home admission required",
        ));
    };
    if !matches!(
        context.authentication(),
        ActorAuthentication::AccountSession { .. } | ActorAuthentication::IdentityProvider
    ) {
        return Err((
            StatusCode::FORBIDDEN,
            "Agent improve requires a human owner",
        ));
    }
    if !wb.lock_unpoisoned().hosted_home_mode() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "Hosted Home required"));
    }
    Ok(context.actor().as_str().to_owned())
}

/// Read only the aggregate reviewer card for a campaign owned by this Home's
/// authenticated Agent source owner. Sealed cases and candidate bytes stay in
/// Home custody.
pub async fn review(
    State(wb): State<SharedWorkbench>,
    Path(agent_id): Path<String>,
    Query(body): Query<ReviewAgentImprove>,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
) -> Response {
    let actor = match hosted_owner(&wb, authenticated) {
        Ok(actor) => actor,
        Err((status, message)) => return problem(status, message),
    };
    let guard = wb.lock_unpoisoned();
    if guard
        .verify_agent_improve_source_owner(&agent_id, Some(&actor))
        .is_err()
    {
        return problem(StatusCode::FORBIDDEN, "Agent improve source owner required");
    }
    match guard.latest_agent_improve_evidence_for_source_owner(
        &agent_id,
        &body.campaign_ref,
        Some(&actor),
    ) {
        Ok(evidence) => Json(evidence).into_response(),
        Err(error) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
    }
}

/// Adoption is a separate owner action. The retained evidence path repeats
/// the campaign, seal, evaluated definition, and current Main-cut checks at
/// its merge lock before changing the draft.
pub async fn adopt(
    State(wb): State<SharedWorkbench>,
    Path((agent_id, evidence_id)): Path<(String, String)>,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
) -> Response {
    let actor = match hosted_owner(&wb, authenticated) {
        Ok(actor) => actor,
        Err((status, message)) => return problem(status, message),
    };
    {
        let guard = wb.lock_unpoisoned();
        if guard
            .verify_agent_improve_source_owner(&agent_id, Some(&actor))
            .is_err()
        {
            return problem(StatusCode::FORBIDDEN, "Agent improve source owner required");
        }
    }
    let result = tokio::task::spawn_blocking(move || {
        wb.lock_unpoisoned()
            .adopt_agent_improve_evidence_for_source_owner(&agent_id, &evidence_id, Some(&actor))
    })
    .await;
    match result {
        Ok(Ok(changed_paths)) => Json(AdoptAgentImproveResult { changed_paths }).into_response(),
        Ok(Err(error)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        Err(_) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Agent adoption worker failed",
        ),
    }
}

/// The request names an existing edit chat and campaign only. Home selects the
/// candidate path, signed policy, new placement identity and verified funding.
pub async fn evaluate(
    State(wb): State<SharedWorkbench>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
    funding: Option<Extension<FundingAuthority>>,
    campaign_queue: Option<Extension<HostedImproveCampaignQueue>>,
    Json(body): Json<EvaluateAgentImprove>,
) -> Response {
    let Some(Extension(context)) = authenticated else {
        return problem(
            StatusCode::UNAUTHORIZED,
            "Authenticated Home admission required",
        );
    };
    if !matches!(
        context.authentication(),
        ActorAuthentication::AccountSession { .. } | ActorAuthentication::IdentityProvider
    ) {
        return problem(
            StatusCode::FORBIDDEN,
            "Agent improve requires a human owner",
        );
    }
    let Some(Extension(_funding)) = funding else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Hosted funding authority unavailable",
        );
    };
    let Some(Extension(HostedImproveCampaignQueue(queue))) = campaign_queue else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Durable hosted improvement is unavailable",
        );
    };
    if !wb.lock_unpoisoned().hosted_home_mode() {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Hosted Home required");
    }
    let operation_id = match crate::command_idempotency::caller_idempotency_key(&headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let actor = context.actor().as_str().to_owned();
    let tenant_scope = crate::workbench_auth::req_scope(&headers);
    if wb
        .lock_unpoisoned()
        .verify_agent_improve_source_owner(&agent_id, Some(&actor))
        .is_err()
    {
        return problem(StatusCode::FORBIDDEN, "Agent improve source owner required");
    }
    let result = tokio::task::spawn_blocking(move || {
        queue.enqueue(HostedImproveJobInput {
            operation_id,
            tenant_scope,
            actor,
            agent_id,
            edit_chat_id: body.edit_chat_id,
            campaign_ref: body.campaign_ref,
        })
    })
    .await;
    match result {
        Ok(Ok(job)) => (StatusCode::ACCEPTED, Json(job)).into_response(),
        Ok(Err(error)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        Err(_) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Agent improve admission worker failed",
        ),
    }
}

/// Poll one durable campaign operation. The queue compares the operation's
/// original human, tenant, and Agent before returning any progress or evidence
/// reference; an unknown or differently owned key has the same 404 result.
pub async fn operation_status(
    State(wb): State<SharedWorkbench>,
    Path((agent_id, operation_id)): Path<(String, String)>,
    headers: HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
    campaign_queue: Option<Extension<HostedImproveCampaignQueue>>,
) -> Response {
    let actor = match hosted_owner(&wb, authenticated) {
        Ok(actor) => actor,
        Err((status, message)) => return problem(status, message),
    };
    let Some(Extension(HostedImproveCampaignQueue(queue))) = campaign_queue else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Durable hosted improvement is unavailable",
        );
    };
    if wb
        .lock_unpoisoned()
        .verify_agent_improve_source_owner(&agent_id, Some(&actor))
        .is_err()
    {
        return problem(StatusCode::FORBIDDEN, "Agent improve source owner required");
    }
    let tenant_scope = crate::workbench_auth::req_scope(&headers);
    let result = tokio::task::spawn_blocking(move || {
        queue.status(&operation_id, &tenant_scope, &actor, &agent_id)
    })
    .await;
    match result {
        Ok(Ok(Some(job))) => Json(job).into_response(),
        Ok(Ok(None)) => problem(StatusCode::NOT_FOUND, "Agent improve operation not found"),
        Ok(Err(_)) | Err(_) => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Agent improve operation status is unavailable",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::ids::AuthorityId;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingQueue(Mutex<Vec<HostedImproveJobInput>>);

    impl HostedImproveJobQueue for RecordingQueue {
        fn enqueue(&self, input: HostedImproveJobInput) -> Result<HostedImproveQueued, String> {
            self.0.lock().unwrap().push(input.clone());
            Ok(HostedImproveQueued {
                operation_id: input.operation_id,
                phase: "queued".into(),
                evidence_id: None,
            })
        }

        fn status(
            &self,
            operation_id: &str,
            _tenant_scope: &str,
            _actor: &str,
            _agent_id: &str,
        ) -> Result<Option<HostedImproveQueued>, String> {
            Ok((operation_id == "op").then(|| HostedImproveQueued {
                operation_id: operation_id.into(),
                phase: "queued".into(),
                evidence_id: None,
            }))
        }
    }

    fn request() -> Json<EvaluateAgentImprove> {
        Json(EvaluateAgentImprove {
            edit_chat_id: "edit-chat".into(),
            campaign_ref: "campaign".into(),
        })
    }

    fn funding() -> Extension<FundingAuthority> {
        Extension(FundingAuthority::new(
            AuthorityId::new("test-funding-issuer"),
            crate::managed_funding::FundingEnvironment::Test,
        ))
    }

    #[tokio::test]
    async fn hosted_entry_requires_verified_human_home_and_server_funding() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let owner = Extension(AuthenticatedActionContext::account_session(
            AuthorityId::new("owner"),
            "session".into(),
        ));
        let call = |auth, funding, admitted_factory| {
            evaluate(
                State(wb.clone()),
                Path("agent".into()),
                HeaderMap::new(),
                auth,
                funding,
                admitted_factory,
                request(),
            )
        };
        assert_eq!(
            call(None, Some(funding()), None).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(Some(owner.clone()), None, None).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            call(Some(owner.clone()), Some(funding()), None)
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        wb.lock_unpoisoned().enable_hosted_home_mode();
        let machine = Extension(AuthenticatedActionContext::local_personal_tracker());
        assert_eq!(
            call(Some(machine), Some(funding()), None).await.status(),
            StatusCode::FORBIDDEN
        );
        // Even a fully authenticated request cannot choose its transport from
        // workbench environment or request data.
        assert_eq!(
            call(Some(owner), Some(funding()), None).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn hosted_entry_enqueues_after_owner_admission_and_status_requires_owner() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        {
            let mut guard = wb.lock_unpoisoned();
            guard.enable_hosted_home_mode();
            let agent = guard.library.agents.get_mut(crate::DEFAULT_AGENT).unwrap();
            agent
                .versions
                .get_mut(&agent.current_version)
                .unwrap()
                .source_owner_authority = Some("owner".into());
        }
        let queue = Arc::new(RecordingQueue::default());
        let extension = Extension(HostedImproveCampaignQueue(queue.clone()));
        let owner = Extension(AuthenticatedActionContext::account_session(
            AuthorityId::new("owner"),
            "session".into(),
        ));
        let outsider = Extension(AuthenticatedActionContext::account_session(
            AuthorityId::new("outsider"),
            "session".into(),
        ));
        let mut headers = HeaderMap::new();
        headers.insert("idempotency-key", "op".parse().unwrap());
        let response = evaluate(
            State(wb.clone()),
            Path(crate::DEFAULT_AGENT.to_owned()),
            headers,
            Some(owner.clone()),
            Some(funding()),
            Some(extension.clone()),
            request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(queue.0.lock().unwrap().len(), 1);
        assert_eq!(queue.0.lock().unwrap()[0].operation_id, "op");
        assert_eq!(
            operation_status(
                State(wb.clone()),
                Path((crate::DEFAULT_AGENT.to_owned(), "op".into())),
                HeaderMap::new(),
                Some(owner),
                Some(extension.clone()),
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            operation_status(
                State(wb),
                Path((crate::DEFAULT_AGENT.to_owned(), "op".into())),
                HeaderMap::new(),
                Some(outsider),
                Some(extension),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn hosted_review_and_adoption_require_the_source_owner() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let owner = Extension(AuthenticatedActionContext::account_session(
            AuthorityId::new("owner"),
            "session".into(),
        ));
        let outsider = Extension(AuthenticatedActionContext::account_session(
            AuthorityId::new("outsider"),
            "session".into(),
        ));
        let review_call = |auth| {
            review(
                State(wb.clone()),
                Path(crate::DEFAULT_AGENT.to_owned()),
                Query(ReviewAgentImprove {
                    campaign_ref: "campaign".into(),
                }),
                auth,
            )
        };
        let adopt_call = |auth| {
            adopt(
                State(wb.clone()),
                Path((crate::DEFAULT_AGENT.to_owned(), "evidence".into())),
                auth,
            )
        };
        assert_eq!(review_call(None).await.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(adopt_call(None).await.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            review_call(Some(owner.clone())).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            adopt_call(Some(owner.clone())).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        {
            let mut guard = wb.lock_unpoisoned();
            guard.enable_hosted_home_mode();
            let agent = guard.library.agents.get_mut(crate::DEFAULT_AGENT).unwrap();
            agent
                .versions
                .get_mut(&agent.current_version)
                .unwrap()
                .source_owner_authority = Some("owner".into());
        }
        for auth in [
            outsider,
            Extension(AuthenticatedActionContext::local_personal_tracker()),
        ] {
            assert_eq!(
                review_call(Some(auth.clone())).await.status(),
                StatusCode::FORBIDDEN
            );
            assert_eq!(adopt_call(Some(auth)).await.status(), StatusCode::FORBIDDEN);
        }
        // The owner reaches the campaign/evidence checks; no campaign or
        // retained candidate can be invented by naming an id in the request.
        assert_eq!(
            review_call(Some(owner.clone())).await.status(),
            StatusCode::CONFLICT
        );
        assert_eq!(adopt_call(Some(owner)).await.status(), StatusCode::CONFLICT);
        let campaign_ref = wb
            .lock_unpoisoned()
            .register_agent_improve_campaign(
                crate::DEFAULT_AGENT,
                br#"{
                  "schema":"gaugedesk.agent-improve.open.v1",
                  "gauges":[{"name":"quality","description":"Return the token"}],
                  "selection":{"ascend":{"quality":null}},
                  "scenarios":[{"id":"open-1","prompt":"Return alpha"}]
                }"#,
                br#"{
                  "schema":"gaugedesk.agent-improve.private.v1",
                  "open_checks":{"open-1":{"quality":{"kind":"assistant-contains","text":"alpha"}}},
                  "sealed_scenarios":[]
                }"#,
            )
            .unwrap();
        let response = review(
            State(wb),
            Path(crate::DEFAULT_AGENT.to_owned()),
            Query(ReviewAgentImprove { campaign_ref }),
            Some(Extension(AuthenticatedActionContext::account_session(
                AuthorityId::new("owner"),
                "session".into(),
            ))),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
