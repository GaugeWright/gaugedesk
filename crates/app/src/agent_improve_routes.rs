//! Authenticated Home entrypoint for a metered Agent improve campaign.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;

use crate::{
    identity::{ActorAuthentication, AuthenticatedActionContext},
    managed_funding::FundingAuthority,
    LockUnpoisoned, SharedWorkbench,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateAgentImprove {
    edit_chat_id: String,
    campaign_ref: String,
}

fn problem(status: StatusCode, message: &'static str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

/// The request names an existing edit chat and campaign only. Home selects the
/// candidate path, signed policy, new placement identity and verified funding.
pub async fn evaluate(
    State(wb): State<SharedWorkbench>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    authenticated: Option<Extension<AuthenticatedActionContext>>,
    funding: Option<Extension<FundingAuthority>>,
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
    let Some(Extension(funding)) = funding else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Hosted funding authority unavailable",
        );
    };
    if !wb.lock_unpoisoned().hosted_home_mode() {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Hosted Home required");
    }
    let actor = context.actor().as_str().to_owned();
    let tenant_scope = crate::workbench_auth::req_scope(&headers);
    let result = tokio::task::spawn_blocking(move || {
        crate::evaluate_agent_improve_from_hosted(
            &wb,
            &agent_id,
            &body.edit_chat_id,
            &body.campaign_ref,
            &actor,
            &tenant_scope,
            funding,
        )
    })
    .await;
    match result {
        Ok(Ok(evidence)) => Json(evidence).into_response(),
        Ok(Err(error)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        Err(_) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Agent improve worker failed",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::ids::AuthorityId;

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
        let call = |auth, funding| {
            evaluate(
                State(wb.clone()),
                Path("agent".into()),
                HeaderMap::new(),
                auth,
                funding,
                request(),
            )
        };
        assert_eq!(
            call(None, Some(funding())).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(Some(owner.clone()), None).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            call(Some(owner.clone()), Some(funding())).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        wb.lock_unpoisoned().enable_hosted_home_mode();
        let machine = Extension(AuthenticatedActionContext::local_personal_tracker());
        assert_eq!(
            call(Some(machine), Some(funding())).await.status(),
            StatusCode::FORBIDDEN
        );
        // The authenticated and funded request reaches Home's source-owner
        // check; the caller cannot choose candidate bytes or a funding ref.
        assert_eq!(
            call(Some(owner), Some(funding())).await.status(),
            StatusCode::CONFLICT
        );
    }
}
