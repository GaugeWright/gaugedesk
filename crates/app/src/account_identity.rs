//! Which account a bearer belongs to, answered by the Hub (DR-0206).
//!
//! A desktop Home cannot judge the credentials remote callers present: desk
//! and the mobile app send a provider id-token or an opaque Hub session, and
//! the desktop has neither the provider's configuration nor the account links
//! that turn one into an account. The Hub has both — it is where the bearer was
//! minted or is honoured — so a Home asks it here. The owner relay checks that
//! account against its owner; the office staff boundary requires bounded source
//! session evidence and independently checks local standing (DR-0262).
//!
//! The answer is the same judgement every `/account/*` route makes about its
//! caller: [`Workbench::authenticate_bearer`], which resolves an opaque session
//! the Hub minted, or a verified id-token through its account link.

use axum::{extract::State, http::HeaderMap, http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

use crate::{net_http, LockUnpoisoned, SharedWorkbench, Workbench};

/// What `GET /account/identity` answers.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AccountIdentity {
    /// The account id — the account's root public key.
    pub account: String,
    /// Present only for a currently verified durable opaque session. Older Hub
    /// responses and verified external id-tokens carry no durable evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<crate::account_session::AccountSessionEvidence>,
}

/// `GET /account/identity` — the [`AccountIdentity`] of the presented bearer.
pub async fn get_account_identity(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> axum::response::Response {
    let wb = wb.lock_unpoisoned();
    identity_response(
        &wb,
        net_http::bearer(&headers),
        crate::workbench_auth::web_account_mode(),
    )
}

fn identity_response(
    wb: &Workbench,
    bearer: Option<&str>,
    on_hub: bool,
) -> axum::response::Response {
    let mut response = match bearer_identity(wb, bearer, on_hub) {
        Ok(identity) => (StatusCode::OK, Json(identity)).into_response(),
        Err((status, message)) => (status, Json(json!({ "error": message }))).into_response(),
    };
    // This answers current session standing. An intermediary must never replay
    // a formerly live identity after revocation or reuse a cached refusal.
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

/// The account `bearer` authenticates as, on a Hub.
///
/// Anywhere else this route does not exist: a desktop answers every caller as
/// its local operator, so its answer would name someone who never presented
/// anything, and a Home that asked it would admit them.
fn bearer_identity(
    wb: &Workbench,
    bearer: Option<&str>,
    on_hub: bool,
) -> Result<AccountIdentity, (StatusCode, &'static str)> {
    if !on_hub {
        return Err((StatusCode::NOT_FOUND, "not served here"));
    }
    let token = bearer.ok_or((StatusCode::UNAUTHORIZED, "present a bearer to identify"))?;
    if let Some((account, session)) = wb.account_session_evidence(token) {
        return Ok(AccountIdentity {
            account,
            session: Some(session),
        });
    }
    wb.authenticate_bearer(token)
        .map(|authority| AccountIdentity {
            account: authority.as_str().to_owned(),
            session: None,
        })
        .ok_or((StatusCode::UNAUTHORIZED, "this bearer is not recognised"))
}

#[cfg(test)]
fn bearer_account(
    wb: &Workbench,
    bearer: Option<&str>,
    on_hub: bool,
) -> Result<String, (StatusCode, &'static str)> {
    bearer_identity(wb, bearer, on_hub).map(|identity| identity.account)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LoopbackIdentityProvider;
    use gaugedesk_core::abac::AuthorityAttributes;
    use gaugedesk_core::ids::AuthorityId;
    use std::sync::Arc;

    fn hub() -> Workbench {
        let mut wb = Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap());
        wb.set_identity_provider(Some(Arc::new(LoopbackIdentityProvider::new().enroll(
            "alice-login",
            AuthorityId::new("alice"),
            AuthorityAttributes::default(),
        ))));
        wb
    }

    #[test]
    fn names_the_account_a_recognised_bearer_belongs_to() {
        assert_eq!(
            bearer_account(&hub(), Some("alice-login"), true),
            Ok("alice".to_owned())
        );
    }

    #[test]
    fn an_opaque_session_the_hub_minted_names_its_account() {
        let mut wb = hub();
        let token = wb
            .mint_account_session("account-root", "test", 60)
            .expect("session");
        assert_eq!(
            bearer_account(&wb, Some(&token), true),
            Ok("account-root".to_owned())
        );
    }

    #[tokio::test]
    async fn identity_http_response_is_current_and_never_cacheable() {
        use axum::{body::Body, http::Request, routing::get, Router};
        use http_body_util::BodyExt;
        use std::sync::Mutex;
        use tower::ServiceExt;
        let mut workbench = hub();
        let token = workbench
            .mint_account_session("account-root", "passkey", 60)
            .unwrap();
        let wb = Arc::new(Mutex::new(workbench));
        let app = Router::new()
            .route(
                "/account/identity",
                get(
                    |State(wb): State<SharedWorkbench>, headers: HeaderMap| async move {
                        identity_response(&wb.lock_unpoisoned(), net_http::bearer(&headers), true)
                    },
                ),
            )
            .with_state(wb.clone());
        let request = || {
            Request::builder()
                .uri("/account/identity")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap()
        };
        let response = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[axum::http::header::CACHE_CONTROL],
            "no-store"
        );
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let identity: AccountIdentity = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(identity.account, "account-root");
        assert!(identity.session.is_some());
        wb.lock_unpoisoned().revoke_account_session(&token);
        let refusal = app.oneshot(request()).await.unwrap();
        assert_eq!(refusal.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            refusal.headers()[axum::http::header::CACHE_CONTROL],
            "no-store"
        );
    }

    #[test]
    fn opaque_session_response_is_bounded_and_contains_no_credentials_or_work() {
        let mut wb = hub();
        let token = wb
            .mint_account_session("account-root", "consumer-oidc:google", 60)
            .unwrap();
        let identity = bearer_identity(&wb, Some(&token), true).unwrap();
        let evidence = identity.session.as_ref().unwrap();
        assert_eq!(
            evidence.session_ref,
            crate::account_session::session_id(&token)
        );
        assert_eq!(evidence.method, "consumer-oidc:google");
        assert!(evidence.issued_at_ms > 0);
        assert!(evidence.expires_at_ms > crate::account::session_now_ms());
        assert!(evidence.expires_at_ms <= evidence.issued_at_ms + 60_000);
        let body = serde_json::to_value(identity).unwrap();
        assert_eq!(body["account"], "account-root");
        assert_eq!(body.as_object().unwrap().len(), 2);
        assert_eq!(body["session"].as_object().unwrap().len(), 4);
        assert!(!body.to_string().contains(&token));
        wb.revoke_account_session(&token);
        assert_eq!(
            bearer_identity(&wb, Some(&token), true).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn external_tokens_and_older_hubs_do_not_invent_durable_session_evidence() {
        let identity = bearer_identity(&hub(), Some("alice-login"), true).unwrap();
        assert!(identity.session.is_none());
        assert_eq!(
            serde_json::to_value(identity).unwrap(),
            json!({"account": "alice"})
        );
        let old: AccountIdentity = serde_json::from_value(json!({"account": "alice"})).unwrap();
        assert!(old.session.is_none());
    }

    #[test]
    fn an_idle_opaque_session_cannot_supply_an_account_only_fallback() {
        let mut wb = hub();
        let token = wb
            .mint_account_session("account-root", "oidc", 30 * 24 * 60 * 60)
            .unwrap();
        let mut record = crate::account_auth::AccountAuth::rebuild(wb.store_ref())
            .unwrap()
            .sessions[&crate::account_session::session_id(&token)]
            .clone();
        record.issued_at_ms -= crate::account::SESSION_IDLE_MS + 1;
        record.last_seen_ms = record.issued_at_ms;
        crate::account_auth::append_facts(
            wb.store_mut(),
            &[crate::account_auth::AccountAuthFact::Session(record)],
        )
        .unwrap();
        assert!(wb.account_sessions().resolve_now(&token).is_some());
        assert_eq!(
            bearer_identity(&wb, Some(&token), true).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn refuses_an_absent_or_unknown_bearer() {
        let wb = hub();
        assert_eq!(
            bearer_account(&wb, None, true).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            bearer_account(&wb, Some("forged"), true).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
    }

    /// A desktop would answer "the local operator" for anyone, which is the
    /// very thing DR-0206 exists to stop being mistaken for an identity.
    #[test]
    fn is_not_served_off_the_hub() {
        let wb = Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap());
        assert_eq!(
            bearer_account(&wb, Some("anything"), false).unwrap_err().0,
            StatusCode::NOT_FOUND
        );
    }
}
