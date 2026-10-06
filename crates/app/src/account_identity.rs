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
    /// Present only when the caller named an address in
    /// [`VERIFIED_EMAIL_HEADER`]: whether this account holds it as an active
    /// verified email (DR-0332). It says nothing about any other account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holds_email: Option<bool>,
}

/// The address a Home asks about when it binds an email invitation to the
/// account accepting it (DR-0332). A header rather than a query parameter, so
/// the address never sits in a URL.
pub const VERIFIED_EMAIL_HEADER: &str = "x-gaugedesk-verified-email";

/// `GET /account/identity` — the [`AccountIdentity`] of the presented bearer.
pub async fn get_account_identity(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> axum::response::Response {
    let wb = wb.lock_unpoisoned();
    let asked = headers
        .get(VERIFIED_EMAIL_HEADER)
        .and_then(|value| value.to_str().ok());
    identity_response(
        &wb,
        net_http::bearer(&headers),
        crate::workbench_auth::web_account_mode(),
        asked,
    )
}

fn identity_response(
    wb: &Workbench,
    bearer: Option<&str>,
    on_hub: bool,
    asked_email: Option<&str>,
) -> axum::response::Response {
    let identity = bearer_identity(wb, bearer, on_hub).map(|mut identity| {
        if let Some(email) = asked_email {
            identity.holds_email = Some(holds_verified_email(wb, &identity.account, email));
        }
        identity
    });
    let mut response = match identity {
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
            holds_email: None,
        });
    }
    wb.authenticate_bearer(token)
        .map(|authority| AccountIdentity {
            account: authority.as_str().to_owned(),
            session: None,
            holds_email: None,
        })
        .ok_or((StatusCode::UNAUTHORIZED, "this bearer is not recognised"))
}

/// Whether `account` holds `email` as an active verified email. An address
/// that does not normalize is held by nobody.
fn holds_verified_email(wb: &Workbench, account: &str, email: &str) -> bool {
    let Some(email) = crate::account_auth::normalize_email_contact(email) else {
        return false;
    };
    crate::account_auth::AccountAuth::rebuild(wb.store_ref()).is_ok_and(|auth| {
        auth.emails.values().any(|record| {
            record.account_id == account
                && record.status == crate::account_auth::AuthMethodStatus::Active
                && record.email == email
        })
    })
}

/// What the Hub says about the account presenting `bearer` and `email`.
#[derive(Debug, PartialEq, Eq)]
pub enum EmailStanding {
    /// The bearer is `account`'s, and that account holds `email` verified.
    Holds { account: String },
    /// The bearer is `account`'s, and that account does not hold `email`.
    DoesNotHold { account: String },
    /// The Hub does not recognise the bearer.
    Unrecognised,
}

/// Ask the Hub at `hub` whether the account `bearer` belongs to holds `email`
/// as a verified email (DR-0332). `Err` is not reaching a Hub that answers.
pub fn hub_email_standing(hub: &str, bearer: &str, email: &str) -> Result<EmailStanding, String> {
    let agent = ureq::AgentBuilder::new()
        // Never follow a redirect with someone's bearer in hand.
        .redirects(0)
        .timeout_connect(std::time::Duration::from_secs(10))
        .timeout_read(std::time::Duration::from_secs(15))
        .build();
    let response = match agent
        .get(&format!("{}/account/identity", hub.trim_end_matches('/')))
        .set("authorization", &format!("Bearer {bearer}"))
        .set(VERIFIED_EMAIL_HEADER, email)
        .call()
    {
        Ok(response) => response,
        Err(ureq::Error::Status(401 | 403, _)) => return Ok(EmailStanding::Unrecognised),
        Err(ureq::Error::Status(status, _)) => {
            return Err(format!("the account service answered {status}"))
        }
        Err(ureq::Error::Transport(error)) => return Err(error.to_string()),
    };
    let identity: AccountIdentity = response
        .into_json()
        .map_err(|error| format!("the account service answered unreadably: {error}"))?;
    if identity.account.is_empty() {
        return Err("the account service named no account".to_owned());
    }
    // A Hub that predates DR-0332 ignores the header and omits the answer;
    // that is not a yes.
    match identity.holds_email {
        Some(true) => Ok(EmailStanding::Holds {
            account: identity.account,
        }),
        Some(false) => Ok(EmailStanding::DoesNotHold {
            account: identity.account,
        }),
        None => Err("the account service cannot confirm an email yet".to_owned()),
    }
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

    /// A Home binding an email invitation learns only whether the caller's own
    /// account holds the address it asked about (DR-0332).
    #[tokio::test]
    async fn a_home_learns_whether_the_caller_holds_an_email_and_nothing_more() {
        use axum::{routing::get, Router};
        use std::sync::Mutex;
        let mut workbench = hub();
        let alice = workbench
            .mint_account_session("account-alice", "passkey", 60)
            .unwrap();
        let bob = workbench
            .mint_account_session("account-bob", "passkey", 60)
            .unwrap();
        crate::account_auth::append_facts(
            workbench.store_mut(),
            &[crate::account_auth::AccountAuthFact::Email(
                crate::account_auth::VerifiedEmailRecord::new(
                    "account-alice",
                    "Alice@Example.test",
                    1,
                )
                .unwrap(),
            )],
        )
        .unwrap();
        let wb = Arc::new(Mutex::new(workbench));
        let app = Router::new()
            .route(
                "/account/identity",
                get(
                    |State(wb): State<SharedWorkbench>, headers: HeaderMap| async move {
                        let asked = headers
                            .get(VERIFIED_EMAIL_HEADER)
                            .and_then(|value| value.to_str().ok());
                        identity_response(
                            &wb.lock_unpoisoned(),
                            net_http::bearer(&headers),
                            true,
                            asked,
                        )
                    },
                ),
            )
            .with_state(wb.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hub = format!("http://{}", listener.local_addr().unwrap());
        let service = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let answers = tokio::task::spawn_blocking(move || {
            [
                hub_email_standing(&hub, &alice, " alice@example.TEST "),
                hub_email_standing(&hub, &bob, "alice@example.test"),
                hub_email_standing(&hub, &alice, "someone@example.test"),
                hub_email_standing(&hub, "not-a-session", "alice@example.test"),
            ]
        })
        .await
        .unwrap();
        service.abort();
        assert_eq!(
            answers,
            [
                Ok(EmailStanding::Holds {
                    account: "account-alice".into()
                }),
                Ok(EmailStanding::DoesNotHold {
                    account: "account-bob".into()
                }),
                Ok(EmailStanding::DoesNotHold {
                    account: "account-alice".into()
                }),
                Ok(EmailStanding::Unrecognised),
            ]
        );
    }

    #[test]
    fn an_identity_asked_nothing_about_email_says_nothing_about_it() {
        let identity: AccountIdentity =
            serde_json::from_value(json!({"account": "alice"})).unwrap();
        assert!(identity.holds_email.is_none());
        assert!(!serde_json::to_string(&identity)
            .unwrap()
            .contains("holds_email"));
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
                        identity_response(
                            &wb.lock_unpoisoned(),
                            net_http::bearer(&headers),
                            true,
                            None,
                        )
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
