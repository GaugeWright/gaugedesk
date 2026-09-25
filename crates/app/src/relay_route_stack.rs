//! What a desktop Home serves to a caller that arrived over its relay leg
//! (DR-0206).
//!
//! The leg used to splice into the Home's one local listener, which serves
//! [`crate::open_control_plane`] — the operator's own channel, where a request
//! with no credentials is the local operator. The relay locator that dials the
//! leg is published in the account's directory record, which anyone may read,
//! so everything the operator could do was open to anyone holding it.
//!
//! This is the relay leg's alone. It admits only the Home's owner:
//!
//! 1. the Hub says whose account the caller's bearer is
//!    ([`crate::account_identity`]), and it must be the Home's owner;
//! 2. `POST /home/admissions` then mints an admission bound to that account,
//!    and every later call must carry it, as on a hosted Home (`HOME-1`);
//! 3. the call is served by the ordinary router under the owner's own Home
//!    session — the one the desktop's window would hold — so every handler
//!    treats it exactly as it treats the owner at the computer.
//!
//! Anything the caller brought besides is removed before it gets there.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json, Router,
};
use gaugedesk_core::ids::AuthorityId;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::home_admission::{HomeAdmissionToken, HOME_ADMISSION_HEADER};
use crate::{net_http, LockUnpoisoned, SharedWorkbench};

/// Said when the Hub named the owner but this computer cannot act for them:
/// nobody is signed in here, or someone else is. Signing in at the computer
/// is the remedy either way.
///
/// The words are the contract, as `target Home admission required` is for an
/// expired admission: desk's `isRelayClosedRefusal` matches them, because the
/// direct transport keeps only a refusal's `error` text and the phone reaches
/// this router through it. Change one and the other goes with it.
pub const RELAY_REFUSAL: &str = "this computer is not signed in to GaugeDesk as you; \
    sign in on the computer itself";

/// The exact refusal desk and mobile already answer by admitting again
/// (`isExpiredHomeAdmission`): an admission that is missing, revoked, or lost
/// to a restart.
const ADMISSION_REQUIRED: &str = "target Home admission required";

/// Headers a remote caller may not carry through. The bearer and admission are
/// judged here and replaced; the rest would be credentials this Home honours
/// for local callers, and nothing about a crossing makes it one.
const STRIPPED: &[&str] = &[
    "authorization",
    "cookie",
    HOME_ADMISSION_HEADER,
    "x-gaugewright-machine-session",
];

/// Whose account a bearer is, as the Hub says. `Ok(None)` is the Hub saying it
/// does not recognise the bearer; `Err` is not reaching the Hub at all.
pub trait BearerAccounts: Send + Sync {
    fn account_for(&self, bearer: &str) -> Result<Option<String>, String>;
}

/// [`BearerAccounts`] answered by the Hub's `GET /account/identity`.
///
/// An answer is kept for a few minutes, keyed by a digest of the bearer, so a
/// burst of calls asks once. That bounds how long a bearer the Hub has since
/// revoked keeps working here; the admission, which this Home holds, can be
/// revoked at once.
pub struct HubBearerAccounts {
    hub: Option<String>,
    remembered: Mutex<HashMap<[u8; 32], (String, Instant)>>,
}

const REMEMBER_FOR: Duration = Duration::from_secs(5 * 60);
const REMEMBER_AT_MOST: usize = 256;

impl HubBearerAccounts {
    /// The Hub this desktop signs in at (`GAUGEDESK_ACCOUNT_HUB_URL`).
    pub fn configured() -> Self {
        Self::at(crate::account_signin::hub_base())
    }

    pub fn at(hub: Option<String>) -> Self {
        Self {
            hub,
            remembered: Mutex::new(HashMap::new()),
        }
    }
}

impl BearerAccounts for HubBearerAccounts {
    fn account_for(&self, bearer: &str) -> Result<Option<String>, String> {
        let key: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
        {
            let mut remembered = self.remembered.lock_unpoisoned();
            remembered.retain(|_, (_, at)| at.elapsed() < REMEMBER_FOR);
            if let Some((account, _)) = remembered.get(&key) {
                return Ok(Some(account.clone()));
            }
        }
        let hub = self
            .hub
            .as_deref()
            .ok_or_else(|| "no account service is configured".to_owned())?;
        let agent = ureq::AgentBuilder::new()
            // Never follow a redirect with someone's bearer in hand.
            .redirects(0)
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(15))
            .build();
        let response = match agent
            .get(&format!("{hub}/account/identity"))
            .set("authorization", &format!("Bearer {bearer}"))
            .call()
        {
            Ok(response) => response,
            Err(ureq::Error::Status(401 | 403, _)) => return Ok(None),
            Err(ureq::Error::Status(status, _)) => {
                return Err(format!("the account service answered {status}"))
            }
            Err(ureq::Error::Transport(error)) => return Err(error.to_string()),
        };
        let body: serde_json::Value = response
            .into_json()
            .map_err(|error| format!("the account service answered unreadably: {error}"))?;
        let Some(account) = body["account"].as_str().filter(|a| !a.is_empty()) else {
            return Err("the account service named no account".to_owned());
        };
        let mut remembered = self.remembered.lock_unpoisoned();
        if remembered.len() >= REMEMBER_AT_MOST {
            remembered.clear();
        }
        remembered.insert(key, (account.to_owned(), Instant::now()));
        Ok(Some(account.to_owned()))
    }
}

#[derive(Clone)]
struct Relay {
    wb: SharedWorkbench,
    accounts: Arc<dyn BearerAccounts>,
}

/// The relay leg's router: the ordinary one, behind [`admit_relay_caller`].
pub fn relay_control_plane(wb: SharedWorkbench, accounts: Arc<dyn BearerAccounts>) -> Router {
    let relay = Relay {
        wb: wb.clone(),
        accounts,
    };
    crate::open_control_plane(wb).layer(axum::middleware::from_fn_with_state(
        relay,
        admit_relay_caller,
    ))
}

fn refuse(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// Whether a route is this computer's own business, and so is never served
/// over the relay even to the owner (DR-0206 §4).
fn local_only(method: &Method, path: &str) -> bool {
    // Signing this computer in and out of the Hub: done at it, not to it.
    (path.starts_with("/account/hub-session") && method != Method::GET)
        // The login shell and the test fixtures have no remote caller.
        || path.starts_with("/auth/")
        || path.starts_with("/test/")
}

fn admission(headers: &HeaderMap) -> Option<HomeAdmissionToken> {
    headers
        .get(HOME_ADMISSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(HomeAdmissionToken::parse)
}

async fn admit_relay_caller(
    State(relay): State<Relay>,
    mut request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    if path == "/health" {
        for name in STRIPPED {
            request.headers_mut().remove(*name);
        }
        return next.run(request).await;
    }
    if local_only(&method, &path) {
        return refuse(
            StatusCode::FORBIDDEN,
            "this is done on the computer itself, not from elsewhere",
        );
    }
    let Some(bearer) = net_http::bearer(request.headers()).map(str::to_owned) else {
        return refuse(StatusCode::UNAUTHORIZED, "sign in to reach this Home");
    };

    // Off the async runtime: this may be a network call to the Hub.
    let accounts = relay.accounts.clone();
    let answered = tokio::task::spawn_blocking(move || accounts.account_for(&bearer)).await;
    let account = match answered {
        Ok(Ok(Some(account))) => account,
        Ok(Ok(None)) => return refuse(StatusCode::UNAUTHORIZED, "sign in to reach this Home"),
        Ok(Err(error)) => {
            tracing::warn!("relay caller not verified: {error}");
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "the account service could not be reached to check who you are",
            );
        }
        Err(_) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "could not check who you are",
            )
        }
    };

    let (owner, home) = {
        let guard = relay.wb.lock_unpoisoned();
        (guard.home_owner_account(), guard.home_id().clone())
    };
    if owner.as_deref() != Some(account.as_str()) {
        return refuse(
            StatusCode::FORBIDDEN,
            "this Home belongs to another account",
        );
    }
    let actor = AuthorityId::new(account.clone());

    // The admission ceremony is answered here, bound to the account the Hub
    // named. The ordinary handler would bind it to whoever its own judgement
    // produced, which on a desktop is the local operator.
    if path == "/home/admissions" {
        let mut guard = relay.wb.lock_unpoisoned();
        return match method {
            Method::POST => {
                let token = guard.home_admissions.open(home.clone(), actor);
                (
                    StatusCode::CREATED,
                    Json(json!({ "home": home.as_str(), "admission": token.encode() })),
                )
                    .into_response()
            }
            Method::DELETE => match admission(request.headers()) {
                Some(token)
                    if guard
                        .home_admissions
                        .authorize(&home, &actor, &token)
                        .is_ok() =>
                {
                    guard.home_admissions.revoke(&home, &actor);
                    StatusCode::NO_CONTENT.into_response()
                }
                _ => refuse(StatusCode::UNAUTHORIZED, ADMISSION_REQUIRED),
            },
            _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        };
    }

    let admitted = admission(request.headers()).is_some_and(|token| {
        relay
            .wb
            .lock_unpoisoned()
            .home_admissions
            .authorize(&home, &actor, &token)
            .is_ok()
    });
    if !admitted {
        return refuse(StatusCode::UNAUTHORIZED, ADMISSION_REQUIRED);
    }

    let wb = relay.wb.clone();
    let session =
        tokio::task::spawn_blocking(move || crate::desktop_session::relay_session(&wb, &account))
            .await
            .ok()
            .flatten();
    let Some(session) = session else {
        return refuse(StatusCode::FORBIDDEN, RELAY_REFUSAL);
    };
    let Ok(authorization) = HeaderValue::from_str(&format!("Bearer {session}")) else {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not serve this call",
        );
    };
    let headers = request.headers_mut();
    for name in STRIPPED {
        headers.remove(*name);
    }
    headers.insert(axum::http::header::AUTHORIZATION, authorization);
    next.run(request).await
}

#[cfg(test)]
#[path = "relay_route_stack_tests.rs"]
mod tests;
