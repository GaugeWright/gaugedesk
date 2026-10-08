//! What a desktop Home serves to a caller that arrived over its relay leg
//! (DR-0206).
//!
//! The leg used to splice into the Home's one local listener, which serves
//! [`crate::open_control_plane`] — the operator's own channel, where a request
//! with no credentials is the local operator. The relay locator that dials the
//! leg is published in the account's directory record, which anyone may read,
//! so everything the operator could do was open to anyone holding it.
//!
//! This is the relay leg's alone. It admits any account the Hub names, as
//! itself, each reaching only the projects it owns or holds a grant to
//! (DR-0328 §6):
//!
//! 1. the Hub says whose account the caller's bearer is
//!    ([`crate::account_identity`]). What that account holds here is its
//!    [`Standing`]: signed in on this computer, a member holding a grant to a
//!    project this Home serves, or neither;
//! 2. `POST /home/invitations/accept` is answered for any of them, as the
//!    account the Hub named, with the caller's own bearer asked about an
//!    email invitation's address (DR-0332). That is how someone invited to a
//!    project on this computer becomes a member of it. A stranger is
//!    answered nothing else, and hung up on;
//! 3. `POST /home/admissions` then mints an admission bound to that account,
//!    and every later call must carry it, as on a hosted Home (`HOME-1`);
//! 4. the call is served by the ordinary router under a session of this
//!    Home's own for that account — its relay session when it is signed in
//!    here, a member session when it is not — so it reaches only the projects
//!    that account owns or holds a grant to, exactly as at the computer. The
//!    computer's own account records never cross ([`local_only`]), and a
//!    member reaches nothing host-wide ([`member_refused`]).
//!
//! Anything the caller brought besides is removed before it gets there.

use std::collections::HashMap;
use std::net::SocketAddr;
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

    /// Whether the account presenting `bearer` holds `email` as a verified
    /// address, as the Hub says (DR-0332 §5). Without a Hub to ask the answer
    /// is an error, which refuses the acceptance it was asked for.
    fn email_standing(
        &self,
        _bearer: &str,
        _email: &str,
    ) -> Result<crate::account_identity::EmailStanding, String> {
        Err("no account service is configured".to_owned())
    }
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
                tracing::info!(
                    cache = "hit",
                    "relay caller identity from the account service"
                );
                return Ok(Some(account.clone()));
            }
        }
        let asked = Instant::now();
        let answer = self.ask_hub(bearer);
        // Never the bearer or the account: only how the lookup went and how long
        // the account service took, which is a reach's first network wait.
        tracing::info!(
            cache = "miss",
            hub_ms = asked.elapsed().as_millis() as u64,
            outcome = match &answer {
                Ok(Some(_)) => "named",
                Ok(None) => "refused",
                Err(_) => "unreachable",
            },
            "relay caller identity from the account service"
        );
        let account = match answer? {
            Some(account) => account,
            None => return Ok(None),
        };
        let mut remembered = self.remembered.lock_unpoisoned();
        if remembered.len() >= REMEMBER_AT_MOST {
            remembered.clear();
        }
        remembered.insert(key, (account.clone(), Instant::now()));
        Ok(Some(account))
    }

    fn email_standing(
        &self,
        bearer: &str,
        email: &str,
    ) -> Result<crate::account_identity::EmailStanding, String> {
        let hub = self
            .hub
            .as_deref()
            .ok_or_else(|| "no account service is configured".to_owned())?;
        crate::account_identity::hub_email_standing(hub, bearer, email)
    }
}

impl HubBearerAccounts {
    /// `GET /account/identity` for this bearer, uncached.
    fn ask_hub(&self, bearer: &str) -> Result<Option<String>, String> {
        let hub = self
            .hub
            .as_deref()
            .ok_or_else(|| "no account service is configured".to_owned())?;
        let agent = net_http::shared_agent(net_http::AgentSettings {
            timeout: None,
            connect: Some(Duration::from_secs(10)),
            read: Some(Duration::from_secs(15)),
            // Never follow a redirect with someone's bearer in hand.
            redirects: false,
        });
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
    // The gate runs inside the relay's own admission, so it sees the session
    // the crossing is served under, never the caller's Hub bearer.
    crate::open_control_plane(wb.clone())
        .layer(axum::middleware::from_fn_with_state(
            wb,
            crate::project_owner::account_project_gate,
        ))
        .layer(axum::middleware::from_fn_with_state(
            relay,
            admit_relay_caller,
        ))
}

fn refuse(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// Answer a caller this Home has not verified, then hang up (DR-0302).
///
/// The locator is public, so anyone may open a crossing; refusing their
/// requests is not enough when the crossing itself is what they hold. Closing
/// the connection after the answer, and asking the crossing that carried it to
/// end, means a stranger holds one for its answer and a few seconds of teardown. A verified owner keeps
/// their connection whatever this router answers them.
fn hang_up(peer: Option<SocketAddr>, mut response: Response) -> Response {
    response.headers_mut().insert(
        axum::http::header::CONNECTION,
        HeaderValue::from_static("close"),
    );
    if let Some(peer) = peer {
        gaugedesk_relay_transport::hang_up_crossing(peer);
    }
    response
}

fn peer_of(request: &Request) -> Option<SocketAddr> {
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|info| info.0)
}

/// Whether a route is this computer's own business, and so is never served
/// over the relay to anyone (DR-0206 §4).
///
/// Any account the Hub names may cross now (DR-0328 §6), so the computer's
/// own account records — its signed-in accounts, Homes, routes, devices,
/// sessions, directory, organizations and Account Settings — never cross.
/// Only the caller's own provider credentials, logins, boxes and settings
/// do, which a desktop keys by the caller's account.
fn local_only(_method: &Method, path: &str) -> bool {
    let caller_scoped = [
        "/account/credentials",
        "/account/boxes",
        "/account/settings",
        "/account/default-model",
        "/account/oauth/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix));
    (path.starts_with("/account/") && !caller_scoped)
        || path.starts_with("/gaugeapps/account-settings/")
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

/// What the account the Hub named holds on this computer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing {
    /// Signed in here: it crosses as itself, as at the computer.
    SignedIn,
    /// Not signed in here, but an active member holding a grant to a project
    /// this Home serves: it crosses to those projects alone.
    Member,
    /// Neither. It may accept an invitation and do nothing else.
    Stranger,
}

impl Standing {
    fn as_str(self) -> &'static str {
        match self {
            Standing::SignedIn => "signed-in",
            Standing::Member => "member",
            Standing::Stranger => "stranger",
        }
    }
}

/// Said to an account the Hub named that holds nothing here.
const STRANGER_REFUSAL: &str = "this account is not signed in on this computer \
    and holds no project here";

/// Said to a member asking for something that is not one of its projects'.
const MEMBER_REFUSAL: &str = "only the projects shared with you on this computer \
    are reached from elsewhere";

/// Said when a member's grant ended between its admission and this call.
const MEMBER_ENDED: &str = "your access to this computer's projects has ended";

/// The largest invitation acceptance body the relay reads itself.
const ACCEPT_BODY_LIMIT: usize = 64 * 1024;

/// Whether a route is beyond what a project member reaches here: anything
/// host-wide rather than about one of its projects (DR-0268 §1, DR-0328 §6).
///
/// A member is not signed in on this computer, so it keeps nothing here —
/// no Personal, no provider credentials or settings, no Agents of its own, no
/// pairings — and it creates no project, which would be the computer's
/// owner's to carry. What it reaches inside its projects is decided per
/// project behind this, by the same gate and handlers as any account here.
/// That includes authoring, trying, publishing and deploying the Agents
/// placed in them ([`member_authors`]).
fn member_refused(method: &Method, path: &str) -> bool {
    if member_authors(method, path) {
        return false;
    }
    const HOST_WIDE: &[&str] = &[
        "/account/",
        "/admin/",
        "/archetypes",
        "/auth/",
        "/boundaries/",
        "/collection-recipients",
        "/console/",
        "/directory",
        "/federation/",
        "/gaugeapps/",
        "/home/invitations",
        "/home/projects/",
        "/local-projects",
        "/mobile/",
        "/organizations/",
        "/pairing-",
        "/product-analytics",
        "/public-deployments",
        "/roster",
        "/saml",
        "/scim",
        "/test/",
        "/tutorials/",
    ];
    if HOST_WIDE.iter().any(|prefix| path.starts_with(prefix)) {
        return true;
    }
    // Creating a project, a quick chat in a Personal of its own, or a fork
    // of a project puts something on this computer that is not one of the
    // member's projects; deleting a project is its owner's.
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    matches!(
        (method, segments.as_slice()),
        (
            &Method::POST,
            ["projects"] | ["chats"] | ["projects", _, "fork"]
        ) | (&Method::DELETE, ["projects", _])
    )
}

/// Whether a route is a member's authoring, trying, publishing or deploying
/// of an Agent placed in one of its projects (DR-0453). The handler behind
/// decides whether this Agent or placement is one: each admits only an
/// account that owns it or holds its project's grant with a role that
/// authors there. What stays the owner's — creating, deleting, forking,
/// copying or placing an Agent, pausing or erasing a deployment, adding or
/// revoking a publisher's credential — is still refused here.
fn member_authors(method: &Method, path: &str) -> bool {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match segments.as_slice() {
        ["archetypes", id] => !id.is_empty() && matches!(*method, Method::GET | Method::PUT),
        ["archetypes", id, "abilities" | "panel-profile"] => {
            !id.is_empty() && matches!(*method, Method::GET | Method::PUT)
        }
        ["archetypes", id, "chats" | "preview" | "publish"] => {
            !id.is_empty() && *method == Method::POST
        }
        // Agent Settings, a GaugeApp at the Agent (`AgentSettings::PATH`).
        ["archetypes", id, "settings", ..] => !id.is_empty(),
        ["public-deployments"]
        | ["public-deployments", "inspect"]
        | ["public-deployments", "credentials", "list"] => *method == Method::POST,
        ["public-deployments", "publisher-authority"] => *method == Method::GET,
        _ => false,
    }
}

/// Judge what `account` holds here. Off the async runtime: it reads the store.
async fn standing_of(wb: &SharedWorkbench, account: &str) -> Standing {
    let wb = wb.clone();
    let account = account.to_owned();
    tokio::task::spawn_blocking(move || {
        if crate::account_signin::hub_standing_for(&wb, &account).is_some() {
            return Standing::SignedIn;
        }
        let guard = wb.lock_unpoisoned();
        if guard.desktop_account_mode()
            && !crate::desktop_session::member_projects(&guard, &account).is_empty()
        {
            Standing::Member
        } else {
            Standing::Stranger
        }
    })
    .await
    .unwrap_or(Standing::Stranger)
}

async fn admit_relay_caller(
    State(relay): State<Relay>,
    mut request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let peer = peer_of(&request);
    // Everything until the Hub names the owner is answered to a stranger, and
    // then the crossing is hung up — `/health` included, which nobody needs
    // to hold a crossing open for.
    if path == "/health" {
        for name in STRIPPED {
            request.headers_mut().remove(*name);
        }
        return hang_up(peer, next.run(request).await);
    }
    let Some(bearer) = net_http::bearer(request.headers()).map(str::to_owned) else {
        return hang_up(
            peer,
            refuse(StatusCode::UNAUTHORIZED, "sign in to reach this Home"),
        );
    };

    // Off the async runtime: this may be a network call to the Hub.
    let started = Instant::now();
    let accounts = relay.accounts.clone();
    let asked = bearer.clone();
    let answered = tokio::task::spawn_blocking(move || accounts.account_for(&asked)).await;
    let identified = started.elapsed();
    let account = match answered {
        Ok(Ok(Some(account))) => account,
        Ok(Ok(None)) => {
            return hang_up(
                peer,
                refuse(StatusCode::UNAUTHORIZED, "sign in to reach this Home"),
            )
        }
        Ok(Err(error)) => {
            tracing::warn!("relay caller not verified: {error}");
            return hang_up(
                peer,
                refuse(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the account service could not be reached to check who you are",
                ),
            );
        }
        Err(_) => {
            return hang_up(
                peer,
                refuse(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "could not check who you are",
                ),
            )
        }
    };

    // Any account the Hub names crosses as itself; what it reaches is decided
    // per project behind this (DR-0328 §6).
    let standing = standing_of(&relay.wb, &account).await;
    let judged = started.elapsed();
    let home = relay.wb.lock_unpoisoned().home_id().clone();
    let actor = AuthorityId::new(account.clone());

    // Refused to everyone, but hung up only on a stranger. A verified caller's
    // other calls may be queued on this crossing, and hanging up on them for
    // one refused read failed those too after the Home's teardown grace: the
    // browser asks every Home for its onboarding status at startup (WS-850).
    if local_only(&method, &path) {
        let refused = refuse(
            StatusCode::FORBIDDEN,
            "this is done on the computer itself, not from elsewhere",
        );
        return if standing == Standing::Stranger {
            hang_up(peer, refused)
        } else {
            refused
        };
    }

    // Accepting an invitation is how an account comes to hold a project here,
    // so it is answered for every account the Hub names. It is answered here,
    // as that account, with the caller's own bearer asked about an email
    // invitation's address: the router behind would judge it as the session
    // it serves under, which on a desktop is never the invitee (DR-0332).
    if path == "/home/invitations/accept" {
        if method != Method::POST {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        let body = match axum::body::to_bytes(request.into_body(), ACCEPT_BODY_LIMIT).await {
            Ok(body) => body,
            Err(_) => {
                return hang_up(
                    peer,
                    refuse(StatusCode::PAYLOAD_TOO_LARGE, "invitation is too large"),
                )
            }
        };
        let accounts = relay.accounts.clone();
        let email: crate::home_invitation::EmailCheck =
            Box::new(move |address: &str| accounts.email_standing(&bearer, address));
        let answer =
            crate::home_invitation::accept_over_relay(relay.wb.clone(), actor, email, &body).await;
        tracing::info!(
            standing = standing.as_str(),
            status = answer.status().as_u16(),
            identity_ms = identified.as_millis() as u64,
            standing_ms = (judged - identified).as_millis() as u64,
            total_ms = started.elapsed().as_millis() as u64,
            "relay invitation acceptance answered"
        );
        // A stranger whose acceptance failed holds nothing here still.
        return if standing == Standing::Stranger && !answer.status().is_success() {
            hang_up(peer, answer)
        } else {
            answer
        };
    }
    match standing {
        Standing::Stranger => {
            tracing::info!(
                %method,
                path,
                identity_ms = identified.as_millis() as u64,
                total_ms = started.elapsed().as_millis() as u64,
                "relay caller holds nothing here"
            );
            return hang_up(peer, refuse(StatusCode::FORBIDDEN, STRANGER_REFUSAL));
        }
        Standing::Member if member_refused(&method, &path) => {
            tracing::info!(%method, path, "relay member refused a host-wide route");
            return refuse(StatusCode::FORBIDDEN, MEMBER_REFUSAL);
        }
        Standing::SignedIn | Standing::Member => {}
    }

    // The admission ceremony is answered here, bound to the account the Hub
    // named. The ordinary handler would bind it to whoever its own judgement
    // produced, which on a desktop is the local operator.
    if path == "/home/admissions" {
        admitted_after(&method, &path, standing, identified, started.elapsed());
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
                    guard.home_admissions.revoke_session(&home, &actor, &token);
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
    let session = tokio::task::spawn_blocking(move || match standing {
        Standing::SignedIn => crate::desktop_session::relay_session(&wb, &account),
        Standing::Member => crate::desktop_session::member_session(&wb, &account),
        Standing::Stranger => None,
    })
    .await
    .ok()
    .flatten();
    let Some(session) = session else {
        let refusal = match standing {
            Standing::Member => MEMBER_ENDED,
            _ => RELAY_REFUSAL,
        };
        return refuse(StatusCode::FORBIDDEN, refusal);
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
    admitted_after(&method, &path, standing, identified, started.elapsed());
    next.run(request).await
}

/// How long judging a relay caller may take before it is a warning. The
/// whole relay round trip is about 150 ms, so a second spent here is a Home
/// that a person reaching it through desk is waiting on (2026-10-07).
const SLOW_ADMISSION: Duration = Duration::from_millis(500);

/// Log that a relay caller was admitted, and how long judging it took — the
/// Hub naming the bearer's account, its standing here and its session —
/// which is latency everyone reaching this Home sees.
fn admitted_after(
    method: &Method,
    path: &str,
    standing: Standing,
    identified: Duration,
    total: Duration,
) {
    let identity_ms = identified.as_millis() as u64;
    let total_ms = total.as_millis() as u64;
    let standing = standing.as_str();
    if total >= SLOW_ADMISSION {
        tracing::warn!(%method, path, standing, identity_ms, total_ms, "relay caller admitted slowly");
    } else {
        tracing::info!(%method, path, standing, identity_ms, total_ms, "relay caller admitted");
    }
}

#[cfg(test)]
#[path = "relay_route_stack_tests.rs"]
mod tests;
