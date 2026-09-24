//! OIDC auth-code + PKCE **shell** (M3 `ID-3`) — the two browser-facing control-plane
//! routes that wrap the verified OIDC core ([`crate::identity_oidc`]) into a real login:
//!
//! - `GET /auth/login` — read the org's configured SSO connection (`/admin/sso`, the
//!   one home for "which IdP"), discover the OP's endpoints, mint a PKCE verifier plus
//!   a CSRF `state`, stash them server-side keyed by `state`, and **302-redirect** the
//!   browser to the OP's authorize endpoint.
//! - `GET /auth/callback` — the OP redirects the browser back here with `code` and
//!   `state`. Look up the pending PKCE verifier by `state` (single-use; an unknown
//!   `state` is refused — the CSRF guard, `INV-20`), redeem the code at the token
//!   endpoint ([`exchange_code`], presenting the verifier so an intercepted code is
//!   useless), then verify the returned id-token against the issuer's live JWKS.
//!
//! Every provider callback resolves an exact external-subject link to an
//! independent GaugeDesk account and mints an opaque, revocable account
//! session. Native handoff returns the same account session after its
//! PKCE-bound exchange; external provider tokens remain server-side and are
//! used only to maintain that session's bound refresh authority.
//!
//! The HTTP-touching logic lives in two seam-generic functions ([`start_login`],
//! [`finish_callback`]) tested against a mock OP; the axum handlers are the thin
//! wiring that supplies the real [`net_http::HttpClient`](crate::net_http)
//! (off the async runtime via [`tokio::task::spawn_blocking`], since the seam is
//! blocking) and the server-side [`PendingAuthStore`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::{
    extract::{Extension, Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    Json,
};
use jsonwebtoken::decode_header;
use serde::Deserialize;
use serde_json::json;

use gaugedesk_core::abac::AuthorityAttributes;
use gaugedesk_core::ids::AuthorityId;

use crate::identity::IdentityProvider;
use crate::identity_oidc::{
    authorize_url, discover_endpoints, discover_jwks, exchange_code, refresh_id_token,
    ClaimMapping, HttpForm, HttpGet, OidcIdentityProvider, Pkce,
};
use crate::net_http::HttpClient;
use crate::org::{Org, RecordOp, SsoConnectionRecord, SsoProtocol, ORG_SCOPE};
use crate::{LockUnpoisoned, SharedWorkbench, Workbench};
use base64::Engine as _;

/// Server-side state carried from `/auth/login` to `/auth/callback` for one
/// auth-code + PKCE exchange, keyed by the CSRF `state` (`ID-3`). Holds the PKCE
/// verifier (never sent on the authorize leg, only on the token exchange) plus the
/// endpoints + verification parameters the login leg already discovered, so the
/// callback need not re-discover. Single-use: the callback consumes it.
#[derive(Clone, Debug)]
pub struct PendingAuth {
    /// The PKCE verifier whose S256 challenge went to the OP; presented at exchange.
    /// Held [`Secret`](crate::secret::Secret) so this `Debug`-deriving
    /// struct never leaks it to a log (`SECAUD-10`).
    pub verifier: crate::secret::Secret,
    /// The OIDC `nonce` minted on the authorize leg and echoed in the id-token's
    /// `nonce` claim. The callback requires the returned id-token to carry exactly
    /// this value, binding the token to *this* browser login (replay/injection
    /// defense, `INV-20`).
    pub nonce: String,
    /// The OP token endpoint the code is redeemed at.
    pub token_endpoint: String,
    /// The OP JWKS endpoint the returned id-token is verified against.
    pub jwks_uri: String,
    /// The issuer the verifier pins (`iss` must match).
    pub issuer: String,
    /// The accepted audiences (`aud` must contain one); the first is the client id.
    pub audiences: Vec<String>,
    /// The exact `redirect_uri` sent on authorize — must match on exchange (RFC 6749).
    pub redirect_uri: String,
    /// How the returned id-token's claims map onto ABAC attributes (`ID-3`).
    pub mapping: ClaimMapping,
    /// The OAuth **client secret** presented at token exchange, if the OP requires a confidential
    /// client (Google "Web application" clients do, even with PKCE). `None` for a public PKCE
    /// client (Okta/Entra). Held [`Secret`](crate::secret::Secret) so it never logs.
    pub client_secret: Option<crate::secret::Secret>,
    /// Exact allowlisted native return URI selected on the login leg. The
    /// callback trusts only this server-side value, never callback input.
    pub native_return: Option<String>,
    /// App-generated S256 challenge binding a native handoff to the GaugeDesk
    /// instance that initiated it. Required whenever `native_return` is set.
    pub native_handoff_challenge: Option<String>,
    /// Exact organization connection selected on the authorize leg. `None`
    /// identifies the consumer-provider fallback; an enterprise callback may
    /// not recover tenant or connection identity from callback input.
    pub login_context: Option<PendingEnterpriseLogin>,
    /// Exact consumer connection selected on the authorize leg (DR-0189 §1).
    /// Set for every consumer ceremony and `None` for an enterprise one. Once a
    /// deployment offers more than one consumer entrance, the callback can no
    /// longer infer which it is finishing, and it must not learn that from
    /// callback input — so it is pinned here beside the issuer and the nonce.
    pub consumer_connection_id: Option<String>,
    /// Why this browser ceremony was started. A corporate connection test uses
    /// the same registered callback as ordinary OIDC sign-in, but its verified
    /// result is folded as revision-bound evidence and must never mint a login,
    /// account, or membership.
    pub purpose: PendingAuthPurpose,
}

/// Server-held context for an isolated corporate browser test. None of these
/// values comes back from the browser or IdP: the random OIDC `state` selects
/// this record, binding the return to the initiating administrator, tenant, and
/// exact saved connection revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingEnterpriseConnectionTest {
    pub id: String,
    pub store_scope: String,
    pub actor: String,
    pub connection_id: String,
    pub connection_revision: String,
}

/// Server-held context for an ordinary corporate sign-in. The IdP callback
/// carries only the random `state`; tenant and connection identity are pinned
/// here at the authorize leg and rechecked before subject resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingEnterpriseLogin {
    pub store_scope: String,
    pub connection_id: String,
    pub connection_revision: String,
    pub protocol: SsoProtocol,
}

/// Server-held authority for linking one consumer OIDC subject to an existing
/// GaugeDesk account. The initiating opaque session is named by its digest so
/// the system browser never needs to share the Desk webview's cookie. The
/// callback rechecks that exact durable session and provider revision before it
/// admits the link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingConsumerOidcLink {
    pub account_id: String,
    pub session_id: String,
    pub connection_id: String,
    pub connection_revision: String,
}

/// Server-held context for the person's explicit re-fetch of their avatar from
/// the consumer provider already linked to their account (DR-0195 §3).
///
/// It is a provider round trip rather than a stored URL because the URL is the
/// photograph: a provider mints a new one when the person changes theirs, so a
/// kept URL would re-fetch the old picture. The callback replaces the avatar
/// only when the returning subject is the one actively linked to this account;
/// it links nothing, mints no session, and stores no token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingConsumerOidcAvatar {
    pub account_id: String,
    pub session_id: String,
    pub connection_id: String,
    pub connection_revision: String,
}

/// All server-held inputs the enterprise composition needs to begin an
/// ordinary SAML login. The returned URL carries only a random RelayState;
/// tenant, connection revision, native handoff, and trust material stay here.
#[derive(Clone, Debug)]
pub struct EnterpriseSamlStartRequest {
    pub connection: SsoConnectionRecord,
    pub login_context: PendingEnterpriseLogin,
    pub public_base: String,
    pub native_return: Option<String>,
    pub native_handoff_challenge: Option<String>,
}

/// Enterprise-owned SAML protocol launcher registered into the shared account
/// shell. Core owns discovery and post-login session delivery; the enterprise
/// band owns SAML metadata, AuthnRequest construction, and assertion verify.
pub type EnterpriseSamlStart =
    Arc<dyn Fn(EnterpriseSamlStartRequest) -> Result<String, String> + Send + Sync>;

/// The callback consequence selected on the authorize leg. `Login` retains the
/// existing session path; a connection test is deliberately non-login.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PendingAuthPurpose {
    #[default]
    Login,
    ConsumerOidcLink(PendingConsumerOidcLink),
    ConsumerOidcAvatar(PendingConsumerOidcAvatar),
    EnterpriseConnectionTest(PendingEnterpriseConnectionTest),
}

/// Verified OIDC return material made available to the composition callback.
/// The external token remains internal; the enterprise test fold consumes only
/// the subject and mapped, non-secret attributes.
pub struct VerifiedOidcIdentity {
    pub authority: AuthorityId,
    pub id_token: String,
    pub refresh_token: Option<String>,
    pub attributes: AuthorityAttributes,
}

/// Provider-neutral corporate identity passed to the organization admission
/// fold after protocol verification. The work-email discovery input never
/// appears here: `verified_email` comes only from the signed OIDC claims or
/// signed SAML assertion.
#[derive(Clone, Debug)]
pub struct VerifiedEnterpriseIdentity {
    pub authority: AuthorityId,
    pub verified_email: Option<String>,
}

/// How long a minted `state` may await its callback. A browser crossing the
/// provider returns in well under this; anything older is an abandoned or
/// never-followed login, and its verifier authorizes nothing worth keeping.
const PENDING_AUTH_TTL: Duration = Duration::from_secs(10 * 60);

/// A ceiling that holds even when nothing has expired yet. The TTL bounds the
/// store by the rate of recent logins, and `/auth/login` is unauthenticated —
/// so without this a caller can mint pending state faster than it ages out.
const PENDING_AUTH_MAX: usize = 512;

/// One login leg's [`PendingAuth`] and the moment it stops being redeemable.
struct PendingEntry {
    pending: PendingAuth,
    expires_at: Instant,
}

/// In-flight `/auth/login` → `/auth/callback` PKCE state, keyed by CSRF `state`
/// (`ID-3`). Single-process, held behind the [`AuthShellState`] mutex. A
/// `state` authorizes exactly one callback: [`take`](Self::take) removes it,
/// so a replayed or forged `state` finds nothing (fail-closed, `INV-20`).
///
/// A callback is the only thing that consumes an entry, and not every login
/// leg reaches one: a person can abandon the provider screen, and the deployed
/// account-session canary reads the redirect deliberately without following
/// it. So entries also expire after [`PENDING_AUTH_TTL`] and are swept on the
/// next [`begin`](Self::begin) — the store is bounded by the rate of *recent*
/// logins rather than by every login the process has ever started. Loopback
/// scaffold: a real multi-node deployment backs this with shared, TTL-bounded
/// storage behind the same seam (mirroring
/// [`SessionStore`](crate::session::SessionStore)).
#[derive(Default)]
pub struct PendingAuthStore {
    by_state: BTreeMap<String, PendingEntry>,
}

impl PendingAuthStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the pending PKCE state a login leg minted, keyed by its CSRF
    /// `state`, and drop whatever has expired by `now`.
    pub fn begin(&mut self, state: impl Into<String>, pending: PendingAuth, now: Instant) {
        self.by_state.retain(|_, entry| entry.expires_at > now);
        // Drop the oldest, never the newest: evicting the entry just minted
        // would break the person who has only this moment clicked sign in.
        while self.by_state.len() >= PENDING_AUTH_MAX {
            let oldest = self
                .by_state
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(state, _)| state.clone());
            match oldest {
                Some(state) => {
                    self.by_state.remove(&state);
                }
                None => break,
            }
        }
        self.by_state.insert(
            state.into(),
            PendingEntry {
                pending,
                expires_at: now + PENDING_AUTH_TTL,
            },
        );
    }

    /// Consume the pending state for a callback's `state` (single-use). `None` for an
    /// unknown / already-redeemed / forged / expired `state` — the CSRF guard.
    pub fn take(&mut self, state: &str, now: Instant) -> Option<PendingAuth> {
        let entry = self.by_state.remove(state)?;
        (entry.expires_at > now).then_some(entry.pending)
    }

    /// How many logins are awaiting their callback.
    pub fn len(&self) -> usize {
        self.by_state.len()
    }

    /// Whether any login is awaiting its callback.
    pub fn is_empty(&self) -> bool {
        self.by_state.is_empty()
    }
}

/// What has proved the person controls the address a consumer signup will use.
#[derive(Clone, Debug)]
pub enum ConsumerSignupEmail {
    /// The provider attested it (`email_verified`), which DR-0177 accepts as
    /// step 1 on its own. From `id_token_verified_email`, never callback input.
    Attested(String),
    /// Nothing has proved it yet. The provider asserts no verified address —
    /// Entra has no such claim — so a code must come back before the account is
    /// created. The address here is a prefill for the form and carries no
    /// authority whatever; it is deliberately not usable as an account fact.
    Unproved { prefill: Option<String> },
}

impl ConsumerSignupEmail {
    /// The attested address, or `None` when nothing has proved one. The only way
    /// to reach an address that may be treated as a verified contact.
    pub fn attested(&self) -> Option<&str> {
        match self {
            Self::Attested(email) => Some(email),
            Self::Unproved { .. } => None,
        }
    }

    /// The address to show in the form, proved or not. Display only.
    pub fn for_display(&self) -> Option<&str> {
        match self {
            Self::Attested(email) => Some(email),
            Self::Unproved { prefill } => prefill.as_deref(),
        }
    }
}

/// Verified Google facts parked between a first-time provider callback and the
/// passkey ceremony that will actually create the account (ADR 0146 §1).
///
/// A provider callback for a subject nobody has linked used to be a dead end: a
/// 403 telling a person with no account to sign in with the passkey they do not
/// have. It is not a dead end because the facts are missing — the id-token has
/// already been signature-, issuer-, audience- and nonce-verified by the time
/// this is built. It was a dead end because nothing carried those facts to the
/// ceremony that creates accounts.
///
/// This is what carries them. It writes **no** account state: an abandoned
/// signup leaves nothing behind. Nothing here is minted into an account until
/// [`finish_registration`](crate::account_auth_ceremony) commits the root, the
/// passkey, this subject link and the recovery batch in one append — so the
/// Google subject is an authenticator *on* the account, never the account.
#[derive(Clone, Debug)]
pub struct PendingConsumerSignup {
    /// The address this signup will record, and what has proved it.
    ///
    /// A sum rather than a string plus a flag, so no caller can read the address
    /// without seeing which kind it is: creating an account from an unproved one
    /// is the failure this type exists to make unrepresentable (DR-0189 §4).
    pub email: ConsumerSignupEmail,
    pub connection_id: String,
    pub connection_revision: String,
    pub issuer: String,
    /// The provider subject that will be linked, not used as the account id.
    pub subject: String,
    /// The `name` claim, offered to prefill the ceremony's name field. A
    /// convenience; the person may replace it.
    pub display_name: Option<String>,
    /// Carried only so a desktop signup's native handoff can seal the same
    /// durable grant an ordinary desktop login does. Redacted from `Debug`.
    pub refresh_token: Option<crate::secret::Secret>,
    pub provider_expires_at_ms: u64,
    /// Both carried through from [`PendingAuth`] so a desktop signup ends where
    /// a desktop login ends, over `gaugewright://`.
    pub native_return: Option<String>,
    pub native_handoff_challenge: Option<String>,
    /// The verified `picture` URL, adopted as the first avatar once the account
    /// exists (DR-0195 §2). Held in memory with the ticket; never stored.
    pub picture: Option<String>,
    /// Which browser completed the provider round trip that minted this ticket.
    ///
    /// Without it the ticket is a pure bearer in a URL fragment: an attacker
    /// signs in with their OWN Google account, takes the resulting link, and
    /// sends it to someone else. That person's browser claims it, is shown the
    /// attacker's address, and — if they do not read it — finishes a passkey
    /// ceremony that creates an account the attacker can sign into with Google.
    /// Everything the person then puts in it is the attacker's. That is
    /// pre-account fixation, and reading the address is a hope rather than a
    /// control.
    ///
    /// So the callback also sets this secret as an `HttpOnly` cookie, and both
    /// redemption routes require it back. The cookie lands on the browser that
    /// did the round trip and nowhere else; a planted link arrives without it.
    /// Redacted from `Debug` for the same reason the refresh token is.
    pub browser_binding: crate::secret::Secret,
}

struct PendingSignupEntry {
    signup: PendingConsumerSignup,
    expires_at: Instant,
}

/// Signup tickets awaiting their passkey ceremony.
///
/// A ticket is a bearer for one verified email and one provider subject:
/// whoever holds it can create an account bound to that Google identity. So it
/// gets exactly the custody [`PendingAuthStore`] has — a CSPRNG token, a single
/// consuming [`take`](Self::take), [`PENDING_AUTH_TTL`], and a
/// [`PENDING_AUTH_MAX`] ceiling that holds even when nothing has expired. It
/// travels in a URL fragment so it never reaches history, a `Referer`, or a
/// server log, and it is never accepted anywhere a WebAuthn ceremony id is.
#[derive(Default)]
pub struct PendingConsumerSignupStore {
    by_ticket: BTreeMap<String, PendingSignupEntry>,
}

impl PendingConsumerSignupStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Park verified provider facts and return the ticket that redeems them.
    pub fn begin(&mut self, signup: PendingConsumerSignup, now: Instant) -> Option<String> {
        self.by_ticket.retain(|_, entry| entry.expires_at > now);
        while self.by_ticket.len() >= PENDING_AUTH_MAX {
            let oldest = self
                .by_ticket
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(ticket, _)| ticket.clone());
            match oldest {
                Some(ticket) => {
                    self.by_ticket.remove(&ticket);
                }
                None => break,
            }
        }
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).ok()?;
        let ticket = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        self.by_ticket.insert(
            ticket.clone(),
            PendingSignupEntry {
                signup,
                expires_at: now + PENDING_AUTH_TTL,
            },
        );
        Some(ticket)
    }

    /// Read without consuming, for the non-secret projection the signup page
    /// renders before it touches the authenticator. Deliberately not `take`:
    /// rendering "create your account for jack@…" must not spend the ticket the
    /// ceremony still needs.
    pub fn peek(&self, ticket: &str, now: Instant) -> Option<&PendingConsumerSignup> {
        let entry = self.by_ticket.get(ticket)?;
        (entry.expires_at > now).then_some(&entry.signup)
    }

    /// Consume the ticket (single-use). An unknown, replayed, or expired ticket
    /// finds nothing.
    pub fn take(&mut self, ticket: &str, now: Instant) -> Option<PendingConsumerSignup> {
        let entry = self.by_ticket.remove(ticket)?;
        (entry.expires_at > now).then_some(entry.signup)
    }

    pub fn len(&self) -> usize {
        self.by_ticket.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ticket.is_empty()
    }
}

/// The consumer login shell's route table (ADR 0122): every composition of
/// the core control plane can serve `/auth/*`. The caller supplies the shell
/// state — with its composition fold registered (enterprise), or plain for a
/// solo/open shell. Mounting this unconfigured is safe: `/auth/login` answers
/// 409 until a connection is configured, and the native handoff + refresh
/// routes answer 404 outside web-account mode.
///
/// The `/auth/mobile/*` wire paths predate the desktop client and are kept
/// verbatim so existing mobile clients never break (ADR 0123).
pub fn auth_routes(state: AuthShellState) -> axum::Router<SharedWorkbench> {
    use axum::routing::{get, post};
    axum::Router::new()
        // `/auth/login` redirects the browser to the configured IdP;
        // `/auth/callback` redeems the code. Hosted corporate login resolves
        // the verified subject to an independent GaugeDesk account before it
        // mints the opaque browser session.
        .route("/auth/login", get(get_login))
        // Work-email discovery is a POST so the address never rides in a URL.
        // The server selects one DNS-verified organization connection and puts
        // that exact scope/revision in the ordinary pending-login state.
        .route("/auth/work-email", post(post_work_email_login))
        .route("/auth/callback", get(get_callback))
        // Consumer OIDC is an optional authenticator on an existing account.
        // Desk starts it over the authenticated API, then opens the returned
        // authorize URL in the system browser; that browser need not share the
        // Desk webview's cookie.
        .route(
            "/auth/account/consumer-oidc/link/start",
            post(post_consumer_oidc_link_start),
        )
        .route(
            "/auth/account/consumer-oidc/avatar/start",
            post(post_consumer_oidc_avatar_start),
        )
        // Safe current-session projection for the Account menu. This is not a
        // linked-method or recovery/custody declaration.
        .route("/auth/session", get(get_session))
        // Session refresh (ADR 0077): a still-valid session mints a fresh id-token
        // cookie from the stored refresh token, so a hosted session outlives the
        // ~1h id-token without re-login.
        .route("/auth/refresh", get(get_refresh))
        // Native device handoff (ADR 0123): mobile and desktop both redeem the
        // custom-scheme single-use code + verifier here.
        .route("/auth/mobile/refresh", post(post_native_refresh))
        .route("/auth/mobile/exchange", post(post_native_exchange))
        // Sign-out expires the shared HttpOnly account cookie. It remains reachable
        // with an expired/absent session so logout is always idempotent cleanup.
        .route("/auth/logout", post(post_logout))
        .merge(crate::account_auth_ceremony::routes())
        .layer(Extension(state))
}

/// The auth shell's composition-scoped state (`ID-3`, ADR 0122) — **axum
/// state**, not a [`Workbench`] field. The composition's route builder mints
/// one and carries it to the `/auth/login` + `/auth/callback` handlers as an
/// [`Extension`], so the pending-login store's lifetime spans requests
/// (created once per composition, never per-request). A cheap-to-clone shared
/// handle; its own mutex keeps [`PendingAuthStore::take`]'s single-use CSRF
/// consumption atomic. The optional [`LoginFold`] is where a composition
/// (e.g. enterprise) registers membership consequences.
#[derive(Clone, Default)]
pub struct AuthShellState {
    pending_auth: Arc<Mutex<PendingAuthStore>>,
    pending_consumer_signup: Arc<Mutex<PendingConsumerSignupStore>>,
    native_handoffs: Arc<Mutex<NativeHandoffStore>>,
    login_fold: Option<LoginFold>,
    enterprise_test_fold: Option<EnterpriseConnectionTestFold>,
    enterprise_saml_start: Option<EnterpriseSamlStart>,
    account_auth: Option<Arc<crate::account_auth_ceremony::AccountAuthRuntime>>,
}

/// What the composition resolves after a provider assertion is verified and
/// before any session is minted (ADR 0122 §3). Corporate subject→account links
/// and explicit organization admission are the composition's responsibility;
/// the shell owns the resulting account session. A consumer-provider fallback
/// has no enterprise login context and therefore does not invoke this fold.
pub type LoginFold = Arc<
    dyn Fn(
            &mut Workbench,
            &PendingEnterpriseLogin,
            &VerifiedEnterpriseIdentity,
        ) -> Result<LoginResolution, LoginFoldRefusal>
        + Send
        + Sync,
>;

/// Account identity and exact method produced by a composition-owned corporate
/// login fold. The external subject is never used as the account id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginResolution {
    pub account_id: String,
    pub session_method: String,
}

/// Closed callback refusal classes. The browser receives a bounded product
/// message rather than reducer internals or identity-provider material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginFoldRefusal {
    NotAdmitted,
    StaleConnection,
    Unavailable,
}

/// Composition-owned durable consequence of a successful isolated browser
/// test. Keeping the hook here lets the shared OIDC shell verify one callback
/// route while the enterprise band owns organization evidence and policy.
pub type EnterpriseConnectionTestFold = Arc<
    dyn Fn(
            &mut Workbench,
            &PendingEnterpriseConnectionTest,
            &VerifiedOidcIdentity,
        ) -> Result<(), String>
        + Send
        + Sync,
>;

impl AuthShellState {
    /// Empty shell state (no composition fold).
    pub fn new() -> Self {
        Self {
            account_auth: crate::account_auth_ceremony::AccountAuthRuntime::from_env(),
            ..Self::default()
        }
    }

    /// Register the composition's post-login fold (ADR 0122 §3).
    pub fn with_login_fold(mut self, fold: LoginFold) -> Self {
        self.login_fold = Some(fold);
        self
    }

    /// Register the enterprise band's non-login callback consequence.
    pub fn with_enterprise_connection_test_fold(
        mut self,
        fold: EnterpriseConnectionTestFold,
    ) -> Self {
        self.enterprise_test_fold = Some(fold);
        self
    }

    /// Register the enterprise band's ordinary SAML authorize leg.
    pub fn with_enterprise_saml_start(mut self, start: EnterpriseSamlStart) -> Self {
        self.enterprise_saml_start = Some(start);
        self
    }

    /// Install the provider-neutral GaugeDesk account ceremony runtime.
    pub fn with_account_auth(
        mut self,
        runtime: Arc<crate::account_auth_ceremony::AccountAuthRuntime>,
    ) -> Self {
        self.account_auth = Some(runtime);
        self
    }

    pub fn account_auth(&self) -> Option<Arc<crate::account_auth_ceremony::AccountAuthRuntime>> {
        self.account_auth.clone()
    }

    /// In-flight OIDC login store (`ID-3`), mutable: `/auth/login` records a
    /// pending PKCE state and `/auth/callback` consumes it (one lock hold per
    /// operation — the store's single-use `take` stays atomic).
    pub fn pending_auth_mut(&self) -> MutexGuard<'_, PendingAuthStore> {
        self.pending_auth.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// First-time provider signup tickets (ADR 0146 §1). `/auth/callback` parks
    /// verified facts here; the account ceremony consumes them.
    pub fn pending_consumer_signup_mut(&self) -> MutexGuard<'_, PendingConsumerSignupStore> {
        self.pending_consumer_signup
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn native_handoffs_mut(&self) -> MutexGuard<'_, NativeHandoffStore> {
        self.native_handoffs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Issue the same one-time native handoff an ordinary provider login issues,
    /// for a desktop signup that finished its passkey ceremony in the system
    /// browser. The account is already resolved — this mints no identity, and
    /// the code is still redeemable only with the verifier whose challenge the
    /// desktop pinned at `/auth/login`.
    pub(crate) fn issue_account_native_handoff(
        &self,
        account_id: &str,
        session_method: &str,
        label: &str,
        provider_expires_at_ms: u64,
        refresh_token: Option<String>,
        challenge: String,
    ) -> String {
        self.native_handoffs_mut().issue(
            NativeHandoffIssue {
                account_id: account_id.to_owned(),
                session_method: session_method.to_owned(),
                label: label.to_owned(),
                provider_expires_at_ms,
                refresh_token,
                challenge,
            },
            Instant::now(),
        )
    }

    fn begin_enterprise_saml(&self, request: EnterpriseSamlStartRequest) -> Result<String, String> {
        self.enterprise_saml_start
            .as_ref()
            .ok_or_else(|| "SAML sign-in is unavailable on this server".to_owned())?(request)
    }

    /// Resolve a verified corporate subject through the composition-owned
    /// organization admission fold. Both OIDC and SAML use this exact seam.
    pub fn resolve_enterprise_login(
        &self,
        wb: &mut Workbench,
        context: &PendingEnterpriseLogin,
        identity: &VerifiedEnterpriseIdentity,
    ) -> Result<LoginResolution, LoginFoldRefusal> {
        self.login_fold
            .as_ref()
            .ok_or(LoginFoldRefusal::Unavailable)?(wb, context, identity)
    }
}

struct NativeHandoff {
    /// Independent GaugeDesk account resolved before the handoff was issued.
    /// Native device enrollment is account-scoped and must not derive this
    /// identity again from the external token's `sub` claim.
    account_id: String,
    /// Exact method that resolved the account. The opaque native session carries
    /// the same method as a browser session from this callback.
    session_method: String,
    /// A non-secret, human-recognizable label projected from the already-verified
    /// assertion. The external token itself never crosses the native exchange.
    label: String,
    /// Expiry of the already-verified provider token. It bounds a session for
    /// which the provider issued no refresh grant and schedules renewal when one
    /// exists; it is not used as native identity evidence.
    provider_expires_at_ms: u64,
    /// The offline-access refresh token captured at the same callback, carried so
    /// the exchange can seal the native session its own durable grant (ADR 0147 §2)
    /// — independent of the browser `web` grant, which a prior logout may already
    /// have tombstoned. `None` when the OP granted no refresh token.
    refresh_token: Option<crate::secret::Secret>,
    challenge: String,
    expires_at: Instant,
}

/// What a redeemed native handoff yields. Provider credentials remain inside the
/// Hub; the native client receives a separately minted opaque account session.
struct RedeemedHandoff {
    account_id: String,
    session_method: String,
    label: String,
    provider_expires_at_ms: u64,
    refresh_token: Option<String>,
}

struct NativeHandoffIssue {
    account_id: String,
    session_method: String,
    label: String,
    provider_expires_at_ms: u64,
    refresh_token: Option<String>,
    challenge: String,
}

/// Provider-neutral inputs for delivering a verified corporate login after
/// the organization fold resolved its independent GaugeDesk account. Protocol
/// credentials stay server-side; the browser or native client receives only a
/// durable opaque account session (or a one-time native handoff code).
pub struct EnterpriseLoginDelivery {
    pub login_context: PendingEnterpriseLogin,
    pub resolution: LoginResolution,
    pub display_label: String,
    pub provider_expires_at_ms: u64,
    pub refresh_token: Option<String>,
    pub native_return: Option<String>,
    pub native_handoff_challenge: Option<String>,
}

#[derive(Default)]
struct NativeHandoffStore {
    by_code: BTreeMap<String, NativeHandoff>,
}

impl NativeHandoffStore {
    fn issue(&mut self, issue: NativeHandoffIssue, now: Instant) -> String {
        self.by_code.retain(|_, handoff| handoff.expires_at > now);
        let code = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(crate::session::random_bytes::<32>());
        self.by_code.insert(
            code.clone(),
            NativeHandoff {
                account_id: issue.account_id,
                session_method: issue.session_method,
                label: issue.label,
                provider_expires_at_ms: issue.provider_expires_at_ms,
                refresh_token: issue.refresh_token.map(Into::into),
                challenge: issue.challenge,
                expires_at: now + Duration::from_secs(5 * 60),
            },
        );
        code
    }

    fn redeem(&mut self, code: &str, verifier: &str, now: Instant) -> Option<RedeemedHandoff> {
        let handoff = self.by_code.remove(code)?;
        if handoff.expires_at <= now
            || crate::identity_oidc::s256_challenge(verifier) != handoff.challenge
        {
            return None;
        }
        Some(RedeemedHandoff {
            account_id: handoff.account_id,
            session_method: handoff.session_method,
            label: handoff.label,
            provider_expires_at_ms: handoff.provider_expires_at_ms,
            refresh_token: handoff
                .refresh_token
                .as_ref()
                .map(|token| token.expose().to_string()),
        })
    }
}

impl AuthShellState {
    /// Complete one corporate login through the shared account-session
    /// authority. OIDC and SAML call this only after assertion verification and
    /// the same organization admission fold; no provider credential is exposed.
    pub fn deliver_enterprise_login(
        &self,
        wb: &SharedWorkbench,
        delivery: EnterpriseLoginDelivery,
    ) -> axum::response::Response {
        let EnterpriseLoginDelivery {
            login_context,
            resolution,
            display_label,
            provider_expires_at_ms,
            refresh_token,
            native_return,
            native_handoff_challenge,
        } = delivery;
        let account_id = resolution.account_id;
        let session_method = resolution.session_method;

        {
            let mut guard = wb.lock_unpoisoned();
            crate::audit::record_in(
                &mut guard,
                &login_context.store_scope,
                &account_id,
                "auth.login",
                &account_id,
            );
            provision_web_account(&mut guard, &account_id, web_account_mode());
        }

        if let Some(native_return) = native_return {
            let Some(challenge) = native_handoff_challenge else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "native handoff challenge was lost",
                )
                    .into_response();
            };
            let code = self.native_handoffs_mut().issue(
                NativeHandoffIssue {
                    account_id,
                    session_method,
                    label: display_label,
                    provider_expires_at_ms,
                    refresh_token,
                    challenge,
                },
                Instant::now(),
            );
            return Redirect::to(&format!("{native_return}#code={code}")).into_response();
        }

        let token = {
            let mut guard = wb.lock_unpoisoned();
            let Some(token) = guard.mint_account_session(
                &account_id,
                &session_method,
                crate::account::SESSION_ABSOLUTE_LIFETIME_MS / 1000,
            ) else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not create the account session",
                )
                    .into_response();
            };
            if web_account_mode() {
                if let Some(refresh_token) = refresh_token.as_deref() {
                    let session_id = crate::account_session::session_id(&token);
                    store_refresh_token(
                        &mut guard,
                        &account_id,
                        refresh_token,
                        crate::account::RefreshBinding::Web,
                        &session_id,
                        "",
                    );
                }
            }
            token
        };

        if web_account_mode() {
            let post_login = gaugedesk_env::var("OIDC_POST_LOGIN_URL")
                .filter(|url| !url.trim().is_empty())
                .unwrap_or_else(|| "/".to_owned());
            let mut response = Redirect::to(&post_login).into_response();
            append_session_cookies(&mut response, &token);
            return response;
        }

        if let Some(url) = gaugedesk_env::var("OIDC_POST_LOGIN_URL") {
            if !url.trim().is_empty() {
                return Redirect::to(&format!("{url}#id_token={token}&token_type=Bearer"))
                    .into_response();
            }
        }
        (
            StatusCode::OK,
            Json(json!({
                "authority": account_id,
                "id_token": token,
                "token_type": "Bearer",
            })),
        )
            .into_response()
    }
}

/// Why `/auth/login` could not begin a flow.
#[derive(Debug)]
pub enum LoginError {
    /// No SSO connection, or it is not an OIDC connection / has no client id.
    NotConfigured,
    /// The OIDC connection has no issuer URL.
    NoIssuer,
    /// OIDC discovery (`.well-known/openid-configuration`) failed.
    Discovery(String),
    /// The OS CSPRNG was unavailable for PKCE/state generation.
    Pkce(String),
}

/// Begin the auth-code + PKCE flow: discover the OP endpoints, mint a PKCE pair + a
/// random CSRF `state`, and build the authorize-endpoint redirect. Returns the URL to
/// send the browser to, the `state` key, and the [`PendingAuth`] for the callback to
/// stash. Free of axum/IO except the injected discovery [`HttpGet`] — so it is tested
/// against a mock OP.
pub fn start_login(
    sso: &SsoConnectionRecord,
    redirect_uri: &str,
    scope: &str,
    mapping: ClaimMapping,
    http: &impl HttpGet,
) -> Result<(String, String, PendingAuth), LoginError> {
    // Everything that is not a consumer entrance — organization connections and
    // every test that predates the provider table — keeps the behaviour it had.
    start_login_with(
        sso,
        redirect_uri,
        scope,
        mapping,
        OfflineGrant::AccessTypeOffline,
        http,
    )
}

/// [`start_login`] for a connection whose refresh-token mechanism is known.
pub fn start_login_with(
    sso: &SsoConnectionRecord,
    redirect_uri: &str,
    scope: &str,
    mapping: ClaimMapping,
    offline: OfflineGrant,
    http: &impl HttpGet,
) -> Result<(String, String, PendingAuth), LoginError> {
    if sso.protocol != SsoProtocol::Oidc {
        return Err(LoginError::NotConfigured);
    }
    if sso.issuer.trim().is_empty() {
        return Err(LoginError::NoIssuer);
    }
    let client_id = sso.audiences.first().ok_or(LoginError::NotConfigured)?;
    let endpoints = discover_endpoints(&sso.issuer, http).map_err(LoginError::Discovery)?;
    // What this login will verify `iss` against. For every ordinary connection it
    // is the configured issuer; for a multi-tenant authority it is the tenant
    // template the authority declares, at the same origin (DR-0189 §2).
    let accepted_issuer = crate::identity_oidc::accepted_issuer(&sso.issuer, &endpoints.issuer)
        .ok_or_else(|| {
            LoginError::Discovery(format!(
                "the authority at {} declares issuer {}, which is neither the configured issuer nor a tenant template at the same origin",
                sso.issuer, endpoints.issuer
            ))
        })?;
    let pkce = Pkce::generate().map_err(LoginError::Pkce)?;
    // 16 CSPRNG bytes hex-encoded — unguessable, so a forged `state` cannot collide
    // with a live login (the CSRF binding the OP echoes back).
    let state = hex::encode(crate::session::random_bytes::<16>());
    // 16 CSPRNG bytes hex-encoded — the OIDC `nonce`. It rides the authorize request and
    // must come back inside the signed id-token's `nonce` claim (checked in
    // `finish_callback`), binding the token to this browser login (replay/injection
    // defense, `INV-20`).
    let nonce = hex::encode(crate::session::random_bytes::<16>());
    // Request **offline access** (ADR 0077 session refresh) the way this provider
    // issues it — see [`OfflineGrant`]. `GAUGEDESK_OIDC_PROMPT_CONSENT` still
    // governs Google's consent screen and no longer reaches anybody else's.
    let prompt_consent = gaugedesk_env::var("OIDC_PROMPT_CONSENT").as_deref() == Some("1");
    let extra = offline.authorize_params(prompt_consent);
    let scope = offline.scope(scope);
    let url = authorize_url(
        &endpoints.authorization_endpoint,
        client_id,
        redirect_uri,
        &scope,
        &state,
        &nonce,
        &pkce.challenge,
        &extra,
    );
    let pending = PendingAuth {
        verifier: pkce.verifier.into(),
        nonce,
        token_endpoint: endpoints.token_endpoint,
        jwks_uri: endpoints.jwks_uri,
        issuer: accepted_issuer,
        audiences: sso.audiences.clone(),
        redirect_uri: redirect_uri.to_string(),
        mapping,
        // The pure login leg carries no secret; the handler injects one from env for a
        // confidential OP (Google). Public PKCE clients leave it `None`.
        client_secret: None,
        native_return: None,
        native_handoff_challenge: None,
        login_context: None,
        // Set by the handler, which knows which authority it is serving.
        consumer_connection_id: None,
        purpose: PendingAuthPurpose::Login,
    };
    Ok((url, state, pending))
}

/// Why `/auth/callback` could not finish a flow.
#[derive(Debug)]
pub enum CallbackError {
    /// The authorization code did not redeem at the token endpoint.
    Exchange(String),
    /// The issuer's JWKS could not be fetched or parsed.
    Jwks(String),
    /// The returned id-token failed signature / claim verification (fail-closed).
    NotVerified,
}

/// Complete the flow: redeem `code` at the token endpoint with the stashed PKCE
/// verifier, fetch the issuer's live JWKS, and verify the returned id-token. Returns
/// the authenticated [`AuthorityId`] and the verified **id-token** (the bearer the
/// control plane accepts). Fail-closed: a code that does not redeem, or a token that
/// does not verify against the live keys, yields an error and no authority (`INV-20`).
pub fn finish_callback(
    pending: &PendingAuth,
    code: &str,
    http: &(impl HttpForm + HttpGet),
) -> Result<(AuthorityId, String, Option<String>), CallbackError> {
    let verified = finish_callback_verified(pending, code, http)?;
    Ok((
        verified.authority,
        verified.id_token,
        verified.refresh_token,
    ))
}

/// Complete and verify an OIDC return while retaining the mapped claim result
/// for an enterprise test-purpose callback. Ordinary callers keep using
/// [`finish_callback`], whose wire-compatible tuple deliberately omits it.
pub fn finish_callback_verified(
    pending: &PendingAuth,
    code: &str,
    http: &(impl HttpForm + HttpGet),
) -> Result<VerifiedOidcIdentity, CallbackError> {
    let client_id = pending
        .audiences
        .first()
        .map(String::as_str)
        .unwrap_or_default();
    let (id_token, refresh_token) = exchange_code(
        &pending.token_endpoint,
        client_id,
        &pending.redirect_uri,
        code,
        pending.verifier.expose(),
        pending.client_secret.as_ref().map(|s| s.expose()), // confidential OP (Google); None = public PKCE
        http,
    )
    .map_err(CallbackError::Exchange)?;

    // Verify against the issuer's *live* JWKS — the token from the exchange is not yet
    // trusted (it could be anything the token endpoint returned).
    let jwks = http.get(&pending.jwks_uri).map_err(CallbackError::Jwks)?;
    let idp = OidcIdentityProvider::new(pending.issuer.clone(), pending.audiences.clone())
        .with_mapping(pending.mapping.clone())
        .with_jwks(&jwks)
        .map_err(CallbackError::Jwks)?;
    let authority = idp
        .authenticate(&id_token)
        .ok_or(CallbackError::NotVerified)?;
    // Bind the id-token to *this* browser login: its `nonce` claim must equal the one
    // minted on the authorize leg and stashed in `pending`. `authenticate` already
    // verified the signature, so the payload is authentic — reading `nonce` off it is
    // safe. A missing or mismatched nonce is fail-closed (replay/injection, `INV-20`).
    if id_token_nonce(&id_token).as_deref() != Some(pending.nonce.as_str()) {
        return Err(CallbackError::NotVerified);
    }
    let attributes = idp.claims(&authority);
    // The refresh token (present only on an offline-access consent grant) rides back so the
    // callback can seal it for the session-refresh leg (ADR 0077).
    Ok(VerifiedOidcIdentity {
        authority,
        id_token,
        refresh_token,
        attributes,
    })
}

/// The `nonce` claim of an **already-verified** id-token (its signature and registered
/// claims were checked via [`OidcIdentityProvider::authenticate`]), read straight off the
/// payload segment for the login-session binding check in [`finish_callback`]. `None` if
/// the token carries no readable `nonce`.
fn id_token_nonce(id_token: &str) -> Option<String> {
    id_token_claims(id_token)?
        .get("nonce")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Claims from an already-verified id-token. This is projection only: callers
/// reach it after signature and registered-claim verification, and no value read
/// here is accepted as a fresh credential.
fn id_token_claims(id_token: &str) -> Option<serde_json::Value> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Human-recognizable label for a native account session. Email is preferred,
/// then name; an opaque provider subject is deliberately not surfaced.
fn id_token_display_label(id_token: &str) -> Option<String> {
    let claims = id_token_claims(id_token)?;
    ["email", "name"].iter().find_map(|key| {
        claims
            .get(*key)
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

/// The provider's `name` claim, offered only to prefill a signup form. It is a
/// convenience string: it names nobody, authenticates nothing, and the person
/// can replace it before the account exists.
fn id_token_display_name(id_token: &str) -> Option<String> {
    id_token_claims(id_token)?
        .get("name")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// The provider's `picture` claim, if it is an `https` URL. Offered to the
/// account as its first avatar and never stored as a URL (DR-0195).
fn id_token_picture(id_token: &str) -> Option<String> {
    crate::account_avatar::picture_claim(&id_token_claims(id_token)?)
}

/// Email admitted from an already-verified OIDC token. Organization admission
/// requires the provider to mark it verified; the address submitted for
/// discovery is deliberately never consulted here.
fn id_token_verified_email(id_token: &str) -> Option<String> {
    let claims = id_token_claims(id_token)?;
    if claims
        .get("email_verified")
        .and_then(|value| value.as_bool())
        != Some(true)
    {
        return None;
    }
    claims
        .get("email")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// The `iss` of an **already-verified** id-token.
///
/// This is the concrete issuer, which for a multi-tenant authority names the
/// tenant that issued the token and is therefore not the template the connection
/// was pinned with. Durable state keys on this, because the tenant is part of the
/// authenticator's identity (DR-0189 §3): the same person's work and personal
/// accounts are two links, and keying on the template would collapse them into
/// one — and let a subject from any tenant resolve against another's link.
///
/// Safe to read off the payload: `authenticate` has already demanded that this
/// exact value equal the accepted issuer with the token's own tenant substituted.
fn id_token_issuer(id_token: &str) -> Option<String> {
    id_token_claims(id_token)?
        .get("iss")
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

/// The address a token merely *asserts*, with nothing attesting control of it.
///
/// Deliberately not named `verified`: Entra ID emits no `email_verified` claim,
/// and its `email`, `preferred_username` and `upn` are mutable values a tenant
/// administrator sets and is not constrained to domains the tenant owns. So this
/// is a prefill for a form and nothing else — the only thing that turns it into
/// an account fact is a code coming back to it (DR-0189 §4).
fn id_token_asserted_email(id_token: &str) -> Option<String> {
    let claims = id_token_claims(id_token)?;
    ["email", "preferred_username"].iter().find_map(|key| {
        claims
            .get(*key)
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| value.contains('@'))
            .map(str::to_string)
    })
}

/// Provider-token expiry in epoch milliseconds. The token was already verified
/// on the callback leg; native code uses this only to schedule server-side
/// renewal or to bound a no-refresh-grant session.
fn id_token_expiry_ms(id_token: &str) -> Option<u64> {
    id_token_claims(id_token)?
        .get("exp")
        .and_then(|value| value.as_u64())
        .map(|seconds| seconds.saturating_mul(1000))
}

// ---- enterprise-mode activation (wb.idp from the SSO connection) ---------

/// How id-token claims map onto ABAC attributes for a connection (`ID-3`). The home
/// is the SSO connection record (`/admin/sso`); each field falls back to its
/// `GAUGEDESK_OIDC_*_CLAIM` env knob (the legacy operator path) and then to unmapped
/// (fail-closed: no attribute is safer than a wrong one). The subject defaults to `sub`.
/// RBAC console gating reads the member's role from the org directory, not the token —
/// so this only feeds the *attribute* path (roles/region/tenant the ABAC evaluator reads).
pub fn claim_mapping_for(sso: &SsoConnectionRecord) -> ClaimMapping {
    let env_opt = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
    let m = &sso.claim_mapping;
    ClaimMapping {
        subject_claim: m
            .subject_claim
            .clone()
            .or_else(|| env_opt("GAUGEDESK_OIDC_SUBJECT_CLAIM"))
            .unwrap_or_else(|| "sub".to_string()),
        roles_claim: m
            .roles_claim
            .clone()
            .or_else(|| env_opt("GAUGEDESK_OIDC_ROLES_CLAIM")),
        region_claim: m
            .region_claim
            .clone()
            .or_else(|| env_opt("GAUGEDESK_OIDC_REGION_CLAIM")),
        tenant_claim: m
            .tenant_claim
            .clone()
            .or_else(|| env_opt("GAUGEDESK_OIDC_TENANT_CLAIM")),
    }
}

/// JWKS refresh cooldown: at most one discovery fetch per window — so a flood of
/// unknown-`kid` tokens can't stampede the OP, and a persistent outage is retried
/// (not hammered). Also the worst-case heal latency after the IdP recovers.
const JWKS_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);

/// The mutable half of a [`RefreshingOidcProvider`]: the loaded verifier plus what we
/// need to decide whether a verification miss warrants a JWKS refresh.
struct RefreshState {
    provider: OidcIdentityProvider,
    /// The `kid`s of the signing keys currently loaded — a token whose `kid` is here
    /// is verifiable, so a miss for it is a bad token, not a stale key set.
    known_kids: BTreeSet<String>,
    /// Whether any signing key is loaded (the IdP has been reached at least once).
    has_keys: bool,
    /// When we last *attempted* a refresh (success or failure) — the cooldown anchor.
    last_refresh: Option<Instant>,
}

/// An [`IdentityProvider`] that verifies OIDC id-tokens and **self-refreshes** its
/// signing keys from the issuer's JWKS (`ID-3`). Wraps the pure [`OidcIdentityProvider`]
/// (which deliberately speaks no HTTP) with the discovery seam, so:
///
/// - a verifier that started **cold** (the IdP was unreachable at startup) heals on
///   the first login once the IdP is back — no restart, no brick; and
/// - **key rotation** is handled: a token signed by a newly-published key (an unknown
///   `kid`) triggers a refresh and then verifies.
///
/// Refreshes are bounded by [`JWKS_REFRESH_COOLDOWN`] and fire only on a genuine
/// cache-miss (an unknown `kid`, or no keys at all) — never for a token whose `kid` we
/// already hold (a bad signature is just rejected), so invalid tokens cannot stampede
/// the OP. Fail-closed throughout (`INV-20`): until keys load, nothing authenticates.
///
/// The refresh runs synchronously on the verifying call (which holds the workbench
/// lock); it is rare (cache-miss only) and uses a short HTTP timeout, so the stall is
/// bounded. A fully off-lock async refresh is a later refinement.
pub struct RefreshingOidcProvider<H: HttpGet> {
    issuer: String,
    audiences: Vec<String>,
    mapping: ClaimMapping,
    http: H,
    /// Minimum spacing between on-request JWKS refreshes ([`JWKS_REFRESH_COOLDOWN`] in
    /// production; tunable so tests can drive the heal path without real time).
    cooldown: Duration,
    state: Mutex<RefreshState>,
}

impl<H: HttpGet> RefreshingOidcProvider<H> {
    /// Build a verifier for `issuer`, doing a **best-effort** initial JWKS load. If the
    /// IdP is unreachable the verifier is cold (authenticates nothing) but heals on
    /// first use once the IdP is back. `cooldown` bounds on-request refreshes.
    pub fn new(
        issuer: impl Into<String>,
        audiences: Vec<String>,
        mapping: ClaimMapping,
        http: H,
        cooldown: Duration,
    ) -> Self {
        let issuer = issuer.into();
        let me = Self {
            issuer: issuer.clone(),
            audiences: audiences.clone(),
            mapping: mapping.clone(),
            http,
            cooldown,
            state: Mutex::new(RefreshState {
                provider: OidcIdentityProvider::new(issuer, audiences).with_mapping(mapping),
                known_kids: BTreeSet::new(),
                has_keys: false,
                last_refresh: None,
            }),
        };
        let _ = me.refresh(); // warm up; cold is fine (heals on first use)
        me
    }

    /// Whether at least one signing key is loaded (the IdP was reachable). Used by the
    /// activation path to report whether a connection went live or is "saved, pending".
    pub fn is_warm(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .has_keys
    }

    /// Re-fetch the issuer's JWKS and rebuild the inner verifier. A failed fetch leaves
    /// the existing keys intact (a transient outage never *drops* working keys). Does
    /// not touch the cooldown anchor — the warm-up call must not spend the budget, so
    /// the first login after the IdP recovers heals immediately; the cooldown is
    /// anchored by the on-request path in [`authenticate`](Self#impl-IdentityProvider).
    fn refresh(&self) -> Result<(), String> {
        let jwks = discover_jwks(&self.issuer, &self.http)?;
        let provider = OidcIdentityProvider::new(self.issuer.clone(), self.audiences.clone())
            .with_mapping(self.mapping.clone())
            .with_jwks(&jwks)?; // errors unless ≥1 usable signing key
        let kids = jwks_kids(&jwks);
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.provider = provider;
        st.known_kids = kids;
        st.has_keys = true;
        Ok(())
    }
}

impl<H: HttpGet + Send + Sync> IdentityProvider for RefreshingOidcProvider<H> {
    fn authenticate(&self, credential: &str) -> Option<AuthorityId> {
        // Fast path: the cached keys verify it (the common case, no network).
        if let Some(authority) = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .provider
            .authenticate(credential)
        {
            return Some(authority);
        }
        // Miss. Refresh only on a genuine key gap (unknown `kid` / no keys), bounded by
        // the cooldown — a token whose `kid` we already hold is simply invalid.
        let header_kid = decode_header(credential).ok().and_then(|h| h.kid);
        {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let key_gap = match header_kid.as_deref() {
                Some(kid) => !st.known_kids.contains(kid),
                None => !st.has_keys,
            };
            let cooled = st.last_refresh.is_none_or(|t| t.elapsed() >= self.cooldown);
            if !(key_gap && cooled) {
                return None;
            }
            // Anchor the cooldown here (not in the warm-up): so the budget is spent by
            // on-request refreshes, and a persistent outage can't stampede the OP.
            st.last_refresh = Some(Instant::now());
        } // release the lock before the network fetch
        if self.refresh().is_err() {
            return None;
        }
        // Retry once against the refreshed keys.
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .provider
            .authenticate(credential)
    }

    fn claims(&self, authority: &AuthorityId) -> AuthorityAttributes {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .provider
            .claims(authority)
    }
}

/// The `kid`s of the usable signing keys in a JWKS document (RSA, not `use:"enc"`) —
/// what [`OidcIdentityProvider::with_jwks`] would load. Tracking them lets the
/// refreshing verifier tell "unknown key, refresh" from "known key, just a bad token".
fn jwks_kids(jwks_json: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(jwks_json) else {
        return out;
    };
    let Some(keys) = doc.get("keys").and_then(|k| k.as_array()) else {
        return out;
    };
    for jwk in keys {
        if jwk.get("use").and_then(|u| u.as_str()) == Some("enc") {
            continue;
        }
        if jwk.get("kty").and_then(|v| v.as_str()) != Some("RSA") {
            continue;
        }
        if let Some(kid) = jwk.get("kid").and_then(|v| v.as_str()) {
            out.insert(kid.to_string());
        }
    }
    out
}

/// Build the [`IdentityProvider`] the control plane authenticates bearers against,
/// from the org's stored SSO connection (`ID-3` enterprise-mode activation). This is
/// what makes the id-token `/auth/callback` returns *honored* on `/admin/*`
/// (`Workbench::authorize` → `idp.authenticate`).
///
/// - No connection / not OIDC / no issuer or audiences ⇒ `None`: single-user local
///   mode (admin ungated) — the product's default.
/// - A configured OIDC connection ⇒ a self-refreshing verifier ([`RefreshingOidcProvider`])
///   plus a `warm` flag = whether the issuer's JWKS loaded on this attempt. A cold
///   verifier (IdP unreachable) is still returned — it heals on first use — so the
///   caller decides whether to attach it (startup: yes, fail-closed + healing) or hold
///   off (a runtime reconfigure: keep the working verifier until the new one is warm).
///
/// Touches the network (the initial JWKS load) — call off the async runtime.
pub fn build_oidc_idp(
    sso: Option<&SsoConnectionRecord>,
) -> Option<(Arc<dyn IdentityProvider + Send + Sync>, bool)> {
    let sso = sso?;
    if sso.protocol != SsoProtocol::Oidc || sso.issuer.trim().is_empty() || sso.audiences.is_empty()
    {
        return None;
    }
    let provider = RefreshingOidcProvider::new(
        sso.issuer.clone(),
        sso.audiences.clone(),
        claim_mapping_for(sso),
        HttpClient::with_timeout(Duration::from_secs(5)),
        JWKS_REFRESH_COOLDOWN,
    );
    let warm = provider.is_warm();
    Some((Arc::new(provider), warm))
}

/// Enterprise-mode activation (`ID-3`): if an OIDC SSO connection is configured,
/// attach a self-refreshing id-token verifier so the bearer `/auth/callback`
/// returns is honored on `/admin/*` (`Workbench::authorize` →
/// `idp.authenticate`).
///
/// No connection means single-user local mode, the default. A cold verifier (IdP
/// unreachable at startup) is still attached: it is fail-closed until keys load
/// and self-heals on the first login once the IdP is reachable.
///
/// Runs at **startup**, matching the pre-split workbench-open activation timing:
/// the ee composition setup (the ee `org_routes::enterprise_control_plane`)
/// calls it before serving, and the hosted shell (`gaugewright-cloud-server`)
/// calls it right after workbench open. Installs the verifier via the open
/// `Workbench::set_identity_provider` seam.
pub fn activate_configured_idp(wb: &mut Workbench) {
    // Prefer a stored SSO connection; else (hosted web account) the Google connection from env,
    // so the verifier that honors the callback's id-token is built even without an /admin/sso
    // record (ADR 0077).
    let sso = Org::rebuild(wb.store_ref())
        .ok()
        .and_then(|o| o.sso)
        .or_else(web_account_sso_from_env);
    if let Some((idp, warm)) = build_oidc_idp(sso.as_ref()) {
        if !warm {
            eprintln!(
                "[gaugewright] WARNING: OIDC SSO is configured but the IdP was unreachable at \
                 startup; /admin/* is fail-closed and the verifier will self-heal on the first \
                 login once the IdP is reachable (no restart needed)."
            );
        }
        wb.set_identity_provider(Some(idp));
    }
}

/// Runtime activation outcome after an admitted SSO reconfiguration. The
/// connection is durable even when an unreachable IdP leaves the prior verifier
/// in place; this result is operational evidence only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeIdpActivation {
    pub oidc_active: bool,
    pub activation_error: Option<String>,
}

/// Activate an admitted SSO connection without blocking the async runtime. Only
/// a warm OIDC provider replaces an existing verifier, so a bad runtime edit
/// cannot lock current administrators out.
pub async fn activate_updated_idp(
    wb: &SharedWorkbench,
    sso: SsoConnectionRecord,
) -> RuntimeIdpActivation {
    let built = tokio::task::spawn_blocking(move || build_oidc_idp(Some(&sso))).await;
    match built {
        Ok(None) => {
            wb.lock_unpoisoned().set_identity_provider(None);
            RuntimeIdpActivation {
                oidc_active: false,
                activation_error: None,
            }
        }
        Ok(Some((idp, true))) => {
            wb.lock_unpoisoned().set_identity_provider(Some(idp));
            RuntimeIdpActivation {
                oidc_active: true,
                activation_error: None,
            }
        }
        Ok(Some((_idp, false))) => RuntimeIdpActivation {
            oidc_active: wb.lock_unpoisoned().has_idp(),
            activation_error: Some(
                "OIDC discovery failed (issuer unreachable?); connection saved but not activated — the existing verifier is unchanged"
                    .to_string(),
            ),
        },
        Err(_) => RuntimeIdpActivation {
            oidc_active: wb.lock_unpoisoned().has_idp(),
            activation_error: Some("activation task panicked".to_string()),
        },
    }
}

/// Whether this deployment is the **hosted web account** (`ADR 0077`): a successful login
/// provisions the person their own account (a personal tenant-of-one), rather than only
/// reconciling them into an enterprise org directory. Off by default — the enterprise SSO and
/// desktop paths are unchanged; the hosted control-plane hub sets `GAUGEDESK_WEB_ACCOUNT=1`.
pub fn web_account_mode() -> bool {
    gaugedesk_env::var("WEB_ACCOUNT")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Whether `/auth/login` may skip the IdP ceremony for this request: only the hosted web
/// flow — never a native/dev handoff, which exists to mint a fresh single-use code — and only
/// when the carried session already authenticates to a real person. Pure; the handler wires in
/// the deployment mode, the handoff intent, and the resolved actor.
pub fn login_ceremony_skippable(web_account: bool, native_login: bool, actor: &str) -> bool {
    web_account && !native_login && actor != "anonymous"
}

/// Every browser/programmatic callback delivers an opaque GaugeDesk session.
/// Native handoff delays that mint until its PKCE-bound one-time code is
/// redeemed. An external provider token is never an account session.
fn requires_account_session(native_login: bool) -> bool {
    !native_login
}

/// Post-login account reconciliation for the hosted web account (`ADR 0077` §9): provision the
/// authenticated person's **personal tenant-of-one** (idempotent), so hosted sign-in lands them in
/// the Console with their own space. `person` is the independently resolved account root, never
/// the OIDC subject. No-op unless `web_account` — the enterprise/desktop login paths are untouched.
/// Returns the personal tenant id when provisioned. Best-effort: a store error yields `None` and
/// the login still succeeds (the person retries; provisioning self-heals, `tenancy::…`).
pub fn provision_web_account(
    wb: &mut Workbench,
    authority: &str,
    web_account: bool,
) -> Option<String> {
    if !web_account {
        return None;
    }
    // The personal tenant is the person's own space — displayed as "Personal", never as an org
    // (ADR 0077 §9); the `TenantRef.personal` flag is what the Console keys on.
    crate::tenancy::provision_personal_tenant(wb.store_mut(), authority, "Personal").ok()
}

/// Seal `refresh_token` into `person`'s own account scope as a durable, bound,
/// timestamped grant (`ADR 0147`). Sealed at rest by the control-plane authority
/// (`SEC-4`); the per-person scope is the access boundary (`INV-1`). Keyed by the
/// binding id — [`WEB_REFRESH_BINDING`](crate::account::WEB_REFRESH_BINDING) for the
/// browser, the enrolled device id for a native client — so concurrent sessions
/// coexist as distinct records rather than one latest-wins grant per person.
/// Best-effort (a seal failure is a no-op, the session just falls back to re-login
/// at id-token expiry).
fn store_refresh_token(
    wb: &mut Workbench,
    person: &str,
    refresh_token: &str,
    binding: crate::account::RefreshBinding,
    binding_id: &str,
    device_id: &str,
) {
    let Some(sealed) = wb.seal_account_secret(refresh_token) else {
        return;
    };
    let scope = crate::account::account_scope(person);
    let now_ms = crate::account::session_now_ms();
    let _ = wb.upsert_account_refresh_in(&scope, binding_id, binding, device_id, &sealed, now_ms);
}

/// The live refresh grant `person` holds for `binding_id`, or `None` if none is
/// stored for that binding or it is tombstoned. Reads the **stored** grant, so a
/// native caller cannot bypass its device binding by omitting a header (ADR 0147 §2).
fn resolve_refresh_grant(
    wb: &Workbench,
    person: &str,
    binding_id: &str,
) -> Option<crate::account::RefreshRecord> {
    let scope = crate::account::account_scope(person);
    wb.account_refresh_session_in(&scope, binding_id).ok()?
}

/// Admit (or refuse) a **browser** refresh for `person`'s session `session_id` at
/// `now_ms` (ADR 0147 §2/§4). The per-session grant keyed by that session id must be
/// live and within its personal-tenant bounds; an absent grant (never minted, or
/// tombstoned by this session's logout/revoke), or an elapsed absolute lifetime or
/// idle timeout, refuses with the reason. Keying by session id — not one coarse
/// per-person `web` key — is what makes concurrent browser sessions independent and
/// per-session revocation real. Returns the live grant on success.
fn admit_browser_refresh(
    wb: &Workbench,
    person: &str,
    session_id: &str,
    now_ms: u64,
) -> Result<crate::account::RefreshRecord, &'static str> {
    let grant = resolve_refresh_grant(wb, person, session_id)
        .ok_or("no refresh token on file; sign in again")?;
    crate::account::refresh_within_bounds(&grant, now_ms)?;
    Ok(grant)
}

/// Admit (or refuse) a **native** refresh for `person`'s opaque `session_id` at
/// `now_ms` (ADR 0147 §2/§4, SOC 2 F-4.2). The bearer digest selects that exact
/// durable grant; its stored device binding must still be admitted and the grant
/// must be within bounds. No request header can substitute either relationship.
/// A revoked session or device folds the grant out and therefore refuses.
fn admit_native_refresh(
    wb: &Workbench,
    person: &str,
    session_id: &str,
    now_ms: u64,
) -> Result<crate::account::RefreshRecord, &'static str> {
    let grant = resolve_refresh_grant(wb, person, session_id)
        .ok_or("no refresh token on file; sign in again")?;
    if !native_device_admitted(wb, person, &grant.device_id) {
        return Err("this device's account session was revoked");
    }
    crate::account::refresh_within_bounds(&grant, now_ms)?;
    Ok(grant)
}

/// Stable provider-connection identity for the configured consumer Google
/// adapter. It is intentionally outside the organization connection namespace.
pub const CONSUMER_GOOGLE_CONNECTION_ID: &str = "consumer-google";

/// Stable provider-connection identity for the consumer Microsoft adapter
/// (DR-0189). Same namespace rule as Google's.
pub const CONSUMER_MICROSOFT_CONNECTION_ID: &str = "consumer-microsoft";

/// How a consumer provider's entrance proves the person controls the address it
/// will record as a verified contact (DR-0189 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailProof {
    /// The provider attests it with `email_verified`, which DR-0177 accepts on
    /// its own: the account is created from the callback with no further step.
    ProviderAttested,
    /// The provider attests nothing, so the address is proved the other way step
    /// 1 admits — a code we send to it. Entra ID has no `email_verified` claim
    /// and its `email`/`upn` are mutable, tenant-settable values, so this is the
    /// only honest reading of a Microsoft token.
    EmailedCode,
}

/// How a provider issues the refresh token the session-refresh leg needs
/// (ADR 0077): the hub mints each fresh id-token for Home access from it, and a
/// session without one ends when its first id-token does — about an hour in.
///
/// It is per provider because the two mechanisms are incompatible, not merely
/// different, and applying one provider's to the other is how the Microsoft
/// entrance shipped: Google's parameters on every request, so Entra never
/// issued a refresh token and every Microsoft session died on its first expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfflineGrant {
    /// Google: `access_type=offline` on the authorize request. A refresh token
    /// comes only on a consent grant, which is why `GAUGEDESK_OIDC_PROMPT_CONSENT`
    /// forces the consent screen — without it an already-granted account gets
    /// no refresh token at all.
    AccessTypeOffline,
    /// The Microsoft identity platform: the `offline_access` scope, and nothing
    /// else. A refresh token comes with every grant that includes it, so
    /// forcing the consent screen buys nothing — and costs a great deal, because
    /// `prompt=consent` demands the *user's* consent even where an administrator
    /// has already granted it, which in a tenant that disables user consent
    /// blocks a work account from signing in at all. Entra ignores
    /// `access_type`; it is left off rather than sent as noise.
    OfflineAccessScope,
}

impl OfflineGrant {
    /// The scope to request, given the deployment's base scope.
    pub fn scope(self, base: &str) -> String {
        match self {
            Self::AccessTypeOffline => base.to_string(),
            Self::OfflineAccessScope => {
                if base.split_whitespace().any(|s| s == "offline_access") {
                    base.to_string()
                } else {
                    format!("{} offline_access", base.trim())
                }
            }
        }
    }

    /// Extra authorize-request parameters, already `&`-prefixed.
    pub fn authorize_params(self, prompt_consent: bool) -> String {
        match self {
            Self::AccessTypeOffline => {
                let mut extra = String::from("&access_type=offline");
                if prompt_consent {
                    extra.push_str("&prompt=consent");
                }
                extra
            }
            Self::OfflineAccessScope => String::new(),
        }
    }
}

/// A consumer identity provider the hosted account may offer as an entrance.
///
/// Everything provider-specific about a consumer entrance is here, so adding a
/// third is this table plus a client id, and no handler has to know which
/// provider it is serving. `authority` is where discovery and authorization
/// happen; the issuer a token must claim comes from that authority's own
/// metadata through `accepted_issuer`, which is how Microsoft's tenant template
/// arrives without being configured anywhere (DR-0189 §2).
#[derive(Clone, Copy, Debug)]
pub struct ConsumerProvider {
    pub connection_id: &'static str,
    /// What the person selects it by: `/auth/login?provider=<slug>`.
    pub slug: &'static str,
    /// What the button and the session projection say.
    pub label: &'static str,
    pub authority: &'static str,
    /// Env var, under the `GAUGEDESK_` prefix, holding the OAuth client id.
    pub client_id_env: &'static str,
    /// Env var holding the client secret, where the OP is confidential.
    pub client_secret_env: &'static str,
    /// Env var that may override `authority`, for a dev or regional endpoint.
    pub authority_env: &'static str,
    pub email_proof: EmailProof,
    pub offline_grant: OfflineGrant,
}

pub const CONSUMER_GOOGLE: ConsumerProvider = ConsumerProvider {
    connection_id: CONSUMER_GOOGLE_CONNECTION_ID,
    slug: "google",
    label: "Google",
    authority: "https://accounts.google.com",
    client_id_env: "GOOGLE_CLIENT_ID",
    client_secret_env: "GOOGLE_CLIENT_SECRET",
    authority_env: "OIDC_ISSUER",
    email_proof: EmailProof::ProviderAttested,
    offline_grant: OfflineGrant::AccessTypeOffline,
};

pub const CONSUMER_MICROSOFT: ConsumerProvider = ConsumerProvider {
    connection_id: CONSUMER_MICROSOFT_CONNECTION_ID,
    slug: "microsoft",
    label: "Microsoft",
    // `common`, so work, school and personal accounts enter the same door and
    // nobody is asked which they hold (DR-0189 §1).
    authority: "https://login.microsoftonline.com/common/v2.0",
    client_id_env: "MICROSOFT_CLIENT_ID",
    client_secret_env: "MICROSOFT_CLIENT_SECRET",
    authority_env: "MICROSOFT_OIDC_AUTHORITY",
    email_proof: EmailProof::EmailedCode,
    offline_grant: OfflineGrant::OfflineAccessScope,
};

/// Every consumer entrance this build knows how to offer, in the order the
/// signed-out card presents them.
pub const CONSUMER_PROVIDERS: [ConsumerProvider; 2] = [CONSUMER_GOOGLE, CONSUMER_MICROSOFT];

/// The provider owning `connection_id`, or `None` for an organization connection.
pub fn consumer_provider(connection_id: &str) -> Option<ConsumerProvider> {
    CONSUMER_PROVIDERS
        .iter()
        .copied()
        .find(|provider| provider.connection_id == connection_id)
}

/// The provider a person selected by slug.
pub fn consumer_provider_by_slug(slug: &str) -> Option<ConsumerProvider> {
    CONSUMER_PROVIDERS
        .iter()
        .copied()
        .find(|provider| provider.slug == slug)
}

impl ConsumerProvider {
    /// This provider's authority for this deployment, after any env override.
    pub fn configured_authority(&self) -> String {
        gaugedesk_env::var(self.authority_env)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| self.authority.to_string())
    }

    /// The connection record for this provider, or `None` when this deployment
    /// has configured no client id for it. A provider without a client id is
    /// simply not offered; it is never a startup failure.
    pub fn configured_connection(&self) -> Option<SsoConnectionRecord> {
        if !web_account_mode() {
            return None;
        }
        let client_id =
            gaugedesk_env::var(self.client_id_env).filter(|value| !value.trim().is_empty())?;
        Some(consumer_sso(
            self.connection_id,
            &self.configured_authority(),
            &client_id,
        ))
    }

    /// The client secret for a confidential OP, where one is configured.
    pub fn client_secret(&self) -> Option<crate::secret::Secret> {
        gaugedesk_env::var(self.client_secret_env)
            .filter(|value| !value.trim().is_empty())
            .map(Into::into)
    }
}

/// Whether `connection` would still admit the issuer and audiences a ceremony
/// pinned on its authorize leg.
///
/// The pinned issuer is what the authority's metadata declared then, which for a
/// multi-tenant authority is a tenant template and therefore not the connection's
/// own `issuer` string (DR-0189 §2). So this asks the same question the login leg
/// asked — would this connection accept that issuer — rather than comparing the
/// two strings, which was only ever equality by coincidence of the single-tenant
/// case.
pub fn connection_still_accepts(
    connection: &SsoConnectionRecord,
    pinned_issuer: &str,
    pinned_audiences: &[String],
) -> bool {
    connection.audiences == pinned_audiences
        && crate::identity_oidc::accepted_issuer(&connection.issuer, pinned_issuer).as_deref()
            == Some(pinned_issuer)
}

/// The consumer connection a session was minted by, read from the method the
/// session itself records (`consumer-oidc:<connection>`, ADR 0147 §1).
///
/// A refresh has to reach the provider that issued the grant. Before DR-0189
/// there was one, so "the configured connection" and "this session's connection"
/// were the same sentence; with two they are not, and using the wrong one sends
/// a Microsoft refresh token to Google's token endpoint.
pub fn session_consumer_connection(
    method: &str,
) -> Option<(ConsumerProvider, SsoConnectionRecord)> {
    configured_consumer_connection(method.strip_prefix("consumer-oidc:")?)
}

/// Every consumer entrance this deployment actually offers.
pub fn configured_consumer_connections() -> Vec<(ConsumerProvider, SsoConnectionRecord)> {
    CONSUMER_PROVIDERS
        .iter()
        .filter_map(|provider| {
            provider
                .configured_connection()
                .map(|connection| (*provider, connection))
        })
        .collect()
}

/// One configured consumer entrance by connection id. This is how a callback and
/// a refresh recover their provider: from server-held state naming the
/// connection, never from a request parameter choosing one.
pub fn configured_consumer_connection(
    connection_id: &str,
) -> Option<(ConsumerProvider, SsoConnectionRecord)> {
    let provider = consumer_provider(connection_id)?;
    provider
        .configured_connection()
        .map(|connection| (provider, connection))
}

/// A Google (or any OIDC) SSO connection for the hosted web account, from env — so the hub
/// offers "Continue with Google" without a manual `/admin/sso` POST. `GAUGEDESK_GOOGLE_CLIENT_ID`
/// is the OAuth client id (the id-token `aud`); the issuer defaults to Google's, overridable via
/// `GAUGEDESK_OIDC_ISSUER`. `None` unless web-account mode with a client id configured.
pub fn web_account_sso_from_env() -> Option<SsoConnectionRecord> {
    CONSUMER_GOOGLE.configured_connection()
}

/// Back-link every legacy consumer account once, before this composition serves a
/// request (GAUGEAPP-9).
///
/// This initiative made the callback resolve an external-subject link before minting a
/// session. An account created by consumer sign-in under the previous rule carries the
/// verified subject as its id and holds no method, so without this it can never sign in
/// again and no route can repair it: linking requires a live passkey-or-recovery
/// session it cannot obtain.
///
/// Runs where configured IdP activation already runs, so the repair lands before the
/// router exists rather than racing the first sign-in. It is a no-op when consumer
/// sign-in is unconfigured, and idempotent, so repeated boots cost one read.
pub fn backlink_legacy_consumer_accounts(wb: &mut Workbench) -> usize {
    let Some(connection) = web_account_sso_from_env() else {
        return 0;
    };
    let Ok(state) = crate::account_auth::AccountAuth::rebuild(wb.store_ref()) else {
        return 0;
    };
    let Ok(catalog) =
        crate::account_auth_custody::AccountAuthCustodyCatalog::rebuild(wb.store_ref())
    else {
        return 0;
    };
    // Only accounts this composition would actually authenticate. A pending erasure or
    // an unmigrated custody scope is not a sign-in problem to solve here.
    let candidates: Vec<String> = catalog
        .authenticatable_account_scoped_account_ids()
        .into_iter()
        .map(str::to_owned)
        .collect();
    let facts: Vec<crate::account_auth::AccountAuthFact> = candidates
        .iter()
        .filter_map(|account_id| {
            crate::account_auth::decide_backlink_legacy_consumer_subject(
                &state,
                account_id,
                &connection.id,
                &connection.issuer,
                crate::account::session_now_ms(),
            )
        })
        .collect();
    if facts.is_empty() {
        return 0;
    }
    let linked = facts.len();
    match crate::account_auth::append_facts(wb.store_mut(), &facts) {
        Ok(_) => linked,
        // A failure here must not stop the composition from serving: the accounts that
        // were already fine still are, and the next boot retries the rest.
        Err(_) => 0,
    }
}

/// Build an OIDC SSO connection record for a consumer `authority` + `client_id`
/// (pure; the env wrapper is [`ConsumerProvider::configured_connection`]). No
/// enforce-SSO: the hosted account is opt-in login, not a locked-down org.
///
/// `authority` lands in the record's `issuer` field because that is the string
/// discovery is performed against. What a token's `iss` must equal is decided at
/// login from the authority's own metadata (DR-0189 §2), so for a multi-tenant
/// authority the two are deliberately not the same string.
pub fn consumer_sso(connection_id: &str, authority: &str, client_id: &str) -> SsoConnectionRecord {
    let mut connection = SsoConnectionRecord {
        id: connection_id.to_string(),
        op: RecordOp::Upsert,
        revision: String::new(),
        credential_revision: None,
        protocol: SsoProtocol::Oidc,
        issuer: authority.to_string(),
        audiences: vec![client_id.to_string()],
        metadata: String::new(),
        saml_sp_entity_id: String::new(),
        saml_acs_url: String::new(),
        enforce_sso: false,
        claim_mapping: Default::default(),
    };
    connection.seal_revision();
    connection
}

/// The Google consumer connection, by name. Kept because the legacy back-link and
/// the tests that predate DR-0189 speak of it directly.
pub fn google_sso(issuer: &str, client_id: &str) -> SsoConnectionRecord {
    consumer_sso(CONSUMER_GOOGLE_CONNECTION_ID, issuer, client_id)
}

/// A safe label for the already-authenticated sign-in session. This is a
/// session projection, not a durable linked-method or recovery declaration.
fn session_method(sso: Option<&SsoConnectionRecord>) -> (&'static str, &'static str) {
    let Some(sso) = sso else {
        return ("local", "Local account");
    };
    match sso.protocol {
        SsoProtocol::Oidc
            if sso.issuer.contains("accounts.google.com")
                || sso.issuer.contains("googleusercontent.com") =>
        {
            ("google", "Google")
        }
        SsoProtocol::Oidc => ("oidc", "Single sign-on (OIDC)"),
        SsoProtocol::Saml => ("saml", "Single sign-on (SAML)"),
    }
}

/// The `(method, label)` an opaque account session reports for its stored sign-in
/// method (ADR 0147 §1). Unknown methods fall back to the passkey label, the safest
/// default for a server-minted opaque session.
fn session_label_for_method(method: &str) -> (&'static str, &'static str) {
    match method {
        method if method.starts_with("consumer-oidc:") => {
            // The label is the provider's, not a guess. An unconfigured or
            // retired connection still labels honestly as consumer sign-in
            // rather than claiming a provider this session did not use.
            match method
                .strip_prefix("consumer-oidc:")
                .and_then(consumer_provider)
            {
                Some(provider) => (provider.slug, provider.label),
                None => ("oidc", "Consumer sign-in"),
            }
        }
        method if method.starts_with("enterprise-oidc:") => ("oidc", "Corporate sign-in (OIDC)"),
        method if method.starts_with("enterprise-saml:") => ("saml", "Corporate sign-in (SAML)"),
        "recovery" => ("recovery", "Recovery code"),
        _ => ("passkey", "Passkey or security key"),
    }
}

/// `GET /auth/session` — the currently authenticated session's sign-in method.
/// It exposes no token, email, subject, refresh state, or tenant membership and
/// must not be rendered as a durable linked-method/custody fact.
pub async fn get_session(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let bearer = crate::net_http::bearer(&headers);
    // An opaque account session reports the true sign-in method that minted it
    // (ADR 0147 §1) — read from the durable session record, never hardcoded. An
    // OIDC-derived session is "oidc"; a passkey ceremony session is "passkey".
    if let Some((method, label)) = bearer
        .and_then(|token| wb.resolve_account_session(token))
        .map(|(_, method)| session_label_for_method(&method))
    {
        return (
            StatusCode::OK,
            Json(json!({ "method": method, "label": label })),
        )
            .into_response();
    }
    if wb.actor(bearer) == "anonymous" {
        return (
            StatusCode::UNAUTHORIZED,
            "authenticate to view this session",
        )
            .into_response();
    }
    // The hosted person account is authenticated by its account-level Google/OIDC
    // connection, never by whichever tenant the Console currently has selected.
    // Enterprise/desktop keeps its tenant-scoped connection projection.
    let sso = if web_account_mode() {
        web_account_sso_from_env()
    } else {
        Org::rebuild_in(wb.store_ref(), &crate::workbench_auth::req_scope(&headers))
            .ok()
            .and_then(|org| org.sso)
    };
    let (method, label) = session_method(sso.as_ref());
    (
        StatusCode::OK,
        Json(json!({ "method": method, "label": label })),
    )
        .into_response()
}

/// The shared web-account session cookie (`ADR 0077`) carrying an opaque account session or a
/// verified legacy OIDC id-token (either credential is accepted by `net_http::bearer`). Pure;
/// the env wrapper is [`session_cookie_header`]. `domain` (e.g. `.gaugewright.com`) makes one sign-in
/// authenticate the whole site; omitted for loopback dev (a Domain cookie can't be set on
/// `localhost`). `HttpOnly` (no JS reads it) + `SameSite=Lax` (survives the top-level OAuth
/// redirect, blocks CSRF on cross-site POSTs); `Secure` off only for dev.
pub fn session_cookie_value(id_token: &str, domain: Option<&str>, secure: bool) -> String {
    let mut c = format!(
        "{}={id_token}; Path=/; HttpOnly; SameSite=Lax",
        crate::net_http::SESSION_COOKIE
    );
    if secure {
        c.push_str("; Secure");
    }
    if let Some(d) = domain.map(str::trim).filter(|d| !d.is_empty()) {
        c.push_str("; Domain=");
        c.push_str(d);
    }
    c
}

/// Expire the shared web-account cookie using the same path/domain/security attributes used
/// when it was issued. Matching those attributes matters: clearing a host-only cookie would
/// leave the production `Domain=.gaugewright.com` cookie alive and the next request would appear
/// to sign the person straight back in.
pub fn expired_session_cookie_value(domain: Option<&str>, secure: bool) -> String {
    let mut c = session_cookie_value("", domain, secure);
    c.push_str("; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
    c
}

/// The JS-readable companion to the session cookie. [`session_cookie_value`] is `HttpOnly`, so
/// the static public site cannot tell a signed-in browser from an anonymous one; this hint —
/// deliberately not `HttpOnly`, carrying the constant `1` and never the credential — is what lets
/// `gaugewright.com` relabel its nav ("Sign in" → "Go to hub"). It grants nothing: a forged or
/// stale hint only changes a label, and the real session cookie still decides every request.
pub const SESSION_HINT_COOKIE: &str = "gw_session_hint";

/// The hint's `Set-Cookie` value, same path/domain/security attributes as the session cookie so
/// the pair always travels — and expires — together.
pub fn session_hint_cookie_value(domain: Option<&str>, secure: bool) -> String {
    let mut c = format!("{SESSION_HINT_COOKIE}=1; Path=/; SameSite=Lax");
    if secure {
        c.push_str("; Secure");
    }
    if let Some(d) = domain.map(str::trim).filter(|d| !d.is_empty()) {
        c.push_str("; Domain=");
        c.push_str(d);
    }
    c
}

/// Expire the hint with the attributes it was issued under (see
/// [`expired_session_cookie_value`] for why the attributes must match).
pub fn expired_session_hint_cookie_value(domain: Option<&str>, secure: bool) -> String {
    let mut c = session_hint_cookie_value(domain, secure);
    c = c.replacen(
        &format!("{SESSION_HINT_COOKIE}=1"),
        &format!("{SESSION_HINT_COOKIE}="),
        1,
    );
    c.push_str("; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
    c
}

/// The `Set-Cookie` value for the login session, from env: `GAUGEDESK_SESSION_COOKIE_DOMAIN`
/// (e.g. `.gaugewright.com`; unset ⇒ host-only, for loopback) and `GAUGEDESK_SESSION_COOKIE_INSECURE=1`
/// (dev-only, drops `Secure` so the cookie works over http loopback).
fn session_cookie_header(id_token: &str) -> String {
    let domain = gaugedesk_env::var("SESSION_COOKIE_DOMAIN");
    let insecure = gaugedesk_env::var("SESSION_COOKIE_INSECURE")
        .map(|v| v == "1")
        .unwrap_or(false);
    session_cookie_value(id_token, domain.as_deref(), !insecure)
}

fn expired_session_cookie_header() -> String {
    let domain = gaugedesk_env::var("SESSION_COOKIE_DOMAIN");
    let insecure = gaugedesk_env::var("SESSION_COOKIE_INSECURE")
        .map(|v| v == "1")
        .unwrap_or(false);
    expired_session_cookie_value(domain.as_deref(), !insecure)
}

fn session_hint_cookie_header() -> String {
    let domain = gaugedesk_env::var("SESSION_COOKIE_DOMAIN");
    let insecure = gaugedesk_env::var("SESSION_COOKIE_INSECURE")
        .map(|v| v == "1")
        .unwrap_or(false);
    session_hint_cookie_value(domain.as_deref(), !insecure)
}

fn expired_session_hint_cookie_header() -> String {
    let domain = gaugedesk_env::var("SESSION_COOKIE_DOMAIN");
    let insecure = gaugedesk_env::var("SESSION_COOKIE_INSECURE")
        .map(|v| v == "1")
        .unwrap_or(false);
    expired_session_hint_cookie_value(domain.as_deref(), !insecure)
}

/// Append both session `Set-Cookie` headers — the `HttpOnly` credential and its JS-readable
/// hint — so the pair can never drift apart at an issue site.
pub(crate) fn append_session_cookies(resp: &mut axum::response::Response, credential: &str) {
    if let Ok(cookie) = axum::http::HeaderValue::from_str(&session_cookie_header(credential)) {
        resp.headers_mut()
            .append(axum::http::header::SET_COOKIE, cookie);
    }
    append_session_hint_cookie(resp);
}

/// Add only the non-credential hint. An authenticated `/auth/login` shortcut uses this to
/// backfill browsers whose still-valid session predates the hint, without rotating or
/// exposing the real credential — it is the half of the pair that carries no secret.
fn append_session_hint_cookie(resp: &mut axum::response::Response) {
    if let Ok(cookie) = axum::http::HeaderValue::from_str(&session_hint_cookie_header()) {
        resp.headers_mut()
            .append(axum::http::header::SET_COOKIE, cookie);
    }
}

// ---- axum handlers -------------------------------------------------------

/// The `redirect_uri` this control plane registers with the OP. An explicit
/// `GAUGEDESK_OIDC_REDIRECT_URI` wins (the value registered at the IdP); otherwise it
/// is derived from the request `Host` so a default loopback dev run works unconfigured.
fn callback_redirect_uri(headers: &HeaderMap) -> String {
    if let Some(uri) = gaugedesk_env::var("OIDC_REDIRECT_URI") {
        if !uri.trim().is_empty() {
            return uri;
        }
    }
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    format!("http://{host}/auth/callback")
}

/// Canonical externally visible origin used when an enterprise protocol needs
/// absolute launch and callback URLs. The explicit deployment value wins;
/// otherwise trusted proxy headers precede Host for the loopback/dev path.
pub fn request_public_base(headers: &HeaderMap) -> String {
    if let Some(url) = gaugedesk_env::var("PUBLIC_URL") {
        if !url.trim().is_empty() {
            return url.trim_end_matches('/').to_owned();
        }
    }
    let host = headers
        .get("x-forwarded-host")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            headers
                .get(axum::http::header::HOST)
                .and_then(|value| value.to_str().ok())
        })
        .unwrap_or("localhost:7878");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("http");
    format!("{scheme}://{host}")
}

fn login_err(e: LoginError) -> axum::response::Response {
    let (code, msg) = match e {
        LoginError::NotConfigured => (
            StatusCode::CONFLICT,
            "SSO is not configured for OIDC (set an OIDC connection + client id at /admin/sso)"
                .to_string(),
        ),
        LoginError::NoIssuer => (
            StatusCode::CONFLICT,
            "the OIDC SSO connection has no issuer".to_string(),
        ),
        LoginError::Discovery(m) => (
            StatusCode::BAD_GATEWAY,
            format!("OIDC discovery failed: {m}"),
        ),
        LoginError::Pkce(m) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("PKCE generation failed: {m}"),
        ),
    };
    (code, msg).into_response()
}

/// Resolve an untrusted work-email routing hint to exactly one configured
/// organization connection. The address is used only for discovery: the IdP
/// callback must independently assert and verify its own email before the
/// organization admission fold may act.
///
/// DNS-verified domain ownership is the lookup authority. Ambiguous domains,
/// incomplete admission configuration, invalid addresses, and protocols whose
/// ordinary login journey is not yet implemented all produce the same absence.
fn enterprise_sso_for_work_email(
    store: &gaugedesk_store::Store,
    email: &str,
) -> Result<Option<(SsoConnectionRecord, PendingEnterpriseLogin)>, gaugedesk_store::AdmitError> {
    let Some(email) = crate::account_auth::normalize_email_contact(email) else {
        return Ok(None);
    };
    let mut matches = Vec::new();
    for scope in store.scope_ids()? {
        if scope != ORG_SCOPE && !scope.starts_with("org::") {
            continue;
        }
        let org = Org::rebuild_in(store, &scope)?;
        if org.org.is_none() || org.sso_admission.is_none() || !org.domain_is_verified(&email) {
            continue;
        }
        let Some(connection) = org.sso else {
            continue;
        };
        matches.push((scope, connection));
    }
    if matches.len() != 1 {
        return Ok(None);
    }
    let (store_scope, connection) = matches.pop().expect("one discovery match");
    let context = PendingEnterpriseLogin {
        store_scope,
        connection_id: connection.id.clone(),
        connection_revision: connection.current_revision(),
        protocol: connection.protocol,
    };
    Ok(Some((connection, context)))
}

/// Resolve a confidential OIDC client secret from the exact organization
/// connection. A configured-but-missing, stale, or undecryptable credential
/// fails closed; it never falls back to the consumer Google environment secret.
pub fn organization_oidc_client_secret(
    wb: &Workbench,
    org: &Org,
    connection: &SsoConnectionRecord,
) -> Result<Option<crate::secret::Secret>, &'static str> {
    if connection.protocol != SsoProtocol::Oidc || connection.credential_revision.is_none() {
        return Ok(None);
    }
    let current = org
        .sso
        .as_ref()
        .filter(|current| {
            current.id == connection.id
                && current.protocol == connection.protocol
                && current.current_revision() == connection.current_revision()
        })
        .ok_or("the organization sign-in connection changed")?;
    let credential = org
        .current_sso_credential()
        .ok_or("the organization OIDC client secret is unavailable")?;
    let binding = current
        .credential_binding()
        .ok_or("the organization OIDC credential binding is unavailable")?;
    let secret = wb
        .unseal_organization_secret(&org.scope, &binding, &credential.sealed_secret)
        .ok_or("the organization OIDC client secret could not be opened")?;
    Ok(Some(crate::secret::Secret::new(secret)))
}

async fn begin_enterprise_browser_login(
    auth: AuthShellState,
    headers: &HeaderMap,
    connection: SsoConnectionRecord,
    login_context: PendingEnterpriseLogin,
    client_secret: Option<crate::secret::Secret>,
    native_return: Option<String>,
    native_handoff_challenge: Option<String>,
) -> axum::response::Response {
    match connection.protocol {
        SsoProtocol::Oidc => {
            begin_oidc_browser_login(
                auth,
                headers,
                connection,
                OidcBrowserOptions {
                    authority: OidcConnectionAuthority::Enterprise {
                        login_context,
                        client_secret,
                    },
                    native_return,
                    native_handoff_challenge,
                    purpose: PendingAuthPurpose::Login,
                },
            )
            .await
        }
        SsoProtocol::Saml => {
            let request = EnterpriseSamlStartRequest {
                connection,
                login_context,
                public_base: request_public_base(headers),
                native_return,
                native_handoff_challenge,
            };
            match auth.begin_enterprise_saml(request) {
                Ok(url) => Redirect::to(&url).into_response(),
                Err(message) => (StatusCode::SERVICE_UNAVAILABLE, message).into_response(),
            }
        }
    }
}

enum OidcConnectionAuthority {
    Consumer(ConsumerProvider),
    Enterprise {
        login_context: PendingEnterpriseLogin,
        client_secret: Option<crate::secret::Secret>,
    },
}

struct OidcBrowserOptions {
    authority: OidcConnectionAuthority,
    native_return: Option<String>,
    native_handoff_challenge: Option<String>,
    purpose: PendingAuthPurpose,
}

async fn begin_oidc_browser_login(
    auth: AuthShellState,
    headers: &HeaderMap,
    sso: SsoConnectionRecord,
    options: OidcBrowserOptions,
) -> axum::response::Response {
    match prepare_oidc_browser_login(auth, headers, sso, options).await {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(response) => response,
    }
}

async fn prepare_oidc_browser_login(
    auth: AuthShellState,
    headers: &HeaderMap,
    sso: SsoConnectionRecord,
    options: OidcBrowserOptions,
) -> Result<String, axum::response::Response> {
    let redirect_uri = callback_redirect_uri(headers);
    let scope =
        gaugedesk_env::var("OIDC_SCOPE").unwrap_or_else(|| "openid profile email".to_string());
    let mapping = claim_mapping_for(&sso);
    let offline = match &options.authority {
        OidcConnectionAuthority::Consumer(provider) => provider.offline_grant,
        OidcConnectionAuthority::Enterprise { .. } => OfflineGrant::AccessTypeOffline,
    };

    // Discovery touches the network — run it off the async runtime (ureq is blocking).
    let started = tokio::task::spawn_blocking(move || {
        let http = HttpClient::new();
        start_login_with(&sso, &redirect_uri, &scope, mapping, offline, &http)
    })
    .await;
    let (url, state, mut pending) = match started {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => return Err(login_err(error)),
        Err(_) => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "login task panicked").into_response())
        }
    };
    // Consumer login retains the deployment-level credential of the provider it
    // is actually using. An enterprise login receives only the exact
    // organization credential resolved before this function; neither ever falls
    // back across authorities, and after DR-0189 that includes not falling back
    // across consumer providers.
    let (enterprise_login, consumer_connection_id, client_secret) = match options.authority {
        OidcConnectionAuthority::Consumer(provider) => (
            None,
            Some(provider.connection_id.to_string()),
            provider.client_secret(),
        ),
        OidcConnectionAuthority::Enterprise {
            login_context,
            client_secret,
        } => (Some(login_context), None, client_secret),
    };
    pending.client_secret = client_secret;
    pending.consumer_connection_id = consumer_connection_id;
    pending.native_return = options.native_return;
    pending.native_handoff_challenge = options.native_handoff_challenge;
    pending.login_context = enterprise_login;
    pending.purpose = options.purpose;
    auth.pending_auth_mut()
        .begin(state, pending, Instant::now());
    Ok(url)
}

/// `GET /auth/login` — begin OIDC login: discover, mint PKCE + state, stash, and
/// redirect the browser to the IdP. See the module docs. The pending-login store
/// arrives as the composition-scoped [`AuthShellState`] extension.
pub async fn get_login(
    State(wb): State<SharedWorkbench>,
    Extension(auth): Extension<AuthShellState>,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
) -> impl IntoResponse {
    let native_return = match native_return_uri(
        query.return_to.as_deref(),
        query.handoff_challenge.as_deref(),
        dev_web_return_enabled(),
    ) {
        Ok(value) => value,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };
    // Hosted web account: a browser that already carries a still-valid session (the shared
    // `.gaugewright.com` cookie) needs no new ceremony — bounce it straight to the post-login
    // surface. The public site's "Sign in" entry lands here, so without this every visit
    // re-ran the full IdP consent even for a signed-in person. An expired/absent cookie
    // authenticates to nobody and falls through to the normal flow.
    {
        let bearer = crate::net_http::bearer(&headers).map(str::to_string);
        let actor = wb.lock_unpoisoned().actor(bearer.as_deref());
        if login_ceremony_skippable(web_account_mode(), native_return.is_some(), &actor) {
            let post_login = gaugedesk_env::var("OIDC_POST_LOGIN_URL")
                .filter(|u| !u.trim().is_empty())
                .unwrap_or_else(|| "/".to_string());
            let mut resp = Redirect::to(&post_login).into_response();
            append_session_hint_cookie(&mut resp);
            return resp;
        }
    }
    let store_scope = crate::workbench_auth::req_scope(&headers);
    let stored_sso = {
        let wb = wb.lock_unpoisoned();
        match Org::rebuild_in(wb.store_ref(), &store_scope) {
            Ok(org) => match org.sso.clone() {
                Some(connection) => match organization_oidc_client_secret(&wb, &org, &connection) {
                    Ok(secret) => Some((connection, secret)),
                    Err(message) => {
                        return (StatusCode::SERVICE_UNAVAILABLE, message).into_response()
                    }
                },
                None => None,
            },
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
        }
    };
    if let Some((connection, client_secret)) = stored_sso {
        let login_context = PendingEnterpriseLogin {
            store_scope,
            connection_id: connection.id.clone(),
            connection_revision: connection.current_revision(),
            protocol: connection.protocol,
        };
        return begin_enterprise_browser_login(
            auth,
            &headers,
            connection,
            login_context,
            client_secret,
            native_return,
            query.handoff_challenge,
        )
        .await;
    }
    // Hosted web account: fall back to a consumer connection from env, so the hub
    // offers "Continue with Google" or "Continue with Microsoft" without a stored
    // /admin/sso record (ADR 0077, DR-0189 §1).
    //
    // The request names a slug, not a connection: an unknown or unconfigured one
    // is refused rather than silently served by another provider, because
    // "continue with Microsoft" quietly running Google is worse than an error.
    let configured = configured_consumer_connections();
    let selected = match query.provider.as_deref().map(str::trim) {
        Some(slug) if !slug.is_empty() => {
            match configured
                .iter()
                .find(|(provider, _)| provider.slug.eq_ignore_ascii_case(slug))
            {
                Some(found) => Some(found.clone()),
                None => {
                    return (
                        StatusCode::CONFLICT,
                        format!("{slug} sign-in is not configured on this server"),
                    )
                        .into_response()
                }
            }
        }
        _ => configured.first().cloned(),
    };
    let Some((provider, sso)) = selected else {
        return (StatusCode::CONFLICT, "no SSO connection configured").into_response();
    };
    begin_oidc_browser_login(
        auth,
        &headers,
        sso,
        OidcBrowserOptions {
            authority: OidcConnectionAuthority::Consumer(provider),
            native_return,
            native_handoff_challenge: query.handoff_challenge,
            purpose: PendingAuthPurpose::Login,
        },
    )
    .await
}

fn independent_account_method(method: &str) -> bool {
    matches!(method, "passkey" | "recovery")
}

/// A live account session for this account, by any method. The avatar
/// re-fetch needs no independent proof: it links nothing, and a person signed
/// in with Google may ask Google for their own photograph.
fn durable_account_session(
    state: &crate::account_auth::AccountAuth,
    session_id: &str,
    account_id: &str,
    now_ms: u64,
) -> bool {
    state.roots.contains_key(account_id)
        && state.sessions.get(session_id).is_some_and(|session| {
            session.account_id == account_id
                && session
                    .issued_at_ms
                    .checked_add(session.lifetime_secs.saturating_mul(1000))
                    .is_some_and(|expires_at| expires_at > now_ms)
        })
}

/// What a callback holds about the assertion that returned: the issuer and
/// audiences pinned on the authorize leg, and the verified token's own issuer
/// and subject.
#[derive(Clone, Copy)]
struct ReturnedConsumerIdentity<'a> {
    pinned_issuer: &'a str,
    pinned_audiences: &'a [String],
    token_issuer: Option<&'a str>,
    subject: &'a str,
}

/// Whether a returning provider identity may replace the avatar of the account
/// that asked (DR-0195 §3). Everything is server-held except the verified
/// subject: the connection must be the one the ceremony started against, the
/// initiating session must still be live, and the subject must be the one
/// already linked to that account — a person signed into a second Google
/// account in the same browser does not get that account's photo.
fn admit_consumer_avatar_refresh(
    account_auth: &crate::account_auth::AccountAuth,
    context: &PendingConsumerOidcAvatar,
    connection: &SsoConnectionRecord,
    returned: &ReturnedConsumerIdentity<'_>,
    now_ms: u64,
) -> Result<(), (StatusCode, &'static str)> {
    let ReturnedConsumerIdentity {
        pinned_issuer,
        pinned_audiences,
        token_issuer,
        subject,
    } = *returned;
    if connection.id != context.connection_id
        || connection.current_revision() != context.connection_revision
        || !connection_still_accepts(connection, pinned_issuer, pinned_audiences)
    {
        return Err((
            StatusCode::CONFLICT,
            "Google sign-in changed while you were updating your photo; return to GaugeDesk and start again",
        ));
    }
    if !durable_account_session(
        account_auth,
        &context.session_id,
        &context.account_id,
        now_ms,
    ) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "the account session that asked for this photo is no longer current",
        ));
    }
    // A link records the issuer its token carried (DR-0189), so the subject is
    // matched against this token's issuer, not the connection's template.
    let Some(token_issuer) = token_issuer else {
        return Err((
            StatusCode::FORBIDDEN,
            "the sign-in result could not be read",
        ));
    };
    if !consumer_subject_linked_to(
        account_auth,
        &context.account_id,
        &connection.id,
        token_issuer,
        subject,
    ) {
        return Err((
            StatusCode::CONFLICT,
            "that Google account is not the one linked to this GaugeDesk account",
        ));
    }
    Ok(())
}

/// Whether `subject` at `issuer` is the consumer identity actively linked to
/// `account_id` through `connection_id`.
fn consumer_subject_linked_to(
    state: &crate::account_auth::AccountAuth,
    account_id: &str,
    connection_id: &str,
    issuer: &str,
    subject: &str,
) -> bool {
    state.external_subjects.values().any(|link| {
        link.account_id == account_id
            && link.connection_id == connection_id
            && link.issuer == issuer
            && link.subject == subject
            && link.kind == crate::account_auth::ExternalSubjectKind::ConsumerOidc
            && link.status == crate::account_auth::AuthMethodStatus::Active
    })
}

fn durable_independent_session(
    state: &crate::account_auth::AccountAuth,
    session_id: &str,
    account_id: &str,
    now_ms: u64,
) -> bool {
    state.roots.contains_key(account_id)
        && state.sessions.get(session_id).is_some_and(|session| {
            session.account_id == account_id
                && independent_account_method(&session.method)
                && session
                    .issued_at_ms
                    .checked_add(session.lifetime_secs.saturating_mul(1000))
                    .is_some_and(|expires_at| expires_at > now_ms)
        })
}

fn resolve_consumer_oidc_account(
    state: &crate::account_auth::AccountAuth,
    connection: &SsoConnectionRecord,
    accepted_issuer: &str,
    verified_issuer: &str,
    subject: &str,
) -> Option<LoginResolution> {
    // The token's issuer must be one the ceremony's pinned rule admits. For a
    // single-tenant connection that is equality, exactly as before; for a
    // tenant-templated one it is membership of the family, which a comparison
    // against the connection's own `common` authority could never be.
    if connection.protocol != SsoProtocol::Oidc
        || !crate::identity_oidc::issuer_matches_tenant_template(accepted_issuer, verified_issuer)
    {
        return None;
    }
    let link = state.active_external_subject(
        &connection.id,
        verified_issuer,
        subject,
        crate::account_auth::ExternalSubjectKind::ConsumerOidc,
    )?;
    Some(LoginResolution {
        account_id: link.account_id.clone(),
        session_method: format!("consumer-oidc:{}", connection.id),
    })
}

/// What a verified consumer-provider callback means for this person.
///
/// Three answers, not two, and the whole judgement lives here — with no store,
/// no clock and no HTTP in it — so each can be held to its meaning by a test
/// rather than by a reading of the handler. The refusal that shipped the bug
/// this repairs had no test at all: the string appeared exactly once in the
/// repository, and the only coverage nearby asserted that the resolver was
/// strict, which it was and which was never the problem.
#[derive(Debug, PartialEq, Eq)]
enum ConsumerCallbackDecision {
    /// An exact active link: this subject is an authenticator on an account.
    Login(LoginResolution),
    /// Nobody has this subject and the provider attested an address: ADR 0146
    /// §1 step 1 is satisfied, so carry the person into passkey creation.
    Signup { verified_email: String },
    /// Nobody has this subject and the provider attests no address, so §1 step 1
    /// is not satisfied and cannot be by anything in the token (DR-0189 §4).
    /// The address the provider asserted may seed the field and proves nothing.
    SignupNeedsEmailProof { asserted_email: Option<String> },
    /// The bounded product message the browser receives.
    Refuse(StatusCode, String),
}

/// The verified facts one consumer callback decides on.
///
/// A struct because they travel together and mean nothing apart: five of the
/// seven come from the same verified token and the other two from the ceremony's
/// pinned state, and an argument list long enough to need this grouping is also
/// long enough to transpose two `&str` by accident.
struct ConsumerCallbackFacts<'a> {
    provider: ConsumerProvider,
    connection: &'a SsoConnectionRecord,
    /// The issuer rule pinned on the authorize leg — a tenant template for a
    /// multi-tenant authority.
    accepted_issuer: &'a str,
    /// The concrete issuer the verified token claims. Durable state keys on it.
    verified_issuer: &'a str,
    subject: &'a str,
    /// An address the provider attested (`email_verified`).
    attested_email: Option<String>,
    /// An address the provider merely asserted, which proves nothing.
    asserted_email: Option<String>,
}

fn decide_consumer_callback(
    account_auth: &crate::account_auth::AccountAuth,
    facts: ConsumerCallbackFacts<'_>,
) -> ConsumerCallbackDecision {
    let ConsumerCallbackFacts {
        provider,
        connection,
        accepted_issuer,
        verified_issuer,
        subject,
        attested_email,
        asserted_email,
    } = facts;
    let label = provider.label;
    if let Some(resolution) = resolve_consumer_oidc_account(
        account_auth,
        connection,
        accepted_issuer,
        verified_issuer,
        subject,
    ) {
        return ConsumerCallbackDecision::Login(resolution);
    }
    // A subject an account deliberately removed is refused before anything about
    // an address is considered, because that refusal is true whatever the
    // provider said about email — and it is the one the person needs to read.
    if account_auth
        .external_subject_of_any_status(&connection.id, verified_issuer, subject)
        .is_some()
    {
        return ConsumerCallbackDecision::Refuse(
            StatusCode::FORBIDDEN,
            format!(
                "this {label} sign-in was removed from a GaugeDesk account; sign in with your passkey or a recovery code, then link {label} again in Account Settings"
            ),
        );
    }
    match provider.email_proof {
        EmailProof::ProviderAttested => {
            let Some(attested_email) = attested_email else {
                return ConsumerCallbackDecision::Refuse(
                    StatusCode::FORBIDDEN,
                    format!(
                        "{label} did not return a verified email address for this account, so GaugeDesk cannot create one. Create your account with a passkey instead."
                    ),
                );
            };
            let Some(attested_email) =
                crate::account_auth::normalize_email_contact(&attested_email)
            else {
                return ConsumerCallbackDecision::Refuse(
                    StatusCode::BAD_REQUEST,
                    format!("{label} returned an email address GaugeDesk cannot use"),
                );
            };
            if account_auth
                .account_holding_active_email(&attested_email)
                .is_some()
            {
                return ConsumerCallbackDecision::Refuse(
                    StatusCode::CONFLICT,
                    format!(
                        "a GaugeDesk account already uses this email address; sign in with your passkey or a recovery code, then link {label} in Account Settings"
                    ),
                );
            }
            ConsumerCallbackDecision::Signup {
                verified_email: attested_email,
            }
        }
        // Nothing is decided about the address here, and deliberately not the
        // collision either: an address this callback has not proved control of
        // must not be able to ask whether an account holds it, or a Microsoft
        // account would be an oracle for which addresses are registered. The
        // collision is checked where it means something — after the code comes
        // back (DR-0189 §4, §5).
        EmailProof::EmailedCode => ConsumerCallbackDecision::SignupNeedsEmailProof {
            asserted_email: asserted_email
                .as_deref()
                .and_then(crate::account_auth::normalize_email_contact),
        },
    }
}

/// A provider callback whose subject resolves to no account: park the verified
/// facts and send the browser to the ceremony that creates accounts (ADR 0146 §1).
///
/// Everything this admits is already signature-, issuer-, audience- and
/// nonce-verified. Nothing it admits creates an account: it writes one
/// single-use ticket into memory and redirects. The account, its root, its
/// passkey, its recovery batch and this subject link are committed together or
/// not at all, later, by `finish_registration`.
///
/// It still refuses three things, and each refusal is the correct one:
///
/// - **No verified email.** Step 1 of §1 is "verify an email address", and the
///   provider is the only thing here that can attest one. Without
///   `email_verified` there is no step 1 to satisfy.
/// - **A subject whose link was revoked.** An account deliberately removed this
///   Google sign-in. Minting a *second* account for it would hand the same
///   person a stranger's-looking empty account and leave the first one where it
///   was.
/// - **An address already verified on an account.** ADR 0146 §1 is explicit
///   that email is "not silently trusted as an account-merge key": anyone who
///   can obtain a Google account bearing an address could otherwise walk into
///   the GaugeDesk account that verified it. The refusal says what to do
///   instead, which is the sentence the old 403 was reaching for and gave to
///   entirely the wrong person.
fn begin_consumer_signup(
    auth: &AuthShellState,
    email: ConsumerSignupEmail,
    connection: &SsoConnectionRecord,
    verified_issuer: &str,
    verified: &VerifiedOidcIdentity,
    native_return: Option<String>,
    native_handoff_challenge: Option<String>,
) -> axum::response::Response {
    let Some(runtime) = auth.account_auth() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "account creation is not configured on this server",
        )
            .into_response();
    };
    let subject = verified.authority.as_str();
    let now_ms = crate::account::session_now_ms();
    // The browser binding. Minted here, where the provider round trip actually
    // finished, so it can only reach the browser that finished it.
    let binding = {
        let mut bytes = [0_u8; 32];
        if getrandom::getrandom(&mut bytes).is_err() {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "account creation is temporarily unavailable",
            )
                .into_response();
        }
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    };
    let signup = PendingConsumerSignup {
        email,
        connection_id: connection.id.clone(),
        connection_revision: connection.current_revision(),
        issuer: verified_issuer.to_owned(),
        subject: subject.to_owned(),
        display_name: id_token_display_name(&verified.id_token),
        picture: id_token_picture(&verified.id_token),
        refresh_token: verified
            .refresh_token
            .as_deref()
            .map(crate::secret::Secret::new),
        provider_expires_at_ms: id_token_expiry_ms(&verified.id_token)
            .unwrap_or_else(|| now_ms.saturating_add(60 * 60 * 1000)),
        native_return,
        native_handoff_challenge,
        browser_binding: crate::secret::Secret::new(&binding),
    };
    let Some(ticket) = auth
        .pending_consumer_signup_mut()
        .begin(signup, Instant::now())
    else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "account creation is temporarily unavailable",
        )
            .into_response();
    };

    // The WebAuthn origin, not this callback's host and not the post-login
    // Console: `navigator.credentials.create` has to run on the one origin the
    // verifier accepts. A fragment, not a query, so the ticket never reaches
    // browser history, a `Referer`, or a server log.
    //
    // The desktop lane redirects here too. It cannot run this ceremony against
    // its own control plane — that composition has no account runtime and 404s
    // these routes — so the system browser stays on the web app until the codes
    // have been shown, and only then hands back over `gaugewright://`.
    let mut response = Redirect::to(&format!(
        "{}/#account_signup={ticket}",
        runtime.origin().trim_end_matches('/')
    ))
    .into_response();
    // Same domain and `Secure` derivation as the session cookie, so a
    // multi-subdomain deployment works without a second knob. `SameSite=Lax` is
    // enough: the WebAuthn origin and this account API are siblings under one
    // registrable domain by construction — `AccountAuthConfig::new` admits an RP
    // id that is a registrable suffix of the origin host precisely so they can
    // be — and SameSite is judged on the registrable domain, so the redemption
    // POST is same-site and carries this. `HttpOnly` because nothing in the page
    // needs to read it; the page holds the ticket, the browser holds the proof
    // it earned the ticket, and neither alone is enough.
    append_signup_binding_cookie(&mut response, &binding);
    response
}

/// The signup binding's `Set-Cookie`, built from the same env as the session
/// cookie so the two cannot drift apart in a deployment.
fn signup_binding_cookie_header(binding: &str) -> String {
    let domain = gaugedesk_env::var("SESSION_COOKIE_DOMAIN");
    let insecure = gaugedesk_env::var("SESSION_COOKIE_INSECURE")
        .map(|v| v == "1")
        .unwrap_or(false);
    let mut c = format!(
        "{}={binding}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        crate::net_http::SIGNUP_BINDING_COOKIE,
        PENDING_AUTH_TTL.as_secs(),
    );
    if !insecure {
        c.push_str("; Secure");
    }
    if let Some(d) = domain.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
        c.push_str("; Domain=");
        c.push_str(d);
    }
    c
}

fn append_signup_binding_cookie(resp: &mut axum::response::Response, binding: &str) {
    if let Ok(value) = axum::http::HeaderValue::from_str(&signup_binding_cookie_header(binding)) {
        resp.headers_mut()
            .append(axum::http::header::SET_COOKIE, value);
    }
}

/// Constant-time equality for the binding secret. Both sides are base64url of
/// 32 random bytes; a length difference is itself an answer, so it short-circuits
/// only there.
pub(crate) fn binding_matches(expected: &str, presented: &str) -> bool {
    let (expected, presented) = (expected.as_bytes(), presented.as_bytes());
    if expected.len() != presented.len() {
        return false;
    }
    expected
        .iter()
        .zip(presented.iter())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

/// Begin linking the configured consumer provider to the account authenticated
/// by this request. The returned authorization URL is opened by the Desk in a
/// real browser; the provider callback needs no access to the Desk webview's
/// cookie because the exact initiating session digest lives in pending state.
/// Which consumer entrance to link. Absent means the first one configured, so a
/// caller that predates DR-0189 and sends no body keeps its meaning.
#[derive(Deserialize, Default)]
pub struct ConsumerLinkStartRequest {
    #[serde(default)]
    provider: Option<String>,
}

pub async fn post_consumer_oidc_link_start(
    State(wb): State<SharedWorkbench>,
    Extension(auth): Extension<AuthShellState>,
    headers: HeaderMap,
    body: Option<Json<ConsumerLinkStartRequest>>,
) -> impl IntoResponse {
    let body = body.map(|Json(body)| body).unwrap_or_default();
    if crate::net_http::bearer(&headers).is_none()
        && crate::account_signin::hub_session_actor(&wb).is_some()
    {
        return crate::account_signin::proxy_account_authority(
            &wb,
            axum::http::Method::POST,
            "/auth/account/consumer-oidc/link/start".to_owned(),
            headers,
            axum::body::Bytes::new(),
        )
        .await;
    }
    let Some(token) = crate::net_http::bearer(&headers).map(str::to_owned) else {
        return (
            StatusCode::UNAUTHORIZED,
            "authenticate with a passkey or recovery code before linking Google",
        )
            .into_response();
    };
    let session_id = crate::account_session::session_id(&token);
    let account_id = {
        let guard = wb.lock_unpoisoned();
        let Some((account_id, method)) = guard.resolve_account_session(&token) else {
            return (
                StatusCode::UNAUTHORIZED,
                "the account session is not active",
            )
                .into_response();
        };
        if !independent_account_method(&method) {
            return (
                StatusCode::CONFLICT,
                "sign in with a passkey or recovery code before linking Google",
            )
                .into_response();
        }
        let account_auth = match crate::account_auth::AccountAuth::rebuild(guard.store_ref()) {
            Ok(state) => state,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "account authentication state is unavailable",
                )
                    .into_response()
            }
        };
        if !durable_independent_session(
            &account_auth,
            &session_id,
            &account_id,
            crate::account::session_now_ms(),
        ) {
            return (
                StatusCode::UNAUTHORIZED,
                "the independent account session is no longer current",
            )
                .into_response();
        }
        account_id
    };

    let configured = configured_consumer_connections();
    let selected = match body.provider.as_deref().map(str::trim) {
        Some(slug) if !slug.is_empty() => configured
            .iter()
            .find(|(provider, _)| provider.slug.eq_ignore_ascii_case(slug))
            .cloned(),
        _ => configured.first().cloned(),
    };
    let Some((provider, connection)) = selected else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "that account linking is not configured",
        )
            .into_response();
    };
    let purpose = PendingAuthPurpose::ConsumerOidcLink(PendingConsumerOidcLink {
        account_id,
        session_id,
        connection_id: connection.id.clone(),
        connection_revision: connection.current_revision(),
    });
    match prepare_oidc_browser_login(
        auth,
        &headers,
        connection,
        OidcBrowserOptions {
            authority: OidcConnectionAuthority::Consumer(provider),
            native_return: None,
            native_handoff_challenge: None,
            purpose,
        },
    )
    .await
    {
        Ok(authorization_url) => (
            StatusCode::OK,
            Json(json!({ "authorization_url": authorization_url })),
        )
            .into_response(),
        Err(response) => response,
    }
}

/// Begin the person's explicit re-fetch of their avatar from the linked
/// consumer provider (DR-0195 §3). Any live account session may ask; the
/// callback accepts the result only from the subject already linked here.
pub async fn post_consumer_oidc_avatar_start(
    State(wb): State<SharedWorkbench>,
    Extension(auth): Extension<AuthShellState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if crate::net_http::bearer(&headers).is_none()
        && crate::account_signin::hub_session_actor(&wb).is_some()
    {
        return crate::account_signin::proxy_account_authority(
            &wb,
            axum::http::Method::POST,
            "/auth/account/consumer-oidc/avatar/start".to_owned(),
            headers,
            axum::body::Bytes::new(),
        )
        .await;
    }
    let Some(token) = crate::net_http::bearer(&headers).map(str::to_owned) else {
        return (
            StatusCode::UNAUTHORIZED,
            "sign in before updating your photo",
        )
            .into_response();
    };
    // Google's connection by name. Of the consumer entrances, Google is the one
    // whose id-token carries a `picture`; a Microsoft token carries none
    // (DR-0189), so a Microsoft round trip could only ever answer "no photo".
    let Some((provider, connection)) =
        configured_consumer_connection(CONSUMER_GOOGLE_CONNECTION_ID)
    else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Google sign-in is not configured",
        )
            .into_response();
    };
    let session_id = crate::account_session::session_id(&token);
    let account_id = {
        let guard = wb.lock_unpoisoned();
        let Some((account_id, _method)) = guard.resolve_account_session(&token) else {
            return (
                StatusCode::UNAUTHORIZED,
                "the account session is not active",
            )
                .into_response();
        };
        let Ok(account_auth) = crate::account_auth::AccountAuth::rebuild(guard.store_ref()) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "account authentication state is unavailable",
            )
                .into_response();
        };
        let linked = account_auth.external_subjects.values().any(|link| {
            link.account_id == account_id
                && link.connection_id == connection.id
                && link.kind == crate::account_auth::ExternalSubjectKind::ConsumerOidc
                && link.status == crate::account_auth::AuthMethodStatus::Active
        });
        if !linked {
            return (
                StatusCode::CONFLICT,
                "link Google to this account before using its photo",
            )
                .into_response();
        }
        account_id
    };
    let purpose = PendingAuthPurpose::ConsumerOidcAvatar(PendingConsumerOidcAvatar {
        account_id,
        session_id,
        connection_id: connection.id.clone(),
        connection_revision: connection.current_revision(),
    });
    match prepare_oidc_browser_login(
        auth,
        &headers,
        connection,
        OidcBrowserOptions {
            authority: OidcConnectionAuthority::Consumer(provider),
            native_return: None,
            native_handoff_challenge: None,
            purpose,
        },
    )
    .await
    {
        Ok(authorization_url) => (
            StatusCode::OK,
            Json(json!({ "authorization_url": authorization_url })),
        )
            .into_response(),
        Err(response) => response,
    }
}

/// The small page the browser lands on after a link or photo ceremony.
fn ceremony_result_page(title: &str, message: &str) -> axum::response::Response {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title></head><body><main><h1>{title}</h1><p>{message}</p></main></body></html>"
        ),
    )
        .into_response()
}

/// Submitted by the signed-out account entry point. POST keeps the work email
/// out of browser history and intermediary request URLs; the handler uses it
/// only to select exactly one DNS-verified organization, then starts the same
/// PKCE flow as `/auth/login`. Tenant, connection, protocol, and revision live
/// only in server-held pending state from this point onward.
#[derive(Deserialize)]
pub struct WorkEmailLoginForm {
    email: String,
    #[serde(default)]
    return_to: Option<String>,
    #[serde(default)]
    handoff_challenge: Option<String>,
}

pub async fn post_work_email_login(
    State(wb): State<SharedWorkbench>,
    Extension(auth): Extension<AuthShellState>,
    headers: HeaderMap,
    Form(form): Form<WorkEmailLoginForm>,
) -> impl IntoResponse {
    let native_return = match native_return_uri(
        form.return_to.as_deref(),
        form.handoff_challenge.as_deref(),
        dev_web_return_enabled(),
    ) {
        Ok(value) => value,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };
    let discovered = {
        let guard = wb.lock_unpoisoned();
        match enterprise_sso_for_work_email(guard.store_ref(), &form.email) {
            Ok(Some((connection, context))) => {
                match Org::rebuild_in(guard.store_ref(), &context.store_scope) {
                    Ok(org) => organization_oidc_client_secret(&guard, &org, &connection)
                        .map(|secret| Some((connection, context, secret))),
                    Err(_) => Err("corporate sign-in discovery is unavailable"),
                }
            }
            Ok(None) => Ok(None),
            Err(_) => Err("corporate sign-in discovery is unavailable"),
        }
    };
    let Some((connection, context, client_secret)) = (match discovered {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "corporate sign-in discovery is unavailable",
            )
                .into_response()
        }
    }) else {
        // One response covers invalid, absent, incomplete, unsupported, and
        // ambiguous matches. Discovery is routing, not an organization or
        // invitation enumeration surface.
        return (
            StatusCode::NOT_FOUND,
            "corporate sign-in is not available for that work email",
        )
            .into_response();
    };
    begin_enterprise_browser_login(
        auth,
        &headers,
        connection,
        context,
        client_secret,
        native_return,
        form.handoff_challenge,
    )
    .await
}

#[derive(Default, Deserialize)]
pub struct LoginQuery {
    #[serde(default)]
    return_to: Option<String>,
    #[serde(default)]
    handoff_challenge: Option<String>,
    /// Which consumer entrance to use (`google`, `microsoft`). Absent means the
    /// first one this deployment offers, so every link that predates DR-0189
    /// keeps its meaning. It selects among the entrances the deployment has
    /// configured; it cannot introduce one.
    #[serde(default)]
    provider: Option<String>,
}

fn native_return_uri(
    raw: Option<&str>,
    challenge: Option<&str>,
    dev_web_return: bool,
) -> Result<Option<String>, &'static str> {
    let challenge_ok = |challenge: &str| {
        challenge.len() == 43
            && challenge
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    };
    match (raw, challenge) {
        (None | Some(""), None) => Ok(None),
        (Some("gaugewright://auth/callback"), Some(challenge)) if challenge_ok(challenge) => {
            Ok(Some("gaugewright://auth/callback".to_string()))
        }
        (Some("gaugewright://auth/callback"), _) => {
            Err("native login requires a valid handoff challenge")
        }
        (Some(raw), Some(challenge)) if dev_web_return && loopback_web_return(raw) => {
            if challenge_ok(challenge) {
                Ok(Some(raw.to_string()))
            } else {
                Err("native login requires a valid handoff challenge")
            }
        }
        (Some(raw), None) if dev_web_return && loopback_web_return(raw) => {
            Err("native login requires a valid handoff challenge")
        }
        _ => Err("unsupported login return URI"),
    }
}

/// Whether this deployment admits dev loopback web returns on the login handoff
/// (ADR 0140): `GAUGEDESK_DEV_WEB_RETURN=1`. Off is the production posture — the
/// hosted Hub never sets it, so the `gaugewright://` scheme stays the only
/// admitted return there.
fn dev_web_return_enabled() -> bool {
    gaugedesk_env::enabled("DEV_WEB_RETURN")
}

/// A dev web return target (ADR 0140, amended): **loopback** only, in two
/// forms — the raw dev loop's plain-http loopback literal
/// (`http://localhost[:port][/path]`, `http://127.0.0.1[:port][/path]`), and
/// the development fabric's named origin (`https://<labels>.localhost[:port]
/// [/path]`, e.g. `https://desk.gw.localhost:7443/`), whose `.localhost` suffix
/// resolves to loopback by RFC 6761 and by every browser that would open the
/// return. Conservative path charset, no query, fragment, or userinfo, so the
/// admitted value can only ever reach a browser on the developer's own machine.
/// Pure; the env gate is [`dev_web_return_enabled`].
pub(crate) fn loopback_web_return(raw: &str) -> bool {
    let rest = match raw
        .strip_prefix("http://localhost")
        .or_else(|| raw.strip_prefix("http://127.0.0.1"))
        .or_else(|| fabric_host_rest(raw))
    {
        Some(rest) => rest,
        None => return false,
    };
    // The host must end exactly there — `http://localhost.evil.example` strips to
    // `.evil.example`, which the port/path grammar below rejects.
    let rest = match rest.strip_prefix(':') {
        Some(after_colon) => {
            let digits = after_colon
                .bytes()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            if digits == 0 {
                return false;
            }
            &after_colon[digits..]
        }
        None => rest,
    };
    rest.is_empty()
        || (rest.starts_with('/')
            && rest.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_' | b'~')
            }))
}

/// The named-origin form: `https://<label>(.<label>)+` where the final label is
/// exactly `localhost` and every label is lowercase alphanumeric-or-hyphen.
/// Returns the remainder after the host (the `[:port][/path]` tail) when the
/// host matches, `None` otherwise. A bare `https://localhost` is deliberately
/// not admitted — the raw loop is plain http; https is the fabric's named
/// origin model.
fn fabric_host_rest(raw: &str) -> Option<&str> {
    let after_scheme = raw.strip_prefix("https://")?;
    let host_len = after_scheme
        .bytes()
        .take_while(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-' || *byte == b'.'
        })
        .count();
    let host = &after_scheme[..host_len];
    let rest = &after_scheme[host_len..];
    let mut labels = host.split('.');
    let Some("localhost") = labels.next_back() else {
        return None;
    };
    let mut named = 0;
    for label in labels {
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        named += 1;
    }
    if named == 0 {
        return None;
    }
    Some(rest)
}

/// The OP's redirect-back query: a success carries `code` + `state`; a denial carries
/// `error` (+ optional `error_description`) per RFC 6749 §4.1.2.1.
#[derive(Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

fn callback_err(e: CallbackError) -> axum::response::Response {
    let (code, msg) = match e {
        CallbackError::Exchange(m) => (
            StatusCode::BAD_GATEWAY,
            format!("token exchange failed: {m}"),
        ),
        CallbackError::Jwks(m) => (
            StatusCode::BAD_GATEWAY,
            format!("JWKS fetch/parse failed: {m}"),
        ),
        CallbackError::NotVerified => (
            StatusCode::UNAUTHORIZED,
            "the id-token did not verify".to_string(),
        ),
    };
    (code, msg).into_response()
}

/// `GET /auth/callback` — finish OIDC login: match the CSRF `state`, redeem the code,
/// verify the id-token, audit the login, and hand the verified id-token (the bearer)
/// back to the client. See the module docs.
pub async fn get_callback(
    State(wb): State<SharedWorkbench>,
    Extension(auth): Extension<AuthShellState>,
    crate::workbench_auth::PeerIp(peer): crate::workbench_auth::PeerIp,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> impl IntoResponse {
    // SECAUD-8: per-**client-IP** failed-callback lockout (429 when locked) — defense-in-depth
    // behind the edge rate-limit, mirroring the SCIM guard. A bad/replayed state or a failed
    // token exchange records a failure; a completed login clears the IP's count. The key is the
    // real client IP (CF-Connecting-IP at the hosted edge, else the socket peer below it), never
    // the client-supplied tenant header — spoofing/rotating that header must not move the bucket.
    // `None` = the client cannot be identified (no edge, no peer), so the in-process backstop is
    // skipped rather than keyed on one shared bucket; the edge remains the primary control.
    let throttle_key = crate::workbench_auth::throttle_scope(
        &headers,
        peer,
        crate::workbench_auth::web_account_mode(),
    );
    let throttle = wb.lock_unpoisoned().oidc_throttle().clone();
    let now = throttle.now_ms();
    if let Some(key) = &throttle_key {
        if !throttle.allowed(key, now) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "too many failed SSO callbacks; retry later",
            )
                .into_response();
        }
    }
    if let Some(err) = q.error {
        let desc = q.error_description.unwrap_or_default();
        return (
            StatusCode::UNAUTHORIZED,
            format!("the IdP denied the login: {err} {desc}")
                .trim()
                .to_string(),
        )
            .into_response();
    }
    let (Some(code), Some(state)) = (q.code, q.state) else {
        if let Some(key) = &throttle_key {
            throttle.record_failure(key, now);
        }
        return (StatusCode::BAD_REQUEST, "missing code or state").into_response();
    };

    // Single-use take: an unknown / replayed / expired `state` finds nothing
    // (CSRF guard).
    let pending = auth.pending_auth_mut().take(&state, Instant::now());
    let Some(pending) = pending else {
        if let Some(key) = &throttle_key {
            throttle.record_failure(key, now);
        }
        return (StatusCode::BAD_REQUEST, "unknown or expired state").into_response();
    };
    let native_return = pending.native_return.clone();
    let native_handoff_challenge = pending.native_handoff_challenge.clone();

    let purpose = pending.purpose.clone();
    let enterprise_login = pending.login_context.clone();
    let pending_issuer = pending.issuer.clone();
    let pending_audiences = pending.audiences.clone();
    let pending_consumer_connection = pending.consumer_connection_id.clone();
    let finished = tokio::task::spawn_blocking(move || {
        let http = HttpClient::new();
        finish_callback_verified(&pending, &code, &http)
    })
    .await;
    let verified = match finished {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            if let Some(key) = &throttle_key {
                throttle.record_failure(key, now);
            }
            return callback_err(e);
        }
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "callback task panicked").into_response()
        }
    };

    // A completed exchange clears this client IP's failed-callback count (SECAUD-8).
    if let Some(key) = &throttle_key {
        throttle.record_success(key);
    }

    // Consumer-provider linking is an account mutation, not a login. The
    // callback rechecks the provider revision and the exact independent
    // session that initiated the ceremony before committing the subject link.
    // It mints no session, provisions no tenant, stores no refresh grant, and
    // exposes no provider credential.
    if let PendingAuthPurpose::ConsumerOidcLink(context) = &purpose {
        // The connection comes from the ceremony's own pinned context, never from
        // the callback, so a second configured provider cannot be reached by
        // returning to this leg with different input.
        let Some((provider, connection)) = configured_consumer_connection(&context.connection_id)
        else {
            return (
                StatusCode::CONFLICT,
                "that account linking is no longer configured",
            )
                .into_response();
        };
        if connection.current_revision() != context.connection_revision
            || !connection_still_accepts(&connection, &pending_issuer, &pending_audiences)
        {
            return (
                StatusCode::CONFLICT,
                format!(
                    "{} sign-in changed while you were linking it; return to GaugeDesk and start again",
                    provider.label
                ),
            )
                .into_response();
        }

        let linked = {
            let mut guard = wb.lock_unpoisoned();
            let account_auth = match crate::account_auth::AccountAuth::rebuild(guard.store_ref()) {
                Ok(state) => state,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "account authentication state is unavailable",
                    )
                        .into_response()
                }
            };
            if !durable_independent_session(
                &account_auth,
                &context.session_id,
                &context.account_id,
                crate::account::session_now_ms(),
            ) {
                return (
                    StatusCode::UNAUTHORIZED,
                    "the independent account session that started this link is no longer current",
                )
                    .into_response();
            }
            let Some(token_issuer) = id_token_issuer(&verified.id_token) else {
                return (
                    StatusCode::FORBIDDEN,
                    "the sign-in result could not be read",
                )
                    .into_response();
            };
            let record = match crate::account_auth::ExternalSubjectRecord::new(
                &context.account_id,
                &connection.id,
                &token_issuer,
                verified.authority.as_str(),
                crate::account_auth::ExternalSubjectKind::ConsumerOidc,
                crate::account::session_now_ms(),
            ) {
                Ok(record) => record,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "the Google sign-in result could not be linked",
                    )
                        .into_response()
                }
            };
            let facts =
                match crate::account_auth::decide_link_external_subject(&account_auth, record) {
                    Ok(facts) => facts,
                    Err(crate::account_auth::AuthRejection::SubjectAlreadyLinked) => {
                        return (
                            StatusCode::CONFLICT,
                            "this Google account is already linked to another GaugeDesk account",
                        )
                            .into_response()
                    }
                    Err(_) => {
                        return (StatusCode::CONFLICT, "this Google account cannot be linked")
                            .into_response()
                    }
                };
            if crate::account_auth::append_facts(guard.store_mut(), &facts).is_err() {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "the Google account link could not be saved",
                )
                    .into_response();
            }
            crate::audit::record_in(
                &mut guard,
                crate::account_auth::ACCOUNT_AUTH_SCOPE,
                &context.account_id,
                "account.consumer-oidc.link",
                &connection.id,
            );
            true
        };
        debug_assert!(linked);
        if let Some(picture) = id_token_picture(&verified.id_token) {
            crate::account_avatar::spawn_provider_adoption(
                wb.clone(),
                context.account_id.clone(),
                picture,
            );
        }
        return (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Google linked</title></head><body><main><h1>Google linked</h1><p>You can close this window and return to GaugeDesk.</p></main></body></html>",
        )
            .into_response();
    }

    // The person asked for their provider photo. This is an account mutation
    // on an existing link, never a login: it runs only for the subject already
    // linked to the account that started it, and it replaces the avatar
    // because that is what the person asked for (DR-0195 §3).
    if let PendingAuthPurpose::ConsumerOidcAvatar(context) = &purpose {
        let Some((_, connection)) = configured_consumer_connection(&context.connection_id) else {
            return (
                StatusCode::CONFLICT,
                "Google sign-in is no longer configured",
            )
                .into_response();
        };
        {
            let guard = wb.lock_unpoisoned();
            let Ok(account_auth) = crate::account_auth::AccountAuth::rebuild(guard.store_ref())
            else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "account authentication state is unavailable",
                )
                    .into_response();
            };
            let token_issuer = id_token_issuer(&verified.id_token);
            if let Err(refusal) = admit_consumer_avatar_refresh(
                &account_auth,
                context,
                &connection,
                &ReturnedConsumerIdentity {
                    pinned_issuer: &pending_issuer,
                    pinned_audiences: &pending_audiences,
                    token_issuer: token_issuer.as_deref(),
                    subject: verified.authority.as_str(),
                },
                crate::account::session_now_ms(),
            ) {
                return refusal.into_response();
            }
        }
        let Some(picture) = id_token_picture(&verified.id_token) else {
            return ceremony_result_page(
                "No photo from Google",
                "Google did not send a photo for this account. Your GaugeDesk photo is unchanged.",
            );
        };
        let fetched = tokio::task::spawn_blocking(move || {
            crate::account_avatar::fetch_provider_picture(&picture)
                .and_then(|bytes| crate::account_avatar::normalize(&bytes).ok())
        })
        .await
        .ok()
        .flatten();
        let Some(avatar) = fetched else {
            return ceremony_result_page(
                "Photo not updated",
                "Google's photo could not be fetched. Your GaugeDesk photo is unchanged.",
            );
        };
        let written = {
            let mut guard = wb.lock_unpoisoned();
            crate::account_avatar::replace_avatar(
                &mut guard,
                &context.account_id,
                Some(&avatar),
                crate::account::AvatarSource::Provider,
                crate::account::session_now_ms(),
            )
            .map(|()| {
                crate::audit::record_in(
                    &mut guard,
                    &crate::account::account_scope(&context.account_id),
                    &context.account_id,
                    "account.avatar.provider",
                    &connection.id,
                );
            })
        };
        return match written {
            Ok(()) => ceremony_result_page(
                "Photo updated",
                "Your Google photo is now your GaugeDesk photo. You can close this window and return to GaugeDesk.",
            ),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "the photo could not be saved",
            )
                .into_response(),
        };
    }

    // A connection test proves the real browser callback and mapped subject,
    // but it is explicitly not account sign-in. It never runs the login fold,
    // provisions a person or membership, mints a session/cookie, stores a
    // refresh token, or returns the external token to the browser.
    if let PendingAuthPurpose::EnterpriseConnectionTest(context) = &purpose {
        let Some(fold) = &auth.enterprise_test_fold else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "enterprise connection-test callback is not configured",
            )
                .into_response();
        };
        let folded = {
            let mut guard = wb.lock_unpoisoned();
            fold(&mut guard, context, &verified)
        };
        if folded.is_err() {
            return (
                StatusCode::CONFLICT,
                "this corporate sign-in test is no longer current; return to GaugeDesk and start again",
            )
                .into_response();
        }
        return (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sign-in test complete</title></head><body><main><h1>Sign-in test complete</h1><p>The verified result is now available in GaugeDesk. You can close this window.</p></main></body></html>",
        )
            .into_response();
    }

    // A corporate login passes through the enterprise admission fold. Consumer
    // OIDC resolves only through an exact active link created from an
    // independently authenticated account session; provider subject and email
    // are never GaugeDesk account identity.
    let resolution = if let Some(context) = enterprise_login.as_ref() {
        let Some(fold) = &auth.login_fold else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "corporate account admission is not configured",
            )
                .into_response();
        };
        let corporate_identity = VerifiedEnterpriseIdentity {
            authority: verified.authority.clone(),
            verified_email: id_token_verified_email(&verified.id_token),
        };
        let folded = {
            let mut guard = wb.lock_unpoisoned();
            fold(&mut guard, context, &corporate_identity)
        };
        match folded {
            Ok(resolution) => {
                if let Some(picture) = id_token_picture(&verified.id_token) {
                    crate::account_avatar::spawn_provider_adoption(
                        wb.clone(),
                        resolution.account_id.clone(),
                        picture,
                    );
                }
                let now_ms = crate::account::session_now_ms();
                let display_label = id_token_display_label(&verified.id_token)
                    .unwrap_or_else(|| resolution.account_id.clone());
                let provider_expires_at_ms = id_token_expiry_ms(&verified.id_token)
                    .unwrap_or_else(|| now_ms.saturating_add(60 * 60 * 1000));
                return auth.deliver_enterprise_login(
                    &wb,
                    EnterpriseLoginDelivery {
                        login_context: context.clone(),
                        resolution,
                        display_label,
                        provider_expires_at_ms,
                        refresh_token: verified.refresh_token.clone(),
                        native_return,
                        native_handoff_challenge,
                    },
                );
            }
            Err(LoginFoldRefusal::NotAdmitted) => {
                return (
                    StatusCode::FORBIDDEN,
                    "this corporate account is not admitted to the organization",
                )
                    .into_response()
            }
            Err(LoginFoldRefusal::StaleConnection) => {
                return (
                    StatusCode::CONFLICT,
                    "corporate sign-in changed while you were signing in; start again",
                )
                    .into_response()
            }
            Err(LoginFoldRefusal::Unavailable) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "corporate account admission is unavailable",
                )
                    .into_response()
            }
        }
    } else {
        let Some((provider, connection)) = pending_consumer_connection
            .as_deref()
            .and_then(configured_consumer_connection)
        else {
            return (
                StatusCode::CONFLICT,
                "consumer sign-in is no longer configured",
            )
                .into_response();
        };
        if !connection_still_accepts(&connection, &pending_issuer, &pending_audiences) {
            return (
                StatusCode::CONFLICT,
                "consumer sign-in changed while you were signing in; start again",
            )
                .into_response();
        }
        let account_auth = {
            let guard = wb.lock_unpoisoned();
            match crate::account_auth::AccountAuth::rebuild(guard.store_ref()) {
                Ok(state) => state,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "account authentication state is unavailable",
                    )
                        .into_response()
                }
            }
        };
        // Three answers, not two. A subject with an active link signs in. A
        // subject nobody has linked is a person who has never had an account
        // here, and ADR 0146 §1 says what happens to them: the provider's
        // verified email satisfies step 1, and they go on to create a passkey
        // and an account, with this subject linked onto it. The refusal that
        // used to stand here told them to sign in with a passkey they had no
        // way to own and link Google from a settings page they could not reach.
        // The concrete issuer this token claims, which the verifier has already
        // bound to the pinned rule. Durable state keys on it, not on the rule.
        let Some(token_issuer) = id_token_issuer(&verified.id_token) else {
            return (
                StatusCode::FORBIDDEN,
                "the sign-in result could not be read",
            )
                .into_response();
        };
        match decide_consumer_callback(
            &account_auth,
            ConsumerCallbackFacts {
                provider,
                connection: &connection,
                accepted_issuer: &pending_issuer,
                verified_issuer: &token_issuer,
                subject: verified.authority.as_str(),
                attested_email: id_token_verified_email(&verified.id_token),
                asserted_email: id_token_asserted_email(&verified.id_token),
            },
        ) {
            ConsumerCallbackDecision::Login(resolution) => resolution,
            ConsumerCallbackDecision::Signup { verified_email } => {
                return begin_consumer_signup(
                    &auth,
                    ConsumerSignupEmail::Attested(verified_email),
                    &connection,
                    &token_issuer,
                    &verified,
                    native_return,
                    native_handoff_challenge,
                );
            }
            // Same ticket, same browser binding, same single spend — the person
            // just has one more thing to do before anything is created.
            ConsumerCallbackDecision::SignupNeedsEmailProof { asserted_email } => {
                return begin_consumer_signup(
                    &auth,
                    ConsumerSignupEmail::Unproved {
                        prefill: asserted_email,
                    },
                    &connection,
                    &token_issuer,
                    &verified,
                    native_return,
                    native_handoff_challenge,
                );
            }
            ConsumerCallbackDecision::Refuse(status, message) => {
                return (status, message).into_response()
            }
        }
    };

    let VerifiedOidcIdentity {
        id_token,
        refresh_token,
        ..
    } = verified;
    let account_id = resolution.account_id;
    let session_method = resolution.session_method;
    // A sign-in supplies the account's first avatar and never the next one:
    // adoption writes only where the account has no avatar record at all.
    if let Some(picture) = id_token_picture(&id_token) {
        crate::account_avatar::spawn_provider_adoption(wb.clone(), account_id.clone(), picture);
    }

    // Browser and programmatic corporate callbacks mint here. A native handoff
    // delays the same opaque-session mint until its PKCE-bound code is redeemed,
    // when the Hub can bind that exact session to the enrolling device.
    let account_session_required = requires_account_session(native_return.is_some());
    let mut account_session_token: Option<String> = None;

    // Attribute the login to the resolved GaugeDesk account (`AUD-1` /
    // `INV-21`). Corporate membership consequences were committed by the fold
    // above before any session exists.
    {
        let mut wb = wb.lock_unpoisoned();
        let actor = account_id.clone();
        let store_scope = enterprise_login
            .as_ref()
            .map(|context| context.store_scope.clone())
            .unwrap_or_else(|| crate::workbench_auth::req_scope(&headers));
        crate::audit::record_in(&mut wb, &store_scope, &actor, "auth.login", &account_id);
        // Hosted web account (ADR 0077 §9): a successful login provisions the person's personal
        // tenant-of-one (idempotent) so they land in the Console with their own space. No-op on
        // the enterprise/desktop paths (web-account mode off).
        provision_web_account(&mut wb, &account_id, web_account_mode());
        // Hosted browser session (ADR 0147 §1): mint a durable, opaque, per-session
        // revocable session token. That token — never the external id-token — becomes
        // the `gw_session` cookie. The external id-token stops being the session; the
        // browser holds a fresh short-lived one in memory (obtained from /auth/refresh)
        // as its Home access credential.
        if account_session_required {
            if let Some(token) = wb.mint_account_session(
                &account_id,
                &session_method,
                crate::account::SESSION_ABSOLUTE_LIFETIME_MS / 1000,
            ) {
                // Seal the offline-access refresh token as this session's OWN durable,
                // bound grant, keyed by the session id (ADR 0147 §2) — not one coarse
                // per-person `web` key — so each login is its own session and logout or
                // revoke ends only it. Only when the OP returned a refresh token; a
                // native client's device-bound grant is written at /auth/mobile/exchange.
                // Best-effort.
                let session_id = crate::account_session::session_id(&token);
                if web_account_mode() {
                    if let Some(rt) = &refresh_token {
                        store_refresh_token(
                            &mut wb,
                            &account_id,
                            rt,
                            crate::account::RefreshBinding::Web,
                            &session_id,
                            "",
                        );
                    }
                }
                account_session_token = Some(token);
            }
        }
    }
    if account_session_required && account_session_token.is_none() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not create the account session",
        )
            .into_response();
    }

    // The custom-scheme redirect carries only a one-time opaque code. The app
    // must redeem it with the verifier whose challenge was pinned to the login
    // state; an app that intercepts the scheme cannot obtain the id-token.
    if let Some(native_return) = native_return {
        let Some(challenge) = native_handoff_challenge else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "native handoff challenge was lost",
            )
                .into_response();
        };
        let now_ms = crate::account::session_now_ms();
        let label = id_token_display_label(&id_token).unwrap_or_else(|| account_id.clone());
        let provider_expires_at_ms =
            id_token_expiry_ms(&id_token).unwrap_or_else(|| now_ms.saturating_add(60 * 60 * 1000));
        let code = auth.native_handoffs_mut().issue(
            NativeHandoffIssue {
                account_id: account_id.clone(),
                session_method,
                label,
                provider_expires_at_ms,
                refresh_token: refresh_token.clone(),
                challenge,
            },
            Instant::now(),
        );
        let target = format!("{native_return}#code={code}");
        return Redirect::to(&target).into_response();
    }

    // Hosted web account (ADR 0077 / ADR 0147 §1): deliver the session as the shared
    // `Domain=.gaugewright.com` cookie carrying the **opaque** session token, not the
    // external id-token and not a URL-fragment bearer — one sign-in authenticates the
    // whole site, the cookie (unlike a header) rides SSE + top-level navigations, and
    // the session is now server-side revocable. Redirect to the Console; no token
    // touches the URL. The client obtains its short-lived id-token from /auth/refresh.
    if web_account_mode() {
        let post_login = gaugedesk_env::var("OIDC_POST_LOGIN_URL")
            .filter(|u| !u.trim().is_empty())
            .unwrap_or_else(|| "/".to_string());
        let mut resp = Redirect::to(&post_login).into_response();
        if let Some(token) = &account_session_token {
            append_session_cookies(&mut resp, token);
        }
        return resp;
    }

    // Programmatic clients receive only an opaque GaugeDesk account bearer.
    // With a configured client URL, deliver it in the URL fragment (never a
    // query parameter or Referer-visible value).
    let Some(delivered_token) = account_session_token else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not deliver the account session",
        )
            .into_response();
    };
    if let Some(url) = gaugedesk_env::var("OIDC_POST_LOGIN_URL") {
        if !url.trim().is_empty() {
            // Both JWT and opaque session alphabets are base64url and fragment-safe.
            let target = format!("{url}#id_token={delivered_token}&token_type=Bearer");
            return Redirect::to(&target).into_response();
        }
    }
    (
        StatusCode::OK,
        Json(json!({
            "authority": account_id,
            "id_token": delivered_token,
            "token_type": "Bearer",
        })),
    )
        .into_response()
}

/// `GET /auth/refresh` (`ADR 0147` §1/§4): mint a fresh short-lived id-token from this
/// session's stored refresh grant and return it in the **body** — the browser holds it
/// in memory as its Home access credential. The opaque session **cookie is unchanged**;
/// it is the session, and the id-token is no longer the session. Admitted only while the
/// current session is still live and within its bounds (fail-closed: the opaque cookie
/// authenticates to nobody once revoked/expired, so it cannot refresh itself). An
/// elapsed absolute lifetime or idle timeout refuses refresh and ends the session on
/// this surface (ADR 0147 §4, closes SOC 2 F-1.4 for the personal path). Web-account
/// only. Authenticated by the opaque cookie alone — never an `Authorization` bearer —
/// so the session id resolves from the session token, not an in-memory id-token.
pub async fn get_refresh(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !web_account_mode() {
        return (StatusCode::NOT_FOUND, "not a web-account deployment").into_response();
    }
    let bearer = crate::net_http::bearer(&headers).map(str::to_string);
    let now_ms = crate::account::session_now_ms();
    let (person, session_id, refresh_token, session_method) = {
        let g = wb.lock_unpoisoned();
        let person = g.actor(bearer.as_deref());
        if person == "anonymous" {
            return (StatusCode::UNAUTHORIZED, "authenticate to refresh").into_response();
        }
        // The opaque session token resolves to the session id that keys this session's
        // own refresh grant (ADR 0147 §2). A non-anonymous person always carries a
        // resolvable bearer here.
        let Some(token) = bearer.as_deref() else {
            return (StatusCode::UNAUTHORIZED, "authenticate to refresh").into_response();
        };
        let session_id = crate::account_session::session_id(token);
        let grant = match admit_browser_refresh(&g, &person, &session_id, now_ms) {
            Ok(grant) => grant,
            Err(reason) => return (StatusCode::UNAUTHORIZED, reason).into_response(),
        };
        // Which provider minted this session, so the grant is refreshed at that
        // provider's token endpoint (DR-0189).
        let method = g.resolve_account_session(token).map(|(_, method)| method);
        match g.unseal_account_secret(&grant.sealed) {
            Some(rt) => (person, session_id, rt, method),
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    "no refresh token on file; sign in again",
                )
                    .into_response()
            }
        }
    };
    let Some((provider, sso)) = session_method
        .as_deref()
        .and_then(session_consumer_connection)
        .or_else(|| configured_consumer_connections().into_iter().next())
    else {
        return (StatusCode::CONFLICT, "web-account SSO not configured").into_response();
    };
    let client_id = sso.audiences.first().cloned().unwrap_or_default();
    let client_secret = provider.client_secret().map(|s| s.expose().to_string());
    let issuer = sso.issuer.clone();
    // Discovery + the refresh grant touch the network — off the async runtime.
    let refreshed = tokio::task::spawn_blocking(move || {
        let http = HttpClient::new();
        let endpoints =
            discover_endpoints(&issuer, &http).map_err(|e| format!("discovery: {e}"))?;
        refresh_id_token(
            &endpoints.token_endpoint,
            &client_id,
            client_secret.as_deref(),
            &refresh_token,
            &http,
        )
    })
    .await;
    let new_id = match refreshed {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            return (StatusCode::BAD_GATEWAY, format!("refresh failed: {e}")).into_response()
        }
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "refresh task panicked").into_response()
        }
    };
    // An admitted refresh touches this session's grant last-seen so the idle clock
    // resets (ADR 0147 §4). Keyed by the session id, so it resets only this session.
    {
        let mut g = wb.lock_unpoisoned();
        let scope = crate::account::account_scope(&person);
        let _ = g.touch_account_refresh_in(&scope, &session_id, now_ms);
    }
    // Return the fresh id-token in the BODY so the client holds it in memory as the Home
    // access credential (ADR 0147 §1). The opaque session cookie is deliberately left
    // untouched — it is the session and it stays stable across refreshes.
    (
        StatusCode::OK,
        Json(json!({ "refreshed": true, "person": person, "id_token": new_id })),
    )
        .into_response()
}

/// Refresh a native GaugeDesk account session. The opaque account bearer names
/// both the person and the exact device-bound refresh grant. The Hub renews its
/// provider authority server-side, discards the external id-token, and returns
/// only non-secret scheduling metadata; the native bearer remains unchanged.
pub async fn post_native_refresh(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !web_account_mode() {
        return (StatusCode::NOT_FOUND, "not a web-account deployment").into_response();
    }
    let bearer = crate::net_http::bearer(&headers).map(str::to_string);
    let now_ms = crate::account::session_now_ms();
    // The native session is bound to its enrolled device (ADR 0147 §2). The client
    // presents only its bearer — no device header — and admission reads the bound
    // device from the STORED native grant, so omitting or forging `x-gw-device`
    // cannot bypass revocation (SOC 2 F-4.2). The header is not consulted here.
    let (person, session_id, refresh_token, session_method) = {
        let g = wb.lock_unpoisoned();
        let person = g.actor(bearer.as_deref());
        if person == "anonymous" {
            return (StatusCode::UNAUTHORIZED, "authenticate to refresh").into_response();
        }
        let Some(token) = bearer.as_deref() else {
            return (StatusCode::UNAUTHORIZED, "authenticate to refresh").into_response();
        };
        let session_id = crate::account_session::session_id(token);
        let grant = match admit_native_refresh(&g, &person, &session_id, now_ms) {
            Ok(grant) => grant,
            Err(reason) => return (StatusCode::UNAUTHORIZED, reason).into_response(),
        };
        // The provider that minted this session, for the same reason the browser
        // leg reads it (DR-0189).
        let method = g.resolve_account_session(token).map(|(_, method)| method);
        match g.unseal_account_secret(&grant.sealed) {
            Some(token) => (person, session_id, token, method),
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    "no refresh token on file; sign in again",
                )
                    .into_response()
            }
        }
    };
    let Some((provider, sso)) = session_method
        .as_deref()
        .and_then(session_consumer_connection)
        .or_else(|| configured_consumer_connections().into_iter().next())
    else {
        return (StatusCode::CONFLICT, "web-account SSO not configured").into_response();
    };
    let client_id = sso.audiences.first().cloned().unwrap_or_default();
    let client_secret = provider
        .client_secret()
        .map(|secret| secret.expose().to_string());
    let issuer = sso.issuer.clone();
    let refreshed = tokio::task::spawn_blocking(move || {
        let http = HttpClient::new();
        let endpoints =
            discover_endpoints(&issuer, &http).map_err(|error| format!("discovery: {error}"))?;
        refresh_id_token(
            &endpoints.token_endpoint,
            &client_id,
            client_secret.as_deref(),
            &refresh_token,
            &http,
        )
    })
    .await;
    match refreshed {
        Ok(Ok(_id_token)) => {
            // An admitted refresh resets the native grant's idle clock (ADR 0147 §4).
            {
                let mut g = wb.lock_unpoisoned();
                let scope = crate::account::account_scope(&person);
                let _ = g.touch_account_refresh_in(&scope, &session_id, now_ms);
            }
            (
                StatusCode::OK,
                Json(json!({
                    "refreshed": true,
                    "person": person,
                    "refresh_after_ms": now_ms.saturating_add(50 * 60 * 1000),
                })),
            )
                .into_response()
        }
        Ok(Err(error)) => {
            (StatusCode::BAD_GATEWAY, format!("refresh failed: {error}")).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "refresh task panicked").into_response(),
    }
}

#[derive(Deserialize)]
pub struct NativeHandoffExchange {
    code: String,
    verifier: String,
    /// Optional device label (LOGIN-3, ADR 0123 §4): a client that names
    /// itself gets that name in the trusted-devices registry. Absent on
    /// pre-existing mobile clients — the wire contract is unchanged for them.
    #[serde(default)]
    device_label: Option<String>,
}

/// Record the redeeming native client in the person's trusted-devices registry
/// (ADR 0123 §4 / ADR 0053): the handoff session is device-bound, so the
/// account surface can see and revoke it. Returns the minted device id.
pub fn record_native_device(wb: &SharedWorkbench, person: &str, label: &str) -> Option<String> {
    let id = format!(
        "native-{}",
        hex::encode(crate::session::random_bytes::<8>())
    );
    let record = crate::account::DeviceRecord {
        id: id.clone(),
        op: RecordOp::Upsert,
        label: label.chars().take(64).collect(),
        kind: crate::account::DeviceKind::Computer,
        subkey_pubkey: String::new(),
        status: crate::account::DeviceStatus::Active,
        enrolled_at: crate::account::device_enrolled_at_now(),
    };
    let scope = crate::account::account_scope(person);
    wb.lock_unpoisoned()
        .upsert_account_device_in(&scope, &record)
        .ok()?;
    Some(id)
}

/// Write the native session's durable refresh grant (ADR 0147 §2), sealing the
/// refresh token the handoff carried from the login callback and binding it to the
/// enrolled `device_id`. The grant is the native session's **own** record — it does
/// not read the browser `web` grant, which a prior logout may already have
/// tombstoned (SOC 2 F-1.3), so a native session established after a browser logout
/// is still valid. Best-effort: with no refresh token (the OP granted none) the
/// native session simply has none and falls back to re-login, as before.
fn bind_native_refresh_grant(
    wb: &SharedWorkbench,
    person: &str,
    session_id: &str,
    device_id: &str,
    refresh_token: Option<&str>,
) -> bool {
    let Some(refresh_token) = refresh_token else {
        return true;
    };
    let mut g = wb.lock_unpoisoned();
    let Some(sealed) = g.seal_account_secret(refresh_token) else {
        return false;
    };
    let scope = crate::account::account_scope(person);
    let now_ms = crate::account::session_now_ms();
    g.upsert_account_refresh_in(
        &scope,
        session_id,
        crate::account::RefreshBinding::Device,
        device_id,
        &sealed,
        now_ms,
    )
    .is_ok()
}

/// Whether `device_id` may continue this person's account session: it must be
/// a known, **unrevoked** device in their registry. Revocation flips the
/// record's status — it stops refresh and future use without rewriting
/// history (`INV-18`).
pub fn native_device_admitted(wb: &Workbench, person: &str, device_id: &str) -> bool {
    let scope = crate::account::account_scope(person);
    let Ok(account) = crate::account::Account::rebuild_in(wb.store_ref(), &scope) else {
        return false; // fail closed: an unreadable registry admits nothing
    };
    account
        .devices
        .get(device_id)
        .is_some_and(|device| device.status == crate::account::DeviceStatus::Active)
}

/// Redeem a single-use native login handoff. Neither the OIDC id-token nor its
/// refresh authority rides the custom-scheme URL or exchange response. The Hub
/// mints an opaque account session and binds its digest-keyed refresh grant to
/// the newly recorded trusted device. Revoking either the session or device
/// stops future use (`ADR 0147` §2–3).
pub async fn post_native_exchange(
    State(wb): State<SharedWorkbench>,
    Extension(auth): Extension<AuthShellState>,
    Json(request): Json<NativeHandoffExchange>,
) -> impl IntoResponse {
    if !web_account_mode() {
        return (StatusCode::NOT_FOUND, "not a web-account deployment").into_response();
    }
    let redeemed =
        auth.native_handoffs_mut()
            .redeem(&request.code, &request.verifier, Instant::now());
    match redeemed {
        Some(RedeemedHandoff {
            account_id,
            session_method,
            label,
            provider_expires_at_ms,
            refresh_token,
        }) => {
            let now_ms = crate::account::session_now_ms();
            let has_refresh_grant = refresh_token.is_some();
            let lifetime_ms = if has_refresh_grant {
                crate::account::SESSION_ABSOLUTE_LIFETIME_MS
            } else {
                provider_expires_at_ms
                    .saturating_sub(now_ms)
                    .min(crate::account::SESSION_ABSOLUTE_LIFETIME_MS)
            };
            if lifetime_ms < 1000 {
                return (StatusCode::UNAUTHORIZED, "the native handoff expired").into_response();
            }
            let lifetime_secs = (lifetime_ms / 1000).max(1);
            let account_session = {
                let mut guard = wb.lock_unpoisoned();
                guard.mint_account_session(&account_id, &session_method, lifetime_secs)
            };
            let Some(account_session) = account_session else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not create the account session",
                )
                    .into_response();
            };
            let device_label = request
                .device_label
                .as_deref()
                .map(str::trim)
                .filter(|label| !label.is_empty())
                .unwrap_or("Native device");
            let Some(device_id) = record_native_device(&wb, &account_id, device_label) else {
                wb.lock_unpoisoned()
                    .revoke_account_session(&account_session);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not enroll the native device",
                )
                    .into_response();
            };
            let session_id = crate::account_session::session_id(&account_session);
            let bound_session = wb.lock_unpoisoned().bind_account_session_device(
                &session_id,
                &account_id,
                &device_id,
            );
            if !bound_session
                || !bind_native_refresh_grant(
                    &wb,
                    &account_id,
                    &session_id,
                    &device_id,
                    refresh_token.as_deref(),
                )
            {
                let mut guard = wb.lock_unpoisoned();
                let scope = crate::account::account_scope(&account_id);
                let _ = guard.revoke_account_device_in(&scope, &device_id);
                guard.revoke_account_session(&account_session);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not bind the native account session",
                )
                    .into_response();
            }
            let expires_at_ms = now_ms.saturating_add(lifetime_secs.saturating_mul(1000));
            let refresh_after_ms = if has_refresh_grant {
                provider_expires_at_ms
                    .saturating_sub(10 * 60 * 1000)
                    .max(now_ms)
            } else {
                0
            };
            (
                StatusCode::OK,
                Json(json!({
                    "account_id": account_id,
                    "account_session": account_session,
                    "token_type": "Bearer",
                    "device_id": device_id,
                    "label": label,
                    "expires_at_ms": expires_at_ms,
                    "refresh_after_ms": refresh_after_ms,
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::UNAUTHORIZED,
            "unknown, expired, or incorrectly bound native handoff",
        )
            .into_response(),
    }
}

/// `POST /auth/logout` — end the browser's hosted account session. Opaque GaugeDesk account
/// sessions are revoked server-side; legacy OIDC id-tokens are self-contained and naturally
/// expire, so logout removes the browser's copy. The handler is intentionally idempotent and
/// does not require a still-valid session, allowing an expired user to return to a clean state.
pub async fn post_logout(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let bearer = crate::net_http::bearer(&headers).map(str::to_string);
    if let Some(token) = &bearer {
        let mut g = wb.lock_unpoisoned();
        // Resolve the caller's person and this session's id BEFORE revoking, so the
        // per-session grant can be tombstoned too.
        let person = g.actor(Some(token));
        let session_id = crate::account_session::session_id(token);
        // Durably revoke THIS opaque session server-side — evict the hot cache and
        // tombstone the durable index — so its token stops resolving now and after a
        // restart (ADR 0147 §3, `INV-18`). This is a true server-side session kill.
        g.revoke_account_session(token);
        // Tombstone this session's OWN refresh grant so refresh cannot mint a fresh
        // id-token after logout (SOC 2 F-1.3). Keyed by the session id, it ends only
        // this session: a concurrent browser session, or an independently-established
        // native device session (which ends only when its device is revoked), stays
        // live. Future-only (`INV-18`); best-effort and idempotent, so an already-
        // expired session still lands clean.
        if web_account_mode() && person != "anonymous" {
            let scope = crate::account::account_scope(&person);
            let _ = g.revoke_account_refresh_in(&scope, &session_id);
        }
    }
    let mut resp = StatusCode::NO_CONTENT.into_response();
    for value in [
        expired_session_cookie_header(),
        expired_session_hint_cookie_header(),
    ] {
        if let Ok(cookie) = axum::http::HeaderValue::from_str(&value) {
            resp.headers_mut()
                .append(axum::http::header::SET_COOKIE, cookie);
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::org::ORG_ID;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    // A real RSA-2048 test keypair (generated for tests only, never used in
    // production). The OP "signs" id-tokens with the private half; the shell verifies
    // against the JWKS the mock serves (the public modulus), exercising the real
    // asymmetric RS256 path — the algorithm Okta / Entra / Google all default to.
    const RSA_PRIVATE_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDDcxUtTJr7p7iI
vTn0SpwErh4ghN/ebHcz75T3xX9S5WxdaP2RRXzvO9tSC71dI+sGvjj1h5NlJSFg
v6DJ28ZbZdqh8rNRgtjvoQbzJLPcnGm15Qoxndu59csA8lMLv/dce4jx/XEpcNEK
3PsN7iyQuIM3maURPrmkJR0BNgVQ4UaNU/sbRHZqbFWUad2t49WooG8CsY5ITSMu
9gJQaT2aXY1JMqfq+SCiSDnw0FZhpcuYiFz9vRHQI+d4hHxIhN/lDg5CAJYQaKuX
01hormXh9Ra57INW6D9Afs9vF8Eh6aSngPbmCgfS29FAEzINrPOmtw1PH8tXTUc1
jjG5IXjtAgMBAAECggEAQ+escGAgqpVjkjJ4O61eVmvuMKsponv50FQJZCo8ad8m
zq9nBb1oQjAAK5nDkWQkyGN3o6qWZbpIRfZeFTPjzyZslv6dGZFF8L94DCrwyJGZ
UqaAa6umRw4kGTCX9Mmd1gZfln/Q/K5jGoybNwRMfH12rW8WwA6UbfitApozr5zw
jCVef7sBNvUw7s9n8x/OAmuzzRGwOX7vNBh/FkeIv5zYoCAeNDCejpoSBCp1PDUb
0ryev+LTi7WlYXGkwYCFLpzUie2GrAgnzHg9h4tuuNdrn5ZKCB3Bo6+65ENNFOla
xdh77h8g1ooGDAV/k7I2bQWX0k05UVR4nGninsT8OwKBgQD88EouhaQ+cu1qki/M
vI4Ct+gJzfurq8atfup3be8SZIiNSnllIiZIM0c7/ulPG5mTn6f3xenQlQay7wMB
uQzIJEGjj/2u+nRgKrhYswD4zn4lrDH5ySQGBlNkHCLU1CtZqtGQLwQ4jO3sVDr/
q9RLzwR66XYK8wkOa7GDTbrISwKBgQDF0KrmahY8+Gs0VhRqa7DvyC++fADPxYKc
wdRWOAZRyKNMEPOewsm9ymLt67xj2PgFIe/glrGX/Ouwhm+mirXN3KXFwvtp5KCH
nWIIaJyqTByGYQByFbh3S6Mijwg5PldK7ygkvTptiPCUkmZCDYw+/3hHMXGnFqQM
KnlgTPhwpwKBgQC29mHSkR0jhyKxihlFcccPtFQGc5dusIzAhyO3TDA5D7uu6IYz
X6ZtZ5pJjbTaYk6O+FgZ5HGjTYlQ+Y8lOeRDCebpF4kbf1ObFIvQrXswfr3FJm/o
DVUffofnzGptpSPOcr+wGjJlbZvU7YDX3EVuqMrG1gVrGi4c3k3DewB3TQKBgB0H
3KzoEM9t3b3WjDR6DYODK46XAD99ywdaYuEsY7EI8v4s1rQL/jN+SjqEiCdXJj8K
lfut4e5eTfCgKi6U2M2XfjShwufth6mfbU2ynJtZhC4sejZD/ch0L0LZHunXvlPe
+VM6+iItILGNMriq6FQuheZc2UMeTYEDksCRSzytAoGAb//H+J3Q73ulQKY0ydF9
fwnv+jEOksgeG3wM+fQkqTqWyBYZLOQhc47xGFMBnY46Qcagq1VzRidTQkACZpRP
Ml6HHZjRK98Vq4rtCrAPJ3f8Vth24MkZ9VlXSmo4L9WGI14ao54uWtp9h+EXfumO
iqlTEKVISscuchxZtKQJ4k8=
-----END PRIVATE KEY-----";
    const JWK_N: &str = "w3MVLUya-6e4iL059EqcBK4eIITf3mx3M--U98V_UuVsXWj9kUV87zvbUgu9XSPrBr449YeTZSUhYL-gydvGW2XaofKzUYLY76EG8ySz3JxpteUKMZ3bufXLAPJTC7_3XHuI8f1xKXDRCtz7De4skLiDN5mlET65pCUdATYFUOFGjVP7G0R2amxVlGndrePVqKBvArGOSE0jLvYCUGk9ml2NSTKn6vkgokg58NBWYaXLmIhc_b0R0CPneIR8SITf5Q4OQgCWEGirl9NYaK5l4fUWueyDVug_QH7PbxfBIemkp4D25goH0tvRQBMyDazzprcNTx_LV01HNY4xuSF47Q";
    const KID: &str = "shell-test-rsa";
    const ISSUER: &str = "https://idp.example.test";
    const CLIENT_ID: &str = "gaugewright-shell";
    const TOKEN_ENDPOINT: &str = "https://idp.example.test/token";
    const AUTHZ_ENDPOINT: &str = "https://idp.example.test/authorize";
    const JWKS_URI: &str = "https://idp.example.test/keys";

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn mint_id_token() -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.to_string());
        let claims = json!({
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "alice@example.test",
            "exp": now() + 3600,
            "iat": now(),
            "roles": ["admin"],
        });
        let key = EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM).expect("test signing key");
        encode(&header, &claims, &key).expect("encode id-token")
    }

    /// Mint an otherwise-valid id-token carrying a specific `nonce` claim — the callback
    /// binds the token to its login by requiring this to match the stored pending nonce.
    fn mint_id_token_with_nonce(nonce: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.to_string());
        let claims = json!({
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "alice@example.test",
            "exp": now() + 3600,
            "iat": now(),
            "roles": ["admin"],
            "nonce": nonce,
        });
        let key = EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM).expect("test signing key");
        encode(&header, &claims, &key).expect("encode id-token")
    }

    fn jwks() -> String {
        format!(
            r#"{{"keys":[{{"kty":"RSA","use":"sig","kid":"{KID}","n":"{n}","e":"AQAB"}}]}}"#,
            n = JWK_N.trim()
        )
    }

    fn discovery() -> String {
        json!({
            "issuer": ISSUER,
            "authorization_endpoint": AUTHZ_ENDPOINT,
            "token_endpoint": TOKEN_ENDPOINT,
            "jwks_uri": JWKS_URI,
        })
        .to_string()
    }

    /// A mock OP: canned GETs (discovery, JWKS) and a token endpoint that records the
    /// posted form and returns a minted id-token.
    struct MockOp {
        gets: BTreeMap<String, String>,
        token_response: String,
        seen_form: Mutex<Vec<(String, String)>>,
    }
    impl HttpGet for MockOp {
        fn get(&self, url: &str) -> Result<String, String> {
            self.gets
                .get(url)
                .cloned()
                .ok_or_else(|| format!("404 {url}"))
        }
    }
    impl HttpForm for MockOp {
        fn post_form(&self, _url: &str, fields: &[(&str, &str)]) -> Result<String, String> {
            *self.seen_form.lock().unwrap() = fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            Ok(self.token_response.clone())
        }
    }

    fn mock_op(token_response: String) -> MockOp {
        let mut gets = BTreeMap::new();
        gets.insert(
            format!("{ISSUER}/.well-known/openid-configuration"),
            discovery(),
        );
        gets.insert(JWKS_URI.to_string(), jwks());
        MockOp {
            gets,
            token_response,
            seen_form: Mutex::new(vec![]),
        }
    }

    fn oidc_sso() -> SsoConnectionRecord {
        SsoConnectionRecord {
            protocol: SsoProtocol::Oidc,
            issuer: ISSUER.to_string(),
            audiences: vec![CLIENT_ID.to_string()],
            ..Default::default()
        }
    }

    fn seed_discovery_org(
        store: &mut gaugedesk_store::Store,
        tenant: &str,
        domain: &str,
        protocol: SsoProtocol,
        with_admission: bool,
    ) -> String {
        use crate::org::{
            tenant_scope, OrgRecord, SsoAdmissionMode, SsoAdmissionRecord, SSO_ADMISSION_KIND,
        };

        let scope = tenant_scope(tenant);
        store
            .append_record(
                &scope,
                "org",
                &serde_json::to_string(&OrgRecord {
                    id: tenant.to_owned(),
                    op: RecordOp::Upsert,
                    display_name: format!("{tenant} company"),
                    verified_domains: vec![domain.to_owned()],
                    pending_domains: Vec::new(),
                    default_region: None,
                    kind: Default::default(),
                })
                .unwrap(),
            )
            .unwrap();
        let mut connection = SsoConnectionRecord {
            id: ORG_ID.to_owned(),
            op: RecordOp::Upsert,
            protocol,
            issuer: format!("https://{tenant}.idp.example.test"),
            audiences: vec![format!("{tenant}-client")],
            metadata: format!("https://{tenant}.idp.example.test/metadata"),
            ..Default::default()
        };
        connection.seal_revision();
        store
            .append_record(&scope, "sso", &serde_json::to_string(&connection).unwrap())
            .unwrap();
        if with_admission {
            store
                .append_record(
                    &scope,
                    SSO_ADMISSION_KIND,
                    &serde_json::to_string(&SsoAdmissionRecord {
                        id: ORG_ID.to_owned(),
                        op: RecordOp::Upsert,
                        mode: SsoAdmissionMode::InvitedOnly,
                    })
                    .unwrap(),
                )
                .unwrap();
        }
        scope
    }

    #[test]
    fn work_email_discovery_selects_one_verified_organization_server_side() {
        let mut store = gaugedesk_store::Store::open_in_memory().unwrap();
        let scope = seed_discovery_org(
            &mut store,
            "organization:acme",
            "acme.example",
            SsoProtocol::Oidc,
            true,
        );

        let (connection, context) = enterprise_sso_for_work_email(&store, "  Alice@Acme.Example ")
            .unwrap()
            .expect("one configured verified-domain connection");
        assert_eq!(context.store_scope, scope);
        assert_eq!(context.connection_id, connection.id);
        assert_eq!(context.connection_revision, connection.current_revision());
        assert_eq!(context.protocol, SsoProtocol::Oidc);
    }

    #[test]
    fn work_email_discovery_supports_saml_and_refuses_incomplete_or_ambiguous_matches() {
        let mut incomplete = gaugedesk_store::Store::open_in_memory().unwrap();
        seed_discovery_org(
            &mut incomplete,
            "organization:acme",
            "acme.example",
            SsoProtocol::Oidc,
            false,
        );
        assert!(
            enterprise_sso_for_work_email(&incomplete, "alice@acme.example")
                .unwrap()
                .is_none()
        );
        assert!(enterprise_sso_for_work_email(&incomplete, "not-an-email")
            .unwrap()
            .is_none());

        let mut saml = gaugedesk_store::Store::open_in_memory().unwrap();
        seed_discovery_org(
            &mut saml,
            "organization:acme",
            "acme.example",
            SsoProtocol::Saml,
            true,
        );
        assert!(enterprise_sso_for_work_email(&saml, "alice@acme.example")
            .unwrap()
            .is_some());

        let mut ambiguous = gaugedesk_store::Store::open_in_memory().unwrap();
        for tenant in ["organization:alpha", "organization:beta"] {
            seed_discovery_org(
                &mut ambiguous,
                tenant,
                "shared.example",
                SsoProtocol::Oidc,
                true,
            );
        }
        assert!(
            enterprise_sso_for_work_email(&ambiguous, "person@shared.example")
                .unwrap()
                .is_none()
        );
    }

    /// The Google path, which is what every decision test below is about.
    /// DR-0189 added the provider and the asserted address to the real
    /// signature; neither changes what Google does, so they are pinned here
    /// rather than repeated in twenty call sites.
    fn decide_google(
        account_auth: &crate::account_auth::AccountAuth,
        connection: &SsoConnectionRecord,
        verified_issuer: &str,
        subject: &str,
        attested_email: Option<String>,
    ) -> ConsumerCallbackDecision {
        decide_consumer_callback(
            account_auth,
            ConsumerCallbackFacts {
                provider: CONSUMER_GOOGLE,
                connection,
                accepted_issuer: verified_issuer,
                verified_issuer,
                subject,
                attested_email,
                asserted_email: None,
            },
        )
    }

    // ---- the Microsoft entrance (DR-0189) ------------------------------------

    fn microsoft_connection() -> SsoConnectionRecord {
        consumer_sso(
            CONSUMER_MICROSOFT_CONNECTION_ID,
            CONSUMER_MICROSOFT.authority,
            "ms-client",
        )
    }

    /// A concrete tenant issuer, which is what a verified Microsoft token claims
    /// — never the connection's own `common` authority.
    const MS_TENANT_ISSUER: &str =
        "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0";

    /// What the ceremony pins: the family, from the authority's own metadata.
    const MS_ACCEPTED_ISSUER: &str = "https://login.microsoftonline.com/{tenantid}/v2.0";

    #[test]
    fn a_microsoft_signup_asks_for_an_email_proof_rather_than_refusing() {
        // The whole point of DR-0189 §4. Entra attests nothing, so the Google
        // path's "no verified email" refusal would close the entrance to every
        // person who pressed the button.
        let state = crate::account_auth::AccountAuth::default();
        let connection = microsoft_connection();
        let decision = decide_consumer_callback(
            &state,
            ConsumerCallbackFacts {
                provider: CONSUMER_MICROSOFT,
                connection: &connection,
                accepted_issuer: MS_ACCEPTED_ISSUER,
                verified_issuer: MS_TENANT_ISSUER,
                subject: "ms-subject-new",
                attested_email: None,
                asserted_email: Some("  New.Person@Example.COM ".to_string()),
            },
        );
        assert_eq!(
            decision,
            ConsumerCallbackDecision::SignupNeedsEmailProof {
                asserted_email: Some("new.person@example.com".to_string()),
            },
        );
    }

    #[test]
    fn a_microsoft_signup_does_not_consult_the_account_an_unproved_address_holds() {
        // The asserted address is not evidence, so it must not be allowed to ask
        // a question about other accounts either: answering differently for a
        // registered address would make any Microsoft account an oracle for
        // which addresses have GaugeDesk accounts.
        let mut state = crate::account_auth::AccountAuth::default();
        state.emails.insert(
            "email-1".to_string(),
            crate::account_auth::VerifiedEmailRecord {
                id: "email-1".to_string(),
                op: Default::default(),
                account_id: "account-someone-else".to_string(),
                email: "taken@example.com".to_string(),
                verified_at: 1_000,
                status: crate::account_auth::AuthMethodStatus::Active,
            },
        );
        assert!(state
            .account_holding_active_email("taken@example.com")
            .is_some());
        let connection = microsoft_connection();
        let decision = decide_consumer_callback(
            &state,
            ConsumerCallbackFacts {
                provider: CONSUMER_MICROSOFT,
                connection: &connection,
                accepted_issuer: MS_ACCEPTED_ISSUER,
                verified_issuer: MS_TENANT_ISSUER,
                subject: "ms-subject-new",
                attested_email: None,
                asserted_email: Some("taken@example.com".to_string()),
            },
        );
        assert_eq!(
            decision,
            ConsumerCallbackDecision::SignupNeedsEmailProof {
                asserted_email: Some("taken@example.com".to_string()),
            },
            "an unproved address must get the same answer whether or not it is taken",
        );
    }

    #[test]
    fn a_microsoft_refusal_names_microsoft() {
        // A person who removed their Microsoft sign-in and is told to re-link
        // "Google" has been given an instruction that does not match any button
        // they can see.
        let mut state = crate::account_auth::AccountAuth::default();
        let connection = microsoft_connection();
        let mut revoked = crate::account_auth::ExternalSubjectRecord::new(
            "account-1",
            &connection.id,
            MS_TENANT_ISSUER,
            "ms-subject-removed",
            crate::account_auth::ExternalSubjectKind::ConsumerOidc,
            1_000,
        )
        .expect("record");
        revoked.status = crate::account_auth::AuthMethodStatus::Revoked;
        state.external_subjects.insert(revoked.id.clone(), revoked);

        let decision = decide_consumer_callback(
            &state,
            ConsumerCallbackFacts {
                provider: CONSUMER_MICROSOFT,
                connection: &connection,
                accepted_issuer: MS_ACCEPTED_ISSUER,
                verified_issuer: MS_TENANT_ISSUER,
                subject: "ms-subject-removed",
                attested_email: None,
                asserted_email: Some("person@example.com".to_string()),
            },
        );
        match decision {
            ConsumerCallbackDecision::Refuse(status, message) => {
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert!(message.contains("Microsoft"), "{message}");
                assert!(!message.contains("Google"), "{message}");
            }
            other => panic!("expected a refusal naming Microsoft, got {other:?}"),
        }
    }

    #[test]
    fn a_tenant_issuer_resolves_against_the_common_connection() {
        // The link is keyed by the concrete tenant issuer, not by the `common`
        // authority the connection carries, so this is the assertion that the
        // two are allowed to differ.
        let mut state = crate::account_auth::AccountAuth::default();
        let connection = microsoft_connection();
        let link = crate::account_auth::ExternalSubjectRecord::new(
            "account-7",
            &connection.id,
            MS_TENANT_ISSUER,
            "ms-subject-known",
            crate::account_auth::ExternalSubjectKind::ConsumerOidc,
            1_000,
        )
        .expect("record");
        state.external_subjects.insert(link.id.clone(), link);

        assert_eq!(
            decide_consumer_callback(
                &state,
                ConsumerCallbackFacts {
                    provider: CONSUMER_MICROSOFT,
                    connection: &connection,
                    accepted_issuer: MS_ACCEPTED_ISSUER,
                    verified_issuer: MS_TENANT_ISSUER,
                    subject: "ms-subject-known",
                    attested_email: None,
                    asserted_email: None,
                },
            ),
            ConsumerCallbackDecision::Login(LoginResolution {
                account_id: "account-7".to_string(),
                session_method: "consumer-oidc:consumer-microsoft".to_string(),
            }),
        );
    }

    #[test]
    fn a_session_labels_the_provider_that_minted_it() {
        assert_eq!(
            session_label_for_method("consumer-oidc:consumer-microsoft"),
            ("microsoft", "Microsoft")
        );
        assert_eq!(
            session_label_for_method("consumer-oidc:consumer-google"),
            ("google", "Google")
        );
        // A connection this build does not know must not be labelled as one it
        // does; it says what it can honestly say.
        assert_eq!(
            session_label_for_method("consumer-oidc:consumer-retired"),
            ("oidc", "Consumer sign-in")
        );
    }

    #[test]
    fn a_pinned_tenant_template_is_still_accepted_by_its_connection() {
        // What the callback re-checks. `connection.issuer` is the `common`
        // authority and the pinned issuer is the template, so a string equality
        // here — which is what the code did before DR-0189 — would refuse every
        // Microsoft callback.
        let connection = microsoft_connection();
        let template = "https://login.microsoftonline.com/{tenantid}/v2.0";
        assert!(connection_still_accepts(
            &connection,
            template,
            &["ms-client".to_string()]
        ));
        assert!(!connection_still_accepts(
            &connection,
            "https://login.microsoftonline.com.evil.test/{tenantid}/v2.0",
            &["ms-client".to_string()]
        ));
        assert!(
            !connection_still_accepts(&connection, template, &["another-client".to_string()]),
            "a changed client id must still refuse"
        );
    }

    fn pending_auth() -> PendingAuth {
        PendingAuth {
            verifier: "v".into(),
            nonce: "n".into(),
            token_endpoint: TOKEN_ENDPOINT.into(),
            jwks_uri: JWKS_URI.into(),
            issuer: ISSUER.into(),
            audiences: vec![CLIENT_ID.into()],
            redirect_uri: "http://localhost/auth/callback".into(),
            mapping: ClaimMapping::default(),
            client_secret: None,
            native_return: None,
            native_handoff_challenge: None,
            login_context: None,
            consumer_connection_id: Some(CONSUMER_GOOGLE_CONNECTION_ID.to_string()),
            purpose: PendingAuthPurpose::Login,
        }
    }

    /// A login the callback never comes for must not be held forever.
    ///
    /// `take` is the only consumer, and not every login leg reaches one — an
    /// abandoned consent screen, or the account-session canary reading the
    /// redirect without following it. Before the sweep, each of those kept a
    /// PKCE verifier and the client secret for the life of the process.
    #[test]
    fn an_abandoned_login_is_swept_by_the_next_one() {
        let mut store = PendingAuthStore::new();
        let start = Instant::now();
        store.begin("abandoned", pending_auth(), start);

        // Still inside its own window: reading a consent screen takes time.
        let soon = start + Duration::from_secs(60);
        store.begin("in-flight", pending_auth(), soon);
        assert_eq!(store.len(), 2);
        assert!(
            store.take("abandoned", soon).is_some(),
            "a live login is still redeemable"
        );

        // Past `in-flight`'s window — measured from when it began, not from the
        // first login.
        let later = soon + PENDING_AUTH_TTL + Duration::from_secs(1);
        store.begin("later", pending_auth(), later);
        assert_eq!(
            store.len(),
            1,
            "the swept login is gone, not merely unredeemable"
        );
        assert!(store.take("in-flight", later).is_none());
        assert!(store.take("later", later).is_some());
    }

    /// An expired `state` is refused even if nothing has swept it yet, so the
    /// guarantee does not depend on another login arriving.
    #[test]
    fn an_expired_state_is_refused_before_any_sweep() {
        let mut store = PendingAuthStore::new();
        let start = Instant::now();
        store.begin("stale", pending_auth(), start);
        assert!(store
            .take("stale", start + PENDING_AUTH_TTL + Duration::from_secs(1))
            .is_none());
    }

    /// `/auth/login` is unauthenticated, so the TTL alone is not a bound.
    #[test]
    fn pending_logins_are_capped_even_when_none_have_expired() {
        let mut store = PendingAuthStore::new();
        let start = Instant::now();
        for index in 0..(PENDING_AUTH_MAX + 40) {
            store.begin(
                format!("state-{index:04}"),
                pending_auth(),
                start + Duration::from_millis(index as u64),
            );
        }
        // The sweep runs before each insert, so this is the size the store
        // settles at rather than one it stays strictly under.
        assert!(
            store.len() <= PENDING_AUTH_MAX,
            "the ceiling holds: {}",
            store.len()
        );
        let newest = format!("state-{:04}", PENDING_AUTH_MAX + 39);
        assert!(
            store
                .take(&newest, start + Duration::from_secs(1))
                .is_some(),
            "the cap drops the oldest, so the newest login still works",
        );
    }

    #[test]
    fn pending_store_take_is_single_use() {
        let now = Instant::now();
        let mut store = PendingAuthStore::new();
        store.begin("state-1", pending_auth(), now);
        assert_eq!(store.len(), 1);
        assert!(store.take("state-1", now).is_some(), "first take redeems");
        assert!(
            store.take("state-1", now).is_none(),
            "second take is empty (single-use)"
        );
        assert!(store.is_empty());
    }

    #[test]
    fn a_login_leg_that_never_reaches_its_callback_does_not_accumulate() {
        // Only `/auth/callback` consumes an entry, and the deployed
        // account-session canary reads the login redirect without following
        // it. Without expiry every such probe would be held for the process
        // lifetime.
        let now = Instant::now();
        let mut store = PendingAuthStore::new();
        store.begin("abandoned", pending_auth(), now);

        let later = now + PENDING_AUTH_TTL + Duration::from_secs(1);
        assert!(
            store.take("abandoned", later).is_none(),
            "an expired state authorizes no callback"
        );

        store.begin("abandoned", pending_auth(), now);
        store.begin("current", pending_auth(), later);
        assert_eq!(store.len(), 1, "the sweep on begin drops what expired");
        assert!(store.take("current", later).is_some());
    }

    #[test]
    fn native_login_return_is_exactly_allowlisted() {
        let challenge =
            crate::identity_oidc::s256_challenge("0123456789012345678901234567890123456789012");
        assert_eq!(native_return_uri(None, None, false), Ok(None));
        assert_eq!(
            native_return_uri(Some("gaugewright://auth/callback"), Some(&challenge), false),
            Ok(Some("gaugewright://auth/callback".to_string()))
        );
        assert!(native_return_uri(Some("gaugewright://auth/callback"), None, false).is_err());
        assert!(native_return_uri(
            Some("https://attacker.example/callback"),
            Some(&challenge),
            false
        )
        .is_err());
        assert!(native_return_uri(
            Some("gaugewright://auth/callback/extra"),
            Some(&challenge),
            false
        )
        .is_err());
    }

    #[test]
    fn dev_web_return_admits_loopback_only_behind_the_gate() {
        let challenge =
            crate::identity_oidc::s256_challenge("0123456789012345678901234567890123456789012");
        let loopback = "http://localhost:5176/auth/native-return";
        // Gate off (the production posture): a loopback return is refused outright.
        assert!(native_return_uri(Some(loopback), Some(&challenge), false).is_err());
        // Gate on: admitted, but only with the same valid PKCE challenge the
        // native scheme requires.
        assert_eq!(
            native_return_uri(Some(loopback), Some(&challenge), true),
            Ok(Some(loopback.to_string()))
        );
        assert!(native_return_uri(Some(loopback), None, true).is_err());
        assert!(native_return_uri(Some(loopback), Some("short"), true).is_err());
        // The native scheme is unchanged by the gate.
        assert_eq!(
            native_return_uri(Some("gaugewright://auth/callback"), Some(&challenge), true),
            Ok(Some("gaugewright://auth/callback".to_string()))
        );
        // Non-loopback web returns stay refused even with the gate on.
        assert!(native_return_uri(
            Some("https://attacker.example/callback"),
            Some(&challenge),
            true
        )
        .is_err());
    }

    #[test]
    fn loopback_web_return_grammar_is_strict() {
        for admitted in [
            "http://localhost",
            "http://localhost:5176",
            "http://localhost:5176/",
            "http://localhost:5176/auth/native-return",
            "http://127.0.0.1:7878/return_here-1.x~ok",
            // The fabric's named loopback origins (ADR 0140 amendment).
            "https://desk.gw.localhost:7443/",
            "https://desk.gw.localhost:7463",
            "https://a.localhost/return",
        ] {
            assert!(loopback_web_return(admitted), "should admit {admitted}");
        }
        for refused in [
            "https://localhost:5176/",        // bare https loopback is not a dev shape
            "http://localhost.evil.example/", // host must end at the loopback name
            "http://localhost:5176evil/",     // port must be digits to the path
            "http://localhost:/",             // empty port
            "http://127.0.0.2:5176/",         // only the canonical loopback literal
            "http://evil.example/",           // not loopback at all
            "http://localhost:5176/?next=x",  // no query
            "http://localhost:5176/#frag",    // no fragment
            "http://user@localhost:5176/",    // no userinfo
            "http://localhost:5176/sp ace",   // conservative charset only
            "gaugewright://auth/callback",    // the native scheme is not a web return
            // Named-origin form: `.localhost` must be the final label of a real
            // named host, http named hosts stay refused, and the tail grammar
            // still holds.
            "https://desk.gw.localhost.evil.example/", // suffix must end the host
            "https://desk.gw.localhostx:7443/",        // exact final label
            "http://desk.gw.localhost:7443/",          // named origins are https-only
            "https://gw..localhost/",                  // no empty labels
            "https://-a.localhost/",                   // no hyphen-edged labels
            "https://DESK.gw.localhost:7443/",         // lowercase hosts only
            "https://desk.gw.localhost@evil.example/", // no userinfo
            "https://desk.gw.localhost:7443/?next=x",  // no query
        ] {
            assert!(!loopback_web_return(refused), "should refuse {refused}");
        }
    }

    #[test]
    fn native_handoff_is_pkce_bound_single_use_and_expires() {
        let verifier = "0123456789012345678901234567890123456789012";
        let challenge = crate::identity_oidc::s256_challenge(verifier);
        let now = Instant::now();
        let mut store = NativeHandoffStore::default();
        let issue = |refresh_token: Option<&str>, challenge: String| NativeHandoffIssue {
            account_id: "account-7".to_string(),
            session_method: "oidc".to_string(),
            label: "alice@example.test".to_string(),
            provider_expires_at_ms: 4_102_444_800_000,
            refresh_token: refresh_token.map(str::to_string),
            challenge,
        };
        let code = store.issue(issue(Some("rt-native"), challenge.clone()), now);
        assert!(store.redeem(&code, "wrong-verifier", now).is_none());
        assert!(
            store.redeem(&code, verifier, now).is_none(),
            "a failed proof consumes the code"
        );

        let code = store.issue(issue(Some("rt-native"), challenge.clone()), now);
        let redeemed = store
            .redeem(&code, verifier, now)
            .expect("redeemed handoff");
        // The handoff carries account/session metadata and the server-held
        // refresh grant, never the external token the native client used to get.
        assert_eq!(redeemed.account_id, "account-7");
        assert_eq!(redeemed.session_method, "oidc");
        assert_eq!(redeemed.label, "alice@example.test");
        assert_eq!(redeemed.provider_expires_at_ms, 4_102_444_800_000);
        assert_eq!(redeemed.refresh_token.as_deref(), Some("rt-native"));
        assert!(
            store.redeem(&code, verifier, now).is_none(),
            "a redeemed code is single-use"
        );

        let code = store.issue(issue(None, challenge), now);
        assert!(store
            .redeem(&code, verifier, now + Duration::from_secs(301))
            .is_none());
    }

    #[test]
    fn unknown_state_finds_nothing() {
        let mut store = PendingAuthStore::new();
        // The CSRF guard: a forged `state` the server never minted finds no verifier.
        assert!(store.take("forged", Instant::now()).is_none());
    }

    #[test]
    fn claim_mapping_prefers_the_record_and_defaults_the_subject() {
        // The record is the home (ID-3): its claim names win, and the subject defaults
        // to `sub` when unset — independent of any GAUGEDESK_OIDC_*_CLAIM env fallback.
        let mut sso = oidc_sso();
        sso.claim_mapping = crate::org::SsoClaimMapping {
            roles_claim: Some("groups".into()),
            region_claim: Some("locale".into()),
            ..Default::default()
        };
        let m = claim_mapping_for(&sso);
        assert_eq!(m.roles_claim.as_deref(), Some("groups"));
        assert_eq!(m.region_claim.as_deref(), Some("locale"));
        assert_eq!(m.subject_claim, "sub");
    }

    #[tokio::test]
    async fn corporate_protocols_share_one_opaque_account_session_delivery() {
        let shared = Arc::new(Mutex::new(Workbench::new(
            gaugedesk_store::Store::open_in_memory().unwrap(),
        )));
        let auth = AuthShellState::new();
        let response = auth.deliver_enterprise_login(
            &shared,
            EnterpriseLoginDelivery {
                login_context: PendingEnterpriseLogin {
                    store_scope: "org::organization:acme".into(),
                    connection_id: "org".into(),
                    connection_revision: "revision".into(),
                    protocol: SsoProtocol::Saml,
                },
                resolution: LoginResolution {
                    account_id: "account:alice".into(),
                    session_method: "enterprise-saml:org::organization:acme:org".into(),
                },
                display_label: "alice@acme.example".into(),
                provider_expires_at_ms: crate::account::session_now_ms()
                    + crate::account::SESSION_ABSOLUTE_LIFETIME_MS,
                refresh_token: None,
                native_return: None,
                native_handoff_challenge: None,
            },
        );
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let bearer = payload["id_token"].as_str().unwrap();
        assert!(
            !bearer.contains('.'),
            "the SAML assertion is not the session"
        );
        assert_eq!(
            shared
                .lock_unpoisoned()
                .account_sessions()
                .resolve_session(bearer),
            Some((
                "account:alice".into(),
                "enterprise-saml:org::organization:acme:org".into()
            ))
        );
    }

    #[test]
    fn web_account_login_provisions_the_persons_personal_tenant() {
        use crate::tenancy::{personal_tenant_id, Tenancy};
        let store = gaugedesk_store::Store::open_in_memory().unwrap();
        let mut wb = Workbench::new(store);
        let person = "google-sub-123";

        // Off (enterprise/desktop): a login provisions no personal tenant.
        assert!(provision_web_account(&mut wb, person, false).is_none());
        assert!(
            Tenancy::rebuild_in(wb.store_ref(), &crate::account::account_scope(person))
                .unwrap()
                .tenants
                .is_empty()
        );

        // On (hosted web account): the login mints the person's personal tenant-of-one.
        let tid =
            provision_web_account(&mut wb, person, true).expect("provisions in web-account mode");
        assert_eq!(tid, personal_tenant_id(person));
        let tenancy =
            Tenancy::rebuild_in(wb.store_ref(), &crate::account::account_scope(person)).unwrap();
        let personal = tenancy.personal().expect("a personal tenant is indexed");
        assert_eq!(personal.id, tid);
        assert_eq!(personal.role, "owner");
        assert!(personal.personal);

        // Idempotent: a second login does not duplicate it.
        assert_eq!(
            provision_web_account(&mut wb, person, true).as_deref(),
            Some(tid.as_str())
        );
        assert_eq!(
            Tenancy::rebuild_in(wb.store_ref(), &crate::account::account_scope(person))
                .unwrap()
                .tenants
                .len(),
            1
        );
    }

    #[test]
    fn session_cookie_carries_the_token_and_shares_the_domain() {
        // Production: parent-domain, Secure, HttpOnly, SameSite=Lax — one sign-in, whole site.
        let c = session_cookie_value("id-tok-123", Some(".gaugewright.com"), true);
        assert!(c.starts_with("gw_session=id-tok-123;"));
        assert!(c.contains("Domain=.gaugewright.com"));
        assert!(c.contains("HttpOnly") && c.contains("SameSite=Lax") && c.contains("Secure"));
        // Loopback dev: no Domain (can't scope to localhost), Secure droppable.
        let dev = session_cookie_value("t", None, false);
        assert!(!dev.contains("Domain="));
        assert!(!dev.contains("Secure"));
        assert!(dev.contains("HttpOnly"));
    }

    #[test]
    fn expired_session_cookie_clears_the_same_shared_cookie() {
        let c = expired_session_cookie_value(Some(".gaugewright.com"), true);
        assert!(c.starts_with("gw_session=;"));
        assert!(c.contains("Domain=.gaugewright.com"));
        assert!(c.contains("Path=/") && c.contains("HttpOnly") && c.contains("Secure"));
        assert!(c.contains("Max-Age=0"));
        assert!(c.contains("Expires=Thu, 01 Jan 1970 00:00:00 GMT"));
    }

    #[test]
    fn a_signed_in_browser_skips_the_login_ceremony_but_native_never_does() {
        // The one skippable case: hosted web flow, no handoff, authenticated actor.
        assert!(login_ceremony_skippable(true, false, "google-sub-123"));
        // An absent/expired/forged cookie authenticates to nobody — full ceremony.
        assert!(!login_ceremony_skippable(true, false, "anonymous"));
        // A native/dev handoff needs its fresh single-use code even when signed in.
        assert!(!login_ceremony_skippable(true, true, "google-sub-123"));
        // Enterprise/desktop deployments are untouched.
        assert!(!login_ceremony_skippable(false, false, "google-sub-123"));
    }

    #[test]
    fn every_non_native_provider_callback_requires_an_account_session() {
        assert!(requires_account_session(false));
        assert!(!requires_account_session(true));
    }

    #[test]
    fn consumer_link_requires_the_exact_live_independent_session() {
        let mut state = crate::account_auth::AccountAuth::default();
        state.roots.insert(
            "account:alice".into(),
            crate::account_auth::CustodiedAccountRootRecord::new(
                "account:alice",
                "sealed-root",
                1_000,
            )
            .unwrap(),
        );
        let passkey = crate::account_auth::AccountSessionRecord::new(
            "session-passkey",
            "account:alice",
            "passkey",
            1_000,
            60,
        )
        .unwrap();
        state.sessions.insert(passkey.id.clone(), passkey);
        assert!(durable_independent_session(
            &state,
            "session-passkey",
            "account:alice",
            2_000,
        ));
        assert!(!durable_independent_session(
            &state,
            "session-passkey",
            "account:bob",
            2_000,
        ));
        assert!(!durable_independent_session(
            &state,
            "session-passkey",
            "account:alice",
            61_001,
        ));

        let provider = crate::account_auth::AccountSessionRecord::new(
            "session-provider",
            "account:alice",
            "consumer-oidc:consumer-google",
            1_000,
            60,
        )
        .unwrap();
        state.sessions.insert(provider.id.clone(), provider);
        assert!(!durable_independent_session(
            &state,
            "session-provider",
            "account:alice",
            2_000,
        ));
    }

    #[test]
    fn session_hint_cookie_is_js_readable_and_carries_no_credential() {
        let c = session_hint_cookie_value(Some(".gaugewright.com"), true);
        assert!(c.starts_with("gw_session_hint=1;"));
        assert!(
            !c.contains("HttpOnly"),
            "the public site's nav script must be able to read it"
        );
        assert!(c.contains("Domain=.gaugewright.com"));
        assert!(c.contains("Path=/") && c.contains("SameSite=Lax") && c.contains("Secure"));
        // Loopback dev mirrors the session cookie: no Domain, Secure droppable.
        let dev = session_hint_cookie_value(None, false);
        assert!(!dev.contains("Domain=") && !dev.contains("Secure"));
    }

    #[test]
    fn expired_session_hint_clears_with_the_issued_attributes() {
        let c = expired_session_hint_cookie_value(Some(".gaugewright.com"), true);
        assert!(c.starts_with("gw_session_hint=;"));
        assert!(c.contains("Domain=.gaugewright.com"));
        assert!(c.contains("Path=/") && c.contains("Secure"));
        assert!(c.contains("Max-Age=0"));
        assert!(c.contains("Expires=Thu, 01 Jan 1970 00:00:00 GMT"));
    }

    #[test]
    fn session_cookies_are_issued_as_a_pair() {
        let mut resp = StatusCode::NO_CONTENT.into_response();
        append_session_cookies(&mut resp, "id-tok-123");
        let cookies: Vec<String> = resp
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(
            cookies.len(),
            2,
            "credential + hint, never one without the other"
        );
        assert!(cookies[0].starts_with("gw_session=id-tok-123;"));
        assert!(cookies[0].contains("HttpOnly"));
        assert!(cookies[1].starts_with("gw_session_hint=1;"));
        assert!(!cookies[1].contains("HttpOnly"));
    }

    #[test]
    fn authenticated_login_shortcut_backfills_only_the_session_hint() {
        let mut resp = StatusCode::TEMPORARY_REDIRECT.into_response();
        append_session_hint_cookie(&mut resp);
        let cookies: Vec<String> = resp
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect();
        assert_eq!(cookies.len(), 1);
        assert!(cookies[0].starts_with("gw_session_hint=1;"));
        assert!(!cookies[0].contains("gw_session="));
        assert!(!cookies[0].contains("HttpOnly"));
    }

    #[test]
    fn google_sso_pins_issuer_and_client_id() {
        let sso = google_sso(
            "https://accounts.google.com",
            "client-xyz.apps.googleusercontent.com",
        );
        assert_eq!(sso.protocol, SsoProtocol::Oidc);
        assert_eq!(sso.id, CONSUMER_GOOGLE_CONNECTION_ID);
        assert_eq!(sso.issuer, "https://accounts.google.com");
        assert_eq!(sso.audiences, vec!["client-xyz.apps.googleusercontent.com"]);
        assert!(
            !sso.enforce_sso,
            "hosted account is opt-in login, not locked-down"
        );
    }

    #[test]
    fn a_multi_tenant_authority_pins_the_template_it_declares() {
        // The end of the DR-0189 §2 chain, through the real login leg: discovery
        // runs against the `common` authority, that document declares the tenant
        // template, and the template is what the callback will verify `iss`
        // against. Before this, `pending.issuer` was the configured string and a
        // Microsoft token could not have matched it.
        let authority = "https://login.microsoftonline.com/common/v2.0";
        let template = "https://login.microsoftonline.com/{tenantid}/v2.0";
        let mut gets = BTreeMap::new();
        gets.insert(
            format!("{authority}/.well-known/openid-configuration"),
            json!({
                "issuer": template,
                "authorization_endpoint": AUTHZ_ENDPOINT,
                "token_endpoint": TOKEN_ENDPOINT,
                "jwks_uri": JWKS_URI,
            })
            .to_string(),
        );
        let op = MockOp {
            gets,
            token_response: String::new(),
            seen_form: Mutex::new(Vec::new()),
        };
        let connection = consumer_sso(CONSUMER_MICROSOFT_CONNECTION_ID, authority, "ms-client");
        let (_url, _state, pending) = start_login(
            &connection,
            "http://localhost:1421/auth/callback",
            "openid profile email",
            ClaimMapping::default(),
            &op,
        )
        .expect("login starts");
        assert_eq!(
            pending.issuer, template,
            "the ceremony pins the declared family, not the authority it discovered through"
        );
        // And the connection still admits it, which is what the callback rechecks.
        assert!(connection_still_accepts(
            &connection,
            &pending.issuer,
            &pending.audiences
        ));
    }

    #[test]
    fn an_authority_declaring_a_foreign_issuer_refuses_the_login() {
        // The guard on the same chain: a document that names an issuer nobody
        // configured must stop the ceremony, not silently become the pin.
        let mut gets = BTreeMap::new();
        gets.insert(
            format!("{ISSUER}/.well-known/openid-configuration"),
            json!({
                "issuer": "https://evil.test",
                "authorization_endpoint": AUTHZ_ENDPOINT,
                "token_endpoint": TOKEN_ENDPOINT,
                "jwks_uri": JWKS_URI,
            })
            .to_string(),
        );
        let op = MockOp {
            gets,
            token_response: String::new(),
            seen_form: Mutex::new(Vec::new()),
        };
        let error = start_login(
            &oidc_sso(),
            "http://localhost:1421/auth/callback",
            "openid",
            ClaimMapping::default(),
            &op,
        )
        .expect_err("a foreign declared issuer refuses");
        assert!(
            matches!(error, LoginError::Discovery(ref message) if message.contains("evil.test")),
            "{error:?}"
        );
    }

    // ---- the refresh-token mechanism is per provider --------------------------

    fn query_of(url: &str) -> std::collections::BTreeMap<String, String> {
        url.split_once('?')
            .map(|(_, q)| q)
            .unwrap_or_default()
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(k, v)| {
                let v = v.replace('+', " ");
                let decoded = percent_decode(&v);
                (k.to_string(), decoded)
            })
            .collect()
    }

    fn percent_decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn microsoft_asks_for_offline_access_and_never_forces_consent() {
        // The whole bug, as it shipped: Google's parameters on a Microsoft
        // request. Entra issued no refresh token, and `prompt=consent` demanded
        // user consent on every sign-in.
        let grant = CONSUMER_MICROSOFT.offline_grant;
        assert_eq!(grant, OfflineGrant::OfflineAccessScope);
        assert_eq!(
            grant.scope("openid profile email"),
            "openid profile email offline_access"
        );
        // Even where the deployment asks for the consent screen, Microsoft does
        // not get it — that setting is Google's.
        assert_eq!(grant.authorize_params(true), "");
        assert_eq!(grant.authorize_params(false), "");
    }

    #[test]
    fn google_keeps_access_type_offline_and_its_consent_prompt() {
        let grant = CONSUMER_GOOGLE.offline_grant;
        assert_eq!(grant, OfflineGrant::AccessTypeOffline);
        assert_eq!(grant.scope("openid profile email"), "openid profile email");
        assert_eq!(
            grant.authorize_params(true),
            "&access_type=offline&prompt=consent"
        );
        assert_eq!(grant.authorize_params(false), "&access_type=offline");
    }

    #[test]
    fn offline_access_is_not_requested_twice() {
        // A deployment that already put it in GAUGEDESK_OIDC_SCOPE must not end
        // up asking for it twice.
        assert_eq!(
            OfflineGrant::OfflineAccessScope.scope("openid offline_access profile"),
            "openid offline_access profile"
        );
    }

    #[test]
    fn a_microsoft_authorize_url_carries_offline_access_and_no_google_parameters() {
        // Through the real login leg, not just the helper: this is the URL a
        // person's browser is sent to.
        let op = mock_op(String::new());
        let (url, _state, _pending) = start_login_with(
            &oidc_sso(),
            "http://localhost:1421/auth/callback",
            "openid profile email",
            ClaimMapping::default(),
            OfflineGrant::OfflineAccessScope,
            &op,
        )
        .expect("login starts");
        let query = query_of(&url);
        let scope = query.get("scope").expect("a scope is requested");
        assert!(
            scope.split_whitespace().any(|s| s == "offline_access"),
            "Microsoft must be asked for offline_access, got scope {scope:?}"
        );
        assert!(!query.contains_key("access_type"), "{url}");
        assert!(!query.contains_key("prompt"), "{url}");
    }

    #[test]
    fn start_login_without_a_grant_is_unchanged_for_every_other_caller() {
        // Organization connections and the tests that predate the provider table
        // go through `start_login`, which must keep the old request exactly.
        let op = mock_op(String::new());
        let (url, _state, _pending) = start_login(
            &oidc_sso(),
            "http://localhost:1421/auth/callback",
            "openid profile email",
            ClaimMapping::default(),
            &op,
        )
        .expect("login starts");
        let query = query_of(&url);
        assert_eq!(
            query.get("access_type").map(String::as_str),
            Some("offline")
        );
        assert_eq!(
            query.get("scope").map(String::as_str),
            Some("openid profile email")
        );
    }

    #[test]
    fn start_login_builds_a_pkce_authorize_url() {
        let op = mock_op(String::new());
        let (url, state, pending) = start_login(
            &oidc_sso(),
            "http://localhost:1421/auth/callback",
            "openid profile email",
            ClaimMapping {
                roles_claim: Some("roles".into()),
                ..ClaimMapping::default()
            },
            &op,
        )
        .expect("login starts");

        assert!(
            url.starts_with(AUTHZ_ENDPOINT),
            "redirects to the discovered authorize endpoint"
        );
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(
            url.contains(&format!("state={state}")),
            "the CSRF state is on the URL"
        );
        assert!(
            url.contains(&format!("nonce={}", pending.nonce)),
            "the OIDC nonce is on the URL and stashed for the callback check"
        );
        assert!(url.contains("scope=openid%20profile%20email"));
        // The verifier is kept server-side, never on the authorize URL.
        assert!(!url.contains(pending.verifier.expose()));
        assert_eq!(pending.token_endpoint, TOKEN_ENDPOINT);
        assert_eq!(pending.jwks_uri, JWKS_URI);
    }

    #[test]
    fn start_login_refuses_a_non_oidc_or_unconfigured_connection() {
        let op = mock_op(String::new());
        // SAML connection → not this shell's job.
        let mut saml = oidc_sso();
        saml.protocol = SsoProtocol::Saml;
        assert!(matches!(
            start_login(&saml, "http://x/cb", "openid", ClaimMapping::default(), &op),
            Err(LoginError::NotConfigured)
        ));
        // OIDC but no issuer.
        let mut no_issuer = oidc_sso();
        no_issuer.issuer = String::new();
        assert!(matches!(
            start_login(
                &no_issuer,
                "http://x/cb",
                "openid",
                ClaimMapping::default(),
                &op
            ),
            Err(LoginError::NoIssuer)
        ));
        // OIDC, issuer, but no client id.
        let mut no_client = oidc_sso();
        no_client.audiences.clear();
        assert!(matches!(
            start_login(
                &no_client,
                "http://x/cb",
                "openid",
                ClaimMapping::default(),
                &op
            ),
            Err(LoginError::NotConfigured)
        ));
    }

    #[test]
    fn finish_callback_exchanges_then_verifies_the_id_token() {
        // The pending state a prior login leg would have stashed — including the nonce it
        // minted, which the returned id-token must echo.
        let login_op = mock_op(String::new());
        let (_url, _state, pending) = start_login(
            &oidc_sso(),
            "http://localhost:1421/auth/callback",
            "openid",
            ClaimMapping {
                roles_claim: Some("roles".into()),
                ..ClaimMapping::default()
            },
            &login_op,
        )
        .unwrap();

        let id_token = mint_id_token_with_nonce(&pending.nonce);
        let op = mock_op(json!({ "id_token": id_token, "token_type": "Bearer" }).to_string());

        let (authority, returned, _refresh) =
            finish_callback(&pending, "auth-code-xyz", &op).expect("callback verifies");
        assert_eq!(authority, AuthorityId::new("alice@example.test"));
        assert_eq!(
            returned, id_token,
            "the verified id-token is the bearer handed back"
        );

        // The PKCE verifier was presented on the exchange (so an intercepted code is useless).
        let seen = op.seen_form.lock().unwrap();
        assert!(seen
            .iter()
            .any(|(k, v)| k == "code_verifier" && v.as_str() == pending.verifier.expose()));
        assert!(seen
            .iter()
            .any(|(k, v)| k == "grant_type" && v == "authorization_code"));
        assert!(seen
            .iter()
            .any(|(k, v)| k == "code" && v == "auth-code-xyz"));
    }

    #[test]
    fn verified_callback_retains_mapped_attributes_for_a_non_login_test() {
        let login_op = mock_op(String::new());
        let (_url, _state, pending) = start_login(
            &oidc_sso(),
            "http://localhost:1421/auth/callback",
            "openid",
            ClaimMapping {
                roles_claim: Some("roles".into()),
                ..ClaimMapping::default()
            },
            &login_op,
        )
        .unwrap();
        let id_token = mint_id_token_with_nonce(&pending.nonce);
        let op = mock_op(json!({ "id_token": id_token, "token_type": "Bearer" }).to_string());

        let verified = finish_callback_verified(&pending, "test-code", &op).unwrap();
        assert_eq!(verified.authority.as_str(), "alice@example.test");
        assert_eq!(
            verified
                .attributes
                .roles
                .iter()
                .map(|role| role.as_str())
                .collect::<Vec<_>>(),
            vec!["admin"]
        );
    }

    #[test]
    fn callback_accepts_matching_nonce() {
        // Happy path: the id-token's nonce equals the login's stored nonce → authenticates.
        let login_op = mock_op(String::new());
        let (_u, _s, pending) = start_login(
            &oidc_sso(),
            "http://x/cb",
            "openid",
            ClaimMapping::default(),
            &login_op,
        )
        .unwrap();
        let id_token = mint_id_token_with_nonce(&pending.nonce);
        let op = mock_op(json!({ "id_token": id_token }).to_string());
        let (authority, _returned, _refresh) =
            finish_callback(&pending, "code", &op).expect("matching nonce authenticates");
        assert_eq!(authority, AuthorityId::new("alice@example.test"));
    }

    #[test]
    fn callback_rejects_mismatched_nonce() {
        // A token whose nonce differs from the one bound to this login is rejected
        // (replay/injection defense, `INV-20`), even though it is otherwise fully valid.
        let login_op = mock_op(String::new());
        let (_u, _s, pending) = start_login(
            &oidc_sso(),
            "http://x/cb",
            "openid",
            ClaimMapping::default(),
            &login_op,
        )
        .unwrap();
        let wrong = format!("not-{}", pending.nonce);
        let id_token = mint_id_token_with_nonce(&wrong);
        let op = mock_op(json!({ "id_token": id_token }).to_string());
        assert!(matches!(
            finish_callback(&pending, "code", &op),
            Err(CallbackError::NotVerified)
        ));
    }

    #[test]
    fn finish_callback_rejects_a_token_for_the_wrong_audience() {
        // The token endpoint returns a token minted for a *different* client — the
        // shell's verification (aud check) must reject it (fail-closed).
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.to_string());
        let claims = json!({
            "iss": ISSUER, "aud": "some-other-client", "sub": "mallory",
            "exp": now() + 3600, "iat": now(),
        });
        let key = EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM).unwrap();
        let bad = encode(&header, &claims, &key).unwrap();
        let op = mock_op(json!({ "id_token": bad }).to_string());
        let (_u, _s, pending) = start_login(
            &oidc_sso(),
            "http://x/cb",
            "openid",
            ClaimMapping::default(),
            &op,
        )
        .unwrap();
        assert!(matches!(
            finish_callback(&pending, "code", &op),
            Err(CallbackError::NotVerified)
        ));
    }

    #[test]
    fn build_oidc_idp_is_none_for_local_or_non_oidc() {
        // These return before any network — no connection / SAML / no issuer ⇒ single-
        // user local (None). (A configured-OIDC build touches the network, so the
        // construction + self-heal behaviour is exercised via RefreshingOidcProvider.)
        assert!(build_oidc_idp(None).is_none());
        let mut saml = oidc_sso();
        saml.protocol = SsoProtocol::Saml;
        assert!(build_oidc_idp(Some(&saml)).is_none());
        let mut no_issuer = oidc_sso();
        no_issuer.issuer = String::new();
        assert!(build_oidc_idp(Some(&no_issuer)).is_none());
    }

    /// An OP whose reachability can be toggled, counting GETs — to drive the cold →
    /// recover → heal path and the refresh cooldown deterministically.
    struct ToggleOp {
        online: Arc<AtomicBool>,
        get_calls: Arc<AtomicUsize>,
    }
    impl HttpGet for ToggleOp {
        fn get(&self, url: &str) -> Result<String, String> {
            self.get_calls.fetch_add(1, Ordering::SeqCst);
            if !self.online.load(Ordering::SeqCst) {
                return Err("offline".to_string());
            }
            if url.ends_with("/.well-known/openid-configuration") {
                return Ok(discovery());
            }
            if url == JWKS_URI {
                return Ok(jwks());
            }
            Err(format!("404 {url}"))
        }
    }

    #[test]
    fn refreshing_provider_heals_after_a_cold_start_when_the_idp_recovers() {
        let online = Arc::new(AtomicBool::new(false));
        let op = ToggleOp {
            online: online.clone(),
            get_calls: Arc::new(AtomicUsize::new(0)),
        };
        // Cold start (IdP unreachable): fail-closed — nothing authenticates.
        let idp = RefreshingOidcProvider::new(
            ISSUER,
            vec![CLIENT_ID.to_string()],
            ClaimMapping::default(),
            op,
            Duration::ZERO, // no cooldown wait in the test
        );
        assert!(!idp.is_warm(), "cold start has no keys");
        assert_eq!(
            idp.authenticate(&mint_id_token()),
            None,
            "cold ⇒ fail-closed"
        );

        // The IdP comes back. The next login triggers a JWKS refresh and verifies — no
        // restart, no brick.
        online.store(true, Ordering::SeqCst);
        assert_eq!(
            idp.authenticate(&mint_id_token()),
            Some(AuthorityId::new("alice@example.test")),
            "self-heals on first use once the IdP is reachable"
        );
        assert!(idp.is_warm());
    }

    #[test]
    fn refreshing_provider_does_not_refetch_for_a_known_key_or_within_cooldown() {
        let online = Arc::new(AtomicBool::new(true));
        let calls = Arc::new(AtomicUsize::new(0));
        let op = ToggleOp {
            online: online.clone(),
            get_calls: calls.clone(),
        };
        // Warm start loads the keys (discovery + JWKS = 2 GETs).
        let idp = RefreshingOidcProvider::new(
            ISSUER,
            vec![CLIENT_ID.to_string()],
            ClaimMapping::default(),
            op,
            Duration::from_secs(3600), // long cooldown
        );
        assert!(idp.is_warm());
        let after_warmup = calls.load(Ordering::SeqCst);

        // A valid token verifies off the cached keys — no refetch.
        assert!(idp.authenticate(&mint_id_token()).is_some());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            after_warmup,
            "known key ⇒ no refetch"
        );

        // A token whose `kid` we already hold but with a broken signature is just
        // rejected — it must NOT stampede the OP with refreshes.
        let mut tampered: Vec<char> = mint_id_token().chars().collect();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == 'a' { 'b' } else { 'a' };
        let tampered: String = tampered.into_iter().collect();
        assert_eq!(idp.authenticate(&tampered), None);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            after_warmup,
            "bad signature for a known kid ⇒ no refetch (no stampede)"
        );
    }

    #[test]
    fn finish_callback_surfaces_a_token_response_without_an_id_token() {
        // An OAuth2-only token response (no id_token) is an exchange error.
        let op = mock_op(json!({ "access_token": "at", "token_type": "Bearer" }).to_string());
        let (_u, _s, pending) = start_login(
            &oidc_sso(),
            "http://x/cb",
            "openid",
            ClaimMapping::default(),
            &op,
        )
        .unwrap();
        assert!(matches!(
            finish_callback(&pending, "code", &op),
            Err(CallbackError::Exchange(_))
        ));
    }

    #[test]
    fn native_exchange_binds_the_session_to_a_registry_device() {
        use crate::account::{Account, DeviceStatus};
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let person = "google-sub-777";

        // The exchange path records the device in the person's own scope…
        let device_id = record_native_device(&wb, person, "GaugeDesk on testhost").unwrap();
        assert!(device_id.starts_with("native-"));
        let scope = crate::account::account_scope(person);
        {
            let g = wb.lock_unpoisoned();
            let account = Account::rebuild_in(g.store_ref(), &scope).unwrap();
            let device = account.devices.get(&device_id).unwrap();
            assert_eq!(device.label, "GaugeDesk on testhost");
            assert_eq!(device.status, DeviceStatus::Active);
            assert!(device.enrolled_at > 0);
            // …and the session is admitted while the device is active.
            assert!(native_device_admitted(&g, person, &device_id));
            assert!(!native_device_admitted(&g, person, "native-unknown"));
            assert!(
                !native_device_admitted(&g, "someone-else", &device_id),
                "another person's registry never admits this device"
            );
        }

        // Revoking from the account surface stops future admission (INV-18)
        // without erasing the record.
        {
            let mut g = wb.lock_unpoisoned();
            g.revoke_account_device_in(&scope, &device_id).unwrap();
        }
        {
            let g = wb.lock_unpoisoned();
            assert!(!native_device_admitted(&g, person, &device_id));
            let account = Account::rebuild_in(g.store_ref(), &scope).unwrap();
            assert_eq!(
                account.devices.get(&device_id).unwrap().status,
                DeviceStatus::Revoked,
                "history is preserved, not rewritten"
            );
        }
    }

    #[test]
    fn refresh_records_fold_and_enforce_bounds() {
        use crate::account::{
            account_scope, RefreshBinding, RefreshRecord, SESSION_ABSOLUTE_LIFETIME_MS,
            SESSION_IDLE_MS, WEB_REFRESH_BINDING,
        };
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let person = "google-sub-901";
        let scope = account_scope(person);

        // The callback seals a durable browser-bound grant, folded latest-wins by
        // the stable `web` key.
        {
            let mut g = wb.lock_unpoisoned();
            store_refresh_token(
                &mut g,
                person,
                "rt-browser",
                RefreshBinding::Web,
                WEB_REFRESH_BINDING,
                "",
            );
        }
        let web = {
            let g = wb.lock_unpoisoned();
            resolve_refresh_grant(&g, person, WEB_REFRESH_BINDING).expect("web grant")
        };
        assert_eq!(web.id, WEB_REFRESH_BINDING);
        assert_eq!(web.binding, RefreshBinding::Web);
        assert!(web.issued_at_ms > 0 && web.last_seen_ms > 0);
        {
            // The browser grant opens back to its plaintext under the account key.
            let g = wb.lock_unpoisoned();
            assert_eq!(
                g.unseal_account_secret(&web.sealed).as_deref(),
                Some("rt-browser")
            );
        }

        // F-1.3 independence: a browser logout tombstones the `web` grant BEFORE the
        // native session is established (the e2e's exact order).
        {
            let mut g = wb.lock_unpoisoned();
            g.revoke_account_refresh_in(&scope, WEB_REFRESH_BINDING)
                .unwrap();
        }

        // A native exchange establishes the opaque session and its OWN grant,
        // sealing the refresh token the handoff carried — not a copy of the
        // (now-tombstoned) browser grant. The grant is keyed by the opaque
        // session digest and carries the enrolled device as a stored field.
        let device_id = record_native_device(&wb, person, "GaugeDesk native").unwrap();
        let session_token = wb
            .lock_unpoisoned()
            .mint_account_session(person, "oidc", SESSION_ABSOLUTE_LIFETIME_MS / 1000)
            .unwrap();
        let session_id = crate::account_session::session_id(&session_token);
        bind_native_refresh_grant(&wb, person, &session_id, &device_id, Some("rt-native"));
        {
            let g = wb.lock_unpoisoned();
            let native = resolve_refresh_grant(&g, person, &session_id).expect("native grant");
            assert_eq!(native.binding, RefreshBinding::Device);
            assert_eq!(native.id, session_id);
            assert_eq!(native.device_id, device_id);
            // Its own captured token, independent of the browser grant.
            assert_eq!(
                g.unseal_account_secret(&native.sealed).as_deref(),
                Some("rt-native")
            );
        }

        // F-4.2 + F-1.3: native refresh admits WITHOUT any device header (the client
        // sends none), reading the bound device from the stored grant — even though
        // the browser grant was already tombstoned by logout.
        {
            let g = wb.lock_unpoisoned();
            let now = crate::account::session_now_ms();
            assert!(admit_native_refresh(&g, person, &session_id, now).is_ok());
        }

        // F-4.2: revoking the device stops native refresh. The cascade tombstones the
        // native grant (matched by its stored `device_id`), and the device is no
        // longer admitted — no request header is ever consulted.
        {
            let mut g = wb.lock_unpoisoned();
            g.revoke_account_device_in(&scope, &device_id).unwrap();
        }
        {
            let g = wb.lock_unpoisoned();
            let now = crate::account::session_now_ms();
            assert!(resolve_refresh_grant(&g, person, &session_id).is_none());
            assert_eq!(
                admit_native_refresh(&g, person, &session_id, now),
                Err("no refresh token on file; sign in again"),
            );
            assert!(g.account_sessions().resolve_now(&session_token).is_none());
            assert!(
                !crate::account_auth::AccountAuth::rebuild(g.store_ref())
                    .unwrap()
                    .sessions
                    .contains_key(&session_id),
                "device revocation must survive a process restart",
            );
        }

        // F-1.4: the absolute-lifetime and idle bounds refuse an over-aged or idle
        // grant on the browser path, and a live one within bounds is admitted.
        {
            let mut g = wb.lock_unpoisoned();
            let base = 1_000_000_000_000_u64;
            let aged = RefreshRecord {
                id: WEB_REFRESH_BINDING.to_string(),
                op: crate::account::RecordOp::Upsert,
                sealed: web.sealed.clone(),
                binding: RefreshBinding::Web,
                device_id: String::new(),
                issued_at_ms: base,
                last_seen_ms: base,
            };
            g.write_account_record_in(&scope, "refresh", WEB_REFRESH_BINDING, &aged)
                .unwrap();
            let within = base + SESSION_IDLE_MS - 1;
            assert!(admit_browser_refresh(&g, person, WEB_REFRESH_BINDING, within).is_ok());
            let over_absolute = base + SESSION_ABSOLUTE_LIFETIME_MS + 1;
            assert_eq!(
                admit_browser_refresh(&g, person, WEB_REFRESH_BINDING, over_absolute),
                Err("absolute session lifetime exceeded"),
            );
            let idle = base + SESSION_IDLE_MS + 1;
            assert_eq!(
                admit_browser_refresh(&g, person, WEB_REFRESH_BINDING, idle),
                Err("session idle timeout exceeded"),
            );
        }

        // F-1.4: a refresh preserves issued-at (the absolute clock keeps running
        // from the mint) while advancing last-seen.
        {
            let mut g = wb.lock_unpoisoned();
            let issued = g
                .account_refresh_session_in(&scope, WEB_REFRESH_BINDING)
                .unwrap()
                .unwrap()
                .issued_at_ms;
            let later = crate::account::session_now_ms() + 5;
            g.upsert_account_refresh_in(
                &scope,
                WEB_REFRESH_BINDING,
                RefreshBinding::Web,
                "",
                "rt-2",
                later,
            )
            .unwrap();
            let after = g
                .account_refresh_session_in(&scope, WEB_REFRESH_BINDING)
                .unwrap()
                .unwrap();
            assert_eq!(
                after.issued_at_ms, issued,
                "issued-at is preserved across refresh"
            );
            assert_eq!(after.last_seen_ms, later, "last-seen advances");
        }

        // F-1.3: logout tombstones the browser grant so refresh cannot mint after
        // it; the tombstone folds the grant out (future-only, INV-18).
        {
            let mut g = wb.lock_unpoisoned();
            assert!(g
                .revoke_account_refresh_in(&scope, WEB_REFRESH_BINDING)
                .unwrap()
                .is_some());
        }
        {
            let g = wb.lock_unpoisoned();
            assert!(resolve_refresh_grant(&g, person, WEB_REFRESH_BINDING).is_none());
            let now = crate::account::session_now_ms();
            assert_eq!(
                admit_browser_refresh(&g, person, WEB_REFRESH_BINDING, now),
                Err("no refresh token on file; sign in again"),
            );
        }
    }

    #[test]
    fn an_opaque_session_reports_its_true_minting_method() {
        // ADR 0147 §1: the session surface reports the method the durable session
        // record stores — provider families never expose their exact connection id.
        assert_eq!(
            session_label_for_method("consumer-oidc:consumer-google"),
            ("google", "Google")
        );
        assert_eq!(
            session_label_for_method("recovery"),
            ("recovery", "Recovery code")
        );
        assert_eq!(
            session_label_for_method("passkey"),
            ("passkey", "Passkey or security key")
        );
        // An unknown method falls back to the safe passkey label rather than leaking.
        assert_eq!(
            session_label_for_method("mystery"),
            ("passkey", "Passkey or security key")
        );
    }

    #[test]
    fn consumer_login_resolves_only_an_exact_active_subject_link() {
        let connection = google_sso("https://accounts.google.com", "client");
        let mut state = crate::account_auth::AccountAuth::default();
        let link = crate::account_auth::ExternalSubjectRecord::new(
            "account:alice",
            &connection.id,
            &connection.issuer,
            "google-subject-7",
            crate::account_auth::ExternalSubjectKind::ConsumerOidc,
            1_000,
        )
        .unwrap();
        state
            .external_subjects
            .insert(link.id.clone(), link.clone());

        let resolved = resolve_consumer_oidc_account(
            &state,
            &connection,
            &connection.issuer,
            &connection.issuer,
            "google-subject-7",
        )
        .expect("exact active link resolves");
        assert_eq!(resolved.account_id, "account:alice");
        assert_ne!(resolved.account_id, "google-subject-7");
        assert_eq!(resolved.session_method, "consumer-oidc:consumer-google");
        assert!(resolve_consumer_oidc_account(
            &state,
            &connection,
            &connection.issuer,
            "https://other.example",
            "google-subject-7",
        )
        .is_none());

        let mut revoked = link;
        revoked.status = crate::account_auth::AuthMethodStatus::Revoked;
        state.external_subjects.insert(revoked.id.clone(), revoked);
        assert!(resolve_consumer_oidc_account(
            &state,
            &connection,
            &connection.issuer,
            &connection.issuer,
            "google-subject-7",
        )
        .is_none());
    }

    #[test]
    fn a_photo_refresh_is_admitted_only_for_the_linked_subject_and_a_live_session() {
        let connection = google_sso("https://accounts.google.com", "client");
        let mut state = crate::account_auth::AccountAuth::default();
        for account in ["account:alice", "account:bob"] {
            state.roots.insert(
                account.to_owned(),
                crate::account_auth::CustodiedAccountRootRecord::new(account, "sealed", 1).unwrap(),
            );
        }
        for (account, subject) in [
            ("account:alice", "google-alice"),
            ("account:bob", "google-bob"),
        ] {
            let link = crate::account_auth::ExternalSubjectRecord::new(
                account,
                &connection.id,
                &connection.issuer,
                subject,
                crate::account_auth::ExternalSubjectKind::ConsumerOidc,
                1,
            )
            .unwrap();
            state.external_subjects.insert(link.id.clone(), link);
        }
        // A provider session is enough: the refresh links nothing.
        let session = crate::account_auth::AccountSessionRecord::new(
            "session-alice",
            "account:alice",
            "consumer-oidc:consumer-google",
            1_000,
            60,
        )
        .unwrap();
        state.sessions.insert(session.id.clone(), session);
        let context = PendingConsumerOidcAvatar {
            account_id: "account:alice".into(),
            session_id: "session-alice".into(),
            connection_id: connection.id.clone(),
            connection_revision: connection.current_revision(),
        };
        let returned =
            |token_issuer: Option<&'static str>, subject: &'static str| ReturnedConsumerIdentity {
                pinned_issuer: "https://accounts.google.com",
                pinned_audiences: std::slice::from_ref(&connection.audiences[0]),
                token_issuer,
                subject,
            };
        let admit = |subject: &'static str, now_ms: u64, context: &PendingConsumerOidcAvatar| {
            admit_consumer_avatar_refresh(
                &state,
                context,
                &connection,
                &returned(Some("https://accounts.google.com"), subject),
                now_ms,
            )
            .map_err(|(status, _)| status)
        };

        assert_eq!(admit("google-alice", 2_000, &context), Ok(()));
        // Bob's Google identity, signed in in alice's browser, is not hers.
        assert_eq!(
            admit("google-bob", 2_000, &context),
            Err(StatusCode::CONFLICT)
        );
        assert_eq!(
            admit("google-nobody", 2_000, &context),
            Err(StatusCode::CONFLICT)
        );
        // The initiating session expired while the browser was at Google.
        assert_eq!(
            admit("google-alice", 70_000, &context),
            Err(StatusCode::UNAUTHORIZED)
        );
        // A session that belongs to another account cannot be borrowed.
        let borrowed = PendingConsumerOidcAvatar {
            account_id: "account:bob".into(),
            ..context.clone()
        };
        assert_eq!(
            admit("google-bob", 2_000, &borrowed),
            Err(StatusCode::UNAUTHORIZED)
        );
        // The connection changed under the ceremony.
        let stale = PendingConsumerOidcAvatar {
            connection_revision: "an older revision".into(),
            ..context.clone()
        };
        assert_eq!(
            admit("google-alice", 2_000, &stale),
            Err(StatusCode::CONFLICT)
        );
        // A token whose issuer cannot be read is refused rather than matched.
        assert_eq!(
            admit_consumer_avatar_refresh(
                &state,
                &context,
                &connection,
                &returned(None, "google-alice"),
                2_000,
            )
            .map_err(|(status, _)| status),
            Err(StatusCode::FORBIDDEN)
        );
    }

    /// The sibling the repository was missing. `consumer_login_resolves_only_an
    /// _exact_active_subject_link` proves the resolver is strict — which was
    /// true and was never the problem. Nothing asked what happens to the person
    /// the resolver correctly declines to recognise, and the answer shipped as
    /// a 403 telling someone with no account to sign in with their passkey.
    /// The decision is tested in isolation above, and on its own that is not
    /// enough: `get_callback` is free to stop calling it. Restoring the old
    /// `let Some(resolution) = resolve_consumer_oidc_account(..) else { 403 }`
    /// in the callback — the literal bug a founder hit on a released 0.4.14
    /// desktop — leaves `decide_consumer_callback` fully covered and green while
    /// putting the refusal back in front of every new person.
    ///
    /// This is a structural assertion, deliberately and with its limits stated:
    /// driving `get_callback` for real needs a provider to redeem a code and
    /// sign an id-token, which this crate has no harness for. It reads the
    /// source with comments stripped, because an assertion that matches prose
    /// rather than code is not an assertion — that mistake has been made twice
    /// in this repository already.
    #[test]
    fn the_consumer_callback_routes_through_the_decision_it_is_given() {
        let source = include_str!("auth_oidc.rs");
        // Production code only, twice over. Comments are stripped because an
        // assertion that matches prose is not an assertion, and the test module
        // is cut off because this very test names the old message in a string
        // literal — without the cut it matches itself and fails on a correct
        // tree, which is the most useless possible gate.
        let production = source
            .split_once("\nmod tests {")
            .map(|(before, _)| before)
            .unwrap_or(source);
        let code: String = production
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            code.contains("match decide_consumer_callback("),
            "the consumer callback must route through decide_consumer_callback; \
             a second, private answer to \"who is this subject\" is how the \
             refusal came back",
        );

        // The exact message the founder was shown. Its absence is the cheapest
        // true statement about this regression: the old behaviour cannot be
        // restored without restoring a blanket refusal, and this one was it.
        assert!(
            !code.contains("this Google account is not linked"),
            "the blanket refusal for an unlinked subject is gone; a first-time \
             person now begins signup, and the remaining refusals each name a \
             specific, correct reason",
        );

        // And the refusals that SHOULD remain, so this test cannot be satisfied
        // by deleting the refusal path altogether.
        assert!(
            code.contains("was removed from a GaugeDesk account"),
            "a revoked link must still be refused",
        );
        assert!(
            code.contains("already uses this email address"),
            "an existing account with the same email must still be refused \
             rather than merged into (ADR 0146 section 1)",
        );
    }

    #[test]
    fn a_first_time_google_subject_begins_signup_instead_of_being_refused() {
        let connection = google_sso("https://accounts.google.com", "client");
        let state = crate::account_auth::AccountAuth::default();

        // Nobody has this subject, and the resolver says so.
        assert!(resolve_consumer_oidc_account(
            &state,
            &connection,
            &connection.issuer,
            &connection.issuer,
            "google-subject-new",
        )
        .is_none());

        // That is now the beginning of account creation, not a dead end. The
        // address is normalized on the way in, because it becomes a verified
        // contact on an account and contacts are compared, not displayed.
        assert_eq!(
            decide_google(
                &state,
                &connection,
                &connection.issuer,
                "google-subject-new",
                Some("  New.Person@Example.COM ".to_string()),
            ),
            ConsumerCallbackDecision::Signup {
                verified_email: "new.person@example.com".to_string(),
            },
        );

        // And the other arm is unchanged: a subject that *is* linked signs in
        // to the account holding it, never to a second one minted beside it.
        let mut linked = crate::account_auth::AccountAuth::default();
        let link = crate::account_auth::ExternalSubjectRecord::new(
            "account:alice",
            &connection.id,
            &connection.issuer,
            "google-subject-7",
            crate::account_auth::ExternalSubjectKind::ConsumerOidc,
            1_000,
        )
        .unwrap();
        linked.external_subjects.insert(link.id.clone(), link);
        assert_eq!(
            decide_google(
                &linked,
                &connection,
                &connection.issuer,
                "google-subject-7",
                Some("someone.else@example.com".to_string()),
            ),
            ConsumerCallbackDecision::Login(LoginResolution {
                account_id: "account:alice".to_string(),
                session_method: "consumer-oidc:consumer-google".to_string(),
            }),
        );
    }

    /// The one remaining dead end, and it is the correct one: step 1 of ADR 0146
    /// §1 is "verify an email address", and without `email_verified` the
    /// provider has attested nothing to satisfy it with. `id_token_verified_email`
    /// is what enforces that, and it is strict — a missing claim, `false`, or the
    /// *string* `"true"` all yield `None`.
    #[test]
    fn google_without_a_verified_email_still_refuses_rather_than_creating_an_account() {
        let connection = google_sso("https://accounts.google.com", "client");
        let state = crate::account_auth::AccountAuth::default();
        let decision = decide_google(
            &state,
            &connection,
            &connection.issuer,
            "google-subject-new",
            None,
        );
        assert!(matches!(
            decision,
            ConsumerCallbackDecision::Refuse(StatusCode::FORBIDDEN, message)
                if message.contains("did not return a verified email"),
        ));

        // The claim reader itself, since it is what produces that `None`.
        assert_eq!(
            id_token_verified_email(&unsigned_id_token(json!({
                "email": "person@example.com",
                "email_verified": true,
            })))
            .as_deref(),
            Some("person@example.com")
        );
        for unverified in [
            json!({"email": "person@example.com"}),
            json!({"email": "person@example.com", "email_verified": false}),
            json!({"email": "person@example.com", "email_verified": "true"}),
            json!({"email": "", "email_verified": true}),
        ] {
            assert_eq!(
                id_token_verified_email(&unsigned_id_token(unverified)),
                None
            );
        }
    }

    /// An account let this Google sign-in go. Minting a second account for the
    /// same subject would hand the person an empty account that looks like
    /// somebody else's and leave the real one exactly where it was — so the
    /// refusal that the link ceremony's tests already pin
    /// (`consumer_login_resolves_only_an_exact_active_subject_link`, revoked
    /// case) has to survive the new entrance too.
    #[test]
    fn a_revoked_google_link_cannot_be_laundered_into_a_new_account() {
        let connection = google_sso("https://accounts.google.com", "client");
        let mut state = crate::account_auth::AccountAuth::default();
        let mut link = crate::account_auth::ExternalSubjectRecord::new(
            "account:alice",
            &connection.id,
            &connection.issuer,
            "google-subject-7",
            crate::account_auth::ExternalSubjectKind::ConsumerOidc,
            1_000,
        )
        .unwrap();
        link.status = crate::account_auth::AuthMethodStatus::Revoked;
        state.external_subjects.insert(link.id.clone(), link);

        // Sign-in still refuses it — that is the behaviour under test elsewhere
        // and it stays green.
        assert!(resolve_consumer_oidc_account(
            &state,
            &connection,
            &connection.issuer,
            &connection.issuer,
            "google-subject-7",
        )
        .is_none());
        // And signup refuses it too, rather than treating "no active link" as
        // "never seen".
        assert!(matches!(
            decide_google(
                &state,
                &connection,
                &connection.issuer,
                "google-subject-7",
                Some("alice@example.com".to_string()),
            ),
            ConsumerCallbackDecision::Refuse(StatusCode::FORBIDDEN, message)
                if message.contains("was removed from a GaugeDesk account"),
        ));
    }

    /// ADR 0146 §1: email is a verified contact and discovery identifier, and is
    /// "not silently trusted as an account-merge key". So an address that an
    /// existing account has already verified is a refusal, not a login — anyone
    /// who could obtain a Google account bearing that address would otherwise
    /// walk into the GaugeDesk account behind it. The refusal carries the
    /// sentence the old 403 was reaching for, now given to the person it is
    /// actually true of.
    #[test]
    fn an_existing_account_with_the_same_email_is_never_merged_into() {
        let connection = google_sso("https://accounts.google.com", "client");
        let mut state = crate::account_auth::AccountAuth::default();
        let email = crate::account_auth::VerifiedEmailRecord::new(
            "account:alice",
            "alice@example.com",
            1_000,
        )
        .unwrap();
        state.emails.insert(email.id.clone(), email);

        let decision = decide_google(
            &state,
            &connection,
            &connection.issuer,
            "google-subject-new",
            // Case and surrounding space must not be a way around the check.
            Some(" Alice@Example.com ".to_string()),
        );
        match decision {
            ConsumerCallbackDecision::Refuse(status, message) => {
                assert_eq!(status, StatusCode::CONFLICT);
                assert!(message.contains("already uses this email address"));
                assert!(message.contains("passkey or a recovery code"));
            }
            other => panic!("an existing account's address must refuse, got {other:?}"),
        }
        // Nothing about that decision names the account it declined to merge
        // into: refusing must not become a way to ask whether an address has an
        // account by reading back whose it is.
        assert_eq!(
            state.account_holding_active_email("alice@example.com"),
            Some("account:alice"),
        );
        // A different address on the same store is still free to sign up.
        assert_eq!(
            decide_google(
                &state,
                &connection,
                &connection.issuer,
                "google-subject-new",
                Some("bob@example.com".to_string()),
            ),
            ConsumerCallbackDecision::Signup {
                verified_email: "bob@example.com".to_string(),
            },
        );
    }

    /// The ticket is a bearer for one verified email and one provider subject,
    /// so it gets the custody the PKCE state beside it has: one use, a TTL, and
    /// a ceiling that holds when nothing has expired.
    #[test]
    fn a_signup_ticket_is_single_use_bounded_and_readable_without_being_spent() {
        let now = Instant::now();
        let mut store = PendingConsumerSignupStore::new();
        let ticket = store
            .begin(test_signup("new.person@example.com"), now)
            .unwrap();
        assert_eq!(store.len(), 1);

        // Reading the projection the page renders must not spend the ticket the
        // ceremony still needs.
        assert_eq!(
            store
                .peek(&ticket, now)
                .map(|s| s.email.for_display().unwrap_or_default().to_string())
                .as_deref(),
            Some("new.person@example.com"),
        );
        assert_eq!(store.len(), 1);
        assert!(store.peek("not-a-ticket", now).is_none());

        assert_eq!(
            store.take(&ticket, now).map(|s| s.subject),
            Some("google-subject-new".to_string()),
        );
        // Single use: a replay finds nothing.
        assert!(store.take(&ticket, now).is_none());
        assert!(store.is_empty());

        // And a ticket nobody redeemed ages out rather than waiting forever.
        let stale = store.begin(test_signup("later@example.com"), now).unwrap();
        assert!(store.peek(&stale, now + PENDING_AUTH_TTL).is_none());
        assert!(store.take(&stale, now + PENDING_AUTH_TTL).is_none());
    }

    /// The refresh token a desktop signup carries must not be one `{:?}` away
    /// from a log file, the way every other secret in this module is not.
    #[test]
    fn a_parked_signup_never_renders_its_provider_refresh_token() {
        let mut signup = test_signup("new.person@example.com");
        signup.refresh_token = Some(crate::secret::Secret::new("google-refresh-token"));
        let rendered = format!("{signup:?}");
        assert!(!rendered.contains("google-refresh-token"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    fn test_signup(email: &str) -> PendingConsumerSignup {
        PendingConsumerSignup {
            email: ConsumerSignupEmail::Attested(email.to_string()),
            connection_id: CONSUMER_GOOGLE_CONNECTION_ID.to_string(),
            connection_revision: "revision".to_string(),
            issuer: "https://accounts.google.com".to_string(),
            subject: "google-subject-new".to_string(),
            display_name: Some("New Person".to_string()),
            refresh_token: None,
            provider_expires_at_ms: 0,
            native_return: None,
            native_handoff_challenge: None,
            picture: None,
            browser_binding: crate::secret::Secret::new("test-binding"),
        }
    }

    /// An id-token body with these claims. Every caller here reads claims from
    /// an *already verified* token, so the signature is not what is under test.
    fn unsigned_id_token(claims: serde_json::Value) -> String {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap());
        format!("header.{payload}.signature")
    }

    #[test]
    fn session_method_is_a_safe_current_connection_label() {
        assert_eq!(session_method(None), ("local", "Local account"));
        let google = google_sso("https://accounts.google.com", "client");
        assert_eq!(session_method(Some(&google)), ("google", "Google"));
        let mut oidc = google.clone();
        oidc.issuer = "https://login.example.test".into();
        assert_eq!(
            session_method(Some(&oidc)),
            ("oidc", "Single sign-on (OIDC)")
        );
        oidc.protocol = SsoProtocol::Saml;
        assert_eq!(
            session_method(Some(&oidc)),
            ("saml", "Single sign-on (SAML)")
        );
    }
}
