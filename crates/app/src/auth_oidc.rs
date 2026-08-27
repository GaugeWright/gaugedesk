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
//! The verified **id-token is the bearer** the control plane already accepts
//! (`Workbench::authorize` → `idp.authenticate`), so the shell hands it back to the
//! client rather than minting a second credential — one home for the session truth
//! (the signed, self-expiring token), no parallel session table to keep in sync.
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
    extract::{Extension, Query, State},
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
use crate::org::{Org, RecordOp, SsoConnectionRecord, SsoProtocol, ORG_ID};
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
        // `/auth/callback` redeems the code and hands back the verified
        // id-token (the bearer the gated routes accept).
        .route("/auth/login", get(get_login))
        .route("/auth/callback", get(get_callback))
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
    native_handoffs: Arc<Mutex<NativeHandoffStore>>,
    login_fold: Option<LoginFold>,
    account_auth: Option<Arc<crate::account_auth_ceremony::AccountAuthRuntime>>,
}

/// What the composition folds after a verified login (ADR 0122 §3). The shell
/// verifies identity, mints the session, audits, and handles the hosted
/// web-account/session machinery itself; **membership consequences** — folding
/// the authenticated subject into an org directory (verified-domain JIT) — are
/// the composition's, registered here. `(workbench, tenant scope, authority,
/// verified id-token)`. A composition without a fold gets a login with no
/// membership side effects.
pub type LoginFold = Arc<dyn Fn(&mut Workbench, &str, &str, &str) + Send + Sync>;

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

    /// Install the provider-neutral GaugeDesk account ceremony runtime.
    pub fn with_account_auth(
        mut self,
        runtime: Arc<crate::account_auth_ceremony::AccountAuthRuntime>,
    ) -> Self {
        self.account_auth = Some(runtime);
        self
    }

    pub(crate) fn account_auth(
        &self,
    ) -> Option<Arc<crate::account_auth_ceremony::AccountAuthRuntime>> {
        self.account_auth.clone()
    }

    /// In-flight OIDC login store (`ID-3`), mutable: `/auth/login` records a
    /// pending PKCE state and `/auth/callback` consumes it (one lock hold per
    /// operation — the store's single-use `take` stays atomic).
    pub fn pending_auth_mut(&self) -> MutexGuard<'_, PendingAuthStore> {
        self.pending_auth.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn native_handoffs_mut(&self) -> MutexGuard<'_, NativeHandoffStore> {
        self.native_handoffs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }
}

struct NativeHandoff {
    id_token: crate::secret::Secret,
    /// The offline-access refresh token captured at the same callback, carried so
    /// the exchange can seal the native session its own durable grant (ADR 0147 §2)
    /// — independent of the browser `web` grant, which a prior logout may already
    /// have tombstoned. `None` when the OP granted no refresh token.
    refresh_token: Option<crate::secret::Secret>,
    challenge: String,
    expires_at: Instant,
}

/// What a redeemed native handoff yields: the id-token the native client presents
/// as its bearer, and the refresh token (if any) to seal into its device-bound grant.
struct RedeemedHandoff {
    id_token: String,
    refresh_token: Option<String>,
}

#[derive(Default)]
struct NativeHandoffStore {
    by_code: BTreeMap<String, NativeHandoff>,
}

impl NativeHandoffStore {
    fn issue(
        &mut self,
        id_token: String,
        refresh_token: Option<String>,
        challenge: String,
        now: Instant,
    ) -> String {
        self.by_code.retain(|_, handoff| handoff.expires_at > now);
        let code = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(crate::session::random_bytes::<32>());
        self.by_code.insert(
            code.clone(),
            NativeHandoff {
                id_token: id_token.into(),
                refresh_token: refresh_token.map(Into::into),
                challenge,
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
            id_token: handoff.id_token.expose().to_string(),
            refresh_token: handoff
                .refresh_token
                .as_ref()
                .map(|token| token.expose().to_string()),
        })
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
    if sso.protocol != SsoProtocol::Oidc {
        return Err(LoginError::NotConfigured);
    }
    if sso.issuer.trim().is_empty() {
        return Err(LoginError::NoIssuer);
    }
    let client_id = sso.audiences.first().ok_or(LoginError::NotConfigured)?;
    let endpoints = discover_endpoints(&sso.issuer, http).map_err(LoginError::Discovery)?;
    let pkce = Pkce::generate().map_err(LoginError::Pkce)?;
    // 16 CSPRNG bytes hex-encoded — unguessable, so a forged `state` cannot collide
    // with a live login (the CSRF binding the OP echoes back).
    let state = hex::encode(crate::session::random_bytes::<16>());
    // 16 CSPRNG bytes hex-encoded — the OIDC `nonce`. It rides the authorize request and
    // must come back inside the signed id-token's `nonce` claim (checked in
    // `finish_callback`), binding the token to this browser login (replay/injection
    // defense, `INV-20`).
    let nonce = hex::encode(crate::session::random_bytes::<16>());
    // Request **offline access** (ADR 0077 session refresh): Google returns a refresh token on the
    // consent grant only with `access_type=offline`. `prompt=consent` (opt-in via env) forces the
    // consent screen so a refresh token is re-issued even for an already-granted account — the hub
    // sets it; enterprise SSO leaves it off (seamless SSO). Standard OAuth ignores unknown params.
    let mut extra = String::from("&access_type=offline");
    if gaugedesk_env::var("OIDC_PROMPT_CONSENT").as_deref() == Some("1") {
        extra.push_str("&prompt=consent");
    }
    let url = authorize_url(
        &endpoints.authorization_endpoint,
        client_id,
        redirect_uri,
        scope,
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
        issuer: sso.issuer.clone(),
        audiences: sso.audiences.clone(),
        redirect_uri: redirect_uri.to_string(),
        mapping,
        // The pure login leg carries no secret; the handler injects one from env for a
        // confidential OP (Google). Public PKCE clients leave it `None`.
        client_secret: None,
        native_return: None,
        native_handoff_challenge: None,
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
    // The refresh token (present only on an offline-access consent grant) rides back so the
    // callback can seal it for the session-refresh leg (ADR 0077).
    Ok((authority, id_token, refresh_token))
}

/// The `nonce` claim of an **already-verified** id-token (its signature and registered
/// claims were checked via [`OidcIdentityProvider::authenticate`]), read straight off the
/// payload segment for the login-session binding check in [`finish_callback`]. `None` if
/// the token carries no readable `nonce`.
fn id_token_nonce(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims
        .get("nonce")
        .and_then(|v| v.as_str())
        .map(str::to_string)
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

/// Post-login account reconciliation for the hosted web account (`ADR 0077` §9): provision the
/// authenticated person's **personal tenant-of-one** (idempotent), so a Google login lands them in
/// the Console with their own space. The authenticated `authority` (the OIDC subject) *is* the
/// person root. No-op unless `web_account` — the enterprise/desktop login paths are untouched.
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

/// Admit (or refuse) a **native** refresh for `person` at `now_ms` (ADR 0147 §2/§4,
/// SOC 2 F-4.2). The native client presents only its bearer — no device header — so
/// admission resolves the person's durable native grant and reads the device it is
/// bound to from the **stored** record, then requires that device to still be
/// admitted and the grant to be within bounds. Because the bound device comes from
/// the record and never from a request header, a caller cannot bypass device
/// revocation by omitting or forging `x-gw-device`; the header is not consulted at
/// all. A revoked device (whose grant the revocation cascade tombstones) refuses.
/// Returns the live grant on success.
fn admit_native_refresh(
    wb: &Workbench,
    person: &str,
    now_ms: u64,
) -> Result<crate::account::RefreshRecord, &'static str> {
    let grant = resolve_refresh_grant(wb, person, crate::account::NATIVE_REFRESH_BINDING)
        .ok_or("no refresh token on file; sign in again")?;
    if !native_device_admitted(wb, person, &grant.device_id) {
        return Err("this device's account session was revoked");
    }
    crate::account::refresh_within_bounds(&grant, now_ms)?;
    Ok(grant)
}

/// A Google (or any OIDC) SSO connection for the hosted web account, from env — so the hub
/// offers "Continue with Google" without a manual `/admin/sso` POST. `GAUGEDESK_GOOGLE_CLIENT_ID`
/// is the OAuth client id (the id-token `aud`); the issuer defaults to Google's, overridable via
/// `GAUGEDESK_OIDC_ISSUER`. `None` unless web-account mode with a client id configured.
pub fn web_account_sso_from_env() -> Option<SsoConnectionRecord> {
    if !web_account_mode() {
        return None;
    }
    let client_id = gaugedesk_env::var("GOOGLE_CLIENT_ID").filter(|s| !s.trim().is_empty())?;
    let issuer = gaugedesk_env::var("OIDC_ISSUER")
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "https://accounts.google.com".to_string());
    Some(google_sso(&issuer, &client_id))
}

/// Build an OIDC SSO connection record for `issuer` + `client_id` (pure; the env wrapper is
/// [`web_account_sso_from_env`]). Singleton id, no enforce-SSO (the hosted account is opt-in
/// login, not a locked-down org).
pub fn google_sso(issuer: &str, client_id: &str) -> SsoConnectionRecord {
    SsoConnectionRecord {
        id: ORG_ID.to_string(),
        op: RecordOp::Upsert,
        protocol: SsoProtocol::Oidc,
        issuer: issuer.to_string(),
        audiences: vec![client_id.to_string()],
        metadata: String::new(),
        enforce_sso: false,
        claim_mapping: Default::default(),
    }
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
        "oidc" => ("oidc", "Single sign-on (OIDC)"),
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
        .and_then(|token| wb.account_sessions().resolve_session(token))
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

/// The OAuth **client secret** for a confidential OP (Google), from `GAUGEDESK_GOOGLE_CLIENT_SECRET`.
/// `None` when unset — a public PKCE client (Okta/Entra) needs no secret at exchange.
fn google_client_secret_from_env() -> Option<crate::secret::Secret> {
    gaugedesk_env::var("GOOGLE_CLIENT_SECRET")
        .filter(|s| !s.trim().is_empty())
        .map(Into::into)
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
    for value in [
        session_cookie_header(credential),
        session_hint_cookie_header(),
    ] {
        if let Ok(cookie) = axum::http::HeaderValue::from_str(&value) {
            resp.headers_mut()
                .append(axum::http::header::SET_COOKIE, cookie);
        }
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
            return Redirect::to(&post_login).into_response();
        }
    }
    let sso = {
        let wb = wb.lock_unpoisoned();
        match Org::rebuild_in(wb.store_ref(), &crate::workbench_auth::req_scope(&headers)) {
            Ok(org) => org.sso,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
        }
    };
    // Hosted web account: fall back to the Google connection from env, so the hub offers
    // "Continue with Google" without a stored /admin/sso record (ADR 0077).
    let sso = sso.or_else(web_account_sso_from_env);
    let Some(sso) = sso else {
        return (StatusCode::CONFLICT, "no SSO connection configured").into_response();
    };

    let redirect_uri = callback_redirect_uri(&headers);
    let scope =
        gaugedesk_env::var("OIDC_SCOPE").unwrap_or_else(|| "openid profile email".to_string());
    // The claim mapping comes from the connection record (env-fallback) — the same
    // resolution the durable verifier uses, so the shell and `wb.idp` agree (`ID-3`).
    let mapping = claim_mapping_for(&sso);

    // Discovery touches the network — run it off the async runtime (ureq is blocking).
    let started = tokio::task::spawn_blocking(move || {
        let http = HttpClient::new();
        start_login(&sso, &redirect_uri, &scope, mapping, &http)
    })
    .await;
    let (url, state, mut pending) = match started {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return login_err(e),
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "login task panicked").into_response()
        }
    };
    // Inject the confidential-client secret (Google) for the token exchange, if configured.
    pending.client_secret = google_client_secret_from_env();
    pending.native_return = native_return;
    pending.native_handoff_challenge = query.handoff_challenge;

    auth.pending_auth_mut()
        .begin(state, pending, Instant::now());
    Redirect::to(&url).into_response()
}

#[derive(Default, Deserialize)]
pub struct LoginQuery {
    #[serde(default)]
    return_to: Option<String>,
    #[serde(default)]
    handoff_challenge: Option<String>,
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
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> impl IntoResponse {
    // SECAUD-8: per-tenant failed-callback lockout (429 when locked) — defense-in-depth
    // behind the edge rate-limit, mirroring the SCIM guard. A bad/replayed state or a failed
    // token exchange records a failure; a completed login clears the tenant's count.
    let tenant = crate::workbench_auth::req_scope(&headers);
    let throttle = wb.lock_unpoisoned().oidc_throttle().clone();
    let now = throttle.now_ms();
    if !throttle.allowed(&tenant, now) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed SSO callbacks; retry later",
        )
            .into_response();
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
        throttle.record_failure(&tenant, now);
        return (StatusCode::BAD_REQUEST, "missing code or state").into_response();
    };

    // Single-use take: an unknown / replayed / expired `state` finds nothing
    // (CSRF guard).
    let pending = auth.pending_auth_mut().take(&state, Instant::now());
    let Some(pending) = pending else {
        throttle.record_failure(&tenant, now);
        return (StatusCode::BAD_REQUEST, "unknown or expired state").into_response();
    };
    let native_return = pending.native_return.clone();
    let native_handoff_challenge = pending.native_handoff_challenge.clone();

    let finished = tokio::task::spawn_blocking(move || {
        let http = HttpClient::new();
        finish_callback(&pending, &code, &http)
    })
    .await;
    let (authority, id_token, refresh_token) = match finished {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            throttle.record_failure(&tenant, now);
            return callback_err(e);
        }
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "callback task panicked").into_response()
        }
    };

    // A completed exchange clears the tenant's failed-callback count (SECAUD-8).
    throttle.record_success(&tenant);

    // The opaque session token minted for a hosted browser login (ADR 0147 §1). It —
    // never the external id-token — is set as the session cookie below.
    let mut web_session_token: Option<String> = None;

    // Attribute the login to the authenticated authority (`AUD-1` / `INV-21`), then
    // run the composition's registered fold (ADR 0122 §3 — e.g. verified-domain
    // JIT membership on the enterprise composition; nothing on a solo shell).
    {
        let mut wb = wb.lock_unpoisoned();
        let actor = authority.as_str().to_string();
        let store_scope = crate::workbench_auth::req_scope(&headers);
        crate::audit::record_in(
            &mut wb,
            &store_scope,
            &actor,
            "auth.login",
            authority.as_str(),
        );
        if let Some(fold) = &auth.login_fold {
            fold(&mut wb, &store_scope, authority.as_str(), &id_token);
        }
        // Hosted web account (ADR 0077 §9): a successful login provisions the person's personal
        // tenant-of-one (idempotent) so they land in the Console with their own space. No-op on
        // the enterprise/desktop paths (web-account mode off).
        provision_web_account(&mut wb, authority.as_str(), web_account_mode());
        // Hosted browser session (ADR 0147 §1): mint a durable, opaque, per-session
        // revocable session token. That token — never the external id-token — becomes
        // the `gw_session` cookie. The external id-token stops being the session; the
        // browser holds a fresh short-lived one in memory (obtained from /auth/refresh)
        // as its Home access credential.
        if web_account_mode() {
            if let Some(token) = wb.mint_account_session(
                authority.as_str(),
                "oidc",
                crate::account::SESSION_ABSOLUTE_LIFETIME_MS / 1000,
            ) {
                // Seal the offline-access refresh token as this session's OWN durable,
                // bound grant, keyed by the session id (ADR 0147 §2) — not one coarse
                // per-person `web` key — so each login is its own session and logout or
                // revoke ends only it. Only when the OP returned a refresh token; a
                // native client's device-bound grant is written at /auth/mobile/exchange.
                // Best-effort.
                let session_id = crate::account_session::session_id(&token);
                if let Some(rt) = &refresh_token {
                    store_refresh_token(
                        &mut wb,
                        authority.as_str(),
                        rt,
                        crate::account::RefreshBinding::Web,
                        &session_id,
                        "",
                    );
                }
                web_session_token = Some(token);
            }
        }
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
        let code = auth.native_handoffs_mut().issue(
            id_token,
            refresh_token.clone(),
            challenge,
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
        if let Some(token) = &web_session_token {
            append_session_cookies(&mut resp, token);
        }
        return resp;
    }

    // Enterprise / programmatic clients: deliver the bearer. With a configured client URL, 302
    // there with the token in the URL *fragment* (not a query param — fragments are never sent to
    // servers, so the token stays out of access logs / `Referer`); otherwise return JSON.
    if let Some(url) = gaugedesk_env::var("OIDC_POST_LOGIN_URL") {
        if !url.trim().is_empty() {
            // A JWT is base64url + `.` — all URL-fragment-safe, no escaping needed.
            let target = format!("{url}#id_token={id_token}&token_type=Bearer");
            return Redirect::to(&target).into_response();
        }
    }
    (
        StatusCode::OK,
        Json(json!({
            "authority": authority.as_str(),
            "id_token": id_token,
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
    let (person, session_id, refresh_token) = {
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
        match g.unseal_account_secret(&grant.sealed) {
            Some(rt) => (person, session_id, rt),
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    "no refresh token on file; sign in again",
                )
                    .into_response()
            }
        }
    };
    let Some(sso) = web_account_sso_from_env() else {
        return (StatusCode::CONFLICT, "web-account SSO not configured").into_response();
    };
    let client_id = sso.audiences.first().cloned().unwrap_or_default();
    let client_secret = google_client_secret_from_env().map(|s| s.expose().to_string());
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

/// Refresh a native GaugeDesk account session. A still-valid short-lived
/// id-token identifies the person; the platform uses the refresh token sealed
/// in that person's account scope and returns only a replacement id-token.
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
    let (person, refresh_token) = {
        let g = wb.lock_unpoisoned();
        let person = g.actor(bearer.as_deref());
        if person == "anonymous" {
            return (StatusCode::UNAUTHORIZED, "authenticate to refresh").into_response();
        }
        let grant = match admit_native_refresh(&g, &person, now_ms) {
            Ok(grant) => grant,
            Err(reason) => return (StatusCode::UNAUTHORIZED, reason).into_response(),
        };
        match g.unseal_account_secret(&grant.sealed) {
            Some(token) => (person, token),
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    "no refresh token on file; sign in again",
                )
                    .into_response()
            }
        }
    };
    let Some(sso) = web_account_sso_from_env() else {
        return (StatusCode::CONFLICT, "web-account SSO not configured").into_response();
    };
    let client_id = sso.audiences.first().cloned().unwrap_or_default();
    let client_secret = google_client_secret_from_env().map(|secret| secret.expose().to_string());
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
        Ok(Ok(id_token)) => {
            // An admitted refresh resets the native grant's idle clock (ADR 0147 §4).
            {
                let mut g = wb.lock_unpoisoned();
                let scope = crate::account::account_scope(&person);
                let _ = g.touch_account_refresh_in(
                    &scope,
                    crate::account::NATIVE_REFRESH_BINDING,
                    now_ms,
                );
            }
            (
                StatusCode::OK,
                Json(json!({
                    "person": person,
                    "id_token": id_token,
                    "token_type": "Bearer",
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

/// The `sub` claim of an **already-verified** id-token (the callback verified
/// signature + claims before the handoff stored it) — projection, not
/// verification.
fn subject_claim(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims
        .get("sub")
        .and_then(|s| s.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
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
    device_id: &str,
    refresh_token: Option<&str>,
) {
    let Some(refresh_token) = refresh_token else {
        return;
    };
    let mut g = wb.lock_unpoisoned();
    let Some(sealed) = g.seal_account_secret(refresh_token) else {
        return;
    };
    let scope = crate::account::account_scope(person);
    let now_ms = crate::account::session_now_ms();
    let _ = g.upsert_account_refresh_in(
        &scope,
        crate::account::NATIVE_REFRESH_BINDING,
        crate::account::RefreshBinding::Device,
        device_id,
        &sealed,
        now_ms,
    );
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
/// refresh authority rides the custom-scheme URL. The redeeming client is
/// recorded in the person's trusted-devices registry and receives its
/// `device_id` — presenting it on refresh binds the session to the device
/// (LOGIN-3); revoking the device from the account surface stops refresh.
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
            id_token,
            refresh_token,
        }) => {
            let device_id = subject_claim(&id_token).and_then(|person| {
                let label = request
                    .device_label
                    .as_deref()
                    .map(str::trim)
                    .filter(|label| !label.is_empty())
                    .unwrap_or("Native device");
                let device_id = record_native_device(&wb, &person, label)?;
                // Establish the native session's own durable refresh grant (ADR 0147
                // §2), sealing the refresh token the handoff carried and binding it to
                // this device. It does not depend on the browser `web` grant, which a
                // prior logout may have tombstoned (F-1.3); admission later reads the
                // bound device from this record, never a request header (F-4.2).
                bind_native_refresh_grant(&wb, &person, &device_id, refresh_token.as_deref());
                Some(device_id)
            });
            (
                StatusCode::OK,
                Json(json!({
                    "id_token": id_token,
                    "token_type": "Bearer",
                    "device_id": device_id,
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
        let code = store.issue(
            "id-token".to_string(),
            Some("rt-native".to_string()),
            challenge.clone(),
            now,
        );
        assert!(store.redeem(&code, "wrong-verifier", now).is_none());
        assert!(
            store.redeem(&code, verifier, now).is_none(),
            "a failed proof consumes the code"
        );

        let code = store.issue(
            "id-token".to_string(),
            Some("rt-native".to_string()),
            challenge.clone(),
            now,
        );
        let redeemed = store
            .redeem(&code, verifier, now)
            .expect("redeemed handoff");
        // The handoff carries both the id-token bearer and the refresh token the
        // native grant seals — the browser grant is not consulted (ADR 0147 §2).
        assert_eq!(redeemed.id_token, "id-token");
        assert_eq!(redeemed.refresh_token.as_deref(), Some("rt-native"));
        assert!(
            store.redeem(&code, verifier, now).is_none(),
            "a redeemed code is single-use"
        );

        let code = store.issue("id-token".to_string(), None, challenge, now);
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
    fn google_sso_pins_issuer_and_client_id() {
        let sso = google_sso(
            "https://accounts.google.com",
            "client-xyz.apps.googleusercontent.com",
        );
        assert_eq!(sso.protocol, SsoProtocol::Oidc);
        assert_eq!(sso.issuer, "https://accounts.google.com");
        assert_eq!(sso.audiences, vec!["client-xyz.apps.googleusercontent.com"]);
        assert!(
            !sso.enforce_sso,
            "hosted account is opt-in login, not locked-down"
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
        let token = {
            use base64::Engine as _;
            let b64 = |v: &serde_json::Value| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(serde_json::to_vec(v).unwrap())
            };
            format!(
                "{}.{}.sig",
                b64(&json!({ "alg": "none" })),
                b64(&json!({ "sub": person }))
            )
        };
        assert_eq!(subject_claim(&token).as_deref(), Some(person));

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
            account_scope, RefreshBinding, RefreshRecord, NATIVE_REFRESH_BINDING,
            SESSION_ABSOLUTE_LIFETIME_MS, SESSION_IDLE_MS, WEB_REFRESH_BINDING,
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

        // A native exchange establishes the native session's OWN grant, sealing the
        // refresh token the handoff carried — not a copy of the (now-tombstoned)
        // browser grant. It is keyed by the stable native binding and carries the
        // enrolled device as a stored field.
        let device_id = record_native_device(&wb, person, "GaugeDesk native").unwrap();
        bind_native_refresh_grant(&wb, person, &device_id, Some("rt-native"));
        {
            let g = wb.lock_unpoisoned();
            let native =
                resolve_refresh_grant(&g, person, NATIVE_REFRESH_BINDING).expect("native grant");
            assert_eq!(native.binding, RefreshBinding::Device);
            assert_eq!(native.id, NATIVE_REFRESH_BINDING);
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
            assert!(admit_native_refresh(&g, person, now).is_ok());
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
            assert!(resolve_refresh_grant(&g, person, NATIVE_REFRESH_BINDING).is_none());
            assert_eq!(
                admit_native_refresh(&g, person, now),
                Err("no refresh token on file; sign in again"),
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
        // record stores — an OIDC-derived session is "oidc", not a hardcoded label.
        assert_eq!(
            session_label_for_method("oidc"),
            ("oidc", "Single sign-on (OIDC)")
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
