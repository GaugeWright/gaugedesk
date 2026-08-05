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

use gaugewright_core::abac::AuthorityAttributes;
use gaugewright_core::ids::AuthorityId;

use crate::identity_oidc::{
    authorize_url, discover_endpoints, discover_jwks, exchange_code, refresh_id_token,
    ClaimMapping, HttpForm, HttpGet, OidcIdentityProvider, Pkce,
};
use base64::Engine as _;
use crate::identity::IdentityProvider;
use crate::net_http::HttpClient;
use crate::org::{
    Org, RecordOp, SsoConnectionRecord, SsoProtocol, ORG_ID,
};
use crate::{LockUnpoisoned, SharedWorkbench, Workbench};

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

/// In-flight `/auth/login` → `/auth/callback` PKCE state, keyed by CSRF `state`
/// (`ID-3`). Single-process, held behind the [`AuthShellState`] mutex. A
/// `state` authorizes exactly one callback: [`take`](Self::take) removes it,
/// so a replayed or forged `state` finds nothing (fail-closed, `INV-20`). Loopback
/// scaffold: a real multi-node deployment backs this with shared, TTL-bounded
/// storage behind the same seam (mirroring
/// [`SessionStore`](crate::session::SessionStore)).
#[derive(Default)]
pub struct PendingAuthStore {
    by_state: BTreeMap<String, PendingAuth>,
}

impl PendingAuthStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the pending PKCE state a login leg minted, keyed by its CSRF `state`.
    pub fn begin(&mut self, state: impl Into<String>, pending: PendingAuth) {
        self.by_state.insert(state.into(), pending);
    }

    /// Consume the pending state for a callback's `state` (single-use). `None` for an
    /// unknown / already-redeemed / forged `state` — the CSRF guard.
    pub fn take(&mut self, state: &str) -> Option<PendingAuth> {
        self.by_state.remove(state)
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
        Self::default()
    }

    /// Register the composition's post-login fold (ADR 0122 §3).
    pub fn with_login_fold(mut self, fold: LoginFold) -> Self {
        self.login_fold = Some(fold);
        self
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
    challenge: String,
    expires_at: Instant,
}

#[derive(Default)]
struct NativeHandoffStore {
    by_code: BTreeMap<String, NativeHandoff>,
}

impl NativeHandoffStore {
    fn issue(&mut self, id_token: String, challenge: String, now: Instant) -> String {
        self.by_code.retain(|_, handoff| handoff.expires_at > now);
        let code = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(crate::session::random_bytes::<32>());
        self.by_code.insert(
            code.clone(),
            NativeHandoff {
                id_token: id_token.into(),
                challenge,
                expires_at: now + Duration::from_secs(5 * 60),
            },
        );
        code
    }

    fn redeem(&mut self, code: &str, verifier: &str, now: Instant) -> Option<String> {
        let handoff = self.by_code.remove(code)?;
        if handoff.expires_at <= now
            || crate::identity_oidc::s256_challenge(verifier) != handoff.challenge
        {
            return None;
        }
        Some(handoff.id_token.expose().to_string())
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
    // Request **offline access** (ADR 0077 session refresh): Google returns a refresh token on the
    // consent grant only with `access_type=offline`. `prompt=consent` (opt-in via env) forces the
    // consent screen so a refresh token is re-issued even for an already-granted account — the hub
    // sets it; enterprise SSO leaves it off (seamless SSO). Standard OAuth ignores unknown params.
    let mut extra = String::from("&access_type=offline");
    if std::env::var("GAUGEWRIGHT_OIDC_PROMPT_CONSENT").as_deref() == Ok("1") {
        extra.push_str("&prompt=consent");
    }
    let url = authorize_url(
        &endpoints.authorization_endpoint,
        client_id,
        redirect_uri,
        scope,
        &state,
        &pkce.challenge,
        &extra,
    );
    let pending = PendingAuth {
        verifier: pkce.verifier.into(),
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
    // The refresh token (present only on an offline-access consent grant) rides back so the
    // callback can seal it for the session-refresh leg (ADR 0077).
    Ok((authority, id_token, refresh_token))
}

// ---- enterprise-mode activation (wb.idp from the SSO connection) ---------

/// How id-token claims map onto ABAC attributes for a connection (`ID-3`). The home
/// is the SSO connection record (`/admin/sso`); each field falls back to its
/// `GAUGEWRIGHT_OIDC_*_CLAIM` env knob (the legacy operator path) and then to unmapped
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
            .or_else(|| env_opt("GAUGEWRIGHT_OIDC_SUBJECT_CLAIM"))
            .unwrap_or_else(|| "sub".to_string()),
        roles_claim: m
            .roles_claim
            .clone()
            .or_else(|| env_opt("GAUGEWRIGHT_OIDC_ROLES_CLAIM")),
        region_claim: m
            .region_claim
            .clone()
            .or_else(|| env_opt("GAUGEWRIGHT_OIDC_REGION_CLAIM")),
        tenant_claim: m
            .tenant_claim
            .clone()
            .or_else(|| env_opt("GAUGEWRIGHT_OIDC_TENANT_CLAIM")),
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
/// desktop paths are unchanged; the hosted control-plane hub sets `GAUGEWRIGHT_WEB_ACCOUNT=1`.
pub fn web_account_mode() -> bool {
    std::env::var("GAUGEWRIGHT_WEB_ACCOUNT")
        .map(|v| v == "1")
        .unwrap_or(false)
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

/// Seal `refresh_token` into `person`'s own account scope (`ADR 0077` session refresh). Sealed at
/// rest by the control-plane authority (`SEC-4`); the per-person scope is the access boundary
/// (`INV-1`). A single latest-wins `refresh` record — best-effort (a seal failure is a no-op, the
/// session just falls back to re-login at id-token expiry).
fn store_refresh_token(wb: &mut Workbench, person: &str, refresh_token: &str) {
    let Some(sealed) = wb.seal_account_secret(refresh_token) else {
        return;
    };
    let scope = crate::account::account_scope(person);
    let rec = json!({ "id": "refresh", "sealed": sealed });
    let _ = wb.write_account_record_in(&scope, "refresh", "refresh", &rec);
}

/// The person's stored refresh token, unsealed — `None` if none is stored or it fails to open.
fn resolve_refresh_token(wb: &Workbench, person: &str) -> Option<String> {
    let scope = crate::account::account_scope(person);
    let rows = wb.store_ref().records(&scope, "refresh").ok()?;
    let last = rows.last()?; // latest-wins
    let doc: serde_json::Value = serde_json::from_str(last).ok()?;
    let sealed = doc.get("sealed").and_then(|v| v.as_str())?;
    wb.unseal_account_secret(sealed)
}

/// A Google (or any OIDC) SSO connection for the hosted web account, from env — so the hub
/// offers "Continue with Google" without a manual `/admin/sso` POST. `GAUGEWRIGHT_GOOGLE_CLIENT_ID`
/// is the OAuth client id (the id-token `aud`); the issuer defaults to Google's, overridable via
/// `GAUGEWRIGHT_OIDC_ISSUER`. `None` unless web-account mode with a client id configured.
pub fn web_account_sso_from_env() -> Option<SsoConnectionRecord> {
    if !web_account_mode() {
        return None;
    }
    let client_id = std::env::var("GAUGEWRIGHT_GOOGLE_CLIENT_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())?;
    let issuer = std::env::var("GAUGEWRIGHT_OIDC_ISSUER")
        .ok()
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

/// `GET /auth/session` — the currently authenticated session's sign-in method.
/// It exposes no token, email, subject, refresh state, or tenant membership and
/// must not be rendered as a durable linked-method/custody fact.
pub async fn get_session(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if wb.actor(crate::net_http::bearer(&headers)) == "anonymous" {
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

/// The shared web-account session cookie (`ADR 0077`) carrying the verified id-token as its
/// value (the same credential the control plane accepts, `net_http::bearer`). Pure; the env
/// wrapper is [`session_cookie_header`]. `domain` (e.g. `.gaugewright.com`) makes one sign-in
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

/// The OAuth **client secret** for a confidential OP (Google), from `GAUGEWRIGHT_GOOGLE_CLIENT_SECRET`.
/// `None` when unset — a public PKCE client (Okta/Entra) needs no secret at exchange.
fn google_client_secret_from_env() -> Option<crate::secret::Secret> {
    std::env::var("GAUGEWRIGHT_GOOGLE_CLIENT_SECRET")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(Into::into)
}

/// The `Set-Cookie` value for the login session, from env: `GAUGEWRIGHT_SESSION_COOKIE_DOMAIN`
/// (e.g. `.gaugewright.com`; unset ⇒ host-only, for loopback) and `GAUGEWRIGHT_SESSION_COOKIE_INSECURE=1`
/// (dev-only, drops `Secure` so the cookie works over http loopback).
fn session_cookie_header(id_token: &str) -> String {
    let domain = std::env::var("GAUGEWRIGHT_SESSION_COOKIE_DOMAIN").ok();
    let insecure = std::env::var("GAUGEWRIGHT_SESSION_COOKIE_INSECURE")
        .map(|v| v == "1")
        .unwrap_or(false);
    session_cookie_value(id_token, domain.as_deref(), !insecure)
}

fn expired_session_cookie_header() -> String {
    let domain = std::env::var("GAUGEWRIGHT_SESSION_COOKIE_DOMAIN").ok();
    let insecure = std::env::var("GAUGEWRIGHT_SESSION_COOKIE_INSECURE")
        .map(|v| v == "1")
        .unwrap_or(false);
    expired_session_cookie_value(domain.as_deref(), !insecure)
}

// ---- axum handlers -------------------------------------------------------

/// The `redirect_uri` this control plane registers with the OP. An explicit
/// `GAUGEWRIGHT_OIDC_REDIRECT_URI` wins (the value registered at the IdP); otherwise it
/// is derived from the request `Host` so a default loopback dev run works unconfigured.
fn callback_redirect_uri(headers: &HeaderMap) -> String {
    if let Ok(uri) = std::env::var("GAUGEWRIGHT_OIDC_REDIRECT_URI") {
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
    ) {
        Ok(value) => value,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };
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
    let scope = std::env::var("GAUGEWRIGHT_OIDC_SCOPE")
        .unwrap_or_else(|_| "openid profile email".to_string());
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

    auth.pending_auth_mut().begin(state, pending);
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
) -> Result<Option<String>, &'static str> {
    match (raw, challenge) {
        (None | Some(""), None) => Ok(None),
        (Some("gaugewright://auth/callback"), Some(challenge))
            if challenge.len() == 43
                && challenge
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_') =>
        {
            Ok(Some("gaugewright://auth/callback".to_string()))
        }
        (Some("gaugewright://auth/callback"), _) => {
            Err("native login requires a valid handoff challenge")
        }
        _ => Err("unsupported login return URI"),
    }
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

    // Single-use take: an unknown / replayed `state` finds nothing (CSRF guard).
    let pending = auth.pending_auth_mut().take(&state);
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
        // Session refresh (ADR 0077): seal the offline-access refresh token into the person's own
        // account scope, so /auth/refresh can mint fresh id-tokens without re-login. Only when the
        // OP returned one (offline-access consent grant); best-effort.
        if web_account_mode() {
            if let Some(rt) = &refresh_token {
                store_refresh_token(&mut wb, authority.as_str(), rt);
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
        let code = auth
            .native_handoffs_mut()
            .issue(id_token, challenge, Instant::now());
        let target = format!("{native_return}#code={code}");
        return Redirect::to(&target).into_response();
    }

    // Hosted web account (ADR 0077): deliver the session as the shared `Domain=.gaugewright.com`
    // cookie, not a URL-fragment bearer — one sign-in authenticates the whole site, and the cookie
    // (unlike a header) rides SSE + top-level navigations. Redirect to the Console; the token never
    // touches the URL.
    if web_account_mode() {
        let post_login = std::env::var("GAUGEWRIGHT_OIDC_POST_LOGIN_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())
            .unwrap_or_else(|| "/".to_string());
        let mut resp = Redirect::to(&post_login).into_response();
        if let Ok(cookie) = axum::http::HeaderValue::from_str(&session_cookie_header(&id_token)) {
            resp.headers_mut()
                .append(axum::http::header::SET_COOKIE, cookie);
        }
        return resp;
    }

    // Enterprise / programmatic clients: deliver the bearer. With a configured client URL, 302
    // there with the token in the URL *fragment* (not a query param — fragments are never sent to
    // servers, so the token stays out of access logs / `Referer`); otherwise return JSON.
    if let Ok(url) = std::env::var("GAUGEWRIGHT_OIDC_POST_LOGIN_URL") {
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

/// `GET /auth/refresh` (`ADR 0077` session refresh): mint a fresh id-token cookie from the person's
/// stored refresh token — **without** re-login — but only while the current session is **still
/// valid** (a still-authenticating id-token). An expired/absent session is `401` (re-login). This
/// proactive model means the Console refreshes *before* expiry and an expired token can never
/// refresh itself. Web-account only.
pub async fn get_refresh(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !web_account_mode() {
        return (StatusCode::NOT_FOUND, "not a web-account deployment").into_response();
    }
    let bearer = crate::net_http::bearer(&headers).map(str::to_string);
    // The still-valid session resolves to the person + their sealed refresh token (fail-closed:
    // an expired id-token authenticates to nobody, so it cannot refresh itself).
    let (person, refresh_token) = {
        let g = wb.lock_unpoisoned();
        let person = g.actor(bearer.as_deref());
        if person == "anonymous" {
            return (StatusCode::UNAUTHORIZED, "authenticate to refresh").into_response();
        }
        match resolve_refresh_token(&g, &person) {
            Some(rt) => (person, rt),
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
    // Set the refreshed id-token as the shared session cookie; the person is unchanged.
    let mut resp = (
        StatusCode::OK,
        Json(json!({ "refreshed": true, "person": person })),
    )
        .into_response();
    if let Ok(cookie) = axum::http::HeaderValue::from_str(&session_cookie_header(&new_id)) {
        resp.headers_mut()
            .append(axum::http::header::SET_COOKIE, cookie);
    }
    resp
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
    let (person, refresh_token) = {
        let g = wb.lock_unpoisoned();
        let person = g.actor(bearer.as_deref());
        if person == "anonymous" {
            return (StatusCode::UNAUTHORIZED, "authenticate to refresh").into_response();
        }
        // LOGIN-3 (ADR 0123 §4): a client that presents its device id binds
        // this refresh to the trusted-devices registry — a revoked or unknown
        // device is refused. Clients predating device binding present none and
        // keep the bearer-only contract.
        if let Some(device_id) = headers.get("x-gw-device").and_then(|v| v.to_str().ok()) {
            if !native_device_admitted(&g, &person, device_id) {
                return (
                    StatusCode::UNAUTHORIZED,
                    "this device's account session was revoked",
                )
                    .into_response();
            }
        }
        match resolve_refresh_token(&g, &person) {
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
        Ok(Ok(id_token)) => (
            StatusCode::OK,
            Json(json!({
                "person": person,
                "id_token": id_token,
                "token_type": "Bearer",
            })),
        )
            .into_response(),
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
    let id = format!("native-{}", hex::encode(crate::session::random_bytes::<8>()));
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
    let token = auth
        .native_handoffs_mut()
        .redeem(&request.code, &request.verifier, Instant::now());
    match token {
        Some(id_token) => {
            let device_id = subject_claim(&id_token).and_then(|person| {
                let label = request
                    .device_label
                    .as_deref()
                    .map(str::trim)
                    .filter(|label| !label.is_empty())
                    .unwrap_or("Native device");
                record_native_device(&wb, &person, label)
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

/// `POST /auth/logout` — end the browser's hosted account session. The OIDC id-token is
/// self-contained and naturally expires server-side; logout removes the browser's only copy of
/// it. The handler is intentionally idempotent and does not require a still-valid session, so an
/// expired user can always return to a clean signed-out state.
pub async fn post_logout() -> impl IntoResponse {
    let mut resp = StatusCode::NO_CONTENT.into_response();
    if let Ok(cookie) = axum::http::HeaderValue::from_str(&expired_session_cookie_header()) {
        resp.headers_mut()
            .append(axum::http::header::SET_COOKIE, cookie);
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

    #[test]
    fn pending_store_take_is_single_use() {
        let mut store = PendingAuthStore::new();
        let pending = PendingAuth {
            verifier: "v".into(),
            token_endpoint: TOKEN_ENDPOINT.into(),
            jwks_uri: JWKS_URI.into(),
            issuer: ISSUER.into(),
            audiences: vec![CLIENT_ID.into()],
            redirect_uri: "http://localhost/auth/callback".into(),
            mapping: ClaimMapping::default(),
            client_secret: None,
            native_return: None,
            native_handoff_challenge: None,
        };
        store.begin("state-1", pending);
        assert_eq!(store.len(), 1);
        assert!(store.take("state-1").is_some(), "first take redeems");
        assert!(
            store.take("state-1").is_none(),
            "second take is empty (single-use)"
        );
        assert!(store.is_empty());
    }

    #[test]
    fn native_login_return_is_exactly_allowlisted() {
        let challenge =
            crate::identity_oidc::s256_challenge("0123456789012345678901234567890123456789012");
        assert_eq!(native_return_uri(None, None), Ok(None));
        assert_eq!(
            native_return_uri(Some("gaugewright://auth/callback"), Some(&challenge)),
            Ok(Some("gaugewright://auth/callback".to_string()))
        );
        assert!(native_return_uri(Some("gaugewright://auth/callback"), None).is_err());
        assert!(
            native_return_uri(Some("https://attacker.example/callback"), Some(&challenge)).is_err()
        );
        assert!(
            native_return_uri(Some("gaugewright://auth/callback/extra"), Some(&challenge)).is_err()
        );
    }

    #[test]
    fn native_handoff_is_pkce_bound_single_use_and_expires() {
        let verifier = "0123456789012345678901234567890123456789012";
        let challenge = crate::identity_oidc::s256_challenge(verifier);
        let now = Instant::now();
        let mut store = NativeHandoffStore::default();
        let code = store.issue("id-token".to_string(), challenge.clone(), now);
        assert_eq!(store.redeem(&code, "wrong-verifier", now), None);
        assert_eq!(
            store.redeem(&code, verifier, now),
            None,
            "a failed proof consumes the code"
        );

        let code = store.issue("id-token".to_string(), challenge.clone(), now);
        assert_eq!(
            store.redeem(&code, verifier, now),
            Some("id-token".to_string())
        );
        assert_eq!(store.redeem(&code, verifier, now), None);

        let code = store.issue("id-token".to_string(), challenge, now);
        assert_eq!(
            store.redeem(&code, verifier, now + Duration::from_secs(301)),
            None,
        );
    }

    #[test]
    fn unknown_state_finds_nothing() {
        let mut store = PendingAuthStore::new();
        // The CSRF guard: a forged `state` the server never minted finds no verifier.
        assert!(store.take("forged").is_none());
    }

    #[test]
    fn claim_mapping_prefers_the_record_and_defaults_the_subject() {
        // The record is the home (ID-3): its claim names win, and the subject defaults
        // to `sub` when unset — independent of any GAUGEWRIGHT_OIDC_*_CLAIM env fallback.
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
        let store = gaugewright_store::Store::open_in_memory().unwrap();
        let mut wb = Workbench::new(store);
        let person = "google-sub-123";

        // Off (enterprise/desktop): a login provisions no personal tenant.
        assert!(provision_web_account(&mut wb, person, false).is_none());
        assert!(Tenancy::rebuild_in(
            wb.store_ref(),
            &crate::account::account_scope(person)
        )
        .unwrap()
        .tenants
        .is_empty());

        // On (hosted web account): the login mints the person's personal tenant-of-one.
        let tid =
            provision_web_account(&mut wb, person, true).expect("provisions in web-account mode");
        assert_eq!(tid, personal_tenant_id(person));
        let tenancy = Tenancy::rebuild_in(
            wb.store_ref(),
            &crate::account::account_scope(person),
        )
        .unwrap();
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
            Tenancy::rebuild_in(
                wb.store_ref(),
                &crate::account::account_scope(person)
            )
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
        let id_token = mint_id_token();
        let op = mock_op(json!({ "id_token": id_token, "token_type": "Bearer" }).to_string());

        // The pending state a prior login leg would have stashed.
        let (_url, _state, pending) = start_login(
            &oidc_sso(),
            "http://localhost:1421/auth/callback",
            "openid",
            ClaimMapping {
                roles_claim: Some("roles".into()),
                ..ClaimMapping::default()
            },
            &op,
        )
        .unwrap();

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
