//! OIDC SSO adapter (M3 `ID-3`) — a real [`IdentityProvider`] that authenticates an
//! **OIDC id-token** (a signed JWT) rather than a bare map key. It verifies the
//! token's signature against the issuer's configured signing key(s), checks the
//! registered claims (`iss` / `aud` / `exp` / `nbf`), then maps the verified subject
//! and claims onto an [`AuthorityId`] + its
//! [`AuthorityAttributes`](gaugedesk_core::abac::AuthorityAttributes). Okta,
//! Microsoft Entra ID, and Google Workspace all issue OIDC id-tokens, so the same
//! adapter serves all three behind the seam (the IdP-specific claim names are the
//! only difference, captured by [`ClaimMapping`]).
//!
//! **This is the verified core of `ID-3`** (per the M3 tracker): id-token
//! verification + claim mapping, **fail-closed** (`INV-20`) — any token that does
//! not verify, or whose `iss`/`aud`/`exp` do not match, yields **no** authority,
//! exactly like [`LoopbackIdentityProvider`](crate::identity::LoopbackIdentityProvider) rejecting an unknown
//! credential. It deliberately does **not** speak HTTP: discovery, JWKS fetch +
//! rotation, and the auth-code + PKCE redirect dance are the follow-on slice — the
//! signing keys are supplied to the constructor (in production, populated from the
//! IdP's JWKS; here and in tests, set explicitly). This mirrors how the ABAC
//! evaluator landed its verified core before any live-route wiring.
//!
//! The [`IdentityProvider`] seam splits authentication ([`authenticate`]) from claim
//! lookup ([`claims`]), but an id-token carries identity *and* claims together. So a
//! successful [`authenticate`] **caches** the attributes it materialized, keyed by
//! authority; [`claims`] returns the attributes from that authority's most recent
//! successful authentication, or the fail-closed default for an unknown authority.
//!
//! [`authenticate`]: IdentityProvider::authenticate
//! [`claims`]: IdentityProvider::claims

use std::collections::BTreeMap;
use std::sync::Mutex;

use gaugedesk_core::abac::{AuthorityAttributes, Region, Role, Tenant};
use gaugedesk_core::ids::AuthorityId;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

use crate::identity::IdentityProvider;

/// Which token claims carry the attributes the ABAC evaluator reads. IdP-specific:
/// Entra puts groups in `groups`, Okta roles in a custom `roles` claim, etc. Unset
/// (`None`) means "do not map that attribute" — fail-closed (no role is safer than a
/// wrongly-mapped one).
#[derive(Clone, Debug)]
pub struct ClaimMapping {
    /// The claim naming the durable subject → [`AuthorityId`]. Default `"sub"` (the
    /// OIDC stable subject identifier).
    pub subject_claim: String,
    /// The claim carrying roles — a JSON array of strings, or a single
    /// space-delimited string. `None` ⇒ no roles mapped.
    pub roles_claim: Option<String>,
    /// The claim carrying the data-residency region (a single string). `None` ⇒ no
    /// region mapped.
    pub region_claim: Option<String>,
    /// The claim carrying the tenant / affiliation (a single string). `None` ⇒ no
    /// affiliation mapped.
    pub tenant_claim: Option<String>,
}

impl Default for ClaimMapping {
    fn default() -> Self {
        Self {
            subject_claim: "sub".to_string(),
            roles_claim: None,
            region_claim: None,
            tenant_claim: None,
        }
    }
}

/// One signing key the issuer may have used. Keyed by `kid` (the JWK key id) when
/// present, so key rotation is just adding/removing entries. `alg` pins the
/// algorithm a token signed with this key must declare — a token claiming a
/// different `alg` for this `kid` is rejected (no algorithm-confusion).
struct SigningKey {
    kid: Option<String>,
    alg: Algorithm,
    key: DecodingKey,
}

/// An OIDC id-token verifier behind the [`IdentityProvider`] seam.
pub struct OidcIdentityProvider {
    issuer: String,
    audiences: Vec<String>,
    keys: Vec<SigningKey>,
    mapping: ClaimMapping,
    /// Attributes materialized at the last successful [`authenticate`], per authority.
    /// Interior mutability: the seam's `&self` methods, with the claims source being
    /// the just-verified token.
    ///
    /// [`authenticate`]: IdentityProvider::authenticate
    cache: Mutex<BTreeMap<AuthorityId, AuthorityAttributes>>,
}

impl OidcIdentityProvider {
    /// A verifier for `issuer`, accepting tokens whose `aud` contains any of
    /// `audiences` (typically the single registered client id). No signing keys yet —
    /// add them with [`with_es256_pem`](Self::with_es256_pem) /
    /// [`with_rs256_pem`](Self::with_rs256_pem). A verifier with no keys authenticates
    /// nothing (fail-closed).
    pub fn new(issuer: impl Into<String>, audiences: impl IntoIterator<Item = String>) -> Self {
        Self {
            issuer: issuer.into(),
            audiences: audiences.into_iter().collect(),
            keys: Vec::new(),
            mapping: ClaimMapping::default(),
            cache: Mutex::new(BTreeMap::new()),
        }
    }

    /// Set how token claims map onto attributes (roles / region / tenant).
    pub fn with_mapping(mut self, mapping: ClaimMapping) -> Self {
        self.mapping = mapping;
        self
    }

    /// Register an ES256 (P-256) public key — PEM-encoded `SubjectPublicKeyInfo`.
    /// `kid` matches the token header's `kid` (pass `None` for a single
    /// keyless issuer).
    pub fn with_es256_pem(
        mut self,
        kid: Option<String>,
        pem: &[u8],
    ) -> Result<Self, jsonwebtoken::errors::Error> {
        self.keys.push(SigningKey {
            kid,
            alg: Algorithm::ES256,
            key: DecodingKey::from_ec_pem(pem)?,
        });
        Ok(self)
    }

    /// Register an RS256 public key — PEM-encoded `SubjectPublicKeyInfo` (the common
    /// case: Okta / Entra / Google all default to RS256).
    pub fn with_rs256_pem(
        mut self,
        kid: Option<String>,
        pem: &[u8],
    ) -> Result<Self, jsonwebtoken::errors::Error> {
        self.keys.push(SigningKey {
            kid,
            alg: Algorithm::RS256,
            key: DecodingKey::from_rsa_pem(pem)?,
        });
        Ok(self)
    }

    /// Register an RS256 key from raw JWK components (base64url `n` modulus + `e`
    /// exponent) — the shape a JWKS endpoint serves, so the follow-on HTTP slice
    /// populates keys through here.
    pub fn with_rs256_components(
        mut self,
        kid: Option<String>,
        n: &str,
        e: &str,
    ) -> Result<Self, jsonwebtoken::errors::Error> {
        self.keys.push(SigningKey {
            kid,
            alg: Algorithm::RS256,
            key: DecodingKey::from_rsa_components(n, e)?,
        });
        Ok(self)
    }

    /// Load every usable signing key from a **JWKS document** (`ID-3`). This is the
    /// local parse half of the HTTP slice: the follow-on fetches the JWKS over the
    /// network and feeds the bytes here (and refreshes on key rotation). Parses RS256
    /// keys (`kty:"RSA"`, base64url `n`/`e`) — the case Okta / Entra / Google all
    /// serve; a key whose `use` is `enc` (encryption, not signing) or whose `kty`/
    /// `alg` we do not handle is skipped, not fatal (forward-compatible). A document
    /// with no usable key is an error (a verifier with no keys authenticates nothing).
    pub fn with_jwks(mut self, jwks_json: &str) -> Result<Self, String> {
        let doc: serde_json::Value =
            serde_json::from_str(jwks_json).map_err(|e| format!("invalid JWKS json: {e}"))?;
        let keys = doc
            .get("keys")
            .and_then(|k| k.as_array())
            .ok_or_else(|| "JWKS has no `keys` array".to_string())?;
        let mut added = 0;
        for jwk in keys {
            // Skip encryption keys; only signing keys verify tokens.
            if jwk.get("use").and_then(|u| u.as_str()) == Some("enc") {
                continue;
            }
            let kty = jwk.get("kty").and_then(|v| v.as_str());
            if kty != Some("RSA") {
                continue; // EC/OKP not handled here (RSA is the OIDC default)
            }
            let (Some(n), Some(e)) = (
                jwk.get("n").and_then(|v| v.as_str()),
                jwk.get("e").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            let kid = jwk
                .get("kid")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let key =
                DecodingKey::from_rsa_components(n, e).map_err(|e| format!("bad RSA JWK: {e}"))?;
            self.keys.push(SigningKey {
                kid,
                alg: Algorithm::RS256,
                key,
            });
            added += 1;
        }
        if added == 0 {
            return Err("JWKS contained no usable signing key".to_string());
        }
        Ok(self)
    }

    /// Pick the key for a token's header. With a `kid`, require an exact `kid` match
    /// **and** that the header `alg` equals the key's pinned `alg`. Without a `kid`,
    /// accept iff there is exactly one registered key and its `alg` matches. Any
    /// ambiguity ⇒ `None` (fail-closed).
    fn select_key(&self, kid: Option<&str>, alg: Algorithm) -> Option<&SigningKey> {
        match kid {
            Some(kid) => self
                .keys
                .iter()
                .find(|k| k.kid.as_deref() == Some(kid) && k.alg == alg),
            None => match self.keys.as_slice() {
                [only] if only.alg == alg => Some(only),
                _ => None,
            },
        }
    }

    /// Map verified token claims onto attributes per [`ClaimMapping`]. Only ever
    /// *adds* attributes the token actually carries; a missing/ill-typed claim maps
    /// to nothing (never a default that widens access).
    fn map_claims(
        &self,
        claims: &serde_json::Map<String, serde_json::Value>,
    ) -> AuthorityAttributes {
        let mut attrs = AuthorityAttributes::default();

        if let Some(name) = &self.mapping.roles_claim {
            if let Some(value) = claims.get(name) {
                attrs.roles = match value {
                    serde_json::Value::Array(items) => items
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(Role::new)
                        .collect(),
                    serde_json::Value::String(s) => s.split_whitespace().map(Role::new).collect(),
                    _ => Default::default(),
                };
            }
        }
        if let Some(name) = &self.mapping.region_claim {
            attrs.region = claims.get(name).and_then(|v| v.as_str()).map(Region::new);
        }
        if let Some(name) = &self.mapping.tenant_claim {
            attrs.affiliation = claims.get(name).and_then(|v| v.as_str()).map(Tenant::new);
        }
        attrs
    }
}

/// The placeholder a tenant-templated issuer carries, spelled the way Microsoft's
/// own `common` discovery document spells its `issuer` (DR-0189 §2).
pub const TENANT_PLACEHOLDER: &str = "{tenantid}";

/// The claim naming the tenant that issued a token.
const TENANT_CLAIM: &str = "tid";

/// Whether `value` is a bare tenant guid — `8-4-4-12` hex, nothing else.
///
/// This is what stops a `tid` from smuggling anything into the expected issuer.
/// Without it a tenant claim of `../../accounts.google.com` or
/// `x/v2.0#` would be substituted verbatim into a URL we then demand equality
/// against, and the attacker would be choosing the string on both sides.
fn is_tenant_guid(value: &str) -> bool {
    let groups = [8_usize, 4, 4, 4, 12];
    let mut parts = value.split('-');
    for width in groups {
        let Some(part) = parts.next() else {
            return false;
        };
        if part.len() != width || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
    }
    parts.next().is_none()
}

/// The tenant a token claims, read from the **unverified** payload.
///
/// Reading an unverified claim is safe here for exactly one reason, and it is
/// worth stating because the safety is not local: the value is used only to
/// compute the issuer string that the signed token must then match exactly,
/// against keys fetched from the authority. A caller who names their own tenant
/// gets a verifier demanding a token issued by that tenant and signed by the
/// authority — which is what a multi-tenant authority means. A caller who names
/// somebody else's gets a refusal, because no key of the authority signed a
/// token whose `iss` names a tenant that did not issue it.
fn unverified_tenant(credential: &str) -> Option<String> {
    let payload = credential.split('.').nth(1)?;
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload).ok()?;
    let claims: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&bytes).ok()?;
    claims.get(TENANT_CLAIM)?.as_str().map(str::to_owned)
}

/// Substitute `tenant` into an issuer `template`, refusing anything that is not a
/// bare tenant guid (DR-0189 §2: substitution, then exact equality).
pub fn substitute_tenant(template: &str, tenant: &str) -> Option<String> {
    if !is_tenant_guid(tenant) {
        return None;
    }
    Some(template.replace(TENANT_PLACEHOLDER, tenant))
}

/// Whether `issuer` is a concrete member of the family `template` describes.
///
/// For a verified token this is a shape question, not a trust question: the
/// verifier has already demanded that `iss` equal the template with this token's
/// own tenant substituted. Callers that key durable state by the verified issuer
/// use this to confirm the issuer belongs to the connection that admitted it.
pub fn issuer_matches_tenant_template(template: &str, issuer: &str) -> bool {
    let Some(placeholder_at) = template.find(TENANT_PLACEHOLDER) else {
        return template == issuer;
    };
    let (prefix, rest) = template.split_at(placeholder_at);
    let suffix = &rest[TENANT_PLACEHOLDER.len()..];
    let Some(middle) = issuer
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(suffix))
    else {
        return false;
    };
    is_tenant_guid(middle)
}

impl IdentityProvider for OidcIdentityProvider {
    fn authenticate(&self, credential: &str) -> Option<AuthorityId> {
        // Read the header to pick the key — but never trust it for verification: the
        // signature check below is what authenticates the token.
        let header = decode_header(credential).ok()?;
        let key = self.select_key(header.kid.as_deref(), header.alg)?;

        // A templated issuer names a family of tenants, so the issuer this token
        // must claim is computed from the token's own tenant and then demanded
        // exactly (DR-0189 §2). A non-templated issuer is unchanged.
        let expected_issuer = if self.issuer.contains(TENANT_PLACEHOLDER) {
            let tenant = unverified_tenant(credential)?;
            substitute_tenant(&self.issuer, &tenant)?
        } else {
            self.issuer.clone()
        };

        let mut validation = Validation::new(key.alg);
        validation.set_issuer(&[expected_issuer.as_str()]);
        validation.set_audience(&self.audiences);
        // `exp` is required and validated by default; `nbf` validated when present.

        let token =
            decode::<serde_json::Map<String, serde_json::Value>>(credential, &key.key, &validation)
                .ok()?;
        let claims = token.claims;

        // The verified payload must carry the same tenant the expected issuer was
        // built from. Today this cannot fail: both reads parse the same payload
        // bytes with the same parser, so deleting it breaks no test — it was
        // checked by mutation, not assumed. It is kept because it is the only
        // place the binding between the unverified read and the verified claim is
        // stated in code, and a later change to `unverified_tenant` (a different
        // source, a laxer parser) would turn it from redundant into load-bearing
        // without anybody having to notice that it had.
        if self.issuer.contains(TENANT_PLACEHOLDER) {
            let verified_tenant = claims.get(TENANT_CLAIM)?.as_str()?;
            if substitute_tenant(&self.issuer, verified_tenant)? != expected_issuer {
                return None;
            }
        }

        let subject = claims.get(&self.mapping.subject_claim)?.as_str()?;
        if subject.is_empty() {
            return None;
        }
        let authority = AuthorityId::new(subject);

        let attrs = self.map_claims(&claims);
        self.cache
            .lock()
            .expect("identity cache mutex poisoned")
            .insert(authority.clone(), attrs);
        Some(authority)
    }

    fn claims(&self, authority: &AuthorityId) -> AuthorityAttributes {
        self.cache
            .lock()
            .expect("identity cache mutex poisoned")
            .get(authority)
            .cloned()
            .unwrap_or_default()
    }
}

// ============================================================================
// The HTTP leg (M3 ID-3): OIDC discovery + JWKS fetch, and the PKCE helpers for the
// auth-code flow. The *logic* here is testable against a mock fetcher; the literal
// network client (a real HTTP GET) and the browser redirect/token-exchange are the
// deferred halves — the GET needs a live OP to test (ID-4/external), the redirect is
// the desktop/web shell's concern. They attach behind [`HttpGet`] / consume the URL
// [`Pkce::authorize_url`] builds, with no change to the verified core above.
// ============================================================================

/// A blocking HTTP GET — the seam the real network client attaches behind (a thin
/// `reqwest`/`ureq` wrapper in production; a canned-response mock in tests). Used
/// only for the one-time discovery + JWKS fetch at setup/rotation, not per-request.
pub trait HttpGet {
    /// Fetch `url`, returning the response body as a string, or an error message.
    fn get(&self, url: &str) -> Result<String, String>;
}

impl HttpGet for crate::net_http::HttpClient {
    fn get(&self, url: &str) -> Result<String, String> {
        self.get_string(url)
    }
}

/// Discover an issuer's JWKS document: fetch `{issuer}/.well-known/openid-configuration`,
/// read its `jwks_uri`, and fetch that — returning the JWKS JSON, which
/// [`OidcIdentityProvider::with_jwks`] then loads. The follow-on rotation simply
/// re-runs this and rebuilds the verifier's key set.
pub fn discover_jwks(issuer: &str, http: &impl HttpGet) -> Result<String, String> {
    let well_known = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let discovery = http.get(&well_known)?;
    let doc: serde_json::Value =
        serde_json::from_str(&discovery).map_err(|e| format!("invalid discovery doc: {e}"))?;
    let jwks_uri = doc
        .get("jwks_uri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "discovery doc has no jwks_uri".to_string())?;
    http.get(jwks_uri)
}

/// The OP's endpoints from its discovery document (OIDC Discovery / RFC 8414): where to
/// send the browser ([`authorize_url`]), where the token exchange POSTs, and where the
/// signing keys live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OidcEndpoints {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    /// The issuer the authority's own metadata declares. Usually the string the
    /// document was fetched from; a multi-tenant authority declares a tenant
    /// template here instead (DR-0189 §2). Read it through
    /// [`accepted_issuer`] rather than trusting it directly.
    pub issuer: String,
}

/// Fetch + parse `{issuer}/.well-known/openid-configuration` into its endpoints.
pub fn discover_endpoints(issuer: &str, http: &impl HttpGet) -> Result<OidcEndpoints, String> {
    let well_known = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let doc: serde_json::Value = serde_json::from_str(&http.get(&well_known)?)
        .map_err(|e| format!("invalid discovery doc: {e}"))?;
    let field = |k: &str| {
        doc.get(k)
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| format!("discovery doc has no {k}"))
    };
    Ok(OidcEndpoints {
        authorization_endpoint: field("authorization_endpoint")?,
        token_endpoint: field("token_endpoint")?,
        jwks_uri: field("jwks_uri")?,
        issuer: field("issuer")?,
    })
}

/// Which issuer a login may verify against, given what was **configured** and what
/// the authority's metadata **declares** (DR-0189 §2).
///
/// Validating `iss` against the discovery document is what OIDC says to do, but
/// taking the declared value on trust would let a misconfigured or hostile OP
/// widen an issuer an administrator pinned. So exactly two answers are admitted:
///
/// - the declaration agrees with the configuration — every ordinary connection,
///   and no change in behaviour; or
/// - the declaration is a tenant template at the **same origin** as the
///   configured authority — a multi-tenant OP, where the configured string names
///   the authority (`…/common/v2.0`) and the declaration names the family
///   (`…/{tenantid}/v2.0`).
///
/// Anything else is a refusal, not a fallback: an authority whose metadata names
/// an issuer we did not ask for is a misconfiguration at best.
pub fn accepted_issuer(configured: &str, declared: &str) -> Option<String> {
    if configured == declared {
        return Some(declared.to_string());
    }
    if declared.contains(TENANT_PLACEHOLDER) && same_origin(configured, declared) {
        return Some(declared.to_string());
    }
    None
}

/// Whether two URLs share scheme, host and port — compared by parsing, never by
/// prefix, so `https://login.microsoftonline.com.evil.test` is a different origin
/// from `https://login.microsoftonline.com`.
fn same_origin(a: &str, b: &str) -> bool {
    fn origin(url: &str) -> Option<(String, String)> {
        let (scheme, rest) = url.split_once("://")?;
        if scheme.is_empty() {
            return None;
        }
        let authority = rest.split(['/', '?', '#']).next()?;
        if authority.is_empty() {
            return None;
        }
        Some((scheme.to_ascii_lowercase(), authority.to_ascii_lowercase()))
    }
    match (origin(a), origin(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// A blocking `application/x-www-form-urlencoded` POST — the seam the auth-code **token
/// exchange** ([`exchange_code`]) attaches behind (the real client posts to the OP token
/// endpoint; tests supply a mock). Returns the response body, or an error.
pub trait HttpForm {
    fn post_form(&self, url: &str, fields: &[(&str, &str)]) -> Result<String, String>;
}

impl HttpForm for crate::net_http::HttpClient {
    fn post_form(&self, url: &str, fields: &[(&str, &str)]) -> Result<String, String> {
        match crate::net_http::HttpClient::post_form(self, url, fields) {
            Ok((status, body)) if (200..300).contains(&status) => Ok(body),
            Ok((status, body)) => Err(format!("HTTP {status}: {body}")),
            Err(e) => Err(e),
        }
    }
}

/// Redeem an authorization `code` for tokens at the OP token endpoint (auth-code + PKCE),
/// returning the verified-by-the-caller **`id_token`**. Presents the PKCE `verifier`, so a
/// code intercepted on the redirect is useless without it (RFC 7636). `client_secret` is
/// `None` for a public (PKCE) client. The returned id-token is *not yet trusted* — feed it
/// to [`OidcIdentityProvider::authenticate`], which verifies signature + claims.
pub fn exchange_code(
    token_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    pkce_verifier: &str,
    client_secret: Option<&str>,
    http: &impl HttpForm,
) -> Result<(String, Option<String>), String> {
    let mut fields = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", pkce_verifier),
    ];
    if let Some(secret) = client_secret {
        fields.push(("client_secret", secret));
    }
    let body = http.post_form(token_endpoint, &fields)?;
    let doc: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("invalid token response: {e}"))?;
    let id_token = doc
        .get("id_token")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| "token response has no id_token".to_string())?;
    // The refresh token (present only with `access_type=offline` on the consent grant, ADR 0077).
    let refresh_token = doc
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);
    Ok((id_token, refresh_token))
}

/// Redeem a **refresh token** for a fresh id-token (`grant_type=refresh_token`, ADR 0077) — the
/// session-refresh leg. Presents the confidential-client secret when the OP requires it (Google).
/// Returns the new id-token. Free of axum/IO except the injected [`HttpForm`], so it is
/// mock-testable like [`exchange_code`].
pub fn refresh_id_token(
    token_endpoint: &str,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
    http: &impl HttpForm,
) -> Result<String, String> {
    let mut fields = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if let Some(secret) = client_secret {
        fields.push(("client_secret", secret));
    }
    let body = http.post_form(token_endpoint, &fields)?;
    let doc: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("invalid refresh response: {e}"))?;
    doc.get("id_token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .ok_or_else(|| "refresh response has no id_token".to_string())
}

/// A PKCE pair (RFC 7636) for the auth-code flow: a random `verifier` and its S256
/// `challenge` = base64url(SHA-256(verifier)). The client keeps the verifier secret
/// and sends the challenge on the authorize request; the token exchange presents the
/// verifier, so an intercepted code cannot be redeemed without it.
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    /// Generate a fresh PKCE pair. The verifier is 64 hex chars (within RFC 7636's
    /// 43–128 unreserved-char range); the challenge is its S256 transform.
    pub fn generate() -> Result<Self, String> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|e| format!("CSPRNG: {e}"))?;
        let verifier = hex::encode(bytes);
        Ok(Self {
            challenge: s256_challenge(&verifier),
            verifier,
        })
    }
}

/// The S256 code-challenge for a verifier: base64url-no-pad of its SHA-256.
pub fn s256_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(verifier.as_bytes());
    base64url_nopad(&h.finalize())
}

/// Build the authorize-endpoint redirect URL for the auth-code + PKCE flow. The
/// browser shell sends the user here; the OP redirects back to `redirect_uri` with a
/// `code` the token exchange then redeems with the PKCE verifier.
#[allow(clippy::too_many_arguments)] // one authorize-request builder; every OIDC param is load-bearing
pub fn authorize_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    state: &str,
    nonce: &str,
    challenge: &str,
    extra_params: &str,
) -> String {
    format!(
        "{authorization_endpoint}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256{extra_params}",
        pct(client_id),
        pct(redirect_uri),
        pct(scope),
        pct(state),
        pct(nonce),
        pct(challenge),
    )
}

/// base64url without padding (RFC 4648 §5) — for the PKCE S256 challenge.
fn base64url_nopad(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(T[(n & 63) as usize] as char);
        }
    }
    out
}

/// Percent-encode a query-parameter value (RFC 3986 unreserved set passes through).
fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::collections::BTreeMap;

    // A real ES256 (P-256) test keypair (generated for tests only, never used in
    // production). Verification uses the public key; tests mint tokens with the
    // private key to exercise the real asymmetric path an OIDC IdP uses.
    const ES256_PRIVATE_PKCS8_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgN9w4Cl52bC/5iv55
oeIMuEWpT72yZEGP7ioZ0Se4U+2hRANCAAT9E4yW5Xxh8N3Pq7W/8PnvWHPvy8Mk
eZmBgMbmh6Icfde8Tv4ZTd6RXS1qNc8nj+Edftjd8cH98tkMMGQH7aF2
-----END PRIVATE KEY-----";
    const ES256_PUBLIC_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/ROMluV8YfDdz6u1v/D571hz78vD
JHmZgYDG5oeiHH3XvE7+GU3ekV0tajXPJ4/hHX7Y3fHB/fLZDDBkB+2hdg==
-----END PUBLIC KEY-----";

    const ISSUER: &str = "https://idp.example.com";
    const AUDIENCE: &str = "gaugewright-client-id";
    const KID: &str = "test-key-1";

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Mint a signed ES256 id-token from a claims object.
    fn mint(claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(KID.to_string());
        let key = EncodingKey::from_ec_pem(ES256_PRIVATE_PKCS8_PEM).expect("test signing key");
        encode(&header, claims, &key).expect("encode token")
    }

    fn provider() -> OidcIdentityProvider {
        OidcIdentityProvider::new(ISSUER, [AUDIENCE.to_string()])
            .with_mapping(ClaimMapping {
                subject_claim: "sub".into(),
                roles_claim: Some("roles".into()),
                region_claim: Some("region".into()),
                tenant_claim: Some("org".into()),
            })
            .with_es256_pem(Some(KID.to_string()), ES256_PUBLIC_PEM)
            .expect("public key parses")
    }

    fn base_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "alice@example.com",
            "exp": now() + 3600,
            "iat": now(),
            "roles": ["admin", "member"],
            "region": "eu",
            "org": "acme",
        })
    }

    #[test]
    fn valid_token_authenticates_to_its_subject() {
        let idp = provider();
        let token = mint(&base_claims());
        assert_eq!(
            idp.authenticate(&token),
            Some(AuthorityId::new("alice@example.com"))
        );
    }

    #[test]
    fn verified_claims_map_to_attributes() {
        // The seam's point: a real principal → authority → attributes the ABAC
        // evaluator reads. authenticate() must populate claims() for that authority.
        let idp = provider();
        let token = mint(&base_claims());
        let authority = idp.authenticate(&token).expect("authenticates");

        let attrs = idp.claims(&authority);
        assert!(attrs.roles.contains(&Role::admin()));
        assert!(attrs.roles.contains(&Role::member()));
        assert_eq!(attrs.region, Some(Region::new("eu")));
        assert_eq!(attrs.affiliation, Some(Tenant::new("acme")));
    }

    #[test]
    fn space_delimited_roles_claim_is_split() {
        let idp = provider();
        let mut claims = base_claims();
        claims["roles"] = serde_json::json!("viewer billing");
        let authority = idp.authenticate(&mint(&claims)).expect("authenticates");
        let attrs = idp.claims(&authority);
        assert!(attrs.roles.contains(&Role::viewer()));
        assert!(attrs.roles.contains(&Role::new("billing")));
    }

    #[test]
    fn tampered_payload_is_rejected() {
        // Flip a byte in the payload segment: the signature no longer verifies.
        let idp = provider();
        let token = mint(&base_claims());
        let mut parts: Vec<&str> = token.split('.').collect();
        let mut payload: Vec<u8> = parts[1].bytes().collect();
        // mutate a character that stays within the base64url alphabet
        let last = payload.len() - 1;
        payload[last] = if payload[last] == b'A' { b'B' } else { b'A' };
        let tampered_payload = String::from_utf8(payload).unwrap();
        parts[1] = &tampered_payload;
        let tampered = parts.join(".");
        assert_eq!(idp.authenticate(&tampered), None);
    }

    #[test]
    fn wrong_issuer_is_rejected() {
        let idp = provider();
        let mut claims = base_claims();
        claims["iss"] = serde_json::json!("https://evil.example.com");
        assert_eq!(idp.authenticate(&mint(&claims)), None);
    }

    // ---- tenant-templated issuers (DR-0189 §2) -------------------------------

    const TENANT: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    const OTHER_TENANT: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";
    const TEMPLATE: &str = "https://login.microsoftonline.com/{tenantid}/v2.0";

    fn tenant_provider() -> OidcIdentityProvider {
        OidcIdentityProvider::new(TEMPLATE, [AUDIENCE.to_string()])
            .with_es256_pem(Some(KID.to_string()), ES256_PUBLIC_PEM)
            .expect("public key parses")
    }

    fn tenant_claims(iss: &str, tid: &str) -> serde_json::Value {
        serde_json::json!({
            "iss": iss,
            "aud": AUDIENCE,
            "sub": "pairwise-subject",
            "tid": tid,
            "exp": now() + 3600,
            "iat": now(),
        })
    }

    #[test]
    fn a_tenant_token_authenticates_against_its_own_issuer() {
        let idp = tenant_provider();
        let iss = format!("https://login.microsoftonline.com/{TENANT}/v2.0");
        let token = mint(&tenant_claims(&iss, TENANT));
        assert_eq!(
            idp.authenticate(&token),
            Some(AuthorityId::new("pairwise-subject"))
        );
    }

    #[test]
    fn a_second_tenant_authenticates_against_the_same_template() {
        // The point of a multi-tenant authority: no tenant is enumerated, and
        // admitting one does not admit it *instead* of the others.
        let idp = tenant_provider();
        let iss = format!("https://login.microsoftonline.com/{OTHER_TENANT}/v2.0");
        assert!(idp
            .authenticate(&mint(&tenant_claims(&iss, OTHER_TENANT)))
            .is_some());
    }

    #[test]
    fn an_issuer_naming_a_different_tenant_than_tid_is_rejected() {
        // The whole substitution rule in one assertion. `iss` and `tid` are both
        // in the signed payload, so a token can carry a mismatched pair; the
        // expected issuer is built from `tid`, so `iss` must agree with it.
        let idp = tenant_provider();
        let iss = format!("https://login.microsoftonline.com/{OTHER_TENANT}/v2.0");
        assert_eq!(idp.authenticate(&mint(&tenant_claims(&iss, TENANT))), None);
    }

    #[test]
    fn a_token_without_a_tenant_claim_is_rejected() {
        let idp = tenant_provider();
        let iss = format!("https://login.microsoftonline.com/{TENANT}/v2.0");
        let mut claims = tenant_claims(&iss, TENANT);
        claims.as_object_mut().expect("object").remove("tid");
        assert_eq!(idp.authenticate(&mint(&claims)), None);
    }

    #[test]
    fn a_tenant_that_is_not_a_guid_is_rejected() {
        // Each of these would be substituted verbatim into the expected issuer by
        // a rule that only did `replace`, handing the caller both sides of the
        // comparison. The last two are the ones that look harmless.
        let idp = tenant_provider();
        for tid in [
            "common",
            "../../accounts.google.com",
            "a/../b",
            "72f988bf86f141af91ab2d7cd011db47",
            "72f988bf-86f1-41af-91ab-2d7cd011db4",
            "72f988bf-86f1-41af-91ab-2d7cd011db47-",
            "72f988bf-86f1-41af-91ab-2d7cd011dbZZ",
            "",
        ] {
            let iss = TEMPLATE.replace(TENANT_PLACEHOLDER, tid);
            assert_eq!(
                idp.authenticate(&mint(&tenant_claims(&iss, tid))),
                None,
                "tenant {tid:?} must not be substituted"
            );
        }
    }

    #[test]
    fn an_issuer_that_merely_contains_the_authority_host_is_rejected() {
        // Every one of these passes a `starts_with`, an `ends_with`, or a
        // `contains` on the authority host. That is why the rule is equality
        // after substitution and not any of those three.
        let idp = tenant_provider();
        for iss in [
            "https://login.microsoftonline.com.evil.test/{tenantid}/v2.0",
            "https://evil.test/login.microsoftonline.com/{tenantid}/v2.0",
            "https://login.microsoftonline.com/{tenantid}/v2.0.evil.test",
            "https://login.microsoftonline.com/{tenantid}/v2.0/../../evil",
        ] {
            let iss = iss.replace(TENANT_PLACEHOLDER, TENANT);
            assert_eq!(
                idp.authenticate(&mint(&tenant_claims(&iss, TENANT))),
                None,
                "issuer {iss:?} must not be admitted"
            );
        }
    }

    #[test]
    fn a_non_templated_issuer_still_ignores_a_tenant_claim() {
        // A connection with one exact issuer must not acquire template behaviour
        // because a token happens to carry `tid`.
        let idp = provider();
        let mut claims = base_claims();
        claims["tid"] = serde_json::json!(TENANT);
        assert!(idp.authenticate(&mint(&claims)).is_some());

        claims["iss"] =
            serde_json::json!(format!("https://login.microsoftonline.com/{TENANT}/v2.0"));
        assert_eq!(idp.authenticate(&mint(&claims)), None);
    }

    #[test]
    fn a_declared_issuer_that_agrees_with_the_configuration_is_accepted() {
        assert_eq!(
            accepted_issuer("https://accounts.google.com", "https://accounts.google.com"),
            Some("https://accounts.google.com".to_string())
        );
    }

    #[test]
    fn a_tenant_template_at_the_same_origin_is_accepted() {
        assert_eq!(
            accepted_issuer(
                "https://login.microsoftonline.com/common/v2.0",
                "https://login.microsoftonline.com/{tenantid}/v2.0"
            ),
            Some("https://login.microsoftonline.com/{tenantid}/v2.0".to_string())
        );
    }

    #[test]
    fn a_declared_issuer_at_another_origin_is_refused() {
        // The regression this guard exists for: an administrator pinned an issuer,
        // and the document at it must not be able to name a different one — with or
        // without a template to dress it up.
        assert_eq!(
            accepted_issuer("https://idp.example.com", "https://evil.test"),
            None
        );
        assert_eq!(
            accepted_issuer(
                "https://login.microsoftonline.com/common/v2.0",
                "https://login.microsoftonline.com.evil.test/{tenantid}/v2.0"
            ),
            None
        );
        assert_eq!(
            accepted_issuer(
                "https://login.microsoftonline.com/common/v2.0",
                "http://login.microsoftonline.com/{tenantid}/v2.0"
            ),
            None,
            "a scheme downgrade is a different origin"
        );
    }

    #[test]
    fn a_differing_declaration_without_a_template_is_refused() {
        // Same origin, no template: the document simply disagrees with the pin, and
        // a disagreement is not a licence to follow it.
        assert_eq!(
            accepted_issuer(
                "https://login.microsoftonline.com/common/v2.0",
                "https://login.microsoftonline.com/other/v2.0"
            ),
            None
        );
    }

    #[test]
    fn same_origin_compares_scheme_host_and_port() {
        assert!(same_origin("https://a.test/x", "https://a.test/y?q=1"));
        assert!(!same_origin("https://a.test", "https://a.test:8443"));
        assert!(!same_origin("https://a.test", "https://a.test.evil"));
        assert!(!same_origin("https://a.test", "https://evil/a.test"));
        assert!(!same_origin("not-a-url", "not-a-url"));
    }

    #[test]
    fn issuer_matches_tenant_template_accepts_only_a_guid_member() {
        assert!(issuer_matches_tenant_template(
            TEMPLATE,
            &format!("https://login.microsoftonline.com/{TENANT}/v2.0")
        ));
        assert!(!issuer_matches_tenant_template(
            TEMPLATE,
            "https://login.microsoftonline.com/common/v2.0"
        ));
        assert!(!issuer_matches_tenant_template(
            TEMPLATE,
            "https://login.microsoftonline.com//v2.0"
        ));
        // A non-templated rule is plain equality.
        assert!(issuer_matches_tenant_template(ISSUER, ISSUER));
        assert!(!issuer_matches_tenant_template(
            ISSUER,
            "https://other.test"
        ));
    }

    #[test]
    fn wrong_audience_is_rejected() {
        let idp = provider();
        let mut claims = base_claims();
        claims["aud"] = serde_json::json!("some-other-client");
        assert_eq!(idp.authenticate(&mint(&claims)), None);
    }

    #[test]
    fn expired_token_is_rejected() {
        let idp = provider();
        let mut claims = base_claims();
        // well past the default leeway
        claims["exp"] = serde_json::json!(now() - 3600);
        assert_eq!(idp.authenticate(&mint(&claims)), None);
    }

    #[test]
    fn token_signed_by_an_unknown_key_is_rejected() {
        // A verifier that knows a *different* key id rejects our token (no kid match).
        let idp = OidcIdentityProvider::new(ISSUER, [AUDIENCE.to_string()])
            .with_es256_pem(Some("some-other-kid".to_string()), ES256_PUBLIC_PEM)
            .expect("public key parses");
        assert_eq!(idp.authenticate(&mint(&base_claims())), None);
    }

    #[test]
    fn verifier_with_no_keys_authenticates_nothing() {
        // Fail-closed: before any JWKS is loaded, no token authenticates.
        let idp = OidcIdentityProvider::new(ISSUER, [AUDIENCE.to_string()]);
        assert_eq!(idp.authenticate(&mint(&base_claims())), None);
    }

    #[test]
    fn garbage_credential_is_rejected() {
        let idp = provider();
        assert_eq!(idp.authenticate("not-a-jwt"), None);
        assert_eq!(idp.authenticate(""), None);
    }

    // A real RSA public key (n/e), JWKS form — generated for tests only.
    const JWK_N: &str = "w9y0Xl3WWXuEvGIVWyfqcnmH68H0C6WIxpejSHoRDcwnGj0LOY1LwZSIVJV6ercNOmcBc_gl3cqXHhN04kcoyAYGfV936dKwCRN7OGz-4F-5db1vIyAAcY37v-JelDLsq6iWLWFVJaWG0G5xHiPqlrlsyILU7nohEZxfSzKhuv7-oTdr4e3L30EksvAAeR-rzXT9Ww9hsBidVkq9kSAfyNVX0LTQ7KvrupLMoHuAPW23hu_SvtyWSZ48kSdQxUDu98a48pjQSDrMgP3blr5sh0NWsoPZysBN9p3eZKpl_bQNh7bg8L8azYLMLuRjxuYGyE6XcfWIUw1G81etmlkyeQ";
    const JWK_E: &str = "AQAB";

    #[test]
    fn with_jwks_loads_rsa_signing_keys() {
        let jwks = format!(
            r#"{{"keys":[{{"kty":"RSA","use":"sig","kid":"rsa-1","n":"{JWK_N}","e":"{JWK_E}"}}]}}"#
        );
        // A real OIDC verifier built purely from a JWKS document (the HTTP slice's
        // local parse): it has a usable key, so it is constructible.
        let idp = OidcIdentityProvider::new(ISSUER, [AUDIENCE.to_string()])
            .with_jwks(&jwks)
            .expect("JWKS with an RSA signing key loads");
        // A token signed by an unrelated (ES256) key still fails — the JWKS keys are
        // real, not a bypass.
        assert_eq!(idp.authenticate(&mint(&base_claims())), None);
    }

    #[test]
    fn with_jwks_skips_encryption_keys_and_rejects_empty() {
        // An `enc`-use key is skipped → no usable signing key → error.
        let enc_only =
            format!(r#"{{"keys":[{{"kty":"RSA","use":"enc","n":"{JWK_N}","e":"{JWK_E}"}}]}}"#);
        assert!(OidcIdentityProvider::new(ISSUER, [AUDIENCE.to_string()])
            .with_jwks(&enc_only)
            .is_err());
        // No `keys` array / malformed → error.
        assert!(OidcIdentityProvider::new(ISSUER, [AUDIENCE.to_string()])
            .with_jwks("{}")
            .is_err());
        assert!(OidcIdentityProvider::new(ISSUER, [AUDIENCE.to_string()])
            .with_jwks("not json")
            .is_err());
    }

    /// A canned-response HTTP double, keyed by URL.
    struct MockHttp(BTreeMap<String, String>);
    impl HttpGet for MockHttp {
        fn get(&self, url: &str) -> Result<String, String> {
            self.0.get(url).cloned().ok_or_else(|| format!("404 {url}"))
        }
    }

    #[test]
    fn discovery_follows_jwks_uri_then_loads_keys() {
        let mut routes = BTreeMap::new();
        routes.insert(
            format!("{ISSUER}/.well-known/openid-configuration"),
            r#"{"issuer":"x","jwks_uri":"https://idp.example.com/keys"}"#.to_string(),
        );
        let jwks = format!(
            r#"{{"keys":[{{"kty":"RSA","use":"sig","kid":"rsa-1","n":"{JWK_N}","e":"{JWK_E}"}}]}}"#
        );
        routes.insert("https://idp.example.com/keys".to_string(), jwks.clone());
        let http = MockHttp(routes);

        let fetched = discover_jwks(ISSUER, &http).expect("discovery + jwks fetch");
        assert_eq!(fetched, jwks);
        // The fetched JWKS loads into a real verifier.
        OidcIdentityProvider::new(ISSUER, [AUDIENCE.to_string()])
            .with_jwks(&fetched)
            .expect("discovered JWKS loads");
    }

    #[test]
    fn discovery_without_jwks_uri_errors() {
        let mut routes = BTreeMap::new();
        routes.insert(
            format!("{ISSUER}/.well-known/openid-configuration"),
            r#"{"issuer":"x"}"#.to_string(),
        );
        assert!(discover_jwks(ISSUER, &MockHttp(routes)).is_err());
    }

    #[test]
    fn discover_endpoints_parses_authorization_token_and_jwks() {
        let mut routes = BTreeMap::new();
        routes.insert(
            format!("{ISSUER}/.well-known/openid-configuration"),
            r#"{"issuer":"x","authorization_endpoint":"https://idp.example.com/authorize",
                "token_endpoint":"https://idp.example.com/token",
                "jwks_uri":"https://idp.example.com/keys"}"#
                .to_string(),
        );
        let eps = discover_endpoints(ISSUER, &MockHttp(routes)).expect("discovery");
        assert_eq!(
            eps.authorization_endpoint,
            "https://idp.example.com/authorize"
        );
        assert_eq!(eps.token_endpoint, "https://idp.example.com/token");
        assert_eq!(eps.jwks_uri, "https://idp.example.com/keys");
    }

    /// A mock token endpoint that records the posted fields and returns a canned response.
    struct MockForm {
        seen: std::sync::Mutex<Vec<(String, String)>>,
        response: String,
    }
    impl HttpForm for MockForm {
        fn post_form(&self, _url: &str, fields: &[(&str, &str)]) -> Result<String, String> {
            *self.seen.lock().unwrap() = fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            Ok(self.response.clone())
        }
    }

    #[test]
    fn exchange_code_posts_pkce_grant_and_returns_the_id_token() {
        let mock = MockForm {
            seen: std::sync::Mutex::new(vec![]),
            response: r#"{"access_token":"at","id_token":"the.id.token","token_type":"Bearer"}"#
                .to_string(),
        };
        let (id_token, refresh) = exchange_code(
            "https://idp.example.com/token",
            "client-1",
            "http://localhost/cb",
            "auth-code-xyz",
            "pkce-verifier-abc",
            None,
            &mock,
        )
        .expect("exchange");
        assert_eq!(id_token, "the.id.token");
        assert!(refresh.is_none(), "no refresh_token in this response");
        // The PKCE auth-code grant was posted with the verifier (so an intercepted code is
        // useless without it).
        let seen = mock.seen.lock().unwrap();
        let has = |k: &str, v: &str| seen.iter().any(|(a, b)| a == k && b == v);
        assert!(has("grant_type", "authorization_code"));
        assert!(has("code", "auth-code-xyz"));
        assert!(has("code_verifier", "pkce-verifier-abc"));
        assert!(has("redirect_uri", "http://localhost/cb"));
    }

    #[test]
    fn exchange_code_without_an_id_token_errors() {
        // A token response missing id_token (e.g. an OAuth2-only response) is rejected.
        let mock = MockForm {
            seen: std::sync::Mutex::new(vec![]),
            response: r#"{"access_token":"at","token_type":"Bearer"}"#.to_string(),
        };
        assert!(exchange_code("u", "c", "r", "code", "v", None, &mock).is_err());
    }

    #[test]
    fn exchange_code_captures_a_refresh_token_when_present() {
        // An offline-access grant returns a refresh_token alongside the id_token (ADR 0077).
        let mock = MockForm {
            seen: std::sync::Mutex::new(vec![]),
            response:
                r#"{"id_token":"the.id.token","refresh_token":"rt-abc","token_type":"Bearer"}"#
                    .to_string(),
        };
        let (id, rt) = exchange_code("u", "c", "r", "code", "v", None, &mock).expect("exchange");
        assert_eq!(id, "the.id.token");
        assert_eq!(rt.as_deref(), Some("rt-abc"));
    }

    #[test]
    fn refresh_id_token_posts_the_refresh_grant_and_returns_a_fresh_id_token() {
        let mock = MockForm {
            seen: std::sync::Mutex::new(vec![]),
            response: r#"{"id_token":"fresh.id.token","token_type":"Bearer"}"#.to_string(),
        };
        let tok = refresh_id_token(
            "https://idp.example.com/token",
            "client-1",
            Some("the-secret"),
            "rt-abc",
            &mock,
        )
        .expect("refresh");
        assert_eq!(tok, "fresh.id.token");
        let seen = mock.seen.lock().unwrap();
        let has = |k: &str, v: &str| seen.iter().any(|(a, b)| a == k && b == v);
        assert!(has("grant_type", "refresh_token"));
        assert!(has("refresh_token", "rt-abc"));
        assert!(has("client_secret", "the-secret"));
    }

    #[test]
    fn pkce_challenge_is_s256_of_verifier() {
        let p = Pkce::generate().unwrap();
        assert_eq!(p.challenge, s256_challenge(&p.verifier));
        // RFC 7636 test vector: verifier → known S256 challenge.
        assert_eq!(
            s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_ne!(
            Pkce::generate().unwrap().verifier,
            Pkce::generate().unwrap().verifier
        );
    }

    #[test]
    fn authorize_url_carries_pkce_and_encodes() {
        let url = authorize_url(
            "https://idp.example.com/authorize",
            "client-1",
            "https://app.example.com/cb",
            "openid email",
            "xyz",
            "NONCE",
            "CHAL",
            "&access_type=offline",
        );
        assert!(url.contains("code_challenge=CHAL"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("scope=openid%20email")); // space encoded
        assert!(url.contains("redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"));
        assert!(url.ends_with("&access_type=offline")); // extra params appended
    }

    #[test]
    fn authorize_url_carries_nonce() {
        // The nonce goes on the authorize request so the id-token can be bound back to
        // this browser login (OIDC replay/injection defense).
        let url = authorize_url(
            "https://idp.example.com/authorize",
            "client-1",
            "https://app.example.com/cb",
            "openid email",
            "state-xyz",
            "nonce-abc",
            "CHAL",
            "",
        );
        assert!(url.contains("nonce=nonce-abc"));
    }

    #[test]
    fn unknown_authority_gets_fail_closed_default_claims() {
        // claims() for an authority that never authenticated → most-restrictive default.
        let idp = provider();
        let attrs = idp.claims(&AuthorityId::new("ghost"));
        assert_eq!(attrs, AuthorityAttributes::default());
        assert!(attrs.roles.is_empty());
    }
}
