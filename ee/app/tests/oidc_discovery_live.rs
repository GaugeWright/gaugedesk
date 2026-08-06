//! Live OIDC **discovery** verification (M3 `ID-3` HTTP leg) — proves the real shared
//! [`net_http::HttpClient`] satisfies the `HttpGet` seam end-to-end: it fetches the
//! issuer's `.well-known/openid-configuration`, follows `jwks_uri`, and returns the JWKS
//! over real HTTP, which then verifies a genuine id-token. Unlike `oidc_live` (which is
//! handed a pasted JWKS), this exercises the literal network client + `discover_jwks`.
//!
//! `#[ignore]`d: needs a live issuer. `scripts/keycloak-oidc-check.sh` runs it against the
//! self-hosted Keycloak (no external dependency, no creds) — closing the "needs a live OP"
//! half of `ID-3` locally.

use gaugedesk_app::identity::IdentityProvider;
use gaugedesk_app::net_http::HttpClient;
use gaugedesk_ee::identity_oidc::{discover_jwks, ClaimMapping, OidcIdentityProvider};

fn env_or_skip(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => {
            eprintln!(
                "SKIP oidc_discovery_live: ${key} unset (run via scripts/keycloak-oidc-check.sh)"
            );
            None
        }
    }
}

#[test]
#[ignore = "needs a live OIDC issuer over HTTP (M3 ID-3); run via scripts/keycloak-oidc-check.sh"]
fn discovers_jwks_over_real_http_then_verifies_a_token() {
    let (Some(issuer), Some(audience), Some(token)) = (
        env_or_skip("OIDC_ISSUER"),
        env_or_skip("OIDC_AUDIENCE"),
        env_or_skip("OIDC_TOKEN"),
    ) else {
        return;
    };

    // The real network client + discovery: well-known -> jwks_uri -> JWKS, over HTTP.
    let http = HttpClient::new();
    let jwks = discover_jwks(&issuer, &http)
        .expect("discover_jwks should fetch the issuer's JWKS over real HTTP");
    println!("discovered JWKS ({} bytes) from {issuer}", jwks.len());

    let idp = OidcIdentityProvider::new(issuer.clone(), [audience])
        .with_mapping(ClaimMapping {
            roles_claim: std::env::var("OIDC_ROLES_CLAIM").ok(),
            ..ClaimMapping::default()
        })
        .with_jwks(&jwks)
        .expect("the discovered JWKS parses into a usable signing key");

    let authority = idp
        .authenticate(&token)
        .expect("a genuine id-token verifies against the discovered JWKS");
    println!("discovery + verify OK ✔  authority = {authority:?}");

    // Fail-closed sanity: a tampered token must not verify under the discovered keys.
    assert!(
        idp.authenticate(&format!("{token}x")).is_none(),
        "a tampered token must fail closed (INV-20)"
    );
}
