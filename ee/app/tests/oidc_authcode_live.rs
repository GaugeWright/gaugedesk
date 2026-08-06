//! Live OIDC **auth-code + PKCE** verification (M3 `ID-3`) — the last leg: given an
//! authorization `code` captured from a real browser login plus the matching PKCE
//! verifier, redeem it at the OP token endpoint via the real [`exchange_code`] +
//! [`net_http::HttpClient`], then verify the returned id-token. Driven against the
//! self-hosted Keycloak (the browser login is automated through it). `#[ignore]`d; the
//! code is single-use and short-lived, so it runs immediately after capture.

use gaugedesk_app::identity::IdentityProvider;
use gaugedesk_app::net_http::HttpClient;
use gaugedesk_ee::identity_oidc::{
    discover_jwks, exchange_code, ClaimMapping, OidcIdentityProvider,
};

fn env_or_skip(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => {
            eprintln!("SKIP oidc_authcode_live: ${key} unset (needs a browser-captured auth code)");
            None
        }
    }
}

#[test]
#[ignore = "needs a browser-captured auth code + PKCE verifier (M3 ID-3)"]
fn auth_code_exchanges_for_a_token_that_verifies() {
    let (
        Some(issuer),
        Some(token_endpoint),
        Some(code),
        Some(verifier),
        Some(client_id),
        Some(redirect),
    ) = (
        env_or_skip("OIDC_ISSUER"),
        env_or_skip("OIDC_TOKEN_ENDPOINT"),
        env_or_skip("OIDC_CODE"),
        env_or_skip("OIDC_PKCE_VERIFIER"),
        env_or_skip("OIDC_CLIENT_ID"),
        env_or_skip("OIDC_REDIRECT_URI"),
    )
    else {
        return;
    };

    let http = HttpClient::new();

    // Redeem the code with the PKCE verifier — the real token exchange.
    let (id_token, _refresh_token) = exchange_code(
        &token_endpoint,
        &client_id,
        &redirect,
        &code,
        &verifier,
        None,
        &http,
    )
    .expect("auth-code + PKCE token exchange against the live OP");
    println!("token exchange OK ({} char id_token)", id_token.len());

    // Verify the returned id-token through the same discovery + verifier path.
    let jwks = discover_jwks(&issuer, &http).expect("discover JWKS");
    let idp = OidcIdentityProvider::new(issuer, [client_id])
        .with_mapping(ClaimMapping {
            roles_claim: std::env::var("OIDC_ROLES_CLAIM").ok(),
            ..ClaimMapping::default()
        })
        .with_jwks(&jwks)
        .expect("JWKS loads");
    let authority = idp
        .authenticate(&id_token)
        .expect("the exchanged id-token verifies");
    println!("auth-code + PKCE flow VERIFIED ✔  authority = {authority:?}");
}
