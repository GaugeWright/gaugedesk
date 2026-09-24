//! Live Entra ID conformance for the consumer Microsoft entrance (DR-0189).
//!
//! The unit tests beside the code prove the *rule*: a templated issuer is
//! admitted by substituting the token's own tenant and then demanding exact
//! equality, and nothing else is. They prove it against tokens this repository
//! mints, which means they prove it against this repository's belief about what
//! Entra does. This file checks that belief against Entra.
//!
//! Three of those beliefs are load-bearing, and each is a silent failure if it
//! is wrong:
//!
//! - the `common` authority declares its issuer as a **tenant template**, so the
//!   accepted issuer has to come from discovery rather than from configuration;
//! - that document's `jwks_uri` lives at the **authority**, not at the template,
//!   so keys are fetched through the authority and the template is only ever the
//!   thing `iss` is compared against; and
//! - Entra attests **no verified email** — there is no `email_verified` claim —
//!   which is the entire reason the Microsoft signup proves its address with a
//!   code instead of taking DR-0177's one-click path.
//!
//! The first two would break the entrance loudly. The third would not: if Entra
//! began attesting addresses, `EmailProof::EmailedCode` would keep asking for a
//! code that is no longer needed, forever, and nothing would say so. That is why
//! it is a conformance assertion and not a comment.
//!
//! **What needs credentials and what does not.** The first three tests need only
//! network: they read Entra's own published metadata and keys. They are the half
//! worth running on a cadence, because what they watch is a vendor changing
//! under us. The last two need a genuine id-token from a real tenant
//! (`ENTRA_ID_TOKEN` + `ENTRA_CLIENT_ID`) and skip without one, in the manner of
//! `ee/app/tests/oidc_discovery_live.rs`.
//!
//! `#[ignore]`d, because live-provider suites stay outside `scripts/check.sh`.
//! Run them with `scripts/entra-oidc-check.sh`.

use gaugedesk_app::identity::IdentityProvider;
use gaugedesk_app::identity_oidc::{
    accepted_issuer, discover_endpoints, issuer_matches_tenant_template, refresh_id_token,
    substitute_tenant, ClaimMapping, HttpGet, OidcIdentityProvider, TENANT_PLACEHOLDER,
};
use gaugedesk_app::net_http::HttpClient;

/// The authority the consumer Microsoft entrance discovers and authorizes
/// through. Spelled out rather than read from `auth_oidc::CONSUMER_MICROSOFT`,
/// so that a change to the table is a change this file disagrees with out loud
/// instead of one it silently follows to a different vendor endpoint.
const COMMON_AUTHORITY: &str = "https://login.microsoftonline.com/common/v2.0";

/// A real Microsoft tenant guid (the one Microsoft publishes for its own
/// tenant), used only as a well-formed value to substitute. Nothing here
/// authenticates against it.
const A_REAL_TENANT: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";

fn env_or_skip(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => {
            eprintln!("SKIP entra_live: ${key} unset (run via scripts/entra-oidc-check.sh)");
            None
        }
    }
}

/// Claims of a token, read without verification. Only for asserting *about* a
/// token in this file; nothing here treats the result as authenticated.
fn unverified_claims(token: &str) -> serde_json::Map<String, serde_json::Value> {
    let payload = token.split('.').nth(1).expect("a JWT has three segments");
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
        .expect("the payload segment is base64url");
    serde_json::from_slice(&bytes).expect("the payload is JSON")
}

#[test]
#[ignore = "reads Entra's live metadata; run via scripts/entra-oidc-check.sh"]
fn entra_common_declares_a_tenant_template_that_our_rule_admits() {
    let http = HttpClient::new();
    let endpoints = discover_endpoints(COMMON_AUTHORITY, &http)
        .expect("Entra's common discovery document is reachable and complete");

    println!("declared issuer = {}", endpoints.issuer);
    assert!(
        endpoints.issuer.contains(TENANT_PLACEHOLDER),
        "Entra's common authority must declare a tenant-templated issuer; it declared {} \
         (if Microsoft now declares a concrete issuer, DR-0189 §2's substitution rule is \
         no longer needed for this authority and the entrance should be simplified)",
        endpoints.issuer
    );

    // The reason the accepted issuer cannot come from configuration: the thing a
    // token must claim is not the thing we discovered through.
    assert_ne!(
        endpoints.issuer, COMMON_AUTHORITY,
        "the declared issuer and the authority are different strings, which is what \
         made comparing them to each other a bug"
    );

    // The rule, against the vendor's real declaration.
    assert_eq!(
        accepted_issuer(COMMON_AUTHORITY, &endpoints.issuer).as_deref(),
        Some(endpoints.issuer.as_str()),
        "the guarded rule must admit Entra's own declaration"
    );

    // And a concrete tenant issuer is a member of the family it declared.
    let concrete = substitute_tenant(&endpoints.issuer, A_REAL_TENANT)
        .expect("a real tenant guid substitutes into the declared template");
    assert_eq!(
        concrete,
        format!("https://login.microsoftonline.com/{A_REAL_TENANT}/v2.0")
    );
    assert!(issuer_matches_tenant_template(&endpoints.issuer, &concrete));
}

#[test]
#[ignore = "reads Entra's live keys; run via scripts/entra-oidc-check.sh"]
fn entras_keys_are_published_at_the_authority_and_load_into_the_verifier() {
    let http = HttpClient::new();
    let endpoints = discover_endpoints(COMMON_AUTHORITY, &http).expect("discovery");

    // The key set is published under the authority, not under the template — so
    // the template is only ever compared against, never fetched from. A change
    // here is what would break key rotation for this entrance.
    assert!(
        !endpoints.jwks_uri.contains(TENANT_PLACEHOLDER),
        "the declared jwks_uri must be concrete, got {}",
        endpoints.jwks_uri
    );
    println!("jwks_uri = {}", endpoints.jwks_uri);

    let jwks = http
        .get(&endpoints.jwks_uri)
        .expect("Entra's key set is reachable");

    // Entra publishes RSA signing keys with no `alg`, which the verifier is
    // expected to default to RS256. That default is the reason this loads at all,
    // and it is asserted here against the real document rather than a fixture.
    let provider =
        OidcIdentityProvider::new(endpoints.issuer.clone(), ["unused-audience".to_string()])
            .with_mapping(ClaimMapping::default())
            .with_jwks(&jwks)
            .expect("Entra's published key set parses into usable signing keys");

    // Fail-closed with real keys: nothing about having Microsoft's keys makes a
    // non-token verify.
    assert!(
        provider.authenticate("not-a-token").is_none(),
        "garbage must fail closed against live keys (INV-20)"
    );
}

#[test]
#[ignore = "reads Entra's live metadata; run via scripts/entra-oidc-check.sh"]
fn entra_still_attests_no_verified_email() {
    // The premise of DR-0189 §4, checked against the vendor rather than
    // remembered. A failure here is good news that needs acting on: Entra would
    // be attesting addresses, and the Microsoft entrance could take DR-0177's
    // one-click path like Google's instead of sending a code.
    let http = HttpClient::new();
    let raw = http
        .get(&format!(
            "{COMMON_AUTHORITY}/.well-known/openid-configuration"
        ))
        .expect("Entra's common discovery document is reachable");
    let document: serde_json::Value =
        serde_json::from_str(&raw).expect("the discovery document is JSON");
    let claims: Vec<&str> = document
        .get("claims_supported")
        .and_then(|value| value.as_array())
        .expect("the document advertises claims_supported")
        .iter()
        .filter_map(|value| value.as_str())
        .collect();
    println!("claims_supported = {claims:?}");

    assert!(
        claims.contains(&"tid"),
        "the tenant claim the substitution rule reads must be advertised"
    );
    assert!(
        !claims.contains(&"email_verified"),
        "Entra now advertises email_verified — revisit DR-0189 §4, which sends an \
         emailed code precisely because it did not"
    );
}

#[test]
#[ignore = "needs a genuine Entra id-token; run via scripts/entra-oidc-check.sh"]
fn a_real_entra_id_token_verifies_against_the_declared_template() {
    let (Some(token), Some(client_id)) = (
        env_or_skip("ENTRA_ID_TOKEN"),
        env_or_skip("ENTRA_CLIENT_ID"),
    ) else {
        return;
    };
    let http = HttpClient::new();
    let endpoints = discover_endpoints(COMMON_AUTHORITY, &http).expect("discovery");
    let jwks = http.get(&endpoints.jwks_uri).expect("live key set");

    let provider = OidcIdentityProvider::new(endpoints.issuer.clone(), [client_id.clone()])
        .with_mapping(ClaimMapping::default())
        .with_jwks(&jwks)
        .expect("live key set parses");

    let authority = provider
        .authenticate(&token)
        .expect("a genuine Entra id-token verifies against the declared template");
    println!("verified ✔  authority = {authority:?}");

    // What the token actually claimed, now that it is verified: the concrete
    // issuer must be this token's own tenant substituted into the template. This
    // is the property durable links key on (DR-0189 §3).
    let claims = unverified_claims(&token);
    let tid = claims
        .get("tid")
        .and_then(|value| value.as_str())
        .expect("a real Entra token carries tid");
    let iss = claims
        .get("iss")
        .and_then(|value| value.as_str())
        .expect("a real Entra token carries iss");
    assert_eq!(
        substitute_tenant(&endpoints.issuer, tid).as_deref(),
        Some(iss),
        "the token's issuer is its own tenant substituted into the declared template"
    );
    assert_ne!(
        iss, endpoints.issuer,
        "a real token claims a concrete issuer, never the template"
    );

    // Fail-closed against live keys.
    assert!(
        provider.authenticate(&format!("{token}x")).is_none(),
        "a tampered token must fail closed (INV-20)"
    );
}

#[test]
#[ignore = "needs a genuine Entra id-token; run via scripts/entra-oidc-check.sh"]
fn the_pre_dr_0189_pin_and_a_foreign_tenant_both_refuse_a_real_token() {
    let (Some(token), Some(client_id)) = (
        env_or_skip("ENTRA_ID_TOKEN"),
        env_or_skip("ENTRA_CLIENT_ID"),
    ) else {
        return;
    };
    let http = HttpClient::new();
    let endpoints = discover_endpoints(COMMON_AUTHORITY, &http).expect("discovery");
    let jwks = http.get(&endpoints.jwks_uri).expect("live key set");

    // The behaviour that shipped before DR-0189: one exact issuer, taken from
    // configuration. Against a real token it refuses — which is the evidence
    // that the substitution rule is what makes this entrance work at all, rather
    // than an elaboration on something that already did.
    let pinned_to_authority = OidcIdentityProvider::new(COMMON_AUTHORITY, [client_id.clone()])
        .with_mapping(ClaimMapping::default())
        .with_jwks(&jwks)
        .expect("live key set parses");
    assert!(
        pinned_to_authority.authenticate(&token).is_none(),
        "a verifier pinned to the authority string cannot admit a real tenant's token"
    );

    // And the cross-tenant property with a real signature behind it: pinning the
    // concrete issuer of a tenant that did not issue this token refuses it, even
    // though the token is genuine and signed by the same authority's keys.
    let claims = unverified_claims(&token);
    let tid = claims
        .get("tid")
        .and_then(|value| value.as_str())
        .expect("tid");
    let foreign = if tid == A_REAL_TENANT {
        "9188040d-6c67-4c5b-b112-36a304b66dad"
    } else {
        A_REAL_TENANT
    };
    let pinned_to_foreign_tenant = OidcIdentityProvider::new(
        substitute_tenant(&endpoints.issuer, foreign).expect("substitutes"),
        [client_id],
    )
    .with_mapping(ClaimMapping::default())
    .with_jwks(&jwks)
    .expect("live key set parses");
    assert!(
        pinned_to_foreign_tenant.authenticate(&token).is_none(),
        "a genuine token from one tenant must not verify against another tenant's issuer"
    );
}

#[test]
#[ignore = "needs a genuine Entra refresh token; run via scripts/entra-oidc-check.sh"]
fn a_real_entra_refresh_token_renews_through_the_hubs_own_refresh() {
    // The session-refresh leg, exactly as the hub runs it: `refresh_id_token`,
    // which sends no `scope`, and which fails the refresh unless the response
    // carries an id-token. The Microsoft entrance first shipped asking Entra for
    // no refresh token at all, so this leg had never been reached for Microsoft;
    // whether Entra answers a scope-less refresh with an id-token is a fact
    // about the vendor, and this is where it is checked rather than assumed.
    let (Some(refresh_token), Some(client_id)) = (
        env_or_skip("ENTRA_REFRESH_TOKEN"),
        env_or_skip("ENTRA_CLIENT_ID"),
    ) else {
        return;
    };
    let http = HttpClient::new();
    let endpoints = discover_endpoints(COMMON_AUTHORITY, &http).expect("discovery");

    // A public client, so no secret — the conformance registration holds none.
    let fresh = refresh_id_token(
        &endpoints.token_endpoint,
        &client_id,
        None,
        &refresh_token,
        &http,
    )
    .expect("Entra answers the hub's scope-less refresh with an id-token");

    let jwks = http.get(&endpoints.jwks_uri).expect("live key set");
    let provider = OidcIdentityProvider::new(endpoints.issuer.clone(), [client_id])
        .with_mapping(ClaimMapping::default())
        .with_jwks(&jwks)
        .expect("live key set parses");
    assert!(
        provider.authenticate(&fresh).is_some(),
        "the refreshed id-token verifies against the declared template, as the first one did"
    );
    println!(
        "refresh ✔  a fresh id-token ({} chars) verified",
        fresh.len()
    );
}
