//! Live OIDC verification harness (M3 `ID-4`) — runs the **real**
//! [`OidcIdentityProvider`] against a genuine IdP's id-token + JWKS, so connecting
//! a real tenant (Okta / Microsoft Entra ID / Google Workspace) is a single
//! command rather than new code. The verifier exercised here is byte-for-byte the
//! one the control plane authenticates SSO logins with.
//!
//! It is `#[ignore]`d: it needs a live tenant's material, supplied via env, so the
//! normal `cargo test` green path never reaches the outside world. It needs **no
//! HTTP client** — you paste the JWKS (the discovery GET is the separate `ID-3`
//! remainder), so this proves the *verification* half end-to-end against real keys.
//!
//! Run (Okta example — the org's default authorization server):
//! ```text
//!   export OIDC_ISSUER=https://dev-XXXXXX.okta.com/oauth2/default
//!   export OIDC_AUDIENCE=<the app's client id>
//!   export OIDC_JWKS="$(curl -s "$OIDC_ISSUER/v1/keys")"
//!   export OIDC_TOKEN=<a real id-token from that tenant>
//!   export OIDC_ROLES_CLAIM=roles        # optional: the custom claim carrying roles
//!   cargo test -p gaugedesk-app --test oidc_live -- --ignored --nocapture
//! ```
//! Entra ID: issuer `https://login.microsoftonline.com/<tenant-id>/v2.0`, JWKS from
//! its `/.well-known/openid-configuration` → `jwks_uri`, roles claim `roles` or
//! `groups`. Google Workspace: issuer `https://accounts.google.com`, JWKS
//! `https://www.googleapis.com/oauth2/v3/certs`.

use gaugedesk_app::identity::IdentityProvider;
use gaugedesk_ee::identity_oidc::{ClaimMapping, OidcIdentityProvider};

/// Read an env var, or skip the test (return `None`) with a one-line reason when the
/// harness is run without a live tenant configured.
fn env_or_skip(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => {
            eprintln!("SKIP oidc_live: ${key} is unset — supply a live tenant's material (see the file header).");
            None
        }
    }
}

#[test]
#[ignore = "needs a live IdP tenant's id-token + JWKS via env (M3 ID-4)"]
fn a_real_idp_id_token_verifies_through_our_seam() {
    let (Some(issuer), Some(audience), Some(jwks), Some(token)) = (
        env_or_skip("OIDC_ISSUER"),
        env_or_skip("OIDC_AUDIENCE"),
        env_or_skip("OIDC_JWKS"),
        env_or_skip("OIDC_TOKEN"),
    ) else {
        return;
    };

    let mapping = ClaimMapping {
        subject_claim: std::env::var("OIDC_SUBJECT_CLAIM").unwrap_or_else(|_| "sub".into()),
        roles_claim: std::env::var("OIDC_ROLES_CLAIM").ok(),
        region_claim: std::env::var("OIDC_REGION_CLAIM").ok(),
        tenant_claim: std::env::var("OIDC_TENANT_CLAIM").ok(),
    };

    let idp = OidcIdentityProvider::new(issuer.clone(), [audience.clone()])
        .with_mapping(mapping)
        .with_jwks(&jwks)
        .expect("the pasted JWKS should parse into at least one RSA signing key");

    // The whole point: the real verifier admits a genuine tenant token, fail-closed.
    let authority = idp.authenticate(&token).unwrap_or_else(|| {
        panic!(
            "the real id-token did NOT verify against issuer={issuer} audience={audience} \
             — check the token is fresh (exp), its `aud` matches the client id, its `iss` \
             matches OIDC_ISSUER exactly, and the JWKS is the issuer's current keys"
        )
    });

    let attrs = idp.claims(&authority);
    println!("oidc_live: VERIFIED ✔");
    println!("  issuer    = {issuer}");
    println!("  authority = {authority:?}");
    println!("  roles     = {:?}", attrs.roles);
    println!("  region    = {:?}", attrs.region);
    println!("  tenant    = {:?}", attrs.affiliation);
    println!("  clearance = {:?}", attrs.clearance);

    // A garbled token under the same verifier must fail-closed (INV-20) — proves the
    // success above was the signature, not a permissive verifier.
    let tampered = format!("{token}x");
    assert!(
        idp.authenticate(&tampered).is_none(),
        "a tampered token must NOT verify (fail-closed, INV-20)"
    );
    println!("  fail-closed on tampered token ✔");
}
