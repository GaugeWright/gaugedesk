//! Live SAML verification harness (M3 `ID-4`, the SAML side) — runs the **real**
//! [`SamlSidecarIdentityProvider`] against a genuine IdP's signed **SAML Response** +
//! signing cert, so connecting a real SAML IdP (Keycloak / Okta / Entra ID / Auth0) is
//! a single command rather than new code. The verifier exercised here is byte-for-byte
//! the one the control plane authenticates SAML logins with.
//!
//! `#[ignore]`d: it needs a live IdP's material, supplied via env, so the normal
//! `cargo test` path never reaches the outside world (and it needs `node` + the
//! sidecar's `node_modules`). The `scripts/keycloak-saml-check.sh` harness mints a real
//! Keycloak assertion (no vendor signup) and feeds it here; a real vendor works the
//! same way — capture a signed `SAMLResponse` and the IdP's cert, then:
//!
//! ```text
//!   export SAML_RESPONSE="$(…base64 SAMLResponse from the IdP POST…)"
//!   export SAML_IDP_CERT="$(…the IdP signing cert, PEM…)"
//!   export SAML_AUDIENCE=<the SP entity id the assertion is scoped to>
//!   export SAML_ROLES_ATTR=roles        # optional: the attribute carrying roles
//!   cargo test -p gaugedesk-app --test saml_live -- --ignored --nocapture
//! ```

use std::path::PathBuf;

use gaugedesk_app::identity::IdentityProvider;
use gaugedesk_ee::identity_saml::{SamlClaimMapping, SamlSidecarIdentityProvider};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn env_or_skip(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => {
            eprintln!("SKIP saml_live: ${key} is unset — supply a live IdP's material (see the file header).");
            None
        }
    }
}

fn provider(cert: &str, audience: &str, roles_attr: Option<String>) -> SamlSidecarIdentityProvider {
    let verify = repo_root().join("ee/sidecar/saml-verify/verify.mjs");
    SamlSidecarIdentityProvider::new(
        vec!["node".to_string(), verify.display().to_string()],
        cert,
        audience,
    )
    .with_mapping(SamlClaimMapping {
        roles_attribute: roles_attr,
        region_attribute: std::env::var("SAML_REGION_ATTR").ok(),
        tenant_attribute: std::env::var("SAML_TENANT_ATTR").ok(),
    })
}

#[test]
#[ignore = "needs a live SAML IdP's signed Response + cert via env (M3 ID-4)"]
fn a_real_idp_saml_response_verifies_through_our_seam() {
    let (Some(response), Some(cert), Some(audience)) = (
        env_or_skip("SAML_RESPONSE"),
        env_or_skip("SAML_IDP_CERT"),
        env_or_skip("SAML_AUDIENCE"),
    ) else {
        return;
    };
    let roles_attr = std::env::var("SAML_ROLES_ATTR")
        .ok()
        .filter(|s| !s.trim().is_empty());

    // The whole point: the real verifier admits a genuine IdP's signed assertion.
    let idp = provider(&cert, &audience, roles_attr);
    let authority = idp.authenticate(&response).unwrap_or_else(|| {
        panic!(
            "the real SAML Response did NOT verify against audience={audience} — check the \
             assertion is signed, its AudienceRestriction contains the SP entity id, its \
             Conditions window is current, and SAML_IDP_CERT is the IdP's signing cert"
        )
    });

    let attrs = idp.claims(&authority);
    println!("saml_live: VERIFIED ✔");
    println!("  audience  = {audience}");
    println!("  authority = {authority:?}");
    println!("  roles     = {:?}", attrs.roles);
    println!("  region    = {:?}", attrs.region);
    println!("  tenant    = {:?}", attrs.affiliation);

    // Fail-closed (`INV-20`): the same genuinely-signed assertion presented to an SP
    // expecting a *different* audience must be rejected — a valid signature is not
    // enough if the AudienceRestriction does not match (a fresh provider instance, so
    // this is not a single-use replay of the call above).
    let wrong = provider(&cert, "a-different-sp-entity-id", None);
    assert_eq!(
        wrong.authenticate(&response),
        None,
        "an assertion scoped to another SP must not verify here"
    );
    println!("  fail-closed on audience mismatch ✔");
}
