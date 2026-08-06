//! Full-stack SAML (M3 ID-2): the Rust `SamlSidecarIdentityProvider` driving the
//! **real** node verify sidecar over a committed signed fixture — proving the
//! spawn + stdin/stdout JSON marshalling + mapping across the real process boundary.
//!
//! Gated: skips cleanly when `node` or the sidecar's `node_modules` are absent (the
//! cargo gate does not `npm install` the sidecar; CI's web/sidecar lane does). The
//! sidecar's own crypto correctness is covered by `ee/sidecar/saml-verify/test`; the
//! Rust adapter logic by the `identity_saml` unit tests. This closes the seam between
//! them.

use std::path::PathBuf;

use gaugedesk_app::identity::IdentityProvider;
use gaugedesk_core::abac::Role;
use gaugedesk_core::ids::AuthorityId;
use gaugedesk_ee::identity_saml::{SamlClaimMapping, SamlSidecarIdentityProvider};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sidecar_available() -> bool {
    let node = std::process::Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    node && repo_root()
        .join("ee/sidecar/saml-verify/node_modules")
        .exists()
}

fn provider(idp_cert: &str, audience: &str) -> SamlSidecarIdentityProvider {
    let verify = repo_root().join("ee/sidecar/saml-verify/verify.mjs");
    SamlSidecarIdentityProvider::new(
        vec!["node".to_string(), verify.display().to_string()],
        idp_cert,
        audience,
    )
    .with_mapping(SamlClaimMapping {
        roles_attribute: Some("roles".into()),
        region_attribute: Some("region".into()),
        tenant_attribute: None,
    })
}

fn fixture() -> serde_json::Value {
    let path = repo_root().join("ee/app/tests/fixtures/saml/valid-response.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture present")).unwrap()
}

#[test]
fn rust_adapter_verifies_a_real_signed_response_through_the_sidecar() {
    if !sidecar_available() {
        eprintln!("skipping: node / sidecar node_modules not available");
        return;
    }
    let fx = fixture();
    let cert = fx["idp_cert"].as_str().unwrap();
    let audience = fx["audience"].as_str().unwrap();
    let response = fx["saml_response"].as_str().unwrap();

    let idp = provider(cert, audience);
    let authority = idp
        .authenticate(response)
        .expect("the committed signed fixture authenticates through the real sidecar");
    assert_eq!(authority, AuthorityId::new("alice@acme.com"));
    let attrs = idp.claims(&authority);
    assert!(attrs.roles.contains(&Role::admin()));
    assert!(attrs.roles.contains(&Role::member()));
}

#[test]
fn rust_adapter_rejects_when_conditions_do_not_hold() {
    if !sidecar_available() {
        eprintln!("skipping: node / sidecar node_modules not available");
        return;
    }
    let fx = fixture();
    let cert = fx["idp_cert"].as_str().unwrap();
    let response = fx["saml_response"].as_str().unwrap();

    // The assertion is signed for audience "gaugewright-sp"; an SP expecting a
    // different audience must reject it (AudienceRestriction mismatch) — the real
    // sidecar says ok:false and the adapter yields no authority (fail-closed across
    // the wire). A genuinely valid signature is not enough if the conditions fail.
    let idp = provider(cert, "a-different-sp-entity-id");
    assert_eq!(idp.authenticate(response), None);
}

#[test]
fn rust_adapter_rejects_a_replayed_assertion_through_the_real_sidecar() {
    if !sidecar_available() {
        eprintln!("skipping: node / sidecar node_modules not available");
        return;
    }
    let fx = fixture();
    let cert = fx["idp_cert"].as_str().unwrap();
    let audience = fx["audience"].as_str().unwrap();
    let response = fx["saml_response"].as_str().unwrap();

    // The same genuinely-signed assertion presented twice: the first consumes its
    // id, the second is a replay the adapter refuses (single-use, INV-20) — proven
    // across the real process boundary, not just the mock.
    let idp = provider(cert, audience);
    assert_eq!(
        idp.authenticate(response),
        Some(AuthorityId::new("alice@acme.com")),
        "first presentation authenticates"
    );
    assert_eq!(
        idp.authenticate(response),
        None,
        "the replayed assertion is rejected"
    );
}
