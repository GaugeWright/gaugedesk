//! Outbound Home availability adapter for ADR 0116.
//!
//! This process parks a role-aware leg at the shared blind broker, terminates
//! the end-to-end pinned TLS session as the Home, and pipes it only to the
//! co-resident control-plane listener. It owns no work authority beyond what
//! that control plane already enforces.

use std::path::PathBuf;

use gaugedesk_relay_transport::{serve_home_forever, RelayRoute, RouteProof, TlsIdentity};

#[tokio::main]
async fn main() {
    let endpoint = required("GAUGEDESK_HOME_RELAY_ENDPOINT");
    let local_control_plane = required("GAUGEDESK_HOME_RELAY_LOCAL")
        .parse()
        .expect("GAUGEDESK_HOME_RELAY_LOCAL must be host:port");
    let handle = required("GAUGEDESK_HOME_RELAY_HANDLE");
    let epoch = required("GAUGEDESK_HOME_RELAY_EPOCH")
        .parse()
        .expect("GAUGEDESK_HOME_RELAY_EPOCH must be a positive integer");
    let proof = RouteProof::from_base64url(&required("GAUGEDESK_HOME_RELAY_PROOF"))
        .expect("GAUGEDESK_HOME_RELAY_PROOF must contain 32 base64url bytes");
    let previous_proof = gaugedesk_env::var("HOME_RELAY_PREVIOUS_PROOF")
        .map(|value| RouteProof::from_base64url(&value))
        .transpose()
        .expect("GAUGEDESK_HOME_RELAY_PREVIOUS_PROOF must contain 32 base64url bytes");
    let identity_directory = PathBuf::from(required("GAUGEDESK_HOME_RELAY_IDENTITY_DIR"));
    let identity =
        TlsIdentity::load_or_generate(&identity_directory).expect("load Home relay TLS identity");
    let fingerprint = identity.fingerprint();
    eprintln!(
        "[home-relay] endpoint={endpoint} local={local_control_plane} tls_pin={}",
        hex::encode(fingerprint)
    );
    let route = RelayRoute {
        endpoint,
        handle,
        epoch,
        proof,
        previous_proof,
        home_fingerprint: fingerprint,
    };
    serve_home_forever(route, local_control_plane, identity)
        .await
        .expect("Home relay availability loop");
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}
