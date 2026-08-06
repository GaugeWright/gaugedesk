//! GaugeDesk self-hosted Administration server (ADR 0121, `ee/` capability set).
//!
//! The AGPL enterprise composition: the shared local control plane
//! plus the org governance surface (SSO/OIDC/SAML sign-in, SCIM, RBAC, audit,
//! admin) behind the ENTSEC-1 enterprise auth middleware — and nothing managed:
//! no embed host, no settlement, no attested operator routes. This is the
//! binary an enterprise runs itself; the GaugeWright-operated equivalent is
//! `gaugewright-cloud-server` (private cloud repo), which layers the managed
//! planes on the same shared substrate.
//!
//! Run: `GAUGEWRIGHT_ADDR=127.0.0.1:7878 gaugewright-enterprise-server`
//! (same env contract as the open binary: `GAUGEWRIGHT_ROOT`, loopback
//! fail-closed bind guard, `GAUGEWRIGHT_ALLOW_NETWORK_HTTP`/`GAUGEWRIGHT_TLS_TERMINATED`
//! opt-ins for proxied deployments).

use gaugewright_app::open_api::open_control_plane_root;
use gaugewright_app::open_runtime::open_listener;
use gaugewright_app::{open_workbench, LockUnpoisoned};

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let root = open_control_plane_root();
    let addr =
        gaugewright_store::process_env::var("ADDR").unwrap_or_else(|| "127.0.0.1:7878".to_string());

    let wb = open_workbench(&root).expect("open workbench");
    gaugewright_app::federation::respawn_restored_receivers(&wb);
    {
        let guard = wb.lock_unpoisoned();
        println!(
            "gaugewright authority `{}` governance key {}",
            guard.authority().as_str(),
            guard.governance_public_key().as_str(),
        );
    }
    // `enterprise_control_plane` activates any persisted IdP configuration
    // (SSO) before building the router.
    let app = gaugewright_ee::org_routes::enterprise_control_plane(wb);
    let listener = open_listener(&addr).await.expect("bind enterprise server");
    println!("gaugewright enterprise control plane listening on http://{addr}");
    axum::serve(listener, app)
        .await
        .expect("serve enterprise control plane");
}
