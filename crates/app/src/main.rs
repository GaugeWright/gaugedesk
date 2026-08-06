//! gaugewright control-plane binary. Opens (or initializes) the local decision + workspace stores
//! instance under `.gaugewright/` and serves the co-resident HTTP control plane on
//! loopback.

#[tokio::main]
async fn main() {
    // Observability (RF-A8): a fmt subscriber gated by `RUST_LOG` (warn by
    // default). Engine turns, admission, and runtime calls emit operational spans
    // and events — metadata only (scope ids, phases, counts), never protected
    // content. Set e.g. `RUST_LOG=gaugedesk_app=info,gaugedesk_whip_runtime=info`.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let root = gaugedesk_app::open_api::open_control_plane_root();
    // The bind address is `GAUGEDESK_ADDR` (default loopback `127.0.0.1:7878`). A
    // multi-machine deployment runs two instances on distinct ports/roots, each
    // with its own `GAUGEDESK_AUTHORITY` identity (D-REMOTE / `SERVE-1`).
    let addr = gaugedesk_env::var("ADDR").unwrap_or_else(|| "127.0.0.1:7878".to_string());
    gaugedesk_app::open_api::open_serve(&addr, &root)
        .await
        .expect("serve open control plane");
}
