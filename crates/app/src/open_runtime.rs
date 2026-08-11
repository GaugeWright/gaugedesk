//! Open-source runtime root resolution and serving helpers.

use crate::{federation, open_control_plane, open_workbench, LockUnpoisoned};

/// Resolve the directory the open control plane roots its decision and workspace stores in.
pub fn open_control_plane_root() -> std::path::PathBuf {
    if let Some(root) = gaugedesk_env::var_os("ROOT") {
        return std::path::PathBuf::from(root);
    }
    if let Some(dirs) = directories::ProjectDirs::from("dev", "gaugewright", "gaugewright") {
        return dirs.data_dir().to_path_buf();
    }
    std::path::PathBuf::from(".gaugewright")
}

/// Bootstrap and serve the open local control plane on `addr`.
pub async fn open_serve(addr: &str, root: &std::path::Path) -> std::io::Result<()> {
    let wb = open_workbench(root)?;
    federation::respawn_restored_receivers(&wb);
    {
        let guard = wb.lock_unpoisoned();
        println!(
            "gaugewright authority `{}` governance key {}",
            guard.authority().as_str(),
            guard.governance_public_key().as_str(),
        );
    }
    let listener = open_listener(addr).await?;
    // Reachability follows the person's publication choice (ADR 0131 §6): a Home
    // that publishes nothing does not park a leg either, so a local-first,
    // signed-out install still dials nowhere.
    let publishes = wb.lock_unpoisoned().library_sync_active();
    if let (Some(endpoint), true) = (configured_relay_endpoint(), publishes) {
        let local = listener.local_addr()?;
        let directory = root.join("relay");
        let identity = gaugedesk_relay_transport::TlsIdentity::load_or_generate(&directory)?;
        let config =
            gaugedesk_relay_transport::HomeRelayConfig::load_or_mint(&directory, &endpoint)?;
        eprintln!(
            "[home-relay] supervised endpoint={} epoch={} tls_pin={}",
            config.endpoint,
            config.route_epoch,
            gaugedesk_relay_transport::HomeRelayConfig::fingerprint_hex(&identity),
        );
        // Reconcile at startup: the parked leg is this Home's current
        // reachability, so the published set should say so before the first
        // client ever resolves a project (ADR 0131 §6).
        let parked = config.relay_route(&identity)?;
        crate::home_reachability::republish(&wb, &parked);
        let (routes, route_reader) = tokio::sync::watch::channel(parked);
        let rotation_identity = identity.clone();
        let rotation_directory = directory.clone();
        let rotation_workbench = wb.clone();
        tokio::spawn(async move {
            let mut current = config;
            loop {
                tokio::time::sleep(HOME_RELAY_ROTATION).await;
                let rotated = match current.rotate(&rotation_directory) {
                    Ok(rotated) => rotated,
                    Err(error) => {
                        eprintln!("[home-relay] rotation failed: {error}");
                        continue;
                    }
                };
                match rotated.relay_route(&rotation_identity) {
                    // Republish before the parked leg is superseded, so the
                    // window where a client holds only the dead epoch is as
                    // short as we can make it.
                    Ok(route) => {
                        crate::home_reachability::republish(&rotation_workbench, &route);
                        if routes.send(route).is_err() {
                            return;
                        }
                        current = rotated;
                    }
                    Err(error) => eprintln!("[home-relay] rotated route invalid: {error}"),
                }
            }
        });
        tokio::spawn(async move {
            if let Err(error) =
                gaugedesk_relay_transport::serve_home_supervised(route_reader, local, identity)
                    .await
            {
                eprintln!("[home-relay] availability loop stopped: {error}");
            }
        });
    }
    axum::serve(listener, open_control_plane(wb)).await
}

/// The canonical blind rendezvous origin, matching the default federation and
/// enrollment already use. A Home needs no configuration to become reachable —
/// only a person's choice to publish (ADR 0131 §6).
pub const DEFAULT_HOME_RELAY_ENDPOINT: &str = "wss://relay.gaugewright.com";

/// How often a parked Home advances its route proof. Rotation is cheap and
/// invalidates any locator that leaked; clients recover by re-reading the route
/// once (ADR 0131 §5).
pub(crate) const HOME_RELAY_ROTATION: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);

/// Where this Home parks its leg. An explicit endpoint wins; `off` disables
/// reachability entirely for an operator who wants a Home that is only ever
/// reached at a known address.
pub(crate) fn configured_relay_endpoint() -> Option<String> {
    match gaugedesk_env::var("HOME_RELAY_ENDPOINT") {
        Some(value) if value.trim().eq_ignore_ascii_case("off") => None,
        Some(value) if !value.trim().is_empty() => Some(value.trim().to_owned()),
        _ => Some(DEFAULT_HOME_RELAY_ENDPOINT.to_owned()),
    }
}

/// Bind the local control-plane listener with the fail-closed loopback guard
/// (systemfd hot-reload aware). Public so band-specific serve shells (e.g. the
/// ee/ self-hosted enterprise server) share one guarded bind path.
pub async fn open_listener(addr: &str) -> std::io::Result<tokio::net::TcpListener> {
    let mut listenfd = listenfd::ListenFd::from_env();
    match listenfd.take_tcp_listener(0)? {
        Some(std_listener) => {
            std_listener.set_nonblocking(true)?;
            let listener = tokio::net::TcpListener::from_std(std_listener)?;
            let bound = listener
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| addr.to_string());
            println!(
                "gaugewright open control plane listening on http://{bound} (systemfd socket)"
            );
            Ok(listener)
        }
        None => {
            let opted_in = gaugedesk_env::enabled("ALLOW_NETWORK_HTTP");
            let tls_acked = gaugedesk_env::enabled("TLS_TERMINATED");
            open_check_loopback_bind(addr, opted_in, tls_acked)?;
            let listener = tokio::net::TcpListener::bind(addr).await?;
            println!("gaugewright open control plane listening on http://{addr}");
            Ok(listener)
        }
    }
}

/// Fail-closed network guard for the open local HTTP API.
pub(crate) fn open_check_loopback_bind(
    addr: &str,
    opted_in: bool,
    tls_acked: bool,
) -> std::io::Result<()> {
    let Ok(parsed) = addr.parse::<std::net::SocketAddr>() else {
        return Ok(());
    };
    if parsed.ip().is_loopback() {
        return Ok(());
    }
    if !opted_in {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to bind the open control-plane HTTP API to non-loopback {addr}: set \
                 GAUGEDESK_ALLOW_NETWORK_HTTP=1 to override behind a trusted network boundary."
            ),
        ));
    }
    if !tls_acked {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to bind the open control-plane HTTP API to non-loopback {addr}: front \
                 it with a TLS-terminating reverse proxy and set GAUGEDESK_TLS_TERMINATED=1."
            ),
        ));
    }
    eprintln!(
        "[gaugewright] WARNING: open control-plane HTTP API bound to non-loopback {addr} via \
         GAUGEDESK_ALLOW_NETWORK_HTTP=1. A TLS-terminating proxy MUST front it."
    );
    Ok(())
}
