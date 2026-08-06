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
    if let Some(endpoint) = configured_relay_endpoint() {
        let local = listener.local_addr()?;
        let directory = root.join("relay");
        let identity = gaugedesk_relay_transport::TlsIdentity::load_or_generate(&directory)?;
        let config =
            gaugedesk_relay_transport::HomeRelayConfig::load_or_mint(&directory, &endpoint)?;
        let route = config.relay_route(&identity)?;
        eprintln!(
            "[home-relay] supervised endpoint={} epoch={} tls_pin={}",
            config.endpoint,
            config.route_epoch,
            gaugedesk_relay_transport::HomeRelayConfig::fingerprint_hex(&identity),
        );
        tokio::spawn(async move {
            if let Err(error) =
                gaugedesk_relay_transport::serve_home_forever(route, local, identity).await
            {
                eprintln!("[home-relay] availability loop stopped: {error}");
            }
        });
    }
    axum::serve(listener, open_control_plane(wb)).await
}

pub(crate) fn configured_relay_endpoint() -> Option<String> {
    gaugedesk_env::var("HOME_RELAY_ENDPOINT")
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
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
