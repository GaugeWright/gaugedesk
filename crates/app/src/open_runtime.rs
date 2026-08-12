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
    let local = listener.local_addr()?;
    tokio::spawn(supervise_home_reachability(
        wb.clone(),
        local,
        root.to_path_buf(),
        configured_relay_endpoint(),
    ));
    axum::serve(listener, open_control_plane(wb)).await
}

/// One parked relay leg and the tasks that keep it current.
struct ParkedLeg {
    availability: tokio::task::JoinHandle<()>,
    rotation: tokio::task::JoinHandle<()>,
}

impl ParkedLeg {
    /// Stop dialing and let the leg go. The relay drops a leg whose socket
    /// closes, so releasing the tasks is the whole of it.
    fn release(self) {
        self.availability.abort();
        self.rotation.abort();
    }
}

/// Keep this Home's reachability equal to the person's publication choice, for
/// as long as it runs (ADR 0131 §6).
///
/// **This used to be read once, at startup, and that was the whole bug.**
/// Everything that parks a leg and authors a route sat inside `if publishes`,
/// evaluated before the server began serving — so switching publishing on in the
/// Account panel changed nothing until the app was restarted, and nothing said
/// so. A person who turned it on saw a Home that stayed unreachable; DESK-7's
/// production canary saw a Home that never authored a locator, because it
/// enabled the facility (as a person would) *after* the control plane came up.
///
/// So it reconciles rather than decides: on every signal it compares the choice
/// against what is actually parked and moves one to match the other. That also
/// covers the paths a handler hook would miss, because the check is on the
/// state, not on the event that changed it.
///
/// The endpoint is resolved by the caller rather than read here, so a test can
/// supervise against a hermetic relay without reaching for a process-wide
/// environment variable.
pub(crate) async fn supervise_home_reachability(
    wb: crate::SharedWorkbench,
    local: std::net::SocketAddr,
    root: std::path::PathBuf,
    endpoint: Option<String>,
) {
    let Some(endpoint) = endpoint else {
        return;
    };
    let changed = wb.lock_unpoisoned().publication_changed();
    let mut parked: Option<ParkedLeg> = None;
    loop {
        // Read and release: this is a std mutex, and holding it across the wait
        // below would stop every request this Home serves.
        let publishes = wb.lock_unpoisoned().library_sync_active();
        match (publishes, parked.is_some()) {
            (true, false) => match start_home_relay(&wb, local, &root, &endpoint) {
                Ok(leg) => parked = Some(leg),
                // Said, not swallowed: a Home that cannot park is unreachable,
                // and the person asked for the opposite.
                Err(error) => eprintln!("[home-relay] could not park a leg: {error}"),
            },
            (false, true) => {
                if let Some(leg) = parked.take() {
                    leg.release();
                }
                // Withdraw the pointers with the leg. `author_home_routes`
                // tombstones every route this Home claims once it reports no
                // reachability, so a client that already holds a locator learns
                // it is dead rather than dialing a leg that is gone.
                let retracted = wb
                    .lock_unpoisoned()
                    .author_home_routes(&crate::home_reachability::HomeReachability::default());
                eprintln!("[home-relay] publishing off — {retracted} route(s) retracted");
            }
            _ => {}
        }
        changed.notified().await;
    }
}

/// Park a leg for this Home and publish where it is.
fn start_home_relay(
    wb: &crate::SharedWorkbench,
    local: std::net::SocketAddr,
    root: &std::path::Path,
    endpoint: &str,
) -> std::io::Result<ParkedLeg> {
    let directory = root.join("relay");
    let identity = gaugedesk_relay_transport::TlsIdentity::load_or_generate(&directory)?;
    let config = gaugedesk_relay_transport::HomeRelayConfig::load_or_mint(&directory, endpoint)?;
    eprintln!(
        "[home-relay] supervised endpoint={} epoch={} tls_pin={}",
        config.endpoint,
        config.route_epoch,
        gaugedesk_relay_transport::HomeRelayConfig::fingerprint_hex(&identity),
    );
    // The parked leg is this Home's current reachability, so the published set
    // should say so before the first client ever resolves a project.
    let parked = config.relay_route(&identity)?;
    crate::home_reachability::republish(wb, &parked);
    let (routes, route_reader) = tokio::sync::watch::channel(parked);
    let rotation_identity = identity.clone();
    let rotation_directory = directory.clone();
    let rotation_workbench = wb.clone();
    let rotation = tokio::spawn(async move {
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
                // Republish before the parked leg is superseded, so the window
                // where a client holds only the dead epoch is as short as we can
                // make it.
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
    let availability = tokio::spawn(async move {
        if let Err(error) =
            gaugedesk_relay_transport::serve_home_supervised(route_reader, local, identity).await
        {
            eprintln!("[home-relay] availability loop stopped: {error}");
        }
    });
    Ok(ParkedLeg {
        availability,
        rotation,
    })
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

#[cfg(test)]
mod reachability_tests {
    use super::*;
    use crate::account::{Account, RecordOp};
    use crate::facility::{FacilityKind, FacilityOwner, FacilityRecord, FacilityStatus};
    use gaugedesk_relay_transport::test_relay::TestRelay;

    fn publication(status: FacilityStatus) -> FacilityRecord {
        FacilityRecord {
            id: "library-sync".to_owned(),
            op: crate::facility::RecordOp::Upsert,
            kind: FacilityKind::LibrarySync,
            owner: FacilityOwner::Person,
            status,
            display_name: "publication".to_owned(),
            config: serde_json::Value::Null,
        }
    }

    /// Every route this Home currently claims as live, with a relay locator.
    fn live_locators(wb: &crate::SharedWorkbench) -> usize {
        let guard = wb.lock_unpoisoned();
        let home = guard.home_id().clone();
        Account::rebuild(guard.store_ref())
            .map(|account| {
                account
                    .home_routes
                    .values()
                    .filter(|route| {
                        route.home_id == home
                            && route.op != RecordOp::Tombstone
                            && route.relay.is_some()
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    async fn settle(wb: &crate::SharedWorkbench, want: usize) -> bool {
        for _ in 0..200 {
            if live_locators(wb) == want {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        false
    }

    /// The defect DESK-7's production canary found, as a test.
    ///
    /// Publication was read once, before the server began serving, so turning it
    /// on afterwards — which is the only way a person ever turns it on — parked
    /// no leg and authored no route. The Home stayed unreachable and said
    /// nothing. Everything here happens while the supervisor is already running,
    /// because that is the case that was broken.
    #[tokio::test]
    async fn publishing_makes_a_running_home_reachable_and_unpublishing_retracts_it() {
        let relay = TestRelay::bind().await.expect("relay");
        let root = tempfile::tempdir().expect("root");
        let wb = crate::open_workbench(root.path()).expect("workbench");
        let local = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback")
            .local_addr()
            .expect("addr");

        let supervisor = tokio::spawn(supervise_home_reachability(
            wb.clone(),
            local,
            root.path().to_path_buf(),
            Some(relay.endpoint().to_owned()),
        ));

        // Signed out and not publishing: a local-first install dials nowhere,
        // and must keep doing so (ADR 0131 §6).
        assert!(
            settle(&wb, 0).await,
            "a Home that publishes nothing authored a locator anyway",
        );

        wb.lock_unpoisoned()
            .upsert_account_facility(&publication(FacilityStatus::Active))
            .expect("attach publication");
        assert!(
            settle(&wb, 1).await,
            "publishing was turned on and the running Home never authored a locator",
        );

        wb.lock_unpoisoned()
            .revoke_account_facility("library-sync")
            .expect("revoke publication");
        // Retracted, not merely stopped: a client holding a locator has to learn
        // it is dead rather than dial a leg that is gone.
        assert!(
            settle(&wb, 0).await,
            "publishing was turned off and the route stayed live",
        );

        supervisor.abort();
    }
}
