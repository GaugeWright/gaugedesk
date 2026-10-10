//! Open-source runtime root resolution and serving helpers.

use crate::{federation, open_control_plane, open_workbench, LockUnpoisoned};

/// The window's loopback port. Every request on it acts as one account: the
/// selected account's session, or the computer's local account when signed
/// out, each reaching only the projects it owns or was granted
/// (DR-0268, DR-0328). No account owns the computer, so no selection is
/// refused here. The relay uses its own listener and its own admission.
/// The desktop serves this behind [`crate::local_operator::guard`], so only its
/// own window, holding the per-launch secret, reaches it at all (DR-0269).
///
/// The Home broker is added as a route, not merged in as a second router:
/// merging replaced the stack's CORS-layered fallback with a bare one, so a
/// route this Home does not serve answered `404` without
/// `Access-Control-Allow-Origin`. The window's `fetch` then rejected instead
/// of seeing the `404`, and the enterprise workbench read the absent
/// `/admin/placement-policy` — whose `404` is its "no organization governs
/// this" signal — as a governed plane whose policy could not be read, so
/// every engagement invite was refused for a personal account.
pub(crate) fn desktop_operator_plane(wb: crate::SharedWorkbench) -> axum::Router {
    let home_broker =
        axum::routing::any(crate::account_signin::proxy_selected_home).with_state(wb.clone());
    open_control_plane(wb.clone())
        .layer(axum::middleware::from_fn_with_state(
            wb.clone(),
            crate::project_owner::account_project_gate,
        ))
        .route("/account/hub-session/home/{home}/{*path}", home_broker)
        .layer(axum::Extension(crate::account_signin::DesktopOperatorPlane))
}

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
    open_serve_workbench(open_prepare(root)?, addr, root).await
}

/// Open the workbench [`open_serve`] would serve, so an in-process caller — the
/// desktop shell — can hold it beside the server (DR-0188).
pub fn open_prepare(root: &std::path::Path) -> std::io::Result<crate::SharedWorkbench> {
    let wb = open_workbench(root)?;
    federation::respawn_restored_receivers(&wb);
    // Say at startup what this computer will present for each retained
    // sign-in, so a window that opens signed out is explained by the log.
    crate::account_signin::log_retained_signins(&wb);
    Ok(wb)
}

/// Why the co-resident control plane stopped serving, in the words the person
/// at the desktop is shown. The webview reaches its control plane over HTTP, so
/// without this all it can say is that a request did not connect.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ControlPlaneFailure {
    /// `store_too_new`, `port_in_use`, or `failed`.
    pub kind: &'static str,
    pub message: String,
}

/// Describe the error [`open_prepare`] or [`open_serve_workbench_with`]
/// returned. `io::Error::source` skips the error it wraps, so the store's
/// refusal is looked for from `get_ref`.
pub fn control_plane_failure(error: &std::io::Error) -> ControlPlaneFailure {
    let wrapped = error
        .get_ref()
        .map(|inner| inner as &(dyn std::error::Error + 'static));
    if let Some(ahead) = wrapped.and_then(gaugedesk_store::SchemaAhead::of) {
        return ControlPlaneFailure {
            kind: "store_too_new",
            message: format!(
                "A newer version of GaugeDesk has already used the data on this computer, \
                 and this version cannot open it (data version {}; this version reads up to {}). \
                 Update GaugeDesk to continue. Nothing was changed.",
                ahead.found, ahead.supported
            ),
        };
    }
    if error.kind() == std::io::ErrorKind::AddrInUse {
        return ControlPlaneFailure {
            kind: "port_in_use",
            message: format!(
                "GaugeDesk could not start its local service because another program is using \
                 its address ({error}). Quit any other copy of GaugeDesk, then open it again."
            ),
        };
    }
    ControlPlaneFailure {
        kind: "failed",
        message: format!(
            "GaugeDesk's local service could not start: {error}. Quit GaugeDesk and open it again."
        ),
    }
}

/// Serve a workbench from [`open_prepare`] on `addr`, requiring the local
/// operator secret `GAUGEDESK_OPERATOR_SECRET` names, if it names one. The
/// desktop shell uses [`open_serve_workbench_with`] and its own secret.
pub async fn open_serve_workbench(
    wb: crate::SharedWorkbench,
    addr: &str,
    root: &std::path::Path,
) -> std::io::Result<()> {
    let secret =
        crate::local_operator::LocalOperatorSecret::from_env().map_err(std::io::Error::other)?;
    open_serve_workbench_with(wb, addr, root, secret).await
}

/// Serve a workbench on `addr`, refusing every request that does not carry
/// `secret` when there is one (DR-0269).
pub async fn open_serve_workbench_with(
    wb: crate::SharedWorkbench,
    addr: &str,
    root: &std::path::Path,
    secret: Option<crate::local_operator::LocalOperatorSecret>,
) -> std::io::Result<()> {
    {
        let guard = wb.lock_unpoisoned();
        println!(
            "gaugewright authority `{}` governance key {}",
            guard.federation_authority().as_str(),
            guard.governance_public_key().as_str(),
        );
    }
    let listener = open_listener(addr).await?;
    spawn_project_workflow_supervisor(wb.clone());
    // The relay leg gets a listener of its own, never this one: this is the
    // operator's channel, where a caller holding the window's secret (or, on a
    // headless server without one, any caller) is the operator, and the leg's
    // locator is public (DR-0206). That one admits only this
    // Home's owner, as the Hub names them.
    let crossings = serve_relay_crossings(
        wb.clone(),
        std::sync::Arc::new(crate::relay_route_stack::HubBearerAccounts::configured()),
    )
    .await?;
    tokio::spawn(supervise_home_reachability(
        wb.clone(),
        crossings,
        root.to_path_buf(),
        configured_relay_endpoint(),
    ));
    // `ConnectInfo` exposes the connection peer address to handlers so the SECAUD-8
    // failed-attempt throttle keeps a socket-peer fallback key below the edge (where no
    // `CF-Connecting-IP` is set). Harmless on the loopback/dev path; the hosted edge's
    // header is preferred when present.
    axum::serve(
        listener,
        crate::local_operator::guard(desktop_operator_plane(wb), secret)
            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
}

/// Serve what a relay crossing reaches, on a loopback listener of its own, and
/// return its address for the leg to splice to (DR-0206).
///
/// A separate listener rather than a separate route prefix because a crossing
/// arrives from loopback exactly like the desktop's own window does: nothing
/// in a request can tell the two apart, so the only sound separation is which
/// socket the leg connects to.
pub(crate) async fn serve_relay_crossings(
    wb: crate::SharedWorkbench,
    accounts: std::sync::Arc<dyn crate::relay_route_stack::BearerAccounts>,
) -> std::io::Result<std::net::SocketAddr> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    // The desktop's own broker reaches this Home here too (see
    // `account_signin::selected_home_transport`).
    wb.lock_unpoisoned().relay_crossings = Some(address);
    let router = crate::relay_route_stack::relay_control_plane(wb, accounts);
    tokio::spawn(async move {
        // With the peer address, as the operator's listener is served: the
        // handlers behind the relay router are the same ones, and some read it.
        let served = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
        if let Err(error) = served {
            tracing::warn!("[home-relay] the relay router stopped: {error}");
        }
    });
    Ok(address)
}

/// Drive this Home's launched folder whips for as long as it serves (DR-0191).
/// Outcomes are logged; the durable record of a run is its own native history.
/// Every composition that serves a Home calls this once, beside its router.
pub fn spawn_project_workflow_supervisor(wb: crate::SharedWorkbench) {
    use crate::project_workflow::{
        supervise_project_workflows, ProjectWorkflowLimits, ProjectWorkflowOutcome,
        ProjectWorkflowSupervisorConfig,
    };
    let (_stop, shutdown) = tokio::sync::watch::channel(false);
    let (notices, mut outcomes) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        // Held for the life of the task: dropping it would read as shutdown.
        let _stop = _stop;
        let config = ProjectWorkflowSupervisorConfig {
            limits: ProjectWorkflowLimits::PRODUCT,
            discovery_page_size: std::num::NonZeroUsize::new(64).expect("nonzero"),
            steps_per_wake: 8,
            sweep: std::time::Duration::from_secs(60),
        };
        if let Err(error) = supervise_project_workflows(wb, config, shutdown, notices).await {
            tracing::error!(%error, "project workflow supervisor stopped");
        }
    });
    tokio::spawn(async move {
        while let Some(notice) = outcomes.recv().await {
            match notice.outcome {
                ProjectWorkflowOutcome::NeedsAttention { detail } => {
                    tracing::warn!(scope = %notice.scope, %detail, "project workflow did not step")
                }
                outcome => tracing::debug!(scope = %notice.scope, ?outcome, "project workflow"),
            }
        }
    });
}

/// One parked relay leg and the tasks that keep it current.
struct ParkedLeg {
    availability: tokio::task::JoinHandle<()>,
    rotation: tokio::task::JoinHandle<()>,
    /// What this Home is currently reachable at, so the route set can be
    /// re-authored when the projects it serves change without the leg moving.
    /// It watches the same channel the availability loop dials on rather than
    /// holding a clone, because rotation replaces the route every 24 hours and
    /// re-authoring a superseded epoch would point every project at a locator
    /// the relay has already invalidated.
    route: tokio::sync::watch::Receiver<gaugedesk_relay_transport::RelayRoute>,
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
    crossings: std::net::SocketAddr,
    root: std::path::PathBuf,
    endpoint: Option<String>,
) {
    let Some(endpoint) = endpoint else {
        return;
    };
    let changed = wb.lock_unpoisoned().publication_changed();
    // A route is authored *per project*, so the set has to be re-authored when
    // the projects change and not only when reachability does — DESK-5a's
    // "re-authors on project create/relocate/delete". The library already
    // announces every such change on its own stream, so this listens rather
    // than adding a second signal beside it.
    let mut library = wb
        .lock_unpoisoned()
        .sender(crate::library::LIBRARY_SCOPE)
        .subscribe();
    let mut parked: Option<ParkedLeg> = None;
    loop {
        // An already claimed computer may need its library sync attachment
        // reconciled from state.
        match crate::first_home::attach_if_never_offered(&wb, &root) {
            Ok(true) => tracing::info!(
                "[first-home] library sync attached; this computer is now publishing its reachability"
            ),
            Ok(false) => {}
            Err(error) => tracing::warn!("first Home not attached: {error}"),
        }
        // What a claim gave its account is written down, so it outlives the
        // claim (DR-0309, DR-0313, WS-588). After the first pass this writes
        // nothing.
        match wb.lock_unpoisoned().settle_claimed_ownership() {
            Ok(0) => {}
            Ok(written) => eprintln!("[ownership] recorded the claimant on {written} records"),
            Err(error) => tracing::warn!("claimed ownership not recorded: {error}"),
        }
        // Each learner's GaugeWright-maintained Tutorials project (DR-0225).
        // After the first pass its source is only compared with this release.
        match wb.lock_unpoisoned().ensure_shipped_tutorials() {
            Ok(crate::shipped_tutorials::ShippedTutorials::Updated(_)) => {
                eprintln!("[tutorials] Tutorials projects now hold this release's source")
            }
            Ok(_) => {}
            Err(error) => tracing::warn!("shipped tutorials not reconciled: {error}"),
        }
        // Every project's Home-owned `tasks` tracker (DR-0199 §3); once each
        // exists this is one read per project.
        if let Err(error) = wb.lock_unpoisoned().ensure_project_tasks_trackers() {
            tracing::warn!("project tasks trackers not ensured: {error}");
        }
        // Read and release: this is a std mutex, and holding it across the wait
        // below would stop every request this Home serves.
        // Signing in makes this computer reachable for the account, with
        // nothing further to choose (DR-0359 §3), so any signed-in account
        // parks a leg as library sync does.
        let signed_in = !crate::account_signin::signed_in_accounts(&wb).is_empty();
        let publishes = signed_in || wb.lock_unpoisoned().library_sync_active();
        match (publishes, parked.is_some()) {
            (true, false) => match start_home_relay(&wb, crossings, &root, &endpoint) {
                Ok(leg) => parked = Some(leg),
                // Said, not swallowed: a Home that cannot park is unreachable,
                // and the person asked for the opposite.
                Err(error) => tracing::warn!("[home-relay] could not park a leg: {error}"),
            },
            (false, true) => {
                if let Some(leg) = parked.take() {
                    leg.release();
                }
                crate::federation::retract_all_home_routes(&wb);
                // Withdraw the pointers with the leg. `author_home_routes`
                // tombstones every route this Home claims once it reports no
                // reachability, so a client that already holds a locator learns
                // it is dead rather than dialing a leg that is gone.
                let retracted = wb
                    .lock_unpoisoned()
                    .author_home_routes(&crate::home_reachability::HomeReachability::default());
                tracing::info!("[home-relay] publishing off — {retracted} route(s) retracted");
            }
            _ => {}
        }
        // Re-author whenever the served set may have moved. `author_home_routes`
        // compares against what is already published and writes only the
        // difference, so running it more often than strictly needed costs a
        // comparison and never an event.
        if let Some(leg) = parked.as_ref() {
            let route = leg.route.borrow().clone();
            crate::home_reachability::republish(&wb, &route);
        }

        // Wait for something that can change the answer. The library stream
        // carries every workspace event, most of which cannot — a chat message
        // must not wake this.
        loop {
            tokio::select! {
                _ = changed.notified() => break,
                event = library.recv() => match event {
                    Ok(crate::stream::ServerEvent::WorkspaceChanged { record, .. })
                        if record == "project" => break,
                    Ok(_) => continue,
                    // A lagged receiver missed events it cannot name, so it
                    // reconciles rather than guessing which.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => break,
                    // Nothing will arrive here again; the publication signal is
                    // still live, so wait on that alone.
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        changed.notified().await;
                        break;
                    }
                },
            }
        }
    }
}

/// Park a leg for this Home and publish where it is.
fn start_home_relay(
    wb: &crate::SharedWorkbench,
    crossings: std::net::SocketAddr,
    root: &std::path::Path,
    endpoint: &str,
) -> std::io::Result<ParkedLeg> {
    let directory = root.join("relay");
    let identity = gaugedesk_relay_transport::TlsIdentity::load_or_generate(&directory)?;
    let config = gaugedesk_relay_transport::HomeRelayConfig::load_or_mint(&directory, endpoint)?;
    tracing::info!(
        "[home-relay] supervised endpoint={} epoch={} tls_pin={}",
        config.endpoint,
        config.route_epoch,
        gaugedesk_relay_transport::HomeRelayConfig::fingerprint_hex(&identity),
    );
    // The parked leg is this Home's current reachability, so the published set
    // should say so before the first client ever resolves a project.
    let parked = config.relay_route(&identity)?;
    crate::home_reachability::republish(wb, &parked);
    // And tell the account where this Home is, so desk can open it (DR-0183).
    crate::first_home::reconcile(wb, &parked);
    let (routes, route_reader) = tokio::sync::watch::channel(parked);
    let current = routes.subscribe();
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
                    tracing::warn!("[home-relay] rotation failed: {error}");
                    continue;
                }
            };
            match rotated.relay_route(&rotation_identity) {
                // Republish before the parked leg is superseded, so the window
                // where a client holds only the dead epoch is as short as we can
                // make it.
                Ok(route) => {
                    crate::home_reachability::republish(&rotation_workbench, &route);
                    // A published locator whose proof has rotated is a Home desk
                    // cannot reach, so the authority is told at the same moment
                    // the routes are re-authored (DR-0183 §4).
                    crate::first_home::reconcile(&rotation_workbench, &route);
                    if routes.send(route).is_err() {
                        return;
                    }
                    current = rotated;
                }
                Err(error) => tracing::warn!("[home-relay] rotated route invalid: {error}"),
            }
        }
    });
    let availability = tokio::spawn(async move {
        // A leg that cannot park leaves this computer unreachable while the app
        // looks entirely healthy — the state DR-0183 exists to end. The loop
        // reports the transitions, so this says the cause once per outage and
        // once again when it clears, rather than never or every ten seconds
        // (DR-0184).
        let outcome = gaugedesk_relay_transport::serve_home_supervised(
            route_reader,
            crossings,
            identity,
            |leg| match leg {
                Ok(epoch) => tracing::info!(
                    "[home-relay] leg parked at epoch {epoch} — this computer is reachable again"
                ),
                Err((epoch, error)) => tracing::warn!(
                    "[home-relay] cannot park a leg at epoch {epoch}, so desk cannot open this \
                     computer; retrying: {error}"
                ),
            },
        )
        .await;
        if let Err(error) = outcome {
            tracing::warn!("[home-relay] availability loop stopped: {error}");
        }
    });
    Ok(ParkedLeg {
        availability,
        rotation,
        route: current,
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

        // A project created *after* the leg parked must get a route too
        // (DESK-5a: re-author on project create). This is the step the
        // production canary stopped on: it enables publishing, then creates the
        // project it means to reach, and polled for a locator that was only
        // ever authored for the projects that existed when the leg went up.
        let before = live_locators(&wb);
        // Resolved before the write: `lock_unpoisoned` is a std mutex and taking
        // it twice in one expression deadlocks on itself.
        let home_id = wb.lock_unpoisoned().home_id().clone();
        wb.lock_unpoisoned()
            .write_project_record(crate::library::ProjectRecord {
                schema: crate::library::LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                id: "proj-after-parking".to_owned(),
                op: crate::library::RecordOp::Upsert,
                name: "created after the leg parked".to_owned(),
                is_default: false,
                home_id,
                network_isolated: false,
                run_purpose: None,
                deployment_mode: None,
            });
        assert!(
            settle(&wb, before + 1).await,
            "a project created after the leg parked never got a route",
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

    /// The locator this Home published for its one live route, as a client
    /// holding the account's directory record would read it.
    fn published_route(wb: &crate::SharedWorkbench) -> gaugedesk_relay_transport::RelayRoute {
        let guard = wb.lock_unpoisoned();
        let home = guard.home_id().clone();
        let account = Account::rebuild(guard.store_ref()).expect("account");
        let relay = account
            .home_routes
            .values()
            .find(|route| route.home_id == home && route.op != RecordOp::Tombstone)
            .and_then(|route| route.relay.clone())
            .expect("a published locator");
        let fingerprint: [u8; 32] = hex::decode(&relay.home_fingerprint)
            .expect("hex fingerprint")
            .try_into()
            .expect("32-byte fingerprint");
        gaugedesk_relay_transport::RelayRoute {
            endpoint: relay.endpoint,
            handle: relay.handle,
            epoch: relay.route_epoch,
            proof: gaugedesk_relay_transport::RouteProof::from_base64url(&relay.proof)
                .expect("proof"),
            previous_proof: None,
            home_fingerprint: fingerprint,
        }
    }

    /// One request carried over the relay, with whatever headers the caller
    /// chose. Answers the status and the whole response.
    async fn carried(
        address: std::net::SocketAddr,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("loopback");
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nhost: home\r\nidempotency-key: {method}{path}{}\r\n\
             content-length: 0\r\nconnection: close\r\n",
            headers.len(),
        );
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.expect("write");
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(20),
            stream.read_to_end(&mut response),
        )
        .await
        .expect("the crossing answered in time")
        .expect("read");
        let text = String::from_utf8_lossy(&response).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("no status line in {text:?}"));
        (status, text)
    }

    /// The Hub, as the relay router asks it: the bearers it recognises, and
    /// the one address the invitee's account holds verified.
    struct FakeHub;

    impl crate::relay_route_stack::BearerAccounts for FakeHub {
        fn account_for(&self, bearer: &str) -> Result<Option<String>, String> {
            Ok(match bearer {
                "owner-bearer" => Some("account-root".to_owned()),
                "someone-elses-bearer" => Some("someone-else".to_owned()),
                "invitee-bearer" => Some("invitee-account".to_owned()),
                "viewer-bearer" => Some("viewer-account".to_owned()),
                _ => None,
            })
        }

        fn email_standing(
            &self,
            bearer: &str,
            email: &str,
        ) -> Result<crate::account_identity::EmailStanding, String> {
            use crate::account_identity::EmailStanding;
            let Some(account) = self.account_for(bearer)? else {
                return Ok(EmailStanding::Unrecognised);
            };
            Ok(
                if (account == "invitee-account" && email == "invitee@example.test")
                    || (account == "viewer-account" && email == "viewer@example.test")
                {
                    EmailStanding::Holds { account }
                } else {
                    EmailStanding::DoesNotHold { account }
                },
            )
        }
    }

    /// A Home publishing a relay locator, signed in as its owner, and a client
    /// loopback that dials it through a test relay with the published locator.
    async fn reachable_home() -> (
        TestRelay,
        tempfile::TempDir,
        std::net::SocketAddr,
        Vec<tokio::task::JoinHandle<()>>,
    ) {
        let (relay, root, _wb, client, tasks) = reachable_home_and_workbench().await;
        (relay, root, client, tasks)
    }

    /// [`reachable_home`], with the Home's workbench.
    pub(super) async fn reachable_home_and_workbench() -> (
        TestRelay,
        tempfile::TempDir,
        crate::SharedWorkbench,
        std::net::SocketAddr,
        Vec<tokio::task::JoinHandle<()>>,
    ) {
        let relay = TestRelay::bind().await.expect("relay");
        let root = tempfile::tempdir().expect("root");
        let wb = crate::open_workbench(root.path()).expect("workbench");
        crate::account_signin::store_session_for_test(&wb);
        crate::home_owner::claim_if_never_claimed(&wb).expect("owner");
        let crossings = serve_relay_crossings(wb.clone(), std::sync::Arc::new(FakeHub))
            .await
            .expect("relay router");
        let supervisor = tokio::spawn(supervise_home_reachability(
            wb.clone(),
            crossings,
            root.path().to_path_buf(),
            Some(relay.endpoint().to_owned()),
        ));
        wb.lock_unpoisoned()
            .upsert_account_facility(&publication(FacilityStatus::Active))
            .expect("attach publication");
        assert!(
            settle(&wb, 2).await,
            "the Home published {} of 2 locators",
            live_locators(&wb),
        );
        let (client, carrier) =
            gaugedesk_relay_transport::bind_client_loopback(published_route(&wb))
                .await
                .expect("client loopback");
        (relay, root, wb, client, vec![supervisor, carrier])
    }

    /// DR-0206, end to end: a stranger who reads the published record, dials
    /// the leg and presents nothing reaches a Home that refuses them.
    ///
    /// Before this the leg spliced into the operator's own router, where a
    /// request with no credentials is the local operator: `POST
    /// /home/admissions` here answered `201 Created` to nobody at all.
    #[tokio::test]
    async fn a_stranger_over_the_relay_reaches_nothing_but_health() {
        let (_relay, _root, client, tasks) = reachable_home().await;
        let (status, body) = carried(client, "GET", "/health", &[]).await;
        assert_eq!(status, 200, "health is answered over the relay: {body}");
        for (method, path) in [
            ("POST", "/home/admissions"),
            ("GET", "/workspace"),
            ("POST", "/projects"),
        ] {
            let (status, body) = carried(client, method, path, &[]).await;
            assert_eq!(
                status, 401,
                "{method} {path} was served over the relay: {body}"
            );
        }
        let (status, body) = carried(
            client,
            "POST",
            "/home/admissions",
            &[("authorization", "Bearer forged")],
        )
        .await;
        assert_eq!(status, 401, "a bearer the Hub does not know: {body}");
        tasks.iter().for_each(|task| task.abort());
    }

    /// The owner, as the Hub names them, is admitted over the relay and works
    /// with the admission the Home mints — and only with it.
    #[tokio::test]
    async fn the_owner_over_the_relay_is_admitted_and_works() {
        let (_relay, _root, client, tasks) = reachable_home().await;
        let owner = [("authorization", "Bearer owner-bearer")];
        let (status, body) = carried(client, "POST", "/home/admissions", &owner).await;
        assert_eq!(status, 201, "the owner is admitted: {body}");
        let reply: serde_json::Value =
            serde_json::from_str(body.split("\r\n\r\n").nth(1).expect("a body")).expect("json");
        let admission = reply["admission"]
            .as_str()
            .expect("an admission")
            .to_owned();

        let (status, body) = carried(client, "GET", "/workspace", &owner).await;
        assert_eq!(status, 401, "a login bearer alone does no work: {body}");
        assert!(body.contains("target Home admission required"), "{body}");

        let admitted = [
            ("authorization", "Bearer owner-bearer"),
            ("x-gaugewright-home-admission", admission.as_str()),
        ];
        let (status, body) = carried(client, "GET", "/workspace", &admitted).await;
        assert_eq!(status, 200, "the admitted owner works: {body}");

        // This computer's own sign-in is not the owner's to change from afar.
        let (status, body) =
            carried(client, "POST", "/account/hub-session/logout", &admitted).await;
        assert_eq!(
            status, 403,
            "signing this computer out from elsewhere: {body}"
        );

        let (status, body) = carried(client, "DELETE", "/home/admissions", &admitted).await;
        assert_eq!(status, 204, "the owner revokes their admission: {body}");
        let (status, body) = carried(client, "GET", "/workspace", &admitted).await;
        assert_eq!(status, 401, "a revoked admission does no work: {body}");
        tasks.iter().for_each(|task| task.abort());
    }

    /// GaugeDesk 0.8.1: the account's only Home was this desktop's own,
    /// reachable from elsewhere only through the relay, and the desktop's
    /// broker dialed it through the relay — asking the relay to splice the
    /// computer to itself — so Panel settings and People & sharing loaded
    /// forever. The broker reaches its own Home on the crossing listener
    /// instead, without the Hub's routes or the relay, and the call is served
    /// as the account, as a crossing is.
    #[tokio::test]
    async fn the_broker_reaches_its_own_home_without_the_relay() {
        let root = tempfile::tempdir().expect("root");
        let wb = crate::open_workbench(root.path()).expect("workbench");
        crate::account_signin::store_session_for_test(&wb);
        crate::home_owner::claim_if_never_claimed(&wb).expect("owner");
        let home = wb.lock_unpoisoned().home_id().as_str().to_owned();
        // Nothing answers here: a broker that consulted the Hub's routes, or
        // dialed a relay, would fail rather than name an address.
        let hub = "http://127.0.0.1:9";
        let crossings = serve_relay_crossings(wb.clone(), std::sync::Arc::new(FakeHub))
            .await
            .expect("relay router");
        let (endpoint, other) = {
            let wb = wb.clone();
            let home = home.clone();
            tokio::task::spawn_blocking(move || {
                let mine = crate::account_signin::selected_home_direct_for_test(
                    &wb,
                    hub,
                    "owner-bearer",
                    &home,
                    "account-root",
                );
                let other = crate::account_signin::selected_home_direct_for_test(
                    &wb,
                    hub,
                    "owner-bearer",
                    "home:somewhere-else",
                    "account-root",
                );
                (mine, other)
            })
            .await
            .expect("broker")
        };
        assert_eq!(
            endpoint.expect("its own Home needs no route"),
            Some(format!("http://{crossings}"))
        );
        assert!(other.is_err(), "another Home is still found by its route");

        let owner = [("authorization", "Bearer owner-bearer")];
        let (status, body) = carried(crossings, "POST", "/home/admissions", &owner).await;
        assert_eq!(status, 201, "the account is admitted: {body}");
        let reply: serde_json::Value =
            serde_json::from_str(body.split("\r\n\r\n").nth(1).expect("a body")).expect("json");
        assert_eq!(reply["home"], home.as_str());
        let admission = reply["admission"].as_str().expect("an admission");
        let admitted = [
            ("authorization", "Bearer owner-bearer"),
            ("x-gaugewright-home-admission", admission),
        ];
        let (status, body) = carried(crossings, "GET", "/workspace", &admitted).await;
        assert_eq!(status, 200, "the account works on its own Home: {body}");
    }

    /// An account the Hub recognises but that is not signed in on this
    /// computer is a stranger here (DR-0328 §6, DR-0302).
    #[tokio::test]
    async fn an_account_not_signed_in_here_is_refused_over_the_relay() {
        let (_relay, _root, client, tasks) = reachable_home().await;
        let (status, body) = carried(
            client,
            "POST",
            "/home/admissions",
            &[("authorization", "Bearer someone-elses-bearer")],
        )
        .await;
        assert_eq!(status, 403, "{body}");
        assert!(body.contains("not signed in on this computer"), "{body}");
        tasks.iter().for_each(|task| task.abort());
    }

    /// One JSON request carried over the relay. Each carries its own
    /// idempotency key, so two alike are two commands.
    pub(super) async fn carried_json(
        address: std::net::SocketAddr,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<serde_json::Value>,
    ) -> (u16, serde_json::Value) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        static SENT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let sent = SENT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let body = body.map(|body| body.to_string()).unwrap_or_default();
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("loopback");
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nhost: home\r\nidempotency-key: carried-{sent}\r\n\
             content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
            body.len(),
        );
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(&body);
        stream.write_all(request.as_bytes()).await.expect("write");
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(20),
            stream.read_to_end(&mut response),
        )
        .await
        .expect("the crossing answered in time")
        .expect("read");
        let text = String::from_utf8_lossy(&response).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("no status line in {text:?}"));
        let json = text
            .split_once("\r\n\r\n")
            .map(|(head, body)| {
                if head
                    .to_ascii_lowercase()
                    .contains("transfer-encoding: chunked")
                {
                    dechunked(body)
                } else {
                    body.to_owned()
                }
            })
            .and_then(|body| serde_json::from_str(&body).ok())
            .unwrap_or_else(|| serde_json::json!({ "raw": text }));
        (status, json)
    }

    /// A chunked HTTP/1.1 body, joined.
    fn dechunked(mut body: &str) -> String {
        let mut joined = String::new();
        while let Some((size, rest)) = body.split_once("\r\n") {
            let Ok(size) = usize::from_str_radix(size.trim(), 16) else {
                break;
            };
            if size == 0 || rest.len() < size {
                break;
            }
            joined.push_str(&rest[..size]);
            body = rest[size..].trim_start_matches("\r\n");
        }
        joined
    }

    /// Wait until this Home authors a relay route for `project`.
    pub(super) async fn routed(wb: &crate::SharedWorkbench, project: &str) -> bool {
        for _ in 0..200 {
            let relayed = Account::rebuild(wb.lock_unpoisoned().store_ref())
                .ok()
                .and_then(|account| account.home_routes.get(project).cloned())
                .is_some_and(|route| route.op == RecordOp::Upsert && route.relay.is_some());
            if relayed {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        false
    }

    /// WS-861, two accounts end to end. The owner's desktop is reachable only
    /// through its relay and invites someone by email to one project. That
    /// person's account has never signed in on the computer. It accepts over
    /// the relay, then reaches the shared project and the Panel agent placed
    /// in it, starts a chat there — and reaches nothing else on the computer,
    /// until the owner takes the grant away.
    #[tokio::test]
    async fn an_invited_account_reaches_only_the_shared_project_over_the_relay() {
        let (_relay, _root, wb, client, tasks) = reachable_home_and_workbench().await;
        let owner = "account-root";
        {
            let mut guard = wb.lock_unpoisoned();
            for (id, name) in [("proj-shared", "Shared"), ("proj-private", "Private")] {
                let mut extra = std::collections::BTreeMap::new();
                crate::project_owner::record_owner(&mut extra, owner);
                crate::library_routes::create_named_project_with_extra(&mut guard, id, name, extra)
                    .expect("project");
            }
            // The owner's Panel agent, placed in the shared project.
            guard
                .seed_panel_placement(
                    "panel-shared",
                    crate::library::PanelPublicProfile::default(),
                )
                .expect("Panel agent");
            let mut placement = guard.library.instances["panel-shared"].clone();
            placement.project_id = Some("proj-shared".to_owned());
            guard.write_instance_record(placement);
        }
        assert!(
            routed(&wb, "proj-shared").await,
            "the shared project has a relay route"
        );

        // The owner invites by email from the computer, as Project Settings does.
        let owner_session = {
            let wb = wb.clone();
            tokio::task::spawn_blocking(move || crate::desktop_session::home_session(&wb))
                .await
                .unwrap()
                .expect("the owner's window session")
        };
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {owner_session}").parse().unwrap(),
        );
        let created = crate::home_invitation::post_invitation(
            axum::extract::State(wb.clone()),
            headers,
            axum::Json(
                serde_json::from_value(serde_json::json!({
                    "email": "invitee@example.test",
                    "project": "proj-shared",
                    "role": "member",
                    "endpoint": "",
                }))
                .unwrap(),
            ),
        )
        .await;
        assert_eq!(created.status(), axum::http::StatusCode::CREATED);
        let created: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(created.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let invite = created["invite"].as_str().expect("an invite").to_owned();
        assert_eq!(
            created["endpoint"], "",
            "a relay-only Home names no endpoint"
        );
        let invitee = [("authorization", "Bearer invitee-bearer")];

        // Before accepting, the invitee holds nothing here.
        let (status, body) = carried_json(client, "POST", "/home/admissions", &invitee, None).await;
        assert_eq!(status, 403, "{body}");

        // Only the account holding the invited address may take it.
        let accept = serde_json::json!({ "invite": invite });
        let (status, body) = carried_json(
            client,
            "POST",
            "/home/invitations/accept",
            &[("authorization", "Bearer someone-elses-bearer")],
            Some(accept.clone()),
        )
        .await;
        assert_eq!(status, 403, "another account took the invitation: {body}");

        let (status, accepted) = carried_json(
            client,
            "POST",
            "/home/invitations/accept",
            &invitee,
            Some(accept),
        )
        .await;
        assert_eq!(
            status, 200,
            "the invitee accepts over the relay: {accepted}"
        );
        assert_eq!(accepted["project"], "proj-shared");
        assert!(
            accepted["relay"]["handle"].is_string()
                && accepted["placement"]["project_key"].is_string(),
            "acceptance names the route the invitee keeps reaching this Home by: {accepted}"
        );
        {
            let guard = wb.lock_unpoisoned();
            let org = crate::org::Org::rebuild(guard.store_ref()).unwrap();
            assert_eq!(
                org.granted_project_ids("invitee-account"),
                ["proj-shared".to_owned()].into(),
                "the grant is to the one project"
            );
        }

        let (status, admitted) =
            carried_json(client, "POST", "/home/admissions", &invitee, None).await;
        assert_eq!(status, 201, "the member is admitted: {admitted}");
        let admission = admitted["admission"].as_str().unwrap().to_owned();
        let member = [
            ("authorization", "Bearer invitee-bearer"),
            ("x-gaugewright-home-admission", admission.as_str()),
        ];

        let (status, workspace) = carried_json(client, "GET", "/workspace", &member, None).await;
        assert_eq!(status, 200, "{workspace}");
        let projects: Vec<&str> = workspace["projects"]
            .as_array()
            .expect("projects")
            .iter()
            .filter_map(|project| project["id"].as_str())
            .collect();
        assert_eq!(projects, ["proj-shared"], "the member sees its one project");

        let (status, body) =
            carried_json(client, "GET", "/placements/panel-shared", &member, None).await;
        assert_eq!(
            status, 200,
            "the member opens the Panel agent's placement: {body}"
        );
        let (status, body) = carried_json(
            client,
            "POST",
            "/placements/panel-shared/settings/sessions",
            &member,
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(
            status, 200,
            "the member opens the Panel agent's settings: {body}"
        );

        // A Panel placement hosts no work chat; the project's own does.
        let general = crate::library_routes::general_placement_id("proj-shared");
        let (status, chat) = carried_json(
            client,
            "POST",
            &format!("/projects/proj-shared/placements/{general}/chats"),
            &member,
            Some(serde_json::json!({ "title": "From the customer" })),
        )
        .await;
        assert_eq!(
            status, 201,
            "the member starts a chat in the shared project: {chat}"
        );
        let chat = chat["id"].as_str().expect("a chat").to_owned();
        let (status, body) = carried_json(
            client,
            "GET",
            &format!("/chats/{chat}/transcript"),
            &member,
            None,
        )
        .await;
        assert_eq!(status, 200, "the member reads its chat: {body}");

        // Nothing beyond the shared project.
        for (method, path, body) in [
            ("GET", "/projects/proj-private/models", None),
            ("GET", "/account/credentials", None),
            ("GET", "/account/hub-sessions", None),
            (
                "POST",
                "/projects",
                Some(serde_json::json!({ "name": "mine" })),
            ),
            ("POST", "/chats", Some(serde_json::json!({}))),
            ("DELETE", "/projects/proj-shared", None),
            ("POST", "/home/invitations", Some(serde_json::json!({}))),
        ] {
            let (status, answer) = carried_json(client, method, path, &member, body).await;
            assert_eq!(status, 403, "{method} {path} reached the member: {answer}");
        }

        // Taking the grant away ends the member's reach at once.
        {
            let mut guard = wb.lock_unpoisoned();
            let revoked = crate::org::MemberGrantRecord {
                id: crate::org::MemberGrantRecord::make_id("invitee-account", "proj-shared"),
                op: crate::org::RecordOp::Tombstone,
                authority: "invitee-account".to_owned(),
                project_id: "proj-shared".to_owned(),
            };
            guard
                .store_mut()
                .append_record(
                    crate::org::ORG_SCOPE,
                    "member_grant",
                    &serde_json::to_string(&revoked).unwrap(),
                )
                .unwrap();
        }
        let (status, body) = carried_json(client, "GET", "/workspace", &member, None).await;
        assert_eq!(
            status, 403,
            "a revoked member reached the workspace: {body}"
        );
        tasks.iter().for_each(|task| task.abort());
    }
}

// DR-0453: a member authors, tries, publishes and deploys the Agent placed in
// the shared project, over the same relay as `reachability_tests`.
#[cfg(test)]
#[path = "open_runtime_member_authoring_tests.rs"]
mod member_authoring_tests;

#[cfg(test)]
mod control_plane_failure_tests {
    use super::*;

    /// The 2026-10-05 failure: an installed build met a store a newer build had
    /// migrated. The person is told to update, in words, not SQLite's text.
    #[test]
    fn a_store_a_newer_build_wrote_tells_the_person_to_update() {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("gaugewright.db");
        drop(gaugedesk_store::Store::open(db.to_str().unwrap()).unwrap());
        let ahead = gaugedesk_store::SUPPORTED_SCHEMA_VERSION + 2;
        rusqlite::Connection::open(&db)
            .unwrap()
            .execute(
                "INSERT INTO schema_migrations(version) VALUES (?1)",
                [ahead],
            )
            .unwrap();

        let error = match open_prepare(root.path()) {
            Ok(_) => panic!("a store a newer build wrote must refuse to open"),
            Err(error) => error,
        };
        let failure = control_plane_failure(&error);
        assert_eq!(failure.kind, "store_too_new", "{failure:?}");
        assert!(
            failure.message.contains("Update GaugeDesk"),
            "{}",
            failure.message
        );
        assert!(
            failure.message.contains(&ahead.to_string())
                && failure
                    .message
                    .contains(&gaugedesk_store::SUPPORTED_SCHEMA_VERSION.to_string()),
            "names both versions: {}",
            failure.message
        );
        assert!(
            !failure.message.contains("SqliteFailure"),
            "{}",
            failure.message
        );
    }

    #[test]
    fn a_taken_address_and_any_other_failure_say_what_happened() {
        let taken = std::io::Error::new(std::io::ErrorKind::AddrInUse, "Address already in use");
        let failure = control_plane_failure(&taken);
        assert_eq!(failure.kind, "port_in_use");
        assert!(
            failure.message.contains("Address already in use"),
            "{}",
            failure.message
        );

        let other = std::io::Error::other("disk I/O error");
        let failure = control_plane_failure(&other);
        assert_eq!(failure.kind, "failed");
        assert!(
            failure.message.contains("disk I/O error"),
            "{}",
            failure.message
        );
    }
}

#[cfg(test)]
mod desktop_operator_plane_tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    fn desktop() -> axum::Router {
        let wb = crate::Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap());
        super::desktop_operator_plane(Arc::new(Mutex::new(wb)))
    }

    /// The desktop serves no organization governance, and its window must be
    /// able to read that `404` as such. Without `Access-Control-Allow-Origin`
    /// the webview's `fetch` rejects, and the client fails closed: a personal
    /// account could accept no engagement invite (2026-10-07).
    #[tokio::test]
    async fn an_unserved_route_is_a_404_the_window_can_read() {
        for tenant in [None, Some("personal:account")] {
            let mut request =
                Request::get("/admin/placement-policy").header("origin", "tauri://localhost");
            if let Some(tenant) = tenant {
                request = request.header("x-gaugewright-tenant", tenant);
            }
            let response = desktop()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{tenant:?}");
            assert_eq!(
                response
                    .headers()
                    .get("access-control-allow-origin")
                    .map(|value| value.to_str().unwrap()),
                Some("tauri://localhost"),
                "{tenant:?}"
            );
        }
    }

    /// Adding the Home broker as a route keeps it reachable.
    #[tokio::test]
    async fn the_home_broker_is_still_mounted() {
        let response = desktop()
            .oneshot(
                Request::get("/account/hub-session/home/h/workspace")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::NOT_FOUND);
    }
}
