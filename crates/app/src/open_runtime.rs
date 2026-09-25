//! Open-source runtime root resolution and serving helpers.

use crate::{federation, open_control_plane, open_workbench, LockUnpoisoned};

/// The window's loopback port is an operator channel for local work, but an
/// account selected in that window cannot inherit the co-resident Home owner's
/// operator authority. The relay uses its own listener and its own admission.
pub(crate) fn desktop_operator_plane(wb: crate::SharedWorkbench) -> axum::Router {
    let home_broker = axum::Router::new()
        .route(
            "/account/hub-session/home/{home}/{*path}",
            axum::routing::any(crate::account_signin::proxy_selected_home),
        )
        .with_state(wb.clone());
    open_control_plane(wb.clone())
        .merge(home_broker)
        .layer(axum::Extension(crate::account_signin::DesktopOperatorPlane))
        .layer(axum::middleware::from_fn_with_state(
            wb,
            selected_account_guard,
        ))
}

async fn selected_account_guard(
    axum::extract::State(wb): axum::extract::State<crate::SharedWorkbench>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let path = request.uri().path();
    // Sign-in and the hosted Account Settings proxy use only the selected
    // account's sealed Hub session. No Home data or local credential is served
    // through these exact surfaces.
    if request.method() == axum::http::Method::OPTIONS
        || path == "/health"
        || path.starts_with("/account/hub-session")
        || path.starts_with("/gaugeapps/account-settings/")
        || path.starts_with("/auth/")
    {
        return next.run(request).await;
    }
    let selected = crate::account_signin::live_hub_session_actor(&wb);
    let owner = wb.lock_unpoisoned().home_owner_account();
    if (selected.is_some() && selected != owner)
        || (owner.is_some()
            && selected.is_none()
            && !crate::account_signin::local_operator_selected(&wb))
    {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": "the selected account has no admission to this local Home"
            })),
        )
            .into_response();
    }
    next.run(request).await
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
    Ok(wb)
}

/// Serve a workbench from [`open_prepare`] on `addr`.
pub async fn open_serve_workbench(
    wb: crate::SharedWorkbench,
    addr: &str,
    root: &std::path::Path,
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
    // operator's channel, where a caller with no credentials is the operator,
    // and the leg's locator is public (DR-0206). That one admits only this
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
        desktop_operator_plane(wb).into_make_service_with_connect_info::<std::net::SocketAddr>(),
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
            eprintln!("[home-relay] the relay router stopped: {error}");
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
        // An already claimed computer may need its reachability attachment
        // reconciled from state. An unclaimed computer remains local-only.
        match crate::first_home::attach_if_never_offered(&wb, &root) {
            Ok(true) => eprintln!(
                "[first-home] library sync attached; this computer is now publishing its reachability"
            ),
            Ok(false) => {}
            Err(error) => tracing::warn!("first Home not attached: {error}"),
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
        let publishes = wb.lock_unpoisoned().library_sync_active();
        match (publishes, parked.is_some()) {
            (true, false) => match start_home_relay(&wb, crossings, &root, &endpoint) {
                Ok(leg) => parked = Some(leg),
                // Said, not swallowed: a Home that cannot park is unreachable,
                // and the person asked for the opposite.
                Err(error) => eprintln!("[home-relay] could not park a leg: {error}"),
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
                eprintln!("[home-relay] publishing off — {retracted} route(s) retracted");
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
                    // A published locator whose proof has rotated is a Home desk
                    // cannot reach, so the authority is told at the same moment
                    // the routes are re-authored (DR-0183 §4).
                    crate::first_home::reconcile(&rotation_workbench, &route);
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
                Ok(epoch) => eprintln!(
                    "[home-relay] leg parked at epoch {epoch} — this computer is reachable again"
                ),
                Err((epoch, error)) => eprintln!(
                    "[home-relay] cannot park a leg at epoch {epoch}, so desk cannot open this \
                     computer; retrying: {error}"
                ),
            },
        )
        .await;
        if let Err(error) = outcome {
            eprintln!("[home-relay] availability loop stopped: {error}");
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

    /// The Hub, as the relay router asks it: two bearers it recognises.
    struct FakeHub;

    impl crate::relay_route_stack::BearerAccounts for FakeHub {
        fn account_for(&self, bearer: &str) -> Result<Option<String>, String> {
            Ok(match bearer {
                "owner-bearer" => Some("account-root".to_owned()),
                "someone-elses-bearer" => Some("someone-else".to_owned()),
                _ => None,
            })
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
        (relay, root, client, vec![supervisor, carrier])
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

    /// Another account the Hub recognises is still not this Home's owner.
    #[tokio::test]
    async fn another_account_over_the_relay_is_refused() {
        let (_relay, _root, client, tasks) = reachable_home().await;
        let (status, body) = carried(
            client,
            "POST",
            "/home/admissions",
            &[("authorization", "Bearer someone-elses-bearer")],
        )
        .await;
        assert_eq!(status, 403, "{body}");
        assert!(body.contains("belongs to another account"), "{body}");
        tasks.iter().for_each(|task| task.abort());
    }
}
