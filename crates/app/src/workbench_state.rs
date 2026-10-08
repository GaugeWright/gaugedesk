//! Workbench state construction, accessors, and in-memory registration helpers.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use gaugedesk_core::ids::{AuthorityId, HomeId};
use gaugedesk_store::Store;
use gaugedesk_workspace::{ChatWorkspace, WhippleWorkspaceProvider, Workspace, WorkspaceProvider};
use tokio::sync::broadcast;

use crate::app_support::{attestation_enabled, attestation_mode_from_env, prepare_workbench_root};
use crate::boundary_keeper::LoopbackKeyReleaseService;
use crate::library::Library;
use crate::library_state;
use crate::measurement_store::MeasurementStore;
use crate::stream::ServerEvent;
use crate::{
    at_rest, audit, content_vault, federation, identity, key_store, throttle, AttestationMode,
    LOCAL_AUTHORITY,
};

/// The co-resident control-plane state. Holds many instances, the durable event
/// store, derived projections, live engagements, streams, and local/remote agent
/// sessions.
/// Workspace construction providers, keyed by substrate id.
pub(crate) type WorkspaceProviders = BTreeMap<&'static str, Arc<dyn WorkspaceProvider>>;

/// The native WhippleScript workspace substrate's registry key.
const WHIPPLE_SUBSTRATE: &str = "whipplescript";

/// The account/global trust boundary — the one scope the v1 onboarding tracker
/// lives on (ADR 0075 §2): no project, no client-tainted data, bottom taint.
/// Per-project boundaries (which key by `project::<id>`) are deferred to Phase 4.
pub(crate) const ACCOUNT_GLOBAL_BOUNDARY: &str = "account::global";

/// Every managed target resolves to the native WhippleScript workspace.
pub(crate) fn target_substrate_id(_target_id: &str) -> &'static str {
    WHIPPLE_SUBSTRATE
}

/// The default registry contains the one standing workspace authority.
pub(crate) fn default_workspace_providers() -> WorkspaceProviders {
    BTreeMap::from([(
        WHIPPLE_SUBSTRATE,
        Arc::new(WhippleWorkspaceProvider) as Arc<dyn WorkspaceProvider>,
    )])
}

/// Resolve the provider that constructs/opens an instance's workspace. The
/// registry always carries every id `target_substrate_id` mints.
pub(crate) fn provider_for(
    providers: &WorkspaceProviders,
    target_id: &str,
) -> Arc<dyn WorkspaceProvider> {
    providers
        .get(target_substrate_id(target_id))
        .cloned()
        .expect("a workspace provider is registered for every substrate id")
}

pub struct Workbench {
    /// Open GaugeDesk-managed work-target stores, keyed only by target id.
    pub(crate) targets: BTreeMap<String, Box<dyn Workspace>>,
    /// Home-local project collaboration stores. These are deliberately
    /// separate from work targets: their Main refs record accepted candidate
    /// collaboration, never native target settlement.
    pub(crate) collaboration_workspaces: BTreeMap<String, Box<dyn Workspace>>,
    /// Workspace construction providers, keyed by substrate id; managed targets
    /// resolve theirs via [`target_substrate_id`].
    pub(crate) providers: WorkspaceProviders,
    /// The default logical placement selected by the zero-setup chat route.
    pub(crate) default_instance: String,
    /// Chat id -> physical WhippleScript workspace id. For legacy/edit chats
    /// this is a target id; project chats use their collaboration workspace id.
    pub(crate) engagement_index: BTreeMap<String, String>,
    pub(crate) library: Library,
    pub(crate) store: Store,
    pub(crate) engagements: BTreeMap<String, Box<dyn ChatWorkspace>>,
    pub(crate) streams: BTreeMap<String, broadcast::Sender<ServerEvent>>,
    /// One agent harness per engagement (ADR 0031), each behind **its own** lock.
    ///
    /// A turn needs exclusive access to one chat's harness for as long as the model
    /// call takes. Holding the workbench lock for that would serialize every other
    /// chat behind it, so a turn instead clones the `Arc` out under a brief lock and
    /// then locks only the harness. An empty slot reserves initialization without
    /// holding the Workbench across the factory's transport or authority callbacks.
    /// The turn claim (DR-0138) covers startup as well as execution.
    pub(crate) sessions: BTreeMap<String, SharedHarness>,
    /// One remote harness per remotely placed engagement (ADR 0020/0031).
    pub(crate) remote_sessions: BTreeMap<String, Box<dyn gaugedesk_harness::RemoteHarness>>,
    /// The trusted reproducible-build measurement allow-list (ATTEST-10).
    pub(crate) measurements: MeasurementStore,
    /// The sealed-key release service (ATTEST-5/-6).
    pub(crate) sealed_keys: LoopbackKeyReleaseService,
    /// How attested-boundary acceptance verifies quotes before releasing sealed keys.
    pub(crate) attestation_mode: AttestationMode,
    /// Deployment-injected real quote verifier factory (ATTEST-15). `None` (the
    /// default) fails closed at attested acceptance; the private managed
    /// composition installs its factory at workbench open time.
    pub(crate) real_verifier_factory: Option<crate::attestation_verifier::RealQuoteVerifierFactory>,
    /// Whether the attested-specific operator surface is mounted.
    pub(crate) attestation_enabled: bool,
    /// The on-disk state root this workbench was opened from.
    pub(crate) root: std::path::PathBuf,
    /// Where managed target state dirs live (`<targets_root>/<target-id>`).
    pub(crate) targets_root: std::path::PathBuf,
    /// This control plane's network federation state (`SERVE-1`/D-REMOTE).
    pub(crate) federation: Option<federation::Federation>,
    /// This control plane's own authority identity (`SERVE-1`/D-REMOTE).
    pub(crate) authority: AuthorityId,
    /// The stable logical Home this workbench realizes (`HOME-1`). Physical
    /// process/root/runtime placement may change without changing this identity.
    pub(crate) home_id: HomeId,
    /// True only when the private hosted Home router has claimed this
    /// workbench. This is composition-bound state, never inferred from a
    /// process-global environment variable or from ordinary account login.
    pub(crate) hosted_home_mode: bool,
    /// The organization tenant a hosted Home was provisioned for, when it was
    /// provisioned for one. Its projects belong to that organization unless
    /// they name another (DR-0325). Composition-bound, like `hosted_home_mode`.
    pub(crate) owning_organization: Option<String>,
    /// Replaceable per-identity Home sessions. Account login alone never appears
    /// here; the target Home mints these only after admission.
    pub(crate) home_admissions: crate::home_admission::HomeAdmissionStore,
    /// Native workforce verification for the separately composed office route.
    /// No source bearer is copied into the local account-session store.
    pub(crate) office_staff_auth:
        Option<crate::office_home_admission::authentication::OfficeStaffAuthentication>,
    /// The identity adapter that authenticates bearer credentials.
    pub(crate) idp: Option<Arc<dyn identity::IdentityProvider + Send + Sync>>,
    /// The Home session this process last handed its desktop UI (DR-0188).
    /// Process memory only: a restart mints another.
    pub(crate) desktop_ui_session: Option<crate::desktop_session::DesktopUiSession>,
    /// The Home session relay crossings for the owner are served under
    /// (DR-0206). Its own slot, so neither rotates the other out from under it.
    /// The session each account's relay crossings are served under.
    pub(crate) relay_sessions:
        std::collections::BTreeMap<String, Option<crate::desktop_session::DesktopUiSession>>,
    /// The session each project member's relay crossings are served under:
    /// an account not signed in here that holds a grant to a project this
    /// Home serves (DR-0328 §6). Process memory only.
    pub(crate) relay_member_sessions:
        std::collections::BTreeMap<String, crate::desktop_session::MemberSession>,
    /// Where this Home serves the callers its relay leg carries, once it
    /// serves them. The desktop's broker reaches its own Home here rather than
    /// dialing itself through the relay, which never completes.
    pub(crate) relay_crossings: Option<std::net::SocketAddr>,
    /// Opaque Hub sessions authenticate a durable GaugeDesk account before any
    /// organization-specific membership decision.
    pub(crate) account_sessions: Arc<crate::account_session::AccountSessionStore>,
    /// The account each recently verified provider identity `(issuer, subject)`
    /// resolved to. A candidate only, never authority: every use re-checks the
    /// link against that one account's current authority and falls back to the
    /// full projection, so a request reads one account instead of all (WS-849).
    pub(crate) linked_subject_hints: Mutex<BTreeMap<(String, String), String>>,
    /// Each recently authenticated session's durable standing, remembered
    /// against the store's read stamp for the scopes it was folded from, so a
    /// burst of requests on one session folds its authority once instead of
    /// once per request under this lock (WS-1010).
    pub(crate) session_standings: crate::account_session::RememberedStandings,
    /// Optional streaming audit sink (`AUD-4`).
    pub(crate) audit_sink: Option<Arc<dyn audit::AuditSink>>,
    /// Governance key store used to sign audit checkpoints (`SECAUD-2`).
    pub(crate) audit_signer: Option<Arc<dyn key_store::KeyStore + Send + Sync>>,
    /// Per-scope content-encryption vault (`SECAUD-9/6`).
    pub(crate) content_vault: Option<Arc<content_vault::ContentVault>>,
    /// Whether sensitive reads are written to the audit trail (`SECAUD-4`).
    pub(crate) audit_reads: bool,
    /// In-process failed-attempt lockout for SCIM bearer checks (`SECAUD-8`).
    pub(crate) scim_throttle: Arc<throttle::Throttle>,
    /// Installed only by a hosted composition. The product never constructs
    /// or selects a remote member-standing authority from a request.
    pub(crate) member_standing_fence: Option<crate::membership_fence::InstalledMemberStandingFence>,
    /// In-process failed-attempt lockout for OIDC callback processing (`SECAUD-8`) — a
    /// per-tenant brute-force guard on the SSO callback, separate from SCIM's counter.
    pub(crate) oidc_throttle: Arc<throttle::Throttle>,
    /// Per-session activity ledger enforcing the org session-timeout policy (`SEC-2`).
    pub(crate) session_activity: Arc<crate::session_activity::SessionActivity>,
    /// Per-session pending device-enrollment legs (`ACCT-1`, the enrollment drive).
    /// An `Arc` so a route handler can clone the handle out under the lock and then
    /// run the broker legs (which await) without holding the workbench mutex.
    pub(crate) enroll_drive: Arc<crate::device_enroll_drive::EnrollDrive>,
    /// The rendezvous broker this workbench dials / advertises for enrollment
    /// (`ACCT-1`); `None` falls back to `GAUGEDESK_RELAY_ENDPOINT` / the default.
    pub(crate) enroll_broker: Option<String>,
    /// The account key a newly-enrolled device recovered over the handshake
    /// (`ACCT-1`), held in memory — never returned over HTTP (`INV-10`).
    pub(crate) recovered_account_key: Option<[u8; 32]>,
    /// Machine-scoped controller invitations, challenges, and short-lived
    /// sessions. Durable grant records live in `store`; raw credentials do not.
    pub(crate) machine_controllers: crate::mobile_machine_session::MachineControllerRuntime,
    /// Woken when the publication facility changes, so reachability can follow
    /// it while the Home runs rather than only at the moment it started.
    pub(crate) publication_changed: Arc<tokio::sync::Notify>,
    /// Bounded grant-reference hints; retained grants remain the source.
    pub(crate) native_editor_dispatch_changed: broadcast::Sender<String>,
    pub(crate) native_editor_dispatch_running: Arc<std::sync::atomic::AtomicBool>,
    /// Disposable wake hints for the folder-whip supervisor (DR-0191): a
    /// launch scope, or `project::<id>` for every launch in a project.
    pub(crate) project_workflow_changed: broadcast::Sender<String>,
    pub(crate) project_workflow_running: Arc<std::sync::atomic::AtomicBool>,
    /// Which projects members used lately, shared by every composition so a
    /// request is counted once however many layers see it (DR-0312).
    pub(crate) member_use: crate::key_delegation::MemberUse,
    /// The verified-funding producer this composition trusts for credit-funded
    /// work chats (GaugeWright DR-0203). Absent, a managed turn keeps the
    /// unverified local plan path and draws no credits.
    pub(crate) managed_funding_authority: Option<crate::managed_funding::FundingAuthority>,
    /// Sessions a test opens to drive the workbench directly, as a request
    /// handler would inside its session (WS-740).
    #[cfg(test)]
    pub(crate) test_session_holds: Vec<crate::content_vault::SessionHold>,
}

impl Workbench {
    /// Fund this composition's managed work chats from verified grants and
    /// credits. Route composition chooses the producer; no request can.
    pub fn set_managed_funding_authority(
        &mut self,
        authority: Option<crate::managed_funding::FundingAuthority>,
    ) {
        self.managed_funding_authority = authority;
    }

    pub fn install_member_standing_fence(
        &mut self,
        fence: crate::membership_fence::InstalledMemberStandingFence,
    ) {
        self.member_standing_fence = Some(fence);
    }

    pub fn member_standing_fence(
        &self,
    ) -> Option<crate::membership_fence::InstalledMemberStandingFence> {
        self.member_standing_fence.clone()
    }
}

pub type SharedWorkbench = Arc<Mutex<Workbench>>;

/// One chat's agent harness, independently lockable so a turn can hold it without
/// holding the workbench (ADR 0031 + the per-chat serialization unit).
pub(crate) type SharedHarness = Arc<Mutex<Option<Box<dyn gaugedesk_harness::Harness>>>>;

/// Shut a harness down, but only if this is the last reference to it. A harness a
/// turn still holds is left to that turn, which drops the final reference when it
/// finishes — a running agent is never killed by a bookkeeping path.
pub(crate) fn shutdown_shared_harness(harness: SharedHarness) {
    if let Ok(harness) = Arc::try_unwrap(harness) {
        let harness = harness
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(harness) = harness {
            let _ = harness.shutdown();
        }
    }
}

/// Open (or initialize) the local workbench under `root`. Agents/projects/chats
/// are rehydrated from target/chat records + native workspaces (ADR 0100): for each
/// target we open its store and reconcile its candidates. A fresh root is seeded
/// with a default agent so the user can chat immediately.
pub fn open_workbench(root: &std::path::Path) -> std::io::Result<SharedWorkbench> {
    let wb = build_workbench(root)?
        .with_attestation_mode(attestation_mode_from_env())
        .with_attestation_enabled(attestation_enabled());
    Ok(Arc::new(Mutex::new(wb)))
}

pub fn open_workbench_with_content_keywrap(
    root: &std::path::Path,
    content_keywrap: impl Fn(&std::path::Path) -> std::io::Result<Box<dyn at_rest::KeyWrap>>,
) -> std::io::Result<SharedWorkbench> {
    let wb = build_workbench_with_content_keywrap_for_home(
        root,
        None,
        content_keywrap,
        StartupSeed::production(),
        content_vault::StartupContentProtection::Ordinary,
    )?
    .with_attestation_mode(attestation_mode_from_env())
    .with_attestation_enabled(attestation_enabled());
    Ok(Arc::new(Mutex::new(wb)))
}

/// What a startup seeds into a fresh root beyond the store itself, and keeps
/// seeded on every open. Production seeds everything; a test that needs a
/// workbench but not the full library asks for less (see [`StartupSeed::lean`]).
#[derive(Clone, Copy)]
pub(crate) struct StartupSeed {
    /// The builtin archetypes to seed. The Default archetype must be among
    /// them: the Personal project's default placement is an instance of it.
    archetypes: &'static [crate::app_support::BuiltinArchetype],
}

impl StartupSeed {
    /// Every builtin archetype: what a user's root gets, and what every non-test opener above uses.
    pub(crate) fn production() -> Self {
        Self {
            archetypes: crate::app_support::builtin_archetypes(),
        }
    }

    /// Only what a test workbench needs to host a chat in the default
    /// placement: the Default archetype, the Personal project and its target.
    /// Each archetype is its own WhippleScript workspace on disk — a SQLite
    /// branch store, a seeded mainline, a probe engagement created and
    /// discarded for its basis — so a full seed is most of what a fresh open
    /// costs. The file-action tests open a fresh root each, 172 of them, and
    /// none reads an archetype; this is the difference between a fixture
    /// that builds what the test uses and one that builds the product.
    ///
    /// A root opened lean is a valid root: a later production open finds the
    /// other archetypes missing and seeds them, exactly as it does for a root
    /// from a release that predates them. A test that reads the archetype
    /// library opens the workbench the ordinary way.
    #[cfg(test)]
    pub(crate) fn lean() -> Self {
        let builtins = crate::app_support::builtin_archetypes();
        let default = builtins
            .iter()
            .position(|archetype| archetype.id == crate::app_support::DEFAULT_AGENT)
            .expect("the Default archetype is built in");
        Self {
            archetypes: &builtins[default..=default],
        }
    }
}

/// [`open_workbench`] with the lean startup seed. Test-only; see
/// [`StartupSeed::lean`] for what it leaves out and who may use it.
#[cfg(test)]
pub(crate) fn open_lean_workbench(root: &std::path::Path) -> std::io::Result<SharedWorkbench> {
    open_lean_workbench_with_content_keywrap(root, at_rest::local_content_keywrap)
}

/// [`open_workbench_with_content_keywrap`] with the lean startup seed.
#[cfg(test)]
pub(crate) fn open_lean_workbench_with_content_keywrap(
    root: &std::path::Path,
    content_keywrap: impl Fn(&std::path::Path) -> std::io::Result<Box<dyn at_rest::KeyWrap>>,
) -> std::io::Result<SharedWorkbench> {
    let wb = build_workbench_with_content_keywrap_for_home(
        root,
        None,
        content_keywrap,
        StartupSeed::lean(),
        content_vault::StartupContentProtection::Ordinary,
    )?
    .with_attestation_mode(attestation_mode_from_env())
    .with_attestation_enabled(attestation_enabled());
    Ok(Arc::new(Mutex::new(wb)))
}

/// Open a workbench whose logical Home and signing-authority identities are
/// supplied by the hosting registry rather than process-global environment. The explicit identity is
/// applied before startup state validation and re-applied after optional local
/// authority activation, so a pooled host cannot accidentally bind a tenant's
/// store to another Home because an environment variable changed.
pub fn open_workbench_for_home_with_content_keywrap(
    root: &std::path::Path,
    home_id: HomeId,
    authority_id: AuthorityId,
    content_keywrap: impl Fn(&std::path::Path) -> std::io::Result<Box<dyn at_rest::KeyWrap>>,
) -> std::io::Result<SharedWorkbench> {
    let wb = build_workbench_with_content_keywrap_for_home(
        root,
        Some((home_id, authority_id)),
        content_keywrap,
        StartupSeed::production(),
        content_vault::StartupContentProtection::Ordinary,
    )?
    .with_attestation_mode(attestation_mode_from_env())
    .with_attestation_enabled(attestation_enabled());
    Ok(Arc::new(Mutex::new(wb)))
}

/// Open an explicitly selected Home with authenticated library metadata from
/// the first read/write. Refuses plaintext history and unavailable custody;
/// supplies no migration, clinical enrollment or staff permission.
pub fn open_workbench_for_home_with_protected_library(
    root: &std::path::Path,
    home_id: HomeId,
    authority_id: AuthorityId,
    content_keywrap: impl Fn(&std::path::Path) -> std::io::Result<Box<dyn at_rest::KeyWrap>>,
) -> std::io::Result<SharedWorkbench> {
    let wb = build_workbench_with_content_keywrap_for_home(
        root,
        Some((home_id, authority_id)),
        content_keywrap,
        StartupSeed::production(),
        content_vault::StartupContentProtection::AuthenticatedLibrary,
    )?
    .with_attestation_mode(attestation_mode_from_env())
    .with_attestation_enabled(attestation_enabled());
    Ok(Arc::new(Mutex::new(wb)))
}

/// Build a fresh [`Workbench`] **value** from an on-disk state root — opening the
/// store, rebuilding (or seeding) the library, and reconciling live engagements.
/// `open_workbench` wraps this in the shared mutex; the test-only reset route uses
/// it to rebuild a clean workbench in place after wiping the root.
pub(crate) fn build_workbench(root: &std::path::Path) -> std::io::Result<Workbench> {
    build_workbench_with_content_keywrap(root, at_rest::local_content_keywrap)
}

pub(crate) fn build_workbench_with_content_keywrap(
    root: &std::path::Path,
    content_keywrap: impl Fn(&std::path::Path) -> std::io::Result<Box<dyn at_rest::KeyWrap>>,
) -> std::io::Result<Workbench> {
    build_workbench_with_content_keywrap_for_home(
        root,
        None,
        content_keywrap,
        StartupSeed::production(),
        content_vault::StartupContentProtection::Ordinary,
    )
}

fn build_workbench_with_content_keywrap_for_home(
    root: &std::path::Path,
    explicit_identity: Option<(HomeId, AuthorityId)>,
    content_keywrap: impl Fn(&std::path::Path) -> std::io::Result<Box<dyn at_rest::KeyWrap>>,
    seed: StartupSeed,
    protection: content_vault::StartupContentProtection,
) -> std::io::Result<Workbench> {
    crate::protected_profiles::scavenge_stale_materializations();
    let (root, targets_dir) = prepare_workbench_root(root)?;

    let (mut store, content_vault) = match protection {
        content_vault::StartupContentProtection::Ordinary => {
            content_vault::open_startup_store(&root, content_keywrap)?
        }
        content_vault::StartupContentProtection::AuthenticatedLibrary => {
            content_vault::open_startup_store_with_protection(&root, content_keywrap, protection)?
        }
    };
    let providers = default_workspace_providers();
    let home_id = explicit_identity
        .as_ref()
        .map(|(home_id, _)| home_id.clone())
        .unwrap_or_else(Workbench::configured_home_id);
    let startup_state = library_state::load_startup_library_state(
        &mut store,
        &targets_dir,
        &providers,
        &home_id,
        seed.archetypes,
    )?;

    let mut wb = Workbench::new(store).with_home_id(home_id);
    wb.providers = providers;
    wb.targets_root = targets_dir;
    wb.apply_startup_library_state(startup_state);
    wb.apply_startup_audit(&root);
    wb.apply_startup_content_vault(content_vault);
    wb.restore_startup_local_projections();
    wb.apply_startup_root(root);
    wb.activate_configured_authority();
    if let Some((home_id, authority_id)) = explicit_identity {
        wb.authority = authority_id;
        wb = wb.with_home_id(home_id);
    }
    // ACCT-1 / ADR 0053 §4: re-adopt a previously-recovered account key (an enrolled
    // device that joined another root) from its at-rest wrap, so restarts keep opening
    // the sealed account state. No-op on a holder / seed-recovered device (none stored).
    wb.restore_recovered_account_key();
    federation::activate_configured_federation(&mut wb)?;
    // DR-0248: every project target has a valid, unique name on collaboration
    // Main, which the target records project.
    wb.migrate_target_names();
    // Enterprise SSO activation (`ID-3`) moved with the ee band (`gaugedesk-ee`,
    // SPLIT-1): the ee/hosted compositions call `activate_configured_idp` right
    // after workbench open, through the open `set_identity_provider` seam.
    Ok(wb)
}

impl Workbench {
    /// An empty workbench (no instances). Startup registers instances from the
    /// library; tests use [`Workbench::with_target`].
    pub fn new(store: Store) -> Self {
        Self {
            targets: BTreeMap::new(),
            collaboration_workspaces: BTreeMap::new(),
            providers: default_workspace_providers(),
            default_instance: String::new(),
            engagement_index: BTreeMap::new(),
            library: Library::default(),
            store,
            engagements: BTreeMap::new(),
            streams: BTreeMap::new(),
            sessions: BTreeMap::new(),
            remote_sessions: BTreeMap::new(),
            measurements: MeasurementStore::new(),
            sealed_keys: LoopbackKeyReleaseService::new(),
            attestation_mode: AttestationMode::RealRequired,
            real_verifier_factory: None,
            attestation_enabled: false,
            root: std::path::PathBuf::new(),
            // The build path and test constructor replace this bare default.
            targets_root: std::path::PathBuf::from(".gaugewright/targets"),
            federation: None,
            authority: AuthorityId::new(LOCAL_AUTHORITY),
            home_id: HomeId::new(format!("home:{LOCAL_AUTHORITY}")),
            hosted_home_mode: false,
            owning_organization: None,
            home_admissions: crate::home_admission::HomeAdmissionStore::new(),
            office_staff_auth: None,
            idp: None,
            desktop_ui_session: None,
            relay_sessions: Default::default(),
            relay_member_sessions: Default::default(),
            relay_crossings: None,
            account_sessions: Arc::new(crate::account_session::AccountSessionStore::new()),
            linked_subject_hints: Mutex::default(),
            session_standings: Default::default(),
            audit_sink: None,
            audit_signer: None,
            content_vault: None,
            audit_reads: false,
            // SECAUD-8: 10 failed SCIM auths within 60s locks the tenant's SCIM endpoint
            // for the rest of the window (defense-in-depth; edge is the primary control).
            scim_throttle: Arc::new(throttle::Throttle::new(10, 60_000)),
            member_standing_fence: None,
            // SECAUD-8: 10 failed OIDC callbacks within 60s locks the tenant's SSO callback
            // for the rest of the window (defense-in-depth behind the edge rate-limit).
            oidc_throttle: Arc::new(throttle::Throttle::new(10, 60_000)),
            // SEC-2: enforce the org session lifetime / idle-timeout policy on data routes.
            session_activity: Arc::new(crate::session_activity::SessionActivity::new()),
            // ACCT-1: the per-session device-enrollment drive; broker + recovered key
            // resolve lazily (env fallback) / on a successful handshake.
            enroll_drive: Arc::new(crate::device_enroll_drive::EnrollDrive::new()),
            enroll_broker: None,
            recovered_account_key: None,
            machine_controllers: crate::mobile_machine_session::MachineControllerRuntime::default(),
            publication_changed: Arc::new(tokio::sync::Notify::new()),
            native_editor_dispatch_changed: broadcast::channel(64).0,
            native_editor_dispatch_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            project_workflow_changed: broadcast::channel(64).0,
            project_workflow_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            member_use: Default::default(),
            managed_funding_authority: None,
            #[cfg(test)]
            test_session_holds: Vec::new(),
        }
    }

    /// Signalled whenever an account facility is attached or revoked.
    ///
    /// Reachability follows the person's publication choice (ADR 0131 §6), and a
    /// choice made while the Home is running has to take effect while it is
    /// running. This is what tells the reachability supervisor to look again.
    ///
    /// `notify_one` rather than `notify_waiters`, so a change that lands between
    /// a supervisor's read and its wait is not lost: the permit is stored and
    /// the next wait returns immediately.
    pub fn publication_changed(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.publication_changed)
    }

    pub(crate) fn signal_publication_changed(&self) {
        self.publication_changed.notify_one();
    }

    /// The provider that constructs/opens this instance's workspace.
    pub(crate) fn workspace_provider(&self, inst_id: &str) -> Arc<dyn WorkspaceProvider> {
        provider_for(&self.providers, inst_id)
    }
}

#[cfg(test)]
#[path = "protected_library_startup_tests.rs"]
mod protected_library_startup_tests;
