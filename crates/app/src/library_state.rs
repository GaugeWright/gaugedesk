//! Open library/workspace state helpers for agents, projects, placements, chats, search, and pairing.

use std::collections::{BTreeMap, BTreeSet};

use gaugedesk_core::attestation::{AttestationQuote, CodeMeasurement};
use gaugedesk_core::boundary_lifecycle::{
    BoundaryCommand, BoundaryPhase, BoundaryState, Operator, Placement, PlacementPolicy,
};
use gaugedesk_core::ids::{BridgeGrantId, DeviceId};
use gaugedesk_core::instance::{InstanceCommand, InstanceState};
use gaugedesk_core::merge::MergeState;
use gaugedesk_core::run::RunState;
use gaugedesk_core::workstream::{WorkstreamPhase, WorkstreamState};
use gaugedesk_harness::HarnessFactory;
use gaugedesk_store::{AdmitError, Store};
use gaugedesk_workspace::{ChatWorkspace, Instance, MergeOutcome, Workspace, WorkspaceError};

use crate::attestation_verifier::{LoopbackVerifier, QuoteVerifier, RealQuoteVerifierError};
use crate::boundary_keeper::{accept_boundary_attested, AcceptError};
use crate::library::{
    Admission, AgentKind, AgentRecord, ArchetypeVersionRecord, ChatRecord, ChatTargetBasisRecord,
    ChatTargetBindingRecord, ChatTargetSetMemberRecord, ChatTargetSetRevisionRecord, InstanceKind,
    InstanceRecord, PanelCollectionRecipient, PanelPublicProfile, PlacementKind,
    PlacementTargetsRecord, ProjectCollaborationWorkspaceRecord, ProjectRecord,
    PublicDeploymentBindingRecord, RecordOp, TargetCapabilities, TargetParticipationMode,
    TargetVcsPosture, WorkTargetKind, WorkTargetOwner, WorkTargetRecord, WorkTargetStatus,
    WorkstreamRecord, WorkstreamRootRecord, LIBRARY_RECORD_SCHEMA, LIBRARY_SCOPE,
};
use crate::workbench_state::{provider_for, WorkspaceProviders};
use crate::{
    io, library, library_routes, AttestationMode, Workbench, DEFAULT_AGENT, DEFAULT_INSTANCE,
    DEFAULT_PLACEMENT, DEFAULT_PROJECT,
};

pub(crate) fn published_package_root(
    targets_dir: &std::path::Path,
    target_id: &str,
    version: u64,
) -> std::path::PathBuf {
    targets_dir
        .join(target_id)
        .join("repo")
        .join(gaugedesk_boundary::definition::version_root(version))
}

pub(crate) fn published_discipline_root(
    targets_dir: &std::path::Path,
    target_id: &str,
    version: u64,
) -> std::path::PathBuf {
    targets_dir
        .join(target_id)
        .join("repo")
        .join(crate::discipline::discipline_version_root(version))
}

fn published_archetype_version(
    targets_dir: &std::path::Path,
    target_id: &str,
    version: u64,
) -> std::io::Result<ArchetypeVersionRecord> {
    let package = gaugedesk_whip_runtime::AuthoredAgentPackage::load(published_package_root(
        targets_dir,
        target_id,
        version,
    ))
    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let discipline = crate::discipline::load(
        &published_discipline_root(targets_dir, target_id, version),
        package.capabilities().iter().cloned(),
    )
    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Ok(ArchetypeVersionRecord {
        package_ref: package.version_ref().to_owned(),
        discipline_ref: discipline.reference,
        panel_profile: None,
    })
}

fn validate_panel_profile(
    profile: &PanelPublicProfile,
    package_capabilities: &[String],
    package_agent_abilities: &[String],
) -> Result<(), String> {
    let supported_panels = ["gw-chat", "gw-viewer", "gw-files", "gw-chats"];
    if profile.panels.components.is_empty()
        || !profile
            .panels
            .components
            .contains(&profile.panels.default_component)
    {
        return Err("the default panel must be in the non-empty panel set".to_owned());
    }
    if let Some(panel) = profile
        .panels
        .components
        .iter()
        .find(|panel| !supported_panels.contains(&panel.as_str()))
    {
        return Err(format!("unsupported public panel `{panel}`"));
    }
    let supported_abilities = ["workspace.read", "workspace.write", "command.run"];
    for ability in &profile.public_abilities {
        if !supported_abilities.contains(&ability.as_str()) {
            return Err(format!("unsupported public ability `{ability}`"));
        }
        if !package_capabilities.contains(ability) {
            return Err(format!(
                "public ability `{ability}` is absent from the package capability registry"
            ));
        }
        if !package_agent_abilities.contains(ability) {
            return Err(format!(
                "public ability `{ability}` is not granted to the authored agent"
            ));
        }
    }
    if profile.provider.provider.trim().is_empty()
        || profile.provider.model.trim().is_empty()
        || profile.provider.base_url.trim().is_empty()
        || profile.provider.credential_class.trim().is_empty()
    {
        return Err("provider, model, base URL, and credential class are required".to_owned());
    }
    if profile.audience_inputs != ["text".to_owned()].into_iter().collect() {
        return Err("the current public host admits exactly the text input class".to_owned());
    }
    if profile.retention.idle_ttl_seconds == 0
        || profile.retention.absolute_ttl_seconds < profile.retention.idle_ttl_seconds
    {
        return Err("retention TTLs are inconsistent".to_owned());
    }
    if let Some(collection) = &profile.collection {
        if collection.exportable_paths.is_empty() && !collection.transcript_eligible {
            return Err("collection declares no eligible output".to_owned());
        }
        if collection.schema_ref.trim().is_empty()
            || collection.recipient_class.trim().is_empty()
            || collection.max_artifact_bytes == 0
            || collection.max_artifact_bytes
                > gaugedesk_core::agent_release::MAX_COLLECTION_ARTIFACT_BYTES
        {
            return Err("collection closure is incomplete or exceeds the size bound".to_owned());
        }
        for path in &collection.exportable_paths {
            let selector = path.strip_suffix("/*").unwrap_or(path);
            if selector.is_empty()
                || selector.starts_with('/')
                || selector.contains('\\')
                || selector.contains("**")
                || selector
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
            {
                return Err(format!(
                    "collection path `{path}` is not a bounded selector"
                ));
            }
        }
    }
    Ok(())
}

fn archetype_files(
    definition: &gaugedesk_boundary::definition::AgentDefinition,
    skills: BTreeSet<String>,
) -> Result<Vec<(String, String)>, String> {
    let mut files = definition.seed_files();
    let manifest = crate::discipline::manifest(
        gaugedesk_boundary::definition::PackageCapabilities::default()
            .names()
            .into_iter()
            .map(str::to_owned),
        skills,
        Vec::new(),
    );
    for root in [
        crate::discipline::DISCIPLINE_DRAFT_ROOT.to_owned(),
        crate::discipline::discipline_version_root(1),
    ] {
        files.push((
            format!("{root}/{}", crate::discipline::DISCIPLINE_MANIFEST),
            manifest.clone(),
        ));
    }
    Ok(files)
}

fn default_archetype_files() -> Vec<(String, String)> {
    archetype_files(
        &crate::app_support::default_agent_definition(),
        BTreeSet::new(),
    )
    .expect("the built-in Default archetype is valid")
}

pub(crate) enum AgentDeleteError {
    DefaultAgent,
    NotFound,
    BoundElsewhere,
}

pub(crate) enum PullArchetypeError {
    NotFound,
    NotFork,
    SourceMissing,
    SourceNotOpen,
    ForkNotOpen,
    Workspace(WorkspaceError),
}

pub(crate) enum BindPlacementError {
    ProjectNotFound,
    AgentNotFound,
    Create(String),
}

pub(crate) enum UpgradePlacementError {
    PlacementNotFound,
    ArchetypeNotFound,
    PackageUnavailable(String),
}

pub(crate) enum PublishArchetypeError {
    NotFound,
    InvalidPackage(String),
    Workspace(String),
}

pub(crate) enum CreateArchetypeChatError {
    ArchetypeNotFound,
    Create(String),
}

pub(crate) struct CreatedArchetype {
    pub(crate) id: String,
    pub(crate) name: String,
}

pub(crate) enum CreateArchetypeError {
    Create(String),
}

pub(crate) enum ForkArchetypeError {
    NotFound,
    SourceNotOpen,
    Create(String),
}

pub(crate) struct ForkedChat {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) forked_from: String,
    pub(crate) forked_from_entry: Option<i64>,
    pub(crate) admitted_home: Option<whipplescript_store::workstreams::BranchHomeReceiptV1>,
}

/// Where a new chat is admitted after its historical content/runtime cut has
/// been cloned.  The destination is topology only: it never changes which
/// files or transcript position the fork materializes.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ForkDestination {
    #[default]
    Inherit,
    Main,
    Workstream {
        workstream_id: String,
    },
}

pub(crate) enum ForkChatError {
    NotFound,
    SourceNotLive,
    InstanceNotOpen,
    Create(String),
    Continuity(String),
    PointNotForkable,
    HistoricalHomeClosed,
}

struct ResolvedForkPoint {
    entry_id: i64,
    /// Inclusive bound on the source-scope records the fork inherits
    /// (ADR 0141): strictly before the user entry on a pre-user cut, through
    /// the assistant entry on a post-assistant cut.
    inherited_cut: i64,
    workspace_cut: String,
    runtime_position: gaugedesk_harness::RuntimePosition,
    reads: Vec<String>,
    taint_evidence_digest: String,
    fork_snapshot: crate::engine::TurnForkSnapshot,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct ChatForkAdmissionRecord {
    schema: String,
    source_chat_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_entry_id: Option<i64>,
    historical_home: whipplescript_store::workstreams::BranchHomeReceiptV1,
    requested_destination: ForkDestination,
    admitted_home: whipplescript_store::workstreams::BranchHomeReceiptV1,
    taint_evidence_digest: String,
    #[serde(default)]
    pub(crate) visible_settlements: Vec<crate::engine::VisibleSettlementSnapshot>,
}

pub(crate) const CHAT_FORK_ADMISSION_KIND: &str = "chat_fork_admission";

struct ResolvedForkDestination {
    line_ref: String,
    workstream_id: Option<String>,
}

pub(crate) struct CreatedPairingRequest {
    pub(crate) pairing_id: String,
    pub(crate) device: String,
    pub(crate) bridge_grant: String,
    pub(crate) status: serde_json::Value,
}

pub(crate) struct BoundaryAttestationInput {
    pub(crate) measurement: String,
    pub(crate) nonce: String,
    pub(crate) expected_nonce: Option<String>,
    pub(crate) quote_bytes: Vec<u8>,
    pub(crate) vcek: Vec<u8>,
    pub(crate) sealed_key_id: Option<String>,
}

pub(crate) enum BoundaryAcceptError {
    PolicyRejected,
    Rejected(String),
    Store(AdmitError),
    QuoteRejected(String),
    MissingVcek,
    RealVerifierUnavailable,
    InvalidEndorsement(String),
}

pub(crate) struct StartupLibraryState {
    pub(crate) library: crate::library::Library,
    pub(crate) targets: BTreeMap<String, Box<dyn Workspace>>,
    pub(crate) collaboration_workspaces: BTreeMap<String, Box<dyn Workspace>>,
    pub(crate) engagements: BTreeMap<String, Box<dyn ChatWorkspace>>,
    pub(crate) engagement_index: BTreeMap<String, String>,
}

pub(crate) fn activate_instance(store: &mut Store, inst_id: &str) {
    let _ = store.admit::<InstanceState>(inst_id, InstanceCommand::PinVersion("v0".into()));
}

pub(crate) fn load_startup_library_state(
    store: &mut Store,
    targets_dir: &std::path::Path,
    providers: &WorkspaceProviders,
    home_id: &gaugedesk_core::ids::HomeId,
) -> std::io::Result<StartupLibraryState> {
    let mut library = crate::library::Library::rebuild(store).map_err(io)?;
    if migrate_exact_pre_target_defaults(store, &library, home_id)? {
        library = crate::library::Library::rebuild(store).map_err(io)?;
    }
    if library.is_empty() {
        seed_default_agent(store, &mut library, targets_dir, providers, home_id)?;
    }
    ensure_builtin_archetypes(store, &mut library, targets_dir, providers, home_id)?;
    if migrate_project_workspaces_and_target_sets(store, &library)? {
        library = crate::library::Library::rebuild(store).map_err(io)?;
    }
    validate_target_cutover(&library, targets_dir)?;
    if migrate_agent_ability_manifests(store, &library, targets_dir, providers)? {
        library = crate::library::Library::rebuild(store).map_err(io)?;
    }
    validate_archetype_versions(&library, targets_dir)?;
    let deleted_chats = explicitly_deleted_chats(store)?;
    let (targets, mut engagements, mut engagement_index) =
        open_startup_targets(&library, targets_dir, providers, &deleted_chats)?;
    let collaboration_workspaces =
        open_project_collaboration_workspaces(&library, targets_dir, providers)?;
    seed_empty_collaboration_workspaces(&library, &targets, &collaboration_workspaces)?;
    migrate_legacy_project_topology(
        store,
        &mut library,
        &targets,
        &collaboration_workspaces,
        &mut engagements,
        &mut engagement_index,
    )?;
    recover_project_workstream_promotions(store, &mut library, &collaboration_workspaces)?;
    open_project_chat_engagements(
        &library,
        &collaboration_workspaces,
        &mut engagements,
        &mut engagement_index,
        None,
    )?;
    for engagement in engagements.values_mut() {
        let _ = engagement.sync_from_main();
    }
    Ok(StartupLibraryState {
        library,
        targets,
        collaboration_workspaces,
        engagements,
        engagement_index,
    })
}

/// ADR 0150/0151's exact additive cutover. A project gains one distinct
/// collaboration workspace, and every singular chat binding becomes revision
/// zero of a non-empty stable-ID target set. The legacy binding remains as
/// historical evidence and compatibility input; new code reads the revisioned
/// set. The whole migration is one store transaction and is idempotent.
fn migrate_project_workspaces_and_target_sets(
    store: &mut Store,
    library: &crate::library::Library,
) -> std::io::Result<bool> {
    let mut records: Vec<(&'static str, String)> = Vec::new();

    for project in library.projects.values() {
        if let Some(existing) = library.project_collaboration_workspaces.get(&project.id) {
            if existing.host_contract_revision == crate::workstream_host_contract::REVISION
                && existing.host_contract_digest == crate::workstream_host_contract::DIGEST
            {
                continue;
            }
            if existing.host_contract_revision
                != crate::workstream_host_contract::MIGRATABLE_PREVIOUS_REVISION
                || existing.host_contract_digest
                    != crate::workstream_host_contract::MIGRATABLE_PREVIOUS_DIGEST
            {
                return Err(invalid_data(format!(
                    "project {} collaboration workspace has unsupported WhippleScript contract pin {} / {}; upgrade through a supported GaugeDesk release or repair/reset this pre-release state root",
                    project.id,
                    existing.host_contract_revision,
                    existing.host_contract_digest
                )));
            }
            if existing.home_id != project.home_id
                || existing.substrate != "whipplescript"
                || existing.workspace_id.is_empty()
            {
                return Err(invalid_data(format!(
                    "project {} collaboration workspace cannot migrate its WhippleScript contract pin because its Home, substrate, or workspace identity is invalid",
                    project.id
                )));
            }
            let mut migrated = existing.clone();
            migrated.host_contract_revision = crate::workstream_host_contract::REVISION.to_owned();
            migrated.host_contract_digest = crate::workstream_host_contract::DIGEST.to_owned();
            records.push((
                "project_collaboration_workspace",
                serde_json::to_string(&migrated).map_err(io)?,
            ));
            continue;
        }
        if project.home_id.as_str().is_empty() {
            return Err(invalid_data(format!(
                "project {} has no Home for its collaboration workspace; repair the project Home binding or reset this pre-release state root",
                project.id
            )));
        }
        let needs_legacy_topology_migration = library.chats.values().any(|chat| {
            library
                .instances
                .get(&chat.instance_id)
                .is_some_and(|instance| instance.project_id.as_deref() == Some(project.id.as_str()))
                && !library.chat_target_sets.contains_key(&chat.id)
        }) || library.workstream_roots.values().any(|root| {
            library
                .instances
                .get(&root.placement_id)
                .is_some_and(|instance| {
                    instance.kind == InstanceKind::Using
                        && instance.project_id.as_deref() == Some(project.id.as_str())
                })
                && root.project_id.is_empty()
        });
        let record = ProjectCollaborationWorkspaceRecord {
            project_id: project.id.clone(),
            workspace_id: format!("project-workspace-{}", project.id),
            home_id: project.home_id.clone(),
            substrate: "whipplescript".to_owned(),
            host_contract_revision: crate::workstream_host_contract::REVISION.to_owned(),
            host_contract_digest: crate::workstream_host_contract::DIGEST.to_owned(),
            op: RecordOp::Upsert,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: if needs_legacy_topology_migration {
                [(
                    "migration_source".to_owned(),
                    serde_json::Value::String("singular-target-v1".to_owned()),
                )]
                .into_iter()
                .collect()
            } else {
                Default::default()
            },
        };
        records.push((
            "project_collaboration_workspace",
            serde_json::to_string(&record).map_err(io)?,
        ));
    }

    for chat in library.chats.values() {
        if library.chat_target_sets.contains_key(&chat.id) {
            continue;
        }
        let binding = library.chat_targets.get(&chat.id).ok_or_else(|| {
            invalid_data(format!(
                "chat {} has no singular target binding to migrate; repair or reset this pre-release chat",
                chat.id
            ))
        })?;
        let target = library
            .work_targets
            .get(&binding.target_id)
            .ok_or_else(|| {
                invalid_data(format!(
                    "chat {} target {} is missing during target-set migration",
                    chat.id, binding.target_id
                ))
            })?;
        let record = ChatTargetSetRevisionRecord {
            chat_id: chat.id.clone(),
            revision: 0,
            members: vec![ChatTargetSetMemberRecord {
                target_id: target.id.clone(),
                adapter_family: target.adapter_family.clone(),
                path_scope: binding.path_scope.clone(),
                capability_ceiling: binding.capabilities.clone(),
                participation: if binding.capabilities.propose {
                    TargetParticipationMode::Writable
                } else {
                    TargetParticipationMode::ReadOnly
                },
            }],
            created_position: 0,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        };
        records.push((
            "chat_target_set",
            serde_json::to_string(&record).map_err(io)?,
        ));
    }

    for workstream in library.workstreams.values() {
        let Some(root) = library.workstream_roots.get(&workstream.id) else {
            continue;
        };
        if !root.project_id.is_empty() {
            continue;
        }
        let instance = library.instances.get(&root.placement_id).ok_or_else(|| {
            invalid_data(format!(
                "workstream {} creator placement is missing during migration",
                workstream.id
            ))
        })?;
        if instance.kind != InstanceKind::Using {
            continue;
        }
        let project_id = instance.project_id.as_deref().ok_or_else(|| {
            invalid_data(format!(
                "workstream {} has no project mapping; reset/repair this pre-project-workstream state",
                workstream.id
            ))
        })?;
        let project_has_historical_turns = library
            .chats
            .values()
            .filter(|chat| {
                library
                    .instances
                    .get(&chat.instance_id)
                    .and_then(|instance| instance.project_id.as_deref())
                    == Some(project_id)
            })
            .try_fold(false, |found, chat| {
                store
                    .records(&chat.id, crate::engine::TURN_BOUNDARY_KIND)
                    .map(|records| found || !records.is_empty())
                    .map_err(io)
            })?;
        if project_has_historical_turns {
            return Err(invalid_data(format!(
                "workstream {} has historical target-workspace turn coordinates that cannot be translated exactly; export the project and use the workstream repair/reset flow",
                workstream.id
            )));
        }
        let workspace_id = library
            .project_collaboration_workspaces
            .get(project_id)
            .map(|record| record.workspace_id.clone())
            .unwrap_or_else(|| format!("project-workspace-{project_id}"));
        let mut migrated = root.clone();
        migrated.project_id = project_id.to_owned();
        migrated.workspace_id = workspace_id;
        migrated.extra.insert(
            "migrated_legacy_target_id".to_owned(),
            serde_json::Value::String(root.target_id.clone()),
        );
        migrated.target_id.clear();
        migrated.adapter_family.clear();
        records.push((
            "workstream_root",
            serde_json::to_string(&migrated).map_err(io)?,
        ));
    }

    if records.is_empty() {
        return Ok(false);
    }
    let facts = records
        .iter()
        .map(|(kind, payload)| (LIBRARY_SCOPE, *kind, payload.as_str()))
        .collect::<Vec<_>>();
    store.append_records_atomically(&facts).map_err(io)?;
    Ok(true)
}

pub(crate) fn authoring_target_id(archetype_id: &str) -> String {
    format!("target-archetype-{archetype_id}")
}

/// The files target a project owns. Public so a caller can locate the
/// project's gate, which lives in that target's mainline (ADR 0110 §5).
pub fn managed_project_target_id(project_id: &str) -> String {
    format!("target-project-{project_id}")
}

fn append_library_record<T: serde::Serialize>(
    store: &mut Store,
    kind: &str,
    record: &T,
) -> std::io::Result<()> {
    store
        .append_record(
            LIBRARY_SCOPE,
            kind,
            &serde_json::to_string(record).map_err(io)?,
        )
        .map(|_| ())
        .map_err(io)
}

fn managed_target_record(
    id: String,
    name: String,
    owner: WorkTargetOwner,
    home_id: &gaugedesk_core::ids::HomeId,
    current_basis: String,
) -> WorkTargetRecord {
    WorkTargetRecord {
        schema: crate::library::LIBRARY_RECORD_SCHEMA,
        extra: Default::default(),
        locator_handle: format!("managed-target:{id}"),
        id,
        op: RecordOp::Upsert,
        name,
        owner,
        kind: WorkTargetKind::Managed,
        authority: home_id.as_str().to_owned(),
        parties: vec![home_id.as_str().to_owned()],
        adapter: "whipplescript".to_owned(),
        adapter_family: "whipplescript-v1".to_owned(),
        vcs_posture: TargetVcsPosture::Managed,
        current_basis: Some(current_basis),
        path_scope: vec![".".to_owned()],
        capabilities: TargetCapabilities::managed_default(),
        status: WorkTargetStatus::Available,
    }
}

/// The files every project's files-target is seeded with: its gate.
///
/// A project has a gate from the moment it exists, and it is review-by-hand
/// ([ADR 0117](../../../specs/decisions/0117-the-gate-is-a-queued-service-and-the-only-verdict.md)
/// §7). That removes the state where material arrives for a project that has no
/// policy for it — there is always a policy, and the safe one is the default.
///
/// It lives in the target's mainline rather than in one chat's worktree because
/// it is the *project's* program: every chat rooted here sees the same gate, and
/// changing it is an ordinary diff a human keeps or rejects (ADR 0110 §5).
fn default_gate_files() -> [(&'static str, &'static str); 2] {
    let (program, envelope) = crate::gate::GateKind::default().program();
    [
        (crate::gate::GATE_PROGRAM_PATH, program),
        (crate::gate::GATE_ENVELOPE_PATH, envelope),
    ]
}

fn init_managed_target(
    targets_dir: &std::path::Path,
    providers: &WorkspaceProviders,
    target_id: &str,
    files: &[(&str, &str)],
) -> std::io::Result<String> {
    let workspace = provider_for(providers, target_id)
        .init_at(&targets_dir.join(target_id))
        .map_err(io)?;
    workspace.seed_main(files).map_err(io)?;
    let probe_id = library::gen_id("target-basis");
    let probe = workspace.create_engagement(&probe_id).map_err(io)?;
    let basis = probe.boundary_cut().map_err(io)?.0;
    drop(probe);
    workspace.remove_engagement(&probe_id).map_err(io)?;
    Ok(basis)
}

/// ADR 0104's one-time additive migration. This recognizes only the untouched
/// built-in projection found in production. It retracts obsolete library
/// declarations without adopting or deleting their placement-owned files; all
/// non-library scopes and the legacy directories remain intact.
fn migrate_exact_pre_target_defaults(
    store: &mut Store,
    library: &crate::library::Library,
    home_id: &gaugedesk_core::ids::HomeId,
) -> std::io::Result<bool> {
    let Some(agent) = library.agents.get(DEFAULT_AGENT) else {
        return Ok(false);
    };
    let Some(project) = library.projects.get(DEFAULT_PROJECT) else {
        return Ok(false);
    };
    let Some(authoring) = library.instances.get(DEFAULT_INSTANCE) else {
        return Ok(false);
    };
    let Some(placement) = library.instances.get(DEFAULT_PLACEMENT) else {
        return Ok(false);
    };

    let exact = library.agents.len() == 1
        && library.projects.len() == 1
        && library.instances.len() == 2
        && library.chats.is_empty()
        && library.workstreams.is_empty()
        && library.work_targets.is_empty()
        && library.placement_targets.is_empty()
        && library.chat_targets.is_empty()
        && library.chat_target_sets.is_empty()
        && library.project_collaboration_workspaces.is_empty()
        && library.workstream_roots.is_empty()
        && agent.name == "assistant"
        && agent.instance_id == DEFAULT_INSTANCE
        && agent.config == "{}"
        && agent.current_version == 1
        && agent.versions.is_empty()
        && !agent.auto_upgrade
        && agent.forked_from.is_none()
        && project.name == "Personal"
        && (project.home_id.as_str().is_empty() || &project.home_id == home_id)
        && !project.network_isolated
        && project.run_purpose.is_none()
        && project.deployment_mode.is_none()
        && authoring.kind == InstanceKind::Authoring
        && authoring.agent_id == DEFAULT_AGENT
        && authoring.project_id.is_none()
        && authoring.version == 1
        && authoring.admission == Admission::Active
        && placement.kind == InstanceKind::Using
        && placement.agent_id == DEFAULT_AGENT
        && placement.project_id.as_deref() == Some(DEFAULT_PROJECT)
        && placement.version == 1
        && placement.admission == Admission::Active;
    if !exact {
        return Ok(false);
    }

    let mut agent = agent.clone();
    agent.op = RecordOp::Tombstone;
    let mut project = project.clone();
    project.op = RecordOp::Tombstone;
    let mut authoring = authoring.clone();
    authoring.op = RecordOp::Tombstone;
    let mut placement = placement.clone();
    placement.op = RecordOp::Tombstone;

    let payloads = [
        serde_json::to_string(&agent).map_err(io)?,
        serde_json::to_string(&project).map_err(io)?,
        serde_json::to_string(&authoring).map_err(io)?,
        serde_json::to_string(&placement).map_err(io)?,
    ];
    store
        .append_records_atomically(&[
            (LIBRARY_SCOPE, "agent", payloads[0].as_str()),
            (LIBRARY_SCOPE, "project", payloads[1].as_str()),
            (LIBRARY_SCOPE, "instance", payloads[2].as_str()),
            (LIBRARY_SCOPE, "instance", payloads[3].as_str()),
        ])
        .map_err(io)?;
    Ok(true)
}

/// ABIL-3's hard cutover persists the new explicit authority ceiling into every
/// pre-cutover authored package exactly once. This is a state migration, not a
/// loader fallback: after this commit lands, ordinary package loading remains
/// strict and a manifest with no `agent_abilities` is invalid.
fn migrate_agent_ability_manifests(
    store: &mut Store,
    library: &crate::library::Library,
    targets_dir: &std::path::Path,
    providers: &WorkspaceProviders,
) -> std::io::Result<bool> {
    let mut migrated = false;
    for archetype in library.agents.values() {
        let target = library.authoring_target_for(&archetype.id).ok_or_else(|| {
            invalid_data(format!(
                "archetype {} has no authoring target for agent-ability migration",
                archetype.id
            ))
        })?;
        if target.kind != WorkTargetKind::Managed {
            continue;
        }
        let workspace = provider_for(providers, &target.id).open_at(&targets_dir.join(&target.id));
        let engagement_id = library::gen_id("ability-migration");
        let engagement = workspace.create_engagement(&engagement_id).map_err(io)?;
        let result = (|| {
            let mut changed = false;
            let mut roots = vec![
                gaugedesk_boundary::definition::DRAFT_ROOT.to_owned(),
                crate::discipline::DISCIPLINE_DRAFT_ROOT.to_owned(),
            ];
            for version in archetype.versions.keys() {
                roots.push(gaugedesk_boundary::definition::version_root(*version));
                roots.push(crate::discipline::discipline_version_root(*version));
            }

            for package_root in roots.iter().step_by(2) {
                let manifest_path = format!(
                    "{package_root}/{}",
                    gaugedesk_boundary::definition::MANIFEST_FILE
                );
                let text = engagement.read_file(&manifest_path).map_err(io)?;
                let mut manifest: serde_json::Value =
                    serde_json::from_str(&text).map_err(invalid_data)?;
                if manifest.get("agent_abilities").is_some() {
                    continue;
                }
                let capabilities = manifest
                    .get_mut("capabilities")
                    .and_then(serde_json::Value::as_array_mut)
                    .ok_or_else(|| invalid_data("legacy package has no capability registry"))?;
                capabilities.retain(|capability| capability.as_str() != Some("human.ask"));
                let abilities = capabilities.clone();
                manifest["agent_abilities"] = serde_json::Value::Array(abilities);
                engagement
                    .write_file(
                        &manifest_path,
                        &format!("{}\n", serde_json::to_string_pretty(&manifest).map_err(io)?),
                    )
                    .map_err(io)?;

                let source_path = format!(
                    "{package_root}/{}",
                    gaugedesk_boundary::definition::SOURCE_FILE
                );
                let source = engagement.read_file(&source_path).map_err(io)?;
                let source = remove_legacy_human_authority(&source);
                engagement.write_file(&source_path, &source).map_err(io)?;
                changed = true;
            }

            for discipline_root in roots.iter().skip(1).step_by(2) {
                let path = format!(
                    "{discipline_root}/{}",
                    crate::discipline::DISCIPLINE_MANIFEST
                );
                let text = engagement.read_file(&path).map_err(io)?;
                let mut manifest: crate::discipline::DisciplineManifest =
                    serde_json::from_str(&text).map_err(invalid_data)?;
                if manifest.capabilities.remove("human.ask") {
                    engagement
                        .write_file(
                            &path,
                            &format!("{}\n", serde_json::to_string_pretty(&manifest).map_err(io)?),
                        )
                        .map_err(io)?;
                    changed = true;
                }
            }

            if changed {
                engagement
                    .commit_turn("migrate explicit agent ability ceilings")
                    .map_err(io)?;
                if engagement.merge_into_main().map_err(io)? != MergeOutcome::Clean {
                    return Err(invalid_data(
                        "archetype changed during agent-ability state migration",
                    ));
                }
            }
            Ok(changed)
        })();
        let _ = workspace.remove_engagement(&engagement_id);
        let changed = result?;

        // Reconcile references even after an interrupted prior run that landed
        // the workspace commit but had not yet appended the library record.
        let mut updated = archetype.clone();
        let mut references_changed = false;
        for version in archetype.versions.keys() {
            let mut resolved = published_archetype_version(targets_dir, &target.id, *version)?;
            // A frozen public profile is authored state, not a published
            // artifact, so the resolver cannot know it and always answers
            // `None`. Reconciling *references* therefore has to carry it
            // across, or this writes a version record with the profile
            // removed — and because the resolved record then always differs
            // from the stored one, it did that on every open, for every Panel
            // agent. The profile is what `publish_agent_deployment` reads, so
            // the symptom was a Panel agent that could be published until the
            // workbench was next opened and never again.
            resolved.panel_profile = archetype
                .versions
                .get(version)
                .and_then(|frozen| frozen.panel_profile.clone());
            if updated.versions.get(version) != Some(&resolved) {
                updated.versions.insert(*version, resolved);
                references_changed = true;
            }
        }
        if references_changed {
            updated.op = RecordOp::Upsert;
            append_library_record(store, "agent", &updated)?;
        }
        migrated |= changed || references_changed;
    }
    Ok(migrated)
}

fn remove_legacy_human_authority(source: &str) -> String {
    source
        .replace(", \"human.ask\"", "")
        .replace("\"human.ask\", ", "")
        .replace("\"human.ask\"", "")
        .replace("\n      with access to human {\n        ask\n      }", "")
}

#[cfg(test)]
mod target_set_migration_tests {
    use super::*;
    use crate::LockUnpoisoned;

    #[test]
    fn persisted_v102_workspace_pin_migrates_once_and_unknown_pins_write_nothing() {
        let mut store = Store::open_in_memory().unwrap();
        let project = ProjectRecord {
            id: "project-contract".to_owned(),
            op: RecordOp::Upsert,
            name: "Contract migration".to_owned(),
            is_default: false,
            home_id: gaugedesk_core::ids::HomeId::new("home-contract"),
            network_isolated: false,
            run_purpose: None,
            deployment_mode: None,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        };
        let previous = ProjectCollaborationWorkspaceRecord {
            project_id: project.id.clone(),
            workspace_id: "workspace-contract".to_owned(),
            home_id: project.home_id.clone(),
            substrate: "whipplescript".to_owned(),
            host_contract_revision: crate::workstream_host_contract::MIGRATABLE_PREVIOUS_REVISION
                .to_owned(),
            host_contract_digest: crate::workstream_host_contract::MIGRATABLE_PREVIOUS_DIGEST
                .to_owned(),
            op: RecordOp::Upsert,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: [("preserved".to_owned(), serde_json::Value::Bool(true))]
                .into_iter()
                .collect(),
        };
        let project_json = serde_json::to_string(&project).unwrap();
        let workspace_json = serde_json::to_string(&previous).unwrap();
        store
            .append_records_atomically(&[
                (LIBRARY_SCOPE, "project", project_json.as_str()),
                (
                    LIBRARY_SCOPE,
                    "project_collaboration_workspace",
                    workspace_json.as_str(),
                ),
            ])
            .unwrap();

        let library = crate::library::Library::rebuild(&store).unwrap();
        assert!(migrate_project_workspaces_and_target_sets(&mut store, &library).unwrap());
        let migrated = crate::library::Library::rebuild(&store).unwrap();
        let workspace = &migrated.project_collaboration_workspaces[&project.id];
        assert_eq!(workspace.workspace_id, previous.workspace_id);
        assert_eq!(workspace.home_id, previous.home_id);
        assert_eq!(workspace.extra, previous.extra);
        assert_eq!(
            workspace.host_contract_revision,
            crate::workstream_host_contract::REVISION
        );
        assert_eq!(
            workspace.host_contract_digest,
            crate::workstream_host_contract::DIGEST
        );
        assert!(!migrate_project_workspaces_and_target_sets(&mut store, &migrated).unwrap());

        let mut unsupported = migrated;
        let workspace = unsupported
            .project_collaboration_workspaces
            .get_mut(&project.id)
            .unwrap();
        workspace.host_contract_digest = "unsupported".to_owned();
        let before = store
            .records(LIBRARY_SCOPE, "project_collaboration_workspace")
            .unwrap()
            .len();
        let error =
            migrate_project_workspaces_and_target_sets(&mut store, &unsupported).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported WhippleScript contract pin"));
        assert_eq!(
            store
                .records(LIBRARY_SCOPE, "project_collaboration_workspace")
                .unwrap()
                .len(),
            before
        );
    }

    #[test]
    fn singular_binding_migrates_once_to_revision_zero_and_a_distinct_project_workspace() {
        let mut store = Store::open_in_memory().unwrap();
        let mut library = crate::library::Library::default();
        library.apply_project(ProjectRecord {
            id: "project-1".to_owned(),
            op: RecordOp::Upsert,
            name: "Project".to_owned(),
            is_default: false,
            home_id: gaugedesk_core::ids::HomeId::new("home-1"),
            network_isolated: false,
            run_purpose: None,
            deployment_mode: None,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        });
        library.apply_instance(InstanceRecord {
            id: "placement-1".to_owned(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Using,
            placement_kind: PlacementKind::Work,
            agent_id: "agent-1".to_owned(),
            project_id: Some("project-1".to_owned()),
            version: 1,
            admission: Admission::Active,
            collection_recipient: None,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        });
        library.apply_chat(ChatRecord {
            id: "chat-1".to_owned(),
            op: RecordOp::Upsert,
            instance_id: "placement-1".to_owned(),
            title: "Chat".to_owned(),
            created_position: 1,
            forked_from: None,
            forked_from_entry: None,
            forked_from_cut: None,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        });
        library.apply_work_target(WorkTargetRecord {
            id: "target/frontend".to_owned(),
            op: RecordOp::Upsert,
            name: "Frontend".to_owned(),
            owner: WorkTargetOwner::Project {
                project_id: "project-1".to_owned(),
            },
            kind: WorkTargetKind::Managed,
            authority: "home-1".to_owned(),
            parties: vec!["home-1".to_owned()],
            locator_handle: "managed:frontend".to_owned(),
            adapter: "whipplescript".to_owned(),
            adapter_family: "whipplescript-v1".to_owned(),
            vcs_posture: TargetVcsPosture::Managed,
            current_basis: Some("cut-1".to_owned()),
            path_scope: vec!["".to_owned()],
            capabilities: TargetCapabilities::managed_default(),
            status: WorkTargetStatus::Available,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        });
        library.apply_chat_target(ChatTargetBindingRecord {
            chat_id: "chat-1".to_owned(),
            op: RecordOp::Upsert,
            target_id: "target/frontend".to_owned(),
            basis: "cut-1".to_owned(),
            path_scope: vec!["".to_owned()],
            capabilities: TargetCapabilities::managed_default(),
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        });
        library.apply_workstream(WorkstreamRecord {
            id: "workstream-1".to_owned(),
            op: RecordOp::Upsert,
            instance_id: "placement-1".to_owned(),
            name: "Feature".to_owned(),
            created_position: 2,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        });
        library.apply_workstream_root(WorkstreamRootRecord {
            workstream_id: "workstream-1".to_owned(),
            op: RecordOp::Upsert,
            placement_id: "placement-1".to_owned(),
            project_id: String::new(),
            workspace_id: String::new(),
            target_id: "target/frontend".to_owned(),
            adapter_family: "whipplescript-v1".to_owned(),
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        });

        assert!(migrate_project_workspaces_and_target_sets(&mut store, &library).unwrap());
        let migrated = crate::library::Library::rebuild(&store).unwrap();
        let set = migrated.current_target_set("chat-1").unwrap();
        assert_eq!(set.revision, 0);
        assert_eq!(set.members[0].target_id, "target/frontend");
        assert_eq!(
            set.members[0].participation,
            TargetParticipationMode::Writable
        );
        let workspace = &migrated.project_collaboration_workspaces["project-1"];
        assert_eq!(workspace.workspace_id, "project-workspace-project-1");
        assert!(!migrated.work_targets.contains_key(&workspace.workspace_id));
        assert_eq!(workspace.extra["migration_source"], "singular-target-v1");
        let workstream_root = &migrated.workstream_roots["workstream-1"];
        assert_eq!(workstream_root.project_id, "project-1");
        assert_eq!(workstream_root.workspace_id, workspace.workspace_id);
        assert!(workstream_root.target_id.is_empty());
        assert_eq!(
            workstream_root.extra["migrated_legacy_target_id"],
            "target/frontend"
        );

        library.chat_target_sets = migrated.chat_target_sets;
        library.project_collaboration_workspaces = migrated.project_collaboration_workspaces;
        library.workstream_roots = migrated.workstream_roots;
        assert!(!migrate_project_workspaces_and_target_sets(&mut store, &library).unwrap());
    }

    #[test]
    fn legacy_workstream_with_untranslatable_turn_coordinates_requires_repair() {
        let mut store = Store::open_in_memory().unwrap();
        let mut library = crate::library::Library::default();
        library.apply_project(ProjectRecord {
            id: "project".into(),
            op: RecordOp::Upsert,
            name: "Project".into(),
            is_default: false,
            home_id: gaugedesk_core::ids::HomeId::new("home"),
            network_isolated: false,
            run_purpose: None,
            deployment_mode: None,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        });
        library.apply_instance(InstanceRecord {
            id: "placement".into(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Using,
            placement_kind: PlacementKind::Work,
            agent_id: "agent".into(),
            project_id: Some("project".into()),
            version: 1,
            admission: Admission::Active,
            collection_recipient: None,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        });
        library.apply_chat(ChatRecord {
            id: "chat".into(),
            op: RecordOp::Upsert,
            instance_id: "placement".into(),
            title: "Chat".into(),
            created_position: 1,
            forked_from: None,
            forked_from_entry: None,
            forked_from_cut: None,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        });
        library
            .apply_chat_target_set(ChatTargetSetRevisionRecord {
                chat_id: "chat".into(),
                revision: 0,
                members: vec![ChatTargetSetMemberRecord {
                    target_id: "target".into(),
                    adapter_family: "whipplescript-v1".into(),
                    path_scope: vec![".".into()],
                    capability_ceiling: TargetCapabilities::managed_default(),
                    participation: TargetParticipationMode::Writable,
                }],
                created_position: 0,
                schema: LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
            })
            .unwrap();
        library.apply_workstream(WorkstreamRecord {
            id: "stream".into(),
            op: RecordOp::Upsert,
            instance_id: "placement".into(),
            name: "Stream".into(),
            created_position: 2,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        });
        library.apply_workstream_root(WorkstreamRootRecord {
            workstream_id: "stream".into(),
            op: RecordOp::Upsert,
            placement_id: "placement".into(),
            project_id: String::new(),
            workspace_id: String::new(),
            target_id: "target".into(),
            adapter_family: "whipplescript-v1".into(),
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        });
        store
            .append_record("chat", crate::engine::TURN_BOUNDARY_KIND, "legacy-boundary")
            .unwrap();
        let error = migrate_project_workspaces_and_target_sets(&mut store, &library).unwrap_err();
        assert!(error.to_string().contains("cannot be translated exactly"));
        assert!(error.to_string().contains("repair/reset"));
    }

    #[test]
    fn startup_cancels_a_bare_reservation_before_any_main_advance() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        {
            let mut workbench = workbench.lock_unpoisoned();
            let collaboration =
                workbench.library.project_collaboration_workspaces[DEFAULT_PROJECT].clone();
            workbench
                .workspace_by_storage_id(&collaboration.workspace_id)
                .unwrap()
                .create_named_workstream("recover-stream", Some("Recover"))
                .unwrap();
            workbench.write_workstream_record(WorkstreamRecord {
                id: "recover-stream".into(),
                op: RecordOp::Upsert,
                instance_id: DEFAULT_PLACEMENT.into(),
                name: "Recover".into(),
                created_position: 0,
                schema: LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
            });
            workbench.write_workstream_root_record(WorkstreamRootRecord {
                workstream_id: "recover-stream".into(),
                op: RecordOp::Upsert,
                placement_id: DEFAULT_PLACEMENT.into(),
                project_id: DEFAULT_PROJECT.into(),
                workspace_id: collaboration.workspace_id.clone(),
                target_id: String::new(),
                adapter_family: String::new(),
                schema: LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
            });
            let reserved = workbench
                .workspace_by_storage_id(&collaboration.workspace_id)
                .unwrap()
                .reserve_workstream_promotion_boundary("recover-stream", "reservation-crash")
                .unwrap();
            assert_eq!(reserved.reservation_id, "reservation-crash");
        }
        drop(workbench);

        let reopened = crate::open_workbench(root.path()).unwrap();
        let reopened = reopened.lock_unpoisoned();
        let collaboration = &reopened.library.project_collaboration_workspaces[DEFAULT_PROJECT];
        let row = reopened
            .workspace_by_storage_id(&collaboration.workspace_id)
            .unwrap()
            .workstream("recover-stream")
            .unwrap()
            .unwrap();
        assert_eq!(
            row.status,
            whipplescript_store::workstreams::StreamStatus::Active,
            "startup cancels a reservation whose pre-CAS intent is not durable"
        );
        assert_eq!(
            reopened.library.workstreams["recover-stream"].extra["promotion_recovery"]["status"],
            "cancelled-before-advance"
        );
    }
}

fn invalid_data(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

/// TARGET-1 rejects every pre-target shape not admitted by ADR 0104 instead of
/// inventing compatibility aliases that would preserve the wrong authority
/// boundary. Such state requires its own explicit migration decision.
fn normalized_target_scope(scope: &str) -> Result<Vec<&str>, String> {
    if scope.is_empty() || scope == "." {
        return Ok(Vec::new());
    }
    if scope.starts_with('/') || scope.contains('\\') || scope.chars().any(char::is_control) {
        return Err(format!("unsafe target path scope `{scope}`"));
    }
    let parts = scope.split('/').collect::<Vec<_>>();
    if parts
        .iter()
        .any(|part| part.is_empty() || *part == "." || *part == "..")
    {
        return Err(format!("unsafe target path scope `{scope}`"));
    }
    Ok(parts)
}

fn target_scopes_physically_overlap(
    targets_dir: &std::path::Path,
    left_target: &WorkTargetRecord,
    left_scopes: &[String],
    right_target: &WorkTargetRecord,
    right_scopes: &[String],
) -> Result<bool, String> {
    let left_root = crate::target_adapter::protected_target_root(targets_dir, left_target)?;
    let right_root = crate::target_adapter::protected_target_root(targets_dir, right_target)?;
    for left in left_scopes {
        let left = normalized_target_scope(left)?
            .into_iter()
            .fold(left_root.clone(), |path, part| path.join(part));
        for right in right_scopes {
            let right = normalized_target_scope(right)?
                .into_iter()
                .fold(right_root.clone(), |path, part| path.join(part));
            if left.starts_with(&right) || right.starts_with(&left) {
                return Ok(true);
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        fn file_identities(root: &std::path::Path) -> Result<BTreeSet<(u64, u64)>, String> {
            let mut identities = BTreeSet::new();
            let mut pending = vec![root.to_path_buf()];
            while let Some(path) = pending.pop() {
                let metadata = match std::fs::symlink_metadata(&path) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.to_string()),
                };
                if metadata.file_type().is_symlink() {
                    continue;
                }
                if metadata.is_dir() {
                    for entry in std::fs::read_dir(&path).map_err(|error| error.to_string())? {
                        pending.push(entry.map_err(|error| error.to_string())?.path());
                    }
                } else if metadata.is_file() && metadata.nlink() > 1 {
                    identities.insert((metadata.dev(), metadata.ino()));
                }
            }
            Ok(identities)
        }

        let mut left_identities = BTreeSet::new();
        for scope in left_scopes {
            let path = normalized_target_scope(scope)?
                .into_iter()
                .fold(left_root.clone(), |path, part| path.join(part));
            left_identities.extend(file_identities(&path)?);
        }
        for scope in right_scopes {
            let path = normalized_target_scope(scope)?
                .into_iter()
                .fold(right_root.clone(), |path, part| path.join(part));
            if file_identities(&path)?
                .iter()
                .any(|identity| left_identities.contains(identity))
            {
                return Ok(true);
            }
        }
    }
    #[cfg(not(unix))]
    if left_target.kind != WorkTargetKind::Managed || right_target.kind != WorkTargetKind::Managed {
        return Err(format!(
            "cannot prove hard-link alias safety between external targets {} and {} on this platform",
            left_target.id, right_target.id
        ));
    }
    Ok(false)
}

fn validate_target_cutover(
    library: &crate::library::Library,
    targets_dir: &std::path::Path,
) -> std::io::Result<()> {
    let invalid = |message: String| std::io::Error::new(std::io::ErrorKind::InvalidData, message);

    for target in library.work_targets.values() {
        let owner_exists = match &target.owner {
            WorkTargetOwner::Project { project_id } => library.projects.contains_key(project_id),
            WorkTargetOwner::Archetype { archetype_id } => {
                library.agents.contains_key(archetype_id)
            }
        };
        let posture_matches = matches!(
            (target.kind, target.vcs_posture),
            (WorkTargetKind::Managed, TargetVcsPosture::Managed)
                | (WorkTargetKind::ExternalVcs, TargetVcsPosture::ExternalVcs)
                | (
                    WorkTargetKind::ExternalFolder,
                    TargetVcsPosture::Unversioned
                )
        );
        if !owner_exists
            || !posture_matches
            || target.name.is_empty()
            || target.authority.is_empty()
            || target.locator_handle.is_empty()
            || target.adapter.is_empty()
            || target.adapter_family.is_empty()
            || target.path_scope.is_empty()
            || !target.capabilities.read
        {
            return Err(invalid(format!(
                "work target {} has an invalid authority, adapter, scope, or VCS posture",
                target.id
            )));
        }
        if target.status == WorkTargetStatus::Available
            && target.current_basis.as_deref().is_none_or(str::is_empty)
        {
            return Err(invalid(format!(
                "available work target {} has no exact current basis",
                target.id
            )));
        }
    }

    for agent in library.agents.values() {
        let target = library.authoring_target_for(&agent.id).ok_or_else(|| {
            invalid(format!(
                "pre-TARGET workspace: archetype {} has no authoring target; reset this pre-release state root",
                agent.id
            ))
        })?;
        if target.kind != WorkTargetKind::Managed {
            return Err(invalid(format!(
                "archetype {} authoring target must be managed",
                agent.id
            )));
        }
    }
    for project in library.projects.values() {
        if project.home_id.as_str().is_empty()
            || library.targets_for_project(&project.id).is_empty()
        {
            return Err(invalid(format!(
                "pre-TARGET workspace: project {} has no Home-bound target; reset this pre-release state root",
                project.id
            )));
        }
        let workspace = library
            .project_collaboration_workspaces
            .get(&project.id)
            .ok_or_else(|| {
                invalid(format!(
                    "project {} has no collaboration workspace; rerun the exact target-set migration",
                    project.id
                ))
            })?;
        if workspace.home_id != project.home_id
            || workspace.substrate != "whipplescript"
            || workspace.host_contract_revision != crate::workstream_host_contract::REVISION
            || workspace.host_contract_digest != crate::workstream_host_contract::DIGEST
        {
            return Err(invalid(format!(
                "project {} collaboration workspace has a mismatched Home or WhippleScript contract pin",
                project.id
            )));
        }
    }
    for placement in library
        .instances
        .values()
        .filter(|instance| instance.kind == InstanceKind::Using)
    {
        let project_id = placement
            .project_id
            .as_deref()
            .ok_or_else(|| invalid(format!("placement {} has no project", placement.id)))?;
        if placement.placement_kind == PlacementKind::Panel {
            if library
                .chats
                .values()
                .any(|chat| chat.instance_id == placement.id)
            {
                return Err(invalid(format!(
                    "panel placement {} must not host work chats",
                    placement.id
                )));
            }
            continue;
        }
        let targets = library
            .placement_targets
            .get(&placement.id)
            .ok_or_else(|| {
                invalid(format!(
                "pre-TARGET workspace: placement {} owns files; reset this pre-release state root",
                placement.id
            ))
            })?;
        if targets.target_ids.is_empty() {
            return Err(invalid(format!(
                "placement {} has no eligible target",
                placement.id
            )));
        }
        for target_id in &targets.target_ids {
            let target = library.work_targets.get(target_id).ok_or_else(|| {
                invalid(format!(
                    "placement {} target {target_id} is missing",
                    placement.id
                ))
            })?;
            if !matches!(&target.owner, WorkTargetOwner::Project { project_id: owner } if owner == project_id)
            {
                return Err(invalid(format!(
                    "placement {} target {target_id} is owned outside project {project_id}",
                    placement.id
                )));
            }
        }
    }
    for chat in library.chats.values() {
        let target_set = library.current_target_set(&chat.id).ok_or_else(|| {
            invalid(format!(
                "chat {} has no immutable target-set revision",
                chat.id
            ))
        })?;
        let binding = library.chat_targets.get(&chat.id);
        if target_set.members.len() == 1 && binding.is_none() {
            return Err(invalid(format!(
                "one-target chat {} has no compatibility binding",
                chat.id
            )));
        }
        if target_set.members.len() > 1 && binding.is_some() {
            return Err(invalid(format!(
                "multi-target chat {} has a misleading singular binding",
                chat.id
            )));
        }
        let root = library.instances.get(&chat.instance_id).ok_or_else(|| {
            invalid(format!(
                "chat {} root {} is missing",
                chat.id, chat.instance_id
            ))
        })?;
        if let Some(binding) = binding {
            let target = library
                .work_targets
                .get(&binding.target_id)
                .ok_or_else(|| {
                    invalid(format!(
                        "chat {} target {} is missing",
                        chat.id, binding.target_id
                    ))
                })?;
            let eligible = match root.kind {
                InstanceKind::Authoring => matches!(
                    &target.owner,
                    WorkTargetOwner::Archetype { archetype_id } if archetype_id == &root.agent_id
                ),
                InstanceKind::Using => library
                    .placement_targets
                    .get(&root.id)
                    .is_some_and(|record| record.target_ids.contains(&binding.target_id)),
            };
            let caps_fit = (!binding.capabilities.read || target.capabilities.read)
                && (!binding.capabilities.propose || target.capabilities.propose)
                && (!binding.capabilities.apply || target.capabilities.apply)
                && (!binding.capabilities.publish || target.capabilities.publish)
                && (!binding.capabilities.release || target.capabilities.release);
            if !eligible
                || binding.basis.is_empty()
                || binding.path_scope.is_empty()
                || !binding
                    .path_scope
                    .iter()
                    .all(|path| target.path_scope.contains(path))
                || !caps_fit
                || binding.target_id != target_set.members[0].target_id
            {
                return Err(invalid(format!(
                    "chat {} has an invalid target binding",
                    chat.id
                )));
            }
        }
        let project_id = root.project_id.as_deref();
        for member in &target_set.members {
            let member_target = library.work_targets.get(&member.target_id).ok_or_else(|| {
                invalid(format!(
                    "chat {} target-set member {} is missing",
                    chat.id, member.target_id
                ))
            })?;
            let owner_matches = match root.kind {
                InstanceKind::Authoring => matches!(
                    &member_target.owner,
                    WorkTargetOwner::Archetype { archetype_id } if archetype_id == &root.agent_id
                ),
                InstanceKind::Using => matches!(
                    (&member_target.owner, project_id),
                    (WorkTargetOwner::Project { project_id: owner }, Some(project_id))
                        if owner == project_id
                ),
            };
            let eligible = match root.kind {
                InstanceKind::Authoring => owner_matches,
                InstanceKind::Using => library
                    .placement_targets
                    .get(&root.id)
                    .is_some_and(|record| record.target_ids.contains(&member.target_id)),
            };
            if !owner_matches
                || !eligible
                || member.adapter_family != member_target.adapter_family
                || member.path_scope.is_empty()
                || member
                    .path_scope
                    .iter()
                    .any(|path| normalized_target_scope(path).is_err())
                || !member
                    .path_scope
                    .iter()
                    .all(|path| member_target.path_scope.contains(path))
            {
                return Err(invalid(format!(
                    "chat {} target-set member {} is outside its root, Home, adapter, or path authority",
                    chat.id, member.target_id
                )));
            }
        }
        for (index, left) in target_set.members.iter().enumerate() {
            let left_target = &library.work_targets[&left.target_id];
            for right in target_set.members.iter().skip(index + 1) {
                let right_target = &library.work_targets[&right.target_id];
                if target_scopes_physically_overlap(
                    targets_dir,
                    left_target,
                    &left.path_scope,
                    right_target,
                    &right.path_scope,
                )
                .map_err(invalid)?
                {
                    return Err(invalid(format!(
                        "chat {} target scopes overlap between {} and {}",
                        chat.id, left.target_id, right.target_id
                    )));
                }
            }
        }
    }
    for workstream in library.workstreams.values() {
        let root = library
            .workstream_roots
            .get(&workstream.id)
            .ok_or_else(|| {
                invalid(format!(
                    "workstream {} has no collaboration root",
                    workstream.id
                ))
            })?;
        if root.placement_id != workstream.instance_id {
            return Err(invalid(format!(
                "workstream {} disagrees with its creator placement",
                workstream.id
            )));
        }
        if !root.project_id.is_empty() {
            let collaboration = library
                .project_collaboration_workspaces
                .get(&root.project_id);
            if !library.projects.contains_key(&root.project_id)
                || !root.target_id.is_empty()
                || !root.adapter_family.is_empty()
                || collaboration.is_none_or(|record| record.workspace_id != root.workspace_id)
            {
                return Err(invalid(format!(
                    "workstream {} has an invalid project collaboration root; reset/repair this pre-project-workstream state",
                    workstream.id
                )));
            }
        } else {
            let instance = library.instances.get(&root.placement_id).ok_or_else(|| {
                invalid(format!(
                    "authoring workstream {} creator placement is missing",
                    workstream.id
                ))
            })?;
            match instance.kind {
                InstanceKind::Using => {
                    return Err(invalid(format!(
                        "workstream {} has a pre-project target root; reset/repair this state",
                        workstream.id
                    )));
                }
                InstanceKind::Authoring => {
                    let target = library.work_targets.get(&root.target_id);
                    if !root.workspace_id.is_empty()
                        || target.is_none_or(|target| target.adapter_family != root.adapter_family)
                    {
                        return Err(invalid(format!(
                            "workstream {} has an invalid authoring target root",
                            workstream.id
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_archetype_versions(
    library: &crate::library::Library,
    targets_dir: &std::path::Path,
) -> std::io::Result<()> {
    for archetype in library.agents.values() {
        let target = library.authoring_target_for(&archetype.id).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("archetype {} has no authoring target", archetype.id),
            )
        })?;
        archetype.versions.get(&archetype.current_version).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "pre-discipline workspace: archetype {} has no complete current version; reset this pre-release state root",
                    archetype.id
                ),
            )
        })?;
        for (version, expected) in &archetype.versions {
            let mut resolved = published_archetype_version(targets_dir, &target.id, *version)?;
            // The check is that the *bytes* still match what the version names.
            // A frozen public profile is authored state the resolver cannot
            // know, so it always answers `None`; comparing it would make every
            // Panel agent fail this validation and refuse to open the workbench
            // it lives in. Carry it across so the comparison is about the two
            // refs this validator is named for.
            resolved.panel_profile = expected.panel_profile.clone();
            if &resolved != expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "archetype {} package or discipline bytes do not match version {}",
                        archetype.id, version
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// What startup reconciliation yields: open managed targets, live engagements,
/// and the chat-id → target-id engagement index.
type StartupTargets = (
    BTreeMap<String, Box<dyn Workspace>>,
    BTreeMap<String, Box<dyn ChatWorkspace>>,
    BTreeMap<String, String>,
);

/// Chat ids whose latest library `chat` record is a tombstone — the only
/// evidence that the chat was *explicitly deleted*. Folded latest-wins over
/// the raw record stream (the [`crate::library::Library`] projection drops
/// tombstoned rows, so it cannot distinguish "deleted" from "never recorded").
fn explicitly_deleted_chats(store: &Store) -> std::io::Result<BTreeSet<String>> {
    let mut deleted = BTreeSet::new();
    for row in store.records(LIBRARY_SCOPE, "chat").map_err(io)? {
        let record: ChatRecord =
            serde_json::from_str(&row).map_err(|error| std::io::Error::other(error.to_string()))?;
        match record.op {
            RecordOp::Tombstone => {
                deleted.insert(record.id);
            }
            RecordOp::Upsert => {
                deleted.remove(&record.id);
            }
        }
    }
    Ok(deleted)
}

fn open_startup_targets(
    library: &crate::library::Library,
    targets_dir: &std::path::Path,
    providers: &WorkspaceProviders,
    deleted_chats: &BTreeSet<String>,
) -> std::io::Result<StartupTargets> {
    let mut targets = BTreeMap::new();
    let mut engagements = BTreeMap::new();
    let mut engagement_index = BTreeMap::new();
    for target in library.work_targets.values() {
        let workspace = match target.kind {
            WorkTargetKind::Managed => {
                provider_for(providers, &target.id).open_at(&targets_dir.join(&target.id))
            }
            WorkTargetKind::ExternalVcs | WorkTargetKind::ExternalFolder => {
                crate::target_adapter::open_external_workspace(targets_dir, target)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?
            }
        };
        let existing = workspace.reconcile_engagements().map_err(io)?;
        for (chat_id, eng) in existing {
            // DR-0054 Phase A: an engagement branch is a chat's working copy —
            // persisted user data. Reconciliation may release it only when the
            // library shows the chat was explicitly deleted. A missing or
            // mismatched binding with no delete record can also mean a failed
            // append or a downgrade, so the branch stays and we say so.
            match library.chat_targets.get(&chat_id) {
                Some(binding) if binding.target_id == target.id => {
                    engagement_index.insert(chat_id.clone(), target.id.clone());
                    engagements.insert(chat_id, eng);
                }
                _ if deleted_chats.contains(&chat_id) => {
                    // Finishing an explicit, recorded delete is governed removal.
                    let _ = workspace.remove_engagement(&chat_id);
                }
                Some(binding) => {
                    tracing::warn!(
                        chat = %chat_id,
                        target = %target.id,
                        bound_target = %binding.target_id,
                        "startup reconcile: engagement branch is bound to another target and the chat was never deleted; leaving it in place",
                    );
                }
                None => {
                    tracing::warn!(
                        chat = %chat_id,
                        target = %target.id,
                        "startup reconcile: engagement branch has no library binding and no delete record; leaving it in place",
                    );
                }
            }
        }
        targets.insert(target.id.clone(), workspace);
    }
    Ok((targets, engagements, engagement_index))
}

fn collaboration_workspaces_dir(targets_dir: &std::path::Path) -> std::path::PathBuf {
    targets_dir
        .parent()
        .unwrap_or(targets_dir)
        .join("collaboration-workspaces")
}

fn open_project_collaboration_workspaces(
    library: &crate::library::Library,
    targets_dir: &std::path::Path,
    providers: &WorkspaceProviders,
) -> std::io::Result<BTreeMap<String, Box<dyn Workspace>>> {
    let root = collaboration_workspaces_dir(targets_dir);
    let mut workspaces = BTreeMap::new();
    for record in library.project_collaboration_workspaces.values() {
        let path = root.join(&record.workspace_id);
        let workspace = if path.join("repo").exists() {
            provider_for(providers, &record.workspace_id).open_at(&path)
        } else {
            provider_for(providers, &record.workspace_id)
                .init_at(&path)
                .map_err(io)?
        };
        workspaces.insert(record.workspace_id.clone(), workspace);
    }
    Ok(workspaces)
}

fn seed_empty_collaboration_workspaces(
    library: &crate::library::Library,
    targets: &BTreeMap<String, Box<dyn Workspace>>,
    collaborations: &BTreeMap<String, Box<dyn Workspace>>,
) -> std::io::Result<()> {
    for record in library.project_collaboration_workspaces.values() {
        let collaboration = collaborations.get(&record.workspace_id).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "declared project collaboration workspace is not open",
            )
        })?;
        let probe_id = library::gen_id("collaboration-probe");
        let probe = collaboration.create_engagement(&probe_id).map_err(io)?;
        let already_seeded = probe.tree().map_err(io)?.iter().any(|entry| !entry.is_dir);
        drop(probe);
        collaboration.remove_engagement(&probe_id).map_err(io)?;
        if already_seeded {
            continue;
        }

        let mut owned = Vec::new();
        for target in library.targets_for_project(&record.project_id) {
            let source = targets.get(&target.id).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("project target {} is not open", target.id),
                )
            })?;
            let source_probe_id = library::gen_id("partition-source");
            let source_probe = source.create_engagement(&source_probe_id).map_err(io)?;
            let encoded = crate::library::target_id_path_v1(&target.id)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            for entry in source_probe.tree().map_err(io)? {
                if entry.is_dir || entry.path.starts_with(".gaugedesk-runtime/") {
                    continue;
                }
                let body = source_probe.read_file(&entry.path).map_err(io)?;
                owned.push((format!("targets/{encoded}/{}", entry.path), body));
            }
            drop(source_probe);
            source.remove_engagement(&source_probe_id).map_err(io)?;
        }
        let borrowed = owned
            .iter()
            .map(|(path, body)| (path.as_str(), body.as_str()))
            .collect::<Vec<_>>();
        collaboration.seed_main(&borrowed).map_err(io)?;
    }
    Ok(())
}

/// Recover a promotion whose durable WhippleScript boundary survived a Home
/// restart. A bare reservation does not prove that manifest construction or a
/// combined target-settlement preflight completed, so startup cancels it before
/// Main moves and records the repair. Once the ref is durably advanced, startup
/// may only close forward by archiving/re-homing the line.
fn recover_project_workstream_promotions(
    store: &mut Store,
    library: &mut crate::library::Library,
    collaborations: &BTreeMap<String, Box<dyn Workspace>>,
) -> std::io::Result<()> {
    let workstreams = library.workstreams.values().cloned().collect::<Vec<_>>();
    for workstream in workstreams {
        let Some(root) = library.workstream_roots.get(&workstream.id) else {
            continue;
        };
        if root.project_id.is_empty() {
            continue;
        }
        let workspace = collaborations.get(&root.workspace_id).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "workstream {} collaboration workspace is unavailable",
                    workstream.id
                ),
            )
        })?;
        let Some(row) = workspace.workstream(&workstream.id).map_err(io)? else {
            continue;
        };
        use whipplescript_store::workstreams::StreamStatus;
        if !matches!(
            row.status,
            StreamStatus::BoundaryReserved | StreamStatus::RefAdvanced
        ) {
            continue;
        }
        let reservation_id = row.reservation_id.as_deref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "workstream {} has a promotion state without its reservation",
                    workstream.id
                ),
            )
        })?;
        if row.status == StreamStatus::BoundaryReserved {
            workspace
                .release_workstream_promotion_boundary(&workstream.id, reservation_id)
                .map_err(io)?;
            let mut repaired = workstream.clone();
            repaired.extra.insert(
                "promotion_recovery".to_owned(),
                serde_json::json!({
                    "status": "cancelled-before-advance",
                    "reservation_id": reservation_id,
                }),
            );
            store
                .append_record(
                    LIBRARY_SCOPE,
                    "workstream",
                    &serde_json::to_string(&repaired).map_err(io)?,
                )
                .map_err(io)?;
            library.apply_workstream(repaired);
            continue;
        }
        match workspace
            .promote_workstream_boundary(&workstream.id, &root.workspace_id, reservation_id)
            .map_err(io)?
        {
            gaugedesk_workspace::WorkstreamPromotionOutcome::Promoted { .. } => {}
            gaugedesk_workspace::WorkstreamPromotionOutcome::Conflicted { .. } => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "workstream {} changed after its Main ref advance; promotion recovery cannot close exactly",
                        workstream.id
                    ),
                ));
            }
            gaugedesk_workspace::WorkstreamPromotionOutcome::Refused(reason) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "workstream {} promotion recovery was refused: {reason}",
                        workstream.id
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Materialize the current substance and topology of the pre-ADR-0151
/// one-target workspace into the new project collaboration workspace. The
/// record migration above refuses projects with historical workstream turn
/// coordinates; this function therefore has an exact current-state mapping and
/// never pretends old cut ids survived a cross-workspace rewrite.
#[allow(clippy::too_many_arguments)]
fn migrate_legacy_project_topology(
    store: &mut Store,
    library: &mut crate::library::Library,
    targets: &BTreeMap<String, Box<dyn Workspace>>,
    collaborations: &BTreeMap<String, Box<dyn Workspace>>,
    engagements: &mut BTreeMap<String, Box<dyn ChatWorkspace>>,
    engagement_index: &mut BTreeMap<String, String>,
) -> std::io::Result<()> {
    let pending = library
        .project_collaboration_workspaces
        .values()
        .filter(|record| {
            record
                .extra
                .get("migration_source")
                .and_then(serde_json::Value::as_str)
                == Some("singular-target-v1")
        })
        .cloned()
        .collect::<Vec<_>>();
    for collaboration_record in pending {
        let collaboration = collaborations
            .get(&collaboration_record.workspace_id)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "project {} migration collaboration workspace is unavailable",
                        collaboration_record.project_id
                    ),
                )
            })?;
        let project_chats = library
            .chats
            .values()
            .filter(|chat| {
                library
                    .instances
                    .get(&chat.instance_id)
                    .and_then(|instance| instance.project_id.as_deref())
                    == Some(collaboration_record.project_id.as_str())
            })
            .cloned()
            .collect::<Vec<_>>();

        for chat in project_chats {
            let Some(binding) = library.chat_targets.get(&chat.id) else {
                continue;
            };
            let Some(source) = engagements.get(&chat.id) else {
                continue;
            };
            let encoded = crate::library::target_id_path_v1(&binding.target_id)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            let prefix = format!("targets/{encoded}");
            let roots = [prefix.clone()].into_iter().collect::<BTreeSet<_>>();
            let migrated = collaboration
                .create_engagement_subset(&chat.id, collaboration.mainline(), &roots)
                .map_err(io)?;
            let source_files = source
                .tree()
                .map_err(io)?
                .into_iter()
                .filter(|entry| !entry.is_dir && !entry.path.starts_with(".gaugedesk-runtime/"))
                .map(|entry| entry.path)
                .collect::<BTreeSet<_>>();
            let migrated_files = migrated
                .tree()
                .map_err(io)?
                .into_iter()
                .filter(|entry| !entry.is_dir && entry.path.starts_with(&format!("{prefix}/")))
                .map(|entry| entry.path)
                .collect::<Vec<_>>();
            for path in migrated_files {
                let relative = path.strip_prefix(&format!("{prefix}/")).unwrap_or_default();
                if !source_files.contains(relative) {
                    migrated.remove_file(&path).map_err(io)?;
                }
            }
            for relative in source_files {
                let body = source
                    .read_file_bytes_capped(&relative, usize::MAX)
                    .map_err(io)?
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("legacy chat {} file {relative} disappeared", chat.id),
                        )
                    })?;
                migrated
                    .write_file_bytes(&format!("{prefix}/{relative}"), &body)
                    .map_err(io)?;
            }
            let _ = migrated
                .commit_turn("migrate singular target candidate")
                .map_err(io)?;
            engagement_index.insert(chat.id.clone(), collaboration_record.workspace_id.clone());
            engagements.insert(chat.id, migrated);
        }

        let roots = library
            .workstream_roots
            .values()
            .filter(|root| root.project_id == collaboration_record.project_id)
            .filter_map(|root| {
                root.extra
                    .get("migrated_legacy_target_id")
                    .and_then(serde_json::Value::as_str)
                    .map(|target_id| (root.clone(), target_id.to_owned()))
            })
            .collect::<Vec<_>>();
        for (root, source_target_id) in roots {
            let workstream = library
                .workstreams
                .get(&root.workstream_id)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "legacy workstream {} declaration is unavailable",
                            root.workstream_id
                        ),
                    )
                })?;
            let source = targets.get(&source_target_id).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "legacy workstream {} target is unavailable",
                        root.workstream_id
                    ),
                )
            })?;
            let source_row = source.workstream(&root.workstream_id).map_err(io)?;
            collaboration
                .create_named_workstream(&root.workstream_id, Some(&workstream.name))
                .map_err(io)?;
            if let Some(source_row) = source_row {
                if source_row.status == whipplescript_store::workstreams::StreamStatus::Archived {
                    collaboration
                        .archive_workstream(&root.workstream_id)
                        .map_err(io)?;
                } else {
                    for chat_id in source.workstream_members(&root.workstream_id).map_err(io)? {
                        collaboration
                            .transfer_engagement_to_workstream(&chat_id, &root.workstream_id)
                            .map_err(io)?;
                        if let Some(engagement) = engagements.get_mut(&chat_id) {
                            engagement
                                .set_target(&collaboration.workstream_ref(&root.workstream_id))
                                .map_err(io)?;
                        }
                    }
                }
            }
        }

        let mut completed = collaboration_record.clone();
        completed.extra.remove("migration_source");
        completed.extra.insert(
            "migration_completed".to_owned(),
            serde_json::Value::String("singular-target-v1".to_owned()),
        );
        append_library_record(store, "project_collaboration_workspace", &completed)?;
        library.apply_project_collaboration_workspace(completed);
    }
    Ok(())
}

fn open_project_chat_engagements(
    library: &crate::library::Library,
    collaborations: &BTreeMap<String, Box<dyn Workspace>>,
    engagements: &mut BTreeMap<String, Box<dyn ChatWorkspace>>,
    engagement_index: &mut BTreeMap<String, String>,
    only_workspace_id: Option<&str>,
) -> std::io::Result<()> {
    for chat in library.chats.values() {
        let Some(instance) = library.instances.get(&chat.instance_id) else {
            continue;
        };
        if instance.kind != InstanceKind::Using {
            continue;
        }
        let project_id = instance.project_id.as_deref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("work chat {} has no project", chat.id),
            )
        })?;
        let collaboration_record = library
            .project_collaboration_workspaces
            .get(project_id)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("work chat {} has no collaboration workspace", chat.id),
                )
            })?;
        if only_workspace_id.is_some_and(|id| id != collaboration_record.workspace_id) {
            continue;
        }
        let workspace = collaborations
            .get(&collaboration_record.workspace_id)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("work chat {} collaboration workspace is not open", chat.id),
                )
            })?;
        let roots = library
            .current_target_set(&chat.id)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("work chat {} has no target set", chat.id),
                )
            })?
            .members
            .iter()
            .map(|member| {
                crate::library::target_id_path_v1(&member.target_id)
                    .map(|encoded| format!("targets/{encoded}"))
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
            })
            .collect::<std::io::Result<BTreeSet<_>>>()?;
        let home = workspace.engagement_home_receipt(&chat.id).map_err(io)?;
        let target = home
            .line_branch_id
            .as_deref()
            .unwrap_or(workspace.mainline());
        let engagement = workspace
            .create_engagement_subset(&chat.id, target, &roots)
            .map_err(io)?;
        engagements.insert(chat.id.clone(), engagement);
        engagement_index.insert(chat.id.clone(), collaboration_record.workspace_id.clone());
    }
    Ok(())
}

fn builtin_instance_id(archetype: &crate::app_support::BuiltinArchetype) -> String {
    if archetype.id == DEFAULT_AGENT {
        DEFAULT_INSTANCE.to_owned()
    } else {
        format!("inst-{}", archetype.id.trim_start_matches("agent-"))
    }
}

fn seed_builtin_archetype(
    store: &mut Store,
    library: &mut crate::library::Library,
    targets_dir: &std::path::Path,
    providers: &WorkspaceProviders,
    home_id: &gaugedesk_core::ids::HomeId,
    archetype: &crate::app_support::BuiltinArchetype,
) -> std::io::Result<()> {
    if library.agents.contains_key(archetype.id) {
        return Ok(());
    }
    let definition = crate::app_support::builtin_agent_definition(archetype);
    let skills = archetype
        .official_skills
        .then(crate::official_skills::office_skill_references)
        .unwrap_or_default();
    let authored_files = archetype_files(&definition, skills)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let authored_files = authored_files
        .iter()
        .map(|(path, content)| (path.as_str(), content.as_str()))
        .collect::<Vec<_>>();
    let authoring_target = authoring_target_id(archetype.id);
    let authoring_basis =
        init_managed_target(targets_dir, providers, &authoring_target, &authored_files)?;
    let version = published_archetype_version(targets_dir, &authoring_target, 1)?;
    let instance_id = builtin_instance_id(archetype);
    let instance = InstanceRecord {
        schema: crate::library::LIBRARY_RECORD_SCHEMA,
        extra: Default::default(),
        id: instance_id.clone(),
        op: RecordOp::Upsert,
        kind: InstanceKind::Authoring,
        placement_kind: crate::library::PlacementKind::Work,
        agent_id: archetype.id.to_owned(),
        project_id: None,
        version: 1,
        admission: Admission::Active,
        collection_recipient: None,
    };
    append_library_record(store, "instance", &instance)?;
    library.apply_instance(instance);
    activate_instance(store, &instance_id);
    let agent = AgentRecord {
        schema: crate::library::LIBRARY_RECORD_SCHEMA,
        extra: Default::default(),
        id: archetype.id.to_owned(),
        op: RecordOp::Upsert,
        name: archetype.name.to_owned(),
        agent_kind: crate::library::AgentKind::Work,
        panel_profile: None,
        instance_id,
        config: "{}".into(),
        current_version: 1,
        versions: [(1, version)].into_iter().collect(),
        auto_upgrade: false,
        forked_from: None,
    };
    append_library_record(store, "agent", &agent)?;
    library.apply_agent(agent);
    let target = managed_target_record(
        authoring_target,
        format!("{} authoring", archetype.name),
        WorkTargetOwner::Archetype {
            archetype_id: archetype.id.to_owned(),
        },
        home_id,
        authoring_basis,
    );
    append_library_record(store, "work_target", &target)?;
    library.apply_work_target(target);
    Ok(())
}

fn ensure_builtin_placement(
    store: &mut Store,
    library: &mut crate::library::Library,
    archetype: &crate::app_support::BuiltinArchetype,
) -> std::io::Result<()> {
    if library.instances.values().any(|instance| {
        instance.kind == InstanceKind::Using
            && instance.agent_id == archetype.id
            && instance.project_id.as_deref() == Some(DEFAULT_PROJECT)
    }) {
        return Ok(());
    }
    let placement_id = if archetype.id == DEFAULT_AGENT {
        DEFAULT_PLACEMENT.to_owned()
    } else {
        format!("placement-{}", archetype.id.trim_start_matches("agent-"))
    };
    let placement = InstanceRecord {
        schema: crate::library::LIBRARY_RECORD_SCHEMA,
        extra: Default::default(),
        id: placement_id.clone(),
        op: RecordOp::Upsert,
        kind: InstanceKind::Using,
        placement_kind: crate::library::PlacementKind::Work,
        agent_id: archetype.id.to_owned(),
        project_id: Some(DEFAULT_PROJECT.into()),
        version: 1,
        admission: Admission::Active,
        collection_recipient: None,
    };
    append_library_record(store, "instance", &placement)?;
    library.apply_instance(placement);
    let eligibility = PlacementTargetsRecord {
        schema: crate::library::LIBRARY_RECORD_SCHEMA,
        extra: Default::default(),
        placement_id: placement_id.clone(),
        op: RecordOp::Upsert,
        target_ids: vec![managed_project_target_id(DEFAULT_PROJECT)],
    };
    append_library_record(store, "placement_targets", &eligibility)?;
    library.apply_placement_targets(eligibility);
    activate_instance(store, &placement_id);
    Ok(())
}

fn ensure_builtin_archetypes(
    store: &mut Store,
    library: &mut crate::library::Library,
    targets_dir: &std::path::Path,
    providers: &WorkspaceProviders,
    home_id: &gaugedesk_core::ids::HomeId,
) -> std::io::Result<()> {
    for archetype in crate::app_support::builtin_archetypes() {
        seed_builtin_archetype(store, library, targets_dir, providers, home_id, archetype)?;
    }
    if library.projects.contains_key(DEFAULT_PROJECT) {
        for archetype in crate::app_support::builtin_archetypes() {
            ensure_builtin_placement(store, library, archetype)?;
        }
    }
    Ok(())
}

/// Seed a fresh library (ADR 0035/0036): the built-in **archetypes** plus the
/// explicit default **Personal project** and their default **placements**.
pub(crate) fn seed_default_agent(
    store: &mut Store,
    library: &mut crate::library::Library,
    targets_dir: &std::path::Path,
    providers: &WorkspaceProviders,
    home_id: &gaugedesk_core::ids::HomeId,
) -> std::io::Result<()> {
    let general = crate::app_support::builtin_archetypes()
        .iter()
        .find(|archetype| archetype.id == DEFAULT_AGENT)
        .expect("the Default archetype is built in");
    seed_builtin_archetype(store, library, targets_dir, providers, home_id, general)?;

    let proj = ProjectRecord {
        schema: crate::library::LIBRARY_RECORD_SCHEMA,
        extra: Default::default(),
        id: DEFAULT_PROJECT.into(),
        op: RecordOp::Upsert,
        name: "Personal".into(),
        is_default: true,
        home_id: home_id.clone(),
        network_isolated: false,
        run_purpose: None,
        deployment_mode: None,
    };
    store
        .append_record(
            LIBRARY_SCOPE,
            "project",
            &serde_json::to_string(&proj).unwrap(),
        )
        .map_err(io)?;
    library.apply_project(proj);
    let project_target = managed_project_target_id(DEFAULT_PROJECT);
    // Personal is a project like any other, so it is seeded with the same
    // default gate (ADR 0117 §7). Leaving it out would make the one project
    // every account starts with the only one that cannot receive inbound
    // material.
    let project_basis = init_managed_target(
        targets_dir,
        providers,
        &project_target,
        &default_gate_files(),
    )?;
    let target = managed_target_record(
        project_target.clone(),
        "Personal files".to_owned(),
        WorkTargetOwner::Project {
            project_id: DEFAULT_PROJECT.to_owned(),
        },
        home_id,
        project_basis,
    );
    append_library_record(store, "work_target", &target)?;
    library.apply_work_target(target);
    let placement = InstanceRecord {
        schema: crate::library::LIBRARY_RECORD_SCHEMA,
        extra: Default::default(),
        id: DEFAULT_PLACEMENT.into(),
        op: RecordOp::Upsert,
        kind: InstanceKind::Using,
        placement_kind: crate::library::PlacementKind::Work,
        agent_id: DEFAULT_AGENT.into(),
        project_id: Some(DEFAULT_PROJECT.into()),
        version: 1,
        admission: Admission::Active,
        collection_recipient: None,
    };
    store
        .append_record(
            LIBRARY_SCOPE,
            "instance",
            &serde_json::to_string(&placement).unwrap(),
        )
        .map_err(io)?;
    library.apply_instance(placement);
    let eligibility = PlacementTargetsRecord {
        schema: crate::library::LIBRARY_RECORD_SCHEMA,
        extra: Default::default(),
        placement_id: DEFAULT_PLACEMENT.to_owned(),
        op: RecordOp::Upsert,
        target_ids: vec![project_target],
    };
    append_library_record(store, "placement_targets", &eligibility)?;
    library.apply_placement_targets(eligibility);
    activate_instance(store, DEFAULT_PLACEMENT);
    ensure_builtin_archetypes(store, library, targets_dir, providers, home_id)?;
    Ok(())
}

impl Workbench {
    pub(crate) fn apply_startup_library_state(&mut self, state: StartupLibraryState) {
        self.targets = state.targets;
        self.collaboration_workspaces = state.collaboration_workspaces;
        self.engagements = state.engagements;
        self.engagement_index = state.engagement_index;
        self.library = state.library;
        self.default_instance = DEFAULT_PLACEMENT.to_owned();
    }

    /// Reopen the chats in one imported project workspace with their exact
    /// target-set roots. A raw workspace reconcile would reopen every branch
    /// without sparse roots and expose unrelated project partitions.
    pub(crate) fn reopen_collaboration_workspace_engagements(
        &mut self,
        workspace_id: &str,
    ) -> std::io::Result<()> {
        let stale = self
            .engagement_index
            .iter()
            .filter_map(|(chat_id, storage_id)| {
                (storage_id == workspace_id).then_some(chat_id.clone())
            })
            .collect::<Vec<_>>();
        for chat_id in stale {
            self.engagement_index.remove(&chat_id);
            self.engagements.remove(&chat_id);
        }
        open_project_chat_engagements(
            &self.library,
            &self.collaboration_workspaces,
            &mut self.engagements,
            &mut self.engagement_index,
            Some(workspace_id),
        )
    }

    /// A test workbench with one managed target as its default chat root.
    pub fn with_target(target_id: impl Into<String>, target: Instance, store: Store) -> Self {
        let target_id = target_id.into();
        let mut wb = Self::new(store);
        // This explicit constructor is a test/composition seam; its caller may
        // provide a standalone repo rather than the production nested layout.
        if let Some(root) = target.repo().parent() {
            wb.targets_root = root.join("targets");
        }
        wb.targets.insert(target_id.clone(), Box::new(target));
        let home_id = wb.home_id().clone();
        if !wb.library.projects.contains_key("test-project") {
            wb.write_project_record(ProjectRecord {
                id: "test-project".to_owned(),
                op: RecordOp::Upsert,
                name: "Test project".to_owned(),
                home_id: home_id.clone(),
                is_default: false,
                network_isolated: false,
                run_purpose: None,
                deployment_mode: None,
                schema: LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
            });
        }
        wb.write_work_target_record(managed_target_record(
            target_id.clone(),
            "Test target".to_owned(),
            WorkTargetOwner::Project {
                project_id: "test-project".to_owned(),
            },
            &home_id,
            "test-basis".to_owned(),
        ));
        wb.write_placement_targets_record(PlacementTargetsRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            placement_id: target_id.clone(),
            op: RecordOp::Upsert,
            target_ids: vec![target_id.clone()],
        });
        wb.write_instance_record(InstanceRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: target_id.clone(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Using,
            placement_kind: crate::library::PlacementKind::Work,
            agent_id: DEFAULT_AGENT.to_owned(),
            project_id: Some("test-project".to_owned()),
            version: 1,
            admission: Admission::Active,
            collection_recipient: None,
        });
        wb.write_project_collaboration_workspace_record(ProjectCollaborationWorkspaceRecord {
            project_id: "test-project".to_owned(),
            workspace_id: "project-workspace-test-project".to_owned(),
            home_id: home_id.clone(),
            substrate: "whipplescript".to_owned(),
            host_contract_revision: crate::workstream_host_contract::REVISION.to_owned(),
            host_contract_digest: crate::workstream_host_contract::DIGEST.to_owned(),
            op: RecordOp::Upsert,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        });
        wb.ensure_project_collaboration_workspace("test-project")
            .expect("test project collaboration workspace");
        wb.ensure_collaboration_target_partition("test-project", &target_id)
            .expect("test target collaboration partition");
        wb.default_instance = target_id;
        wb
    }

    /// Seed a Panel placement that `publish_agent_deployment` can name.
    ///
    /// Publishing needs a Panel-kind placement whose agent version carries a
    /// frozen public profile. Authoring one is an agent-driven flow, every
    /// release subcommand takes a placement that already exists, and this
    /// repository builds the state in-process in its own tests — so nothing
    /// outside this crate could produce it. gaugewright-cloud's composition
    /// test is what paid for that: it drives the release binary against a fresh
    /// workbench and never reached the publisher at all.
    ///
    /// It builds a whole archetype rather than a bare record, because a bare
    /// one does not survive: every agent must own an authoring target, and
    /// startup refuses to open a workbench where one does not. It is cloned
    /// from the Default archetype so its authored files, package ref, and
    /// discipline ref name artifacts that exist.
    ///
    /// It never touches an existing agent or placement. Freezing a profile is
    /// the point here, so the one thing it must not do is freeze over
    /// something a person authored.
    pub fn seed_panel_placement(
        &mut self,
        placement_id: &str,
        profile: crate::library::PanelPublicProfile,
    ) -> std::io::Result<serde_json::Value> {
        self.seed_panel_placement_with_recipient(placement_id, profile, None)
    }

    /// The composition harness variant of [`Self::seed_panel_placement`]. A
    /// collecting Panel placement freezes the same agent profile but also binds
    /// the exact project-owned recipient that a product placement gets from the
    /// placement route. Keeping that value on the placement is the behavior the
    /// cross-repository host test needs to exercise; deployment publication must
    /// not be allowed to invent it later.
    pub fn seed_panel_placement_with_recipient(
        &mut self,
        placement_id: &str,
        profile: crate::library::PanelPublicProfile,
        collection_recipient: Option<crate::library::PanelCollectionRecipient>,
    ) -> std::io::Result<serde_json::Value> {
        if profile.collection.is_some() != collection_recipient.is_some() {
            return Err(invalid_data(
                "a seeded collection profile and project recipient must be supplied together"
                    .to_owned(),
            ));
        }
        if placement_id.trim().is_empty() {
            return Err(invalid_data("a seeded placement needs an id".to_owned()));
        }
        if self.library.instances.contains_key(placement_id) {
            return Err(invalid_data(format!(
                "placement {placement_id} already exists; seeding never overwrites"
            )));
        }
        let agent_id = format!("{placement_id}-agent");
        if self.library.agents.contains_key(&agent_id) {
            return Err(invalid_data(format!(
                "agent {agent_id} already exists; seeding never overwrites"
            )));
        }

        let builtins = crate::app_support::builtin_archetypes();
        let archetype = builtins
            .iter()
            .find(|archetype| archetype.id == DEFAULT_AGENT)
            .ok_or_else(|| invalid_data("the Default archetype is not built in".to_owned()))?;
        let definition = crate::app_support::builtin_agent_definition(archetype);
        let skills = archetype
            .official_skills
            .then(crate::official_skills::office_skill_references)
            .unwrap_or_default();
        let authored = archetype_files(&definition, skills)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let authored = authored
            .iter()
            .map(|(path, content)| (path.as_str(), content.as_str()))
            .collect::<Vec<_>>();

        let targets_dir = self.targets_dir();
        let authoring_target = authoring_target_id(&agent_id);
        let basis =
            init_managed_target(&targets_dir, &self.providers, &authoring_target, &authored)?;
        let mut version = published_archetype_version(&targets_dir, &authoring_target, 1)?;
        version.panel_profile = Some(profile.clone());

        let authoring_instance = format!("{agent_id}-authoring");
        let authoring = InstanceRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: authoring_instance.clone(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Authoring,
            placement_kind: crate::library::PlacementKind::Work,
            agent_id: agent_id.clone(),
            project_id: None,
            version: 1,
            admission: Admission::Active,
            collection_recipient: None,
        };
        let agent = AgentRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: agent_id.clone(),
            op: RecordOp::Upsert,
            name: format!("Seeded panel agent for {placement_id}"),
            agent_kind: crate::library::AgentKind::Panel,
            panel_profile: Some(profile.clone()),
            instance_id: authoring_instance,
            config: "{}".into(),
            current_version: 1,
            versions: [(1, version)].into_iter().collect(),
            auto_upgrade: false,
            forked_from: None,
        };
        let target = managed_target_record(
            authoring_target,
            format!("Seeded panel agent for {placement_id} authoring"),
            WorkTargetOwner::Archetype {
                archetype_id: agent_id.clone(),
            },
            &self.home_id,
            basis,
        );
        let placement = InstanceRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: placement_id.to_owned(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Using,
            placement_kind: crate::library::PlacementKind::Panel,
            agent_id: agent_id.clone(),
            project_id: Some(DEFAULT_PROJECT.to_owned()),
            version: 1,
            admission: Admission::Active,
            collection_recipient,
        };

        let store = self.store_mut();
        append_library_record(store, "instance", &authoring)?;
        append_library_record(store, "agent", &agent)?;
        append_library_record(store, "work_target", &target)?;
        append_library_record(store, "instance", &placement)?;
        // The publisher reads the folded projection, not the log, so a seed
        // that only appended would be invisible to the command it exists for.
        self.rebuild_library();

        Ok(serde_json::json!({
            "placement_id": placement_id,
            "project_id": DEFAULT_PROJECT,
            "agent_id": agent_id,
            "version": 1,
            "panels": profile.panels.components,
        }))
    }

    /// Rebuild the cached library projection from the store. Federation handoff
    /// import paths call this after writing relocated library records so the
    /// project appears in this authority's local projection.
    pub fn rebuild_library(&mut self) {
        if let Ok(lib) = crate::library::Library::rebuild(self.store_ref()) {
            self.library = lib;
        }
    }

    pub(crate) fn library_project_display_name(&self, project_id: &str) -> String {
        self.library
            .projects
            .get(project_id)
            .map(|project| project.name.clone())
            .unwrap_or_else(|| project_id.to_string())
    }

    pub fn project_home_id(&self, project_id: &str) -> Option<&gaugedesk_core::ids::HomeId> {
        self.library.project_home_id(project_id)
    }

    /// The declared engagement placement, defaulting to the local unattested
    /// mode for pre-declaration and legacy project records (DEPLOY-1/4).
    pub fn project_deployment_mode(
        &self,
        project_id: &str,
    ) -> gaugedesk_core::boundary_lifecycle::Placement {
        self.library.deployment_mode_of(project_id)
    }

    pub fn owns_project(&self, project_id: &str) -> bool {
        self.project_home_id(project_id) == Some(self.home_id())
    }

    pub(crate) fn project_record_for_home_rebind(
        &self,
        project_id: &str,
        home_id: gaugedesk_core::ids::HomeId,
    ) -> Option<ProjectRecord> {
        let mut project = self.library.projects.get(project_id)?.clone();
        project.home_id = home_id;
        Some(project)
    }

    pub(crate) fn apply_atomic_project_home_rebind(&mut self, project: ProjectRecord) {
        let id = project.id.clone();
        self.library.apply_project(project);
        self.notify_library_changed("project", &id, "upsert");
    }

    pub(crate) fn library_project_of_chat(&self, chat_id: &str) -> Option<String> {
        self.library.project_of_chat(chat_id).map(str::to_string)
    }

    pub(crate) fn library_placement_of_chat(&self, chat_id: &str) -> Option<String> {
        self.library
            .chats
            .get(chat_id)
            .map(|chat| chat.instance_id.clone())
    }

    pub(crate) fn library_chat_network_isolated(&self, chat_id: &str) -> bool {
        self.library.chat_network_isolated(chat_id)
    }

    pub(crate) fn library_chat_run_purpose(&self, chat_id: &str) -> Option<String> {
        self.library.chat_run_purpose(chat_id).map(str::to_owned)
    }

    pub(crate) fn library_has_instance_record(&self, id: &str) -> bool {
        self.library.instances.contains_key(id)
    }

    /// Whether `id` names an active placement, rather than an authoring
    /// instance. Hosted deployment and migration compositions use this narrow
    /// query without receiving the library projection itself.
    pub fn has_placement(&self, id: &str) -> bool {
        self.library
            .instances
            .get(id)
            .is_some_and(|instance| instance.kind == InstanceKind::Using)
    }

    /// The project that owns an active placement. Hosted management
    /// compositions use this exact binding when admitting project-scoped
    /// automation and deployment commands; a placement selector alone is not
    /// authority and may not be paired with an arbitrary project id.
    pub fn placement_project_id(&self, id: &str) -> Option<&str> {
        let instance = self.library.instances.get(id)?;
        if instance.kind != InstanceKind::Using {
            return None;
        }
        instance
            .project_id
            .as_deref()
            .filter(|project| !project.is_empty())
    }

    /// Abilities frozen into the immutable archetype version used by a
    /// placement. This deliberately does not read the mutable authoring draft.
    pub(crate) fn placement_abilities(&self, id: &str) -> Result<Vec<String>, String> {
        let instance = self
            .library
            .instances
            .get(id)
            .filter(|instance| instance.kind == InstanceKind::Using)
            .ok_or_else(|| "no such placement".to_owned())?;
        let archetype = self
            .library
            .agents
            .get(&instance.agent_id)
            .ok_or_else(|| "placement archetype is unavailable".to_owned())?;
        let authoring_target = self
            .library
            .authoring_target_for(&archetype.id)
            .ok_or_else(|| "archetype authoring target is unavailable".to_owned())?;
        let package = gaugedesk_whip_runtime::AuthoredAgentPackage::load(published_package_root(
            &self.targets_dir(),
            &authoring_target.id,
            instance.version,
        ))
        .map_err(|error| error.to_string())?;
        Ok(package.agent_abilities().to_vec())
    }

    pub(crate) fn library_fork_forest(&self) -> Vec<crate::library::ForkNode> {
        self.library.fork_forest()
    }

    pub(crate) fn library_chat_mode(&self, chat_id: &str) -> crate::library::ChatMode {
        self.library
            .chats
            .get(chat_id)
            .and_then(|chat| self.library.instances.get(&chat.instance_id))
            .map(|instance| instance.kind.chat_mode())
            .unwrap_or_default()
    }

    pub(crate) fn library_project_relocation_content_bundles(
        &self,
        project: &str,
    ) -> Vec<(String, String, Vec<u8>, bool)> {
        let mut out = Vec::new();
        let mut target_ids = self
            .library
            .targets_for_project(project)
            .into_iter()
            .map(|target| target.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for instance in self
            .library
            .instances
            .values()
            .filter(|instance| instance.project_id.as_deref() == Some(project))
        {
            if crate::protected_profiles::distribution_for(self.store_ref(), &instance.id)
                .is_some_and(|record| {
                    record.profile
                        == crate::protected_profiles::DistributionProfile::ProtectedCommercial
                })
            {
                continue;
            }
            if let Some(target) = self.library.authoring_target_for(&instance.agent_id) {
                target_ids.insert(target.id.clone());
            }
        }
        for target_id in target_ids {
            let Some(target) = self.library.work_targets.get(&target_id) else {
                continue;
            };
            if target.kind != WorkTargetKind::Managed {
                continue;
            }
            match self.targets.get(&target.id) {
                Some(inst) => match inst.export() {
                    Ok(export) => out.push((
                        target.id.clone(),
                        inst.export_format().to_string(),
                        export.0,
                        false,
                    )),
                    Err(e) => {
                        tracing::warn!("handoff: cannot bundle target {}: {e}", target.id)
                    }
                },
                None => tracing::warn!("handoff: no live store for target {}", target.id),
            }
        }
        if let Some(record) = self.library.project_collaboration_workspaces.get(project) {
            match self.collaboration_workspaces.get(&record.workspace_id) {
                Some(workspace) => match workspace.export() {
                    Ok(export) => out.push((
                        record.workspace_id.clone(),
                        workspace.export_format().to_owned(),
                        export.0,
                        true,
                    )),
                    Err(error) => tracing::warn!(
                        "handoff: cannot bundle collaboration workspace {}: {error}",
                        record.workspace_id
                    ),
                },
                None => tracing::warn!(
                    "handoff: project collaboration workspace {} is not open",
                    record.workspace_id
                ),
            }
        }
        out
    }

    fn library_op_str(op: RecordOp) -> &'static str {
        match op {
            RecordOp::Upsert => "upsert",
            RecordOp::Tombstone => "tombstone",
        }
    }

    pub(crate) fn write_agent_record(&mut self, record: AgentRecord) -> i64 {
        let id = record.id.clone();
        let op = Self::library_op_str(record.op);
        let pos = self
            .store_mut()
            .append_record(
                LIBRARY_SCOPE,
                "agent",
                &serde_json::to_string(&record).unwrap(),
            )
            .unwrap_or(0);
        self.library.apply_agent(record);
        self.notify_library_changed("archetype", &id, op);
        pos
    }

    pub(crate) fn write_project_record(&mut self, record: ProjectRecord) {
        let id = record.id.clone();
        let op = Self::library_op_str(record.op);
        let _ = self.store_mut().append_record(
            LIBRARY_SCOPE,
            "project",
            &serde_json::to_string(&record).unwrap(),
        );
        self.library.apply_project(record);
        self.notify_library_changed("project", &id, op);
    }

    pub(crate) fn write_instance_record(&mut self, record: InstanceRecord) {
        let id = record.id.clone();
        let op = Self::library_op_str(record.op);
        let _ = self.store_mut().append_record(
            LIBRARY_SCOPE,
            "instance",
            &serde_json::to_string(&record).unwrap(),
        );
        self.library.apply_instance(record);
        self.notify_library_changed("placement", &id, op);
    }

    pub(crate) fn write_public_deployment_record(
        &mut self,
        record: PublicDeploymentBindingRecord,
    ) -> std::io::Result<()> {
        let id = record.id.clone();
        let op = Self::library_op_str(record.op);
        let payload = serde_json::to_string(&record).map_err(std::io::Error::other)?;
        self.store_mut()
            .append_record(LIBRARY_SCOPE, "public_deployment_binding", &payload)
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
        self.library.apply_public_deployment(record);
        self.notify_library_changed("public_deployment", &id, op);
        Ok(())
    }

    pub(crate) fn write_chat_record(&mut self, record: ChatRecord) {
        let id = record.id.clone();
        let op = Self::library_op_str(record.op);
        let _ = self.store_mut().append_record(
            LIBRARY_SCOPE,
            "chat",
            &serde_json::to_string(&record).unwrap(),
        );
        self.library.apply_chat(record);
        self.notify_library_changed("chat", &id, op);
    }

    pub(crate) fn write_created_chat_record(&mut self, record: ChatRecord) {
        let id = record.id.clone();
        let op = Self::library_op_str(record.op);
        let position = self
            .store_mut()
            .append_record(
                LIBRARY_SCOPE,
                "chat",
                &serde_json::to_string(&record).unwrap(),
            )
            .unwrap_or(0);
        self.library.apply_chat(ChatRecord {
            created_position: position,
            ..record
        });
        self.notify_library_changed("chat", &id, op);
    }

    pub(crate) fn write_workstream_record(&mut self, record: WorkstreamRecord) -> i64 {
        let id = record.id.clone();
        let op = Self::library_op_str(record.op);
        let position = self
            .store_mut()
            .append_record(
                LIBRARY_SCOPE,
                "workstream",
                &serde_json::to_string(&record).unwrap(),
            )
            .unwrap_or(0);
        self.library.apply_workstream(record);
        self.notify_library_changed("workstream", &id, op);
        position
    }

    pub(crate) fn write_work_target_record(&mut self, record: WorkTargetRecord) {
        let id = record.id.clone();
        let op = Self::library_op_str(record.op);
        let _ = self.store_mut().append_record(
            LIBRARY_SCOPE,
            "work_target",
            &serde_json::to_string(&record).unwrap(),
        );
        self.library.apply_work_target(record);
        self.notify_library_changed("work_target", &id, op);
    }

    pub(crate) fn refresh_work_target_basis_from_chat(&mut self, chat_id: &str) {
        let Some(target_id) = self.engagement_index.get(chat_id).cloned() else {
            return;
        };
        let Some(basis) = self
            .engagements
            .get(chat_id)
            .and_then(|engagement| engagement.standing_revision().ok())
            .map(|revision| revision.0)
        else {
            return;
        };
        let Some(mut target) = self.library.work_targets.get(&target_id).cloned() else {
            return;
        };
        if target.current_basis.as_deref() == Some(&basis) {
            return;
        }
        target.current_basis = Some(basis);
        self.write_work_target_record(target);
    }

    pub(crate) fn write_placement_targets_record(&mut self, record: PlacementTargetsRecord) {
        let id = record.placement_id.clone();
        let op = Self::library_op_str(record.op);
        let _ = self.store_mut().append_record(
            LIBRARY_SCOPE,
            "placement_targets",
            &serde_json::to_string(&record).unwrap(),
        );
        self.library.apply_placement_targets(record);
        self.notify_library_changed("placement", &id, op);
    }

    pub(crate) fn write_chat_target_record(&mut self, record: ChatTargetBindingRecord) {
        let id = record.chat_id.clone();
        let op = Self::library_op_str(record.op);
        let _ = self.store_mut().append_record(
            LIBRARY_SCOPE,
            "chat_target",
            &serde_json::to_string(&record).unwrap(),
        );
        self.library.apply_chat_target(record);
        self.notify_library_changed("chat", &id, op);
    }

    pub(crate) fn write_chat_target_set_record(
        &mut self,
        record: ChatTargetSetRevisionRecord,
    ) -> Result<(), String> {
        if let Some(current) = self.library.current_target_set(&record.chat_id) {
            if record.revision <= current.revision {
                return Err(format!(
                    "target-set revision must advance past {}",
                    current.revision
                ));
            }
        } else if record.revision != 0 {
            return Err("the first target-set revision must be zero".to_owned());
        }
        let payload = serde_json::to_string(&record).map_err(|error| error.to_string())?;
        self.store_mut()
            .append_record(LIBRARY_SCOPE, "chat_target_set", &payload)
            .map_err(|error| format!("{error:?}"))?;
        let id = record.chat_id.clone();
        self.library.apply_chat_target_set(record)?;
        self.notify_library_changed("chat", &id, "upsert");
        Ok(())
    }

    pub(crate) fn write_chat_target_basis_record(
        &mut self,
        record: ChatTargetBasisRecord,
    ) -> Result<(), String> {
        let payload = serde_json::to_string(&record).map_err(|error| error.to_string())?;
        self.store_mut()
            .append_record(LIBRARY_SCOPE, "chat_target_basis", &payload)
            .map_err(|error| format!("{error:?}"))?;
        let id = record.chat_id.clone();
        self.library.apply_chat_target_basis(record);
        self.notify_library_changed("chat", &id, "upsert");
        Ok(())
    }

    pub(crate) fn write_project_collaboration_workspace_record(
        &mut self,
        record: ProjectCollaborationWorkspaceRecord,
    ) {
        let id = record.project_id.clone();
        let op = Self::library_op_str(record.op);
        let _ = self.store_mut().append_record(
            LIBRARY_SCOPE,
            "project_collaboration_workspace",
            &serde_json::to_string(&record).unwrap(),
        );
        self.library.apply_project_collaboration_workspace(record);
        self.notify_library_changed("project", &id, op);
    }

    pub(crate) fn ensure_project_collaboration_workspace(
        &mut self,
        project_id: &str,
    ) -> Result<(), String> {
        let record = self
            .library
            .project_collaboration_workspaces
            .get(project_id)
            .ok_or_else(|| "project collaboration workspace is undeclared".to_owned())?;
        if self
            .collaboration_workspaces
            .contains_key(&record.workspace_id)
        {
            return Ok(());
        }
        let path = collaboration_workspaces_dir(&self.targets_dir()).join(&record.workspace_id);
        let workspace = self
            .workspace_provider(&record.workspace_id)
            .init_at(&path)
            .map_err(|error| error.to_string())?;
        self.collaboration_workspaces
            .insert(record.workspace_id.clone(), workspace);
        Ok(())
    }

    pub(crate) fn ensure_collaboration_target_partition(
        &mut self,
        project_id: &str,
        target_id: &str,
    ) -> Result<(), String> {
        self.ensure_project_collaboration_workspace(project_id)?;
        let record = self
            .library
            .project_collaboration_workspaces
            .get(project_id)
            .ok_or_else(|| "project collaboration workspace is undeclared".to_owned())?;
        let workspace_id = record.workspace_id.clone();
        let root = format!("targets/{}", crate::library::target_id_path_v1(target_id)?);

        let collaboration = self
            .collaboration_workspaces
            .get(&workspace_id)
            .ok_or_else(|| "project collaboration workspace is not open".to_owned())?;
        let collab_probe_id = library::gen_id("partition-probe");
        let collab_probe = collaboration
            .create_engagement(&collab_probe_id)
            .map_err(|error| error.to_string())?;
        let exists = collab_probe
            .tree()
            .map_err(|error| error.to_string())?
            .iter()
            .any(|entry| entry.path == root || entry.path.starts_with(&format!("{root}/")));
        drop(collab_probe);
        collaboration
            .remove_engagement(&collab_probe_id)
            .map_err(|error| error.to_string())?;
        if exists {
            return Ok(());
        }

        let probe_id = library::gen_id("partition-source");
        let source = self
            .targets
            .get(target_id)
            .ok_or_else(|| "target storage is not open".to_owned())?;
        let probe = source
            .create_engagement(&probe_id)
            .map_err(|error| error.to_string())?;
        let mut owned = Vec::new();
        for entry in probe.tree().map_err(|error| error.to_string())? {
            if entry.is_dir || entry.path.starts_with(".gaugedesk-runtime/") {
                continue;
            }
            let body = probe
                .read_file(&entry.path)
                .map_err(|error| error.to_string())?;
            owned.push((format!("{root}/{}", entry.path), body));
        }
        drop(probe);
        let _ = source.remove_engagement(&probe_id);
        let borrowed = owned
            .iter()
            .map(|(path, body)| (path.as_str(), body.as_str()))
            .collect::<Vec<_>>();
        self.collaboration_workspaces
            .get(&workspace_id)
            .ok_or_else(|| "project collaboration workspace is not open".to_owned())?
            .seed_main(&borrowed)
            .map_err(|error| error.to_string())
    }

    pub(crate) fn write_workstream_root_record(&mut self, record: WorkstreamRootRecord) {
        let id = record.workstream_id.clone();
        let op = Self::library_op_str(record.op);
        let _ = self.store_mut().append_record(
            LIBRARY_SCOPE,
            "workstream_root",
            &serde_json::to_string(&record).unwrap(),
        );
        self.library.apply_workstream_root(record);
        self.notify_library_changed("workstream", &id, op);
    }

    /// Create a target-owned managed store. Placements only receive eligibility;
    /// they never get a fork/copy of this workspace.
    pub(crate) fn create_managed_project_target(
        &mut self,
        project_id: &str,
        name: String,
    ) -> Result<String, String> {
        let target_id = managed_project_target_id(project_id);
        if self.library.work_targets.contains_key(&target_id) {
            return Ok(target_id);
        }
        let project = self
            .library
            .projects
            .get(project_id)
            .ok_or_else(|| "no such project".to_owned())?;
        if &project.home_id != self.home_id() {
            return Err("project belongs to another Home".to_owned());
        }
        let workspace = self
            .workspace_provider(&target_id)
            .init_at(&self.targets_dir().join(&target_id))
            .map_err(|error| error.to_string())?;
        // Every project has a gate from the moment it exists, and it is
        // review-by-hand (ADR 0117 §7). Seeding it into the target's mainline
        // rather than writing it into one chat's worktree is what makes it the
        // *project's* program: every chat rooted on this target sees the same
        // gate, and changing it is an ordinary diff a human keeps or rejects
        // (ADR 0110 §5) instead of an ambient edit.
        //
        // Review-by-hand is the only gate that can be seeded unconditionally --
        // it needs no provider, no key, and no judgement about whether a
        // classifier suits the material -- so `coerce-screen` is something an
        // author moves to, never a default.
        workspace
            .seed_main(&default_gate_files())
            .map_err(|error| error.to_string())?;
        let probe_id = library::gen_id("target-basis");
        let probe = workspace
            .create_engagement(&probe_id)
            .map_err(|error| error.to_string())?;
        let basis = probe.boundary_cut().map_err(|error| error.to_string())?.0;
        drop(probe);
        workspace
            .remove_engagement(&probe_id)
            .map_err(|error| error.to_string())?;
        self.targets.insert(target_id.clone(), workspace);
        self.write_work_target_record(managed_target_record(
            target_id.clone(),
            name,
            WorkTargetOwner::Project {
                project_id: project_id.to_owned(),
            },
            self.home_id(),
            basis,
        ));
        let placements = self
            .library
            .using_instances_of(project_id)
            .into_iter()
            .map(|placement| placement.id.clone())
            .collect::<Vec<_>>();
        for placement_id in placements {
            self.write_placement_targets_record(PlacementTargetsRecord {
                schema: crate::library::LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                placement_id,
                op: RecordOp::Upsert,
                target_ids: vec![target_id.clone()],
            });
        }
        self.ensure_collaboration_target_partition(project_id, &target_id)?;
        Ok(target_id)
    }

    pub(crate) fn library_restamp_workstream_position(
        &mut self,
        workstream_id: &str,
        position: i64,
    ) {
        if let Some(record) = self.library.workstreams.get(workstream_id).cloned() {
            self.library.apply_workstream(WorkstreamRecord {
                created_position: position,
                ..record
            });
        }
    }

    pub(crate) fn library_workstreams_in(&self, instance_id: &str) -> Vec<&WorkstreamRecord> {
        let Some(instance) = self.library.instances.get(instance_id) else {
            return Vec::new();
        };
        if instance.kind == InstanceKind::Authoring {
            return self.library.workstreams_in(instance_id);
        }
        let project_id = instance.project_id.as_deref().unwrap_or_default();
        let mut records = self
            .library
            .workstreams
            .values()
            .filter(|record| {
                self.library
                    .workstream_roots
                    .get(&record.id)
                    .is_some_and(|root| root.project_id == project_id)
            })
            .collect::<Vec<_>>();
        records.sort_by_key(|record| record.created_position);
        records
    }

    pub(crate) fn library_workstream(&self, workstream_id: &str) -> Option<WorkstreamRecord> {
        self.library.workstreams.get(workstream_id).cloned()
    }

    pub(crate) fn library_has_workstream(&self, workstream_id: &str) -> bool {
        self.library.workstreams.contains_key(workstream_id)
    }

    pub(crate) fn library_workstream_root(
        &self,
        workstream_id: &str,
    ) -> Option<WorkstreamRootRecord> {
        self.library.workstream_roots.get(workstream_id).cloned()
    }

    pub(crate) fn library_chat_target_binding(
        &self,
        chat_id: &str,
    ) -> Option<ChatTargetBindingRecord> {
        self.library.chat_targets.get(chat_id).cloned()
    }

    pub(crate) fn library_chat_placement(&self, chat_id: &str) -> Option<&str> {
        self.library
            .chats
            .get(chat_id)
            .map(|chat| chat.instance_id.as_str())
    }

    pub(crate) fn resolve_placement_target(
        &self,
        placement_id: &str,
        requested: Option<&str>,
    ) -> Result<WorkTargetRecord, String> {
        let eligible = self
            .library
            .placement_targets
            .get(placement_id)
            .map(|record| record.target_ids.as_slice())
            .unwrap_or_default();
        let target_id = match requested {
            Some(target_id) if eligible.iter().any(|id| id == target_id) => target_id,
            Some(_) => return Err("work target is not eligible for this placement".to_owned()),
            None if eligible.len() == 1 => &eligible[0],
            None if eligible.is_empty() => return Err("placement has no work target".to_owned()),
            None => return Err("select a work target".to_owned()),
        };
        let target = self
            .library
            .work_targets
            .get(target_id)
            .cloned()
            .ok_or_else(|| "work target is unresolved".to_owned())?;
        if target.status != WorkTargetStatus::Available {
            return Err("work target is unavailable".to_owned());
        }
        Ok(target)
    }

    pub(crate) fn workspace_by_storage_id(&self, storage_id: &str) -> Option<&dyn Workspace> {
        self.targets.get(storage_id).map(Box::as_ref).or_else(|| {
            self.collaboration_workspaces
                .get(storage_id)
                .map(Box::as_ref)
        })
    }

    #[cfg(test)]
    pub(crate) fn seed_boundary_for_test(
        &mut self,
        boundary_id: &str,
        participants: std::collections::BTreeSet<String>,
        placement: Placement,
    ) -> Result<(), AdmitError> {
        self.store_mut()
            .admit::<BoundaryState>(boundary_id, BoundaryCommand::Propose(participants))?;
        self.store_mut()
            .admit::<BoundaryState>(boundary_id, BoundaryCommand::DeclareCeiling(placement))?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn seed_attested_boundary_release_for_test(
        &mut self,
        build_image: &str,
        build_version: &str,
        measurement: CodeMeasurement,
        sealed_key_id: &str,
        sealed_key: Vec<u8>,
    ) {
        self.measurements
            .register(crate::measurement_store::MeasurementRecord::new(
                crate::measurement_store::BuildId::new(build_image, build_version),
                measurement.clone(),
            ));
        self.sealed_keys
            .seal(gaugedesk_core::key_release::SealedKeyRecord::new(
                sealed_key_id,
                measurement,
                sealed_key,
            ));
    }

    #[cfg(test)]
    pub(crate) fn seed_org_placement_policy_for_test(
        &mut self,
        policy: crate::org::PlacementPolicyRecord,
    ) -> Result<(), AdmitError> {
        self.store_mut().append_record(
            crate::org::ORG_SCOPE,
            "placement_policy",
            &serde_json::to_string(&policy).unwrap(),
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn write_chat_transcript_event(
        &mut self,
        chat_id: &str,
        event: crate::stream::ServerEvent,
    ) -> Result<(), AdmitError> {
        self.store_mut()
            .append_record(chat_id, "transcript", &event.to_json())?;
        Ok(())
    }

    pub(crate) fn targets_dir(&self) -> std::path::PathBuf {
        self.targets_root.clone()
    }

    pub(crate) fn destroy_chat(&mut self, chat_id: &str) {
        if let Some(harness) = self.sessions.remove(chat_id) {
            crate::workbench_state::shutdown_shared_harness(harness);
        }
        if let Some(inst_id) = self.engagement_index.remove(chat_id) {
            if let Some(inst) = self.targets.get(&inst_id) {
                let _ = inst.remove_engagement(chat_id);
            }
        }
        self.engagements.remove(chat_id);
        self.streams.remove(chat_id);
        if let Some(existing) = self.library.chats.get(chat_id).cloned() {
            self.write_chat_record(ChatRecord {
                op: RecordOp::Tombstone,
                ..existing
            });
        }
        if let Some(existing) = self.library.chat_targets.get(chat_id).cloned() {
            self.write_chat_target_record(ChatTargetBindingRecord {
                op: RecordOp::Tombstone,
                ..existing
            });
        }
    }

    pub(crate) fn destroy_instance(&mut self, inst_id: &str) {
        let instance_kind = self
            .library
            .instances
            .get(inst_id)
            .map(|instance| instance.kind);
        let authoring_target = self
            .library
            .instances
            .get(inst_id)
            .filter(|instance| instance.kind == InstanceKind::Authoring)
            .and_then(|instance| self.library.authoring_target_for(&instance.agent_id))
            .map(|target| target.id.clone());
        let chat_ids: Vec<String> = self
            .library
            .chats
            .values()
            .filter(|c| c.instance_id == inst_id)
            .map(|c| c.id.clone())
            .collect();
        for chat_id in chat_ids {
            self.destroy_chat(&chat_id);
        }
        // Authoring workstreams remain children of their authoring placement.
        // Work workstreams are project-owned: `instance_id` is only immutable
        // creator provenance, so unbinding that placement must not retire them.
        let workstream_ids: Vec<String> = if instance_kind == Some(InstanceKind::Authoring) {
            self.library
                .workstreams
                .values()
                .filter(|workstream| workstream.instance_id == inst_id)
                .map(|workstream| workstream.id.clone())
                .collect()
        } else {
            Vec::new()
        };
        for workstream_id in workstream_ids {
            if let Some(existing) = self.library.workstreams.get(&workstream_id).cloned() {
                self.write_workstream_record(WorkstreamRecord {
                    op: RecordOp::Tombstone,
                    ..existing
                });
            }
            if let Some(existing) = self.library.workstream_roots.get(&workstream_id).cloned() {
                self.write_workstream_root_record(WorkstreamRootRecord {
                    op: RecordOp::Tombstone,
                    ..existing
                });
            }
        }
        let deployment_ids = self
            .library
            .public_deployments
            .values()
            .filter(|binding| binding.placement_id == inst_id)
            .map(|binding| binding.id.clone())
            .collect::<Vec<_>>();
        for deployment_id in deployment_ids {
            if let Some(existing) = self.library.public_deployments.get(&deployment_id).cloned() {
                let _ = self.write_public_deployment_record(PublicDeploymentBindingRecord {
                    op: RecordOp::Tombstone,
                    ..existing
                });
            }
        }
        if let Some(existing) = self.library.instances.get(inst_id).cloned() {
            self.write_instance_record(InstanceRecord {
                op: RecordOp::Tombstone,
                ..existing
            });
        }
        if let Some(existing) = self.library.placement_targets.get(inst_id).cloned() {
            self.write_placement_targets_record(PlacementTargetsRecord {
                op: RecordOp::Tombstone,
                ..existing
            });
        }
        if let Some(target_id) = authoring_target {
            self.targets.remove(&target_id);
            let _ = std::fs::remove_dir_all(self.targets_dir().join(&target_id));
            if let Some(existing) = self.library.work_targets.get(&target_id).cloned() {
                self.write_work_target_record(WorkTargetRecord {
                    op: RecordOp::Tombstone,
                    ..existing
                });
            }
        }
    }

    /// Overlay a chat-local config onto the archetype base. An unparseable
    /// side is an error, never coerced to `{}` (DR-0054 Phase A): a corrupt
    /// config surfaced as empty would be re-persisted empty by the next
    /// save, permanently destroying a recoverable value.
    fn merge_agent_config(base: &str, overlay: &str) -> Result<String, String> {
        let base_json = serde_json::from_str::<serde_json::Value>(base)
            .map_err(|error| format!("stored agent config is not readable JSON: {error}"))?;
        let overlay_json = serde_json::from_str::<serde_json::Value>(overlay).map_err(|error| {
            format!("stored local config overlay is not readable JSON: {error}")
        })?;
        match (base_json, overlay_json) {
            (serde_json::Value::Object(mut base_map), serde_json::Value::Object(overlay_map)) => {
                for (key, value) in overlay_map {
                    base_map.insert(key, value);
                }
                serde_json::to_string(&serde_json::Value::Object(base_map))
                    .map_err(|error| format!("merged agent config did not serialize: {error}"))
            }
            _ => Ok(base.to_string()),
        }
    }

    /// Runtime selection is control-plane state. It is resolved for a turn and
    /// never copied into the target candidate. Fails when a stored config is
    /// unreadable rather than pretending it is empty.
    pub(crate) fn effective_agent_config_for_chat(&self, chat_id: &str) -> Result<String, String> {
        let Some(chat) = self.library.chats.get(chat_id) else {
            return Ok("{}".to_owned());
        };
        let Some(instance) = self.library.instances.get(&chat.instance_id) else {
            return Ok("{}".to_owned());
        };
        let base = self
            .library
            .agents
            .get(&instance.agent_id)
            .map(|agent| agent.config.clone())
            .unwrap_or_else(|| "{}".to_owned());
        match self
            .store_ref()
            .fold::<InstanceState>(&instance.id)
            .ok()
            .and_then(|state| state.local_config)
            .filter(|overlay| !overlay.trim().is_empty())
        {
            Some(overlay) => Self::merge_agent_config(&base, &overlay),
            None => Ok(base),
        }
    }

    /// Recreate the selected immutable discipline as an ephemeral, read-only
    /// runtime mount. The workspace adapter excludes this root from every cut
    /// and diff, so archetype bytes cannot become target-owned by accident.
    pub(crate) fn refresh_chat_discipline_mount(&self, chat_id: &str) -> Result<(), String> {
        let chat = self
            .library
            .chats
            .get(chat_id)
            .ok_or_else(|| "no such chat".to_owned())?;
        let instance = self
            .library
            .instances
            .get(&chat.instance_id)
            .ok_or_else(|| "chat placement is unavailable".to_owned())?;
        if instance.kind == InstanceKind::Authoring {
            return Ok(());
        }
        let archetype = self
            .library
            .agents
            .get(&instance.agent_id)
            .ok_or_else(|| "chat archetype is unavailable".to_owned())?;
        let authoring_target = self
            .library
            .authoring_target_for(&archetype.id)
            .ok_or_else(|| "archetype authoring target is unavailable".to_owned())?;
        let package_root =
            published_package_root(&self.targets_dir(), &authoring_target.id, instance.version);
        let package = gaugedesk_whip_runtime::AuthoredAgentPackage::load(&package_root)
            .map_err(|error| error.to_string())?;
        let bundle = crate::discipline::load(
            &published_discipline_root(&self.targets_dir(), &authoring_target.id, instance.version),
            package.capabilities().iter().cloned(),
        )?;
        let engagement = self
            .engagements
            .get(chat_id)
            .ok_or_else(|| "chat target candidate is unavailable".to_owned())?;
        let mount = engagement
            .path()
            .join(gaugedesk_boundary::definition::RUNTIME_MOUNT_ROOT);
        if mount.exists() {
            std::fs::remove_dir_all(&mount).map_err(|error| error.to_string())?;
        }
        for (path, body) in bundle.files {
            let destination = mount.join("discipline").join(path);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            std::fs::write(destination, body).map_err(|error| error.to_string())?;
        }
        self.refresh_chat_target_set_mount(chat_id)
    }

    /// Refresh the host-owned target-set declaration independently of an agent
    /// discipline package. Project workspaces need this declaration even in
    /// composition tests (and recovery states) where no archetype is mounted.
    pub(crate) fn refresh_chat_target_set_mount(&self, chat_id: &str) -> Result<(), String> {
        let engagement = self
            .engagements
            .get(chat_id)
            .ok_or_else(|| "chat target candidate is unavailable".to_owned())?;
        let mount = engagement
            .path()
            .join(gaugedesk_boundary::definition::RUNTIME_MOUNT_ROOT);
        std::fs::create_dir_all(&mount).map_err(|error| error.to_string())?;
        let target_set = self
            .library
            .current_target_set(chat_id)
            .ok_or_else(|| "chat target set is unavailable".to_owned())?;
        let members = target_set
            .members
            .iter()
            .map(|member| {
                let target = self
                    .library
                    .work_targets
                    .get(&member.target_id)
                    .ok_or_else(|| format!("target {} is unavailable", member.target_id))?;
                Ok(serde_json::json!({
                    "target_id": member.target_id,
                    "display_name": target.name,
                    "root": format!("targets/{}", crate::library::target_id_path_v1(&member.target_id)?),
                    "kind": target.kind,
                    "adapter_family": member.adapter_family,
                    "basis": self.library.chat_target_basis(chat_id, &member.target_id)
                        .map(str::to_owned)
                        .or_else(|| target.current_basis.clone()),
                    "path_scope": member.path_scope,
                    "capability_ceiling": member.capability_ceiling,
                    "participation": member.participation,
                }))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let manifest = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "gaugedesk.target-set.v1",
            "chat_id": chat_id,
            "target_set_revision": target_set.revision,
            "targets": members,
        }))
        .map_err(|error| error.to_string())?;
        std::fs::write(mount.join("target-set.json"), manifest)
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Capture the GaugeDesk coordinates WhippleScript cuts do not themselves
    /// version.  This is called while turn admission still owns the current
    /// project/target facts; the engine adds the before/after collaboration cuts
    /// to the same immutable boundary record.
    pub(crate) fn turn_fork_snapshot(
        &self,
        chat_id: &str,
        governance_epoch: Option<u64>,
        signed_governance_envelope: Option<&str>,
        process_declaration: Option<crate::target_change_set::TurnProcessDeclaration>,
    ) -> Result<Option<crate::engine::TurnForkSnapshot>, String> {
        use sha2::{Digest, Sha256};

        let Some(chat) = self.library.chats.get(chat_id) else {
            // Low-level harness/composition tests can register an ephemeral
            // workspace without a durable project chat. There is no project
            // fork vector to capture for that compatibility seam.
            return Ok(None);
        };
        let instance = self
            .library
            .instances
            .get(&chat.instance_id)
            .ok_or_else(|| "chat placement is unavailable".to_owned())?;
        if instance.kind != InstanceKind::Using {
            return Ok(None);
        }
        let project_id = instance
            .project_id
            .as_deref()
            .ok_or_else(|| "work chat has no project".to_owned())?;
        let collaboration = self
            .library
            .project_collaboration_workspaces
            .get(project_id)
            .ok_or_else(|| "project collaboration workspace is unavailable".to_owned())?;
        let workspace = self
            .collaboration_workspaces
            .get(&collaboration.workspace_id)
            .ok_or_else(|| "project collaboration workspace is not open".to_owned())?;
        let target_set = self
            .library
            .current_target_set(chat_id)
            .ok_or_else(|| "chat target set is unavailable".to_owned())?;
        let compatibility_binding = self.library.chat_targets.get(chat_id);
        let mut targets = target_set
            .members
            .iter()
            .map(|member| {
                let target = self
                    .library
                    .work_targets
                    .get(&member.target_id)
                    .ok_or_else(|| format!("target {} is unavailable", member.target_id))?;
                let native_basis = self
                    .library
                    .chat_target_basis(chat_id, &member.target_id)
                    .map(str::to_owned)
                    .or_else(|| {
                        compatibility_binding
                            .filter(|binding| binding.target_id == member.target_id)
                            .map(|binding| binding.basis.clone())
                            .or_else(|| target.current_basis.clone())
                    })
                    .ok_or_else(|| format!("target {} has no exact basis", member.target_id))?;
                Ok(crate::engine::TurnTargetMemberSnapshot {
                    target_id: member.target_id.clone(),
                    native_basis,
                    adapter_family: member.adapter_family.clone(),
                    path_scope: member.path_scope.clone(),
                    capabilities: member.capability_ceiling.clone(),
                    participation: member.participation,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        targets.sort_by(|left, right| left.target_id.cmp(&right.target_id));
        let envelope = signed_governance_envelope.unwrap_or_default();
        let reads = crate::resource_store::engagement_reads(&self.store, chat_id)
            .map_err(|error| format!("{error:?}"))?
            .items()
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let taint_evidence_digest = crate::engine::taint_evidence_digest(&reads);
        let visible_settlements = self.visible_target_settlement_evidence(chat_id)?;
        let visible_settlement_handles = visible_settlements
            .iter()
            .flat_map(|evidence| evidence.receipt_handles.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(Some(crate::engine::TurnForkSnapshot {
            target_set_revision: target_set.revision,
            targets,
            collaboration_workspace_id: collaboration.workspace_id.clone(),
            historical_home: workspace
                .engagement_home_receipt(chat_id)
                .map_err(|error| error.to_string())?,
            governance_epoch: governance_epoch.unwrap_or_default(),
            governance_envelope_digest: format!(
                "sha256:{}",
                hex::encode(Sha256::digest(envelope.as_bytes()))
            ),
            process_declaration,
            visible_settlement_handles,
            visible_settlements,
            before_taint_evidence_digest: taint_evidence_digest.clone(),
            after_taint_evidence_digest: taint_evidence_digest,
            before_collaboration_cut: String::new(),
            after_collaboration_cut: String::new(),
        }))
    }

    pub(crate) fn create_chat_in_instance(
        &mut self,
        inst_id: &str,
        title: &str,
    ) -> Result<serde_json::Value, String> {
        self.create_chat_in_instance_on_target(inst_id, title, None)
    }

    pub(crate) fn create_chat_in_instance_on_target(
        &mut self,
        inst_id: &str,
        title: &str,
        requested_target_id: Option<&str>,
    ) -> Result<serde_json::Value, String> {
        let requested = requested_target_id
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        self.create_chat_in_instance_on_targets(inst_id, title, &requested)
    }

    pub(crate) fn create_chat_in_instance_on_targets(
        &mut self,
        inst_id: &str,
        title: &str,
        requested_target_ids: &[String],
    ) -> Result<serde_json::Value, String> {
        let Some(inst_rec) = self.library.instances.get(inst_id).cloned() else {
            return Err("no such instance".into());
        };
        if inst_rec.kind == InstanceKind::Using && inst_rec.placement_kind == PlacementKind::Panel {
            return Err("panel placements do not host work chats".into());
        }
        // APPROVE-1 (ADR 0064): a placement hosts work chats only while active. A pending
        // placement (approved-but-not-yet-accepted under an approval-required policy) is
        // refused up front — fail closed until the project owner accepts it.
        if inst_rec.admission == Admission::Pending {
            return Err("placement is pending approval — accept it before starting a chat".into());
        }
        let kind = inst_rec.kind.chat_kind();
        if !self
            .store_ref()
            .fold::<InstanceState>(inst_id)
            .map(|s| s.runnable)
            .unwrap_or(false)
        {
            return Err("instance is not runnable (suspended or torn down)".into());
        }
        let targets = match inst_rec.kind {
            InstanceKind::Using => {
                let requested = if requested_target_ids.is_empty() {
                    let eligible = self
                        .library
                        .placement_targets
                        .get(inst_id)
                        .map(|record| record.target_ids.as_slice())
                        .unwrap_or_default();
                    match eligible {
                        [only] => vec![only.clone()],
                        [] => return Err("placement has no work target".to_owned()),
                        _ => return Err("select one or more work targets".to_owned()),
                    }
                } else {
                    requested_target_ids.to_vec()
                };
                let mut seen = BTreeSet::new();
                let mut targets = Vec::with_capacity(requested.len());
                for target_id in requested {
                    if !seen.insert(target_id.clone()) {
                        return Err(format!("target set repeats stable target id {target_id}"));
                    }
                    targets.push(self.resolve_placement_target(inst_id, Some(&target_id))?);
                }
                targets
            }
            InstanceKind::Authoring => {
                let target = self
                    .library
                    .authoring_target_for(&inst_rec.agent_id)
                    .cloned()
                    .ok_or_else(|| "archetype authoring target is unresolved".to_owned())?;
                if requested_target_ids
                    .iter()
                    .any(|requested| requested != &target.id)
                    || requested_target_ids.len() > 1
                {
                    return Err("edit chat target does not belong to this archetype".to_owned());
                }
                vec![target]
            }
        };
        for target in &targets {
            if !target.capabilities.read {
                return Err(format!("work target {} does not grant read", target.id));
            }
        }
        for (index, left) in targets.iter().enumerate() {
            for right in targets.iter().skip(index + 1) {
                if target_scopes_physically_overlap(
                    &self.targets_dir(),
                    left,
                    &left.path_scope,
                    right,
                    &right.path_scope,
                )? {
                    return Err(format!(
                        "targets {} and {} have overlapping physical scopes",
                        left.id, right.id
                    ));
                }
            }
        }
        let target_id = targets[0].id.clone();
        let (storage_id, sparse_roots) = match inst_rec.kind {
            InstanceKind::Using => {
                let project_id = inst_rec
                    .project_id
                    .as_deref()
                    .ok_or_else(|| "work placement has no project".to_owned())?;
                for target in &targets {
                    self.ensure_collaboration_target_partition(project_id, &target.id)?;
                }
                let workspace = self
                    .library
                    .project_collaboration_workspaces
                    .get(project_id)
                    .ok_or_else(|| "project collaboration workspace is unresolved".to_owned())?;
                let roots = targets
                    .iter()
                    .map(|target| {
                        crate::library::target_id_path_v1(&target.id)
                            .map(|encoded| format!("targets/{encoded}"))
                    })
                    .collect::<Result<BTreeSet<_>, _>>()?;
                (workspace.workspace_id.clone(), Some(roots))
            }
            InstanceKind::Authoring => (target_id.clone(), None),
        };
        let Some(storage) = self.workspace_by_storage_id(&storage_id) else {
            return Err("chat collaboration storage is not open".into());
        };
        let chat_id = library::gen_id("chat");
        let eng = match &sparse_roots {
            Some(roots) => storage.create_engagement_subset(&chat_id, storage.mainline(), roots),
            None => storage.create_engagement(&chat_id),
        }
        .map_err(|e| e.to_string())?;
        // Pin the exact standing target basis. Runtime config and discipline
        // are control/materialized state and never mint target cuts.
        let _candidate = eng.boundary_cut().map_err(|error| error.to_string())?.0;
        let basis = targets[0]
            .current_basis
            .clone()
            .ok_or_else(|| "work target has no exact standing basis".to_owned())?;
        let rec = ChatRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: chat_id.clone(),
            op: RecordOp::Upsert,
            instance_id: inst_id.to_string(),
            title: title.to_string(),
            created_position: 0,
            forked_from: None,
            forked_from_entry: None,
            forked_from_cut: None,
        };
        let pos = self
            .store_mut()
            .append_record(LIBRARY_SCOPE, "chat", &serde_json::to_string(&rec).unwrap())
            .unwrap_or(0);
        let rec = ChatRecord {
            created_position: pos,
            ..rec
        };
        self.library.apply_chat(rec);
        self.notify_library_changed("chat", &chat_id, "upsert");
        let binding = (targets.len() == 1).then(|| ChatTargetBindingRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            chat_id: chat_id.clone(),
            op: RecordOp::Upsert,
            target_id: target_id.clone(),
            basis: basis.clone(),
            path_scope: targets[0].path_scope.clone(),
            capabilities: targets[0].capabilities.clone(),
        });
        if let Some(binding) = binding.clone() {
            self.write_chat_target_record(binding);
        }
        self.write_chat_target_set_record(ChatTargetSetRevisionRecord {
            chat_id: chat_id.clone(),
            revision: 0,
            members: targets
                .iter()
                .map(|target| ChatTargetSetMemberRecord {
                    target_id: target.id.clone(),
                    adapter_family: target.adapter_family.clone(),
                    path_scope: target.path_scope.clone(),
                    capability_ceiling: target.capabilities.clone(),
                    participation: if target.capabilities.propose {
                        TargetParticipationMode::Writable
                    } else {
                        TargetParticipationMode::ReadOnly
                    },
                })
                .collect(),
            created_position: 0,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        })?;
        self.register_engagement(chat_id.clone(), storage_id, eng);
        self.refresh_chat_discipline_mount(&chat_id)?;
        for target in &targets {
            self.record_target_act(
                Some(&chat_id),
                &target.id,
                crate::target_adapter::TargetActKind::Read,
                None,
                Vec::new(),
                None,
                crate::target_adapter::TargetActStatus::Completed,
                None,
            )?;
        }
        Ok(serde_json::json!({
            "id": chat_id,
            "title": title,
            "kind": kind,
            // Compatibility-only singular projection.  A multi-target chat has
            // no distinguished or "primary" target.
            "target_id": (targets.len() == 1).then_some(target_id),
            "target_ids": targets.iter().map(|target| target.id.clone()).collect::<Vec<_>>(),
            "basis": basis,
        }))
    }

    /// Admit a new immutable target-set revision between settled turns.  This
    /// changes only the chat's sparse view; WhippleScript branch membership and
    /// named-workstream topology are deliberately untouched.
    pub(crate) fn revise_chat_targets(
        &mut self,
        chat_id: &str,
        requested: &[(String, TargetParticipationMode)],
    ) -> Result<serde_json::Value, String> {
        if requested.is_empty() {
            return Err("a chat target set cannot be empty".to_owned());
        }
        if crate::engine::turn_is_live(chat_id) {
            return Err("target set cannot change while a turn is live".to_owned());
        }
        if self.engagement_rehome_blocked(chat_id) {
            return Err("settle or discard the current candidate before changing targets".into());
        }
        let chat = self
            .library
            .chats
            .get(chat_id)
            .cloned()
            .ok_or_else(|| "no such chat".to_owned())?;
        let instance = self
            .library
            .instances
            .get(&chat.instance_id)
            .cloned()
            .ok_or_else(|| "chat placement is unavailable".to_owned())?;
        if instance.kind != InstanceKind::Using {
            return Err("an edit chat keeps its one managed authoring target".to_owned());
        }
        let project_id = instance
            .project_id
            .as_deref()
            .ok_or_else(|| "work chat has no project".to_owned())?;
        let mut seen = BTreeSet::new();
        let mut targets = Vec::with_capacity(requested.len());
        for (target_id, participation) in requested {
            if !seen.insert(target_id.clone()) {
                return Err(format!("target set repeats stable target id {target_id}"));
            }
            let target = self.resolve_placement_target(&chat.instance_id, Some(target_id))?;
            if !target.capabilities.read {
                return Err(format!("target {} does not grant read", target.id));
            }
            if *participation == TargetParticipationMode::Writable && !target.capabilities.propose {
                return Err(format!("target {} does not grant propose", target.id));
            }
            targets.push((target, *participation));
        }
        for (index, (left, _)) in targets.iter().enumerate() {
            for (right, _) in targets.iter().skip(index + 1) {
                if target_scopes_physically_overlap(
                    &self.targets_dir(),
                    left,
                    &left.path_scope,
                    right,
                    &right.path_scope,
                )? {
                    return Err(format!(
                        "targets {} and {} have overlapping physical scopes",
                        left.id, right.id
                    ));
                }
            }
        }
        for (target, _) in &targets {
            self.ensure_collaboration_target_partition(project_id, &target.id)?;
        }
        let roots = targets
            .iter()
            .map(|(target, _)| {
                crate::library::target_id_path_v1(&target.id)
                    .map(|encoded| format!("targets/{encoded}"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        self.engagements
            .get_mut(chat_id)
            .ok_or_else(|| "chat collaboration branch is unavailable".to_owned())?
            .replace_sparse_roots(&roots)
            .map_err(|error| error.to_string())?;

        let revision = self
            .library
            .current_target_set(chat_id)
            .map_or(0, |current| current.revision + 1);
        let members = targets
            .iter()
            .map(|(target, participation)| ChatTargetSetMemberRecord {
                target_id: target.id.clone(),
                adapter_family: target.adapter_family.clone(),
                path_scope: target.path_scope.clone(),
                capability_ceiling: target.capabilities.clone(),
                participation: *participation,
            })
            .collect::<Vec<_>>();
        self.write_chat_target_set_record(ChatTargetSetRevisionRecord {
            chat_id: chat_id.to_owned(),
            revision,
            members,
            created_position: 0,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        })?;
        if let [(target, _)] = targets.as_slice() {
            self.write_chat_target_record(ChatTargetBindingRecord {
                chat_id: chat_id.to_owned(),
                op: RecordOp::Upsert,
                target_id: target.id.clone(),
                basis: target
                    .current_basis
                    .clone()
                    .ok_or_else(|| "selected target has no exact basis".to_owned())?,
                path_scope: target.path_scope.clone(),
                capabilities: target.capabilities.clone(),
                schema: LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
            });
        } else if let Some(binding) = self.library.chat_targets.get(chat_id).cloned() {
            self.write_chat_target_record(ChatTargetBindingRecord {
                op: RecordOp::Tombstone,
                ..binding
            });
        }
        self.refresh_chat_discipline_mount(chat_id)?;
        Ok(serde_json::json!({
            "chat_id": chat_id,
            "target_set_revision": revision,
            "targets": targets.iter().map(|(target, participation)| serde_json::json!({
                "target_id": target.id,
                "participation": participation,
            })).collect::<Vec<_>>(),
        }))
    }

    pub(crate) fn agent_record(&self, id: &str) -> Option<AgentRecord> {
        self.library.agents.get(id).cloned()
    }

    pub(crate) fn panel_profile(&self, id: &str) -> Result<PanelPublicProfile, String> {
        let agent = self
            .library
            .agents
            .get(id)
            .ok_or_else(|| "no such agent".to_owned())?;
        if agent.agent_kind != AgentKind::Panel {
            return Err("agent is not a panel agent".to_owned());
        }
        agent
            .panel_profile
            .clone()
            .ok_or_else(|| "panel agent has no public profile".to_owned())
    }

    pub(crate) fn set_panel_profile(
        &mut self,
        id: &str,
        profile: PanelPublicProfile,
    ) -> Result<PanelPublicProfile, String> {
        let mut agent = self
            .library
            .agents
            .get(id)
            .cloned()
            .ok_or_else(|| "no such agent".to_owned())?;
        if agent.agent_kind != AgentKind::Panel {
            return Err("agent is not a panel agent".to_owned());
        }
        let target = self
            .library
            .authoring_target_for(id)
            .ok_or_else(|| "agent authoring target is unavailable".to_owned())?;
        let package = gaugedesk_whip_runtime::AuthoredAgentPackage::load(
            self.targets_dir()
                .join(&target.id)
                .join("repo")
                .join(gaugedesk_boundary::definition::DRAFT_ROOT),
        )
        .map_err(|error| error.to_string())?;
        validate_panel_profile(&profile, package.capabilities(), package.agent_abilities())?;
        agent.op = RecordOp::Upsert;
        agent.panel_profile = Some(profile.clone());
        self.write_agent_record(agent);
        Ok(profile)
    }

    pub(crate) fn archetype_abilities(&self, id: &str) -> Result<Vec<String>, String> {
        let target_id = self
            .library
            .authoring_target_for(id)
            .map(|target| target.id.clone())
            .ok_or_else(|| "no such archetype".to_owned())?;
        let workspace = self
            .targets
            .get(&target_id)
            .ok_or_else(|| "archetype authoring target is not open".to_owned())?;
        let engagement_id = library::gen_id("abilities-read");
        let engagement = workspace
            .create_engagement(&engagement_id)
            .map_err(|error| error.to_string())?;
        let result = (|| {
            let text = engagement
                .read_file(&format!(
                    "{}/{}",
                    gaugedesk_boundary::definition::DRAFT_ROOT,
                    gaugedesk_boundary::definition::MANIFEST_FILE
                ))
                .map_err(|error| error.to_string())?;
            let manifest: serde_json::Value =
                serde_json::from_str(&text).map_err(|error| error.to_string())?;
            manifest
                .get("agent_abilities")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| "package manifest has no explicit agent_abilities".to_owned())?
                .iter()
                .map(|ability| {
                    ability
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| "agent_abilities must contain strings".to_owned())
                })
                .collect()
        })();
        let _ = workspace.remove_engagement(&engagement_id);
        result
    }

    pub(crate) fn set_archetype_abilities(
        &mut self,
        id: &str,
        mut abilities: Vec<String>,
    ) -> Result<Vec<String>, String> {
        abilities.sort();
        abilities.dedup();
        let admitted = [
            Vec::<String>::new(),
            vec!["workspace.read".to_owned()],
            vec!["workspace.read".to_owned(), "workspace.write".to_owned()],
            vec![
                "command.run".to_owned(),
                "workspace.read".to_owned(),
                "workspace.write".to_owned(),
            ],
        ];
        if !admitted.contains(&abilities) {
            return Err("abilities must match one GaugeDesk ability preset".to_owned());
        }
        let target_id = self
            .library
            .authoring_target_for(id)
            .map(|target| target.id.clone())
            .ok_or_else(|| "no such archetype".to_owned())?;
        let workspace = self
            .targets
            .get(&target_id)
            .ok_or_else(|| "archetype authoring target is not open".to_owned())?;
        let engagement_id = library::gen_id("abilities-write");
        let engagement = workspace
            .create_engagement(&engagement_id)
            .map_err(|error| error.to_string())?;
        let result = (|| {
            let path = format!(
                "{}/{}",
                gaugedesk_boundary::definition::DRAFT_ROOT,
                gaugedesk_boundary::definition::MANIFEST_FILE
            );
            let text = engagement
                .read_file(&path)
                .map_err(|error| error.to_string())?;
            let mut manifest: serde_json::Value =
                serde_json::from_str(&text).map_err(|error| error.to_string())?;
            let capabilities = manifest
                .get("capabilities")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| "package manifest has no capability registry".to_owned())?;
            for ability in &abilities {
                if !capabilities
                    .iter()
                    .any(|capability| capability.as_str() == Some(ability))
                {
                    return Err(format!(
                        "agent ability `{ability}` is absent from the package capability registry"
                    ));
                }
            }
            manifest["agent_abilities"] = serde_json::Value::Array(
                abilities
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            );
            let body = format!(
                "{}\n",
                serde_json::to_string_pretty(&manifest).map_err(|error| error.to_string())?
            );
            engagement
                .write_file(&path, &body)
                .map_err(|error| error.to_string())?;
            engagement
                .commit_turn("set archetype agent abilities")
                .map_err(|error| error.to_string())?;
            match engagement
                .merge_into_main()
                .map_err(|error| error.to_string())?
            {
                MergeOutcome::Clean => Ok(abilities.clone()),
                MergeOutcome::Conflict => {
                    Err("archetype changed while abilities were being saved".to_owned())
                }
            }
        })();
        let _ = workspace.remove_engagement(&engagement_id);
        result
    }

    pub(crate) fn package_selection_for_chat(&self, chat_id: &str) -> Option<(u64, String)> {
        let chat = self.library.chats.get(chat_id)?;
        let instance = self.library.instances.get(&chat.instance_id)?;
        let agent = self.library.agents.get(&instance.agent_id)?;
        agent
            .versions
            .get(&instance.version)
            .map(|version| (instance.version, version.package_ref.clone()))
    }

    pub(crate) fn package_root_for_chat(
        &self,
        chat_id: &str,
        version: u64,
    ) -> Option<std::path::PathBuf> {
        let chat = self.library.chats.get(chat_id)?;
        let instance = self.library.instances.get(&chat.instance_id)?;
        let agent = self.library.agents.get(&instance.agent_id)?;
        let target = self.library.authoring_target_for(&agent.id)?;
        Some(published_package_root(
            &self.targets_dir(),
            &target.id,
            version,
        ))
    }

    pub(crate) fn update_agent_record(
        &mut self,
        id: &str,
        name: Option<String>,
        config: Option<String>,
    ) -> Option<AgentRecord> {
        let existing = self.library.agents.get(id).cloned()?;
        let updated = AgentRecord {
            name: name.unwrap_or(existing.name),
            config: config.unwrap_or(existing.config),
            ..existing
        };
        self.write_agent_record(updated.clone());
        Some(updated)
    }

    pub(crate) fn delete_agent_cascade(&mut self, id: &str) -> Result<(), AgentDeleteError> {
        if id == DEFAULT_AGENT {
            return Err(AgentDeleteError::DefaultAgent);
        }
        let Some(agent) = self.library.agents.get(id).cloned() else {
            return Err(AgentDeleteError::NotFound);
        };
        let bound_elsewhere = self.library.instances.values().any(|instance| {
            instance.agent_id == id
                && instance.kind == InstanceKind::Using
                && instance.project_id.as_deref() != Some(DEFAULT_PROJECT)
        });
        if bound_elsewhere {
            return Err(AgentDeleteError::BoundElsewhere);
        }
        let personal: Vec<String> = self
            .library
            .instances
            .values()
            .filter(|instance| {
                instance.agent_id == id
                    && instance.kind == InstanceKind::Using
                    && instance.project_id.as_deref() == Some(DEFAULT_PROJECT)
            })
            .map(|instance| instance.id.clone())
            .collect();
        for instance_id in personal {
            self.destroy_instance(&instance_id);
        }
        self.destroy_instance(&agent.instance_id);
        if let Some(existing) = self.library.agents.get(id).cloned() {
            self.write_agent_record(AgentRecord {
                op: RecordOp::Tombstone,
                ..existing
            });
        }
        Ok(())
    }

    pub(crate) fn pull_archetype_from_source(
        &mut self,
        id: &str,
    ) -> Result<MergeOutcome, PullArchetypeError> {
        let Some(fork) = self.library.agents.get(id).cloned() else {
            return Err(PullArchetypeError::NotFound);
        };
        let Some(source_id) = fork.forked_from.clone() else {
            return Err(PullArchetypeError::NotFork);
        };
        let Some(source) = self.library.agents.get(&source_id).cloned() else {
            return Err(PullArchetypeError::SourceMissing);
        };
        let source_target = self
            .library
            .authoring_target_for(&source.id)
            .map(|target| target.id.clone())
            .ok_or(PullArchetypeError::SourceNotOpen)?;
        let Some(src) = self
            .targets
            .get(&source_target)
            .map(|instance| instance.peer_source())
        else {
            return Err(PullArchetypeError::SourceNotOpen);
        };
        let fork_target = self
            .library
            .authoring_target_for(&fork.id)
            .map(|target| target.id.clone())
            .ok_or(PullArchetypeError::ForkNotOpen)?;
        let Some(fork_inst) = self.targets.get(&fork_target) else {
            return Err(PullArchetypeError::ForkNotOpen);
        };
        let outcome = fork_inst
            .pull_from(&src)
            .map_err(PullArchetypeError::Workspace)?;
        if matches!(outcome, MergeOutcome::Clean) {
            self.notify_library_changed("archetype", id, "upsert");
        }
        Ok(outcome)
    }

    pub(crate) fn project_home_value(&self, id: &str) -> Option<serde_json::Value> {
        if !self.library.projects.contains_key(id) {
            return None;
        }
        let placements = self.library.using_instances_of(id).len();
        let chats = self.library.project_chats(id);
        let mut recent_runs = Vec::new();
        let mut outputs = Vec::new();
        let mut events_total = 0usize;
        for chat in chats.iter() {
            let run = self
                .store_ref()
                .fold::<RunState>(&chat.id)
                .unwrap_or_default();
            recent_runs.push(serde_json::json!({
                "chat": chat.id,
                "title": chat.title,
                "phase": run.phase,
                "ran": run.admitted_once,
            }));
            let merge = self
                .store_ref()
                .fold::<MergeState>(&chat.id)
                .unwrap_or_default();
            if !matches!(
                merge.phase,
                gaugedesk_core::merge::MergePhase::Idle | gaugedesk_core::merge::MergePhase::Clean
            ) {
                outputs.push(serde_json::json!({
                    "chat": chat.id,
                    "title": chat.title,
                    "phase": merge.phase,
                }));
            }
            events_total += self
                .store_ref()
                .events(&chat.id)
                .map(|events| events.len())
                .unwrap_or(0);
        }
        recent_runs.sort_by(|left, right| {
            right["ran"]
                .as_u64()
                .unwrap_or(0)
                .cmp(&left["ran"].as_u64().unwrap_or(0))
        });
        Some(serde_json::json!({
            "project_id": id,
            "recent_runs": recent_runs,
            "outputs": outputs,
            "audit": {
                "placements": placements,
                "chats": chats.len(),
                "events": events_total,
            },
        }))
    }

    pub(crate) fn update_project_record(
        &mut self,
        id: &str,
        name: Option<String>,
        network_isolated: Option<bool>,
        deployment_mode: Option<Placement>,
        run_purpose: Option<Option<String>>,
    ) -> Option<ProjectRecord> {
        let existing = self.library.projects.get(id).cloned()?;
        let updated = ProjectRecord {
            name: name.unwrap_or_else(|| existing.name.clone()),
            network_isolated: network_isolated.unwrap_or(existing.network_isolated),
            deployment_mode: deployment_mode.or(existing.deployment_mode),
            run_purpose: run_purpose.unwrap_or(existing.run_purpose),
            ..existing
        };
        self.write_project_record(updated.clone());
        Some(updated)
    }

    pub(crate) fn delete_project_cascade(&mut self, id: &str) -> bool {
        let Some(project) = self.library.projects.get(id).cloned() else {
            return false;
        };
        let instance_ids: Vec<String> = self
            .library
            .using_instances_of(id)
            .iter()
            .map(|instance| instance.id.clone())
            .collect();
        for instance_id in &instance_ids {
            self.destroy_instance(instance_id);
        }
        // The hosting instances whose workspace blobs must be purged once the
        // project's chats are gone. Placement handles survive `destroy_instance`
        // (it removes only authoring targets), so they stay resolvable in
        // `self.targets` for the purge below.
        let mut affected: Vec<String> = instance_ids.clone();
        let target_ids = self
            .library
            .targets_for_project(id)
            .into_iter()
            .map(|target| target.id.clone())
            .collect::<Vec<_>>();
        for target_id in target_ids {
            let chats = self
                .library
                .chat_targets
                .values()
                .filter(|binding| binding.target_id == target_id)
                .map(|binding| binding.chat_id.clone())
                .collect::<Vec<_>>();
            for chat_id in chats {
                // Capture the host before teardown drops the index entry, so the
                // per-instance workspace purge below can reach its blobs.
                if let Some(inst) = self.engagement_index.get(&chat_id).cloned() {
                    affected.push(inst);
                }
                self.destroy_chat(&chat_id);
            }
            self.targets.remove(&target_id);
            let _ = std::fs::remove_dir_all(self.targets_dir().join(&target_id));
            if let Some(target) = self.library.work_targets.get(&target_id).cloned() {
                crate::target_adapter::remove_locator(&self.targets_dir(), &target.locator_handle);
                self.write_work_target_record(WorkTargetRecord {
                    op: RecordOp::Tombstone,
                    ..target
                });
            }
        }
        let project_workstreams = self
            .library
            .workstream_roots
            .values()
            .filter(|root| root.project_id == id)
            .map(|root| root.workstream_id.clone())
            .collect::<Vec<_>>();
        for workstream_id in project_workstreams {
            if let Some(existing) = self.library.workstreams.get(&workstream_id).cloned() {
                self.write_workstream_record(WorkstreamRecord {
                    op: RecordOp::Tombstone,
                    ..existing
                });
            }
            if let Some(existing) = self.library.workstream_roots.get(&workstream_id).cloned() {
                self.write_workstream_root_record(WorkstreamRootRecord {
                    op: RecordOp::Tombstone,
                    ..existing
                });
            }
        }
        if let Some(workspace) = self
            .library
            .project_collaboration_workspaces
            .get(id)
            .cloned()
        {
            let workspace_id = workspace.workspace_id.clone();
            self.write_project_collaboration_workspace_record(
                ProjectCollaborationWorkspaceRecord {
                    op: RecordOp::Tombstone,
                    ..workspace
                },
            );
            self.collaboration_workspaces.remove(&workspace_id);
            let _ = std::fs::remove_dir_all(
                collaboration_workspaces_dir(&self.targets_dir()).join(&workspace_id),
            );
        }
        self.write_project_record(ProjectRecord {
            op: RecordOp::Tombstone,
            ..project
        });
        // Match delete_chat_cascade (ADR 0141 / SECAUD-6): destroy the DEKs of
        // now-unreachable deleted scopes and purge their workspace blobs, so a
        // project delete erases its chats' content instead of leaving tombstones
        // with the keys and ciphertext intact.
        self.sweep_deferred_crypto_erasure();
        for inst_id in affected {
            if let Some(inst) = self.targets.get(&inst_id) {
                let _ = inst.purge_unreachable_objects();
            }
        }
        true
    }

    pub(crate) fn create_archetype(
        &mut self,
        name: String,
        agent_kind: AgentKind,
    ) -> Result<CreatedArchetype, CreateArchetypeError> {
        let agent_id = library::gen_id("agent");
        let inst_id = library::gen_id("inst");
        let target_id = authoring_target_id(&agent_id);
        let dir = self.targets_dir().join(&target_id);
        let provider = self.workspace_provider(&target_id);
        let workspace = provider
            .init_at(&dir)
            .map_err(|error| CreateArchetypeError::Create(error.to_string()))?;
        let files = default_archetype_files();
        let files = files
            .iter()
            .map(|(path, content)| (path.as_str(), content.as_str()))
            .collect::<Vec<_>>();
        workspace
            .seed_main(&files)
            .map_err(|error| CreateArchetypeError::Create(error.to_string()))?;
        let basis_probe = library::gen_id("target-basis");
        let probe = workspace
            .create_engagement(&basis_probe)
            .map_err(|error| CreateArchetypeError::Create(error.to_string()))?;
        let basis = probe
            .boundary_cut()
            .map_err(|error| CreateArchetypeError::Create(error.to_string()))?
            .0;
        drop(probe);
        workspace
            .remove_engagement(&basis_probe)
            .map_err(|error| CreateArchetypeError::Create(error.to_string()))?;
        let mut version = published_archetype_version(&self.targets_dir(), &target_id, 1)
            .map_err(|error| CreateArchetypeError::Create(error.to_string()))?;
        let panel_profile = (agent_kind == AgentKind::Panel).then(PanelPublicProfile::default);
        version.panel_profile = panel_profile.clone();
        self.targets.insert(target_id.clone(), workspace);
        self.write_instance_record(InstanceRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: inst_id.clone(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Authoring,
            placement_kind: agent_kind.into(),
            agent_id: agent_id.clone(),
            project_id: None,
            version: 1,
            admission: Admission::Active,
            collection_recipient: None,
        });
        activate_instance(self.store_mut(), &inst_id);
        self.write_agent_record(AgentRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: agent_id.clone(),
            op: RecordOp::Upsert,
            name: name.clone(),
            agent_kind,
            panel_profile,
            instance_id: inst_id.clone(),
            config: "{}".into(),
            current_version: 1,
            versions: [(1, version)].into_iter().collect(),
            auto_upgrade: false,
            forked_from: None,
        });
        let home_id = self.home_id().clone();
        self.write_work_target_record(managed_target_record(
            target_id,
            format!("{name} authoring"),
            WorkTargetOwner::Archetype {
                archetype_id: agent_id.clone(),
            },
            &home_id,
            basis,
        ));
        if agent_kind == AgentKind::Work {
            let _ = self.place_archetype_on_project(
                DEFAULT_PROJECT,
                &agent_id,
                crate::library::Admission::Active,
            );
        }
        Ok(CreatedArchetype { id: agent_id, name })
    }

    pub(crate) fn fork_archetype(
        &mut self,
        id: &str,
        name: Option<String>,
    ) -> Result<CreatedArchetype, ForkArchetypeError> {
        let Some(src) = self.library.agents.get(id).cloned() else {
            return Err(ForkArchetypeError::NotFound);
        };
        let source_target_id = self
            .library
            .authoring_target_for(&src.id)
            .map(|target| target.id.clone())
            .ok_or(ForkArchetypeError::SourceNotOpen)?;
        let Some(src_source) = self
            .targets
            .get(&source_target_id)
            .map(|instance| instance.peer_source())
        else {
            return Err(ForkArchetypeError::SourceNotOpen);
        };
        let new_agent = library::gen_id("agent");
        let new_inst = library::gen_id("inst");
        let new_target = authoring_target_id(&new_agent);
        let dir = self.targets_dir().join(&new_target);
        let workspace = self
            .workspace_provider(&new_target)
            .fork_from_at(&dir, &src_source)
            .map_err(|error| ForkArchetypeError::Create(error.to_string()))?;
        let basis_probe = library::gen_id("target-basis");
        let probe = workspace
            .create_engagement(&basis_probe)
            .map_err(|error| ForkArchetypeError::Create(error.to_string()))?;
        let basis = probe
            .boundary_cut()
            .map_err(|error| ForkArchetypeError::Create(error.to_string()))?
            .0;
        drop(probe);
        workspace
            .remove_engagement(&basis_probe)
            .map_err(|error| ForkArchetypeError::Create(error.to_string()))?;
        self.targets.insert(new_target.clone(), workspace);
        self.write_instance_record(InstanceRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: new_inst.clone(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Authoring,
            placement_kind: src.agent_kind.into(),
            agent_id: new_agent.clone(),
            project_id: None,
            version: 1,
            admission: Admission::Active,
            collection_recipient: None,
        });
        activate_instance(self.store_mut(), &new_inst);
        let name = name.unwrap_or_else(|| format!("{} (fork)", src.name));
        self.write_agent_record(AgentRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: new_agent.clone(),
            op: RecordOp::Upsert,
            name: name.clone(),
            agent_kind: src.agent_kind,
            panel_profile: src.panel_profile.clone(),
            instance_id: new_inst.clone(),
            config: src.config.clone(),
            current_version: src.current_version,
            versions: src.versions.clone(),
            auto_upgrade: false,
            forked_from: Some(src.id.clone()),
        });
        let home_id = self.home_id().clone();
        self.write_work_target_record(managed_target_record(
            new_target,
            format!("{name} authoring"),
            WorkTargetOwner::Archetype {
                archetype_id: new_agent.clone(),
            },
            &home_id,
            basis,
        ));
        if src.agent_kind == AgentKind::Work {
            let _ = self.place_archetype_on_project(
                DEFAULT_PROJECT,
                &new_agent,
                crate::library::Admission::Active,
            );
        }
        Ok(CreatedArchetype {
            id: new_agent,
            name,
        })
    }

    /// Explicitly copy any Agent into a new Panel-agent lineage. Kind is never
    /// mutated in place; the new lineage receives a complete default public
    /// profile on every inherited version and no Personal work placement.
    pub(crate) fn copy_agent_as_panel(
        &mut self,
        id: &str,
        name: Option<String>,
    ) -> Result<CreatedArchetype, ForkArchetypeError> {
        let source_name = self
            .library
            .agents
            .get(id)
            .map(|agent| agent.name.clone())
            .ok_or(ForkArchetypeError::NotFound)?;
        let created = self.fork_archetype(
            id,
            Some(name.unwrap_or_else(|| format!("{source_name} Panel"))),
        )?;
        let personal_placements = self
            .library
            .instances
            .values()
            .filter(|instance| {
                instance.kind == InstanceKind::Using
                    && instance.agent_id == created.id
                    && instance.project_id.as_deref() == Some(DEFAULT_PROJECT)
            })
            .map(|instance| instance.id.clone())
            .collect::<Vec<_>>();
        for placement in personal_placements {
            self.destroy_instance(&placement);
        }
        let profile = PanelPublicProfile::default();
        let mut agent = self
            .library
            .agents
            .get(&created.id)
            .cloned()
            .ok_or(ForkArchetypeError::NotFound)?;
        agent.agent_kind = AgentKind::Panel;
        agent.panel_profile = Some(profile.clone());
        for version in agent.versions.values_mut() {
            version.panel_profile = Some(profile.clone());
        }
        let authoring_instance_id = agent.instance_id.clone();
        self.write_agent_record(agent);
        if let Some(mut instance) = self.library.instances.get(&authoring_instance_id).cloned() {
            instance.placement_kind = PlacementKind::Panel;
            self.write_instance_record(instance);
        }
        Ok(created)
    }

    pub(crate) fn place_archetype_on_project(
        &mut self,
        project_id: &str,
        agent_id: &str,
        admission: Admission,
    ) -> Result<String, String> {
        let inst_id = library::gen_id("inst");
        self.place_archetype_on_project_with_id(project_id, agent_id, &inst_id, admission)
    }

    pub(crate) fn place_archetype_on_project_with_id(
        &mut self,
        project_id: &str,
        agent_id: &str,
        inst_id: &str,
        admission: Admission,
    ) -> Result<String, String> {
        let inst_id = inst_id.to_string();
        if !self.library.projects.contains_key(project_id) {
            return Err("no such project".to_owned());
        }
        let agent = self
            .library
            .agents
            .get(agent_id)
            .cloned()
            .ok_or_else(|| "no such archetype".to_owned())?;
        if agent.agent_kind == AgentKind::Panel {
            return Err("panel agents require an explicit project binding".to_owned());
        }
        let target_ids = self
            .library
            .targets_for_project(project_id)
            .into_iter()
            .filter(|target| target.status == WorkTargetStatus::Available)
            .map(|target| target.id.clone())
            .collect::<Vec<_>>();
        if target_ids.is_empty() {
            return Err("project has no work target".to_owned());
        }
        let version = agent.current_version;
        self.write_instance_record(InstanceRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: inst_id.clone(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Using,
            placement_kind: PlacementKind::Work,
            agent_id: agent_id.to_string(),
            project_id: Some(project_id.to_string()),
            version,
            admission,
            collection_recipient: None,
        });
        self.write_placement_targets_record(PlacementTargetsRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            placement_id: inst_id.clone(),
            op: RecordOp::Upsert,
            target_ids,
        });
        let _ = self
            .store_mut()
            .admit::<InstanceState>(&inst_id, InstanceCommand::PinVersion("v0".into()));
        Ok(inst_id)
    }

    fn place_panel_agent_on_project(
        &mut self,
        project_id: &str,
        agent_id: &str,
        admission: Admission,
        collection_recipient: Option<PanelCollectionRecipient>,
    ) -> Result<String, String> {
        if !self.library.projects.contains_key(project_id) {
            return Err("no such project".to_owned());
        }
        let agent = self
            .library
            .agents
            .get(agent_id)
            .cloned()
            .ok_or_else(|| "no such archetype".to_owned())?;
        if agent.agent_kind != AgentKind::Panel {
            return Err("agent is not a panel agent".to_owned());
        }
        let profile = agent
            .versions
            .get(&agent.current_version)
            .and_then(|version| version.panel_profile.as_ref())
            .ok_or_else(|| "panel agent version has no frozen public profile".to_owned())?;
        if profile.collection.is_some() && collection_recipient.is_none() {
            return Err("a collecting panel agent requires a project recipient".to_owned());
        }
        if profile.collection.is_none() && collection_recipient.is_some() {
            return Err("this panel agent version does not collect output".to_owned());
        }
        let inst_id = library::gen_id("inst");
        self.write_instance_record(InstanceRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: inst_id.clone(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Using,
            placement_kind: PlacementKind::Panel,
            agent_id: agent_id.to_owned(),
            project_id: Some(project_id.to_owned()),
            version: agent.current_version,
            admission,
            collection_recipient,
        });
        let _ = self
            .store_mut()
            .admit::<InstanceState>(&inst_id, InstanceCommand::PinVersion("v0".into()));
        Ok(inst_id)
    }

    /// Bind a library agent into a project as a placement (`APPROVE-1`, ADR 0064). The
    /// placement's admission is **policy-gated**: under an approval-required project
    /// policy it enters `Pending` (awaiting the owner's accept); by default it is
    /// frictionless and lands `Active` at once.
    pub(crate) fn bind_agent_to_project(
        &mut self,
        project_id: &str,
        agent_id: &str,
        collection_recipient: Option<PanelCollectionRecipient>,
    ) -> Result<String, BindPlacementError> {
        if !self.library.projects.contains_key(project_id) {
            return Err(BindPlacementError::ProjectNotFound);
        }
        let agent_kind = self
            .library
            .agents
            .get(agent_id)
            .map(|agent| agent.agent_kind)
            .ok_or(BindPlacementError::AgentNotFound)?;
        let admission = if self.require_archetype_approval() {
            Admission::Pending
        } else {
            Admission::Active
        };
        let result = match agent_kind {
            AgentKind::Work => {
                if collection_recipient.is_some() {
                    return Err(BindPlacementError::Create(
                        "work placements cannot bind collection recipients".to_owned(),
                    ));
                }
                self.place_archetype_on_project(project_id, agent_id, admission)
            }
            AgentKind::Panel => self.place_panel_agent_on_project(
                project_id,
                agent_id,
                admission,
                collection_recipient,
            ),
        };
        result.map_err(BindPlacementError::Create)
    }

    /// The effective per-org archetype-approval policy (`APPROVE-1`, ADR 0064): when set,
    /// an explicitly-placed archetype must be accepted by the project owner before it is
    /// usable. Read from the org projection; defaults to frictionless (`false`).
    pub(crate) fn require_archetype_approval(&self) -> bool {
        crate::org::Org::rebuild(self.store_ref())
            .map(|org| org.effective_require_archetype_approval())
            .unwrap_or(false)
    }

    /// **Accept** a pending placement (`APPROVE-1`, ADR 0064): the project owner's second
    /// explicit act flips it `Pending → Active`, so it can host work chats and appear in
    /// the chat picker. Accepting an already-active placement is idempotent. Returns
    /// `None` for an unknown placement.
    pub(crate) fn accept_placement(&mut self, inst_id: &str) -> Option<Admission> {
        let mut placement = self.library.instances.get(inst_id).cloned()?;
        placement.op = RecordOp::Upsert;
        placement.admission = Admission::Active;
        self.write_instance_record(placement);
        Some(Admission::Active)
    }

    fn freeze_archetype_draft(
        &mut self,
        target_id: &str,
        version: u64,
        panel_profile: Option<PanelPublicProfile>,
    ) -> Result<ArchetypeVersionRecord, PublishArchetypeError> {
        let snapshot_chat = library::gen_id("package-freeze");
        let instance = self
            .targets
            .get(target_id)
            .ok_or(PublishArchetypeError::NotFound)?;
        let engagement = instance
            .create_engagement(&snapshot_chat)
            .map_err(|error| PublishArchetypeError::Workspace(error.to_string()))?;
        let draft = gaugedesk_boundary::definition::DRAFT_ROOT;
        let target = gaugedesk_boundary::definition::version_root(version);
        let result = (|| {
            if engagement
                .tree()
                .map_err(|error| PublishArchetypeError::Workspace(error.to_string()))?
                .iter()
                .any(|entry| entry.path == target || entry.path.starts_with(&format!("{target}/")))
            {
                return Err(PublishArchetypeError::InvalidPackage(format!(
                    "package version {version} is already frozen"
                )));
            }
            for file in [
                gaugedesk_boundary::definition::MANIFEST_FILE,
                gaugedesk_boundary::definition::SOURCE_FILE,
                gaugedesk_boundary::definition::PERSONA_FILE,
            ] {
                let body = engagement
                    .read_file(&format!("{draft}/{file}"))
                    .map_err(|error| PublishArchetypeError::InvalidPackage(error.to_string()))?;
                engagement
                    .write_file(&format!("{target}/{file}"), &body)
                    .map_err(|error| PublishArchetypeError::Workspace(error.to_string()))?;
            }
            let package =
                gaugedesk_whip_runtime::AuthoredAgentPackage::load(engagement.path().join(&target))
                    .map_err(PublishArchetypeError::InvalidPackage)?;
            if let Some(profile) = &panel_profile {
                validate_panel_profile(profile, package.capabilities(), package.agent_abilities())
                    .map_err(PublishArchetypeError::InvalidPackage)?;
            }
            let discipline = crate::discipline::load(
                &engagement
                    .path()
                    .join(crate::discipline::DISCIPLINE_DRAFT_ROOT),
                package.capabilities().iter().cloned(),
            )
            .map_err(PublishArchetypeError::InvalidPackage)?;
            let discipline_target = crate::discipline::discipline_version_root(version);
            for (path, body) in &discipline.files {
                engagement
                    .write_file(&format!("{discipline_target}/{path}"), body)
                    .map_err(|error| PublishArchetypeError::Workspace(error.to_string()))?;
            }
            let frozen_discipline = crate::discipline::load(
                &engagement.path().join(&discipline_target),
                package.capabilities().iter().cloned(),
            )
            .map_err(PublishArchetypeError::InvalidPackage)?;
            let version_record = ArchetypeVersionRecord {
                package_ref: package.version_ref().to_owned(),
                discipline_ref: frozen_discipline.reference,
                panel_profile: panel_profile.clone(),
            };
            engagement
                .commit_turn(&format!("freeze archetype version {version}"))
                .map_err(|error| PublishArchetypeError::Workspace(error.to_string()))?;
            match engagement
                .merge_into_main()
                .map_err(|error| PublishArchetypeError::Workspace(error.to_string()))?
            {
                MergeOutcome::Clean => Ok(version_record),
                MergeOutcome::Conflict => Err(PublishArchetypeError::Workspace(
                    "archetype draft changed while it was being published".to_owned(),
                )),
            }
        })();
        let _ = instance.remove_engagement(&snapshot_chat);
        result
    }

    pub(crate) fn publish_archetype_version(
        &mut self,
        id: &str,
        auto_upgrade: Option<bool>,
    ) -> Result<(u64, u64), PublishArchetypeError> {
        let mut agent = self
            .library
            .agents
            .get(id)
            .cloned()
            .ok_or(PublishArchetypeError::NotFound)?;
        let new_version = agent.current_version + 1;
        let target_id = self
            .library
            .authoring_target_for(id)
            .map(|target| target.id.clone())
            .ok_or(PublishArchetypeError::NotFound)?;
        if agent.agent_kind == AgentKind::Panel && agent.panel_profile.is_none() {
            return Err(PublishArchetypeError::InvalidPackage(
                "panel agent has no public profile".to_owned(),
            ));
        }
        let version_record =
            self.freeze_archetype_draft(&target_id, new_version, agent.panel_profile.clone())?;
        if let Some(auto_upgrade) = auto_upgrade {
            agent.auto_upgrade = auto_upgrade;
        }
        agent.op = RecordOp::Upsert;
        agent.current_version = new_version;
        agent.versions.insert(new_version, version_record);
        let owner_auto = agent.auto_upgrade;
        self.write_agent_record(agent);
        let org_allows = crate::org::Org::rebuild(self.store_ref())
            .map(|org| org.allow_auto_upgrade())
            .unwrap_or(false);
        let mut auto_upgraded = 0u64;
        if owner_auto && org_allows {
            let behind: Vec<String> = self
                .library
                .instances
                .values()
                .filter(|instance| {
                    instance.agent_id == id
                        && matches!(instance.kind, InstanceKind::Using)
                        && instance.version < new_version
                })
                .map(|instance| instance.id.clone())
                .collect();
            for placement in behind {
                if self.upgrade_placement_version(&placement).is_ok() {
                    auto_upgraded += 1;
                }
            }
        }
        Ok((new_version, auto_upgraded))
    }

    pub(crate) fn upgrade_placement_version(
        &mut self,
        id: &str,
    ) -> Result<u64, UpgradePlacementError> {
        let Some(mut placement) = self.library.instances.get(id).cloned() else {
            return Err(UpgradePlacementError::PlacementNotFound);
        };
        let Some(agent) = self.library.agents.get(&placement.agent_id).cloned() else {
            return Err(UpgradePlacementError::ArchetypeNotFound);
        };
        let expected_version = agent
            .versions
            .get(&agent.current_version)
            .cloned()
            .ok_or_else(|| {
                UpgradePlacementError::PackageUnavailable(format!(
                    "archetype version {} has no frozen package reference",
                    agent.current_version
                ))
            })?;
        let authoring_target = self
            .library
            .authoring_target_for(&agent.id)
            .ok_or(UpgradePlacementError::ArchetypeNotFound)?;
        let resolved = gaugedesk_whip_runtime::AuthoredAgentPackage::load(published_package_root(
            &self.targets_dir(),
            &authoring_target.id,
            agent.current_version,
        ))
        .map_err(UpgradePlacementError::PackageUnavailable)?;
        if resolved.version_ref() != expected_version.package_ref {
            return Err(UpgradePlacementError::PackageUnavailable(
                "placement package bytes do not match the published reference".to_owned(),
            ));
        }
        let discipline = crate::discipline::load(
            &published_discipline_root(
                &self.targets_dir(),
                &authoring_target.id,
                agent.current_version,
            ),
            resolved.capabilities().iter().cloned(),
        )
        .map_err(UpgradePlacementError::PackageUnavailable)?;
        if discipline.reference != expected_version.discipline_ref {
            return Err(UpgradePlacementError::PackageUnavailable(
                "placement discipline bytes do not match the published reference".to_owned(),
            ));
        }
        // An upgrade selects a new immutable discipline but never rewrites a
        // target. Changed scaffold/managed declarations become ordinary
        // target proposals with the target's exact standing basis.
        let old_assets =
            published_discipline_root(&self.targets_dir(), &authoring_target.id, placement.version);
        let old_files = crate::discipline::load(
            &old_assets,
            gaugedesk_whip_runtime::AuthoredAgentPackage::load(published_package_root(
                &self.targets_dir(),
                &authoring_target.id,
                placement.version,
            ))
            .map_err(UpgradePlacementError::PackageUnavailable)?
            .capabilities()
            .iter()
            .cloned(),
        )
        .map(|bundle| bundle.files.into_iter().collect::<BTreeMap<_, _>>())
        .unwrap_or_default();
        let new_files = discipline.files.iter().cloned().collect::<BTreeMap<_, _>>();
        let proposed_changes = discipline
            .manifest
            .assets
            .iter()
            .filter(|asset| {
                matches!(
                    asset.treatment,
                    crate::discipline::DisciplineTreatment::Scaffold
                        | crate::discipline::DisciplineTreatment::Managed
                ) && old_files.get(&asset.path) != new_files.get(&asset.path)
            })
            .map(|asset| format!("{:?}:{}", asset.treatment, asset.path))
            .collect::<Vec<_>>();
        if !proposed_changes.is_empty() {
            let target_ids = self
                .library
                .placement_targets
                .get(id)
                .map(|record| record.target_ids.clone())
                .unwrap_or_default();
            for target_id in target_ids {
                self.record_target_act(
                    None,
                    &target_id,
                    crate::target_adapter::TargetActKind::Propose,
                    Some(expected_version.discipline_ref.clone()),
                    proposed_changes.clone(),
                    None,
                    crate::target_adapter::TargetActStatus::Completed,
                    Some(format!(
                        "archetype upgrade {} -> {}",
                        placement.version, agent.current_version
                    )),
                )
                .map_err(UpgradePlacementError::PackageUnavailable)?;
            }
        }
        placement.op = RecordOp::Upsert;
        placement.version = agent.current_version;
        let version = placement.version;
        self.write_instance_record(placement);
        Ok(version)
    }

    pub(crate) fn unbind_instance(&mut self, id: &str) -> bool {
        if !self.library.instances.contains_key(id) {
            return false;
        }
        self.destroy_instance(id);
        true
    }

    pub(crate) fn create_chat_under_agent(
        &mut self,
        agent_id: &str,
        title: &str,
    ) -> Result<serde_json::Value, CreateArchetypeChatError> {
        let Some(agent) = self.library.agents.get(agent_id).cloned() else {
            return Err(CreateArchetypeChatError::ArchetypeNotFound);
        };
        self.create_chat_in_instance(&agent.instance_id, title)
            .map_err(CreateArchetypeChatError::Create)
    }

    pub(crate) fn use_archetype_chat(
        &mut self,
        agent_id: &str,
        title: &str,
    ) -> Result<serde_json::Value, CreateArchetypeChatError> {
        let agent = self
            .library
            .agents
            .get(agent_id)
            .ok_or(CreateArchetypeChatError::ArchetypeNotFound)?;
        if agent.agent_kind == AgentKind::Panel {
            return Err(CreateArchetypeChatError::Create(
                "panel agents are previewed with their public contract and are not used in Personal"
                    .to_owned(),
            ));
        }
        let existing = self
            .library
            .instances
            .values()
            .find(|instance| {
                instance.kind == InstanceKind::Using
                    && instance.agent_id == agent_id
                    && instance.project_id.as_deref() == Some(DEFAULT_PROJECT)
            })
            .map(|instance| instance.id.clone());
        let placement_id = match existing {
            Some(placement_id) => placement_id,
            None => self
                .place_archetype_on_project(DEFAULT_PROJECT, agent_id, Admission::Active)
                .map_err(CreateArchetypeChatError::Create)?,
        };
        self.create_chat_in_instance(&placement_id, title)
            .map_err(CreateArchetypeChatError::Create)
    }

    fn compensate_failed_chat_fork(
        &mut self,
        storage_id: &str,
        chat_id: &str,
        continuity: &gaugedesk_harness::HarnessContinuitySpec,
    ) {
        if let Some(harness) = self.sessions.remove(chat_id) {
            crate::workbench_state::shutdown_shared_harness(harness);
        }
        self.engagements.remove(chat_id);
        self.engagement_index.remove(chat_id);
        if let Some(workspace) = self.workspace_by_storage_id(storage_id) {
            let _ = workspace.leave_engagement_workstream(chat_id);
            let _ = workspace.remove_engagement(chat_id);
            let _ = workspace.purge_unreachable_objects();
        }
        if let Ok(factory) = self.whip_harness_factory() {
            let _ = factory.discard_continuity(continuity);
        }
        if let Some(existing) = self.library.chats.get(chat_id).cloned() {
            self.write_chat_record(ChatRecord {
                op: RecordOp::Tombstone,
                ..existing
            });
        }
        if let Some(existing) = self.library.chat_targets.get(chat_id).cloned() {
            self.write_chat_target_record(ChatTargetBindingRecord {
                op: RecordOp::Tombstone,
                ..existing
            });
        }
        self.crypto_erase_content(chat_id);
    }

    pub(crate) fn fork_chat_with_destination(
        &mut self,
        id: &str,
        destination: ForkDestination,
    ) -> Result<ForkedChat, ForkChatError> {
        self.fork_chat_from(id, None, destination)
    }

    pub(crate) fn fork_chat_at_with_destination(
        &mut self,
        id: &str,
        entry_id: i64,
        destination: ForkDestination,
    ) -> Result<ForkedChat, ForkChatError> {
        let point = self.resolve_fork_point(id, entry_id)?;
        self.fork_chat_from(id, Some(point), destination)
    }

    fn resolve_fork_point(
        &self,
        id: &str,
        entry_id: i64,
    ) -> Result<ResolvedForkPoint, ForkChatError> {
        let exact_snapshot = |snapshot: crate::engine::TurnForkSnapshot| {
            if !snapshot.visible_settlement_handles.is_empty()
                && snapshot.visible_settlements.is_empty()
            {
                Err(ForkChatError::PointNotForkable)
            } else {
                Ok(snapshot)
            }
        };
        let boundaries = self
            .store
            .records(id, crate::engine::TURN_BOUNDARY_KIND)
            .map_err(|error| ForkChatError::Continuity(format!("{error:?}")))?;
        for payload in boundaries {
            let boundary: crate::engine::TurnBoundaryRecord = serde_json::from_str(&payload)
                .map_err(|error| ForkChatError::Continuity(error.to_string()))?;
            if boundary.user_entry_id == entry_id {
                let fork_snapshot = exact_snapshot(
                    boundary
                        .fork_snapshot
                        .ok_or(ForkChatError::PointNotForkable)?,
                )?;
                return Ok(ResolvedForkPoint {
                    entry_id,
                    inherited_cut: entry_id - 1,
                    workspace_cut: boundary.before_workspace_cut,
                    runtime_position: boundary.runtime_before,
                    reads: boundary.reads_before,
                    taint_evidence_digest: fork_snapshot.before_taint_evidence_digest.clone(),
                    fork_snapshot,
                });
            }
            if boundary.assistant_entry_id == entry_id {
                let fork_snapshot = exact_snapshot(
                    boundary
                        .fork_snapshot
                        .ok_or(ForkChatError::PointNotForkable)?,
                )?;
                return Ok(ResolvedForkPoint {
                    entry_id,
                    inherited_cut: entry_id,
                    workspace_cut: boundary.after_workspace_cut,
                    runtime_position: boundary.runtime_after,
                    reads: boundary.reads_after,
                    taint_evidence_digest: fork_snapshot.after_taint_evidence_digest.clone(),
                    fork_snapshot,
                });
            }
        }
        Err(ForkChatError::PointNotForkable)
    }

    fn resolve_fork_destination(
        &self,
        instance_kind: InstanceKind,
        storage_id: &str,
        snapshot: Option<&crate::engine::TurnForkSnapshot>,
        destination: &ForkDestination,
    ) -> Result<Option<ResolvedForkDestination>, ForkChatError> {
        if instance_kind != InstanceKind::Using {
            return match destination {
                ForkDestination::Inherit => Ok(None),
                _ => Err(ForkChatError::Continuity(
                    "explicit project destinations require a work chat".to_owned(),
                )),
            };
        }
        let snapshot = snapshot.ok_or(ForkChatError::SourceNotLive)?;
        if snapshot.collaboration_workspace_id != storage_id {
            return Err(ForkChatError::Continuity(
                "historical fork point belongs to a different collaboration workspace".to_owned(),
            ));
        }
        let workspace = self
            .workspace_by_storage_id(storage_id)
            .ok_or(ForkChatError::InstanceNotOpen)?;
        let active_workstream = |workstream_id: &str,
                                 inherited: bool|
         -> Result<ResolvedForkDestination, ForkChatError> {
            if workstream_id.is_empty() {
                return Err(ForkChatError::Continuity(
                    "fork destination workstream id is empty".to_owned(),
                ));
            }
            let row = workspace
                .workstream(workstream_id)
                .map_err(|error| ForkChatError::Continuity(error.to_string()))?
                .ok_or_else(|| {
                    ForkChatError::Continuity(
                        "fork destination workstream is unavailable".to_owned(),
                    )
                })?;
            if row.status == whipplescript_store::workstreams::StreamStatus::Archived {
                return if inherited {
                    Err(ForkChatError::HistoricalHomeClosed)
                } else {
                    Err(ForkChatError::Continuity(
                        "fork destination workstream is archived".to_owned(),
                    ))
                };
            }
            if row.status != whipplescript_store::workstreams::StreamStatus::Active {
                return Err(ForkChatError::Continuity(
                    "fork destination workstream is not active".to_owned(),
                ));
            }
            Ok(ResolvedForkDestination {
                line_ref: row.line_branch_id,
                workstream_id: Some(workstream_id.to_owned()),
            })
        };
        match destination {
            ForkDestination::Inherit => match snapshot.historical_home.stream_id.as_deref() {
                Some(workstream_id) => active_workstream(workstream_id, true).map(Some),
                None => Ok(Some(ResolvedForkDestination {
                    line_ref: workspace.mainline().to_owned(),
                    workstream_id: None,
                })),
            },
            ForkDestination::Main => Ok(Some(ResolvedForkDestination {
                line_ref: workspace.mainline().to_owned(),
                workstream_id: None,
            })),
            ForkDestination::Workstream { workstream_id } => {
                active_workstream(workstream_id, false).map(Some)
            }
        }
    }

    fn fork_chat_from(
        &mut self,
        id: &str,
        point: Option<ResolvedForkPoint>,
        destination: ForkDestination,
    ) -> Result<ForkedChat, ForkChatError> {
        let Some(src_chat) = self.library.chats.get(id).cloned() else {
            return Err(ForkChatError::NotFound);
        };
        let runtime_placement_id = self.library_placement_of_chat(id);
        let inst_id = src_chat.instance_id.clone();
        let source_binding = self.library.chat_targets.get(id).cloned();
        let instance = self
            .library
            .instances
            .get(&inst_id)
            .cloned()
            .ok_or(ForkChatError::SourceNotLive)?;
        let storage_id = self
            .engagement_index
            .get(id)
            .cloned()
            .ok_or(ForkChatError::SourceNotLive)?;
        let current_snapshot = if point.is_none() && instance.kind == InstanceKind::Using {
            let policy = self.latest_whipple_policy(id).ok().flatten();
            self.turn_fork_snapshot(
                id,
                policy.as_ref().map(|(epoch, _)| *epoch),
                policy.as_ref().map(|(_, envelope)| envelope.as_str()),
                None,
            )
            .ok()
            .flatten()
        } else {
            None
        };
        let historical_snapshot = point
            .as_ref()
            .map(|point| point.fork_snapshot.clone())
            .or(current_snapshot);
        let members = historical_snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .targets
                    .iter()
                    .map(|target| ChatTargetSetMemberRecord {
                        target_id: target.target_id.clone(),
                        adapter_family: target.adapter_family.clone(),
                        path_scope: target.path_scope.clone(),
                        capability_ceiling: target.capabilities.clone(),
                        participation: target.participation,
                    })
                    .collect::<Vec<_>>()
            })
            .or_else(|| {
                self.library
                    .current_target_set(id)
                    .map(|set| set.members.clone())
            })
            .or_else(|| {
                source_binding.as_ref().and_then(|binding| {
                    self.library
                        .work_targets
                        .get(&binding.target_id)
                        .map(|target| {
                            vec![ChatTargetSetMemberRecord {
                                target_id: binding.target_id.clone(),
                                adapter_family: target.adapter_family.clone(),
                                path_scope: binding.path_scope.clone(),
                                capability_ceiling: binding.capabilities.clone(),
                                participation: if binding.capabilities.propose {
                                    TargetParticipationMode::Writable
                                } else {
                                    TargetParticipationMode::ReadOnly
                                },
                            }]
                        })
                })
            })
            .ok_or(ForkChatError::SourceNotLive)?;
        let member_bases = members
            .iter()
            .map(|member| {
                let basis = historical_snapshot
                    .as_ref()
                    .and_then(|snapshot| {
                        snapshot
                            .targets
                            .iter()
                            .find(|target| target.target_id == member.target_id)
                    })
                    .map(|target| target.native_basis.clone())
                    .or_else(|| {
                        self.library
                            .chat_target_basis(id, &member.target_id)
                            .map(str::to_owned)
                    })
                    .or_else(|| {
                        self.library
                            .chat_targets
                            .get(id)
                            .filter(|binding| binding.target_id == member.target_id)
                            .map(|binding| binding.basis.clone())
                    })
                    .or_else(|| {
                        self.library
                            .work_targets
                            .get(&member.target_id)
                            .and_then(|target| target.current_basis.clone())
                    })
                    .ok_or(ForkChatError::SourceNotLive)?;
                Ok((member.target_id.clone(), basis))
            })
            .collect::<Result<BTreeMap<_, _>, ForkChatError>>()?;
        let singular_basis = members
            .first()
            .filter(|_| members.len() == 1)
            .and_then(|member| member_bases.get(&member.target_id).cloned());
        // Resolve current topology before creating either the collaboration
        // branch or runtime fork. Historical home is provenance; current Home
        // decides whether and where the child may join.
        let resolved_destination = self.resolve_fork_destination(
            instance.kind,
            &storage_id,
            historical_snapshot.as_ref(),
            &destination,
        )?;
        let (src_path, source_branch, source_target, current_cut) = {
            let Some(src_eng) = self.engagements.get(id) else {
                return Err(ForkChatError::SourceNotLive);
            };
            let current_cut = src_eng
                .boundary_cut()
                .map_err(|error| ForkChatError::Create(error.to_string()))?;
            (
                src_eng.path().to_path_buf(),
                src_eng.branch().to_owned(),
                src_eng.target().to_owned(),
                current_cut.0,
            )
        };
        let workspace_cut = point
            .as_ref()
            .map(|point| point.workspace_cut.as_str())
            .unwrap_or(current_cut.as_str());
        let new_id = library::gen_id("chat");
        let (mut new_eng, new_path, mode) = {
            let Some(inst) = self.workspace_by_storage_id(&storage_id) else {
                return Err(ForkChatError::InstanceNotOpen);
            };
            let sparse_roots = (instance.kind == InstanceKind::Using
                && historical_snapshot.is_some())
            .then(|| {
                members
                    .iter()
                    .map(|member| {
                        crate::library::target_id_path_v1(&member.target_id)
                            .map(|encoded| format!("targets/{encoded}"))
                    })
                    .collect::<Result<BTreeSet<_>, _>>()
            })
            .transpose()
            .map_err(ForkChatError::Create)?;
            let eng = match &sparse_roots {
                Some(roots) => inst.fork_engagement_subset_at(
                    &new_id,
                    &source_branch,
                    &source_target,
                    workspace_cut,
                    roots,
                ),
                None => {
                    inst.fork_engagement_at(&new_id, &source_branch, &source_target, workspace_cut)
                }
            }
            .map_err(|error| ForkChatError::Create(error.to_string()))?;
            let path = eng.path().to_path_buf();
            let mode = instance.kind.chat_mode();
            (eng, path, mode)
        };
        // Continuity belongs to WhippleScript even when the fake is active. A
        // fork is not admitted unless the runtime gives the target a distinct,
        // source-bound thread identity; file-only forks would silently forget
        // the conversation they claim to clone.
        let prompt_override = matches!(mode, crate::library::ChatMode::Edit)
            .then(|| crate::engine::EDITOR_FRAMING.to_owned());
        let package_selection = self.library.instances.get(&inst_id).and_then(|instance| {
            self.library
                .agents
                .get(&instance.agent_id)
                .and_then(|agent| {
                    let target = self.library.authoring_target_for(&agent.id)?;
                    agent.versions.get(&instance.version).map(|version| {
                        (
                            instance.version,
                            version.package_ref.clone(),
                            published_package_root(
                                &self.targets_dir(),
                                &target.id,
                                instance.version,
                            ),
                        )
                    })
                })
        });
        let source_package_root = package_selection
            .as_ref()
            .map(|(_, _, package_root)| package_root.clone());
        let target_package_root = source_package_root.clone();
        let package_version_ref = package_selection.map(|(_, package_ref, _)| package_ref);
        let source_policy = self
            .latest_whipple_policy(id)
            .map_err(ForkChatError::Continuity)?;
        let source_continuity = gaugedesk_harness::HarnessContinuitySpec {
            chat_id: id.to_owned(),
            runtime_placement_id: runtime_placement_id.clone(),
            worktree: src_path,
            mode,
            package_root: source_package_root,
            package_version_ref: package_version_ref.clone(),
            system_prompt: prompt_override.clone(),
            policy_epoch: source_policy.as_ref().map(|(epoch, _)| *epoch),
            signed_policy_envelope: source_policy.as_ref().map(|(_, envelope)| envelope.clone()),
            source_position: point.as_ref().map(|point| point.runtime_position.clone()),
        };
        let target_continuity = gaugedesk_harness::HarnessContinuitySpec {
            chat_id: new_id.clone(),
            runtime_placement_id,
            worktree: new_path,
            mode,
            package_root: target_package_root,
            package_version_ref,
            system_prompt: prompt_override,
            policy_epoch: source_policy.as_ref().map(|(epoch, _)| *epoch),
            signed_policy_envelope: source_policy.map(|(_, envelope)| envelope),
            source_position: None,
        };
        let continuity = self
            .whip_harness_factory()
            .and_then(|factory| factory.clone_continuity(&source_continuity, &target_continuity));
        if let Err(error) = continuity {
            drop(new_eng);
            self.compensate_failed_chat_fork(&storage_id, &new_id, &target_continuity);
            return Err(ForkChatError::Continuity(error.to_string()));
        }
        // The forked branch stays at the promised historical cut.  Its active
        // home is admitted separately; changing the topology must not pull the
        // destination's latest files into this initial materialization.
        let topology_admission = (|| {
            let Some(admitted) = &resolved_destination else {
                return Ok(None);
            };
            let workspace = self
                .workspace_by_storage_id(&storage_id)
                .ok_or(ForkChatError::InstanceNotOpen)?;
            if let Some(stream_id) = admitted.workstream_id.as_deref() {
                match workspace
                    .transfer_engagement_to_workstream(&new_id, stream_id)
                    .map_err(|error| ForkChatError::Continuity(error.to_string()))?
                {
                    gaugedesk_workspace::WorkstreamTransferOutcome::Joined { .. } => {}
                    outcome => {
                        return Err(ForkChatError::Continuity(format!(
                            "fork destination workstream join refused: {outcome:?}"
                        )));
                    }
                }
            }
            new_eng
                .set_target(&admitted.line_ref)
                .map_err(|error| ForkChatError::Continuity(error.to_string()))?;
            workspace
                .engagement_home_receipt(&new_id)
                .map(Some)
                .map_err(|error| ForkChatError::Continuity(error.to_string()))
        })();
        let admitted_home = match topology_admission {
            Ok(home) => home,
            Err(error) => {
                drop(new_eng);
                self.compensate_failed_chat_fork(&storage_id, &new_id, &target_continuity);
                return Err(error);
            }
        };
        let source_events = self
            .store
            .events(id)
            .map_err(|error| ForkChatError::Continuity(format!("{error:?}")))?;
        let through = point
            .as_ref()
            .map(|point| point.entry_id)
            .unwrap_or(i64::MAX);
        let inherited_records = (|| {
            let mut records = Vec::<(String, String, String)>::new();
            for (_, kind, payload) in source_events
                .iter()
                .filter(|(position, kind, _)| *position <= through && kind == "resource")
            {
                records.push((new_id.clone(), kind.clone(), payload.clone()));
            }
            let reads = match &point {
                Some(point) => point.reads.clone(),
                None => crate::resource_store::engagement_reads(&self.store, id)
                    .map_err(|error| ForkChatError::Continuity(format!("{error:?}")))?
                    .items()
                    .iter()
                    .cloned()
                    .collect(),
            };
            for read in reads {
                records.push((new_id.clone(), "read".to_owned(), read));
            }
            if let (Some(snapshot), Some(admitted_home)) =
                (historical_snapshot.as_ref(), admitted_home.as_ref())
            {
                let admission = ChatForkAdmissionRecord {
                    schema: "gaugedesk.chat-fork-admission.v1".to_owned(),
                    source_chat_id: id.to_owned(),
                    source_entry_id: point.as_ref().map(|point| point.entry_id),
                    historical_home: snapshot.historical_home.clone(),
                    requested_destination: destination.clone(),
                    admitted_home: admitted_home.clone(),
                    taint_evidence_digest: point
                        .as_ref()
                        .map(|point| point.taint_evidence_digest.clone())
                        .unwrap_or_else(|| snapshot.after_taint_evidence_digest.clone()),
                    visible_settlements: snapshot.visible_settlements.clone(),
                };
                let payload = serde_json::to_string(&admission)
                    .map_err(|error| ForkChatError::Continuity(error.to_string()))?;
                records.push((new_id.clone(), CHAT_FORK_ADMISSION_KIND.to_owned(), payload));
            }
            let borrowed = records
                .iter()
                .map(|(scope, kind, payload)| (scope.as_str(), kind.as_str(), payload.as_str()))
                .collect::<Vec<_>>();
            self.store
                .append_records_atomically(&borrowed)
                .map_err(|error| ForkChatError::Continuity(format!("{error:?}")))?;
            Ok(())
        })();
        if let Err(error) = inherited_records {
            drop(new_eng);
            self.compensate_failed_chat_fork(&storage_id, &new_id, &target_continuity);
            return Err(error);
        }
        self.register_engagement(new_id.clone(), storage_id.clone(), new_eng);
        let title = format!("{} (fork)", src_chat.title);
        // ADR 0141: the durable log forks by lineage, not by copy. The cut is
        // the inclusive bound on the parent-scope records this child inherits —
        // the resolved point's bound, or the parent's whole log for a tip fork.
        let inherited_cut = point.as_ref().map(|point| point.inherited_cut).unwrap_or(
            source_events
                .iter()
                .map(|(position, _, _)| *position)
                .max()
                .unwrap_or(0),
        );
        let rec = ChatRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: new_id.clone(),
            op: RecordOp::Upsert,
            instance_id: inst_id,
            title: title.clone(),
            created_position: 0,
            forked_from: Some(id.to_string()),
            forked_from_entry: point.as_ref().map(|point| point.entry_id),
            forked_from_cut: Some(inherited_cut),
        };
        let pos = match self.store.append_record(
            LIBRARY_SCOPE,
            "chat",
            &serde_json::to_string(&rec).unwrap(),
        ) {
            Ok(pos) => pos,
            Err(error) => {
                self.compensate_failed_chat_fork(&storage_id, &new_id, &target_continuity);
                return Err(ForkChatError::Continuity(format!("{error:?}")));
            }
        };
        self.library.apply_chat(ChatRecord {
            created_position: pos,
            ..rec
        });
        // Keep the former singular record strictly as a one-member wire/storage
        // compatibility projection.  A multi-target child has no primary.
        if let ([member], Some(basis)) = (members.as_slice(), singular_basis) {
            self.write_chat_target_record(ChatTargetBindingRecord {
                schema: crate::library::LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                chat_id: new_id.clone(),
                op: RecordOp::Upsert,
                target_id: member.target_id.clone(),
                basis,
                path_scope: member.path_scope.clone(),
                capabilities: member.capability_ceiling.clone(),
            });
        }
        if let Err(error) = self.write_chat_target_set_record(ChatTargetSetRevisionRecord {
            chat_id: new_id.clone(),
            revision: 0,
            members,
            created_position: 0,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        }) {
            self.compensate_failed_chat_fork(&storage_id, &new_id, &target_continuity);
            return Err(ForkChatError::Create(error));
        }
        for (target_id, basis) in member_bases {
            if let Err(error) = self.write_chat_target_basis_record(ChatTargetBasisRecord {
                chat_id: new_id.clone(),
                target_id,
                basis,
                schema: LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
            }) {
                self.compensate_failed_chat_fork(&storage_id, &new_id, &target_continuity);
                return Err(ForkChatError::Create(error));
            }
        }
        if let Err(error) = self.refresh_chat_discipline_mount(&new_id) {
            self.compensate_failed_chat_fork(&storage_id, &new_id, &target_continuity);
            return Err(ForkChatError::Create(error));
        }
        self.notify_library_changed("chat", &new_id, "upsert");
        Ok(ForkedChat {
            id: new_id,
            title,
            forked_from: id.to_string(),
            forked_from_entry: point.map(|point| point.entry_id),
            admitted_home,
        })
    }

    /// The chat's **effective-log lineage** (ADR 0141): the (authoring chat,
    /// inclusive position bound) pairs whose records compose this chat's
    /// durable log, root first, ending with the chat itself (unbounded). Walks
    /// [`Library::chat_lineage`], so deleted ancestors still resolve; an edge
    /// without a recorded cut (a pre-ADR-0141 fork) inherits nothing and ends
    /// the walk.
    pub(crate) fn effective_log_lineage(&self, id: &str) -> Vec<(String, Option<i64>)> {
        let mut chain = vec![(id.to_owned(), None)];
        let mut current = id.to_owned();
        while let Some(lineage) = self.library.chat_lineage.get(&current) {
            let (Some(parent), Some(cut)) = (lineage.forked_from.clone(), lineage.forked_from_cut)
            else {
                break;
            };
            // Fork can never record a cycle (a child is always a new id), but a
            // corrupt log must not hang the reader.
            if chain.iter().any(|(scope, _)| scope == &parent) {
                break;
            }
            chain.push((parent.clone(), Some(cut)));
            current = parent;
        }
        chain.reverse();
        chain
    }

    pub(crate) fn delete_chat_cascade(&mut self, id: &str) -> bool {
        if !self.engagement_index.contains_key(id) && !self.library.chats.contains_key(id) {
            return false;
        }
        // Capture the hosting instance before teardown drops the index entry, so we can
        // purge its now-unreachable workspace blobs after the engagement line is gone (SECAUD-6).
        let inst_id = self.engagement_index.get(id).cloned();
        self.destroy_chat(id);
        // ADR 0141: this chat's records may still compose a live descendant's
        // effective log, so crypto-erasure is deferred to the reachability
        // sweep — which erases this scope immediately when nothing inherits
        // from it, and an ancestor's the moment its last descendant goes.
        self.sweep_deferred_crypto_erasure();
        // SECAUD-6: erase the workspace payload too — `destroy_chat` removed
        // the engagement branch, so its unique objects are now unreachable; prune them so the
        // deleted chat's workspace content is unrecoverable, matching the store crypto-erasure.
        // (`purge_unreachable_objects` is itself reachability-based: objects a
        // fork's branch still reaches survive, the workspace half of ADR 0141.)
        if let Some(inst) = inst_id.and_then(|iid| self.targets.get(&iid)) {
            let _ = inst.purge_unreachable_objects();
        }
        true
    }

    /// Destroy the DEK of every deleted chat scope no live chat's effective log
    /// reaches (ADR 0141 refcounted DEK lifetime). Reachability is the
    /// effective-log walk, so an inheritance edge without a recorded cut does
    /// not hold its ancestors' keys. Idempotent — long-erased scopes simply
    /// have no key left to destroy.
    fn sweep_deferred_crypto_erasure(&mut self) {
        let mut reached: std::collections::BTreeSet<String> = Default::default();
        for live in self.library.chats.keys() {
            for (scope, _) in self.effective_log_lineage(live) {
                reached.insert(scope);
            }
        }
        let erasable: Vec<String> = self
            .library
            .chat_lineage
            .keys()
            .filter(|id| !self.library.chats.contains_key(*id) && !reached.contains(*id))
            .cloned()
            .collect();
        for scope in erasable {
            self.crypto_erase_content(&scope);
        }
    }

    pub(crate) fn rename_chat_record(&mut self, id: &str, title: String) -> Option<ChatRecord> {
        let existing = self.library.chats.get(id).cloned()?;
        let updated = ChatRecord { title, ..existing };
        self.write_chat_record(updated.clone());
        Some(updated)
    }

    /// The nav-badge flag for a chat — the **badge** attention surface
    /// (ADR 0082 §3): a signal the operator muted shows no dot either; `queue`
    /// and `badge` both keep it (the task bar is the only thing `badge` drops).
    ///
    /// Conflict is the only one left. The companion `changes` dot went with the
    /// per-change review hold it reported (ADR 0136): a clean candidate now
    /// always settles, so there is no state for that dot to describe.
    fn library_chat_conflicted(
        &self,
        chat_id: &str,
        rules: &crate::attention::AttentionRules,
    ) -> bool {
        use crate::attention::{Attention, Signal};
        if !self.engagement_index.contains_key(chat_id) {
            return false;
        }
        let merge = self
            .store_ref()
            .fold::<MergeState>(chat_id)
            .unwrap_or_default();
        ((merge.phase == gaugedesk_core::merge::MergePhase::Rejected
            && merge.workspace_outcome == gaugedesk_core::merge::WorkspaceOutcome::Conflict)
            || merge.phase == gaugedesk_core::merge::MergePhase::Repairing)
            && rules.attention(Signal::Conflict) != Attention::Mute
    }

    /// Whether moving this chat would discard or transplant workspace state. This is
    /// derived from the provider's actual chat→target diff rather than a UI lifecycle
    /// hint, so manual file edits and interrupted turns fail closed too.
    fn library_chat_rehome_blocked(&self, chat_id: &str) -> bool {
        self.engagement_rehome_blocked(chat_id)
    }

    fn library_chat_json(
        &self,
        chat: &ChatRecord,
        chat_ws: &std::collections::BTreeMap<String, String>,
        rules: &crate::attention::AttentionRules,
    ) -> serde_json::Value {
        let kind = self
            .library
            .instances
            .get(&chat.instance_id)
            .map(|instance| instance.kind.chat_kind())
            .unwrap_or("work");
        let conflict = self.library_chat_conflicted(&chat.id, rules);
        let rehome_blocked = self.library_chat_rehome_blocked(&chat.id);
        let binding = self.library.chat_targets.get(&chat.id);
        let current_set = self.library.current_target_set(&chat.id);
        let (target_set_revision, target_set_members) = match (current_set, binding) {
            (Some(set), _) => (set.revision, set.members.clone()),
            (None, Some(binding)) => {
                let target = self
                    .library
                    .work_targets
                    .get(&binding.target_id)
                    .expect("validated chat binding names a target");
                (
                    0,
                    vec![ChatTargetSetMemberRecord {
                        target_id: binding.target_id.clone(),
                        adapter_family: target.adapter_family.clone(),
                        path_scope: binding.path_scope.clone(),
                        capability_ceiling: binding.capabilities.clone(),
                        participation: if binding.capabilities.propose {
                            TargetParticipationMode::Writable
                        } else {
                            TargetParticipationMode::ReadOnly
                        },
                    }],
                )
            }
            (None, None) => panic!("validated chat has a target set"),
        };
        let singular = (target_set_members.len() == 1).then(|| {
            self.library
                .work_targets
                .get(&target_set_members[0].target_id)
                .expect("validated target-set member names a target")
        });
        let collaboration_workspace_id = self
            .library
            .project_of_chat(&chat.id)
            .and_then(|project_id| {
                self.library
                    .project_collaboration_workspaces
                    .get(project_id)
            })
            .map(|workspace| workspace.workspace_id.clone());
        let workspace_root = collaboration_workspace_id.clone().unwrap_or_else(|| {
            let target = singular.expect("edit chat has one target");
            format!(
                "{}::{}::{}",
                chat.instance_id, target.id, target.adapter_family
            )
        });
        let candidate_revision = self
            .engagements
            .get(&chat.id)
            .and_then(|engagement| engagement.current_cut().ok())
            .flatten()
            .or_else(|| binding.map(|binding| binding.basis.clone()))
            .unwrap_or_default();
        let available_acts = self.available_target_acts(&chat.id);
        let target_members = target_set_members
            .iter()
            .map(|member| {
                let member_target = self
                    .library
                    .work_targets
                    .get(&member.target_id)
                    .expect("validated target-set member names a target");
                let basis = self
                    .library
                    .chat_target_basis(&chat.id, &member.target_id)
                    .map(str::to_owned)
                    .or_else(|| {
                        binding
                            .filter(|binding| member.target_id == binding.target_id)
                            .map(|binding| binding.basis.clone())
                            .or_else(|| member_target.current_basis.clone())
                    })
                    .unwrap_or_default();
                serde_json::json!({
                    "target_id": member.target_id,
                    "root": format!(
                        "targets/{}",
                        crate::library::target_id_path_v1(&member.target_id)
                            .expect("validated stable target id has a path encoding")
                    ),
                    "name": member_target.name,
                    "kind": member_target.kind,
                    "adapter": member_target.adapter,
                    "adapter_family": member.adapter_family,
                    "basis": basis,
                    "path_scope": member.path_scope,
                    "capability_ceiling": member.capability_ceiling,
                    "participation": member.participation,
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "id": chat.id,
            "title": chat.title,
            "kind": kind,
            "forked_from": chat.forked_from,
            "placement": chat.instance_id,
            "workspace_root": workspace_root,
            "target_id": singular.map(|target| target.id.clone()),
            "target_basis": binding.map(|binding| binding.basis.clone()),
            "target_kind": singular.map(|target| target.kind),
            "target_adapter": singular.map(|target| target.adapter.clone()),
            "target_path_scope": binding.map(|binding| binding.path_scope.clone()),
            "target_capabilities": binding.map(|binding| binding.capabilities.clone()),
            "candidate_revision": candidate_revision,
            "available_acts": available_acts,
            "target_set_revision": target_set_revision,
            "targets": target_members,
            "collaboration_workspace_id": collaboration_workspace_id,
            "workstream": chat_ws.get(&chat.id),
            "conflict": conflict,
            "rehome_blocked": rehome_blocked,
        })
    }

    pub(crate) fn work_target_json(target: &WorkTargetRecord) -> serde_json::Value {
        let (owner_kind, owner_id) = match &target.owner {
            WorkTargetOwner::Project { project_id } => ("project", project_id.as_str()),
            WorkTargetOwner::Archetype { archetype_id } => ("archetype", archetype_id.as_str()),
        };
        let concurrency = match target.kind {
            WorkTargetKind::Managed => "serialized",
            WorkTargetKind::ExternalVcs => "native-vcs",
            WorkTargetKind::ExternalFolder => "compare-before-write-weak",
        };
        serde_json::json!({
            "id": target.id,
            "name": target.name,
            "owner_kind": owner_kind,
            "owner_id": owner_id,
            "authority": target.authority,
            "parties": target.parties,
            "kind": target.kind,
            "adapter": target.adapter,
            "adapter_family": target.adapter_family,
            "vcs_posture": target.vcs_posture,
            "current_basis": target.current_basis,
            "path_scope": target.path_scope,
            "capabilities": target.capabilities,
            "status": target.status,
            "concurrency": concurrency,
        })
    }

    pub(crate) fn workspace_value(&self) -> serde_json::Value {
        let lib = &self.library;
        // The operator's attention rules (ATTN-2) gate the badge flags below —
        // parsed once per projection read, shared by every chat row.
        let rules = crate::attention::AttentionRules::parse(
            self.account_settings()
                .ok()
                .and_then(|s| s.get(crate::attention::ATTENTION_RULES_SETTING).cloned())
                .as_deref(),
        );
        let mut chat_ws: std::collections::BTreeMap<String, String> = Default::default();
        for workstream in lib.workstreams.values() {
            if let Some(root) = lib
                .workstream_roots
                .get(&workstream.id)
                .filter(|root| !root.project_id.is_empty())
            {
                let active = self
                    .workspace_by_storage_id(&root.workspace_id)
                    .and_then(|workspace| workspace.workstream(&workstream.id).ok().flatten())
                    .is_some_and(|row| {
                        row.status == whipplescript_store::workstreams::StreamStatus::Active
                    });
                if active {
                    for member in self.workstream_members(&workstream.id) {
                        chat_ws.insert(member, workstream.id.clone());
                    }
                }
                continue;
            }
            if let Ok(state) = self.store_ref().fold::<WorkstreamState>(&workstream.id) {
                if state.phase != WorkstreamPhase::Active {
                    continue;
                }
                for member in state.members {
                    chat_ws.insert(member, workstream.id.clone());
                }
            }
        }

        let archetypes: Vec<_> = lib
            .agents
            .values()
            .map(|agent| {
                serde_json::json!({
                    "id": agent.id,
                    "name": agent.name,
                    "kind": agent.agent_kind,
                    // Library Preview exercises the mutable draft contract. A
                    // project placement below projects its pinned version
                    // instead, so deployment never follows draft edits.
                    "panel_profile": agent.panel_profile,
                    "instance_id": agent.instance_id,
                    "authoring_target_id": lib.authoring_target_for(&agent.id).expect("validated archetype has an authoring target").id,
                    "is_default": agent.id == DEFAULT_AGENT,
                    "forked_from": agent.forked_from,
                    "forked_from_name": agent.forked_from.as_ref().and_then(|src| lib.agents.get(src).map(|source| source.name.clone())),
                    "chats": lib.chats_in(&agent.instance_id).iter().map(|chat| self.library_chat_json(chat, &chat_ws, &rules)).collect::<Vec<_>>(),
                    "workstreams": self.library_workstreams_in(&agent.instance_id).iter().map(|workstream| crate::workstream_routes::workstream_json(self, workstream)).collect::<Vec<_>>(),
                })
            })
            .collect();

        let mut projects: Vec<_> = lib
            .projects
            .values()
            .filter(|project| project.home_id == self.home_id)
            .map(|project| {
                let placements: Vec<_> = lib
                    .using_instances_of(&project.id)
                    .iter()
                    .map(|instance| {
                        let archetype_name = lib
                            .agents
                            .get(&instance.agent_id)
                            .map(|agent| agent.name.clone())
                            .unwrap_or_default();
                        let inst_state = self.store_ref().fold::<InstanceState>(&instance.id).ok();
                        let pinned_version = inst_state
                            .as_ref()
                            .and_then(|state| state.pinned_version.clone());
                        let has_config = inst_state
                            .as_ref()
                            .map(|state| {
                                state
                                    .local_config
                                    .as_deref()
                                    .map(|config| !config.trim().is_empty())
                                    .unwrap_or(false)
                                    || state
                                        .notes
                                        .as_deref()
                                        .map(|notes| !notes.trim().is_empty())
                                        .unwrap_or(false)
                            })
                            .unwrap_or(false);
                        let current_version = lib
                            .agents
                            .get(&instance.agent_id)
                            .map(|agent| agent.current_version)
                            .unwrap_or(instance.version);
                        serde_json::json!({
                            "placement_id": instance.id,
                            "kind": instance.placement_kind,
                            "archetype_id": instance.agent_id,
                            "archetype_name": archetype_name,
                            "is_default": instance.id == library_routes::general_placement_id(&project.id),
                            "has_config": has_config,
                            "pinned_version": pinned_version,
                            "version": instance.version,
                            "current_version": current_version,
                            "panel_profile": lib.agents.get(&instance.agent_id).and_then(|agent| agent.versions.get(&instance.version)).and_then(|version| version.panel_profile.clone()),
                            "upgrade_available": lib.upgrade_available(&instance.id),
                            // APPROVE-1 (ADR 0064): a pending placement is approved-but-not-yet-accepted
                            // under an approval-required policy — the nav flags it so the owner can accept.
                            "pending": instance.admission == Admission::Pending,
                            "deployments": lib.public_deployments.values().filter(|binding| binding.placement_id == instance.id).map(|binding| serde_json::json!({
                                "id": binding.id,
                                "deployment_id": binding.hosted_deployment_id,
                                "edge_origin": binding.edge_origin,
                                "active_release_id": binding.active_release_id,
                                "status": binding.status,
                            })).collect::<Vec<_>>(),
                            "target_ids": lib.placement_targets.get(&instance.id).map(|targets| targets.target_ids.clone()).unwrap_or_default(),
                            "chats": lib.chats_in(&instance.id).iter().map(|chat| self.library_chat_json(chat, &chat_ws, &rules)).collect::<Vec<_>>(),
                            "workstreams": self.library_workstreams_in(&instance.id).iter().map(|workstream| crate::workstream_routes::workstream_json(self, workstream)).collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                serde_json::json!({
                    "id": project.id,
                    "name": project.name,
                    "is_personal": project.is_default,
                    "home_id": project.home_id.as_str(),
                    "network_isolated": project.network_isolated,
                    "targets": lib.targets_for_project(&project.id).into_iter().map(Self::work_target_json).collect::<Vec<_>>(),
                    "placements": placements,
                })
            })
            .collect();
        projects.sort_by_key(|project| {
            !project
                .get("is_personal")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        });

        let mut recent: Vec<&ChatRecord> = lib.chats.values().collect();
        recent.retain(|chat| {
            lib.project_of_chat(&chat.id)
                .is_none_or(|project| self.owns_project(project))
        });
        recent.sort_by_key(|chat| std::cmp::Reverse(chat.created_position));
        let recent: Vec<_> = recent
            .into_iter()
            .map(|chat| {
                let inst = lib.instances.get(&chat.instance_id);
                let archetype_name = inst
                    .and_then(|instance| lib.agents.get(&instance.agent_id))
                    .map(|agent| agent.name.clone())
                    .unwrap_or_default();
                let mut projected = self.library_chat_json(chat, &chat_ws, &rules);
                projected
                    .as_object_mut()
                    .expect("chat projections are objects")
                    .insert(
                        "archetype".to_owned(),
                        serde_json::Value::String(archetype_name),
                    );
                projected
            })
            .collect();

        let workstreams: Vec<_> = lib
            .workstreams
            .values()
            .map(|workstream| crate::workstream_routes::workstream_json(self, workstream))
            .collect();

        serde_json::json!({
            "archetypes": archetypes,
            "projects": projects,
            "recent": recent,
            "workstreams": workstreams,
            "work_targets": lib.work_targets.values().map(Self::work_target_json).collect::<Vec<_>>(),
            "personal_placement": DEFAULT_PLACEMENT,
        })
    }

    /// SEARCH-2 file-content walk bounds. A per-query worktree walk (NOT a persistent
    /// file index): the WhippleScript workspace swap (v0.5.0) brings the proper indexing
    /// primitive, so an index now would be throwaway migration — a bounded walk is correct
    /// at current scale (the SCALE-* items are deferred as "fine at current scale"). These
    /// caps keep the walk from being "materially heavier" than folding the chat log:
    /// at most `FILE_SEARCH_MAX_FILES` files per chat, `FILE_SEARCH_MAX_BYTES` read per file.
    pub(crate) const FILE_SEARCH_MAX_FILES: usize = 500;
    pub(crate) const FILE_SEARCH_MAX_BYTES: usize = 256 * 1024;

    /// The full content-search projection (`navigation.md` "Search scope and relevance"):
    /// the **chat-log** tier (tier 2, SEARCH-1) followed by the **file-content** tier
    /// (tier 3, SEARCH-2), each hit carrying its `tier` so the nav preserves title > log >
    /// file ordering. Both tiers are server projections (`INV-5`, projection-first): the
    /// client never folds transcripts nor walks worktrees. A chat that already matched in
    /// the log tier is not repeated as a file hit — the stronger (log) tier wins per chat.
    pub(crate) fn search_value(&self, query: &str) -> serde_json::Value {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return serde_json::json!({ "hits": [] });
        }
        let mut chats: Vec<&ChatRecord> = self.library.chats.values().collect();
        chats.sort_by_key(|chat| std::cmp::Reverse(chat.created_position));

        // Tier 2 — chat log: fold each chat's *effective* transcript (its own
        // records plus the inherited lineage prefix, ADR 0141) and
        // substring-match — a fork is findable by the history it carries.
        let mut hits = Vec::new();
        let mut logged: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for chat in &chats {
            let mut hay = String::new();
            for (scope, bound) in self.effective_log_lineage(&chat.id) {
                let Ok(events) = self.store_ref().events(&scope) else {
                    continue;
                };
                let bound = bound.unwrap_or(i64::MAX);
                for (_, _, row) in events
                    .iter()
                    .filter(|(position, kind, _)| *position <= bound && kind == "transcript")
                {
                    let Ok(value) = serde_json::from_str::<serde_json::Value>(row) else {
                        continue;
                    };
                    for key in ["text", "delta"] {
                        if let Some(text) = value.get(key).and_then(|item| item.as_str()) {
                            hay.push_str(text);
                            hay.push('\n');
                        }
                    }
                }
            }
            if let Some(index) = hay.to_lowercase().find(&needle) {
                logged.insert(chat.id.as_str());
                hits.push(serde_json::json!({
                    "id": chat.id,
                    "title": chat.title,
                    "snippet": Self::snippet_around(&hay, index, needle.len()),
                    "tier": "log",
                }));
            }
        }

        // Tier 3 — file content: a bounded walk of each chat's worktree (SEARCH-2),
        // ranked after the log tier. Chats that already matched in the log are skipped
        // so each surfaces once via its strongest tier.
        for chat in &chats {
            if logged.contains(chat.id.as_str()) {
                continue;
            }
            if let Some(hit) = self.search_engagement_files(chat, &needle) {
                hits.push(hit);
            }
        }
        serde_json::json!({ "hits": hits })
    }

    /// SEARCH-2 tier-3 walk for one chat: enumerate its live worktree (relative paths,
    /// provider metadata already skipped by [`ChatWorkspace::tree`]) and case-insensitively match the
    /// first file whose content contains `needle`, returning its path + a one-line snippet.
    /// Bounded per [`FILE_SEARCH_MAX_FILES`](Self::FILE_SEARCH_MAX_FILES) /
    /// [`FILE_SEARCH_MAX_BYTES`](Self::FILE_SEARCH_MAX_BYTES); binary files are skipped
    /// (null-byte sniff in `read_file_capped`). All reads go through the workspace's
    /// path-confined API, so the walk can never read outside the chat's worktree.
    fn search_engagement_files(
        &self,
        chat: &ChatRecord,
        needle: &str,
    ) -> Option<serde_json::Value> {
        let eng = self.engagements.get(&chat.id)?;
        let entries = eng.tree().ok()?;
        let mut scanned = 0usize;
        for entry in entries {
            if entry.is_dir {
                continue;
            }
            if scanned >= Self::FILE_SEARCH_MAX_FILES {
                break;
            }
            scanned += 1;
            let Ok(Some(text)) = eng.read_file_capped(&entry.path, Self::FILE_SEARCH_MAX_BYTES)
            else {
                continue;
            };
            if let Some(index) = text.to_lowercase().find(needle) {
                let snippet = Self::snippet_around(&text, index, needle.len());
                return Some(serde_json::json!({
                    "id": chat.id,
                    "title": chat.title,
                    "path": entry.path,
                    // The nav renders one snippet per hit (id → snippet); lead a file
                    // snippet with its path so the row shows which file matched.
                    "snippet": format!("{}: {}", entry.path, snippet),
                    "tier": "file",
                }));
            }
        }
        None
    }

    fn snippet_around(text: &str, match_byte: usize, match_len: usize) -> String {
        const PAD: usize = 48;
        let clamp_down = |mut index: usize| {
            while index > 0 && !text.is_char_boundary(index) {
                index -= 1;
            }
            index
        };
        let clamp_up = |mut index: usize| {
            let len = text.len();
            while index < len && !text.is_char_boundary(index) {
                index += 1;
            }
            index.min(len)
        };
        let start = clamp_down(match_byte.saturating_sub(PAD));
        let end = clamp_up((match_byte + match_len + PAD).min(text.len()));
        let mut snippet = String::new();
        if start > 0 {
            snippet.push('…');
        }
        snippet.push_str(text[start..end].trim());
        if end < text.len() {
            snippet.push('…');
        }
        snippet.replace('\n', " ")
    }

    /// The unified task-bar projection (ADR 0075 §3/§5): onboarding checklist
    /// `issue` tasks from the account-global whip tracker, followed by the
    /// existing clean-merge `review` tasks. It owns no truth — it joins the whip
    /// issue (content) with its admitted assignment. Every tracker task carries
    /// its boundary because an item id is only meaningful inside that tracker;
    /// the client must send both back when it assigns the item.
    pub(crate) fn task_queue_value(&self) -> serde_json::Value {
        // The acting authority remains the default assignee for chat-derived
        // tasks below. Tracker issues instead project their durable assignment;
        // unassigned is a meaningful "whoever has access" state (GATE-3f).
        let assignee = self.authority.as_str();

        // Chats with an unanswered agent question (ADR 0113). The question is a
        // GaugeDesk record in the chat's own scope, so this is read per chat
        // below rather than from one tracker query.

        // Onboarding issues first — the active first-run guidance. `list_items`
        // returns them in filing order (WS-1, WS-2, …), which is checklist order.
        let mut tasks: Vec<serde_json::Value> = Vec::new();
        if let Some(tracker) = self
            .tracker_runtimes
            .get(crate::workbench_state::ACCOUNT_GLOBAL_BOUNDARY)
        {
            match tracker.list_items(Some(crate::onboarding::ONBOARDING_QUEUE), Some("open")) {
                Ok(items) => {
                    for item in items {
                        tasks.push(serde_json::json!({
                            "id": item.id,
                            "title": item.title,
                            "agent": "",
                            "kind": "issue",
                            "assignee": item.assigned_to,
                            "boundary": crate::workbench_state::ACCOUNT_GLOBAL_BOUNDARY,
                        }));
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "task queue: could not list onboarding items");
                }
            }
        }

        // Inbound items waiting on a person (ADR 0110 §7, ADR 0117 §5). Project-
        // scoped, which makes this the first task source that is not a chat's
        // own signal — the count belongs to the project, and the chat it names
        // is only where a reviewer goes to look.
        //
        // The count is the gate's parked questions, not every `Pending`
        // quarantine row: an item still being screened awaits the *gate*, and
        // showing it as work for a person would ask them to do something they
        // cannot yet do. General across inbound sources by construction — it
        // counts what the gate parked, never where the material came from.
        for project in self.library.projects.values() {
            if project.home_id != self.home_id {
                continue;
            }
            let state_dir = crate::gate_service::gate_state_dir(&self.root_path(), &project.id);
            let waiting =
                match gaugedesk_whip_runtime::gate_runner::reviews_awaiting_a_person(&state_dir) {
                    Ok(waiting) => waiting,
                    Err(error) => {
                        tracing::warn!(
                            project = %project.id,
                            error = %error,
                            "task queue: could not read the project's parked reviews",
                        );
                        continue;
                    }
                };
            if waiting == 0 {
                continue;
            }
            // The door needs somewhere to open. A project with no chat has
            // nowhere to show the index, so the count waits rather than
            // rendering a pill that goes nowhere.
            let Some(chat) = self
                .library
                .project_chats(&project.id)
                .first()
                .map(|c| c.id.clone())
            else {
                continue;
            };
            tasks.push(serde_json::json!({
                "id": chat,
                "title": project.name,
                "agent": "",
                "kind": "screen",
                "assignee": assignee,
                "project": project.id,
                "waiting": waiting,
            }));
        }

        // Ask-typed chat tasks (ADR 0082 §2–3), current-first. Each chat raises
        // its signals from durable lifecycle state (the projection owns no
        // truth) and contributes at most one task: the highest-priority raised
        // signal whose attention — under the operator's rules (ATTN-2) — is
        // `Queue`. A muted/badged signal falls through to the next, so muting
        // reviews does not silence an opted-in `reply` ping.
        let rules = crate::attention::AttentionRules::parse(
            self.account_settings()
                .ok()
                .and_then(|s| s.get(crate::attention::ATTENTION_RULES_SETTING).cloned())
                .as_deref(),
        );
        let mut chat_tasks: Vec<(i64, serde_json::Value)> = Vec::new();
        for chat in self.library.chats.values() {
            if !self.engagement_index.contains_key(&chat.id) {
                continue;
            }
            let run_phase = self
                .store
                .fold::<RunState>(&chat.id)
                .map(|run| run.phase)
                .ok();
            let merge = self.store.fold::<MergeState>(&chat.id).ok();
            // ATTN-1: settle-time facts are appended by the engine while it
            // owns the workspace/runtime context. This projection only folds
            // the newest record. `run_phase` remains the compatibility source
            // for pre-ATTN-1 stores and the lifecycle-owned merge signals.
            let turn_summary = crate::turn_summary::latest(&self.store, &chat.id)
                .ok()
                .flatten();
            let raised = |signal: crate::attention::Signal| -> bool {
                use crate::attention::Signal;
                match signal {
                    // ADR 0111: an agent's question is a tracker item, not a
                    // parked run phase. The chat raises `question` while it has
                    // an unanswered one.
                    Signal::Question => {
                        !crate::agent_question::open_questions(&self.store, &chat.id)
                            .unwrap_or_default()
                            .is_empty()
                    }
                    Signal::Conflict => matches!(&merge, Some(m)
                        if m.phase == gaugedesk_core::merge::MergePhase::Rejected
                            && m.workspace_outcome
                                == gaugedesk_core::merge::WorkspaceOutcome::Conflict),
                    // A newer attempt appends a newer summary, so reply clears
                    // by construction when the human speaks/runs again.
                    Signal::TurnSettled => {
                        turn_summary.as_ref().is_some_and(|summary| {
                            matches!(
                                summary.receipt_status,
                                crate::turn_summary::ReceiptStatus::Completed
                                    | crate::turn_summary::ReceiptStatus::Failed
                            )
                        }) || (turn_summary.is_none()
                            && run_phase == Some(gaugedesk_core::run::RunPhase::Completed))
                    }
                }
            };
            let raised_signal = crate::attention::Signal::ALL.into_iter().find(|&signal| {
                raised(signal) && rules.attention(signal) == crate::attention::Attention::Queue
            });
            let Some(raised_signal) = raised_signal else {
                continue;
            };
            let ask = raised_signal.ask();
            // ADR 0113 §3: the agent declared it cannot usefully proceed. This drives a
            // stronger presentation and suppresses *automatic* continuation — it is
            // never a lock on the person's own chat, who may always type.
            let blocking = raised_signal == crate::attention::Signal::Question
                && crate::agent_question::is_blocked(&self.store, &chat.id);
            let agent = self
                .library
                .instances
                .get(&chat.instance_id)
                .and_then(|instance| self.library.agents.get(&instance.agent_id))
                .map(|agent| agent.name.clone())
                .unwrap_or_default();
            chat_tasks.push((
                chat.created_position,
                serde_json::json!({
                    "id": chat.id,
                    "title": chat.title,
                    "agent": agent,
                    "kind": ask,
                    "assignee": assignee,
                    "blocking": blocking,
                }),
            ));
        }
        chat_tasks.sort_by_key(|(position, _)| std::cmp::Reverse(*position));
        tasks.extend(chat_tasks.into_iter().map(|(_, task)| task));

        serde_json::json!({ "tasks": tasks })
    }

    fn pairing_status_json(state: &BoundaryState) -> serde_json::Value {
        let bound = state.device_binding.as_ref().map(|(device, grant)| {
            serde_json::json!({ "device": device.as_str(), "bridge_grant": grant.as_str() })
        });
        serde_json::json!({
            "phase": format!("{:?}", state.phase),
            "bound": bound,
            "paired": state.active(),
            "ceiling": library::BoundaryProjection::from_state(state),
        })
    }

    pub(crate) fn create_pairing_request(
        &mut self,
        device: String,
        bridge_grant: Option<String>,
    ) -> Result<CreatedPairingRequest, AdmitError> {
        let pairing_id = library::gen_id("pairing");
        let device = DeviceId::new(device);
        let grant = BridgeGrantId::new(bridge_grant.unwrap_or_else(|| library::gen_id("grant")));
        let required = std::collections::BTreeSet::from([self.authority().as_str().to_string()]);
        self.store_mut()
            .admit::<BoundaryState>(&pairing_id, BoundaryCommand::Propose(required))?;
        self.store_mut().admit::<BoundaryState>(
            &pairing_id,
            BoundaryCommand::DeclareCeiling(Placement {
                operator: Operator::Local,
                attested: false,
            }),
        )?;
        let state = self.store_mut().admit::<BoundaryState>(
            &pairing_id,
            BoundaryCommand::BindDevice {
                device: device.clone(),
                bridge_grant: grant.clone(),
            },
        )?;
        Ok(CreatedPairingRequest {
            pairing_id,
            device: device.as_str().to_string(),
            bridge_grant: grant.as_str().to_string(),
            status: Self::pairing_status_json(&state),
        })
    }

    pub(crate) fn pairing_status_value(
        &self,
        pairing_id: &str,
    ) -> Result<Option<serde_json::Value>, AdmitError> {
        let state = self.store_ref().fold::<BoundaryState>(pairing_id)?;
        if state.phase == BoundaryPhase::Init {
            return Ok(None);
        }
        Ok(Some(Self::pairing_status_json(&state)))
    }

    fn boundary_accept_value(
        state: &BoundaryState,
        participant: &str,
        released: Option<bool>,
    ) -> serde_json::Value {
        let mut out = serde_json::json!({
            "accepted": state.accepted.contains(participant),
            "active": state.active(),
            "ceiling": library::BoundaryProjection::from_state(state),
        });
        if let Some(released) = released {
            out["released"] = serde_json::json!(released);
        }
        out
    }

    pub(crate) fn accept_boundary(
        &mut self,
        boundary_id: &str,
        participant: String,
        attestation: Option<BoundaryAttestationInput>,
    ) -> Result<serde_json::Value, BoundaryAcceptError> {
        let placement_policy = crate::org::Org::rebuild(self.store_ref())
            .map_err(BoundaryAcceptError::Store)?
            .effective_placement_policy();
        if placement_policy != PlacementPolicy::open()
            && !crate::boundary_keeper::pairing_policy_admits(
                self.store_ref(),
                boundary_id,
                &placement_policy,
                attestation.is_some(),
            )
        {
            return Err(BoundaryAcceptError::PolicyRejected);
        }

        let (state, released) = match attestation {
            None => {
                let state = self
                    .store_mut()
                    .admit::<BoundaryState>(
                        boundary_id,
                        BoundaryCommand::Accept {
                            participant: participant.clone(),
                            evidence: None,
                        },
                    )
                    .map_err(|error| match error {
                        AdmitError::Rejected(rejection) => {
                            BoundaryAcceptError::Rejected(rejection.reason.to_string())
                        }
                        other => BoundaryAcceptError::Store(other),
                    })?;
                (state, None)
            }
            Some(att) => {
                let measurement = CodeMeasurement::new(att.measurement);
                let quote = AttestationQuote::new(measurement, att.nonce.clone(), att.quote_bytes);
                let expected =
                    match crate::challenge::current(self.store_ref(), boundary_id, &participant) {
                        Ok(Some(issued)) => issued,
                        Ok(None) => att.expected_nonce.unwrap_or(att.nonce),
                        Err(error) => return Err(BoundaryAcceptError::Store(error)),
                    };
                let allow_list = self.measurements.allow_list();
                let verifier: Box<dyn QuoteVerifier> = match self.attestation_mode() {
                    AttestationMode::Loopback => Box::new(LoopbackVerifier::new(allow_list)),
                    AttestationMode::RealRequired => {
                        if att.vcek.is_empty() {
                            return Err(BoundaryAcceptError::MissingVcek);
                        }
                        match self.real_quote_verifier(&att.vcek, allow_list) {
                            Ok(verifier) => verifier,
                            Err(RealQuoteVerifierError::Unavailable) => {
                                return Err(BoundaryAcceptError::RealVerifierUnavailable)
                            }
                            Err(RealQuoteVerifierError::InvalidEndorsement(reason)) => {
                                return Err(BoundaryAcceptError::InvalidEndorsement(reason))
                            }
                        }
                    }
                };
                let entitlement =
                    crate::package_flow::attested_run_verdict(self.store_ref(), boundary_id)
                        .map_err(BoundaryAcceptError::Store)?;
                let (store, sealed_keys) = self.store_mut_and_sealed_keys();
                let out = accept_boundary_attested(
                    store,
                    boundary_id,
                    &participant,
                    quote,
                    &expected,
                    &*verifier,
                    sealed_keys,
                    entitlement,
                    att.sealed_key_id.as_deref(),
                )
                .map_err(|error| match error {
                    AcceptError::QuoteRejected(reason) => {
                        BoundaryAcceptError::QuoteRejected(format!("{reason:?}"))
                    }
                    AcceptError::Boundary(rejection) => {
                        BoundaryAcceptError::Rejected(rejection.reason.to_string())
                    }
                    AcceptError::Store(error) => BoundaryAcceptError::Store(error),
                })?;
                if let Some(evidence) = out.state.attestation_evidence.get(&participant).cloned() {
                    let _ = crate::resource_store::release_sealed_keys(
                        store,
                        boundary_id,
                        boundary_id,
                        &participant,
                        &evidence,
                        entitlement,
                        sealed_keys,
                    );
                }
                (
                    out.state,
                    out.release.map(|decision| decision.is_released()),
                )
            }
        };

        Ok(Self::boundary_accept_value(&state, &participant, released))
    }
}

#[cfg(test)]
mod agent_config_merge_tests {
    /// DR-0054 Phase A: a corrupt stored config is an error, never `{}` — the
    /// old coercion let the emptied merge be read back and re-persisted,
    /// permanently destroying a recoverable value.
    #[test]
    fn an_unparseable_config_side_is_an_error_not_empty() {
        assert!(super::Workbench::merge_agent_config("{not json", "{}").is_err());
        assert!(super::Workbench::merge_agent_config("{}", "{not json").is_err());
        assert_eq!(
            super::Workbench::merge_agent_config(r#"{"model":"a"}"#, r#"{"model":"b"}"#)
                .expect("clean merge"),
            r#"{"model":"b"}"#
        );
    }
}

#[cfg(test)]
mod startup_reconcile_tests {
    use super::*;
    use crate::workbench_state::default_workspace_providers;

    fn managed_library_with_target(target_id: &str) -> crate::library::Library {
        let mut library = crate::library::Library::default();
        library.apply_work_target(managed_target_record(
            target_id.to_owned(),
            "reconcile fixture".to_owned(),
            WorkTargetOwner::Project {
                project_id: "proj-fixture".to_owned(),
            },
            &gaugedesk_core::ids::HomeId::new("home:fixture"),
            String::new(),
        ));
        library
    }

    /// DR-0054 Phase A: a missing binding is not evidence of deletion — it can
    /// be a failed append or a downgrade. The engagement branch must survive
    /// startup reconciliation (skipped, not discarded).
    #[test]
    fn an_engagement_with_no_library_binding_survives_startup_reconciliation() {
        let targets_dir = tempfile::tempdir().expect("targets dir");
        let providers = default_workspace_providers();
        let library = managed_library_with_target("target-x");

        let workspace =
            provider_for(&providers, "target-x").open_at(&targets_dir.path().join("target-x"));
        let chat = workspace
            .create_engagement("chat-unbound")
            .expect("engagement");
        chat.write_file("draft.txt", "working branch bytes")
            .expect("write");
        chat.commit_turn("draft").expect("cut");
        drop(chat);
        drop(workspace);

        let (targets, engagements, _index) =
            open_startup_targets(&library, targets_dir.path(), &providers, &BTreeSet::new())
                .expect("startup targets");

        assert!(
            !engagements.contains_key("chat-unbound"),
            "an unbound engagement is not registered live"
        );
        let survivors = targets
            .get("target-x")
            .expect("target opened")
            .reconcile_engagements()
            .expect("reconcile");
        let survivor = survivors
            .iter()
            .find(|(id, _)| id == "chat-unbound")
            .map(|(_, eng)| eng)
            .expect("the working branch was not discarded");
        assert_eq!(
            survivor.read_file("draft.txt").expect("branch content"),
            "working branch bytes"
        );
    }

    /// The one legitimate removal: the library's record stream shows the chat
    /// was explicitly deleted (a tombstone), so reconciliation finishes it.
    #[test]
    fn a_tombstoned_chats_engagement_is_removed_at_startup() {
        let targets_dir = tempfile::tempdir().expect("targets dir");
        let providers = default_workspace_providers();
        let library = managed_library_with_target("target-x");

        let workspace =
            provider_for(&providers, "target-x").open_at(&targets_dir.path().join("target-x"));
        workspace
            .create_engagement("chat-deleted")
            .expect("engagement");
        drop(workspace);

        let deleted = BTreeSet::from(["chat-deleted".to_owned()]);
        let (targets, engagements, _index) =
            open_startup_targets(&library, targets_dir.path(), &providers, &deleted)
                .expect("startup targets");

        assert!(!engagements.contains_key("chat-deleted"));
        assert!(
            targets
                .get("target-x")
                .expect("target opened")
                .reconcile_engagements()
                .expect("reconcile")
                .iter()
                .all(|(id, _)| id != "chat-deleted"),
            "an explicitly deleted chat's branch is released"
        );
    }
}
