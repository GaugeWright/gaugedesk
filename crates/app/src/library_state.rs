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
    Admission, AgentRecord, ArchetypeVersionRecord, ChatRecord, ChatTargetBindingRecord,
    InstanceKind, InstanceRecord, PlacementTargetsRecord, ProjectRecord, RecordOp,
    TargetCapabilities, TargetVcsPosture, WorkTargetKind, WorkTargetOwner, WorkTargetRecord,
    WorkTargetStatus, WorkstreamRecord, WorkstreamRootRecord, LIBRARY_SCOPE,
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
    })
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
}

pub(crate) enum ForkChatError {
    NotFound,
    SourceNotLive,
    InstanceNotOpen,
    Create(String),
    Continuity(String),
    PointNotForkable,
}

struct ResolvedForkPoint {
    entry_id: i64,
    workspace_cut: String,
    runtime_position: gaugedesk_harness::RuntimePosition,
    reads: Vec<String>,
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
    validate_target_cutover(&library)?;
    if migrate_agent_ability_manifests(store, &library, targets_dir, providers)? {
        library = crate::library::Library::rebuild(store).map_err(io)?;
    }
    validate_archetype_versions(&library, targets_dir)?;
    let deleted_chats = explicitly_deleted_chats(store)?;
    let (targets, mut engagements, engagement_index) =
        open_startup_targets(&library, targets_dir, providers, &deleted_chats)?;
    for engagement in engagements.values_mut() {
        let _ = engagement.sync_from_main();
    }
    Ok(StartupLibraryState {
        library,
        targets,
        engagements,
        engagement_index,
    })
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
            let resolved = published_archetype_version(targets_dir, &target.id, *version)?;
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

fn invalid_data(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

/// TARGET-1 rejects every pre-target shape not admitted by ADR 0104 instead of
/// inventing compatibility aliases that would preserve the wrong authority
/// boundary. Such state requires its own explicit migration decision.
fn validate_target_cutover(library: &crate::library::Library) -> std::io::Result<()> {
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
        let binding = library.chat_targets.get(&chat.id).ok_or_else(|| {
            invalid(format!(
                "pre-TARGET workspace: chat {} has no exact target binding; reset this pre-release state root",
                chat.id
            ))
        })?;
        let target = library
            .work_targets
            .get(&binding.target_id)
            .ok_or_else(|| {
                invalid(format!(
                    "chat {} target {} is missing",
                    chat.id, binding.target_id
                ))
            })?;
        let root = library.instances.get(&chat.instance_id).ok_or_else(|| {
            invalid(format!(
                "chat {} root {} is missing",
                chat.id, chat.instance_id
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
        {
            return Err(invalid(format!(
                "chat {} has an invalid target binding",
                chat.id
            )));
        }
    }
    for workstream in library.workstreams.values() {
        let root = library.workstream_roots.get(&workstream.id).ok_or_else(|| {
            invalid(format!(
                "pre-TARGET workspace: workstream {} has no target root; reset this pre-release state root",
                workstream.id
            ))
        })?;
        let target = library.work_targets.get(&root.target_id);
        let root_eligible = library
            .placement_targets
            .get(&root.placement_id)
            .is_some_and(|record| record.target_ids.contains(&root.target_id));
        if root.placement_id != workstream.instance_id
            || !root_eligible
            || target.is_none_or(|target| target.adapter_family != root.adapter_family)
        {
            return Err(invalid(format!(
                "workstream {} has an invalid target root",
                workstream.id
            )));
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
            let resolved = published_archetype_version(targets_dir, &target.id, *version)?;
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
        agent_id: archetype.id.to_owned(),
        project_id: None,
        version: 1,
        admission: Admission::Active,
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
        agent_id: archetype.id.to_owned(),
        project_id: Some(DEFAULT_PROJECT.into()),
        version: 1,
        admission: Admission::Active,
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
        agent_id: DEFAULT_AGENT.into(),
        project_id: Some(DEFAULT_PROJECT.into()),
        version: 1,
        admission: Admission::Active,
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
        self.engagements = state.engagements;
        self.engagement_index = state.engagement_index;
        self.library = state.library;
        self.default_instance = DEFAULT_PLACEMENT.to_owned();
    }

    /// A test workbench with one managed target as its default chat root.
    pub fn with_target(target_id: impl Into<String>, target: Instance, store: Store) -> Self {
        let target_id = target_id.into();
        let mut wb = Self::new(store);
        // Managed targets live at `<targets-root>/<target-id>/repo`.
        if let Some(root) = target.repo().parent().and_then(|p| p.parent()) {
            wb.targets_root = root.to_path_buf();
        }
        wb.targets.insert(target_id.clone(), Box::new(target));
        let home_id = wb.home_id().clone();
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
            agent_id: DEFAULT_AGENT.to_owned(),
            project_id: Some("test-project".to_owned()),
            version: 1,
            admission: Admission::Active,
        });
        wb.default_instance = target_id;
        wb
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
    ) -> Vec<(String, String, Vec<u8>)> {
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
                    )),
                    Err(e) => {
                        tracing::warn!("handoff: cannot bundle target {}: {e}", target.id)
                    }
                },
                None => tracing::warn!("handoff: no live store for target {}", target.id),
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

    pub(crate) fn library_workstream_ids(&self) -> Vec<String> {
        self.library.workstreams.keys().cloned().collect()
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
        self.library.workstreams_in(instance_id)
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

    pub(crate) fn managed_target_storage_id(&self, target_id: &str) -> Option<&str> {
        self.library
            .work_targets
            .get(target_id)
            .filter(|target| target.kind == WorkTargetKind::Managed)
            .map(|target| target.id.as_str())
    }

    pub(crate) fn create_target_workstream_ref(
        &self,
        target_id: &str,
        workstream_id: &str,
    ) -> std::io::Result<()> {
        let Some(target) = self.targets.get(target_id) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "managed target is not open",
            ));
        };
        target.create_workstream(workstream_id).map_err(io)
    }

    pub(crate) fn promote_target_workstream_ref_to_main(
        &self,
        workstream_id: &str,
        target_id: &str,
    ) -> std::io::Result<MergeOutcome> {
        let Some(target) = self.targets.get(target_id) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "managed target is not open",
            ));
        };
        target.promote_workstream_to_main(workstream_id).map_err(io)
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
        // A workstream declaration and its target root are children of the
        // placement. Leaving either live while tombstoning the placement makes
        // the durable library fail closed on its next startup because the root
        // can no longer be eligible for that placement.
        let workstream_ids: Vec<String> = self
            .library
            .workstreams
            .values()
            .filter(|workstream| workstream.instance_id == inst_id)
            .map(|workstream| workstream.id.clone())
            .collect();
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
        Ok(())
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
        let Some(inst_rec) = self.library.instances.get(inst_id).cloned() else {
            return Err("no such instance".into());
        };
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
        let target = match inst_rec.kind {
            InstanceKind::Using => self.resolve_placement_target(inst_id, requested_target_id)?,
            InstanceKind::Authoring => {
                let target = self
                    .library
                    .authoring_target_for(&inst_rec.agent_id)
                    .cloned()
                    .ok_or_else(|| "archetype authoring target is unresolved".to_owned())?;
                if requested_target_id.is_some_and(|requested| requested != target.id) {
                    return Err("edit chat target does not belong to this archetype".to_owned());
                }
                target
            }
        };
        let target_id = target.id.clone();
        if !target.capabilities.read || !target.capabilities.propose {
            return Err("work target does not grant read and propose".to_owned());
        }
        let Some(inst) = self.targets.get(&target_id) else {
            return Err("work target storage is not open".into());
        };
        let chat_id = library::gen_id("chat");
        let eng = inst
            .create_engagement(&chat_id)
            .map_err(|e| e.to_string())?;
        // Pin the exact standing target basis. Runtime config and discipline
        // are control/materialized state and never mint target cuts.
        let basis = eng.boundary_cut().map_err(|error| error.to_string())?.0;
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
        let mut standing_target = target.clone();
        standing_target.current_basis = Some(basis.clone());
        self.write_work_target_record(standing_target);
        self.write_chat_target_record(ChatTargetBindingRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            chat_id: chat_id.clone(),
            op: RecordOp::Upsert,
            target_id: target_id.clone(),
            basis: basis.clone(),
            path_scope: target.path_scope,
            capabilities: target.capabilities,
        });
        self.register_engagement(chat_id.clone(), target_id.clone(), eng);
        self.refresh_chat_discipline_mount(&chat_id)?;
        self.record_target_act(
            Some(&chat_id),
            &target_id,
            crate::target_adapter::TargetActKind::Read,
            None,
            Vec::new(),
            None,
            crate::target_adapter::TargetActStatus::Completed,
            None,
        )?;
        Ok(serde_json::json!({
            "id": chat_id,
            "title": title,
            "kind": kind,
            "target_id": target_id,
            "basis": basis,
        }))
    }

    pub(crate) fn agent_record(&self, id: &str) -> Option<AgentRecord> {
        self.library.agents.get(id).cloned()
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
        for instance_id in instance_ids {
            self.destroy_instance(&instance_id);
        }
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
        self.write_project_record(ProjectRecord {
            op: RecordOp::Tombstone,
            ..project
        });
        true
    }

    pub(crate) fn create_archetype(
        &mut self,
        name: String,
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
        let version = published_archetype_version(&self.targets_dir(), &target_id, 1)
            .map_err(|error| CreateArchetypeError::Create(error.to_string()))?;
        self.targets.insert(target_id.clone(), workspace);
        self.write_instance_record(InstanceRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: inst_id.clone(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Authoring,
            agent_id: agent_id.clone(),
            project_id: None,
            version: 1,
            admission: Admission::Active,
        });
        activate_instance(self.store_mut(), &inst_id);
        self.write_agent_record(AgentRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: agent_id.clone(),
            op: RecordOp::Upsert,
            name: name.clone(),
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
        let _ = self.place_archetype_on_project(
            DEFAULT_PROJECT,
            &agent_id,
            crate::library::Admission::Active,
        );
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
            agent_id: new_agent.clone(),
            project_id: None,
            version: 1,
            admission: Admission::Active,
        });
        activate_instance(self.store_mut(), &new_inst);
        let name = name.unwrap_or_else(|| format!("{} (fork)", src.name));
        self.write_agent_record(AgentRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: new_agent.clone(),
            op: RecordOp::Upsert,
            name: name.clone(),
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
        let _ = self.place_archetype_on_project(
            DEFAULT_PROJECT,
            &new_agent,
            crate::library::Admission::Active,
        );
        Ok(CreatedArchetype {
            id: new_agent,
            name,
        })
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
        if !self.library.agents.contains_key(agent_id) {
            return Err("no such archetype".to_owned());
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
        let version = self
            .library
            .agents
            .get(agent_id)
            .map(|agent| agent.current_version)
            .unwrap_or(1);
        self.write_instance_record(InstanceRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: inst_id.clone(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Using,
            agent_id: agent_id.to_string(),
            project_id: Some(project_id.to_string()),
            version,
            admission,
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

    /// Bind a library agent into a project as a placement (`APPROVE-1`, ADR 0064). The
    /// placement's admission is **policy-gated**: under an approval-required project
    /// policy it enters `Pending` (awaiting the owner's accept); by default it is
    /// frictionless and lands `Active` at once.
    pub(crate) fn bind_agent_to_project(
        &mut self,
        project_id: &str,
        agent_id: &str,
    ) -> Result<String, BindPlacementError> {
        if !self.library.projects.contains_key(project_id) {
            return Err(BindPlacementError::ProjectNotFound);
        }
        if !self.library.agents.contains_key(agent_id) {
            return Err(BindPlacementError::AgentNotFound);
        }
        let admission = if self.require_archetype_approval() {
            Admission::Pending
        } else {
            Admission::Active
        };
        self.place_archetype_on_project(project_id, agent_id, admission)
            .map_err(BindPlacementError::Create)
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
        let version_record = self.freeze_archetype_draft(&target_id, new_version)?;
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
        if !self.library.agents.contains_key(agent_id) {
            return Err(CreateArchetypeChatError::ArchetypeNotFound);
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

    pub(crate) fn fork_chat(&mut self, id: &str) -> Result<ForkedChat, ForkChatError> {
        self.fork_chat_from(id, None)
    }

    pub(crate) fn fork_chat_at(
        &mut self,
        id: &str,
        entry_id: i64,
    ) -> Result<ForkedChat, ForkChatError> {
        let point = self.resolve_fork_point(id, entry_id)?;
        self.fork_chat_from(id, Some(point))
    }

    fn resolve_fork_point(
        &self,
        id: &str,
        entry_id: i64,
    ) -> Result<ResolvedForkPoint, ForkChatError> {
        let boundaries = self
            .store
            .records(id, crate::engine::TURN_BOUNDARY_KIND)
            .map_err(|error| ForkChatError::Continuity(format!("{error:?}")))?;
        for payload in boundaries {
            let boundary: crate::engine::TurnBoundaryRecord = serde_json::from_str(&payload)
                .map_err(|error| ForkChatError::Continuity(error.to_string()))?;
            if boundary.user_entry_id == entry_id {
                return Ok(ResolvedForkPoint {
                    entry_id,
                    workspace_cut: boundary.before_workspace_cut,
                    runtime_position: boundary.runtime_before,
                    reads: boundary.reads_before,
                });
            }
            if boundary.assistant_entry_id == entry_id {
                return Ok(ResolvedForkPoint {
                    entry_id,
                    workspace_cut: boundary.after_workspace_cut,
                    runtime_position: boundary.runtime_after,
                    reads: boundary.reads_after,
                });
            }
        }
        Err(ForkChatError::PointNotForkable)
    }

    fn fork_chat_from(
        &mut self,
        id: &str,
        point: Option<ResolvedForkPoint>,
    ) -> Result<ForkedChat, ForkChatError> {
        let Some(src_chat) = self.library.chats.get(id).cloned() else {
            return Err(ForkChatError::NotFound);
        };
        let source_binding = self
            .library
            .chat_targets
            .get(id)
            .cloned()
            .ok_or(ForkChatError::SourceNotLive)?;
        let source_target_record = self
            .library
            .work_targets
            .get(&source_binding.target_id)
            .cloned()
            .ok_or(ForkChatError::SourceNotLive)?;
        if source_target_record.kind != WorkTargetKind::Managed {
            return Err(ForkChatError::InstanceNotOpen);
        }
        let storage_target_id = source_target_record.id;
        let runtime_placement_id = self.library_placement_of_chat(id);
        let inst_id = src_chat.instance_id.clone();
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
        let (new_eng, new_path, mode) = {
            let Some(inst) = self.targets.get(&storage_target_id) else {
                return Err(ForkChatError::InstanceNotOpen);
            };
            let eng = inst
                .fork_engagement_at(&new_id, &source_branch, &source_target, workspace_cut)
                .map_err(|error| ForkChatError::Create(error.to_string()))?;
            let path = eng.path().to_path_buf();
            let mode = self
                .library
                .instances
                .get(&inst_id)
                .map(|instance| instance.kind.chat_mode())
                .unwrap_or_default();
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
            if let Some(inst) = self.targets.get(&storage_target_id) {
                let _ = inst.remove_engagement(&new_id);
            }
            return Err(ForkChatError::Continuity(error.to_string()));
        }
        let source_events = self
            .store
            .events(id)
            .map_err(|error| ForkChatError::Continuity(format!("{error:?}")))?;
        let through = point
            .as_ref()
            .map(|point| point.entry_id)
            .unwrap_or(i64::MAX);
        for (_, kind, payload) in source_events
            .iter()
            .filter(|(position, kind, _)| *position <= through && kind == "resource")
        {
            self.store
                .append_record(&new_id, kind, payload)
                .map_err(|error| ForkChatError::Continuity(format!("{error:?}")))?;
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
            self.store
                .append_record(&new_id, "read", &read)
                .map_err(|error| ForkChatError::Continuity(format!("{error:?}")))?;
        }
        self.register_engagement(new_id.clone(), storage_target_id, new_eng);
        let title = format!("{} (fork)", src_chat.title);
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
        };
        let pos = self
            .store
            .append_record(LIBRARY_SCOPE, "chat", &serde_json::to_string(&rec).unwrap())
            .unwrap_or(0);
        self.library.apply_chat(ChatRecord {
            created_position: pos,
            ..rec
        });
        self.write_chat_target_record(ChatTargetBindingRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            chat_id: new_id.clone(),
            op: RecordOp::Upsert,
            target_id: source_binding.target_id,
            basis: workspace_cut.to_owned(),
            path_scope: source_binding.path_scope,
            capabilities: source_binding.capabilities,
        });
        self.refresh_chat_discipline_mount(&new_id)
            .map_err(ForkChatError::Create)?;
        self.notify_library_changed("chat", &new_id, "upsert");
        Ok(ForkedChat {
            id: new_id,
            title,
            forked_from: id.to_string(),
            forked_from_entry: point.map(|point| point.entry_id),
        })
    }

    pub(crate) fn delete_chat_cascade(&mut self, id: &str) -> bool {
        if !self.engagement_index.contains_key(id) && !self.library.chats.contains_key(id) {
            return false;
        }
        // Capture the hosting instance before teardown drops the index entry, so we can
        // purge its now-unreachable workspace blobs after the engagement line is gone (SECAUD-6).
        let inst_id = self.engagement_index.get(id).cloned();
        self.destroy_chat(id);
        self.crypto_erase_content(id);
        // SECAUD-6: erase the workspace payload too — `destroy_chat` removed
        // the engagement branch, so its unique objects are now unreachable; prune them so the
        // deleted chat's workspace content is unrecoverable, matching the store crypto-erasure.
        if let Some(inst) = inst_id.and_then(|iid| self.targets.get(&iid)) {
            let _ = inst.purge_unreachable_objects();
        }
        true
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
        let binding = self
            .library
            .chat_targets
            .get(&chat.id)
            .expect("validated chat has a target binding");
        let target = self
            .library
            .work_targets
            .get(&binding.target_id)
            .expect("validated chat binding names a target");
        let workspace_root = format!(
            "{}::{}::{}",
            chat.instance_id, binding.target_id, target.adapter_family
        );
        let candidate_revision = self
            .engagements
            .get(&chat.id)
            .and_then(|engagement| engagement.current_cut().ok())
            .flatten()
            .unwrap_or_else(|| binding.basis.clone());
        let available_acts = self.available_target_acts(&chat.id);
        serde_json::json!({
            "id": chat.id,
            "title": chat.title,
            "kind": kind,
            "forked_from": chat.forked_from,
            "placement": chat.instance_id,
            "workspace_root": workspace_root,
            "target_id": binding.target_id,
            "target_basis": binding.basis,
            "target_kind": target.kind,
            "target_adapter": target.adapter,
            "target_path_scope": binding.path_scope,
            "target_capabilities": binding.capabilities,
            "candidate_revision": candidate_revision,
            "available_acts": available_acts,
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
                    "instance_id": agent.instance_id,
                    "authoring_target_id": lib.authoring_target_for(&agent.id).expect("validated archetype has an authoring target").id,
                    "is_default": agent.id == DEFAULT_AGENT,
                    "forked_from": agent.forked_from,
                    "forked_from_name": agent.forked_from.as_ref().and_then(|src| lib.agents.get(src).map(|source| source.name.clone())),
                    "chats": lib.chats_in(&agent.instance_id).iter().map(|chat| self.library_chat_json(chat, &chat_ws, &rules)).collect::<Vec<_>>(),
                    "workstreams": lib.workstreams_in(&agent.instance_id).iter().map(|workstream| crate::workstream_routes::workstream_json(self, workstream)).collect::<Vec<_>>(),
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
                            "archetype_id": instance.agent_id,
                            "archetype_name": archetype_name,
                            "is_default": instance.id == library_routes::general_placement_id(&project.id),
                            "has_config": has_config,
                            "pinned_version": pinned_version,
                            "version": instance.version,
                            "current_version": current_version,
                            "upgrade_available": lib.upgrade_available(&instance.id),
                            // APPROVE-1 (ADR 0064): a pending placement is approved-but-not-yet-accepted
                            // under an approval-required policy — the nav flags it so the owner can accept.
                            "pending": instance.admission == Admission::Pending,
                            "target_ids": lib.placement_targets.get(&instance.id).expect("validated placement has target eligibility").target_ids,
                            "chats": lib.chats_in(&instance.id).iter().map(|chat| self.library_chat_json(chat, &chat_ws, &rules)).collect::<Vec<_>>(),
                            "workstreams": lib.workstreams_in(&instance.id).iter().map(|workstream| crate::workstream_routes::workstream_json(self, workstream)).collect::<Vec<_>>(),
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
                let kind = inst
                    .map(|instance| instance.kind.chat_kind())
                    .unwrap_or("work");
                let conflict = self.library_chat_conflicted(&chat.id, &rules);
                let binding = lib
                    .chat_targets
                    .get(&chat.id)
                    .expect("validated chat has a target binding");
                let target = lib
                    .work_targets
                    .get(&binding.target_id)
                    .expect("validated chat binding names a target");
                let workspace_root = format!(
                    "{}::{}::{}",
                    chat.instance_id, binding.target_id, target.adapter_family
                );
                let candidate_revision = self
                    .engagements
                    .get(&chat.id)
                    .and_then(|engagement| engagement.current_cut().ok())
                    .flatten()
                    .unwrap_or_else(|| binding.basis.clone());
                serde_json::json!({
                    "id": chat.id,
                    "title": chat.title,
                    "archetype": archetype_name,
                    "kind": kind,
                    "forked_from": chat.forked_from,
                    "placement": chat.instance_id,
                    "workspace_root": workspace_root,
                    "target_id": binding.target_id,
                    "target_basis": binding.basis,
                    "target_kind": target.kind,
                    "target_adapter": target.adapter,
                    "candidate_revision": candidate_revision,
                    "available_acts": self.available_target_acts(&chat.id),
                    "workstream": chat_ws.get(&chat.id),
                            "conflict": conflict,
                    "rehome_blocked": self.library_chat_rehome_blocked(&chat.id),
                })
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

        // Tier 2 — chat log: fold each chat's transcript records and substring-match.
        let mut hits = Vec::new();
        let mut logged: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for chat in &chats {
            let Ok(rows) = self.store_ref().records(&chat.id, "transcript") else {
                continue;
            };
            let mut hay = String::new();
            for row in &rows {
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
