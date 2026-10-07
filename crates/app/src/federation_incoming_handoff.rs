//! WHIP-3: receive original authority and workspace bytes under one product commit.
use super::*;
use crate::library::{
    Library, ProjectCollaborationWorkspaceRecord, ProjectRecord, WorkTargetKind, WorkTargetOwner,
};
use gaugedesk_store::{AdmitError, CommandRecordFact};
use gaugedesk_workspace::Workspace;

#[derive(Clone, Copy)]
pub(super) enum Consent {
    Pending,
    Preauthorized,
}

type InstalledWorkspace = (String, bool, Box<dyn Workspace>);

fn refused(reason: &'static str) -> AdmitError {
    AdmitError::Rejected(gaugedesk_core::Rejection { reason })
}
fn fact(scope: &str, kind: &str, value: &impl Serialize) -> Result<CommandRecordFact, AdmitError> {
    Ok(CommandRecordFact {
        scope_id: scope.into(),
        kind: kind.into(),
        payload: serde_json::to_string(value)?,
    })
}

/// One directory component on every supported host. Stable ids are retained;
/// offered ids cannot become paths outside either managed workspace directory.
fn directory_id(id: &str) -> Result<(), AdmitError> {
    if id.is_empty()
        || id == "."
        || id == ".."
        || id.ends_with('.')
        || id.ends_with(' ')
        || id.chars().any(|c| {
            c.is_control() || matches!(c, '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*')
        })
    {
        return Err(refused(
            "incoming workspace id is not a managed directory component",
        ));
    }
    let stem = id
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
    {
        return Err(refused("incoming workspace id is reserved by the host"));
    }
    Ok(())
}

fn selected_ids(
    rows: &[(String, serde_json::Value)],
    kind: &str,
    field: &str,
    keep: impl Fn(&serde_json::Value) -> bool,
) -> BTreeSet<String> {
    rows.iter()
        .filter(|(k, value)| k == kind && keep(value))
        .filter_map(|(_, value)| {
            value[field]
                .as_str()
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
        })
        .collect()
}

fn validate_log(wire: &HandoffWire) -> Result<(), AdmitError> {
    // HTTP attempt companions belong only to this installation. Reject the
    // entire offer: dropping an imported row would shift retained chat ordinals.
    if wire.log.iter().any(|record| {
        crate::engine::is_task_attempt_scope(&record.scope)
            || record.kind == crate::engine::TASK_CORRELATION_ATTEMPT_KIND
    }) {
        return Err(refused("incoming log contains private HTTP task metadata"));
    }
    if wire.project.is_empty() || wire.project.contains("::") {
        return Err(refused(
            "incoming project id aliases a nested authority scope",
        ));
    }
    let rows = wire
        .log
        .iter()
        .filter(|r| r.scope == LIBRARY_SCOPE)
        .map(|r| {
            Ok((
                r.kind.clone(),
                serde_json::from_str::<serde_json::Value>(&r.payload)?,
            ))
        })
        .collect::<Result<Vec<_>, AdmitError>>()?;
    let using = selected_ids(&rows, "instance", "id", |v| {
        v["project_id"].as_str() == Some(&wire.project)
    });
    let agents = selected_ids(&rows, "instance", "agent_id", |v| {
        using.contains(v["id"].as_str().unwrap_or_default())
    });
    // A built-in Agent is the receiving Home's own seed. Its record may travel
    // as a reference to the pinned version, but another Home's seed of it
    // (authoring instance, authoring target) is never admitted.
    let seeded = |id: &str| crate::app_support::is_builtin_agent(id);
    let authoring = selected_ids(&rows, "agent", "instance_id", |v| {
        let id = v["id"].as_str().unwrap_or_default();
        agents.contains(id) && !seeded(id)
    });
    let seed_rows = selected_ids(&rows, "agent", "instance_id", |v| {
        seeded(v["id"].as_str().unwrap_or_default())
    });
    if rows.iter().any(|(kind, v)| {
        (kind == "instance" && seed_rows.contains(v["id"].as_str().unwrap_or_default()))
            || (kind == "work_target"
                && v["owner"]["kind"] == "archetype"
                && seeded(v["owner"]["archetype_id"].as_str().unwrap_or_default()))
    }) {
        return Err(refused(
            "incoming log carries another Home's seed of a built-in Agent",
        ));
    }
    let instances = using.union(&authoring).cloned().collect::<BTreeSet<_>>();
    let chats = selected_ids(&rows, "chat", "id", |v| {
        using.contains(v["instance_id"].as_str().unwrap_or_default())
    });
    let streams = selected_ids(&rows, "workstream", "id", |v| {
        using.contains(v["instance_id"].as_str().unwrap_or_default())
    });
    let target_belongs = |v: &serde_json::Value| match v["owner"]["kind"].as_str() {
        Some("project") => v["owner"]["project_id"].as_str() == Some(&wire.project),
        Some("archetype") => {
            agents.contains(v["owner"]["archetype_id"].as_str().unwrap_or_default())
        }
        _ => false,
    };
    let project_targets = selected_ids(&rows, "work_target", "id", |v| {
        v["owner"]["kind"] == "project" && target_belongs(v)
    });
    for (kind, v) in &rows {
        let id = v["id"].as_str().unwrap_or_default();
        let allowed = match kind.as_str() {
            "project" => id == wire.project,
            "project_collaboration_workspace" => v["project_id"].as_str() == Some(&wire.project),
            "instance" => {
                using.contains(id) || (authoring.contains(id) && v["project_id"].is_null())
            }
            "agent" => agents.contains(id),
            "chat" => chats.contains(id),
            "workstream" => streams.contains(id),
            "work_target" => target_belongs(v),
            "placement_targets" => using.contains(v["placement_id"].as_str().unwrap_or_default()),
            "placement_distribution" => {
                let record: crate::protected_profiles::PlacementDistributionRecord =
                    serde_json::from_value(v.clone())?;
                using.contains(&record.placement_id)
            }
            "chat_target" | "chat_target_set" => {
                chats.contains(v["chat_id"].as_str().unwrap_or_default())
            }
            "workstream_root" => streams.contains(v["workstream_id"].as_str().unwrap_or_default()),
            _ => false,
        };
        if !allowed {
            return Err(refused(
                "incoming library record is outside the relocated project",
            ));
        }
    }
    let related: BTreeSet<_> = instances
        .iter()
        .chain(&chats)
        .chain(&streams)
        .cloned()
        .collect();
    // These legacy lifecycle scopes use raw entity ids. They must never alias
    // the Home's reserved scopes or a separately namespaced command family.
    for id in &related {
        if id.is_empty()
            || id.contains("::")
            || matches!(
                id.as_str(),
                "library"
                    | "account"
                    | "org"
                    | "account-auth"
                    | "audit"
                    | "audit_checkpoint"
                    | "machine-controllers"
                    | "measurements"
            )
        {
            return Err(refused("incoming entity aliases a reserved Home scope"));
        }
    }
    let mut settlements = BTreeSet::new();
    for record in &wire.log {
        if (chats.contains(&record.scope) && record.kind == "target_settlement_ref")
            || (streams.contains(&record.scope)
                && record.kind == "workstream_target_settlement_ref")
        {
            let value: serde_json::Value = serde_json::from_str(&record.payload)?;
            let id = value["declaration_id"]
                .as_str()
                .filter(|id| !id.is_empty())
                .ok_or_else(|| refused("incoming settlement reference is incomplete"))?;
            settlements.insert(format!("target-settlement::{id}"));
        }
    }
    let lanes = project_targets
        .iter()
        .map(|id| format!("target-settlement-lane::{id}"))
        .collect::<BTreeSet<_>>();
    if wire.log.iter().any(|r| {
        r.scope != LIBRARY_SCOPE
            && !is_project_scope(&r.scope, &wire.project)
            && !related.contains(&r.scope)
            && !settlements.contains(&r.scope)
            && !lanes.contains(&r.scope)
    }) {
        return Err(refused(
            "incoming log scope is outside the relocated project",
        ));
    }
    Ok(())
}

fn incoming_library(wire: &HandoffWire) -> Result<Library, AdmitError> {
    validate_log(wire)?;
    let library = Library::from_records(|kind| {
        Ok(wire
            .log
            .iter()
            .filter(|record| record.scope == LIBRARY_SCOPE && record.kind == kind)
            .map(|record| record.payload.clone())
            .collect())
    })?;
    if library.projects.len() != 1
        || !library.projects.contains_key(&wire.project)
        || library
            .project_collaboration_workspaces
            .keys()
            .any(|project| project != &wire.project)
    {
        return Err(refused(
            "incoming project binding is missing or contains another project",
        ));
    }
    let agents: BTreeSet<_> = library
        .instances
        .values()
        .filter(|instance| instance.project_id.as_deref() == Some(wire.project.as_str()))
        .map(|instance| instance.agent_id.as_str())
        .collect();
    for target in library.work_targets.values() {
        let belongs = match &target.owner {
            WorkTargetOwner::Project { project_id } => project_id == &wire.project,
            WorkTargetOwner::Archetype { archetype_id } => agents.contains(archetype_id.as_str()),
        };
        if !belongs {
            return Err(refused("incoming target belongs to another project"));
        }
    }
    // Read the exact original top-level records, not a serialization of a
    // rebuilt projection. Their only new field is the admitted Home below.
    for kind in ["project", "project_collaboration_workspace"] {
        if wire
            .log
            .iter()
            .filter(|record| record.scope == LIBRARY_SCOPE && record.kind == kind)
            .count()
            > 1
        {
            return Err(refused("incoming Home binding is ambiguous"));
        }
    }
    let mut expected: BTreeSet<(bool, String)> = library
        .work_targets
        .values()
        .filter(|target| target.kind == WorkTargetKind::Managed)
        .map(|target| (false, target.id.clone()))
        .collect();
    for workspace in library.project_collaboration_workspaces.values() {
        expected.insert((true, workspace.workspace_id.clone()));
    }
    let mut actual = BTreeSet::new();
    for bundle in &wire.content {
        directory_id(&bundle.target_id)?;
        if !actual.insert((bundle.collaboration, bundle.target_id.clone())) {
            return Err(refused("incoming workspace bundle is duplicated"));
        }
    }
    if actual != expected {
        return Err(refused(
            "incoming workspace bundles do not match the project bindings",
        ));
    }
    Ok(library)
}

fn home_facts(
    wire: &HandoffWire,
    home: &HomeId,
    local_account: &str,
) -> Result<Vec<CommandRecordFact>, AdmitError> {
    let mut facts = Vec::new();
    for record in &wire.log {
        if record.scope != LIBRARY_SCOPE {
            continue;
        }
        match record.kind.as_str() {
            "project" => {
                let mut original: ProjectRecord = serde_json::from_str(&record.payload)?;
                original.home_id = home.clone();
                // A local account belongs to its own computer and does not
                // travel: a project its origin's local account owned (which
                // the origin names by its own federation authority), or one
                // with no recorded owner, arrives as this computer's local
                // account's, and the account that accepts it takes it from
                // there (DR-0328 §4). An account's project keeps its owner.
                if crate::project_owner::takes_legacy_owner(&original)
                    || crate::project_owner::recorded_owner(&original) == Some(wire.source.as_str())
                {
                    crate::project_owner::record_owner(&mut original.extra, local_account);
                }
                facts.push(fact(LIBRARY_SCOPE, "project", &original)?);
            }
            "project_collaboration_workspace" => {
                let mut original: ProjectCollaborationWorkspaceRecord =
                    serde_json::from_str(&record.payload)?;
                original.home_id = home.clone();
                facts.push(fact(
                    LIBRARY_SCOPE,
                    "project_collaboration_workspace",
                    &original,
                )?);
            }
            _ => {}
        }
    }
    Ok(facts)
}

/// A relocated placement of a built-in Agent binds to this Home's own seed of
/// it. The offered record is a reference and is never admitted. When this Home
/// holds the exact published version the placement pins, the placement keeps
/// it; otherwise it is rebound to this Home's current published version of its
/// own seed (DR-0449, narrowing DR-0389 §2). Two Homes number the same built-in
/// differently — one seeded before a built-in migration publishes version 2,
/// a fresh install seeds the migrated content as version 1 — so an exact pin
/// across Homes refused every project from an upgraded Home.
///
/// Returns the placements to rebind, by id, with the version they now run.
fn compatible_seeded_agents(
    current: &Library,
    incoming: &Library,
) -> Result<BTreeMap<String, u64>, AdmitError> {
    let mut rebind = BTreeMap::new();
    for placement in incoming.instances.values() {
        if !crate::app_support::is_builtin_agent(&placement.agent_id) {
            continue;
        }
        let local = current.agents.get(&placement.agent_id).ok_or_else(|| {
            refused("incoming project uses a built-in Agent this Home has not seeded")
        })?;
        let offered = incoming
            .agents
            .get(&placement.agent_id)
            .and_then(|agent| agent.versions.get(&placement.version))
            .ok_or_else(|| refused("incoming placement pins no built-in Agent version"))?;
        match local.versions.get(&placement.version) {
            Some(held) if serde_json::to_value(held)? == serde_json::to_value(offered)? => {}
            _ => {
                if !local.versions.contains_key(&local.current_version) {
                    return Err(refused(
                        "this Home's built-in Agent has no published version to bind",
                    ));
                }
                rebind.insert(placement.id.clone(), local.current_version);
            }
        }
    }
    Ok(rebind)
}

/// Rewrite an offered placement record of a built-in Agent to run this Home's
/// own version of it, as [`compatible_seeded_agents`] decided.
fn rebound_placement(
    record: &HandoffLogRecord,
    rebind: &BTreeMap<String, u64>,
) -> Result<String, AdmitError> {
    if record.scope != LIBRARY_SCOPE || record.kind != "instance" || rebind.is_empty() {
        return Ok(record.payload.clone());
    }
    let mut value: serde_json::Value = serde_json::from_str(&record.payload)?;
    match value["id"].as_str().and_then(|id| rebind.get(id)) {
        Some(version) => {
            value["version"] = serde_json::json!(version);
            Ok(value.to_string())
        }
        None => Ok(record.payload.clone()),
    }
}

fn compatible_library(
    current: &Library,
    incoming: &Library,
) -> Result<BTreeMap<String, u64>, AdmitError> {
    let rebind = compatible_seeded_agents(current, incoming)?;
    for (id, offered) in &incoming.agents {
        if crate::app_support::is_builtin_agent(id) {
            continue;
        }
        if let Some(existing) = current.agents.get(id) {
            if serde_json::to_value(existing)? != serde_json::to_value(offered)? {
                return Err(refused(
                    "incoming library identity conflicts with local authority",
                ));
            }
        }
    }
    macro_rules! check {
        ($($field:ident),+ $(,)?) => {$(
            for (id, offered) in &incoming.$field {
                if let Some(existing) = current.$field.get(id) {
                    if serde_json::to_value(existing)? != serde_json::to_value(offered)? {
                        return Err(refused("incoming library identity conflicts with local authority"));
                    }
                }
            }
        )+};
    }
    check!(
        instances,
        chats,
        workstreams,
        work_targets,
        placement_targets,
        chat_targets,
        chat_target_sets,
        workstream_roots,
        project_collaboration_workspaces
    );
    for offered in incoming.project_collaboration_workspaces.values() {
        if current
            .project_collaboration_workspaces
            .values()
            .any(|existing| {
                existing.workspace_id == offered.workspace_id
                    && existing.project_id != offered.project_id
            })
        {
            return Err(refused(
                "incoming workspace identity belongs to another local project",
            ));
        }
    }
    Ok(rebind)
}

/// The offered record of a built-in Agent: checked against this Home's seed by
/// [`compatible_seeded_agents`], never written over it.
fn is_seeded_agent_reference(record: &HandoffLogRecord) -> bool {
    record.scope == LIBRARY_SCOPE
        && record.kind == "agent"
        && serde_json::from_str::<serde_json::Value>(&record.payload).is_ok_and(|value| {
            crate::app_support::is_builtin_agent(value["id"].as_str().unwrap_or_default())
        })
}

fn matching_existing_scopes(
    store: &Store,
    wire: &HandoffWire,
) -> Result<BTreeSet<String>, AdmitError> {
    let mut offered: BTreeMap<&str, Vec<(&str, &str)>> = BTreeMap::new();
    for record in &wire.log {
        if record.scope != LIBRARY_SCOPE
            && (wire.project_commands.is_none() || !is_project_scope(&record.scope, &wire.project))
        {
            offered
                .entry(&record.scope)
                .or_default()
                .push((&record.kind, &record.payload));
        }
    }
    let mut reused = BTreeSet::new();
    for (scope, incoming) in offered {
        let existing = store.retained_events(scope)?;
        if existing.is_empty() {
            continue;
        }
        if existing
            .iter()
            .map(|(_, kind, payload)| (kind.as_str(), payload.as_str()))
            .collect::<Vec<_>>()
            != incoming
        {
            return Err(refused(
                "incoming lifecycle scope conflicts with retained local history",
            ));
        }
        reused.insert(scope.to_owned());
    }
    Ok(reused)
}

fn receipt_snapshot(wire: &HandoffWire, home: &HomeId) -> Result<String, AdmitError> {
    Ok(serde_json::json!({
        "protocol": "gaugedesk.handoff-receive.v1", "project": wire.project,
        "source": wire.source, "source_home": wire.source_home, "target": wire.target,
        "home": home, "offer_sha256": hex::encode(Sha256::digest(serde_json::to_vec(wire)?)),
    })
    .to_string())
}

fn credential_key(guard: &Workbench, wire: &HandoffWire) -> Result<Option<[u8; 32]>, AdmitError> {
    let carries = wire.log.iter().any(|record| {
        record.scope == format!("project::{}", wire.project) && record.kind == "credential"
    });
    match &wire.credential_key {
        Some(sealed) => {
            let bytes = open_sealed(&federation_root_signing_key(guard), sealed)
                .ok_or_else(|| refused("incoming credential key did not open for this Home"))?;
            let key = <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| refused("incoming credential key length is invalid"))?;
            if guard
                .project_credential_key_for_handoff(&wire.project)
                .is_some_and(|existing| existing != key)
            {
                return Err(refused(
                    "incoming credential key conflicts with retained custody",
                ));
            }
            Ok(Some(key))
        }
        None if carries => Err(refused("incoming credentials have no receiving key")),
        None => Ok(None),
    }
}

fn publish_views(guard: &mut Workbench, installed: Vec<InstalledWorkspace>) {
    guard.rebuild_library();
    for (id, collaboration, workspace) in installed {
        if collaboration {
            guard.collaboration_workspaces.insert(id.clone(), workspace);
            if let Err(error) = guard.reopen_collaboration_workspace_engagements(&id) {
                tracing::warn!(%error, %id, "committed handoff needs workspace projection recovery");
            }
        } else {
            // Registration cannot undo admission. A failed view is recoverable
            // from its original stores and the committed library records.
            let engagements = workspace.reconcile_engagements();
            guard.register_target(id.clone(), workspace);
            match engagements {
                Ok(engagements) => {
                    for (chat, engagement) in engagements {
                        guard.register_engagement(chat, id.clone(), engagement);
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, %id, "committed handoff needs target projection recovery")
                }
            }
        }
    }
}

pub(super) fn commit(
    guard: &mut Workbench,
    wire: &HandoffWire,
    consent: Consent,
) -> Result<(), AdmitError> {
    let grant = verify_handoff(guard, wire).map_err(refused)?;
    let incoming = incoming_library(wire)?;
    let home = guard.home_id().clone();
    let scope = handoff_scope(&wire.project);
    let snapshot = receipt_snapshot(wire, &home)?;
    let mut writer = guard.store_ref().sibling().map_err(AdmitError::Db)?;
    let mut scopes: BTreeSet<String> = wire.log.iter().map(|record| record.scope.clone()).collect();
    scopes.extend([
        scope.clone(),
        LIBRARY_SCOPE.into(),
        BRIDGE_SCOPE.into(),
        crate::org::ORG_SCOPE.into(),
        HANDOFF_INCOMING_SCOPE.into(),
        HANDOFF_PREAUTH_SCOPE.into(),
        HANDOFF_ONESHOT_SCOPE.into(),
        project_participants_scope(&wire.project),
    ]);
    let ((replayed, oneshot, reused, rebind), basis) = writer.read_for_dispatch(
        &scopes.iter().map(String::as_str).collect::<Vec<_>>(),
        |store| {
            if let Some(original) = store.committed_record_snapshot(&scope, "receive")? {
                if original != snapshot {
                    return Err(refused("receiving receipt belongs to a different offer"));
                }
                let library = Library::rebuild(store)?;
                if retained_handoff(store, &wire.project)?.phase != HandoffPhase::Committed
                    || library.project_home_id(&wire.project) != Some(&home)
                    || incoming
                        .project_collaboration_workspaces
                        .get(&wire.project)
                        .is_some_and(|original| {
                            !library
                                .project_collaboration_workspaces
                                .get(&wire.project)
                                .is_some_and(|current| {
                                    current.workspace_id == original.workspace_id
                                        && current.home_id == home
                                })
                        })
                {
                    return Err(refused(
                        "receiving receipt has no matching committed Home facts",
                    ));
                }
                return Ok((true, None, BTreeSet::new(), BTreeMap::new()));
            }
            if retained_handoff(store, &wire.project)?.phase != HandoffPhase::Draft
                || Library::rebuild(store)?
                    .projects
                    .contains_key(&wire.project)
            {
                return Err(refused(
                    "receiving Home already has project authority without this receipt",
                ));
            }
            let oneshot = match consent {
                Consent::Pending => {
                    let retained = pending_incoming(store)
                        .into_iter()
                        .find(|offer| offer["project"].as_str() == Some(&wire.project))
                        .ok_or_else(|| refused("explicit handoff consent has no pending offer"))?;
                    let retained = pending_handoff_wire(&retained).map_err(refused)?;
                    if receipt_snapshot(&retained, &home)? != snapshot {
                        return Err(refused("pending handoff changed before explicit consent"));
                    }
                    None
                }
                Consent::Preauthorized if handoff_preauthorized(store, &wire.source) => None,
                Consent::Preauthorized => Some(
                    handoff_oneshot_available(store, &wire.source, &wire.project).ok_or_else(
                        || refused("incoming handoff has no current receiving consent"),
                    )?,
                ),
            };
            let rebind = compatible_library(&Library::rebuild(store)?, &incoming)?;
            let reused = matching_existing_scopes(store, wire)?;
            Ok((false, oneshot, reused, rebind))
        },
    )?;
    project_authority::receive(guard, wire, replayed)
        .map_err(|error| AdmitError::Codec(error.to_string()))?;
    if replayed {
        // Later workflow writes legitimately change the installation receipt.
        // Recover this product admission before considering another import.
        guard.rebuild_library();
        return Ok(());
    }
    let expiry = wire
        .delegation
        .as_ref()
        .map_or(grant.expiry, |d| grant.expiry.min(d.expiry));
    let expiry = oneshot
        .as_ref()
        .map_or(expiry, |(_, consent_expiry)| expiry.min(*consent_expiry));
    let deadline = std::time::UNIX_EPOCH + std::time::Duration::from_secs(expiry);
    let basis = basis.with_deadline(deadline);
    let key = credential_key(guard, wire)?;
    let workflow_key = workflow_keys::receive(guard, wire)
        .map_err(|error| AdmitError::Codec(error.to_string()))?;
    let workflow_protection = workflow_key
        .as_ref()
        .map(|key| {
            let workspace = incoming
                .project_collaboration_workspaces
                .get(&wire.project)
                .ok_or_else(|| refused("workflow custody has no admitted collaboration binding"))?;
            gaugedesk_workspace::WorkflowProtection::new(&workspace.workspace_id, key.clone())
                .map_err(|error| AdmitError::Codec(error.to_string()))
        })
        .transpose()?;
    let mut facts = wire
        .log
        .iter()
        .filter(|record| {
            !reused.contains(&record.scope)
                && (wire.project_commands.is_none()
                    || !is_project_scope(&record.scope, &wire.project))
                && !is_seeded_agent_reference(record)
        })
        .map(|record| {
            Ok(CommandRecordFact {
                scope_id: record.scope.clone(),
                kind: record.kind.clone(),
                payload: rebound_placement(record, &rebind)?,
            })
        })
        .collect::<Result<Vec<_>, AdmitError>>()?;
    let mut state = HandoffState::default();
    for command in [
        HandoffCommand::OfferHandoff,
        HandoffCommand::SyncLog,
        HandoffCommand::CommitHandoff,
    ] {
        for event in handoff::decide(&state, command).map_err(AdmitError::Rejected)? {
            facts.push(fact(&scope, HANDOFF_KIND, &event)?);
            state = handoff::evolve(&state, event);
        }
    }
    facts.extend(home_facts(wire, &home, guard.authority().as_str())?);
    // Pin the key the origin signs its runs with, as the pairing that verified
    // this move vouches for it now, so the runs arriving here stay checkable
    // after that pairing expires or is revoked (DR-0201). A revoked pairing
    // stops new moves; it does not strand runs that already arrived.
    let origin = super::active_bridge(guard.store_ref(), &wire.source)
        .ok_or_else(|| refused("handoff origin has no active pairing to pin"))?;
    facts.push(fact(
        &super::workflow_signers_scope(&wire.project),
        super::WORKFLOW_SIGNER_PIN_KIND,
        &super::WorkflowSignerPin {
            issuer: wire.source.clone(),
            governance_pubkey: origin.ticket.governance_pubkey,
        },
    )?);
    for (authority, owns) in [
        (wire.target.as_str(), PayloadClass::Data),
        (wire.source.as_str(), PayloadClass::Archetypes),
    ] {
        facts.push(fact(
            &project_participants_scope(&wire.project),
            "participant",
            &ParticipantRecord {
                authority: authority.into(),
                role: owns.role().into(),
                owns,
                revoked: false,
            },
        )?);
    }
    facts.push(fact(
        HANDOFF_INCOMING_SCOPE,
        "event",
        &serde_json::json!({
            "op":"resolved", "project":wire.project, "outcome":"committed"
        }),
    )?);
    if let Some((invite_id, _)) = oneshot {
        facts.push(fact(
            HANDOFF_ONESHOT_SCOPE,
            "event",
            &serde_json::json!({"op":"consume", "invite_id":invite_id}),
        )?);
    }
    let installed =
        writer.with_dispatch_record_admission(&basis, |admission| -> Result<_, AdmitError> {
            let publish = || -> Result<_, AdmitError> {
                let admission = match &wire.project_commands {
                    Some(archive) => admission.import_command_scopes(archive, |candidate| {
                        is_project_scope(candidate, &wire.project)
                    })?,
                    None => admission,
                };
                let mut installed = Vec::new();
                for bundle in &wire.content {
                    let parent = if bundle.collaboration {
                        "collaboration-workspaces"
                    } else {
                        "targets"
                    };
                    let path = guard.root.join(parent).join(&bundle.target_id);
                    let provider = guard.workspace_provider(&bundle.target_id);
                    if !provider.accepts_export_format(&bundle.format) {
                        return Err(refused("incoming workspace export format is incompatible"));
                    }
                    let workspace = if bundle.workflow_key.is_some() {
                        let protection = workflow_protection
                            .as_ref()
                            .ok_or_else(|| refused("protected workflow has no prepared key"))?;
                        provider.from_protected_export_at(&path, &bundle.bundle, protection)
                    } else {
                        provider.from_export_at(&path, &bundle.bundle)
                    }
                    .map_err(|error| AdmitError::Codec(error.to_string()))?;
                    installed.push((bundle.target_id.clone(), bundle.collaboration, workspace));
                }
                if let Some(key) = key {
                    guard
                        .install_project_credential_key(&wire.project, key)
                        .ok_or_else(|| {
                            refused("receiving credential custody could not be persisted")
                        })?;
                }
                if std::time::SystemTime::now() >= deadline {
                    return Err(refused("handoff authority expired before receiving commit"));
                }
                admission.commit(&scope, "receive", &snapshot, &facts)?;
                Ok(installed)
            };
            match &workflow_key {
                Some(key) => key
                    .retain(|| Ok::<_, std::io::Error>(publish()))
                    .map_err(|error| AdmitError::Codec(error.to_string()))?,
                None => publish(),
            }
        })??;
    publish_views(guard, installed);
    Ok(())
}

#[cfg(test)]
#[path = "federation_incoming_handoff_tests.rs"]
mod tests;
