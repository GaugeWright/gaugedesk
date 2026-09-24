//! Project-owned declarations and ordinary resource-access bases for native
//! trackers. This module owns no issues, assignments, runtime, or scheduler.
//! The public methods are admission-shell operations; no route is activated.

use std::collections::BTreeMap;

use gaugedesk_core::{
    abac::{Action, AuthorityAttributes, Policy, ResourceAttributes},
    boundary::Authority,
    ids::HomeId,
    resource::{ContentLocator, Resource, ResourceId, ResourceKind, ResourceRecord},
    resource_access::{self, AccessCommand, AccessPhase, AccessState},
    Lifecycle, Rejection,
};
use gaugedesk_store::{command_dispatch::DispatchReadBasis, AdmitError, CommandRecordFact, Store};
use serde::{Deserialize, Serialize};

use crate::{
    identity::AuthenticatedActionContext,
    library::{Library, LIBRARY_SCOPE},
    org::{Org, ORG_SCOPE},
    Workbench,
};

const DEFINITION: &str = "project_tracker_v1";

/// The queue of the tracker every project has, owned by the Home (DR-0199 §3).
/// A workflow run from the project's Home-owned files files into it, and every
/// member with current access to the project reads and contributes to it.
pub const PROJECT_TASKS: &str = "tasks";
const ACCESS_BASIS: &str = "project_tracker_access_basis_v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectTracker {
    pub project_id: String,
    pub workspace_id: String,
    pub queue: String,
    pub resource: ResourceRecord,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrackerPermission {
    Read,
    Contribute,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerAccessBasis {
    pub id: String,
    pub requested_by: String,
    pub request_id: String,
    pub recipient: String,
    pub permission: TrackerPermission,
    pub purpose: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrackerAccessDecision {
    Approve,
    Reject,
    Revoke,
    Cancel,
}

#[derive(Default)]
struct Registry {
    tracker: Option<ProjectTracker>,
    bases: BTreeMap<String, TrackerAccessBasis>,
}

struct ProjectAuthority {
    workspace: String,
    purpose: Option<String>,
    attributes: AuthorityAttributes,
    policy: Policy,
    deadline_ms: Option<u64>,
    org: Org,
}

struct Snapshot {
    authority: ProjectAuthority,
    project: String,
    /// The tracker is the project's own, owned by the Home: project access is
    /// its access rule, and it carries no grants (DR-0199 §3).
    home_owned: bool,
    registry: Registry,
    access: BTreeMap<String, AccessState>,
    prior_command: Option<String>,
}

fn refused(reason: &'static str) -> AdmitError {
    AdmitError::Rejected(Rejection { reason })
}

fn encode(value: &impl Serialize) -> Result<String, AdmitError> {
    Ok(serde_json::to_string(value)?)
}

fn registry_scope(project: &str, queue: &str) -> Result<String, AdmitError> {
    if project.trim().is_empty() || queue.trim().is_empty() {
        return Err(refused("tracker requires a project and queue name"));
    }
    Ok(format!(
        "project::{project}::tracker::{}",
        hex::encode(queue)
    ))
}

fn command_scope(registry: &str, actor: &str) -> String {
    format!("{registry}::commands::{}", hex::encode(actor))
}

fn access_scope(registry: &str, basis: &str) -> String {
    format!("{registry}::access::{basis}")
}

fn resource_handle(workspace: &str, queue: &str) -> Result<String, AdmitError> {
    Ok(format!(
        "tracker:{}",
        hex::encode(encode(&(workspace, queue))?)
    ))
}

fn new_basis(
    registry: &str,
    actor: &str,
    request_id: &str,
    recipient: &str,
    permission: TrackerPermission,
    purpose: Option<String>,
) -> Result<TrackerAccessBasis, AdmitError> {
    if [actor, request_id, recipient]
        .iter()
        .any(|s| s.trim().is_empty())
    {
        return Err(refused("tracker access has incomplete identity"));
    }
    Ok(TrackerAccessBasis {
        id: whipplescript_store::stable_hash_hex(&encode(&(
            registry, actor, request_id, permission,
        ))?),
        requested_by: actor.into(),
        request_id: request_id.into(),
        recipient: recipient.into(),
        permission,
        purpose,
    })
}

fn registry(store: &Store, scope: &str) -> Result<Registry, AdmitError> {
    let mut result = Registry::default();
    for (_, kind, payload) in store.retained_events(scope)? {
        match kind.as_str() {
            DEFINITION if result.tracker.is_none() => {
                result.tracker = Some(serde_json::from_str(&payload)?);
            }
            ACCESS_BASIS => {
                let basis: TrackerAccessBasis = serde_json::from_str(&payload)?;
                let expected = new_basis(
                    scope,
                    &basis.requested_by,
                    &basis.request_id,
                    &basis.recipient,
                    basis.permission,
                    basis.purpose.clone(),
                )?;
                if basis != expected || result.bases.insert(basis.id.clone(), basis).is_some() {
                    return Err(refused("tracker has conflicting access basis evidence"));
                }
            }
            _ => return Err(refused("tracker declaration is conflicting or unsupported")),
        }
    }
    if result.tracker.is_none() && !result.bases.is_empty() {
        return Err(refused("tracker access has no owning declaration"));
    }
    Ok(result)
}

fn current_project(
    store: &Store,
    home: &HomeId,
    context: &AuthenticatedActionContext,
    project: &str,
) -> Result<ProjectAuthority, AdmitError> {
    let deadline_ms = crate::identity::revalidate_workflow_context(store, home, context)?;
    store.retained_events(LIBRARY_SCOPE)?;
    store.retained_events(ORG_SCOPE)?;
    let library = Library::rebuild(store)?;
    let org = Org::rebuild(store)?;
    let record = library
        .projects
        .get(project)
        .ok_or_else(|| refused("tracker project is unavailable"))?;
    let workspace = library
        .project_collaboration_workspaces
        .get(project)
        .ok_or_else(|| refused("tracker project has no collaboration workspace"))?;
    if &record.home_id != home
        || &workspace.home_id != home
        || workspace.project_id != project
        || workspace.workspace_id.trim().is_empty()
        || !org.can_access_project(context.actor().as_str(), project)
        || library
            .project_collaboration_workspaces
            .values()
            .any(|other| {
                other.project_id != project && other.workspace_id == workspace.workspace_id
            })
    {
        return Err(refused("tracker exceeds current project or Home authority"));
    }
    Ok(ProjectAuthority {
        workspace: workspace.workspace_id.clone(),
        purpose: record.run_purpose.clone(),
        attributes: org.with_directory_role(context.claims().clone(), context.actor().as_str()),
        policy: org.policy(),
        deadline_ms,
        org,
    })
}

fn capture(
    store: &Store,
    home: &HomeId,
    context: &AuthenticatedActionContext,
    project: &str,
    queue: &str,
    request_id: Option<&str>,
) -> Result<(Snapshot, DispatchReadBasis), AdmitError> {
    let scope = registry_scope(project, queue)?;
    // A workflow's unattended standing reads its trackers; it never declares,
    // requests or decides access.
    if request_id.is_some()
        && matches!(
            context.authentication(),
            crate::identity::ActorAuthentication::ProjectWorkflowInvocation { .. }
        )
    {
        return Err(refused("workflow authority cannot change tracker access"));
    }
    current_project(store, home, context, project)?;
    let before = registry(store, &scope)?;
    let commands = command_scope(&scope, context.actor().as_str());
    // New access scopes must be empty and fenced just like existing ones. A
    // partial import must not let a new request append around orphaned grants.
    let mut anticipated = Vec::new();
    if let Some(key) = request_id {
        for permission in [TrackerPermission::Read, TrackerPermission::Contribute] {
            anticipated.push(
                new_basis(
                    &scope,
                    context.actor().as_str(),
                    key,
                    context.actor().as_str(),
                    permission,
                    None,
                )?
                .id,
            );
        }
    }
    let handoff = crate::federation::handoff_scope(project);
    let mut scopes = vec![
        LIBRARY_SCOPE.into(),
        ORG_SCOPE.into(),
        crate::account_auth::ACCOUNT_AUTH_SCOPE.into(),
        crate::mobile_machine_session::SCOPE.into(),
        scope.clone(),
        commands.clone(),
        handoff,
    ];
    scopes.extend(before.bases.keys().map(|id| access_scope(&scope, id)));
    scopes.extend(anticipated.iter().map(|id| access_scope(&scope, id)));
    scopes.sort();
    scopes.dedup();
    let (snapshot, basis) = store.read_for_dispatch(
        &scopes.iter().map(String::as_str).collect::<Vec<_>>(),
        |store| {
            let authority = current_project(store, home, context, project)?;
            if request_id.is_some() {
                crate::federation::require_project_writes_available(store, project)?;
            }
            let registry = registry(store, &scope)?;
            if registry.bases != before.bases {
                return Err(refused(
                    "tracker access changed while its scopes were resolved",
                ));
            }
            for id in &anticipated {
                if !registry.bases.contains_key(id)
                    && !store.retained_events(&access_scope(&scope, id))?.is_empty()
                {
                    return Err(refused("tracker has orphaned access evidence"));
                }
            }
            let mut access = BTreeMap::new();
            if let Some(tracker) = &registry.tracker {
                let handle = resource_handle(&authority.workspace, queue)?;
                let owner = &tracker.resource.resource.owner;
                if tracker.project_id != project
                    || tracker.workspace_id != authority.workspace
                    || tracker.queue != queue
                    || owner.as_str().trim().is_empty()
                    || tracker.resource
                        != ResourceRecord::new(
                            Resource::input(
                                ResourceId::new(&handle),
                                ResourceKind::new("tracker"),
                                owner.clone(),
                            ),
                            ContentLocator::Content { handle },
                            |_| owner.clone(),
                        )
                        .with_attributes(tracker.resource.attributes.clone())
                {
                    return Err(refused(
                        "tracker has an invalid or replaced resource binding",
                    ));
                }
                for id in registry.bases.keys() {
                    let mut state = AccessState::default();
                    for (_, kind, payload) in store.retained_events(&access_scope(&scope, id))? {
                        if kind != AccessState::KIND {
                            return Err(refused(
                                "tracker access has unsupported retained evidence",
                            ));
                        }
                        state = resource_access::evolve(&state, serde_json::from_str(&payload)?);
                    }
                    if state.required != tracker.resource.stakeholders {
                        return Err(refused("tracker access has the wrong required approvers"));
                    }
                    if state.phase == AccessPhase::Granted && state.approvals != state.required {
                        return Err(refused(
                            "tracker access is missing required approval evidence",
                        ));
                    }
                    access.insert(id.clone(), state);
                }
            }
            let prior_command = request_id
                .map(|key| store.committed_record_snapshot(&commands, key))
                .transpose()?
                .flatten();
            if prior_command.is_none()
                && anticipated.iter().any(|id| registry.bases.contains_key(id))
            {
                return Err(refused(
                    "tracker access basis has no original command receipt",
                ));
            }
            let home_owned = registry
                .tracker
                .as_ref()
                .is_some_and(|tracker| tracker.resource.resource.owner.as_str() == home.as_str());
            if home_owned && !registry.bases.is_empty() {
                return Err(refused("a project's Home tracker carries no access grants"));
            }
            Ok(Snapshot {
                authority,
                project: project.to_owned(),
                home_owned,
                registry,
                access,
                prior_command,
            })
        },
    )?;
    let basis = if let Some(ms) = snapshot.authority.deadline_ms {
        basis.with_deadline(
            std::time::UNIX_EPOCH
                .checked_add(std::time::Duration::from_millis(ms))
                .ok_or_else(|| refused("tracker authentication deadline is out of range"))?,
        )
    } else {
        basis
    };
    Ok((snapshot, basis))
}

fn fact(scope: &str, kind: &str, value: &impl Serialize) -> Result<CommandRecordFact, AdmitError> {
    Ok(CommandRecordFact {
        scope_id: scope.into(),
        kind: kind.into(),
        payload: encode(value)?,
    })
}

fn access_events(
    scope: &str,
    state: &AccessState,
    command: AccessCommand,
) -> Result<(AccessState, Vec<CommandRecordFact>), AdmitError> {
    let events = resource_access::decide(state, command).map_err(AdmitError::Rejected)?;
    let mut next = state.clone();
    let mut facts = Vec::new();
    for event in events {
        facts.push(fact(scope, AccessState::KIND, &event)?);
        next = resource_access::evolve(&next, event);
    }
    Ok((next, facts))
}

fn check_replay(snapshot: &Snapshot, command: &str) -> Result<bool, AdmitError> {
    match snapshot.prior_command.as_deref() {
        Some(original) if original == command => Ok(true),
        Some(_) => Err(refused("tracker request key reused with different meaning")),
        None => Ok(false),
    }
}

fn commit(
    store: &mut Store,
    basis: &DispatchReadBasis,
    scope: &str,
    key: &str,
    command: &str,
    facts: &[CommandRecordFact],
) -> Result<(), AdmitError> {
    if key.trim().is_empty() {
        return Err(refused("tracker command requires an idempotency key"));
    }
    store.with_dispatch_record_admission(basis, |writer| {
        writer.commit(scope, key, command, facts)
    })??;
    Ok(())
}

fn permitted(snapshot: &Snapshot, recipient: &str, permission: TrackerPermission) -> bool {
    if snapshot.home_owned {
        return snapshot
            .authority
            .org
            .can_access_project(recipient, &snapshot.project);
    }
    snapshot.registry.bases.values().any(|grant| {
        grant.recipient == recipient
            && grant.permission == permission
            && grant.purpose == snapshot.authority.purpose
            && snapshot.access[&grant.id].payload_accessible()
    })
}

fn check_policy(
    snapshot: &Snapshot,
    resource: &ResourceRecord,
    action: Action,
) -> Result<(), AdmitError> {
    crate::policy_compiler::validate_resources_for_action(
        &[resource],
        &snapshot.authority.attributes,
        &snapshot.authority.policy,
        snapshot.authority.purpose.as_deref(),
        false,
        action,
    )
    .map_err(|_| refused("current resource policy refuses tracker access"))
}

impl Workbench {
    /// Declare an empty native tracker resource. Existing names never acquire a
    /// new owner or fresh owner grants from re-opening a source file.
    pub fn declare_project_tracker(
        &mut self,
        context: &AuthenticatedActionContext,
        project: &str,
        queue: &str,
        request_id: &str,
        attributes: ResourceAttributes,
    ) -> Result<ProjectTracker, AdmitError> {
        let scope = registry_scope(project, queue)?;
        let (snapshot, basis) = capture(
            self.store_ref(),
            self.home_id(),
            context,
            project,
            queue,
            Some(request_id),
        )?;
        let actor = context.actor().as_str();
        let owner = Authority::from(actor);
        let handle = resource_handle(&snapshot.authority.workspace, queue)?;
        let tracker = ProjectTracker {
            project_id: project.into(),
            workspace_id: snapshot.authority.workspace.clone(),
            queue: queue.into(),
            resource: ResourceRecord::new(
                Resource::input(
                    ResourceId::new(&handle),
                    ResourceKind::new("tracker"),
                    owner.clone(),
                ),
                ContentLocator::Content { handle },
                |_| owner.clone(),
            )
            .with_attributes(attributes),
        };
        check_policy(&snapshot, &tracker.resource, Action::Access)?;
        let command = encode(&("declare_tracker.v1", actor, &tracker))?;
        if check_replay(&snapshot, &command)? && snapshot.registry.tracker.is_none() {
            return Err(refused(
                "tracker declaration receipt has no retained resource",
            ));
        }
        let mut facts = Vec::new();
        if let Some(existing) = &snapshot.registry.tracker {
            if existing != &tracker {
                return Err(refused(
                    "tracker name already has another resource declaration",
                ));
            }
        } else {
            facts.push(fact(&scope, DEFINITION, &tracker)?);
            for permission in [TrackerPermission::Read, TrackerPermission::Contribute] {
                let grant = new_basis(
                    &scope,
                    actor,
                    request_id,
                    actor,
                    permission,
                    snapshot.authority.purpose.clone(),
                )?;
                facts.push(fact(&scope, ACCESS_BASIS, &grant)?);
                let grant_scope = access_scope(&scope, &grant.id);
                let (requested, request) = access_events(
                    &grant_scope,
                    &AccessState::default(),
                    AccessCommand::RequestAccess {
                        required: tracker.resource.stakeholders.clone(),
                    },
                )?;
                facts.extend(request);
                facts.extend(
                    access_events(
                        &grant_scope,
                        &requested,
                        AccessCommand::Approve(owner.clone()),
                    )?
                    .1,
                );
            }
        }
        commit(
            self.store_mut(),
            &basis,
            &command_scope(&scope, actor),
            request_id,
            &command,
            &facts,
        )?;
        Ok(tracker)
    }

    /// Ensure the project's Home-owned `tasks` tracker exists (DR-0199 §3).
    /// It is declared by the Home, not by a person, so it carries no grants;
    /// a project whose collaboration workspace does not exist yet gets it once
    /// it does. Returns whether it was declared now.
    pub fn ensure_project_tasks_tracker(&mut self, project: &str) -> Result<bool, String> {
        // A project mid-move is declared on by whichever Home keeps it.
        if self.project_moving(project) {
            return Ok(false);
        }
        let home = self.home_id().clone();
        let Some(workspace) = self
            .library
            .project_collaboration_workspaces
            .get(project)
            .filter(|workspace| workspace.home_id == home && !workspace.workspace_id.is_empty())
            .map(|workspace| workspace.workspace_id.clone())
        else {
            return Ok(false);
        };
        if self
            .library
            .projects
            .get(project)
            .is_none_or(|record| record.home_id != home)
        {
            return Ok(false);
        }
        let scope = registry_scope(project, PROJECT_TASKS).map_err(|e| format!("{e:?}"))?;
        if registry(self.store_ref(), &scope)
            .map_err(|e| format!("{e:?}"))?
            .tracker
            .is_some()
        {
            return Ok(false);
        }
        // Labelled as the project's files are, so what a workflow reads there
        // may be filed here: text flows only to a tracker exactly as private.
        let attributes = self
            .library
            .work_targets
            .get(&crate::library_state::managed_project_target_id(project))
            .map(|target| target.attributes.clone())
            .unwrap_or_default();
        let owner = Authority::from(home.as_str());
        let handle = resource_handle(&workspace, PROJECT_TASKS).map_err(|e| format!("{e:?}"))?;
        let tracker = ProjectTracker {
            project_id: project.into(),
            workspace_id: workspace,
            queue: PROJECT_TASKS.into(),
            resource: ResourceRecord::new(
                Resource::input(
                    ResourceId::new(&handle),
                    ResourceKind::new("tracker"),
                    owner.clone(),
                ),
                ContentLocator::Content { handle },
                |_| owner.clone(),
            )
            .with_attributes(attributes),
        };
        self.store_mut()
            .append_record(
                &scope,
                DEFINITION,
                &encode(&tracker).map_err(|e| format!("{e:?}"))?,
            )
            .map_err(|error| format!("{error:?}"))?;
        Ok(true)
    }

    /// Ensure every project of this Home has its `tasks` tracker.
    pub fn ensure_project_tasks_trackers(&mut self) -> Result<(), String> {
        let projects: Vec<String> = self.library.projects.keys().cloned().collect();
        for project in projects {
            self.ensure_project_tasks_tracker(&project)?;
        }
        Ok(())
    }

    /// Request a fresh ordinary access basis. Terminal bases remain terminal;
    /// the returned reference identifies this request, not an access grant.
    pub fn request_project_tracker_access(
        &mut self,
        context: &AuthenticatedActionContext,
        project: &str,
        queue: &str,
        request_id: &str,
        recipient: &str,
        permission: TrackerPermission,
    ) -> Result<TrackerAccessBasis, AdmitError> {
        let scope = registry_scope(project, queue)?;
        let (snapshot, basis) = capture(
            self.store_ref(),
            self.home_id(),
            context,
            project,
            queue,
            Some(request_id),
        )?;
        let tracker = snapshot
            .registry
            .tracker
            .as_ref()
            .ok_or_else(|| refused("tracker is unavailable"))?;
        if snapshot.home_owned {
            return Err(refused(
                "a project's Home tracker admits every project member without a request",
            ));
        }
        let actor = context.actor().as_str();
        if (actor != recipient && actor != tracker.resource.resource.owner.as_str())
            || !snapshot
                .authority
                .org
                .can_access_project(recipient, project)
        {
            return Err(refused(
                "tracker access request exceeds recipient authority",
            ));
        }
        let grant = new_basis(
            &scope,
            actor,
            request_id,
            recipient,
            permission,
            snapshot.authority.purpose.clone(),
        )?;
        let command = encode(&("request_tracker_access.v1", actor, &grant))?;
        let replay = check_replay(&snapshot, &command)?;
        let facts = if replay {
            if snapshot.registry.bases.get(&grant.id) != Some(&grant) {
                return Err(refused(
                    "tracker request receipt has no original access basis",
                ));
            }
            Vec::new()
        } else {
            let mut facts = vec![fact(&scope, ACCESS_BASIS, &grant)?];
            facts.extend(
                access_events(
                    &access_scope(&scope, &grant.id),
                    &AccessState::default(),
                    AccessCommand::RequestAccess {
                        required: tracker.resource.stakeholders.clone(),
                    },
                )?
                .1,
            );
            facts
        };
        commit(
            self.store_mut(),
            &basis,
            &command_scope(&scope, actor),
            request_id,
            &command,
            &facts,
        )?;
        Ok(grant)
    }

    pub fn decide_project_tracker_access(
        &mut self,
        context: &AuthenticatedActionContext,
        project: &str,
        queue: &str,
        request_id: &str,
        access_basis: &str,
        decision: TrackerAccessDecision,
    ) -> Result<AccessPhase, AdmitError> {
        let scope = registry_scope(project, queue)?;
        let (snapshot, basis) = capture(
            self.store_ref(),
            self.home_id(),
            context,
            project,
            queue,
            Some(request_id),
        )?;
        let tracker = snapshot
            .registry
            .tracker
            .as_ref()
            .ok_or_else(|| refused("tracker is unavailable"))?;
        let grant = snapshot
            .registry
            .bases
            .get(access_basis)
            .ok_or_else(|| refused("tracker access basis is unavailable"))?;
        let actor = context.actor().as_str();
        let owner = &tracker.resource.resource.owner;
        let allowed = match decision {
            TrackerAccessDecision::Cancel => actor == grant.requested_by,
            _ => actor == owner.as_str(),
        };
        if !allowed {
            return Err(refused(
                "tracker access decision requires its actual approver",
            ));
        }
        if matches!(decision, TrackerAccessDecision::Approve)
            && (grant.purpose != snapshot.authority.purpose
                || !snapshot
                    .authority
                    .org
                    .can_access_project(&grant.recipient, project))
        {
            return Err(refused(
                "tracker approval exceeds current recipient or purpose authority",
            ));
        }
        let command = encode(&("decide_tracker_access.v1", actor, access_basis, decision))?;
        let state = &snapshot.access[access_basis];
        let (next, facts) = if check_replay(&snapshot, &command)? {
            (state.clone(), Vec::new())
        } else {
            let action = match decision {
                TrackerAccessDecision::Approve => AccessCommand::Approve(owner.clone()),
                TrackerAccessDecision::Reject => AccessCommand::Reject(owner.clone()),
                TrackerAccessDecision::Revoke => AccessCommand::Revoke,
                TrackerAccessDecision::Cancel => AccessCommand::Cancel,
            };
            access_events(&access_scope(&scope, access_basis), state, action)?
        };
        commit(
            self.store_mut(),
            &basis,
            &command_scope(&scope, actor),
            request_id,
            &command,
            &facts,
        )?;
        Ok(next.phase)
    }

    /// Return admitted resource metadata only. Actual issue payload resolution
    /// must additionally fence current authority through its native read.
    pub fn read_project_tracker(
        &self,
        context: &AuthenticatedActionContext,
        project: &str,
        queue: &str,
        permission: TrackerPermission,
    ) -> Result<ProjectTracker, AdmitError> {
        self.prepare_project_tracker_read(context, project, queue, permission)
            .map(|(tracker, _)| tracker)
    }

    /// Current metadata with the original resource-access observation. A caller
    /// resolving native payloads must combine and fence this basis through use.
    pub(crate) fn prepare_project_tracker_read(
        &self,
        context: &AuthenticatedActionContext,
        project: &str,
        queue: &str,
        permission: TrackerPermission,
    ) -> Result<(ProjectTracker, DispatchReadBasis), AdmitError> {
        let (snapshot, basis) = capture(
            self.store_ref(),
            self.home_id(),
            context,
            project,
            queue,
            None,
        )?;
        let tracker = snapshot
            .registry
            .tracker
            .as_ref()
            .ok_or_else(|| refused("tracker is unavailable"))?;
        if !permitted(&snapshot, context.actor().as_str(), TrackerPermission::Read)
            || !permitted(&snapshot, context.actor().as_str(), permission)
        {
            return Err(refused(
                "tracker requires a current recipient-specific access grant",
            ));
        }
        check_policy(
            &snapshot,
            &tracker.resource,
            if permission == TrackerPermission::Read {
                Action::Access
            } else {
                Action::Run
            },
        )?;
        Ok((tracker.clone(), basis))
    }
    /// Resolve assignment recipients from current directory and resource grants.
    /// This is an actor-authorized roster read, never recipient authentication.
    pub(crate) fn prepare_project_tracker_recipients(
        &self,
        context: &AuthenticatedActionContext,
        project: &str,
        queue: &str,
    ) -> Result<
        (
            ProjectTracker,
            std::collections::BTreeSet<String>,
            DispatchReadBasis,
        ),
        AdmitError,
    > {
        let (snapshot, basis) = capture(
            self.store_ref(),
            self.home_id(),
            context,
            project,
            queue,
            None,
        )?;
        let tracker = snapshot
            .registry
            .tracker
            .as_ref()
            .ok_or_else(|| refused("tracker is unavailable"))?;
        if !permitted(&snapshot, context.actor().as_str(), TrackerPermission::Read)
            || !permitted(
                &snapshot,
                context.actor().as_str(),
                TrackerPermission::Contribute,
            )
        {
            return Err(refused(
                "tracker requires a current recipient-specific access grant",
            ));
        }
        check_policy(&snapshot, &tracker.resource, Action::Run)?;
        let candidates: std::collections::BTreeSet<&String> = if snapshot.home_owned {
            snapshot
                .authority
                .org
                .members
                .values()
                .map(|member| &member.authority)
                .collect()
        } else {
            snapshot
                .registry
                .bases
                .values()
                .map(|grant| &grant.recipient)
                .collect()
        };
        let recipients = candidates
            .into_iter()
            .filter_map(|recipient| {
                if !snapshot
                    .authority
                    .org
                    .can_access_project(recipient, project)
                    || !permitted(&snapshot, recipient, TrackerPermission::Read)
                {
                    return None;
                }
                let attributes = if recipient == context.actor().as_str() {
                    snapshot.authority.attributes.clone()
                } else {
                    snapshot
                        .authority
                        .org
                        .with_directory_role(AuthorityAttributes::default(), recipient)
                };
                crate::policy_compiler::validate_resources_for_action(
                    &[&tracker.resource],
                    &attributes,
                    &snapshot.authority.policy,
                    snapshot.authority.purpose.as_deref(),
                    false,
                    Action::Access,
                )
                .ok()
                .map(|_| recipient.clone())
            })
            .collect();
        Ok((tracker.clone(), recipients, basis))
    }
}

#[cfg(test)]
#[path = "project_tracker_tests.rs"]
mod tests;

/// An explicit completion precondition; override is never inferred from actor identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrackerCompletionClaim {
    Holder { holder: String },
    Override,
}

/// Human intent to close one ordinary native issue. No caller supplies authority or storage.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteTrackerIssue {
    pub project: String,
    pub queue: String,
    pub item_id: String,
    /// Permanent subject returned by the admitted backlog read.
    pub subject_id: String,
    pub request_id: String,
    pub summary: String,
    pub claim: TrackerCompletionClaim,
}

#[path = "project_tracker_query.rs"]
mod query;
pub use query::{
    ProjectTrackerBacklog, ProjectTrackerIssue, ProjectTrackerTasks, ReadableProjectTracker,
};
