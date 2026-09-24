//! Current project/source authority for ordinary folder invocation.
use super::*;
use crate::{
    library::{Library, WorkTargetOwner, WorkTargetStatus, LIBRARY_SCOPE},
    org::{Org, ORG_SCOPE},
};
use gaugedesk_core::{
    abac::Action,
    boundary::Authority,
    resource::{ContentLocator, Resource, ResourceId, ResourceKind, ResourceRecord},
};
use gaugedesk_store::{command_dispatch::DispatchReadBasis, AdmitError, Store};
use gaugedesk_whip_runtime::{HostGovernancePolicy, ResourcePolicy};
use std::collections::BTreeSet;

pub(super) struct LaunchAuthority {
    pub workspace: String,
    pub source: ResourceRecord,
    pub policy: HostGovernancePolicy,
    pub basis: DispatchReadBasis,
}

fn denied(reason: &'static str) -> AdmitError {
    AdmitError::Rejected(gaugedesk_core::Rejection { reason })
}

impl Workbench {
    pub(super) fn prepare_workflow_authority(
        &self,
        context: &AuthenticatedActionContext,
        request: &ProjectWorkflowLaunch,
    ) -> Result<LaunchAuthority, String> {
        let handoff = crate::federation::handoff_scope(&request.project);
        let ((workspace, source, actor_attributes, org_policy, purpose, deadline), basis) = self
            .store_ref()
            .read_for_dispatch(
                &[
                    LIBRARY_SCOPE,
                    ORG_SCOPE,
                    crate::account_auth::ACCOUNT_AUTH_SCOPE,
                    crate::mobile_machine_session::SCOPE,
                    &handoff,
                ],
                |store: &Store| {
                    let deadline = crate::identity::revalidate_workflow_context(
                        store,
                        self.home_id(),
                        context,
                    )?;
                    crate::federation::require_project_writes_available(store, &request.project)?;
                    store.retained_events(LIBRARY_SCOPE)?;
                    store.retained_events(ORG_SCOPE)?;
                    let library = Library::rebuild(store)?;
                    let org = Org::rebuild(store)?;
                    let project = library
                        .projects
                        .get(&request.project)
                        .ok_or_else(|| denied("workflow project is unavailable"))?;
                    let workspace = library
                        .project_collaboration_workspaces
                        .get(&request.project)
                        .ok_or_else(|| denied("workflow workspace is unavailable"))?;
                    let target = library
                        .work_targets
                        .get(&request.target)
                        .ok_or_else(|| denied("workflow source target is unavailable"))?;
                    if &project.home_id != self.home_id()
                        || workspace.home_id != project.home_id
                        || workspace.workspace_id.is_empty()
                        || library
                            .project_collaboration_workspaces
                            .values()
                            .any(|other| {
                                other.project_id != request.project
                                    && other.workspace_id == workspace.workspace_id
                            })
                        || !org.can_access_project(context.actor().as_str(), &request.project)
                        || target.owner
                            != (WorkTargetOwner::Project {
                                project_id: request.project.clone(),
                            })
                        || target.status != WorkTargetStatus::Available
                        || !target.capabilities.read
                        || (target.authority != context.actor().as_str()
                            && !target
                                .parties
                                .iter()
                                .any(|party| party == context.actor().as_str()))
                        || !crate::engagement_routes::path_is_in_scope(
                            &request.path,
                            &target.path_scope,
                        )
                    {
                        return Err(denied(
                            "workflow exceeds current project, source or Home authority",
                        ));
                    }
                    let owner = Authority::from(target.authority.as_str());
                    let source = ResourceRecord {
                        resource: Resource::input(
                            ResourceId::new(format!("workflow-source:{}", target.id)),
                            ResourceKind::context(),
                            owner.clone(),
                        ),
                        stakeholders: target
                            .parties
                            .iter()
                            .map(|party| Authority::from(party.as_str()))
                            .chain(std::iter::once(owner))
                            .collect(),
                        locator: ContentLocator::Content {
                            handle: target.locator_handle.clone(),
                        },
                        tombstoned: false,
                        attributes: target.attributes.clone(),
                    };
                    Ok((
                        workspace.workspace_id.clone(),
                        source,
                        org.with_directory_role(context.claims().clone(), context.actor().as_str()),
                        org.policy(),
                        project.run_purpose.clone(),
                        deadline,
                    ))
                },
            )
            .map_err(debug_error)?;
        crate::policy_compiler::validate_resources_for_action(
            &[&source],
            &actor_attributes,
            &org_policy,
            purpose.as_deref(),
            false,
            Action::Run,
        )?;
        let readers = crate::policy_compiler::resource_reader_roles(&source);
        let clearances = crate::policy_compiler::actor_clearances(
            &actor_attributes,
            purpose.as_deref(),
            std::slice::from_ref(&source),
            std::iter::empty(),
        );
        if !readers.is_subset(&clearances) {
            return Err("workflow source exceeds actor clearance".into());
        }
        let actor = crate::policy_compiler::authority_role(context.actor().as_str());
        let policy = HostGovernancePolicy {
            resources: BTreeMap::from([(
                "workflow:source".into(),
                ResourcePolicy {
                    reader: readers,
                    writer: BTreeSet::new(),
                    ..Default::default()
                },
            )]),
            bindings: BTreeMap::from([("workflow:source".into(), "workflow:source".into())]),
            parties: BTreeMap::from([(context.actor().as_str().into(), actor.clone())]),
            delegations: clearances
                .into_iter()
                .filter(|role| role != &actor)
                .map(|role| [actor.clone(), role])
                .collect(),
            ..Default::default()
        };
        let basis = match deadline {
            Some(ms) => basis.with_deadline(
                std::time::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_millis(ms))
                    .ok_or("workflow authentication deadline is invalid")?,
            ),
            None => basis,
        };
        Ok(LaunchAuthority {
            workspace,
            source,
            policy,
            basis,
        })
    }
}

pub(super) fn bind_program(
    wb: &Workbench,
    context: &AuthenticatedActionContext,
    request: &ProjectWorkflowLaunch,
    action: &CompiledHostAction,
    mut authority: LaunchAuthority,
) -> Result<
    (
        LaunchAuthority,
        BTreeMap<String, crate::project_tracker::ProjectTracker>,
    ),
    String,
> {
    let actor = crate::policy_compiler::authority_role(context.actor().as_str());
    let source_readers = crate::policy_compiler::resource_reader_roles(&authority.source);
    let mut evidence_readers = source_readers.clone();
    let mut trackers = BTreeMap::new();
    for declaration in &action.program().trackers {
        if declaration.provider != "builtin" {
            return Err("workflow tracker has no admitted native provider".into());
        }
        let (tracker, basis) = wb
            .prepare_project_tracker_read(
                context,
                &request.project,
                &declaration.name,
                crate::project_tracker::TrackerPermission::Contribute,
            )
            .map_err(debug_error)?;
        if tracker.workspace_id != authority.workspace {
            return Err("workflow tracker belongs to another workspace".into());
        }
        let readers = crate::policy_compiler::resource_reader_roles(&tracker.resource);
        // Source literals must not escape the source compartment by becoming a
        // tracker title/body. No endorsement or declassification is inferred.
        if !source_readers.is_subset(&readers) {
            return Err("workflow source cannot flow to this tracker".into());
        }
        evidence_readers.extend(readers.iter().cloned());
        let handle = tracker.resource.resource.id.as_str().to_owned();
        authority.policy.resources.insert(
            handle.clone(),
            ResourcePolicy {
                reader: readers.clone(),
                writer: BTreeSet::new(),
                ..Default::default()
            },
        );
        authority
            .policy
            .bindings
            .insert(declaration.name.clone(), handle);
        authority.policy.delegations.extend(
            readers
                .into_iter()
                .filter(|role| role != &actor)
                .map(|role| [actor.clone(), role]),
        );
        authority.basis = authority.basis.combine(basis).map_err(debug_error)?;
        trackers.insert(declaration.name.clone(), tracker);
    }
    authority.policy.delegations.sort();
    authority.policy.delegations.dedup();
    for contract in &action.program().workflow_contracts {
        if contract.kind == gaugedesk_whip_runtime::host_actions::IrWorkflowContractKind::Input {
            let handle = format!("input:{}", contract.name);
            let label = ResourcePolicy {
                reader: source_readers.clone(),
                writer: BTreeSet::new(),
                ..Default::default()
            };
            authority
                .policy
                .resources
                .insert(handle.clone(), label.clone());
            authority.policy.bindings.insert(handle.clone(), handle);
            authority.policy.resources.insert(
                format!(
                    "fact:{}",
                    whipplescript_kernel::rule_lowering::ir_type_name(&contract.ty)
                ),
                label,
            );
        }
    }
    for sink in ["result", "error"] {
        authority.policy.resources.insert(
            sink.into(),
            ResourcePolicy {
                reader: evidence_readers.clone(),
                writer: BTreeSet::new(),
                ..Default::default()
            },
        );
        authority.policy.bindings.insert(sink.into(), sink.into());
    }
    // These are native package capabilities, not a tutorial-specific engine.
    authority
        .policy
        .capabilities
        .extend(["tracker.file".into(), "tracker.wait_closed".into()]);
    authority.policy.validate()?;
    Ok((authority, trackers))
}
