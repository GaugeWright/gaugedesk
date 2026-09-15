//! Revalidate original invocation and prepare its exact retained resource set.
use super::*;

pub(super) struct PreparedWorkflow {
    pub project: String,
    pub authority: authority::LaunchAuthority,
    pub trackers: BTreeMap<String, crate::project_tracker::ProjectTracker>,
    pub key: Arc<PreparedScopeKey>,
    pub protection: WorkflowProtection,
    pub storage: NativeWorkflowStorage,
    pub root: GovernanceRootVerifier,
    pub policy: crate::action_policy::RetainedActionPolicy,
    pub input: ActionInput,
    pub action: CompiledHostAction,
    pub delivery: CommittedDispatch<HostActionCommand>,
}

impl Workbench {
    pub(super) fn prepare_project_workflow(
        &mut self,
        context: &AuthenticatedActionContext,
        scope: &str,
        command: HostActionCommand,
        limits: ProjectWorkflowLimits,
    ) -> Result<PreparedWorkflow, String> {
        if command.operation != OPERATION
            || command.provenance.initiator != context.actor().as_str()
            || command.provenance.executor != context.actor().as_str()
            || command.provenance.origin != "folder.launch"
            || !command.provenance.delegation.is_empty()
            || !command.provenance.causes.is_empty()
        {
            return Err("workflow original actor binding is invalid".into());
        }
        let project = command
            .scope
            .strip_prefix("project::")
            .and_then(|scope| scope.split_once("::workflow::"))
            .map(|(project, _)| project)
            .ok_or("workflow project scope is invalid")?
            .to_owned();
        if scope != request_scope(&project, context.actor().as_str(), &command.request_id)? {
            return Err("workflow command belongs to another request".into());
        }
        let binding = source_binding(&command)?;
        let request = ProjectWorkflowLaunch {
            project: project.clone(),
            target: binding.target,
            path: binding.path,
            cut: binding.cut,
            request_id: command.request_id.clone(),
            inputs: BTreeMap::new(),
        };
        let mut authority = self.prepare_workflow_authority(context, &request)?;
        let key = self.workflow_key(&project, &authority.workspace, false)?;
        let protection =
            WorkflowProtection::new(&authority.workspace, key.clone()).map_err(debug_error)?;
        let storage = self.workflow_storage(&authority.workspace)?;
        let (root, trust_basis) = self.workflow_policy_root(&command.issuer)?;
        authority.basis = authority.basis.combine(trust_basis).map_err(debug_error)?;
        let identity = ActionPolicyIdentity {
            issuer: command.issuer.clone(),
            scope: command.scope.clone(),
            request_id: command.request_id.clone(),
        };
        let policy = load_project_action_policy(
            self.store_ref(),
            &project,
            &identity,
            &command.policy,
            &root,
        )?;
        let mut writer = self.store_ref().sibling().map_err(debug_error)?;
        let input = source_reference(&command)?;
        let source = writer
            .with_dispatch_basis(&authority.basis, || {
                key.retain(|| -> std::io::Result<_> {
                    let stores = storage
                        .open_existing_protected(&protection)
                        .map_err(|error| std::io::Error::other(debug_error(error)))?;
                    let inputs = NativeActionInputCustody::new(
                        stores.inputs,
                        &authority.workspace,
                        limits.source_bytes.max(limits.input_bytes),
                    )
                    .map_err(|error| std::io::Error::other(debug_error(error)))?;
                    let source = inputs
                        .resolve(&input)
                        .map_err(|error| std::io::Error::other(debug_error(error)))?;
                    if source.content.len() > limits.source_bytes
                        || source.content_hash != binding.content_hash
                    {
                        return Err(std::io::Error::other(
                            "retained workflow source binding changed",
                        ));
                    }
                    Ok(source.content)
                })
            })
            .map_err(debug_error)?
            .map_err(debug_error)?;
        let action = compile(&source)?;
        if action.version_ref() != command.program_version_ref
            || action.input_schema_ref() != command.input_schema_ref
        {
            return Err("retained workflow source has a different program identity".into());
        }
        let (authority, trackers) =
            authority::bind_program(self, context, &request, &action, authority)?;
        if command.resources.len() != trackers.len() + 1 {
            return Err("workflow resource set changed".into());
        }
        for (queue, tracker) in &trackers {
            let resource = command
                .resources
                .get(queue)
                .ok_or("workflow tracker binding is missing")?;
            let expected = ActionResource {
                resource: ResourceRef {
                    handle: tracker.resource.resource.id.as_str().into(),
                    kind: "tracker".into(),
                    selector: Some(queue.clone()),
                    writable: Some(true),
                },
                basis: ActionBasis::Version {
                    version_ref: whipplescript_store::stable_hash_hex(
                        &serde_json::to_string(&tracker).map_err(debug_error)?,
                    ),
                },
                label_ref: format!("policy:{}:{queue}", command.policy.envelope_hash),
            };
            if resource != &expected {
                return Err("workflow original tracker binding changed".into());
            }
        }
        if whipplescript_kernel::gov::canonicalize(policy.signed_envelope())?
            != whipplescript_kernel::gov::canonicalize(&authority.policy.to_json()?)?
        {
            return Err("workflow current policy differs from its admitted ceiling".into());
        }
        let (_, receipt_basis) = self
            .store_ref()
            .read_for_dispatch(&[scope, crate::federation::BRIDGE_SCOPE], |_| Ok(()))
            .map_err(debug_error)?;
        let delivery: CommittedDispatch<HostActionCommand> = self
            .store_mut()
            .committed_dispatch::<ProductActionAdmission>(scope, &command.request_id)
            .map_err(debug_error)?
            .ok_or("workflow has no committed product admission")?;
        if delivery.command != command
            || delivery.dispatch.runtime_ref != format!("workspace:{}", authority.workspace)
            || delivery.dispatch.command_ref != command.fingerprint().map_err(debug_error)?
        {
            return Err("workflow dispatch differs from its original admission".into());
        }
        let mut authority = authority;
        authority.basis = authority
            .basis
            .combine(receipt_basis)
            .map_err(debug_error)?;
        Ok(PreparedWorkflow {
            project,
            authority,
            trackers,
            key,
            protection,
            storage,
            root,
            policy,
            input,
            action,
            delivery,
        })
    }
}
