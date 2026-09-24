//! Saved-source product admission and recoverable native delivery.
use super::*;
use crate::{
    action_policy::{
        load_project_action_policy, prepare_project_action_policy, ActionPolicyIdentity,
    },
    content_vault::PreparedScopeKey,
};
use gaugedesk_core::signature::{verify_signature, Signature, SigningKey};
use gaugedesk_store::{
    command_dispatch::{CommandDispatch, CommittedDispatch},
    CommandRecordFact,
};
use gaugedesk_whip_runtime::{
    host_actions::facade::{ActionInputResolver, GovernedHostFacade, HostFacadeError},
    ifc, GovernanceRootVerifier, ProtocolError, ResourceRef,
};
use gaugedesk_workspace::{NativeWorkflowStorage, WorkflowProtection, WorkflowProtectionMode};
use std::sync::Arc;

const SOURCE: &str = "@source";
const OPERATION: &str = "workflow.launch";

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceBinding {
    pub(super) target: String,
    pub(super) path: String,
    pub(super) cut: String,
    content_hash: String,
}

fn source_reference(command: &HostActionCommand) -> Result<ActionInput, String> {
    let source = command
        .resources
        .get(SOURCE)
        .ok_or("workflow source binding is missing")?;
    let ActionBasis::Version { version_ref } = &source.basis else {
        return Err("workflow source has no immutable input version".into());
    };
    if source.resource.kind != "method"
        || source.resource.handle != "workflow:source"
        || source.resource.writable != Some(false)
    {
        return Err("workflow source binding is invalid".into());
    }
    Ok(ActionInput {
        handle: source.resource.handle.clone(),
        label_ref: source.label_ref.clone(),
        version_ref: version_ref.clone(),
    })
}
pub(super) fn source_binding(command: &HostActionCommand) -> Result<SourceBinding, String> {
    serde_json::from_str(
        command
            .resources
            .get(SOURCE)
            .and_then(|resource| resource.resource.selector.as_deref())
            .ok_or("workflow source coordinates are missing")?,
    )
    .map_err(debug_error)
}
fn compile(source: &str) -> Result<CompiledHostAction, String> {
    let action = CompiledHostAction::compile_materialized_inputs(OPERATION, source, None)?;
    if !action.program().includes.is_empty() {
        return Err("workflow includes require retained dependency bindings".into());
    }
    Ok(action)
}

struct ExactAdmission<'a> {
    command: &'a HostActionCommand,
    key: gaugedesk_core::ids::PublicKey,
}
impl ActionAdmissionVerifier for ExactAdmission<'_> {
    fn verify(
        &self,
        command: &HostActionCommand,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if command != self.command
            || bytes != self.command.signing_bytes()?
            || !verify_signature(bytes, &Signature::new(proof), &self.key).unwrap_or(false)
        {
            return Err(ProtocolError::Mismatch(
                "current project workflow admission",
            ));
        }
        Ok(())
    }
}
/// Constructed only inside the original input authority's retained callback.
struct Inputs<'a> {
    command: &'a HostActionCommand,
    values: BTreeMap<String, serde_json::Value>,
}
impl ActionInputResolver for Inputs<'_> {
    fn with_inputs<T>(
        &self,
        admission: &VerifiedActionAdmission,
        consume: impl FnOnce(BTreeMap<String, serde_json::Value>) -> T,
    ) -> Result<T, HostFacadeError> {
        if admission.command() != self.command {
            return Err(ProtocolError::Mismatch("retained workflow inputs").into());
        }
        Ok(consume(self.values.clone()))
    }
}

impl Workbench {
    pub(crate) fn workflow_storage(
        &self,
        workspace: &str,
    ) -> Result<NativeWorkflowStorage, String> {
        self.collaboration_workspaces
            .get(workspace)
            .ok_or("project collaboration workspace is not open")?
            .native_workflow_storage()
            .map_err(debug_error)
    }
    pub(crate) fn workflow_key(
        &self,
        project: &str,
        workspace: &str,
        initialize: bool,
    ) -> Result<Arc<PreparedScopeKey>, String> {
        let storage = self.workflow_storage(workspace)?;
        let mode = storage.protection_mode(workspace).map_err(debug_error)?;
        if mode == Some(WorkflowProtectionMode::Plain) || (mode.is_none() && !initialize) {
            return Err("workflow requires existing protected project storage".into());
        }
        let vault = self
            .content_vault
            .as_ref()
            .ok_or("project workflow custody is not configured")?;
        let scope = content_scope(project).map_err(debug_error)?;
        if mode.is_none() {
            vault.initialize_scope_key(&scope).map_err(debug_error)?;
        }
        vault
            .prepare_scope_key(&scope)
            .map(Arc::new)
            .map_err(debug_error)
    }
    /// The root a run's signed policy is checked against. This Home's own key
    /// for its own runs; for a run that arrived with a relocated project, the key
    /// pinned when that move was admitted (DR-0201), which outlives the pairing;
    /// otherwise the issuer's current, unexpired pairing.
    pub(super) fn workflow_policy_root(
        &self,
        project: &str,
        issuer: &str,
    ) -> Result<
        (
            GovernanceRootVerifier,
            gaugedesk_store::command_dispatch::DispatchReadBasis,
        ),
        String,
    > {
        use crate::federation::{BridgeRecord, BRIDGE_SCOPE};
        let pins = crate::federation::workflow_signers_scope(project);
        let ((key, expiry), basis) = self
            .store_ref()
            .read_for_dispatch(&[BRIDGE_SCOPE, &pins], |store| {
                if issuer == self.authority().as_str() {
                    let key = SigningKey::from_seed(&self.governance_seed()).map_err(|_| {
                        gaugedesk_store::AdmitError::Rejected(gaugedesk_core::Rejection {
                            reason: "local workflow signing root is unavailable",
                        })
                    })?;
                    return Ok((key.public_key(), None));
                }
                store.retained_events(&pins)?;
                let mut pinned = None;
                for row in store.records(&pins, crate::federation::WORKFLOW_SIGNER_PIN_KIND)? {
                    let pin: crate::federation::WorkflowSignerPin = serde_json::from_str(&row)?;
                    if pin.issuer == issuer {
                        pinned = Some(pin.governance_pubkey);
                    }
                }
                if let Some(key) = pinned {
                    return Ok((gaugedesk_core::ids::PublicKey::new(key), None));
                }
                // Read the authoritative roster, including tombstones and revokes.
                // A cached pairing or a key carried by the offer is not this evidence.
                store.retained_events(BRIDGE_SCOPE)?;
                let mut current = None;
                for row in store.records(BRIDGE_SCOPE, "bridge")? {
                    let record: BridgeRecord = serde_json::from_str(&row)?;
                    if record.id == issuer {
                        current = Some(record);
                    }
                }
                let record = current
                    .filter(|record| {
                        record.op == crate::library::RecordOp::Upsert
                            && record.active
                            && record.ticket.authority == issuer
                            && record.ticket.expiry > crate::account::session_now_ms() / 1000
                    })
                    .ok_or(gaugedesk_store::AdmitError::Rejected(
                        gaugedesk_core::Rejection {
                            reason: "original workflow signing authority is not currently trusted",
                        },
                    ))?;
                Ok((
                    gaugedesk_core::ids::PublicKey::new(record.ticket.governance_pubkey),
                    Some(record.ticket.expiry),
                ))
            })
            .map_err(debug_error)?;
        let basis = match expiry {
            Some(expiry) => basis.with_deadline(
                std::time::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_secs(expiry))
                    .ok_or("workflow signing trust deadline is invalid")?,
            ),
            None => basis,
        };
        Ok((
            GovernanceRootVerifier::new(gaugedesk_core::ids::AuthorityId::new(issuer), key),
            basis,
        ))
    }

    pub fn launch_project_workflow(
        &mut self,
        context: &AuthenticatedActionContext,
        request: &ProjectWorkflowLaunch,
        limits: ProjectWorkflowLimits,
    ) -> Result<ProjectWorkflowInvocation, String> {
        let result = self.launch_project_workflow_admitted(context, request, limits);
        if result.is_ok() {
            self.hint_project_workflows(
                result
                    .as_ref()
                    .map(|invocation| invocation.product_scope.clone())
                    .unwrap_or_default(),
            );
        }
        result
    }

    fn launch_project_workflow_admitted(
        &mut self,
        context: &AuthenticatedActionContext,
        request: &ProjectWorkflowLaunch,
        limits: ProjectWorkflowLimits,
    ) -> Result<ProjectWorkflowInvocation, String> {
        if matches!(
            context.authentication(),
            crate::identity::ActorAuthentication::ProjectWorkflowInvocation { .. }
        ) {
            return Err("workflow authority cannot launch a workflow".into());
        }
        let scope = request_scope(
            &request.project,
            context.actor().as_str(),
            &request.request_id,
        )?;
        if request.path.is_empty()
            || request
                .path
                .split('/')
                .any(|part| matches!(part, "" | "." | ".."))
            || request.path.contains(['\\', '\0'])
            || gaugedesk_boundary::is_control_surface_path(&request.path)
            || request.cut.is_empty()
        {
            return Err("workflow source coordinates are invalid".into());
        }
        let authority = self.prepare_workflow_authority(context, request)?;
        let mut writer = self.store_ref().sibling().map_err(debug_error)?;
        let existing = writer
            .fold::<ProductActionAdmission>(&scope)
            .map_err(debug_error)?
            .command;
        if let Some(command) = existing {
            let binding = source_binding(&command)?;
            if binding.target != request.target
                || binding.path != request.path
                || binding.cut != request.cut
            {
                return Err("workflow request key has different source intent".into());
            }
            return self.deliver_project_workflow(
                context,
                &scope,
                command,
                limits,
                Some(&request.inputs),
            );
        }
        let target = self
            .targets
            .get(&request.target)
            .ok_or("workflow source target is not open")?;
        let source = writer
            .with_dispatch_basis(&authority.basis, || {
                target.workflow_source(&request.path, &request.cut, limits.source_bytes)
            })
            .map_err(debug_error)?
            .map_err(debug_error)?;
        let action = compile(&source.content)?;
        let declared: std::collections::BTreeSet<_> = action
            .program()
            .workflow_contracts
            .iter()
            .filter(|contract| {
                contract.kind == gaugedesk_whip_runtime::host_actions::IrWorkflowContractKind::Input
            })
            .map(|contract| contract.name.as_str())
            .collect();
        if declared != request.inputs.keys().map(String::as_str).collect() {
            return Err("workflow input names do not match its declared contract".into());
        }
        whipplescript_kernel::workflow_input::validate_workflow_start_input(
            action.program(),
            &serde_json::to_value(&request.inputs).map_err(debug_error)?,
        )
        .map_err(debug_error)?;
        let (authority, trackers) =
            authority::bind_program(self, context, request, &action, authority)?;
        let key = self.workflow_key(&request.project, &authority.workspace, true)?;
        let protection =
            WorkflowProtection::new(&authority.workspace, key.clone()).map_err(debug_error)?;
        let storage = self.workflow_storage(&authority.workspace)?;
        let identity = ActionPolicyIdentity {
            issuer: self.authority().as_str().into(),
            scope: format!(
                "project::{}::workflow::{}",
                request.project,
                hex::encode(context.actor().as_str())
            ),
            request_id: request.request_id.clone(),
        };
        let signing_key = SigningKey::from_seed(&self.governance_seed()).map_err(debug_error)?;
        let policy = prepare_project_action_policy(
            self.store_mut(),
            &request.project,
            &identity,
            &authority.policy,
            &signing_key,
        )?;
        let (root, _) = self.workflow_policy_root(&request.project, &identity.issuer)?;
        let envelope =
            ifc::VerifiedEnvelope::verify_signed_text_with(policy.signed_envelope(), &root)?;
        if !ifc::check_with_envelope(action.program(), &envelope).is_empty() {
            return Err("workflow violates admitted resource policy".into());
        }
        let label = |handle: &str| format!("policy:{}:{handle}", policy.policy_ref().envelope_hash);
        let command = writer
            .with_dispatch_record_admission(&authority.basis, |admission| {
                key.retain(|| -> std::io::Result<_> {
                    let stores = storage
                        .initialize_protected(&protection)
                        .map_err(|error| std::io::Error::other(debug_error(error)))?;
                    let inputs = NativeActionInputCustody::new(
                        stores.inputs,
                        &authority.workspace,
                        limits.source_bytes.max(limits.input_bytes),
                    )
                    .map_err(|error| std::io::Error::other(debug_error(error)))?;
                    let source_input = inputs
                        .prepare(
                            "workflow:source",
                            &label("workflow:source"),
                            &source.content,
                        )
                        .map_err(|error| std::io::Error::other(debug_error(error)))?;
                    let mut command_inputs = BTreeMap::new();
                    let mut input_bytes = 0usize;
                    for (name, value) in &request.inputs {
                        let content = serde_json::to_string(value)
                            .map_err(|error| std::io::Error::other(debug_error(error)))?;
                        input_bytes = input_bytes.checked_add(content.len()).ok_or_else(|| {
                            std::io::Error::other("workflow inputs exceed budget")
                        })?;
                        if input_bytes > limits.input_bytes {
                            return Err(std::io::Error::other("workflow inputs exceed budget"));
                        }
                        let handle = format!("input:{name}");
                        command_inputs.insert(
                            name.clone(),
                            inputs
                                .prepare(&handle, &label(&handle), &content)
                                .map_err(|error| std::io::Error::other(debug_error(error)))?,
                        );
                    }
                    let mut resources = BTreeMap::new();
                    resources.insert(
                        SOURCE.into(),
                        ActionResource {
                            resource: ResourceRef {
                                handle: "workflow:source".into(),
                                kind: "method".into(),
                                selector: Some(
                                    serde_json::to_string(&SourceBinding {
                                        target: request.target.clone(),
                                        path: request.path.clone(),
                                        cut: source.cut.clone(),
                                        content_hash: source.content_hash.clone(),
                                    })
                                    .map_err(|error| std::io::Error::other(debug_error(error)))?,
                                ),
                                writable: Some(false),
                            },
                            basis: ActionBasis::Version {
                                version_ref: source_input.version_ref.clone(),
                            },
                            label_ref: source_input.label_ref.clone(),
                        },
                    );
                    for (queue, tracker) in &trackers {
                        let handle = tracker.resource.resource.id.as_str();
                        resources.insert(
                            queue.clone(),
                            ActionResource {
                                resource: ResourceRef {
                                    handle: handle.into(),
                                    kind: "tracker".into(),
                                    selector: Some(queue.clone()),
                                    writable: Some(true),
                                },
                                basis: ActionBasis::Version {
                                    version_ref: whipplescript_store::stable_hash_hex(
                                        &serde_json::to_string(tracker).map_err(|error| {
                                            std::io::Error::other(debug_error(error))
                                        })?,
                                    ),
                                },
                                label_ref: label(queue),
                            },
                        );
                    }
                    let command = HostActionCommand {
                        protocol: HOST_ACTION_PROTOCOL.into(),
                        issuer: identity.issuer.clone(),
                        scope: identity.scope.clone(),
                        request_id: request.request_id.clone(),
                        operation: OPERATION.into(),
                        program_version_ref: action.version_ref().into(),
                        input_schema_ref: action.input_schema_ref().into(),
                        policy: policy.policy_ref().clone(),
                        provenance: ActionProvenance {
                            initiator: context.actor().as_str().into(),
                            executor: context.actor().as_str().into(),
                            delegation: vec![],
                            origin: "folder.launch".into(),
                            causes: vec![],
                        },
                        inputs: command_inputs,
                        resources,
                    };
                    let dispatch = CommandDispatch {
                        runtime_ref: format!("workspace:{}", authority.workspace),
                        command_ref: command
                            .fingerprint()
                            .map_err(|error| std::io::Error::other(debug_error(error)))?,
                    };
                    let retained: Vec<_> = command
                        .inputs
                        .values()
                        .cloned()
                        .chain(std::iter::once(source_input))
                        .collect();
                    inputs
                        .publish(&retained, || {
                            admission
                                .commit_dispatch::<ProductActionAdmission>(
                                    &scope,
                                    &request.request_id,
                                    command.clone(),
                                    &dispatch,
                                )
                                .map_err(|error| {
                                    whipplescript_store::StoreError::Conflict(debug_error(error))
                                })
                        })
                        .map_err(|error| std::io::Error::other(debug_error(error)))?;
                    Ok(command)
                })
            })
            .map_err(debug_error)?
            .map_err(debug_error)?;
        self.deliver_project_workflow(context, &scope, command, limits, None)
    }
}

#[path = "project_workflow_delivery.rs"]
mod delivery;

#[path = "project_workflow_execution.rs"]
mod execution;
#[path = "project_workflow_preparation.rs"]
mod preparation;

#[path = "project_tracker_completion.rs"]
mod tracker_completion;
#[path = "project_tracker_control.rs"]
pub(crate) mod tracker_control;
