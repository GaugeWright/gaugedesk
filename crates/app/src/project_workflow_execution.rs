//! One bounded native step under current project and tracker authority.
use super::*;
use gaugedesk_core::ids::PublicKey;
use gaugedesk_whip_runtime::host_actions::{
    action_result::{
        ActionInstanceStatus, ActionResultSnapshot, ActionResultVerifier, ReadActionResult,
        ACTION_RESULT_PROTOCOL,
    },
    execution::{
        effect_observation_fingerprint, ActionExecutionVerifier, ExecuteActionEffect,
        ACTION_EXECUTION_PROTOCOL,
    },
    NativeStores,
};
use std::collections::BTreeSet;
use whipplescript_kernel::{
    host_facade::{TrackerExecutionAuthority, TrackerWaitAuthority},
    tracker_filing::TrackerBinding,
};
use whipplescript_store::{
    tracker_filing::TrackerFiling, ClaimableEffect, RuntimeStore, StoreError, StoreResult,
};

fn runtime_error(error: impl std::fmt::Debug) -> StoreError {
    StoreError::Conflict(debug_error(error))
}

struct ReadAuthority<'a> {
    request: &'a ReadActionResult,
    key: PublicKey,
}
impl ActionResultVerifier for ReadAuthority<'_> {
    fn verify(
        &self,
        request: &ReadActionResult,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if request != self.request
            || bytes != request.signing_bytes()?
            || !verify_signature(bytes, &Signature::new(proof), &self.key).unwrap_or(false)
        {
            return Err(ProtocolError::Mismatch(
                "current project workflow observation",
            ));
        }
        Ok(())
    }
}

pub(super) fn read_result(
    runtime: &GovernedHostFacade<NativeStores>,
    invocation: &ProjectWorkflowInvocation,
    key: &SigningKey,
) -> StoreResult<ActionResultSnapshot> {
    let command = &invocation.command;
    let request = ReadActionResult {
        protocol: ACTION_RESULT_PROTOCOL.into(),
        issuer: command.issuer.clone(),
        scope: command.scope.clone(),
        policy: command.policy.clone(),
        provenance: command.provenance.clone(),
        admission: invocation.admission.clone(),
        evidence_handle: "result".into(),
        evidence_label_ref: format!("policy:{}:result", command.policy.envelope_hash),
        through: None,
    };
    let bytes = request.signing_bytes().map_err(runtime_error)?;
    let authority = ReadAuthority {
        request: &request,
        key: key.public_key(),
    };
    let snapshot = runtime
        .read_action_result(request.clone(), &authority, key.sign(&bytes).as_bytes())
        .map_err(runtime_error)?;
    if snapshot.command != *command {
        return Err(runtime_error(
            "workflow native admission differs from its product command",
        ));
    }
    Ok(snapshot)
}

/// Constructed only inside product, project-key and retained-input exclusions.
/// The opened native store is the prepared collaboration workspace, and these
/// recipient grants were captured from that exact tracker's current registry.
struct EffectAuthority<'a> {
    request: &'a ExecuteActionEffect,
    command: &'a HostActionCommand,
    binding: &'a TrackerBinding,
    recipients: &'a BTreeSet<String>,
    key: PublicKey,
}
impl ActionExecutionVerifier for EffectAuthority<'_> {
    fn authenticate(
        &self,
        request: &ExecuteActionEffect,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if request != self.request
            || bytes != request.signing_bytes()?
            || !verify_signature(bytes, &Signature::new(proof), &self.key).unwrap_or(false)
        {
            return Err(ProtocolError::Mismatch(
                "current project workflow execution",
            ));
        }
        Ok(())
    }
    fn authorize(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        effect: &ClaimableEffect,
    ) -> Result<(), ProtocolError> {
        if request != self.request
            || original != self.command
            || request.provenance != original.provenance
            || request.effect_fingerprint != effect_observation_fingerprint(effect)?
            || (effect.kind != "tracker.file"
                && !whipplescript_kernel::tracker_wait::is_tracker_wait(effect))
        {
            return Err(ProtocolError::Mismatch("workflow original effect ceiling"));
        }
        Ok(())
    }
}
impl EffectAuthority<'_> {
    fn observation(
        &self,
        request: &ExecuteActionEffect,
        binding: &TrackerBinding,
    ) -> Result<(), ProtocolError> {
        if request != self.request
            || binding != self.binding
            || binding.scope != self.command.scope
            || self.command.resources.get(&binding.queue) != Some(&binding.resource)
        {
            return Err(ProtocolError::Mismatch("workflow actual tracker store"));
        }
        Ok(())
    }
}
impl TrackerExecutionAuthority for EffectAuthority<'_> {
    fn authorize_observation(
        &self,
        request: &ExecuteActionEffect,
        binding: &TrackerBinding,
    ) -> Result<(), ProtocolError> {
        self.observation(request, binding)
    }
    fn authorize_filing(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        binding: &TrackerBinding,
        filing: &TrackerFiling,
    ) -> Result<(), ProtocolError> {
        self.observation(request, binding)?;
        if original != self.command
            || filing.instance_id != request.admission.instance_ref
            || filing.effect_id != request.effect_id
            || filing.actor != request.provenance.executor
            || filing.queue != binding.queue
            || filing
                .assigned_to
                .as_ref()
                .is_some_and(|assignee| !self.recipients.contains(assignee))
        {
            return Err(ProtocolError::Mismatch(
                "tracker assignment requires a current readable recipient",
            ));
        }
        Ok(())
    }
}
impl TrackerWaitAuthority for EffectAuthority<'_> {
    fn authorize_observation(
        &self,
        request: &ExecuteActionEffect,
        binding: &TrackerBinding,
    ) -> Result<(), ProtocolError> {
        self.observation(request, binding)
    }
    fn authorize_wait(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        binding: &TrackerBinding,
        input: &serde_json::Value,
    ) -> Result<(), ProtocolError> {
        self.observation(request, binding)?;
        if original != self.command
            || input
                .pointer("/arguments/arg0/queue")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|queue| queue != binding.queue)
        {
            return Err(ProtocolError::Mismatch(
                "workflow closure observation binding",
            ));
        }
        Ok(())
    }
}

// Called only within the current product, key and input retention callbacks.
fn advance_native(
    runtime: &mut GovernedHostFacade<NativeStores>,
    action: &CompiledHostAction,
    invocation: &ProjectWorkflowInvocation,
    recipients: &BTreeMap<String, BTreeSet<String>>,
    signing_key: &SigningKey,
) -> StoreResult<super::super::ProjectWorkflowStep> {
    let before = read_result(runtime, invocation, signing_key)?;
    if let Some(effect) = recovery::recover_one(runtime, action, invocation, &before, signing_key)?
    {
        return Ok(super::super::ProjectWorkflowStep {
            executed_effect: None,
            recovered_effect: Some(effect),
            snapshot: read_result(runtime, invocation, signing_key)?,
        });
    }
    if before.instance_status != ActionInstanceStatus::Running {
        return Ok(super::super::ProjectWorkflowStep {
            executed_effect: None,
            recovered_effect: None,
            snapshot: before,
        });
    }
    let instance = &invocation.admission.instance_ref;
    let now = runtime.kernel().store().resolve_clock("now")?;
    whipplescript_kernel::time_pass::resolve_due_time_effects(
        runtime.kernel_mut(),
        instance,
        &now,
    )?;
    whipplescript_kernel::rule_pass::step_instance_generic(
        runtime.kernel_mut(),
        instance,
        action.program(),
        None,
        None,
    )?;
    let effect = runtime
        .kernel()
        .claimable_effects(instance)?
        .into_iter()
        .next();
    let executed_effect = if let Some(effect) = effect {
        let queue = if effect.kind == "tracker.file" {
            effect
                .target
                .clone()
                .ok_or_else(|| runtime_error("tracker filing has no queue"))?
        } else if whipplescript_kernel::tracker_wait::is_tracker_wait(&effect) {
            // Whole-instance observation is authorized above; this
            // resolves only the queue to pass to the governed call.
            let input =
                whipplescript_kernel::effect_handlers::resolve_effect_input_after_bindings_generic(
                    runtime.kernel().store(),
                    instance,
                    &effect,
                )?;
            let input: serde_json::Value = serde_json::from_str(&input)?;
            match input
                .pointer("/arguments/arg0/queue")
                .and_then(serde_json::Value::as_str)
            {
                Some(queue) => queue.to_owned(),
                None if recipients.len() == 1 => recipients.keys().next().unwrap().clone(),
                None => return Err(runtime_error("tracker wait has no unique admitted queue")),
            }
        } else {
            return Err(runtime_error(
                "workflow effect has no admitted product adapter",
            ));
        };
        let readers = recipients
            .get(&queue)
            .ok_or_else(|| runtime_error("workflow effect names an undeclared tracker"))?;
        let binding = TrackerBinding {
            scope: invocation.command.scope.clone(),
            queue: queue.clone(),
            resource: invocation.command.resources[&queue].clone(),
        };
        let request = ExecuteActionEffect {
            protocol: ACTION_EXECUTION_PROTOCOL.into(),
            issuer: invocation.command.issuer.clone(),
            scope: invocation.command.scope.clone(),
            admission: invocation.admission.clone(),
            policy: invocation.command.policy.clone(),
            provenance: invocation.command.provenance.clone(),
            effect_id: effect.effect_id.clone(),
            effect_fingerprint: effect_observation_fingerprint(&effect).map_err(runtime_error)?,
        };
        let bytes = request.signing_bytes().map_err(runtime_error)?;
        let authority = EffectAuthority {
            request: &request,
            command: &invocation.command,
            binding: &binding,
            recipients: readers,
            key: signing_key.public_key(),
        };
        let proof = signing_key.sign(&bytes);
        if effect.kind == "tracker.file" {
            runtime.execute_tracker_filing(
                request.clone(),
                action,
                &authority,
                proof.as_bytes(),
                &binding,
            )
        } else {
            runtime.execute_tracker_wait(
                request.clone(),
                action,
                &authority,
                proof.as_bytes(),
                &binding,
            )
        }
        .map_err(runtime_error)?;
        Some(effect.effect_id)
    } else {
        None
    };
    let snapshot = read_result(runtime, invocation, signing_key)?;
    Ok(super::super::ProjectWorkflowStep {
        executed_effect,
        recovered_effect: None,
        snapshot,
    })
}

impl Workbench {
    /// Advance the original workflow and execute at most one ready native tracker
    /// effect. Waiting returns without dispatching a provider or filing again.
    /// This caller-driven step is not the background supervisor's authority.
    pub fn step_project_workflow(
        &mut self,
        context: &AuthenticatedActionContext,
        project: &str,
        request_id: &str,
        limits: ProjectWorkflowLimits,
    ) -> Result<super::super::ProjectWorkflowStep, String> {
        let invocation = self.resume_project_workflow(context, project, request_id, limits)?;
        let mut prepared = self.prepare_project_workflow(
            context,
            &invocation.product_scope,
            invocation.command.clone(),
            limits,
        )?;
        let mut recipients = BTreeMap::new();
        for (queue, tracker) in &prepared.trackers {
            let (current, readers, basis) = self
                .prepare_project_tracker_recipients(context, project, queue)
                .map_err(debug_error)?;
            if &current != tracker {
                return Err("workflow tracker changed during recipient resolution".into());
            }
            prepared.authority.basis = prepared
                .authority
                .basis
                .combine(basis)
                .map_err(debug_error)?;
            recipients.insert(queue.clone(), readers);
        }
        let signing_key = SigningKey::from_seed(&self.governance_seed()).map_err(debug_error)?;
        let mut writer = self.store_ref().sibling().map_err(debug_error)?;
        writer
            .with_dispatch_basis(&prepared.authority.basis, || {
                prepared.key.retain(|| -> std::io::Result<_> {
                    let stores = prepared
                        .storage
                        .open_existing_protected(&prepared.protection)
                        .map_err(|error| std::io::Error::other(debug_error(error)))?;
                    let inputs = NativeActionInputCustody::new(
                        stores.inputs,
                        &prepared.authority.workspace,
                        limits.source_bytes.max(limits.input_bytes),
                    )
                    .map_err(|error| std::io::Error::other(debug_error(error)))?;
                    let retained = invocation
                        .command
                        .inputs
                        .values()
                        .cloned()
                        .chain(std::iter::once(prepared.input.clone()))
                        .collect::<Vec<_>>();
                    inputs
                        .with_resolved_many(&retained, |_| {
                            let mut runtime = GovernedHostFacade::from_signed_store_with_verifier(
                                stores.runtime,
                                1,
                                prepared.policy.signed_envelope(),
                                &prepared.root,
                            )
                            .map_err(runtime_error)?;
                            advance_native(
                                &mut runtime,
                                &prepared.action,
                                &invocation,
                                &recipients,
                                &signing_key,
                            )
                        })
                        .map_err(|error| std::io::Error::other(debug_error(error)))
                })
            })
            .map_err(debug_error)?
            .map_err(debug_error)
    }
}

#[path = "project_workflow_recovery.rs"]
mod recovery;
