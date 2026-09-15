//! Execute or recover the original human closure while current authority is held.
use super::*;
use gaugedesk_core::ids::PublicKey;
use gaugedesk_whip_runtime::host_actions::{
    action_result::{ActionInstanceStatus, ActionResultSnapshot},
    execution::{
        effect_observation_fingerprint, ActionExecutionVerifier, ExecuteActionEffect,
        ACTION_EXECUTION_PROTOCOL,
    },
    tracker_recovery::{RecoverTrackerClosure, TRACKER_RECOVERY_PROTOCOL},
    LogAppend, NativeStores,
};
use whipplescript_kernel::{
    host_facade::{TrackerClosureAuthority, TrackerClosureRecoveryAuthority},
    tracker_closure::ClosureDispatch,
};
use whipplescript_store::{tracker_closure::TrackerClosure, ClaimableEffect, RuntimeStore};

struct ClosureAuthority<'a> {
    request: &'a ExecuteActionEffect,
    command: &'a HostActionCommand,
    binding: &'a TrackerClosureBinding,
    summary: &'a str,
    key: PublicKey,
}
fn check_closure(
    command: &HostActionCommand,
    binding: &TrackerClosureBinding,
    summary: &str,
    closure: &TrackerClosure,
    request: &ExecuteActionEffect,
) -> Result<(), ProtocolError> {
    if request.provenance != command.provenance
        || closure.actor != command.provenance.executor
        || closure.instance_id != request.admission.instance_ref
        || closure.effect_id != request.effect_id
        || closure.queue != binding.tracker.queue
        || closure.item_id != binding.item_id
        || closure.subject_id != binding.subject_id
        || closure.expected_holder != binding.expected_holder
        || closure.summary.as_deref() != Some(summary)
    {
        return Err(ProtocolError::Mismatch("human completion original intent"));
    }
    Ok(())
}
impl ActionExecutionVerifier for ClosureAuthority<'_> {
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
                "current human completion execution",
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
            || effect.kind != "tracker.finish"
            || request.effect_fingerprint != effect_observation_fingerprint(effect)?
        {
            return Err(ProtocolError::Mismatch("human completion original effect"));
        }
        Ok(())
    }
}
impl TrackerClosureAuthority for ClosureAuthority<'_> {
    fn authorize_observation(
        &self,
        request: &ExecuteActionEffect,
        binding: &TrackerClosureBinding,
    ) -> Result<(), ProtocolError> {
        if request != self.request
            || binding != self.binding
            || binding.tracker.scope != self.command.scope
            || self.command.resources.get(&binding.tracker.queue) != Some(&binding.tracker.resource)
        {
            return Err(ProtocolError::Mismatch("human completion actual tracker"));
        }
        Ok(())
    }
    fn authorize_closure(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        binding: &TrackerClosureBinding,
        closure: &TrackerClosure,
    ) -> Result<(), ProtocolError> {
        self.authorize_observation(request, binding)?;
        if original != self.command {
            return Err(ProtocolError::Mismatch("human completion original command"));
        }
        check_closure(original, binding, self.summary, closure, request)
    }
}
struct RecoveryAuthority<'a> {
    request: &'a RecoverTrackerClosure,
    command: &'a HostActionCommand,
    binding: &'a TrackerClosureBinding,
    summary: &'a str,
    key: PublicKey,
}
impl TrackerClosureRecoveryAuthority for RecoveryAuthority<'_> {
    fn authenticate(
        &self,
        request: &RecoverTrackerClosure,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if request != self.request
            || bytes != request.signing_bytes()?
            || !verify_signature(bytes, &Signature::new(proof), &self.key).unwrap_or(false)
        {
            return Err(ProtocolError::Mismatch("current human completion recovery"));
        }
        Ok(())
    }
    fn authorize_observation(
        &self,
        request: &RecoverTrackerClosure,
        binding: &TrackerClosureBinding,
    ) -> Result<(), ProtocolError> {
        if request != self.request
            || binding != self.binding
            || binding.tracker.scope != self.command.scope
            || self.command.resources.get(&binding.tracker.queue) != Some(&binding.tracker.resource)
        {
            return Err(ProtocolError::Mismatch("human completion recovery tracker"));
        }
        Ok(())
    }
    fn authorize_recovery(
        &self,
        request: &RecoverTrackerClosure,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        dispatch: &ClosureDispatch,
        closure: &TrackerClosure,
    ) -> Result<(), ProtocolError> {
        self.authorize_observation(request, &dispatch.binding)?;
        if original != self.command
            || execution.admission != request.admission
            || request.provenance != original.provenance
        {
            return Err(ProtocolError::Mismatch(
                "human completion recovery original command",
            ));
        }
        check_closure(original, self.binding, self.summary, closure, execution)
    }
}
fn recover(
    runtime: &mut GovernedHostFacade<NativeStores>,
    action: &CompiledHostAction,
    invocation: &ProjectWorkflowInvocation,
    binding: &TrackerClosureBinding,
    summary: &str,
    snapshot: &ActionResultSnapshot,
    key: &SigningKey,
) -> StoreResult<Option<String>> {
    let instance = &invocation.admission.instance_ref;
    let facts = runtime
        .kernel()
        .store()
        .list_facts_including_consumed(instance)?;
    for effect in &snapshot.effects {
        for attempt in &effect.attempts {
            let Some(marker) = &attempt.dispatch else {
                continue;
            };
            if marker.frame.kind != "tracker.finish" {
                return Err(native_error("completion contains an unsupported dispatch"));
            }
            let settled = facts
                .iter()
                .filter(|fact| {
                    matches!(
                        fact.name.as_str(),
                        "tracker.finish.completed" | "tracker.finish.failed"
                    )
                })
                .map(|fact| {
                    serde_json::from_str::<serde_json::Value>(&fact.value_json)
                        .map_err(StoreError::from)
                })
                .collect::<StoreResult<Vec<_>>>()?
                .iter()
                .any(|value| {
                    value["effect_id"] == effect.effect_id && value["run_id"] == attempt.run_id
                });
            if settled {
                continue;
            }
            let command = &invocation.command;
            let request = RecoverTrackerClosure {
                protocol: TRACKER_RECOVERY_PROTOCOL.into(),
                issuer: command.issuer.clone(),
                scope: command.scope.clone(),
                admission: invocation.admission.clone(),
                policy: command.policy.clone(),
                provenance: command.provenance.clone(),
                effect_id: effect.effect_id.clone(),
                run_id: attempt.run_id.clone(),
            };
            let authority = RecoveryAuthority {
                request: &request,
                command,
                binding,
                summary,
                key: key.public_key(),
            };
            let proof = key.sign(&request.signing_bytes().map_err(native_error)?);
            let epoch = runtime
                .kernel_mut()
                .store_mut()
                .claim_instance_ownership(instance)?;
            runtime
                .recover_tracker_closure(
                    request.clone(),
                    action,
                    epoch,
                    &authority,
                    proof.as_bytes(),
                    binding,
                )
                .map_err(native_error)?;
            return Ok(Some(effect.effect_id.clone()));
        }
    }
    Ok(None)
}
/// Only called with the product writer, scope key and retained inputs held.
pub(super) fn advance(
    runtime: &mut GovernedHostFacade<NativeStores>,
    action: &CompiledHostAction,
    invocation: &ProjectWorkflowInvocation,
    binding: &TrackerClosureBinding,
    summary: &str,
    key: &SigningKey,
) -> StoreResult<super::super::super::ProjectWorkflowStep> {
    let before = super::super::execution::read_result(runtime, invocation, key)?;
    let recovered = recover(runtime, action, invocation, binding, summary, &before, key)?;
    let mut executed = None;
    if before.instance_status == ActionInstanceStatus::Running {
        whipplescript_kernel::rule_pass::step_instance_generic(
            runtime.kernel_mut(),
            &invocation.admission.instance_ref,
            action.program(),
            None,
            None,
        )?;
        if recovered.is_none() {
            if let Some(effect) = runtime
                .kernel()
                .claimable_effects(&invocation.admission.instance_ref)?
                .into_iter()
                .next()
            {
                let command = &invocation.command;
                let request = ExecuteActionEffect {
                    protocol: ACTION_EXECUTION_PROTOCOL.into(),
                    issuer: command.issuer.clone(),
                    scope: command.scope.clone(),
                    admission: invocation.admission.clone(),
                    policy: command.policy.clone(),
                    provenance: command.provenance.clone(),
                    effect_id: effect.effect_id.clone(),
                    effect_fingerprint: effect_observation_fingerprint(&effect)
                        .map_err(native_error)?,
                };
                let authority = ClosureAuthority {
                    request: &request,
                    command,
                    binding,
                    summary,
                    key: key.public_key(),
                };
                let proof = key.sign(&request.signing_bytes().map_err(native_error)?);
                runtime
                    .execute_tracker_closure(
                        request.clone(),
                        action,
                        &authority,
                        proof.as_bytes(),
                        binding,
                    )
                    .map_err(native_error)?;
                executed = Some(effect.effect_id);
                whipplescript_kernel::rule_pass::step_instance_generic(
                    runtime.kernel_mut(),
                    &invocation.admission.instance_ref,
                    action.program(),
                    None,
                    None,
                )?;
            }
        }
    }
    Ok(super::super::super::ProjectWorkflowStep {
        executed_effect: executed,
        recovered_effect: recovered,
        snapshot: super::super::execution::read_result(runtime, invocation, key)?,
    })
}
