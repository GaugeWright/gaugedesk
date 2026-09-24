//! Execute or recover the original tracker control while current authority is held.
use super::*;
use gaugedesk_core::ids::PublicKey;
use gaugedesk_whip_runtime::host_actions::{
    action_result::{ActionInstanceStatus, ActionResultSnapshot},
    execution::{
        effect_observation_fingerprint, ActionExecutionVerifier, ExecuteActionEffect,
        ACTION_EXECUTION_PROTOCOL,
    },
    tracker_recovery::{RecoverTrackerControl, TRACKER_RECOVERY_PROTOCOL},
    LogAppend, NativeStores,
};
use whipplescript_kernel::{
    host_facade::{TrackerControlAuthority, TrackerControlRecoveryAuthority},
    tracker_control::ControlDispatch,
};
use whipplescript_store::{
    tracker_control::{TrackerControl, TrackerControlAction},
    ClaimableEffect,
};

struct ControlAuthority<'a> {
    request: &'a ExecuteActionEffect,
    command: &'a HostActionCommand,
    binding: &'a TrackerControlBinding,
    input: &'a serde_json::Value,
    key: PublicKey,
}

/// The actual control is exactly the original intent: the same actor, issue,
/// subject and action, with the same expiry, holder or recipients.
fn check_control(
    command: &HostActionCommand,
    binding: &TrackerControlBinding,
    input: &serde_json::Value,
    control: &TrackerControl,
    request: &ExecuteActionEffect,
) -> Result<(), ProtocolError> {
    let text = |name: &str| input[name].as_str().map(str::to_owned);
    let intended = match &control.action {
        TrackerControlAction::Claim { expires_at } | TrackerControlAction::Renew { expires_at } => {
            text("expires_at").as_deref() == Some(expires_at.as_str())
        }
        TrackerControlAction::Release { expected_holder } => {
            text("expected_holder") == *expected_holder
        }
        TrackerControlAction::Assign {
            expected_assignee,
            assignee,
        } => text("expected_assignee") == *expected_assignee && text("assigned_to") == *assignee,
    };
    if !intended
        || request.provenance != command.provenance
        || control.actor != command.provenance.executor
        || control.instance_id != request.admission.instance_ref
        || control.effect_id != request.effect_id
        || control.queue != binding.tracker.queue
        || control.item_id != binding.item_id
        || control.subject_id != binding.subject_id
    {
        return Err(ProtocolError::Mismatch("tracker control original intent"));
    }
    Ok(())
}

impl ActionExecutionVerifier for ControlAuthority<'_> {
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
            return Err(ProtocolError::Mismatch("current tracker control execution"));
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
            || !whipplescript_kernel::tracker_control::is_tracker_control(effect)
            || request.effect_fingerprint != effect_observation_fingerprint(effect)?
        {
            return Err(ProtocolError::Mismatch("tracker control original effect"));
        }
        Ok(())
    }
}

impl TrackerControlAuthority for ControlAuthority<'_> {
    fn authorize_observation(
        &self,
        request: &ExecuteActionEffect,
        binding: &TrackerControlBinding,
    ) -> Result<(), ProtocolError> {
        if request != self.request
            || binding != self.binding
            || binding.tracker.scope != self.command.scope
            || self.command.resources.get(&binding.tracker.queue) != Some(&binding.tracker.resource)
        {
            return Err(ProtocolError::Mismatch("tracker control actual tracker"));
        }
        Ok(())
    }
    fn authorize_control(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        binding: &TrackerControlBinding,
        control: &TrackerControl,
    ) -> Result<(), ProtocolError> {
        self.authorize_observation(request, binding)?;
        if original != self.command {
            return Err(ProtocolError::Mismatch("tracker control original command"));
        }
        check_control(original, binding, self.input, control, request)
    }
}

struct RecoveryAuthority<'a> {
    request: &'a RecoverTrackerControl,
    command: &'a HostActionCommand,
    binding: &'a TrackerControlBinding,
    input: &'a serde_json::Value,
    key: PublicKey,
}

impl TrackerControlRecoveryAuthority for RecoveryAuthority<'_> {
    fn authenticate(
        &self,
        request: &RecoverTrackerControl,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if request != self.request
            || bytes != request.signing_bytes()?
            || !verify_signature(bytes, &Signature::new(proof), &self.key).unwrap_or(false)
        {
            return Err(ProtocolError::Mismatch("current tracker control recovery"));
        }
        Ok(())
    }
    fn authorize_observation(
        &self,
        request: &RecoverTrackerControl,
        binding: &TrackerControlBinding,
    ) -> Result<(), ProtocolError> {
        if request != self.request
            || binding != self.binding
            || binding.tracker.scope != self.command.scope
            || self.command.resources.get(&binding.tracker.queue) != Some(&binding.tracker.resource)
        {
            return Err(ProtocolError::Mismatch("tracker control recovery tracker"));
        }
        Ok(())
    }
    fn authorize_recovery(
        &self,
        request: &RecoverTrackerControl,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        dispatch: &ControlDispatch,
        control: &TrackerControl,
    ) -> Result<(), ProtocolError> {
        self.authorize_observation(request, &dispatch.binding)?;
        if original != self.command
            || execution.admission != request.admission
            || request.provenance != original.provenance
        {
            return Err(ProtocolError::Mismatch(
                "tracker control recovery original command",
            ));
        }
        check_control(original, self.binding, self.input, control, execution)
    }
}

/// Recover a control dispatched but never settled, rather than dispatching it
/// again: its fate is read back from the tracker's own receipt.
fn recover(
    runtime: &mut GovernedHostFacade<NativeStores>,
    action: &CompiledHostAction,
    invocation: &ProjectWorkflowInvocation,
    binding: &TrackerControlBinding,
    input: &serde_json::Value,
    snapshot: &ActionResultSnapshot,
    key: &SigningKey,
) -> StoreResult<Option<String>> {
    let instance = &invocation.admission.instance_ref;
    for effect in &snapshot.effects {
        for attempt in &effect.attempts {
            if attempt.dispatch.is_none() || attempt.terminal_status.is_some() {
                continue;
            }
            let command = &invocation.command;
            let request = RecoverTrackerControl {
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
                input,
                key: key.public_key(),
            };
            let proof = key.sign(&request.signing_bytes().map_err(native_error)?);
            let epoch = runtime
                .kernel_mut()
                .store_mut()
                .claim_instance_ownership(instance)?;
            runtime
                .recover_tracker_control(
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
    binding: &TrackerControlBinding,
    input: &serde_json::Value,
    key: &SigningKey,
) -> StoreResult<super::super::super::ProjectWorkflowStep> {
    let before = super::super::execution::read_result(runtime, invocation, key)?;
    let recovered = recover(runtime, action, invocation, binding, input, &before, key)?;
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
                let authority = ControlAuthority {
                    request: &request,
                    command,
                    binding,
                    input,
                    key: key.public_key(),
                };
                let proof = key.sign(&request.signing_bytes().map_err(native_error)?);
                runtime
                    .execute_tracker_control(
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
