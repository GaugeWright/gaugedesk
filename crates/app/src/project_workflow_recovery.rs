//! Receipt-proved recovery of an interrupted native filing, never a re-dispatch.
use super::*;
use gaugedesk_whip_runtime::host_actions::{
    tracker_recovery::{RecoverTrackerFiling, TRACKER_RECOVERY_PROTOCOL},
    LogAppend,
};
use whipplescript_kernel::{host_facade::TrackerRecoveryAuthority, tracker_filing::FilingDispatch};

struct RecoveryAuthority<'a> {
    request: &'a RecoverTrackerFiling,
    command: &'a HostActionCommand,
    binding: &'a TrackerBinding,
    key: PublicKey,
}
impl TrackerRecoveryAuthority for RecoveryAuthority<'_> {
    fn authenticate(
        &self,
        request: &RecoverTrackerFiling,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if request != self.request
            || bytes != request.signing_bytes()?
            || !verify_signature(bytes, &Signature::new(proof), &self.key).unwrap_or(false)
        {
            return Err(ProtocolError::Mismatch("current workflow filing recovery"));
        }
        Ok(())
    }
    fn authorize_observation(
        &self,
        request: &RecoverTrackerFiling,
        binding: &TrackerBinding,
    ) -> Result<(), ProtocolError> {
        if request != self.request
            || binding != self.binding
            || self.command.resources.get(&binding.queue) != Some(&binding.resource)
        {
            return Err(ProtocolError::Mismatch("workflow recovery actual tracker"));
        }
        Ok(())
    }
    fn authorize_recovery(
        &self,
        request: &RecoverTrackerFiling,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        dispatch: &FilingDispatch,
    ) -> Result<(), ProtocolError> {
        self.authorize_observation(request, &dispatch.binding)?;
        if original != self.command
            || execution.provenance != original.provenance
            || request.provenance != original.provenance
            || execution.admission != request.admission
            || dispatch.queue != self.binding.queue
        {
            return Err(ProtocolError::Mismatch(
                "workflow recovery original execution",
            ));
        }
        Ok(())
    }
}

/// The caller already holds current instance/resource access, the product
/// writer, project key, and all retained inputs through this entire call.
pub(super) fn recover_one(
    runtime: &mut GovernedHostFacade<NativeStores>,
    action: &CompiledHostAction,
    invocation: &ProjectWorkflowInvocation,
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
            if marker.frame.kind != "tracker.file" {
                continue;
            }
            let settled = facts
                .iter()
                .filter(|fact| {
                    matches!(
                        fact.name.as_str(),
                        "tracker.file.completed" | "tracker.file.failed"
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
            let queue = marker
                .frame
                .target
                .as_ref()
                .ok_or_else(|| runtime_error("original filing has no tracker"))?;
            let resource = invocation
                .command
                .resources
                .get(queue)
                .ok_or_else(|| runtime_error("original filing tracker is undeclared"))?;
            let binding = TrackerBinding {
                scope: invocation.command.scope.clone(),
                queue: queue.clone(),
                resource: resource.clone(),
            };
            let request = RecoverTrackerFiling {
                protocol: TRACKER_RECOVERY_PROTOCOL.into(),
                issuer: invocation.command.issuer.clone(),
                scope: invocation.command.scope.clone(),
                admission: invocation.admission.clone(),
                policy: invocation.command.policy.clone(),
                provenance: invocation.command.provenance.clone(),
                effect_id: effect.effect_id.clone(),
                run_id: attempt.run_id.clone(),
            };
            let authority = RecoveryAuthority {
                request: &request,
                command: &invocation.command,
                binding: &binding,
                key: key.public_key(),
            };
            let proof = key.sign(&request.signing_bytes().map_err(runtime_error)?);
            // Acquire this ownership epoch while the product writer excludes
            // competing execution; reading somebody else's epoch is not a claim.
            let epoch = runtime
                .kernel_mut()
                .store_mut()
                .claim_instance_ownership(instance)?;
            runtime
                .recover_tracker_filing(
                    request.clone(),
                    action,
                    epoch,
                    &authority,
                    proof.as_bytes(),
                    &binding,
                )
                .map_err(runtime_error)?;
            return Ok(Some(effect.effect_id.clone()));
        }
    }
    Ok(None)
}
