//! Execute an independently admitted correction through the runtime owner.
//! The original input, current authority and actual target remain bound under
//! their retention and product fences through the governed recording attempt.
use super::*;
use crate::file_action_factory::execution::read_evidence;
use gaugedesk_core::{
    ids::PublicKey,
    signature::{verify_signature, Signature},
};
use gaugedesk_whip_runtime::{
    host_actions::{
        action_result::ActionResultSnapshot,
        execution::{
            effect_observation_fingerprint, ActionExecutionVerifier, ExecuteActionEffect,
            ACTION_EXECUTION_PROTOCOL,
        },
        facade::GovernedHostFacade,
        NativeStores, RuntimeStore,
    },
    ProtocolError,
};
use whipplescript_kernel::{
    host_facade::ResolutionRecordingAuthority, resolution_recording::recording_operation_id,
};
use whipplescript_store::{
    file_settlement::{RESOLUTION_RECORDING_CAPABILITY, RESOLUTION_RECORDING_PROVIDER},
    vcs::resolution_scope::ResolutionMemoryScope,
    vcs_resolution_recording::ResolutionRecordingBinding,
    ClaimableEffect, StoreError, StoreResult, StoredEvent,
};

fn refused(error: impl std::fmt::Debug) -> StoreError {
    StoreError::Conflict(format!("native correction operation refused: {error:?}"))
}

/// Constructed inside the current Home fence from resolved custody and the
/// actual native descriptor. An input's envelope version is not its body hash.
struct NativeRecordingAuthority<'a> {
    command: &'a HostActionCommand,
    request: &'a ExecuteActionEffect,
    binding: &'a ResolutionRecordingBinding,
    resolved_hash: &'a str,
    target_scope: &'a ResolutionMemoryScope,
    key: PublicKey,
}
impl ActionExecutionVerifier for NativeRecordingAuthority<'_> {
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
                "current native correction execution",
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
        let mismatch = || ProtocolError::Mismatch("exact native correction input and target");
        if request != self.request
            || original != self.command
            || request.provenance != original.provenance
            || request.provenance.executor != self.binding.batch().actor
            || effect_observation_fingerprint(effect)? != request.effect_fingerprint
            || self.binding.input_hash() != self.resolved_hash
            || original
                .inputs
                .get("corrections")
                .map(|input| input.label_ref.as_str())
                != Some(self.binding.input_label())
            || self.binding.scope() != self.target_scope
            || delivery::original_scope(original).as_ref() != Ok(self.target_scope)
        {
            return Err(mismatch());
        }
        Ok(())
    }
}
impl ResolutionRecordingAuthority for NativeRecordingAuthority<'_> {
    fn authorize_recording(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        effect: &ClaimableEffect,
        binding: &ResolutionRecordingBinding,
    ) -> Result<(), ProtocolError> {
        self.authorize(request, original, effect)?;
        if binding != self.binding {
            return Err(ProtocolError::Mismatch("actual native correction binding"));
        }
        Ok(())
    }
}

impl Workbench {
    /// Current original-author metadata inspection. No input resolution, rule
    /// advancement or target access; other investigators need their own boundary.
    pub fn read_editor_corrections_result(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        runtime: &GovernedHostFacade<NativeStores>,
    ) -> Result<ActionResultSnapshot, String> {
        let prepared =
            self.prepare_native_corrections(context, inputs, command, runtime.policy_ref())?;
        self.store_mut()
            .with_dispatch_basis(&prepared.basis, || {
                read_evidence(runtime, command, admission, &prepared.key)
            })
            .map_err(|error| format!("{error:?}"))?
            .map_err(|error| format!("{error:?}"))
    }

    /// One ordinary rule pass under current authority. This returns pending
    /// effect identities; each effect needs a separately verified execution.
    pub fn advance_editor_corrections(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        runtime: &mut GovernedHostFacade<NativeStores>,
    ) -> Result<Vec<String>, String> {
        let prepared =
            self.prepare_native_corrections(context, inputs, command, runtime.policy_ref())?;
        let recording = delivery::registered_recording_workflow(command)?;
        self.store_mut()
            .with_dispatch_basis(&prepared.basis, || {
                read_evidence(runtime, command, admission, &prepared.key)?;
                let instance = runtime
                    .kernel()
                    .store()
                    .get_instance(&prepared.scope)?
                    .ok_or_else(|| refused("admitted correction instance is unavailable"))?;
                // The schema has no ambient provider. Bind only this admitted
                // fixed program; target/configuration and each execution grant
                // remain behind the owner's governed recording door.
                runtime.kernel().store().bind_capability(
                    whipplescript_store::CapabilityBinding {
                        binding_id: &format!("gaugedesk:corrections:{}", instance.program_id),
                        program_id: Some(&instance.program_id),
                        capability: RESOLUTION_RECORDING_CAPABILITY,
                        provider: RESOLUTION_RECORDING_PROVIDER,
                        config_json: "{}",
                    },
                )?;
                whipplescript_kernel::rule_pass::step_instance_generic(
                    runtime.kernel_mut(),
                    &prepared.scope,
                    recording.action().program(),
                    None,
                    None,
                )?;
                Ok::<_, StoreError>(
                    runtime
                        .kernel()
                        .claimable_effects(&prepared.scope)?
                        .into_iter()
                        .map(|effect| effect.effect_id)
                        .collect(),
                )
            })
            .map_err(|error| format!("{error:?}"))?
            .map_err(|error| format!("{error:?}"))
    }

    /// Execute one actual claimable correction effect. The owner persists
    /// dispatch, records the exact batch and settles the attempt. Its terminal
    /// evidence does not by itself admit any resulting product fact.
    pub fn execute_editor_corrections_effect(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        effect_id: &str,
        runtime: &mut GovernedHostFacade<NativeStores>,
    ) -> Result<StoredEvent, String> {
        let prepared =
            self.prepare_native_corrections(context, inputs, command, runtime.policy_ref())?;
        let recording = delivery::registered_recording_workflow(command)?;
        let input = &command.inputs["corrections"];
        inputs
            .with_resolved(input, |resolved| {
                self.store_mut()
                    .with_dispatch_basis(&prepared.basis, || -> StoreResult<_> {
                        let mapping = prepared.input_binding.as_ref()
                            .ok_or_else(|| refused("correction has no original Home input mapping"))?;
                        if mapping.input() != input || mapping.content_hash() != resolved.content_hash {
                            return Err(refused("correction bytes differ from the original Home input mapping"));
                        }
                        read_evidence(runtime, command, admission, &prepared.key)?;
                        if runtime.kernel().store().list_runs(&prepared.scope)?.iter()
                            .any(|run| run.effect_id == effect_id)
                        {
                            return Err(refused("correction was already attempted; inspect or reconcile its original outcome"));
                        }
                        let effect = runtime
                            .kernel()
                            .claimable_effects(&prepared.scope)?
                            .into_iter()
                            .find(|effect| effect.effect_id == effect_id)
                            .ok_or_else(|| refused("correction effect is not claimable"))?;
                        let recorded_at = runtime.kernel().store().resolve_clock("now")?;
                        let binding = ResolutionRecordingBinding::prepare(
                            &resolved.content,
                            &input.label_ref,
                            prepared.target.scope().clone(),
                            &recording_operation_id(&admission.instance_ref, &effect.effect_id),
                            context.actor().as_str(),
                            &command.fingerprint().map_err(refused)?,
                            &recorded_at,
                        )?;
                        let request = ExecuteActionEffect {
                            protocol: ACTION_EXECUTION_PROTOCOL.into(),
                            issuer: command.issuer.clone(),
                            scope: command.scope.clone(),
                            admission: admission.clone(),
                            policy: command.policy.clone(),
                            provenance: command.provenance.clone(),
                            effect_id: effect.effect_id.clone(),
                            effect_fingerprint: effect_observation_fingerprint(&effect)
                                .map_err(refused)?,
                        };
                        let authority = NativeRecordingAuthority {
                            command,
                            request: &request,
                            binding: &binding,
                            resolved_hash: &resolved.content_hash,
                            target_scope: prepared.target.scope(),
                            key: prepared.key.public_key(),
                        };
                        let bytes = request.signing_bytes().map_err(refused)?;
                        let proof = prepared.key.sign(&bytes);
                        authority
                            .authenticate(&request, &bytes, proof.as_bytes())
                            .map_err(refused)?;
                        authority
                            .authorize_recording(&request, command, &effect, &binding)
                            .map_err(refused)?;
                        // The host checks raw flows before opening its actual target,
                        // using the same owner algebra the facade rechecks at dispatch.
                        for source in ["admitted_corrections", "admitted_resolutions"] {
                            for sink in ["admitted_resolutions", "result", "error"] {
                                prepared
                                    .envelope
                                    .check_resource_flow(source, sink)
                                    .map_err(refused)?;
                            }
                        }
                        let mut target =
                            prepared.target.open_recording(binding.clone(), &resolved.content)?;
                        runtime
                            .execute_resolution_recording(
                                request.clone(),
                                &recording,
                                &authority,
                                proof.as_bytes(),
                                &mut target,
                            )
                            .map_err(refused)
                    })
                    .map_err(refused)?
            })
            .map_err(|error| format!("{error:?}"))
    }
}
