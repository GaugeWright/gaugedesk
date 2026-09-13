//! Deliver the original independently admitted correction under current authority.
//! No effect executes here; its input and target still need governed execution.
use super::*;
use crate::{
    action_policy::load_action_policy,
    host_action_delivery::{record_runtime_acknowledgment, RuntimeAcknowledgment},
};
use gaugedesk_store::command_dispatch::{CommittedDispatch, DispatchReadBasis};
use gaugedesk_whip_runtime::host_actions::{facade::GovernedHostFacade, LogAppend, RuntimeStore};
use whipplescript_kernel::gov::canonicalize;
use whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope;

pub(in crate::file_action_factory) struct NativeCorrectionPreparation {
    pub(super) scope: String,
    pub(in crate::file_action_factory) key: SigningKey,
    pub(in crate::file_action_factory) basis: DispatchReadBasis,
    pub(super) target: gaugedesk_workspace::NativeResolutionRecordingTarget,
    pub(super) envelope: ifc::VerifiedEnvelope,
    pub(super) input_binding: Option<crate::action_input_binding::NativeInputBinding>,
    pub(super) delivery: CommittedDispatch<HostActionCommand>,
}

pub(super) fn registered_recording_workflow(
    command: &HostActionCommand,
) -> Result<ResolutionRecordingAction, String> {
    let recording = ResolutionRecordingAction::compile()?;
    let action = recording.action();
    if command.operation != RECORDING_OPERATION
        || command.program_version_ref != action.version_ref()
        || command.input_schema_ref != action.input_schema_ref()
    {
        return Err("correction command uses an unavailable registered executable".into());
    }
    Ok(recording)
}

pub(super) fn original_scope(command: &HostActionCommand) -> Result<ResolutionMemoryScope, String> {
    let admitted = command
        .resources
        .get("resolutions")
        .ok_or("correction command has no admitted resolution scope")?;
    let scope: ResolutionMemoryScope = serde_json::from_str(
        admitted
            .resource
            .selector
            .as_deref()
            .ok_or("correction resolution scope is missing")?,
    )
    .map_err(|error| error.to_string())?;
    if admitted != &recording_resource(&scope, &command.policy.envelope_hash)? {
        return Err("correction resource differs from its admitted descriptor".into());
    }
    Ok(scope)
}

pub(super) fn original_policy(envelope: &str) -> Result<HostGovernancePolicy, String> {
    let policy: HostGovernancePolicy =
        serde_json::from_str(envelope).map_err(|error| error.to_string())?;
    if canonicalize(&policy.to_json()?)? != canonicalize(envelope)? {
        return Err("original correction policy cannot be represented losslessly".into());
    }
    Ok(policy)
}

impl Workbench {
    pub(in crate::file_action_factory) fn prepare_native_corrections(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        runtime_policy: &gaugedesk_whip_runtime::PolicyEpochRef,
    ) -> Result<NativeCorrectionPreparation, String> {
        let refused = || "native correction delivery binding is invalid".to_owned();
        if command.issuer != self.authority().as_str()
            || inputs.authority_scope() != self.home_id().as_str()
            || command.provenance.initiator != context.actor().as_str()
            || command.provenance.executor != context.actor().as_str()
            || !command.provenance.delegation.is_empty()
            || command.inputs.len() != 1
            || command.resources.len() != 1
        {
            return Err(refused());
        }
        let source_scope = Self::correction_source_scope(command)?;
        registered_recording_workflow(command)?;
        let (format, project, chat, path): (String, String, String, String) =
            serde_json::from_str(&command.scope).map_err(|_| refused())?;
        if format != "gaugedesk.editor-corrections.v1" {
            return Err(refused());
        }
        let original_scope = original_scope(command)?;
        let input = command.inputs.get("corrections").ok_or_else(refused)?;
        if input.handle != "admitted_corrections"
            || input.label_ref
                != format!(
                    "policy:{}:admitted_corrections",
                    command.policy.envelope_hash
                )
        {
            return Err(refused());
        }
        let home = self.home_id().clone();
        let scope = command.instance_ref().map_err(|_| refused())?;
        let identity = ActionPolicyIdentity {
            issuer: command.issuer.clone(),
            scope: command.scope.clone(),
            request_id: command.request_id.clone(),
        };
        let policy_scope = identity.storage_scope()?;
        let key = SigningKey::from_seed(&self.governance_seed()).map_err(|error| error.reason)?;
        let mapping_scope =
            crate::action_input_binding::input_binding_scope(&command.issuer, input)
                .map_err(|error| format!("correction input mapping refused: {error:?}"))?;
        let root = GovernanceRootVerifier::new(self.authority().clone(), key.public_key());
        let mut scopes = vec![
            LIBRARY_SCOPE,
            ORG_SCOPE,
            crate::account_auth::ACCOUNT_AUTH_SCOPE,
            crate::mobile_machine_session::SCOPE,
            &scope,
            &policy_scope,
            &mapping_scope,
        ];
        scopes.extend(source_scope.as_deref());
        let ((authority, input_binding, policy), basis) = self
            .store_ref()
            .read_for_dispatch(&scopes, |store| {
                let policy = load_action_policy(store, &identity, &command.policy, &root)
                    .map_err(|_| invalid("original correction policy is unavailable"))?;
                let original_policy = original_policy(policy.signed_envelope())
                    .map_err(|_| invalid("original correction policy is unrepresentable"))?;
                let source_policy = Self::correction_source_policy(
                    store,
                    home.as_str(),
                    &key.public_key(),
                    command,
                    &original_policy,
                )
                .map_err(|_| invalid("original correction source evidence is unavailable"))?;
                let authority = current_target_authority_with_source(
                    store,
                    &home,
                    context,
                    &NativeTargetIntent {
                        chat_id: &chat,
                        request_id: &command.request_id,
                        path: &path,
                    },
                    NativeActionKind::RecordCorrections,
                    source_policy.as_ref(),
                )?;
                let mapping = crate::action_input_binding::load_input_binding(
                    store,
                    &command.issuer,
                    home.as_str(),
                    input,
                    &key.public_key(),
                );
                Ok((authority, mapping, policy))
            })
            .map_err(|error| format!("current correction authority refused: {error:?}"))?;
        let input_binding = input_binding
            .map_err(|error| format!("correction input mapping refused: {error:?}"))?;
        if authority.project_id != project
            || authority.workspace_path != path
            || authority.resolution_scope != original_scope
        {
            return Err("current correction scope differs from its admitted ceiling".into());
        }
        if canonicalize(policy.signed_envelope())? != canonicalize(&authority.policy.to_json()?)?
            || runtime_policy != policy.policy_ref()
        {
            return Err("current correction policy differs from its admitted ceiling".into());
        }
        let delivery = self
            .store_mut()
            .committed_dispatch::<ProductActionAdmission>(&scope, &command.request_id)
            .map_err(|error| format!("correction product receipt refused: {error:?}"))?
            .ok_or("correction action has no committed dispatch")?;
        let original = self
            .store_ref()
            .fold::<ProductActionAdmission>(&scope)
            .map_err(|error| format!("correction admission history refused: {error:?}"))?;
        if original.command.as_ref() != Some(command)
            || &delivery.command != command
            || delivery.dispatch.runtime_ref != format!("{home}:native")
            || delivery.dispatch.command_ref != command.fingerprint().map_err(|_| refused())?
        {
            return Err("correction dispatch differs from its original admission".into());
        }
        let target = self
            .engagements
            .get(&chat)
            .ok_or("chat workspace is unavailable")?
            .native_resolution_recording_target(&path, original_scope)
            .map_err(|error| format!("{error:?}"))?;
        let envelope =
            ifc::VerifiedEnvelope::verify_signed_text_with(policy.signed_envelope(), &root)?;
        crate::resolution_recording_policy::validate_resolution_recording_flows(&envelope)?;
        let basis = authority
            .bind_deadline(basis)
            .map_err(|error| format!("correction authority deadline refused: {error:?}"))?;
        Ok(NativeCorrectionPreparation {
            scope,
            key,
            basis,
            delivery,
            target,
            envelope,
            input_binding,
        })
    }

    /// Deliver only an exact receipted command to a trusted Home runtime.
    /// Same-command redelivery retrieves its original runtime admission. The
    /// product acknowledgment is independently recoverable under that identity.
    pub fn deliver_editor_corrections<S: RuntimeStore + LogAppend>(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        runtime: &mut GovernedHostFacade<S>,
    ) -> Result<RuntimeAcknowledgment, String> {
        let prepared =
            self.prepare_native_corrections(context, inputs, command, runtime.policy_ref())?;
        let recording = registered_recording_workflow(command)?;
        let bytes = command
            .signing_bytes()
            .map_err(|error| format!("{error:?}"))?;
        let receipt = inputs
            .publish(std::slice::from_ref(&command.inputs["corrections"]), || {
                self.store_mut()
                    .with_dispatch_basis(&prepared.basis, || {
                        let verifier = super::super::delivery::NativeAdmissionVerifier {
                            command,
                            key: prepared.key.public_key(),
                        };
                        runtime.admit_action(
                            command.clone(),
                            recording.action(),
                            &verifier,
                            prepared.key.sign(&bytes).as_bytes(),
                        )
                    })
                    .map_err(|error| {
                        whipplescript_store::StoreError::Conflict(format!(
                            "correction delivery authority changed: {error:?}",
                        ))
                    })?
                    .map_err(|error| {
                        whipplescript_store::StoreError::Conflict(format!(
                            "runtime correction admission refused: {error:?}",
                        ))
                    })
            })
            .map_err(|error| format!("{error:?}"))?;
        record_runtime_acknowledgment(
            self.store_mut(),
            &prepared.scope,
            prepared.delivery,
            receipt,
        )
        .map_err(|error| format!("correction runtime acknowledgment refused: {error:?}"))
    }
}
