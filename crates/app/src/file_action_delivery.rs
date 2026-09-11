//! Current authenticated delivery of an already admitted native editor action.
//! The verifier exists only while product standing is fenced. Execution needs
//! its own per-effect current authority and is not enabled by this boundary.

use super::*;
use crate::action_policy::load_action_policy;
use crate::host_action_delivery::{record_runtime_acknowledgment, RuntimeAcknowledgment};
use gaugedesk_core::{
    ids::PublicKey,
    signature::{verify_signature, Signature},
};
use gaugedesk_store::command_dispatch::{CommittedDispatch, DispatchReadBasis};
use gaugedesk_whip_runtime::{
    host_actions::{facade::GovernedHostFacade, LogAppend, RuntimeStore},
    ProtocolError,
};
use whipplescript_kernel::gov::canonicalize;

/// Constructed only inside the current-authority writer guard, used once there,
/// and never returned. The Home key authenticates the exact factory command;
/// it does not substitute the Home for that command's initiating actor.
pub(super) struct NativeAdmissionVerifier<'a> {
    pub(super) command: &'a HostActionCommand,
    pub(super) key: PublicKey,
}

impl ActionAdmissionVerifier for NativeAdmissionVerifier<'_> {
    fn verify(
        &self,
        command: &HostActionCommand,
        signing_bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if command != self.command
            || signing_bytes != self.command.signing_bytes()?
            || !verify_signature(signing_bytes, &Signature::new(proof), &self.key).unwrap_or(false)
        {
            return Err(ProtocolError::Mismatch("current native editor admission"));
        }
        Ok(())
    }
}

/// A current observation only; the product basis must be fenced before use.
pub(super) struct NativeEditorPreparation {
    pub(super) scope: String,
    pub(super) chat_id: String,
    pub(super) key: SigningKey,
    pub(super) basis: DispatchReadBasis,
    pub(super) delivery: CommittedDispatch<HostActionCommand>,
    pub(super) grant_cause: Option<ActionCause>,
    pub(super) resolution_scope: whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope,
}

pub(super) fn registered_editor_workflow(
    command: &HostActionCommand,
) -> Result<CompiledHostAction, String> {
    let action = editor_file_save_workflow()?;
    if command.operation != "file.save"
        || command.program_version_ref != action.version_ref()
        || command.input_schema_ref != action.input_schema_ref()
    {
        return Err("editor command uses an unavailable registered executable".into());
    }
    Ok(action)
}

impl Workbench {
    pub(super) fn prepare_native_editor_action(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        runtime_policy: &gaugedesk_whip_runtime::PolicyEpochRef,
    ) -> Result<NativeEditorPreparation, String> {
        self.prepare_native_editor_action_scoped(context, inputs, command, runtime_policy, &[])
    }

    pub(super) fn prepare_native_editor_action_scoped(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        runtime_policy: &gaugedesk_whip_runtime::PolicyEpochRef,
        extra_scopes: &[&str],
    ) -> Result<NativeEditorPreparation, String> {
        let refused = || "native editor delivery binding is invalid".to_owned();
        if command.issuer != self.authority().as_str()
            || inputs.authority_scope() != self.home_id().as_str()
            || command.provenance.initiator != context.actor().as_str()
            || command.provenance.executor != context.actor().as_str()
            || !command.provenance.delegation.is_empty()
            || !command.provenance.causes.is_empty()
            || command.provenance.origin != "editor.save"
            || command.operation != "file.save"
            || command.inputs.len() != 1
            || command.resources.len() != 2
        {
            return Err(refused());
        }
        let (format, project_id, chat_id): (String, String, String) =
            serde_json::from_str(&command.scope).map_err(|_| refused())?;
        if format != "gaugedesk.editor-file.v1" {
            return Err(refused());
        }
        let resolution_scope = resolution_scope::original(command)?;
        let input = command.inputs.get("content").ok_or_else(refused)?;
        let resource = command.resources.get("target").ok_or_else(refused)?;
        let (target_id, _branch, path): (String, String, String) =
            serde_json::from_str(resource.resource.selector.as_deref().ok_or_else(refused)?)
                .map_err(|_| refused())?;
        let ActionBasis::Version { version_ref: base } = &resource.basis else {
            return Err(refused());
        };
        let request = EditorFileSave {
            chat_id: &chat_id,
            request_id: &command.request_id,
            path: &path,
            base_cut: base,
            // Authorization uses intent coordinates, never caller-resupplied
            // replacement bytes. The exact admitted input is resolved below.
            content: "",
        };
        let home = self.home_id().clone();
        let scope = command.instance_ref().map_err(|_| refused())?;
        let identity = ActionPolicyIdentity {
            issuer: command.issuer.clone(),
            scope: command.scope.clone(),
            request_id: command.request_id.clone(),
        };
        let policy_scope = identity.storage_scope()?;
        let key = SigningKey::from_seed(&self.governance_seed()).map_err(|error| error.reason)?;
        let mut scopes = vec![
            LIBRARY_SCOPE,
            ORG_SCOPE,
            crate::account_auth::ACCOUNT_AUTH_SCOPE,
            crate::mobile_machine_session::SCOPE,
            &scope,
            &policy_scope,
        ];
        scopes.extend_from_slice(extra_scopes);
        if let ActorAuthentication::NativeEditorDispatchGrant { grant_ref } =
            context.authentication()
        {
            scopes.push(grant_ref);
        }
        let ((authority, grant_cause), basis) = self
            .store_ref()
            .read_for_dispatch(&scopes, |store| match context.authentication() {
                ActorAuthentication::NativeEditorDispatchGrant { grant_ref } => {
                    dispatch_grant::current_granted_authority(
                        store,
                        &home,
                        context,
                        grant_ref,
                        command,
                        &request,
                        &key.public_key(),
                    )
                    .map(|(authority, cause)| (authority, Some(cause)))
                }
                _ => current_authority(store, &home, context, &request)
                    .map(|authority| (authority, None)),
            })
            .map_err(|error| format!("current editor delivery authority refused: {error:?}"))?;
        if authority.project_id != project_id
            || authority.target_id != target_id
            || authority.workspace_path != path
        {
            return Err(refused());
        }
        if authority.resolution_scope != resolution_scope {
            return Err("current editor resolution scope differs from its admitted ceiling".into());
        }
        let root = GovernanceRootVerifier::new(self.authority().clone(), key.public_key());
        let policy = load_action_policy(self.store_ref(), &identity, &command.policy, &root)?;
        if canonicalize(policy.signed_envelope())? != canonicalize(&authority.policy.to_json()?)?
            || runtime_policy != policy.policy_ref()
        {
            return Err("current editor policy differs from its admitted ceiling".into());
        }
        let label = |binding| format!("policy:{}:{binding}", command.policy.envelope_hash);
        if input.handle != "admitted_input"
            || input.label_ref != label("admitted_input")
            || resource.label_ref != label("admitted_target")
            || resource.resource.handle != "admitted_target"
            || resource.resource.kind != "file_store"
            || resource.resource.writable != Some(true)
        {
            return Err(refused());
        }
        let delivery = self
            .store_mut()
            .committed_dispatch::<ProductActionAdmission>(&scope, &command.request_id)
            .map_err(|error| format!("editor product receipt refused: {error:?}"))?
            .ok_or_else(|| "editor action has no committed dispatch".to_owned())?;
        let original = self
            .store_ref()
            .fold::<ProductActionAdmission>(&scope)
            .map_err(|error| format!("editor admission history refused: {error:?}"))?;
        if original.command.as_ref() != Some(command) {
            return Err("editor receipt differs from its original admission history".into());
        }
        if &delivery.command != command
            || delivery.dispatch.runtime_ref != format!("{}:native", home)
            || delivery.dispatch.command_ref != command.fingerprint().map_err(|_| refused())?
        {
            return Err(refused());
        }
        let basis = authority
            .bind_deadline(basis)
            .map_err(|error| format!("editor authority deadline refused: {error:?}"))?;
        Ok(NativeEditorPreparation {
            scope,
            chat_id,
            key,
            basis,
            delivery,
            grant_cause,
            resolution_scope,
        })
    }

    pub(super) fn bind_native_editor_target(
        &self,
        chat_id: &str,
        command: &HostActionCommand,
    ) -> Result<gaugedesk_workspace::NativeFileActionTarget, String> {
        let resource = command
            .resources
            .get("target")
            .ok_or("missing editor target")?;
        let (_, branch, path): (String, String, String) = serde_json::from_str(
            resource
                .resource
                .selector
                .as_deref()
                .ok_or("missing editor target selector")?,
        )
        .map_err(|_| "invalid editor target selector")?;
        let ActionBasis::Version { version_ref: base } = &resource.basis else {
            return Err("editor target has no exact base".into());
        };
        let target = self
            .engagements
            .get(chat_id)
            .ok_or("editor workspace is unavailable")?
            .native_file_action_target(&path, base)
            .map_err(|error| format!("editor base refused: {error:?}"))?;
        if target.branch() != branch || target.path() != path || target.base() != base {
            return Err("editor target differs from its actual native binding".into());
        }
        Ok(target)
    }

    /// Deliver an exact factory command using the current request's verified
    /// actor context. Runtime and custody are trusted Home configuration. Caller
    /// command data is only an address/expectation until current authorization
    /// and the durable product receipt have both been checked.
    /// No effect executes, and missing admission is never repaired here.
    pub fn deliver_editor_file_save<S: RuntimeStore + LogAppend>(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        runtime: &mut GovernedHostFacade<S>,
    ) -> Result<RuntimeAcknowledgment, String> {
        let NativeEditorPreparation {
            scope,
            chat_id,
            key,
            basis,
            delivery,
            ..
        } = self.prepare_native_editor_action(context, inputs, command, runtime.policy_ref())?;
        let action = registered_editor_workflow(command)?;
        let target = self.bind_native_editor_target(&chat_id, command)?;
        let input = &command.inputs["content"];
        let refused = || "native editor delivery binding is invalid".to_owned();
        let bytes = command.signing_bytes().map_err(|_| refused())?;
        let receipt = inputs
            .publish(std::slice::from_ref(input), || {
                target.publish_base(|| {
                    self.store_mut()
                        .with_dispatch_basis(&basis, || {
                            let verifier = NativeAdmissionVerifier {
                                command,
                                key: key.public_key(),
                            };
                            let proof = key.sign(&bytes);
                            runtime.admit_action(
                                command.clone(),
                                &action,
                                &verifier,
                                proof.as_bytes(),
                            )
                        })
                        .map_err(|error| {
                            whipplescript_store::StoreError::Conflict(format!(
                                "editor delivery authorization changed: {error:?}"
                            ))
                        })?
                        .map_err(|error| {
                            whipplescript_store::StoreError::Conflict(format!(
                                "runtime editor admission refused: {error:?}"
                            ))
                        })
                })
            })
            .map_err(|error| format!("{error:?}"))?;
        record_runtime_acknowledgment(self.store_mut(), &scope, delivery, receipt)
            .map_err(|error| format!("editor runtime acknowledgment refused: {error:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LockUnpoisoned;
    #[test]
    fn native_admission_proof_binds_exact_command_bytes_and_configured_key() {
        let dir = tempfile::tempdir().unwrap();
        let (wb, command, _, _) = super::super::tests::admitted_fixture(dir.path());
        let key = SigningKey::from_seed(&wb.lock_unpoisoned().governance_seed()).unwrap();
        let verifier = NativeAdmissionVerifier {
            command: &command,
            key: key.public_key(),
        };
        let bytes = command.signing_bytes().unwrap();
        let signature = key.sign(&bytes);
        assert!(verifier
            .verify(&command, &bytes, signature.as_bytes())
            .is_ok());
        let foreign = SigningKey::from_seed(&[91; 32]).unwrap().sign(&bytes);
        assert!(verifier
            .verify(&command, &bytes, foreign.as_bytes())
            .is_err());
        assert!(verifier
            .verify(&command, b"different bytes", signature.as_bytes())
            .is_err());
        let mut changed = command.clone();
        changed.provenance.executor = "other actor".into();
        assert!(verifier
            .verify(&changed, &bytes, signature.as_bytes())
            .is_err());
    }
}
