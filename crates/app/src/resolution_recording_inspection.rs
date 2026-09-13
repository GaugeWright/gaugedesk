//! Current read authority over original correction evidence. Neither a former
//! author's grant nor a result receipt authorizes this investigator.
use super::*;
use crate::action_input_binding::{input_binding_scope, load_input_binding, NativeInputBinding};
use crate::action_policy::load_action_policy;
use crate::file_action_factory::storage::NativeActionObservationSource;
use gaugedesk_core::{
    ids::PublicKey,
    signature::{verify_signature, Signature},
};
use gaugedesk_store::command_dispatch::DispatchReadBasis;
use gaugedesk_whip_runtime::{
    host_actions::{
        action_result::{
            ActionResultSnapshot, ActionResultVerifier, ReadActionResult, ACTION_RESULT_PROTOCOL,
        },
        facade::GovernedHostFacade,
        LogAppend,
    },
    sign_hosted_policy_envelope, ProtocolError,
};
use whipplescript_kernel::gov::canonicalize;
use whipplescript_store::{
    branches::resolution_batch::ResolutionMemoryReceipt,
    vcs_resolution_recording::{read_committed_resolution_recording, ResolutionRecordingBinding},
    SqliteStore, StoreError, StoreResult,
};

#[path = "resolution_recording_inspection_binding.rs"]
mod original;
#[path = "resolution_recording_inspection_policy.rs"]
mod policy;

/// Authorized historical metadata. The snapshot retains the runtime's own
/// disposition: finding a target receipt does not reconcile or complete it.
pub struct EditorCorrectionObservation {
    pub evidence: ActionResultSnapshot,
    pub binding: ResolutionRecordingBinding,
    pub receipt: Option<ResolutionMemoryReceipt>,
}

struct CorrectionInspectionPreparation {
    key: SigningKey,
    basis: DispatchReadBasis,
    signed_policy: String,
    read_policy: HostGovernancePolicy,
    read_clearances: BTreeSet<String>,
    input_binding: Option<NativeInputBinding>,
    target: gaugedesk_workspace::NativeResolutionRecordingEvidenceTarget,
    source: NativeActionObservationSource,
}

fn refused(error: impl std::fmt::Debug) -> StoreError {
    StoreError::Conflict(format!("correction inspection refused: {error:?}"))
}

struct CurrentReadVerifier<'a> {
    request: &'a ReadActionResult,
    key: PublicKey,
}
impl ActionResultVerifier for CurrentReadVerifier<'_> {
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
                "current correction evidence reader",
            ));
        }
        Ok(())
    }
}

fn read_evidence(
    runtime: &GovernedHostFacade<SqliteStore>,
    context: &AuthenticatedActionContext,
    command: &HostActionCommand,
    admission: &ActionAdmissionReceipt,
    key: &SigningKey,
) -> StoreResult<ActionResultSnapshot> {
    admission.validate_for(command).map_err(refused)?;
    let request = ReadActionResult {
        protocol: ACTION_RESULT_PROTOCOL.into(),
        issuer: command.issuer.clone(),
        scope: command.scope.clone(),
        policy: runtime.policy_ref().clone(),
        provenance: ActionProvenance {
            initiator: context.actor().as_str().into(),
            executor: context.actor().as_str().into(),
            delegation: vec![],
            origin: "editor.corrections.inspect".into(),
            causes: vec![],
        },
        admission: admission.clone(),
        evidence_handle: "result".into(),
        evidence_label_ref: format!("policy:{}:result", runtime.policy_ref().envelope_hash),
        through: None,
    };
    let bytes = request.signing_bytes().map_err(refused)?;
    let verifier = CurrentReadVerifier {
        request: &request,
        key: key.public_key(),
    };
    let snapshot = runtime
        .read_action_result(request.clone(), &verifier, key.sign(&bytes).as_bytes())
        .map_err(refused)?;
    if &snapshot.command != command || &snapshot.admission != admission {
        return Err(refused(
            "runtime differs from the original admitted correction",
        ));
    }
    Ok(snapshot)
}

impl CorrectionInspectionPreparation {
    fn runtime(
        &self,
        issuer: &gaugedesk_core::ids::AuthorityId,
    ) -> StoreResult<GovernedHostFacade<SqliteStore>> {
        let root = GovernanceRootVerifier::new(issuer.clone(), self.key.public_key());
        GovernedHostFacade::from_signed_store_with_verifier(
            self.source.open()?,
            1,
            &self.signed_policy,
            &root,
        )
        .map_err(refused)
    }
}

impl Workbench {
    fn prepare_correction_inspection(
        &mut self,
        context: &AuthenticatedActionContext,
        command: &HostActionCommand,
    ) -> Result<CorrectionInspectionPreparation, String> {
        self.prepare_correction_inspection_scoped(context, command, &[])
    }

    fn prepare_correction_inspection_scoped(
        &mut self,
        context: &AuthenticatedActionContext,
        command: &HostActionCommand,
        extra_scopes: &[&str],
    ) -> Result<CorrectionInspectionPreparation, String> {
        if command.issuer != self.authority().as_str()
            || command.provenance.initiator != command.provenance.executor
            || !command.provenance.delegation.is_empty()
            || command.inputs.len() != 1
            || command.resources.len() != 1
        {
            return Err(
                "original correction command is outside the registered native profile".into(),
            );
        }
        let source_scope = Self::correction_source_scope(command)?;
        // Validate the original registered operation, not the old actor's current
        // account. Revoking that actor must not erase another reader's history.
        delivery::registered_recording_workflow(command)?;
        command
            .signing_bytes()
            .map_err(|error| format!("{error:?}"))?;
        let original_scope = delivery::original_scope(command)?;
        let (version, project, chat, path): (String, String, String, String) =
            serde_json::from_str(&command.scope).map_err(|error| error.to_string())?;
        if version != "gaugedesk.editor-corrections.v1" {
            return Err("original correction scope is unavailable".into());
        }
        let input = command
            .inputs
            .get("corrections")
            .ok_or("original correction input is missing")?;
        if input.handle != "admitted_corrections"
            || input.label_ref
                != format!(
                    "policy:{}:admitted_corrections",
                    command.policy.envelope_hash
                )
        {
            return Err("original correction input binding is invalid".into());
        }
        let home = self.home_id().clone();
        let identity = ActionPolicyIdentity {
            issuer: command.issuer.clone(),
            scope: command.scope.clone(),
            request_id: command.request_id.clone(),
        };
        let scope = command
            .instance_ref()
            .map_err(|error| format!("{error:?}"))?;
        let policy_scope = identity.storage_scope()?;
        let mapping_scope =
            input_binding_scope(&command.issuer, input).map_err(|error| format!("{error:?}"))?;
        let key = SigningKey::from_seed(&self.governance_seed()).map_err(|error| error.reason)?;
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
        scopes.extend_from_slice(extra_scopes);
        scopes.extend(source_scope.as_deref());
        let ((current, admitted, original, mapping), basis) = self
            .store_ref()
            .read_for_dispatch(&scopes, |store| {
                let current = current_target_authority(
                    store,
                    &home,
                    context,
                    &NativeTargetIntent {
                        chat_id: &chat,
                        request_id: &command.request_id,
                        path: &path,
                    },
                    NativeActionKind::InspectHistory,
                )?;
                let admitted = store.fold::<ProductActionAdmission>(&scope)?;
                let retained = load_action_policy(store, &identity, &command.policy, &root)
                    .map_err(|_| invalid("original correction policy is unavailable"))?;
                let original = delivery::original_policy(retained.signed_envelope())
                    .map_err(|_| invalid("original correction policy is unrepresentable"))?;
                Self::correction_source_policy(
                    store,
                    home.as_str(),
                    &key.public_key(),
                    command,
                    &original,
                )
                .map_err(|_| invalid("original correction source evidence is unavailable"))?;
                let mapping = load_input_binding(
                    store,
                    &command.issuer,
                    home.as_str(),
                    input,
                    &key.public_key(),
                );
                Ok((current, admitted, original, mapping))
            })
            .map_err(|error| format!("current correction read authority refused: {error:?}"))?;
        if admitted.command.as_ref() != Some(command)
            || current.project_id != project
            || current.workspace_path != path
        {
            return Err(
                "correction inspection differs from original admission or current target".into(),
            );
        }
        let dispatch = self
            .store_mut()
            .committed_dispatch::<ProductActionAdmission>(&scope, &command.request_id)
            .map_err(|error| format!("original correction receipt refused: {error:?}"))?
            .ok_or("original correction has no committed dispatch")?;
        if dispatch.command != *command
            || dispatch.dispatch.runtime_ref != format!("{home}:native")
            || dispatch.dispatch.command_ref
                != command
                    .fingerprint()
                    .map_err(|error| format!("{error:?}"))?
        {
            return Err("correction inspection has no original Home outbox binding".into());
        }
        let read_policy = policy::compile(&current, &original_scope, &original)?;
        let signed_policy =
            sign_hosted_policy_envelope(&read_policy.to_json()?, self.authority(), &key, 1)?;
        let target = self
            .engagements
            .get(&chat)
            .ok_or("correction workspace is unavailable")?
            .native_resolution_recording_evidence_target(&path, original_scope)
            .map_err(|error| format!("{error:?}"))?;
        let source = self.native_action_observation_source()?;
        let basis = current
            .bind_deadline(basis)
            .map_err(|error| format!("{error:?}"))?;
        Ok(CorrectionInspectionPreparation {
            key,
            basis,
            signed_policy,
            read_policy,
            read_clearances: current.read_clearances.clone(),
            input_binding: mapping.map_err(|error| format!("{error:?}"))?,
            target,
            source,
        })
    }

    /// Read original metadata as a current independently authorized reader.
    /// No input database, writer initialization, lease or effect is required.
    pub fn read_editor_corrections_evidence(
        &mut self,
        context: &AuthenticatedActionContext,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
    ) -> Result<ActionResultSnapshot, String> {
        let prepared = self.prepare_correction_inspection(context, command)?;
        let issuer = self.authority().clone();
        self.store_mut()
            .with_dispatch_basis(&prepared.basis, || {
                let runtime = prepared.runtime(&issuer)?;
                read_evidence(&runtime, context, command, admission, &prepared.key)
            })
            .map_err(|error| format!("{error:?}"))?
            .map_err(|error| format!("{error:?}"))
    }

    /// Inspect one original attempt and its actual retained batch. An absent
    /// target receipt remains absent, without inferring that nothing happened.
    pub fn inspect_editor_correction_attempt(
        &mut self,
        context: &AuthenticatedActionContext,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        effect_id: &str,
        run_id: &str,
    ) -> Result<EditorCorrectionObservation, String> {
        let prepared = self.prepare_correction_inspection(context, command)?;
        let issuer = self.authority().clone();
        self.store_mut()
            .with_dispatch_basis(&prepared.basis, || -> StoreResult<_> {
                let runtime = prepared.runtime(&issuer)?;
                let evidence = read_evidence(&runtime, context, command, admission, &prepared.key)?;
                let mapping = prepared
                    .input_binding
                    .as_ref()
                    .ok_or_else(|| refused("original input mapping is unavailable"))?;
                let store = runtime.kernel().store();
                let effect = store
                    .list_effects(&admission.instance_ref)?
                    .into_iter()
                    .find(|effect| effect.effect_id == effect_id)
                    .ok_or_else(|| refused("original effect is unavailable"))?;
                let binding = original::binding(
                    &evidence,
                    store.chain_prefix(&admission.instance_ref)?,
                    effect,
                    run_id,
                    mapping,
                    prepared.target.scope(),
                )?;
                let receipt = prepared.target.observe(&binding, |workspace| {
                    read_committed_resolution_recording(workspace, &binding)
                })?;
                Ok(EditorCorrectionObservation {
                    evidence,
                    binding,
                    receipt,
                })
            })
            .map_err(|error| format!("{error:?}"))?
            .map_err(|error| format!("{error:?}"))
    }
}

#[path = "resolution_recording_reconciliation.rs"]
mod reconciliation;
pub use reconciliation::{
    AdmittedEditorCorrectionReconciliation, AdmittedEditorCorrectionResult,
    CorrectionReconciliationAcknowledgment, EditorCorrectionReconciliation,
    EditorCorrectionResultRequest, NativeCorrectionReconciliationRuntime,
    NativeEditorCorrectionResult,
};
