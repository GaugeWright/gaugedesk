//! Delivery of a separately admitted investigation, with current authority and
//! explicit runtime ownership. Acknowledgment is not a product correction result.
use super::*;
use crate::action_policy::load_action_policy;
use gaugedesk_store::{command_dispatch::CommittedDispatch, CommandRecordFact};
use gaugedesk_whip_runtime::host_actions::{
    execution::ExecuteActionEffect,
    recovery::{ReconciliationReceipt, RecordedReconciliation},
};
use whipplescript_kernel::host_facade::{
    ResolutionRecordingEvidenceSource, ResolutionRecordingReconciliationAuthority,
};
use whipplescript_store::event_chain::fold_owned;

const ACK_KIND: &str = "native_correction_reconciliation_ack_v1";

/// Holds the epoch actually acquired for this exact admitted request. Possession
/// never replaces the current product authority checked by each delivery.
pub struct NativeCorrectionReconciliationRuntime {
    runtime: GovernedHostFacade<SqliteStore>,
    home_root: std::path::PathBuf,
    original: ActionAdmissionReceipt,
    command: ReconcileEffectCommand,
    epoch: i64,
}

impl NativeCorrectionReconciliationRuntime {
    fn require_home(&self, wb: &Workbench) -> StoreResult<()> {
        if self.home_root != wb.root_path().canonicalize()? {
            return Err(refused(
                "correction reconciliation belongs to a different Home root",
            ));
        }
        Ok(())
    }

    fn require_current(
        &self,
        original: &ActionAdmissionReceipt,
        command: &ReconcileEffectCommand,
    ) -> StoreResult<()> {
        if original != &self.original
            || command != &self.command
            || self.runtime.policy_ref() != &command.policy
            || self
                .runtime
                .kernel()
                .store()
                .instance_owner_epoch(&original.instance_ref)?
                != self.epoch
        {
            return Err(refused(
                "correction reconciliation ownership is stale or mismatched",
            ));
        }
        Ok(())
    }
}

/// A durable link to the runtime owner's receipt. It claims no product outcome,
/// successful terminal, continuation or insertion by the investigator.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrectionReconciliationAcknowledgment {
    pub product_command_id: String,
    pub runtime_ref: String,
    pub receipt: ReconciliationReceipt,
}

struct Preparation {
    inspection: CorrectionInspectionPreparation,
    scope: String,
    delivery: CommittedDispatch<ReconcileEffectCommand>,
    signed_policy: String,
}

struct CurrentAuthority<'a> {
    request: &'a ReconcileEffectCommand,
    original: &'a HostActionCommand,
    execution: &'a ExecuteActionEffect,
    binding: &'a ResolutionRecordingBinding,
    key: PublicKey,
}

impl ResolutionRecordingReconciliationAuthority for CurrentAuthority<'_> {
    fn authenticate(
        &self,
        command: &ReconcileEffectCommand,
        signing_bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if command != self.request
            || signing_bytes != self.request.signing_bytes()?
            || !verify_signature(signing_bytes, &Signature::new(proof), &self.key).unwrap_or(false)
        {
            return Err(ProtocolError::Mismatch(
                "current correction investigator proof",
            ));
        }
        Ok(())
    }

    fn authorize(
        &self,
        command: &ReconcileEffectCommand,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        binding: &ResolutionRecordingBinding,
    ) -> Result<(), ProtocolError> {
        if command != self.request
            || original != self.original
            || execution != self.execution
            || binding != self.binding
        {
            return Err(ProtocolError::Mismatch(
                "current correction historical binding",
            ));
        }
        Ok(())
    }
}

fn validate_receipt(
    runtime: &GovernedHostFacade<SqliteStore>,
    command: &ReconcileEffectCommand,
    receipt: &ReconciliationReceipt,
) -> StoreResult<RecordedReconciliation> {
    let instance = &command.evidence.frame.instance_id;
    if receipt.protocol != EFFECT_RECONCILIATION_PROTOCOL
        || receipt.request_key != command.request_key().map_err(refused)?
        || receipt.fingerprint != command.fingerprint().map_err(refused)?
        || receipt.recorded_at.instance_ref != *instance
    {
        return Err(refused(
            "runtime reconciliation receipt differs from its request",
        ));
    }
    let sequence = i64::try_from(receipt.recorded_at.sequence).map_err(refused)?;
    let mut prefix = runtime.kernel().store().chain_prefix(instance)?;
    prefix.retain(|row| row.sequence <= sequence);
    let head = fold_owned(instance, &prefix);
    let event = prefix
        .last()
        .ok_or_else(|| refused("reconciliation receipt history is missing"))?;
    if head.sequence != Some(sequence)
        || head.digest != receipt.recorded_at.head_digest
        || event.event_type != "effect.disposition.reconciled"
        || event.source.as_deref() != Some("kernel")
    {
        return Err(refused(
            "reconciliation receipt has no matching runtime event",
        ));
    }
    let recorded: RecordedReconciliation = serde_json::from_str(&event.payload_json)?;
    if recorded.command != *command {
        return Err(refused("reconciliation history contains another request"));
    }
    // A diagnostic can acknowledge an investigation without establishing an
    // undisputed Applied outcome. Product result admission remains separate.
    Ok(recorded)
}

impl Workbench {
    fn prepare_correction_reconciliation_delivery(
        &mut self,
        context: &AuthenticatedActionContext,
        original: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        command: &ReconcileEffectCommand,
    ) -> Result<Preparation, String> {
        command
            .signing_bytes()
            .map_err(|error| format!("{error:?}"))?;
        admission
            .validate_for(original)
            .map_err(|error| format!("{error:?}"))?;
        let scope = request_scope(original, &command.request_id)?;
        let identity = ActionPolicyIdentity {
            issuer: original.issuer.clone(),
            scope: scope.clone(),
            request_id: command.request_id.clone(),
        };
        let policy_scope = identity.storage_scope()?;
        let inspection =
            self.prepare_correction_inspection_scoped(context, original, &[&scope, &policy_scope])?;
        let delivery = self
            .store_mut()
            .committed_dispatch::<ProductReconciliationAdmission>(&scope, &command.request_id)
            .map_err(|error| format!("{error:?}"))?
            .ok_or("correction reconciliation has no committed outbox")?;
        if delivery.command != *command
            || delivery.dispatch.runtime_ref != format!("{}:native", self.home_id())
            || delivery.dispatch.command_ref
                != command
                    .fingerprint()
                    .map_err(|error| format!("{error:?}"))?
            || command.issuer != original.issuer
            || command.scope != original.scope
            || command.provenance != reconciliation_provenance(context, original, admission)?
            || command.evidence.frame.instance_id != admission.instance_ref
            || command.evidence.disposition != EvidenceDisposition::Applied
            || command.evidence.authority_ref != original.issuer
            || command.evidence.evidence_ref != original.resources["resolutions"].resource.handle
            || command.evidence_label_ref != original.resources["resolutions"].label_ref
        {
            return Err(
                "correction reconciliation differs from its admitted current authority".into(),
            );
        }
        let root =
            GovernanceRootVerifier::new(self.authority().clone(), inspection.key.public_key());
        let policy = load_action_policy(self.store_ref(), &identity, &command.policy, &root)?;
        if canonicalize(policy.signed_envelope())?
            != canonicalize(&inspection.read_policy.to_json()?)?
        {
            return Err("current correction read policy differs from its admitted ceiling".into());
        }
        Ok(Preparation {
            inspection,
            scope,
            delivery,
            signed_policy: policy.signed_envelope().into(),
        })
    }

    /// Acquire metadata ownership for an existing, separately admitted request.
    /// This does not reconcile, retry a recording or create an original action.
    pub fn claim_editor_correction_reconciliation(
        &mut self,
        context: &AuthenticatedActionContext,
        original: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        command: &ReconcileEffectCommand,
    ) -> Result<NativeCorrectionReconciliationRuntime, String> {
        let prepared =
            self.prepare_correction_reconciliation_delivery(context, original, admission, command)?;
        let source = self.native_action_reconciliation_source()?;
        let issuer = self.authority().clone();
        self.store_mut()
            .with_dispatch_basis(&prepared.inspection.basis, || -> StoreResult<_> {
                // Missing original history refuses before opening a metadata writer.
                let observed = prepared.inspection.runtime(&issuer)?;
                read_evidence(
                    &observed,
                    context,
                    original,
                    admission,
                    &prepared.inspection.key,
                )?;
                let root =
                    GovernanceRootVerifier::new(issuer, prepared.inspection.key.public_key());
                let (home_root, store) = source.open()?;
                let mut runtime = GovernedHostFacade::from_signed_store_with_verifier(
                    store,
                    command.policy.epoch,
                    &prepared.signed_policy,
                    &root,
                )
                .map_err(refused)?;
                // Verify the actual writer too; an observation never vouches for a
                // replacement database or grants ownership to a new empty history.
                read_evidence(
                    &runtime,
                    context,
                    original,
                    admission,
                    &prepared.inspection.key,
                )?;
                let epoch = runtime
                    .kernel_mut()
                    .store_mut()
                    .claim_instance_ownership(&admission.instance_ref)?;
                Ok(NativeCorrectionReconciliationRuntime {
                    runtime,
                    home_root,
                    original: admission.clone(),
                    command: command.clone(),
                    epoch,
                })
            })
            .map_err(|error| format!("{error:?}"))?
            .map_err(|error| format!("{error:?}"))
    }

    /// Deliver the original outbox request under current access and its acquired
    /// owner epoch. Lost acknowledgments recover the same runtime receipt.
    pub fn deliver_editor_correction_reconciliation(
        &mut self,
        context: &AuthenticatedActionContext,
        original: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        command: &ReconcileEffectCommand,
        owner: &mut NativeCorrectionReconciliationRuntime,
    ) -> Result<CorrectionReconciliationAcknowledgment, String> {
        owner
            .require_home(self)
            .map_err(|error| format!("{error:?}"))?;
        let prepared =
            self.prepare_correction_reconciliation_delivery(context, original, admission, command)?;
        owner
            .require_current(admission, command)
            .map_err(|error| format!("{error:?}"))?;
        self.store_mut()
            .with_dispatch_record_admission(
                &prepared.inspection.basis,
                |writer| -> StoreResult<_> {
                    owner.require_current(admission, command)?;
                    let evidence = read_evidence(
                        &owner.runtime,
                        context,
                        original,
                        admission,
                        &prepared.inspection.key,
                    )?;
                    let store = owner.runtime.kernel().store();
                    let effect = store
                        .list_effects(&admission.instance_ref)?
                        .into_iter()
                        .find(|effect| effect.effect_id == command.evidence.frame.effect_id)
                        .ok_or_else(|| refused("original correction effect is unavailable"))?;
                    let mapping = prepared.inspection.input_binding.as_ref().ok_or_else(|| {
                        refused("original correction input mapping is unavailable")
                    })?;
                    let historical = original::verified(
                        &evidence,
                        store.chain_prefix(&admission.instance_ref)?,
                        effect,
                        &command.evidence.frame.run_id,
                        mapping,
                        prepared.inspection.target.scope(),
                    )?;
                    let authority = CurrentAuthority {
                        request: command,
                        original,
                        execution: &historical.execution,
                        binding: &historical.binding,
                        key: prepared.inspection.key.public_key(),
                    };
                    let proof = prepared
                        .inspection
                        .key
                        .sign(&command.signing_bytes().map_err(refused)?);
                    let action = ResolutionRecordingAction::compile().map_err(refused)?;
                    prepared
                        .inspection
                        .target
                        .observe(&historical.binding, |workspace| {
                            let source = ResolutionRecordingEvidenceSource {
                                action: &action,
                                admission,
                                workspace,
                                authority_ref: &original.issuer,
                            };
                            let receipt = owner
                                .runtime
                                .reconcile_resolution_recording(
                                    command.clone(),
                                    owner.epoch,
                                    &source,
                                    &authority,
                                    proof.as_bytes(),
                                )
                                .map_err(refused)?;
                            validate_receipt(&owner.runtime, command, &receipt)?;
                            let ack = CorrectionReconciliationAcknowledgment {
                                product_command_id: prepared.delivery.command_id.clone(),
                                runtime_ref: prepared.delivery.dispatch.runtime_ref.clone(),
                                receipt,
                            };
                            let payload = serde_json::to_string(&ack)?;
                            writer
                                .commit(
                                    &format!("correction-reconciliation-ack:{}", prepared.scope),
                                    "reconciled",
                                    &payload,
                                    &[CommandRecordFact {
                                        scope_id: prepared.scope.clone(),
                                        kind: ACK_KIND.into(),
                                        payload: payload.clone(),
                                    }],
                                )
                                .map_err(refused)?;
                            Ok(ack)
                        })
                },
            )
            .map_err(|error| format!("{error:?}"))?
            .map_err(|error| format!("{error:?}"))
    }
}

#[path = "resolution_recording_result.rs"]
mod result;
pub use result::{
    AdmittedEditorCorrectionResult, EditorCorrectionResultRequest, NativeEditorCorrectionResult,
};
