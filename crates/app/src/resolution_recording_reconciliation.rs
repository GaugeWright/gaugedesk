//! A current investigator's independently admitted request to reconcile one
//! historical correction attempt. Admission changes no runtime disposition.
use super::*;
use gaugedesk_core::host_action_admission::HostActionAdmission;
use gaugedesk_store::command_dispatch::CommandDispatch;
use gaugedesk_whip_runtime::host_actions::recovery::{
    ReconcileEffectCommand, EFFECT_RECONCILIATION_PROTOCOL,
};
use sha2::{Digest, Sha256};
use whipplescript_store::effect_recovery::{DispositionEvidence, EvidenceDisposition};

/// Request coordinates only. Authority, policy, attribution and target proof
/// are derived from the current Home and original recorded attempt.
pub struct EditorCorrectionReconciliation<'a> {
    pub request_id: &'a str,
    pub effect_id: &'a str,
    pub run_id: &'a str,
}

#[derive(Debug)]
pub struct AdmittedEditorCorrectionReconciliation {
    pub command: ReconcileEffectCommand,
    pub replayed: bool,
}

// The existing product lifecycle carries the owner's exact command wire type.
// Reconciliation has its own storage namespace, never the original admission's.
type ProductReconciliationAdmission = HostActionAdmission<ReconcileEffectCommand>;

fn request_scope(original: &HostActionCommand, request_id: &str) -> Result<String, String> {
    if request_id.trim().is_empty() {
        return Err("correction reconciliation requires a stable request identity".into());
    }
    // Reconciliation request identity belongs to one original runtime instance.
    serde_json::to_string(&(
        "gaugedesk.editor-corrections.reconcile.v1",
        original
            .instance_ref()
            .map_err(|error| format!("{error:?}"))?,
        &original.issuer,
        &original.scope,
        request_id,
    ))
    .map_err(|error| error.to_string())
}

fn reconciliation_provenance(
    context: &AuthenticatedActionContext,
    original: &HostActionCommand,
    admission: &ActionAdmissionReceipt,
) -> Result<ActionProvenance, String> {
    Ok(ActionProvenance {
        initiator: context.actor().as_str().into(),
        executor: context.actor().as_str().into(),
        delegation: vec![],
        origin: "editor.corrections.reconcile".into(),
        causes: vec![ActionCause {
            authority: original.issuer.clone(),
            record_ref: serde_json::to_string(&(
                &admission.instance_ref,
                admission.admitted_at.sequence,
            ))
            .map_err(|error| error.to_string())?,
            digest: admission.admitted_at.head_digest.clone(),
        }],
    })
}

impl Workbench {
    /// Durably admit a new investigator act and its exact runtime outbox.
    /// This is intent, not applied standing, ownership or a recording retry.
    pub fn admit_editor_correction_reconciliation(
        &mut self,
        context: &AuthenticatedActionContext,
        original: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        request: &EditorCorrectionReconciliation<'_>,
    ) -> Result<AdmittedEditorCorrectionReconciliation, String> {
        let scope = request_scope(original, request.request_id)?;
        // Keep the basis from before historical observation through admission.
        // A later snapshot must not legitimize metadata obtained before a
        // mapping, grant or target change between these two operations.
        let prepared = self.prepare_correction_inspection(context, original)?;
        let observed = self.inspect_editor_correction_attempt(
            context,
            original,
            admission,
            request.effect_id,
            request.run_id,
        )?;
        let receipt = observed
            .receipt
            .as_ref()
            .ok_or("correction target receipt is unavailable; outcome remains unknown")?;
        let frame = observed
            .evidence
            .effects
            .iter()
            .find(|effect| effect.effect_id == request.effect_id)
            .and_then(|effect| {
                effect
                    .attempts
                    .iter()
                    .find(|attempt| attempt.run_id == request.run_id)
            })
            .and_then(|attempt| attempt.dispatch.as_ref())
            .ok_or("original correction dispatch is unavailable")?
            .frame
            .clone();
        let (receipt_json, _) = receipt.encode().map_err(|error| format!("{error:?}"))?;
        let resource = original
            .resources
            .get("resolutions")
            .ok_or("original correction resource is unavailable")?;
        let identity = ActionPolicyIdentity {
            issuer: original.issuer.clone(),
            scope: scope.clone(),
            request_id: request.request_id.into(),
        };
        let policy = crate::action_policy::prepare_action_policy(
            self.store_mut(),
            &identity,
            &prepared.read_policy,
            &prepared.key,
        )?;
        let command = ReconcileEffectCommand {
            protocol: EFFECT_RECONCILIATION_PROTOCOL.into(),
            issuer: original.issuer.clone(),
            scope: original.scope.clone(),
            request_id: request.request_id.into(),
            policy: policy.policy_ref().clone(),
            provenance: reconciliation_provenance(context, original, admission)?,
            evidence: DispositionEvidence {
                frame,
                disposition: EvidenceDisposition::Applied,
                evidence_ref: resource.resource.handle.clone(),
                evidence_digest: hex::encode(Sha256::digest(receipt_json.as_bytes())),
                authority_ref: original.issuer.clone(),
            },
            evidence_label_ref: resource.label_ref.clone(),
        };
        let dispatch = CommandDispatch {
            runtime_ref: format!("{}:native", self.home_id()),
            command_ref: command
                .fingerprint()
                .map_err(|error| format!("{error:?}"))?,
        };
        let admitted = self
            .store_mut()
            .admit_with_dispatch_against::<ProductReconciliationAdmission>(
                &scope,
                request.request_id,
                command.clone(),
                &dispatch,
                &prepared.basis,
            )
            .map_err(|error| format!("correction reconciliation admission refused: {error:?}"))?;
        Ok(AdmittedEditorCorrectionReconciliation {
            command,
            replayed: admitted.replayed,
        })
    }
}

#[path = "resolution_recording_reconciliation_delivery.rs"]
mod delivery;
pub use delivery::{
    AdmittedEditorCorrectionResult, CorrectionReconciliationAcknowledgment,
    EditorCorrectionResultRequest, NativeCorrectionReconciliationRuntime,
    NativeEditorCorrectionResult,
};
