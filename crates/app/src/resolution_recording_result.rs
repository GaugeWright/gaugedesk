//! Admit a historical correction result without changing execution or memory.
use super::*;
use gaugedesk_whip_runtime::PolicyEpochRef;
use sha2::{Digest, Sha256};
use whipplescript_kernel::host_protocol::PinnedPosition;
use whipplescript_store::effect_recovery::ExternalDisposition;

const RESULT_KIND: &str = "native_correction_result_v1";
const RESULT_PROTOCOL: &str = "gaugedesk.native-correction-result.v1";

/// Coordinates for a new product admission, never supplied outcome evidence.
pub struct EditorCorrectionResultRequest<'a> {
    pub request_id: &'a str,
    pub reconciliation_request_id: &'a str,
}

/// Metadata observed at an exact runtime prefix. Content identities do not
/// promise retained bodies, today's memory, or completion of the workflow.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEditorCorrectionResult {
    pub protocol: String,
    pub issuer: String,
    pub request_id: String,
    pub admission: ActionAdmissionReceipt,
    pub policy: PolicyEpochRef,
    pub evidence_label_ref: String,
    pub provenance: ActionProvenance,
    pub reconciliation: ReconcileEffectCommand,
    pub acknowledgment: CorrectionReconciliationAcknowledgment,
    pub observed_at: PinnedPosition,
    pub binding: ResolutionRecordingBinding,
    pub recording: ResolutionMemoryReceipt,
}

pub struct AdmittedEditorCorrectionResult {
    pub result: NativeEditorCorrectionResult,
    pub replayed: bool,
}

fn result_scope(original: &HostActionCommand, request_id: &str) -> Result<String, String> {
    if request_id.trim().is_empty() {
        return Err("correction result requires a stable request identity".into());
    }
    serde_json::to_string(&(
        "gaugedesk.editor-corrections.result.v1",
        original
            .instance_ref()
            .map_err(|error| format!("{error:?}"))?,
        request_id,
    ))
    .map_err(|error| error.to_string())
}

fn result_policy_identity(
    original: &HostActionCommand,
    request_id: &str,
) -> Result<ActionPolicyIdentity, String> {
    Ok(ActionPolicyIdentity {
        issuer: original.issuer.clone(),
        scope: result_scope(original, request_id)?,
        request_id: request_id.into(),
    })
}

fn cause(original: &HostActionCommand, position: &PinnedPosition) -> StoreResult<ActionCause> {
    Ok(ActionCause {
        authority: original.issuer.clone(),
        record_ref: serde_json::to_string(&(&position.instance_ref, position.sequence))?,
        digest: position.head_digest.clone(),
    })
}

fn verify_reconciliation_identity(
    original: &HostActionCommand,
    admission: &ActionAdmissionReceipt,
    command: &ReconcileEffectCommand,
) -> StoreResult<()> {
    command.validate().map_err(refused)?;
    let resource = original
        .resources
        .get("resolutions")
        .ok_or_else(|| refused("missing original resource"))?;
    if command.issuer != original.issuer
        || command.scope != original.scope
        || command.evidence.frame.instance_id != admission.instance_ref
        || command.evidence.disposition != EvidenceDisposition::Applied
        || command.evidence.authority_ref != original.issuer
        || command.evidence.evidence_ref != resource.resource.handle
        || command.evidence_label_ref != resource.label_ref
        || command.provenance.initiator != command.provenance.executor
        || command.provenance.origin != "editor.corrections.reconcile"
        || !command.provenance.delegation.is_empty()
        || command.provenance.causes != [cause(original, &admission.admitted_at)?]
    {
        return Err(refused(
            "reconciliation is not an original correction investigation",
        ));
    }
    Ok(())
}

fn retained_fact<T: serde::de::DeserializeOwned>(
    store: &Store,
    command_scope: &str,
    key: &str,
    fact_scope: &str,
    kind: &str,
) -> Result<Option<T>, String> {
    let payload = store
        .committed_record_snapshot(command_scope, key)
        .map_err(|error| format!("{error:?}"))?;
    let facts = store
        .records(fact_scope, kind)
        .map_err(|error| format!("{error:?}"))?;
    let Some(payload) = payload else {
        return if facts.is_empty() {
            Ok(None)
        } else {
            Err("correction product fact has no committed receipt".into())
        };
    };
    if facts != [payload.clone()] {
        return Err("correction result has no unique matching product fact".into());
    }
    serde_json::from_str(&payload)
        .map(Some)
        .map_err(|_| "invalid correction result fact".into())
}

fn verify_result_identity(
    original: &HostActionCommand,
    admission: &ActionAdmissionReceipt,
    request_id: &str,
    result: &NativeEditorCorrectionResult,
) -> StoreResult<()> {
    admission.validate_for(original).map_err(refused)?;
    verify_reconciliation_identity(original, admission, &result.reconciliation)?;
    let receipt = &result.acknowledgment.receipt;
    let (json, digest) = result.recording.encode()?;
    // Delegate receipt ordering and first-winner consistency to its owner.
    ResolutionMemoryReceipt::decode(&result.recording.request.operation_id, &json, &digest)?;
    if result.protocol != RESULT_PROTOCOL
        || result.issuer != original.issuer
        || result.request_id != request_id
        || result.admission != *admission
        || result.evidence_label_ref != format!("policy:{}:result", result.policy.envelope_hash)
        || result.provenance.initiator != result.provenance.executor
        || result.provenance.origin != "editor.corrections.result"
        || !result.provenance.delegation.is_empty()
        || result.provenance.causes
            != [
                cause(original, &admission.admitted_at)?,
                cause(original, &receipt.recorded_at)?,
            ]
        || result.recording.request != *result.binding.batch()
        || result.recording.request.actor != original.provenance.executor
        || result.recording.request.intent != original.fingerprint().map_err(refused)?
        || result.binding.scope()
            != &crate::file_action_factory::recording::delivery::original_scope(original)
                .map_err(refused)?
        || result.observed_at.instance_ref != admission.instance_ref
        || receipt.recorded_at.instance_ref != admission.instance_ref
        || receipt.recorded_at.sequence > result.observed_at.sequence
        || receipt.protocol != EFFECT_RECONCILIATION_PROTOCOL
        || receipt.request_key != result.reconciliation.request_key().map_err(refused)?
        || receipt.fingerprint != result.reconciliation.fingerprint().map_err(refused)?
        || hex::encode(Sha256::digest(json.as_bytes()))
            != result.reconciliation.evidence.evidence_digest
    {
        return Err(refused(
            "correction result differs from its historical identities",
        ));
    }
    result.provenance.validate().map_err(refused)
}

// Additional historical metadata restrictions survive policy relaxation.
// This adds confidentiality only; it never imports historical execution grants.
fn retain_restrictions(
    prepared: &mut CorrectionInspectionPreparation,
    retained: &crate::action_policy::RetainedActionPolicy,
    issuer: &gaugedesk_core::ids::AuthorityId,
) -> Result<(), String> {
    let policy: HostGovernancePolicy = serde_json::from_str(retained.signed_envelope())
        .map_err(|_| "invalid retained correction metadata policy")?;
    if canonicalize(&policy.to_json()?)? != canonicalize(retained.signed_envelope())? {
        return Err("retained correction metadata policy cannot be represented losslessly".into());
    }
    let restrictions: BTreeSet<_> = prepared
        .read_policy
        .resources
        .values()
        .chain(policy.resources.values())
        .flat_map(|resource| resource.reader.iter().cloned())
        .collect();
    if !restrictions.is_subset(&prepared.read_clearances) {
        return Err("current reader does not clear retained correction result restrictions".into());
    }
    for resource in prepared.read_policy.resources.values_mut() {
        resource.reader = restrictions.clone();
    }
    prepared.signed_policy =
        sign_hosted_policy_envelope(&prepared.read_policy.to_json()?, issuer, &prepared.key, 1)?;
    Ok(())
}

impl Workbench {
    /// Read only the immutable admitted product fact under current access and
    /// every retained result restriction. No runtime, target or input is opened.
    pub fn read_editor_correction_result(
        &mut self,
        context: &AuthenticatedActionContext,
        original: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        request_id: &str,
    ) -> Result<Option<NativeEditorCorrectionResult>, String> {
        admission
            .validate_for(original)
            .map_err(|error| format!("{error:?}"))?;
        let identity = result_policy_identity(original, request_id)?;
        let scope = &identity.scope;
        let policy_scope = identity.storage_scope()?;
        let mut prepared =
            self.prepare_correction_inspection_scoped(context, original, &[scope, &policy_scope])?;
        let result: Option<NativeEditorCorrectionResult> =
            retained_fact(self.store_ref(), scope, request_id, scope, RESULT_KIND)?;
        let Some(result) = result else {
            return Ok(None);
        };
        verify_result_identity(original, admission, request_id, &result)
            .map_err(|error| format!("{error:?}"))?;
        let root = GovernanceRootVerifier::new(self.authority().clone(), prepared.key.public_key());
        let retained = load_action_policy(self.store_ref(), &identity, &result.policy, &root)?;
        retain_restrictions(&mut prepared, &retained, self.authority())?;
        self.store_mut()
            .with_dispatch_basis(&prepared.basis, || Some(result))
            .map_err(|error| format!("{error:?}"))
    }

    /// Verify actual historical evidence and admit one attributable result.
    /// A replay returns the first fact; a different reader uses the read API.
    pub fn admit_editor_correction_result(
        &mut self,
        context: &AuthenticatedActionContext,
        original: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        request: &EditorCorrectionResultRequest<'_>,
    ) -> Result<AdmittedEditorCorrectionResult, String> {
        if let Some(result) =
            self.read_editor_correction_result(context, original, admission, request.request_id)?
        {
            if result.reconciliation.request_id != request.reconciliation_request_id
                || result.provenance.initiator != context.actor().as_str()
            {
                return Err("correction result identity already has another meaning".into());
            }
            return Ok(AdmittedEditorCorrectionResult {
                result,
                replayed: true,
            });
        }
        let identity = result_policy_identity(original, request.request_id)?;
        let scope = &identity.scope;
        let reconciliation_scope = request_scope(original, request.reconciliation_request_id)?;
        let reconciliation_identity = ActionPolicyIdentity {
            issuer: original.issuer.clone(),
            scope: reconciliation_scope.clone(),
            request_id: request.reconciliation_request_id.into(),
        };
        let reconciliation_policy_scope = reconciliation_identity.storage_scope()?;
        let policy_scope = identity.storage_scope()?;
        let mut initial = self.prepare_correction_inspection_scoped(
            context,
            original,
            &[&reconciliation_scope, &reconciliation_policy_scope],
        )?;
        let first = self
            .store_mut()
            .committed_dispatch::<ProductReconciliationAdmission>(
                &reconciliation_scope,
                request.reconciliation_request_id,
            )
            .map_err(|error| format!("{error:?}"))?
            .ok_or("correction result requires the original reconciliation outbox")?;
        verify_reconciliation_identity(original, admission, &first.command)
            .map_err(|error| format!("{error:?}"))?;
        let root = GovernanceRootVerifier::new(self.authority().clone(), initial.key.public_key());
        let reconciliation_policy = load_action_policy(
            self.store_ref(),
            &reconciliation_identity,
            &first.command.policy,
            &root,
        )?;
        retain_restrictions(&mut initial, &reconciliation_policy, self.authority())?;
        let retained = crate::action_policy::prepare_action_policy(
            self.store_mut(),
            &identity,
            &initial.read_policy,
            &initial.key,
        )?;
        // No target or runtime evidence was read before this final authority
        // snapshot. Include the policy preparation that just became durable.
        let mut prepared = self.prepare_correction_inspection_scoped(
            context,
            original,
            &[
                scope,
                &policy_scope,
                &reconciliation_scope,
                &reconciliation_policy_scope,
            ],
        )?;
        retain_restrictions(&mut prepared, &reconciliation_policy, self.authority())?;
        if canonicalize(retained.signed_envelope())?
            != canonicalize(&prepared.read_policy.to_json()?)?
        {
            return Err("correction result authority changed during preparation".into());
        }
        let dispatched = self
            .store_mut()
            .committed_dispatch::<ProductReconciliationAdmission>(
                &reconciliation_scope,
                request.reconciliation_request_id,
            )
            .map_err(|error| format!("{error:?}"))?
            .ok_or("correction result requires the original reconciliation outbox")?;
        if dispatched != first {
            return Err("correction reconciliation changed during result preparation".into());
        }
        let reconciliation = dispatched.command;
        verify_reconciliation_identity(original, admission, &reconciliation)
            .map_err(|error| format!("{error:?}"))?;
        let acknowledgment: CorrectionReconciliationAcknowledgment = retained_fact(
            self.store_ref(),
            &format!("correction-reconciliation-ack:{reconciliation_scope}"),
            "reconciled",
            &reconciliation_scope,
            ACK_KIND,
        )?
        .ok_or("correction result requires its committed reconciliation acknowledgment")?;
        if dispatched.dispatch.runtime_ref != format!("{}:native", self.home_id())
            || dispatched.dispatch.command_ref
                != reconciliation
                    .fingerprint()
                    .map_err(|error| format!("{error:?}"))?
            || acknowledgment.product_command_id != dispatched.command_id
            || acknowledgment.runtime_ref != dispatched.dispatch.runtime_ref
        {
            return Err("correction reconciliation acknowledgment differs from its outbox".into());
        }
        let issuer = self.authority().clone();
        let root = GovernanceRootVerifier::new(issuer.clone(), prepared.key.public_key());
        load_action_policy(
            self.store_ref(),
            &reconciliation_identity,
            &reconciliation.policy,
            &root,
        )?;
        self.store_mut()
            .with_dispatch_record_admission(&prepared.basis, |writer| -> StoreResult<_> {
                let runtime = prepared.runtime(&issuer)?;
                let evidence =
                    read_evidence(&runtime, context, original, admission, &prepared.key)?;
                if evidence.read_policy != *retained.policy_ref() {
                    return Err(refused(
                        "correction result read policy differs from its retained policy",
                    ));
                }
                let recorded =
                    validate_receipt(&runtime, &reconciliation, &acknowledgment.receipt)?;
                let attempt = evidence
                    .effects
                    .iter()
                    .find(|effect| effect.effect_id == reconciliation.evidence.frame.effect_id)
                    .and_then(|effect| {
                        effect
                            .attempts
                            .iter()
                            .find(|attempt| attempt.run_id == reconciliation.evidence.frame.run_id)
                    })
                    .ok_or_else(|| refused("original correction attempt is unavailable"))?;
                if recorded.diagnostic.is_some()
                    || attempt.disposition != ExternalDisposition::Applied
                    || attempt.disputed
                    || !attempt.evidence.contains(&reconciliation.evidence)
                    || attempt.dispatch.as_ref().map(|marker| &marker.frame)
                        != Some(&reconciliation.evidence.frame)
                {
                    return Err(refused(
                        "correction result requires undisputed Applied evidence",
                    ));
                }
                let store = runtime.kernel().store();
                let effect = store
                    .list_effects(&admission.instance_ref)?
                    .into_iter()
                    .find(|effect| effect.effect_id == reconciliation.evidence.frame.effect_id)
                    .ok_or_else(|| refused("original correction effect is unavailable"))?;
                let mapping = prepared
                    .input_binding
                    .as_ref()
                    .ok_or_else(|| refused("original correction input mapping is unavailable"))?;
                let historical = original::verified(
                    &evidence,
                    store.chain_prefix(&admission.instance_ref)?,
                    effect,
                    &reconciliation.evidence.frame.run_id,
                    mapping,
                    prepared.target.scope(),
                )?;
                prepared.target.observe(&historical.binding, |workspace| {
                    let recording =
                        read_committed_resolution_recording(workspace, &historical.binding)?
                            .ok_or_else(|| refused("original correction receipt is unavailable"))?;
                    let result = NativeEditorCorrectionResult {
                        protocol: RESULT_PROTOCOL.into(),
                        issuer: original.issuer.clone(),
                        request_id: request.request_id.into(),
                        admission: admission.clone(),
                        policy: retained.policy_ref().clone(),
                        evidence_label_ref: format!(
                            "policy:{}:result",
                            retained.policy_ref().envelope_hash
                        ),
                        provenance: ActionProvenance {
                            initiator: context.actor().as_str().into(),
                            executor: context.actor().as_str().into(),
                            delegation: vec![],
                            origin: "editor.corrections.result".into(),
                            causes: vec![
                                cause(original, &admission.admitted_at)?,
                                cause(original, &acknowledgment.receipt.recorded_at)?,
                            ],
                        },
                        reconciliation: reconciliation.clone(),
                        acknowledgment: acknowledgment.clone(),
                        observed_at: evidence.observed_at.clone(),
                        binding: historical.binding.clone(),
                        recording,
                    };
                    verify_result_identity(original, admission, request.request_id, &result)?;
                    let payload = serde_json::to_string(&result)?;
                    let admitted = writer
                        .commit(
                            scope,
                            request.request_id,
                            &payload,
                            &[CommandRecordFact {
                                scope_id: scope.clone(),
                                kind: RESULT_KIND.into(),
                                payload: payload.clone(),
                            }],
                        )
                        .map_err(refused)?;
                    Ok(AdmittedEditorCorrectionResult {
                        result,
                        replayed: admitted.replayed,
                    })
                })
            })
            .map_err(|error| format!("{error:?}"))?
            .map_err(|error| format!("{error:?}"))
    }
}
