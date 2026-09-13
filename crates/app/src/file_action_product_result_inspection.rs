//! Read retained product Saved facts without reopening execution or content.
use super::*;
use gaugedesk_whip_runtime::ResourcePolicy;
use whipplescript_store::vcs_file_save::SCOPED_SAVE_RECEIPT_SCHEMA;

/// Original product evidence in its fact order. The attempt coordinates locate
/// history; they carry no permission to retry or reconcile that attempt.
pub struct ObservedEditorSavedProductResult {
    pub effect_id: String,
    pub run_id: String,
    pub position: i64,
    pub result: NativeEditorSavedResult,
}

pub struct EditorFileSavedResultObservation {
    results: Vec<ObservedEditorSavedProductResult>,
    restrictions: ResourcePolicy,
    observer: String,
}
impl EditorFileSavedResultObservation {
    pub fn results(&self) -> &[ObservedEditorSavedProductResult] {
        &self.results
    }
    pub fn restrictions(&self) -> &ResourcePolicy {
        &self.restrictions
    }
    pub fn observer(&self) -> &str {
        &self.observer
    }
}

fn verify_saved_product_identity(
    command: &HostActionCommand,
    acknowledgment: &crate::host_action_delivery::RuntimeAcknowledgment,
    result: &NativeEditorSavedResult,
    history: &dispatch_grant::NativeDispatchHistory,
) -> StoreResult<()> {
    result
        .admission
        .validate_for(command)
        .map_err(|_| refused())?;
    result.result_reference.validate()?;
    result.provenance.validate().map_err(|_| refused())?;
    if result.protocol != RESULT_PROTOCOL
        || result.issuer != command.issuer
        || result.product_command_id != acknowledgment.product_command_id
        || result.runtime_ref != acknowledgment.runtime_ref
        || result.admission != acknowledgment.receipt
        || result.policy != command.policy
        || result.evidence_handle != "result"
        || result.evidence_label_ref != format!("policy:{}:result", command.policy.envelope_hash)
        || result.result_reference.schema_ref != SCOPED_SAVE_RECEIPT_SCHEMA
        || result.result_reference.label_ref != command.resources["target"].label_ref
        || result.reconciliation.kind != "effect.disposition.reconciled"
        || result.reconciliation.sequence <= result.admission.admitted_at.sequence
        || [
            &result.reconciliation.event_id,
            &result.reconciliation_fingerprint,
            &result.cut_id,
            &result.operation_id,
            &result.content_hash,
        ]
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err(refused());
    }
    let cause = |sequence, digest| -> StoreResult<ActionCause> {
        Ok(ActionCause {
            authority: command.issuer.clone(),
            record_ref: serde_json::to_string(&(&result.admission.instance_ref, sequence))?,
            digest,
        })
    };
    let reconciliation_cause = result.provenance.causes.get(1).ok_or_else(refused)?;
    let original = ActionProvenance {
        initiator: command.provenance.executor.clone(),
        executor: command.provenance.executor.clone(),
        origin: "editor.save.result".into(),
        delegation: vec![],
        causes: vec![
            cause(
                result.admission.admitted_at.sequence,
                result.admission.admitted_at.head_digest.clone(),
            )?,
            cause(
                result.reconciliation.sequence,
                reconciliation_cause.digest.clone(),
            )?,
        ],
    };
    history
        .verify(command, &result.provenance, &original)
        .map_err(|_| refused())
}

impl Workbench {
    /// Independently authorize retained product Saved metadata. An empty result
    /// means no retained product fact, never non-execution. No runtime, input,
    /// target or coordination store is opened, and no receipt is repaired.
    pub fn observe_editor_file_saved_results(
        &mut self,
        context: &AuthenticatedActionContext,
        command: &HostActionCommand,
    ) -> Result<EditorFileSavedResultObservation, String> {
        let scope = command.instance_ref().map_err(|e| format!("{e:?}"))?;
        let result_scope = format!("host-action-native-save-result:{scope}");
        let prepared =
            self.prepare_editor_file_save_inspection(context, command, &[&result_scope], None)?;
        let history = dispatch_grant::NativeDispatchHistory::open(self, prepared.key.public_key())?;
        self.store_mut()
            .with_dispatch_basis(&prepared.basis, || {
                let snapshots = history
                    .store
                    .committed_record_snapshots(&result_scope)
                    .map_err(|_| refused())?;
                let facts = history
                    .store
                    .retained_events(&scope)
                    .map_err(|_| refused())?;
                let mut by_payload = BTreeMap::new();
                for snapshot in snapshots {
                    let key = snapshot.idempotency_key;
                    let payload = snapshot.snapshot_json;
                    let (effect, run): (String, String) =
                        serde_json::from_str(&key).map_err(|_| refused())?;
                    if effect.trim().is_empty()
                        || run.trim().is_empty()
                        || serde_json::to_string(&(&effect, &run))? != key
                        || by_payload
                            .insert(payload, (effect, run, snapshot.first_fact_position))
                            .is_some()
                    {
                        return Err(refused());
                    }
                }
                let acknowledgment = crate::host_action_delivery::retained_runtime_acknowledgment(
                    &history.store,
                    &prepared.dispatch,
                )
                .map_err(|_| refused())?;
                let mut results = Vec::new();
                for (position, kind, payload) in facts {
                    if kind != RESULT_KIND {
                        continue;
                    }
                    let (effect_id, run_id, expected_position) =
                        by_payload.remove(&payload).ok_or_else(refused)?;
                    if position != expected_position {
                        return Err(refused());
                    }
                    let result: NativeEditorSavedResult =
                        serde_json::from_str(&payload).map_err(|_| refused())?;
                    verify_saved_product_identity(
                        command,
                        acknowledgment.as_ref().ok_or_else(refused)?,
                        &result,
                        &history,
                    )?;
                    results.push(ObservedEditorSavedProductResult {
                        effect_id,
                        run_id,
                        position,
                        result,
                    });
                }
                if !by_payload.is_empty() {
                    return Err(refused());
                }
                Ok(EditorFileSavedResultObservation {
                    results,
                    restrictions: prepared.restrictions,
                    observer: context.actor().as_str().into(),
                })
            })
            .map_err(|e| format!("{e:?}"))?
            .map_err(|e| format!("{e:?}"))
    }
}
