//! Product acknowledgment of an exact applied native save. Runtime disposition,
//! target evidence and product admission remain distinct durable facts.
use super::*;
use gaugedesk_store::CommandRecordFact;
use gaugedesk_whip_runtime::host_actions::{
    action_result::ActionEvidenceRef, recovery::RecordedReconciliation,
};
use whipplescript_store::{
    branches::write_evidence::WriteEvidenceRef, effect_recovery::ExternalDisposition,
    vcs_file_save::SaveResult,
};

const RESULT_KIND: &str = "native_editor_saved_result_v1";
const RESULT_PROTOCOL: &str = "gaugedesk.native-editor-saved-result.v1";

/// A reference-only product fact. It claims this saved cut, never today's head
/// or successful completion of the original workflow.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEditorSavedResult {
    pub protocol: String,
    pub issuer: String,
    pub product_command_id: String,
    pub runtime_ref: String,
    pub admission: ActionAdmissionReceipt,
    pub policy: gaugedesk_whip_runtime::PolicyEpochRef,
    pub evidence_handle: String,
    pub evidence_label_ref: String,
    pub provenance: ActionProvenance,
    pub reconciliation: ActionEvidenceRef,
    pub reconciliation_fingerprint: String,
    pub result_reference: WriteEvidenceRef,
    pub cut_id: String,
    pub operation_id: String,
    pub content_hash: String,
    pub merged: bool,
}

pub struct AdmittedEditorSavedResult {
    pub result: NativeEditorSavedResult,
    pub replayed: bool,
}

/// Select the first matching reconciliation in the authenticated prefix, so
/// later metadata appends cannot change an already admitted result's meaning.
fn applied_reconciliation(
    snapshot: &ActionResultSnapshot,
    prefix: &[OwnedChainEntry],
    original: &OriginalSave,
    history: &dispatch_grant::NativeDispatchHistory,
) -> StoreResult<(ActionEvidenceRef, RecordedReconciliation, String)> {
    let attempt = snapshot
        .effects
        .iter()
        .find(|effect| effect.effect_id == original.attempt.effect_id)
        .and_then(|effect| {
            effect
                .attempts
                .iter()
                .find(|attempt| attempt.run_id == original.attempt.run_id)
        })
        .ok_or_else(refused)?;
    if attempt.disposition != ExternalDisposition::Applied || attempt.disputed {
        return Err(StoreError::Conflict(
            "native saved result requires an undisputed applied disposition".into(),
        ));
    }
    for (index, event) in prefix.iter().enumerate() {
        if event.sequence > i64::try_from(snapshot.observed_at.sequence).map_err(|_| refused())?
            || event.event_type != "effect.disposition.reconciled"
            || event.source.as_deref() != Some("kernel")
        {
            continue;
        }
        let recorded: RecordedReconciliation =
            serde_json::from_str(&event.payload_json).map_err(|_| refused())?;
        let command = &recorded.command;
        if command.evidence.frame != original.dispatch.frame {
            continue;
        }
        command.validate().map_err(|_| refused())?;
        history
            .verify(
                &snapshot.command,
                &command.provenance,
                &reconciliation_provenance(&snapshot.command, &snapshot.admission)?,
            )
            .map_err(|_| refused())?;
        if recorded.diagnostic.is_some()
            || command.evidence.disposition != EvidenceDisposition::Applied
            || command.issuer != snapshot.command.issuer
            || command.scope != snapshot.command.scope
            || command.policy != snapshot.command.policy
            || command.evidence_label_ref != original.binding.evidence_label
            || command.evidence.authority_ref != snapshot.command.issuer
            || command.evidence.evidence_ref != snapshot.command.resources["target"].resource.handle
            || !attempt.evidence.contains(&command.evidence)
        {
            return Err(refused());
        }
        let reference = snapshot
            .evidence
            .iter()
            .find(|reference| {
                reference.event_id == event.event_id
                    && i64::try_from(reference.sequence).ok() == Some(event.sequence)
                    && reference.kind == event.event_type
            })
            .ok_or_else(refused)?
            .clone();
        let head = fold_owned(&snapshot.admission.instance_ref, &prefix[..=index]);
        return Ok((reference, recorded, head.digest));
    }
    Err(refused())
}

impl Workbench {
    /// Admit only a retained, reconciled saved cut. This does not publish a UI
    /// event, write the target or resume an interrupted workflow.
    pub fn admit_editor_file_save_result(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        attempt: EditorFileSaveAttempt<'_>,
        runtime: &GovernedHostFacade<NativeStores>,
    ) -> Result<Option<AdmittedEditorSavedResult>, String> {
        self.admit_editor_file_save_result_fenced(
            context, inputs, command, admission, attempt, runtime, None,
        )
    }

    #[allow(clippy::too_many_arguments)] // Retain the direct boundary plus its acquired owner epoch.
    pub(in crate::file_action_factory) fn admit_editor_file_save_result_fenced(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        attempt: EditorFileSaveAttempt<'_>,
        runtime: &GovernedHostFacade<NativeStores>,
        epoch: Option<i64>,
    ) -> Result<Option<AdmittedEditorSavedResult>, String> {
        let prepared =
            self.prepare_native_editor_action(context, inputs, command, runtime.policy_ref())?;
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
            .get(&prepared.chat_id)
            .ok_or("editor workspace is unavailable")?
            .native_file_action_evidence_target(&path, base)
            .map_err(|_| "editor evidence target is unavailable")?;
        if target.branch() != branch || target.path() != path || target.base() != base {
            return Err("editor target differs from its actual native binding".into());
        }
        let history = dispatch_grant::NativeDispatchHistory::open(self, prepared.key.public_key())?;
        self.store_mut()
            .with_dispatch_record_admission(&prepared.basis, |writer| {
                ownership::require_epoch(runtime, admission, epoch)?;
                let snapshot = super::super::execution::read_evidence(
                    runtime,
                    command,
                    admission,
                    &prepared.key,
                )?;
                let store = runtime.kernel().store();
                let prefix = store.chain_prefix(&admission.instance_ref)?;
                let effect = store
                    .list_effects(&admission.instance_ref)?
                    .into_iter()
                    .find(|effect| effect.effect_id == attempt.effect_id)
                    .ok_or_else(refused)?;
                let original =
                    original_save(&snapshot, prefix.clone(), effect, attempt.run_id, &history)?;
                let (reference, reconciliation, digest) =
                    applied_reconciliation(&snapshot, &prefix, &original, &history)?;
                target.publish_committed_scoped_result(
                    &original.binding,
                    &original.resolution_scope,
                    &original.attempt,
                    |_, saved| {
                        let proof_digest: String = Sha256::digest(saved.receipt_json.as_bytes())
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect();
                        if reconciliation.command.evidence.evidence_digest != proof_digest {
                            return Err(refused());
                        }
                        let (cut_id, operation_id, content_hash, merged) =
                            match &saved.receipt.result {
                                SaveResult::Written {
                                    cut_id,
                                    operation_id,
                                    accepted_content_hash,
                                    ..
                                } => (cut_id, operation_id, accepted_content_hash, false),
                                SaveResult::Merged {
                                    cut_id,
                                    operation_id,
                                    accepted_content_hash,
                                    ..
                                } => (cut_id, operation_id, accepted_content_hash, true),
                                SaveResult::Conflicted { .. } => return Err(refused()),
                            };
                        let cause = |sequence, digest| -> StoreResult<ActionCause> {
                            Ok(ActionCause {
                                authority: command.issuer.clone(),
                                record_ref: serde_json::to_string(&(
                                    &admission.instance_ref,
                                    sequence,
                                ))
                                .map_err(|_| refused())?,
                                digest,
                            })
                        };
                        let base_provenance = ActionProvenance {
                            initiator: context.actor().as_str().into(),
                            executor: context.actor().as_str().into(),
                            origin: "editor.save.result".into(),
                            delegation: Vec::new(),
                            causes: vec![
                                cause(
                                    admission.admitted_at.sequence,
                                    admission.admitted_at.head_digest.clone(),
                                )?,
                                cause(reference.sequence, digest)?,
                            ],
                        };
                        let mut result = NativeEditorSavedResult {
                            protocol: RESULT_PROTOCOL.into(),
                            issuer: command.issuer.clone(),
                            product_command_id: prepared.delivery.command_id.clone(),
                            runtime_ref: prepared.delivery.dispatch.runtime_ref.clone(),
                            admission: admission.clone(),
                            policy: command.policy.clone(),
                            evidence_handle: snapshot.evidence_handle.clone(),
                            evidence_label_ref: snapshot.evidence_label_ref.clone(),
                            provenance: dispatch_grant::with_grant_cause(
                                base_provenance.clone(),
                                prepared.grant_cause.as_ref(),
                            ),
                            reconciliation_fingerprint: reconciliation
                                .command
                                .fingerprint()
                                .map_err(|_| refused())?,
                            reconciliation: reference,
                            result_reference: saved.reference.clone(),
                            cut_id: cut_id.clone(),
                            operation_id: operation_id.clone(),
                            content_hash: content_hash.clone(),
                            merged,
                        };
                        let key = serde_json::to_string(&(attempt.effect_id, attempt.run_id))
                            .map_err(|_| refused())?;
                        let result_scope =
                            format!("host-action-native-save-result:{}", prepared.scope);
                        // Deliver the immutable first result under current authority.
                        // A renewed grant cannot rewrite which grant admitted it.
                        if let Some(payload) = history
                            .store
                            .committed_record_snapshot(&result_scope, &key)
                            .map_err(|_| refused())?
                        {
                            let recorded: NativeEditorSavedResult =
                                serde_json::from_str(&payload).map_err(|_| refused())?;
                            history
                                .verify(command, &recorded.provenance, &base_provenance)
                                .map_err(|_| refused())?;
                            let mut expected = result.clone();
                            expected.provenance = recorded.provenance.clone();
                            let facts = history
                                .store
                                .retained_events(&prepared.scope)
                                .map_err(|_| refused())?;
                            if recorded != expected
                                || facts
                                    .iter()
                                    .filter(|(_, kind, stored)| {
                                        kind == RESULT_KIND && stored == &payload
                                    })
                                    .count()
                                    != 1
                            {
                                return Err(refused());
                            }
                            result = recorded;
                        }
                        let payload = serde_json::to_string(&result).map_err(|_| refused())?;
                        let receipt = writer
                            .commit(
                                &result_scope,
                                &key,
                                &payload,
                                &[CommandRecordFact {
                                    scope_id: prepared.scope.clone(),
                                    kind: RESULT_KIND.into(),
                                    payload: payload.clone(),
                                }],
                            )
                            .map_err(|error| {
                                StoreError::Conflict(format!(
                                    "native saved result admission refused: {error:?}"
                                ))
                            })?;
                        Ok(AdmittedEditorSavedResult {
                            result,
                            replayed: receipt.replayed,
                        })
                    },
                )
            })
            .map_err(|error| format!("{error:?}"))?
            .map_err(|error| format!("{error:?}"))
    }
}

#[cfg(test)]
#[path = "file_action_result_admission_tests.rs"]
mod tests;
