//! Exact saved-source preparation for subsequent derived admission (ACTION-4).
//! A signed source is evidence of retained input, never a grant or endorsement.
use super::*;
use crate::file_action_factory::project_signature::{NativeHistoryRoots, ProjectSignature};
use gaugedesk_store::CommandRecordFact;
use serde::{Deserialize, Serialize};
use whipplescript_store::{
    branches::write_evidence::WriteEvidenceRef,
    effect_recovery::{canonical_value, AttemptDisposition},
};

const PROTOCOL: &str = "gaugedesk.saved-action-source.v1";
const KIND: &str = "native_saved_action_source_v1";
const KEY: &str = "retain";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceStatement {
    protocol: String,
    home: String,
    issuer: String,
    request_id: String,
    observer: String,
    command_fingerprint: String,
    original_provenance: ActionProvenance,
    admission: ActionAdmissionReceipt,
    observed_at: PinnedPosition,
    effect_id: String,
    attempt: AttemptDisposition,
    receipt: WriteEvidenceRef,
    receipt_digest: String,
    content_hash: String,
    restrictions: ResourcePolicy,
    input: ActionInput,
}
impl SourceStatement {
    fn snapshot(&self) -> StoreResult<String> {
        Ok(serde_json::to_string(&canonical_value(
            &serde_json::to_value(self)?,
        ))?)
    }
    fn signing_bytes(&self) -> StoreResult<Vec<u8>> {
        let mut bytes = b"gaugedesk:saved-action-source:v1\0".to_vec();
        bytes.extend(self.snapshot()?.as_bytes());
        Ok(bytes)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedSource {
    statement: SourceStatement,
    signature: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    project_signature: Option<ProjectSignature>,
}

/// Durable body-free source coordinates. Each later use must verify its Home
/// record and input custody under current authority; this object is no grant.
pub struct RetainedEditorFileSaveSource {
    input: ActionInput,
    cause: ActionCause,
    replayed: bool,
}
impl RetainedEditorFileSaveSource {
    pub fn input(&self) -> &ActionInput {
        &self.input
    }
    pub fn cause(&self) -> &ActionCause {
        &self.cause
    }
    pub fn replayed(&self) -> bool {
        self.replayed
    }
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn source_scope(home: &str, observer: &str, request_id: &str) -> StoreResult<String> {
    if request_id.trim().is_empty() {
        return Err(refused());
    }
    Ok(format!(
        "native-saved-source:{}",
        serde_json::to_string(&(home, observer, request_id))?
    ))
}
fn label(restrictions: &ResourcePolicy) -> StoreResult<String> {
    Ok(format!(
        "saved-source-policy:{}",
        digest(
            serde_json::to_string(&canonical_value(&serde_json::to_value(restrictions)?),)?
                .as_bytes()
        )
    ))
}
fn statement(
    home: &str,
    request_id: &str,
    input: ActionInput,
    observed: &EditorFileSaveObservation,
    attempt: EditorFileSaveAttempt<'_>,
) -> StoreResult<SourceStatement> {
    let saved = observed.saved.as_ref().ok_or_else(refused)?;
    let evidence = &observed.evidence;
    let disposition = evidence
        .effects
        .iter()
        .find(|effect| effect.effect_id == attempt.effect_id)
        .and_then(|effect| {
            effect
                .attempts
                .iter()
                .find(|item| item.run_id == attempt.run_id)
        })
        .ok_or_else(refused)?;
    Ok(SourceStatement {
        protocol: PROTOCOL.into(),
        home: home.into(),
        issuer: evidence.command.issuer.clone(),
        request_id: request_id.into(),
        observer: observed.observer.clone(),
        command_fingerprint: evidence.command.fingerprint().map_err(|_| refused())?,
        original_provenance: evidence.command.provenance.clone(),
        admission: evidence.admission.clone(),
        observed_at: evidence.observed_at.clone(),
        effect_id: attempt.effect_id.into(),
        attempt: disposition.clone(),
        receipt: saved.reference.clone(),
        receipt_digest: digest(saved.receipt_json.as_bytes()),
        content_hash: whipplescript_store::stable_hash_hex(&saved.accepted_content),
        restrictions: observed.restrictions.clone(),
        input,
    })
}

// Read under the product writer fence. Replay must return the original signed
// fact, not manufacture evidence for a missing or changed receipt/record pair.
fn original_source(
    store: &Store,
    scope: &str,
    expected: &SourceStatement,
    roots: &NativeHistoryRoots,
) -> StoreResult<Option<SignedSource>> {
    let source = load_source(store, scope, roots)?;
    if source
        .as_ref()
        .is_some_and(|source| source.statement != *expected)
    {
        return Err(refused());
    }
    Ok(source)
}

fn load_source(
    store: &Store,
    scope: &str,
    roots: &NativeHistoryRoots,
) -> StoreResult<Option<SignedSource>> {
    let records = store.records(scope, KIND).map_err(|_| refused())?;
    let snapshot = store
        .committed_record_snapshot(scope, KEY)
        .map_err(|_| refused())?;
    match (records.as_slice(), snapshot) {
        ([], None) => Ok(None),
        ([record], Some(snapshot)) => {
            let source: SignedSource = serde_json::from_str(record)?;
            let command = store
                .fold::<ProductActionAdmission>(&source.statement.admission.instance_ref)
                .map_err(|_| refused())?
                .command
                .ok_or_else(refused)?;
            if command.issuer != source.statement.issuer
                || command.fingerprint().map_err(|_| refused())?
                    != source.statement.command_fingerprint
                || command.instance_ref().map_err(|_| refused())?
                    != source.statement.admission.instance_ref
            {
                return Err(refused());
            }
            let root = match &source.project_signature {
                Some(frame) => frame.root(roots, store, &command),
                None => roots.original_root(store, &command),
            }
            .map_err(|_| refused())?;
            let bytes = source.statement.signing_bytes()?;
            let bytes = match &source.project_signature {
                Some(frame) => frame.signing_bytes(&bytes).map_err(|_| refused())?,
                None => bytes,
            };
            if source.statement.snapshot()? != snapshot
                || !verify_signature(
                    &bytes,
                    &Signature::new(source.signature.as_slice()),
                    root.expected_key(),
                )
                .unwrap_or(false)
            {
                return Err(refused());
            }
            Ok(Some(source))
        }
        _ => Err(refused()),
    }
}

impl Workbench {
    /// Prepare a pinned saved source for later derived admission. Revalidate
    /// authority and original evidence twice: an earlier observation is only
    /// expected coordinates. Neither unknown disposition nor attribution changes.
    pub fn retain_editor_file_save_source(
        &mut self,
        context: &AuthenticatedActionContext,
        storage: &NativeActionStorage,
        request_id: &str,
        observed: &EditorFileSaveObservation,
        attempt: EditorFileSaveAttempt<'_>,
    ) -> Result<RetainedEditorFileSaveSource, String> {
        storage.require_home(self)?;
        let home = self.home_id().as_str().to_owned();
        let scope = source_scope(&home, context.actor().as_str(), request_id)
            .map_err(|e| format!("{e:?}"))?;
        let command = &observed.evidence.command;
        let admission = &observed.evidence.admission;
        let current = self.with_editor_file_save_observation(
            context,
            command,
            admission,
            EditorFileSaveAttempt {
                effect_id: attempt.effect_id,
                run_id: attempt.run_id,
            },
            SavedObservationOptions {
                through: Some(observed.evidence.observed_at.clone()),
                retained: None,
                publish_metadata: true,
            },
            |current, _, _, _| Ok(current),
        )?;
        // Only this fresh observation supplies bytes/labels. Copies in the
        // caller's earlier observation never reconstruct erased target content.
        let saved = current
            .saved
            .as_ref()
            .ok_or("saved source bytes are unavailable")?;
        let project = crate::file_action_factory::project_signature::command_project(command)?;
        let key = self
            .project_signing_key(&project)
            .map_err(|e| e.to_string())?;
        let roots = NativeHistoryRoots::open(self)?;
        let previous = self
            .store_ref()
            .read_for_dispatch(&[&scope], |store| Ok(load_source(store, &scope, &roots)))
            .map_err(|e| format!("{e:?}"))?
            .0
            .map_err(|e| format!("{e:?}"))?;
        let inputs = storage.inputs();
        let source_label = label(&current.restrictions).map_err(|e| format!("{e:?}"))?;
        // A receipted input is resolved as-is. Retry must never recreate missing
        // custody from a still-readable target or the caller's old observation.
        let input = match &previous {
            Some(previous) => previous.statement.input.clone(),
            None => inputs
                .prepare_unerased("saved_source", &source_label, &saved.accepted_content)
                .map_err(|e| format!("{e:?}"))?,
        };
        if input.handle != "saved_source" || input.label_ref != source_label {
            return Err("saved source input differs from current restrictions".into());
        }
        let expected = statement(
            &home,
            request_id,
            input.clone(),
            &current,
            EditorFileSaveAttempt {
                effect_id: attempt.effect_id,
                run_id: attempt.run_id,
            },
        )
        .map_err(|e| format!("{e:?}"))?;
        if previous
            .as_ref()
            .is_some_and(|source| source.statement != expected)
        {
            return Err("saved source preparation identity changed meaning".into());
        }
        let history = dispatch_grant::NativeDispatchHistory::open(self)?;
        inputs
            .publish(std::slice::from_ref(&input), || {
                self.with_editor_file_save_observation(
                    context,
                    command,
                    admission,
                    attempt,
                    SavedObservationOptions {
                        through: Some(current.evidence.observed_at.clone()),
                        retained: None,
                        publish_metadata: true,
                    },
                    |fresh, original, target, writer| {
                        let actual = statement(
                            &home,
                            request_id,
                            input.clone(),
                            &fresh,
                            EditorFileSaveAttempt {
                                effect_id: &expected.effect_id,
                                run_id: &expected.attempt.run_id,
                            },
                        )?;
                        if actual != expected {
                            return Err(refused());
                        }
                        target
                            .publish_committed_scoped_result(
                                &original.binding,
                                &original.resolution_scope,
                                &original.attempt,
                                |_, saved| {
                                    if digest(saved.receipt_json.as_bytes())
                                        != expected.receipt_digest
                                        || saved.reference != expected.receipt
                                        || whipplescript_store::stable_hash_hex(
                                            &saved.accepted_content,
                                        ) != expected.content_hash
                                    {
                                        return Err(refused());
                                    }
                                    let source = match original_source(
                                        &history.store,
                                        &scope,
                                        &expected,
                                        &history.roots,
                                    )? {
                                        Some(source) => source,
                                        None => {
                                            let frame = ProjectSignature::new(&project, &key);
                                            let bytes = frame
                                                .signing_bytes(&expected.signing_bytes()?)
                                                .map_err(|_| refused())?;
                                            SignedSource {
                                                signature: key.sign(&bytes).as_bytes().to_vec(),
                                                statement: expected.clone(),
                                                project_signature: Some(frame),
                                            }
                                        }
                                    };
                                    let snapshot = source.statement.snapshot()?;
                                    let receipt = writer
                                        .commit(
                                            &scope,
                                            KEY,
                                            &snapshot,
                                            &[CommandRecordFact {
                                                scope_id: scope.clone(),
                                                kind: KIND.into(),
                                                payload: serde_json::to_string(&source)?,
                                            }],
                                        )
                                        .map_err(|_| refused())?;
                                    Ok(RetainedEditorFileSaveSource {
                                        input: input.clone(),
                                        cause: ActionCause {
                                            authority: source
                                                .project_signature
                                                .as_ref()
                                                .map_or_else(
                                                    || expected.issuer.clone(),
                                                    |frame| frame.authority().into(),
                                                ),
                                            record_ref: serde_json::to_string(&(&scope, KEY))?,
                                            digest: digest(snapshot.as_bytes()),
                                        },
                                        replayed: receipt.replayed,
                                    })
                                },
                            )?
                            .ok_or_else(refused)
                    },
                )
                .map_err(StoreError::Conflict)
            })
            .map_err(|e| format!("saved source retention refused: {e:?}"))
    }
}

#[cfg(test)]
#[path = "file_action_source_tests.rs"]
mod tests;

#[path = "file_action_derived_source.rs"]
mod derived;
