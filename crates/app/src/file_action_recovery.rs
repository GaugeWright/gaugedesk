//! Current authorized inspection of an original native save. Runtime metadata
//! resolves opaque input versions; target content remains a separate read.

use super::*;
use gaugedesk_core::{
    ids::PublicKey,
    signature::{verify_signature, Signature},
};
use gaugedesk_whip_runtime::host_actions::{
    action_result::ActionResultSnapshot,
    execution::{effect_observation_fingerprint, ExecuteActionEffect},
    facade::GovernedHostFacade,
    LogAppend, NativeStores, RuntimeStore,
};
use gaugedesk_whip_runtime::{
    host_actions::recovery::{
        ReconcileEffectCommand, ReconciliationReceipt, EFFECT_RECONCILIATION_PROTOCOL,
    },
    ProtocolError,
};
use sha2::{Digest, Sha256};
use whipplescript_kernel::save_reconciliation::{
    SaveReconciliationAuthority, ScopedSaveReconciliationAuthority,
    ScopedVersionedSaveEvidenceSource, VersionedSaveEvidenceSource,
};
use whipplescript_store::effect_recovery::{DispositionEvidence, EvidenceDisposition};
use whipplescript_store::{
    effect_recovery::DispatchMarker,
    event_chain::{fold_owned, OwnedChainEntry},
    vcs_file_save::{RecoveredSave, SaveAttempt, SaveResultBinding, ScopedSaveReceipt},
    ClaimableEffect, EffectView, StoreError, StoreResult,
};

#[path = "file_action_result_admission.rs"]
mod result_admission;
pub use result_admission::{AdmittedEditorSavedResult, NativeEditorSavedResult};

fn refused() -> StoreError {
    StoreError::Conflict("original native save evidence binding is unavailable".into())
}

/// These are expected coordinates from an authenticated result read, never a
/// grant or a claim that the historical effect is currently claimable.
struct OriginalSave {
    execution: ExecuteActionEffect,
    dispatch: DispatchMarker,
    binding: SaveResultBinding,
    attempt: SaveAttempt,
    resolution_scope: whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope,
}

fn original_save(
    snapshot: &ActionResultSnapshot,
    mut prefix: Vec<OwnedChainEntry>,
    effect: EffectView,
    run_id: &str,
    history: &dispatch_grant::NativeDispatchHistory,
) -> StoreResult<OriginalSave> {
    let command = &snapshot.command;
    let pin = &snapshot.observed_at;
    let sequence = i64::try_from(pin.sequence).map_err(|_| refused())?;
    prefix.retain(|row| row.sequence <= sequence);
    let head = fold_owned(&snapshot.admission.instance_ref, &prefix);
    if pin.instance_ref != snapshot.admission.instance_ref
        || head.sequence != Some(sequence)
        || head.digest != pin.head_digest
    {
        return Err(refused());
    }
    let dispatch = snapshot
        .effects
        .iter()
        .find(|record| record.effect_id == effect.effect_id)
        .and_then(|record| {
            record
                .attempts
                .iter()
                .find(|attempt| attempt.run_id == run_id)
        })
        .and_then(|attempt| attempt.dispatch.as_ref())
        .ok_or_else(refused)?;
    let frame = &dispatch.frame;
    if frame.instance_id != snapshot.admission.instance_ref
        || frame.effect_id != effect.effect_id
        || frame.run_id != run_id
        || frame.kind != "file.write"
        || frame.provider != "files"
    {
        return Err(refused());
    }
    let mut started = None;
    for event in &prefix {
        if event.event_type != "effect.run_started" || event.source.as_deref() != Some("kernel") {
            continue;
        }
        let payload: serde_json::Value =
            serde_json::from_str(&event.payload_json).map_err(|_| refused())?;
        if payload["run_id"].as_str() != Some(run_id) {
            continue;
        }
        let marker: DispatchMarker =
            serde_json::from_value(payload["external_dispatch"].clone()).map_err(|_| refused())?;
        if &marker != dispatch || started.is_some() {
            return Err(refused());
        }
        let execution: ExecuteActionEffect =
            serde_json::from_value(payload["metadata"]["action_execution"]["request"].clone())
                .map_err(|_| refused())?;
        started = Some((event.event_id.clone(), execution));
    }
    let (started_event_id, execution) = started.ok_or_else(refused)?;
    // Reuse the owner's data fingerprint. Building this value conveys no
    // scheduling authority and does not query the pending-effect queue.
    let observed = ClaimableEffect {
        effect_id: effect.effect_id,
        kind: effect.kind,
        target: effect.target,
        profile: effect.profile,
        input_json: effect.input_json,
        required_capabilities_json: effect.required_capabilities_json,
        declared_profiles_json: effect.declared_profiles_json,
    };
    if execution.admission != snapshot.admission
        || execution.issuer != command.issuer
        || execution.scope != command.scope
        || execution.policy != command.policy
        || execution.effect_id != observed.effect_id
        || execution.effect_fingerprint
            != effect_observation_fingerprint(&observed).map_err(|_| refused())?
    {
        return Err(refused());
    }
    history
        .verify(command, &execution.provenance, &command.provenance)
        .map_err(|_| refused())?;
    execution.signing_bytes().map_err(|_| refused())?;
    let input = command.inputs.get("content").ok_or_else(refused)?;
    let resource = command.resources.get("target").ok_or_else(refused)?;
    let (_, branch, path): (String, String, String) =
        serde_json::from_str(resource.resource.selector.as_deref().ok_or_else(refused)?)
            .map_err(|_| refused())?;
    let ActionBasis::Version { version_ref: base } = &resource.basis else {
        return Err(refused());
    };
    let json: serde_json::Value =
        serde_json::from_str(&observed.input_json).map_err(|_| refused())?;
    if observed.kind != "file.write"
        || observed
            .target
            .as_deref()
            .is_some_and(|target| target != resource.resource.handle)
        || json["store"] != resource.resource.handle
        || json["root"] != "/action/output"
        || json["path"] != "target"
        || json["format"] != "reference"
        || json["mode"] != "upsert"
        || json["body_ref"]["label_ref"] != input.label_ref
        || json.get("body").is_some()
        || json.get("body_expr").is_some()
    {
        return Err(refused());
    }
    let hash = json["body_ref"]["content_hash"]
        .as_str()
        .ok_or_else(refused)?;
    let resolution_scope = resolution_scope::original(command).map_err(|_| refused())?;
    Ok(OriginalSave {
        resolution_scope,
        execution,
        dispatch: dispatch.clone(),
        binding: SaveResultBinding {
            branch_id: branch,
            path,
            base_cut_id: base.clone(),
            draft_hash: hash.into(),
            executing_principal: command.provenance.executor.clone(),
            evidence_label: resource.label_ref.clone(),
        },
        attempt: SaveAttempt {
            instance_id: frame.instance_id.clone(),
            effect_id: frame.effect_id.clone(),
            run_id: frame.run_id.clone(),
            started_event_id,
        },
    })
}

impl Workbench {
    /// Inspect retained target content as the original current actor. This is
    /// neither a retention lease nor permission to reconcile or resume work.
    /// None remains an absent observation, never proof of non-application.
    pub fn inspect_editor_file_save_attempt(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        attempt: EditorFileSaveAttempt<'_>,
        runtime: &GovernedHostFacade<NativeStores>,
    ) -> Result<Option<RecoveredSave<ScopedSaveReceipt>>, String> {
        let EditorFileSaveAttempt { effect_id, run_id } = attempt;
        let prepared =
            self.prepare_native_editor_action(context, inputs, command, runtime.policy_ref())?;
        // Bind the actual private store before borrowing the product writer.
        // Constructing this descriptor performs no target content read.
        let resource = command
            .resources
            .get("target")
            .ok_or_else(|| "missing editor target".to_owned())?;
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
            .with_dispatch_basis(&prepared.basis, || {
                let snapshot =
                    super::execution::read_evidence(runtime, command, admission, &prepared.key)?;
                let store = runtime.kernel().store();
                let effect = store
                    .list_effects(&admission.instance_ref)?
                    .into_iter()
                    .find(|effect| effect.effect_id == effect_id)
                    .ok_or_else(refused)?;
                let original = original_save(
                    &snapshot,
                    store.chain_prefix(&admission.instance_ref)?,
                    effect,
                    run_id,
                    &history,
                )?;
                target.read_committed_scoped_result(
                    &original.binding,
                    &original.resolution_scope,
                    &original.attempt,
                )
            })
            .map_err(|error| format!("{error:?}"))?
            .map_err(|error| format!("{error:?}"))
    }
}

fn reconciliation_provenance(
    command: &HostActionCommand,
    admission: &ActionAdmissionReceipt,
) -> StoreResult<ActionProvenance> {
    Ok(ActionProvenance {
        initiator: command.provenance.initiator.clone(),
        executor: command.provenance.executor.clone(),
        delegation: vec![],
        origin: "editor.save.reconcile".into(),
        causes: vec![ActionCause {
            authority: command.issuer.clone(),
            record_ref: serde_json::to_string(&(
                &admission.instance_ref,
                admission.admitted_at.sequence,
            ))
            .map_err(|_| refused())?,
            digest: admission.admitted_at.head_digest.clone(),
        }],
    })
}

/// Renewed current authority may redeliver the same admitted reconciliation,
/// but cannot change its original grant or any evidence coordinate.
fn retained_reconciliation(
    snapshot: &ActionResultSnapshot,
    prefix: &[OwnedChainEntry],
    candidate: ReconcileEffectCommand,
    history: &dispatch_grant::NativeDispatchHistory,
) -> StoreResult<ReconcileEffectCommand> {
    use gaugedesk_whip_runtime::host_actions::recovery::RecordedReconciliation;
    let through = i64::try_from(snapshot.observed_at.sequence).map_err(|_| refused())?;
    let mut previous = None;
    for event in prefix {
        if event.sequence > through
            || event.event_type != "effect.disposition.reconciled"
            || event.source.as_deref() != Some("kernel")
        {
            continue;
        }
        let recorded: RecordedReconciliation =
            serde_json::from_str(&event.payload_json).map_err(|_| refused())?;
        let command = recorded.command;
        if command.issuer != candidate.issuer
            || command.scope != candidate.scope
            || command.request_id != candidate.request_id
        {
            continue;
        }
        history
            .verify(
                &snapshot.command,
                &command.provenance,
                &reconciliation_provenance(&snapshot.command, &snapshot.admission)?,
            )
            .map_err(|_| refused())?;
        let mut expected = candidate.clone();
        expected.provenance = command.provenance.clone();
        if previous.is_some() || command != expected {
            return Err(refused());
        }
        previous = Some(command);
    }
    Ok(previous.unwrap_or(candidate))
}

struct NativeSaveReconciliationAuthority<'a> {
    request: &'a ReconcileEffectCommand,
    original: &'a HostActionCommand,
    save: &'a OriginalSave,
    key: PublicKey,
}

impl SaveReconciliationAuthority for NativeSaveReconciliationAuthority<'_> {
    fn authenticate(
        &self,
        command: &ReconcileEffectCommand,
        signing_bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if command != self.request
            || signing_bytes != command.signing_bytes()?
            || !verify_signature(signing_bytes, &Signature::new(proof), &self.key).unwrap_or(false)
        {
            return Err(ProtocolError::Mismatch(
                "current native save reconciliation",
            ));
        }
        Ok(())
    }
    fn authorize(
        &self,
        command: &ReconcileEffectCommand,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        binding: &SaveResultBinding,
    ) -> Result<(), ProtocolError> {
        let expected = &self.save.binding;
        if command != self.request
            || original != self.original
            || execution != &self.save.execution
            || binding.branch_id != expected.branch_id
            || binding.path != expected.path
            || binding.base_cut_id != expected.base_cut_id
            || binding.draft_hash != expected.draft_hash
            || binding.executing_principal != expected.executing_principal
            || binding.evidence_label != expected.evidence_label
        {
            return Err(ProtocolError::Mismatch(
                "exact native save reconciliation binding",
            ));
        }
        Ok(())
    }
}

impl ScopedSaveReconciliationAuthority for NativeSaveReconciliationAuthority<'_> {
    fn authorize_resolution_scope(
        &self,
        command: &ReconcileEffectCommand,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        binding: &SaveResultBinding,
        scope: &whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope,
    ) -> Result<(), ProtocolError> {
        self.authorize(command, original, execution, binding)?;
        if scope != &self.save.resolution_scope
            || resolution_scope::original(original).as_ref() != Ok(scope)
        {
            return Err(ProtocolError::Mismatch("original native resolution scope"));
        }
        Ok(())
    }
}

impl Workbench {
    /// Publish an applied disposition for an exact original save. This is a new
    /// current-authority act, never a target retry or a successful workflow fact.
    pub fn reconcile_editor_file_save_attempt(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        request: EditorFileSaveReconciliation<'_>,
        owner: &mut NativeEditorActionRuntime,
    ) -> Result<Option<ReconciliationReceipt>, String> {
        if request.request_id.trim().is_empty() {
            return Err("native save reconciliation requires a stable request identity".into());
        }
        let prepared = self.prepare_native_editor_action(
            context,
            inputs,
            command,
            owner.runtime.policy_ref(),
        )?;
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
            .with_dispatch_basis(&prepared.basis, || {
                owner.require_current(admission)?;
                let snapshot = super::execution::read_evidence(
                    &owner.runtime,
                    command,
                    admission,
                    &prepared.key,
                )?;
                let store = owner.runtime.kernel().store();
                let effect = store
                    .list_effects(&admission.instance_ref)?
                    .into_iter()
                    .find(|effect| effect.effect_id == request.attempt.effect_id)
                    .ok_or_else(refused)?;
                let prefix = store.chain_prefix(&admission.instance_ref)?;
                let original = original_save(
                    &snapshot,
                    prefix.clone(),
                    effect,
                    request.attempt.run_id,
                    &history,
                )?;
                target.publish_committed_scoped_result(
                    &original.binding,
                    &original.resolution_scope,
                    &original.attempt,
                    |workspace, result| {
                        owner.require_current(admission)?;
                        let reconciliation = ReconcileEffectCommand {
                            protocol: EFFECT_RECONCILIATION_PROTOCOL.into(),
                            issuer: command.issuer.clone(),
                            scope: command.scope.clone(),
                            request_id: request.request_id.into(),
                            policy: command.policy.clone(),
                            provenance: dispatch_grant::with_grant_cause(
                                reconciliation_provenance(command, admission)?,
                                prepared.grant_cause.as_ref(),
                            ),
                            evidence: DispositionEvidence {
                                frame: original.dispatch.frame.clone(),
                                disposition: EvidenceDisposition::Applied,
                                evidence_ref: resource.resource.handle.clone(),
                                evidence_digest: Sha256::digest(result.receipt_json.as_bytes())
                                    .iter()
                                    .map(|byte| format!("{byte:02x}"))
                                    .collect(),
                                authority_ref: command.issuer.clone(),
                            },
                            evidence_label_ref: original.binding.evidence_label.clone(),
                        };
                        let reconciliation =
                            retained_reconciliation(&snapshot, &prefix, reconciliation, &history)?;
                        let source = VersionedSaveEvidenceSource {
                            admission,
                            workspace,
                            binding: &original.binding,
                            input_name: "content",
                            resource_name: "target",
                            authority_ref: &command.issuer,
                        };
                        let source = ScopedVersionedSaveEvidenceSource {
                            save: source,
                            resolution_scope: &original.resolution_scope,
                        };
                        let verifier = NativeSaveReconciliationAuthority {
                            request: &reconciliation,
                            original: command,
                            save: &original,
                            key: prepared.key.public_key(),
                        };
                        let bytes = reconciliation.signing_bytes().map_err(|_| refused())?;
                        owner
                            .runtime
                            .reconcile_scoped_versioned_save(
                                reconciliation.clone(),
                                owner.epoch,
                                &source,
                                &verifier,
                                prepared.key.sign(&bytes).as_bytes(),
                            )
                            .map_err(|error| {
                                StoreError::Conflict(format!(
                                    "native save reconciliation refused: {error:?}"
                                ))
                            })
                    },
                )
            })
            .map_err(|error| format!("{error:?}"))?
            .map_err(|error| format!("{error:?}"))
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::tests::{admitted_fixture, configure_native_files, editor_runtime};
    use super::*;
    use crate::LockUnpoisoned;
    use whipplescript_store::content::{ContentBlobs, ContentStore};

    pub(super) struct Saved {
        pub(super) dir: tempfile::TempDir,
        pub(super) wb: crate::SharedWorkbench,
        pub(super) command: HostActionCommand,
        pub(super) inputs: NativeActionInputCustody,
        pub(super) token: String,
        pub(super) admission: ActionAdmissionReceipt,
        pub(super) runtime: GovernedHostFacade<NativeStores>,
        pub(super) effect_id: String,
        pub(super) run_id: String,
    }

    pub(super) fn saved(lose_settlement: bool) -> Saved {
        saved_with_context(lose_settlement, |wb, _, _, token| {
            wb.authenticate_action_context(token).unwrap()
        })
    }

    pub(super) fn saved_with_context(
        lose_settlement: bool,
        authenticate: impl FnOnce(
            &mut Workbench,
            &NativeActionInputCustody,
            &HostActionCommand,
            &str,
        ) -> AuthenticatedActionContext,
    ) -> Saved {
        let dir = tempfile::tempdir().unwrap();
        let (shared, command, inputs, token) = admitted_fixture(dir.path());
        let mut wb = shared.lock_unpoisoned();
        let context = authenticate(&mut wb, &inputs, &command, &token);
        let mut runtime = editor_runtime(&wb, &command, dir.path());
        configure_native_files(runtime.kernel().store());
        let admission = wb
            .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
            .unwrap()
            .receipt;
        let reads = wb
            .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
            .unwrap();
        wb.execute_editor_file_save_effect(
            &context,
            &inputs,
            &command,
            &admission,
            &reads[0],
            &mut runtime,
        )
        .unwrap();
        let writes = wb
            .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
            .unwrap();
        let fault = rusqlite::Connection::open(dir.path().join("runtime.sqlite")).unwrap();
        if lose_settlement {
            fault.execute_batch("CREATE TRIGGER lose_inspection_terminal BEFORE INSERT ON events WHEN NEW.event_type = 'effect.terminal' BEGIN SELECT RAISE(ABORT, 'lost settlement'); END;").unwrap();
        }
        let write = wb.execute_editor_file_save_effect(
            &context,
            &inputs,
            &command,
            &admission,
            &writes[0],
            &mut runtime,
        );
        assert_eq!(write.is_err(), lose_settlement);
        if lose_settlement {
            fault
                .execute_batch("DROP TRIGGER lose_inspection_terminal")
                .unwrap();
        }
        let snapshot = wb
            .read_editor_file_save_result(&context, &inputs, &command, &admission, &runtime)
            .unwrap();
        let run_id = snapshot
            .effects
            .iter()
            .find(|effect| effect.effect_id == writes[0])
            .unwrap()
            .attempts[0]
            .run_id
            .clone();
        drop(wb);
        Saved {
            dir,
            wb: shared,
            command,
            inputs,
            token,
            admission,
            runtime,
            effect_id: writes[0].clone(),
            run_id,
        }
    }

    pub(in crate::file_action_factory) fn erase_fixture_base(
        root: &std::path::Path,
        base: &str,
        path: &str,
    ) -> usize {
        let mut erased = 0;
        for entry in std::fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            let location = entry.path();
            if entry.file_type().unwrap().is_dir() {
                erased += erase_fixture_base(&location, base, path);
            } else if entry.file_name() == "content.sqlite"
                && root.join("branches.sqlite").is_file()
            {
                // Locate only this synthetic fixture's actual owning store;
                // production code never derives or traverses private DB paths.
                let workspace = whipplescript_store::vcs::NativeWorkspaceVcs::open_read_only(
                    root.join("branches.sqlite"),
                    &location,
                )
                .unwrap();
                if workspace.get_cut(base).unwrap().is_some() {
                    let body = workspace.read_at_cut(base, path).unwrap().unwrap();
                    assert_eq!(body, "recorded base");
                    let content = ContentStore::open(&location).unwrap();
                    assert!(matches!(
                        content
                            .erase(
                                &whipplescript_store::stable_hash_hex(&body),
                                "erase fixture base"
                            )
                            .unwrap(),
                        whipplescript_store::content::EraseOutcome::Erased { .. }
                    ));
                    erased += 1;
                }
            }
        }
        erased
    }

    #[test]
    fn current_inspection_recovers_original_save_after_input_erasure_and_restart() {
        for lost in [false, true] {
            let Saved {
                dir,
                wb,
                command,
                inputs,
                token: _,
                admission,
                runtime,
                effect_id,
                run_id,
            } = saved(lost);
            let content = ContentStore::open(dir.path().join("inputs.sqlite")).unwrap();
            let draft_hash = inputs
                .resolve(&command.inputs["content"])
                .unwrap()
                .content_hash;
            // The draft lives inside this retained envelope, not in a
            // second raw-hash entry in the input authority.
            assert!(matches!(
                content
                    .erase(
                        &command.inputs["content"].version_ref,
                        "erase draft envelope"
                    )
                    .unwrap(),
                whipplescript_store::content::EraseOutcome::Erased { .. }
            ));
            assert!(inputs.resolve(&command.inputs["content"]).is_err());
            drop(inputs);
            drop(wb);
            drop(runtime);
            let shared = crate::open_workbench(dir.path()).unwrap();
            let mut wb = shared.lock_unpoisoned();
            let token = wb.mint_account_session("alice", "passkey", 3600).unwrap();
            let context = wb.authenticate_action_context(&token).unwrap();
            let inputs = NativeActionInputCustody::open(
                dir.path().join("inputs.sqlite"),
                wb.home_id().as_str(),
                4096,
            )
            .unwrap();
            let runtime = editor_runtime(&wb, &command, dir.path());
            let before = wb
                .read_editor_file_save_result(&context, &inputs, &command, &admission, &runtime)
                .unwrap();
            let events = runtime
                .kernel()
                .store()
                .list_events(&admission.instance_ref)
                .unwrap();
            let (_, _, chat): (String, String, String) =
                serde_json::from_str(&command.scope).unwrap();
            let path = wb.engagement_workspace_path(&chat, "note.txt");
            wb.engagements[&chat]
                .write_file(&path, "later recorded head")
                .unwrap();
            let later = wb.engagements[&chat]
                .commit_turn("later fixture edit")
                .unwrap()
                .unwrap()
                .0;
            wb.engagements[&chat]
                .write_file(&path, "unobserved manual edit")
                .unwrap();
            let ActionBasis::Version { version_ref: base } = &command.resources["target"].basis
            else {
                panic!("exact fixture base");
            };
            assert_eq!(erase_fixture_base(dir.path(), base, &path), 1);
            assert!(wb.bind_native_editor_target(&chat, &command).is_err());
            let recovered = wb
                .inspect_editor_file_save_attempt(
                    &context,
                    &inputs,
                    &command,
                    &admission,
                    EditorFileSaveAttempt {
                        effect_id: &effect_id,
                        run_id: &run_id,
                    },
                    &runtime,
                )
                .unwrap()
                .unwrap();
            assert_eq!(recovered.accepted_content, "private editor draft");
            assert_eq!(recovered.receipt.binding.draft_hash, draft_hash);
            assert_ne!(
                recovered.receipt.binding.draft_hash,
                command.inputs["content"].version_ref
            );
            assert_eq!(recovered.receipt.attempt.run_id, run_id);
            assert_eq!(
                wb.engagements[&chat].observe().unwrap().recorded_cut,
                Some(later)
            );
            assert_eq!(
                wb.engagements[&chat].read_file(&path).unwrap(),
                "unobserved manual edit"
            );
            assert_eq!(
                wb.read_editor_file_save_result(&context, &inputs, &command, &admission, &runtime)
                    .unwrap(),
                before
            );
            for (effect, run) in [
                ("other-effect", run_id.as_str()),
                (effect_id.as_str(), "other-run"),
            ] {
                assert!(wb
                    .inspect_editor_file_save_attempt(
                        &context,
                        &inputs,
                        &command,
                        &admission,
                        EditorFileSaveAttempt {
                            effect_id: effect,
                            run_id: run
                        },
                        &runtime
                    )
                    .is_err());
            }
            wb.revoke_account_session(&token);
            assert!(wb
                .inspect_editor_file_save_attempt(
                    &context,
                    &inputs,
                    &command,
                    &admission,
                    EditorFileSaveAttempt {
                        effect_id: &effect_id,
                        run_id: &run_id
                    },
                    &runtime
                )
                .is_err());
            assert_eq!(
                runtime
                    .kernel()
                    .store()
                    .list_events(&admission.instance_ref)
                    .unwrap(),
                events
            );
        }
    }

    pub(super) fn erase_fixture_result(root: &std::path::Path, hash: &str) -> usize {
        let mut erased = 0;
        for entry in std::fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                erased += erase_fixture_result(&path, hash);
            } else if entry.file_name() == "content.sqlite"
                && root.join("branches.sqlite").is_file()
            {
                let content = ContentStore::open(&path).unwrap();
                if content.get(hash).unwrap().is_some() {
                    assert!(matches!(
                        content.erase(hash, "erase result fixture").unwrap(),
                        whipplescript_store::content::EraseOutcome::Erased { .. }
                    ));
                    erased += 1;
                }
            }
        }
        erased
    }

    fn assert_reconciliation_verifier(
        wb: &Workbench,
        owner: &NativeEditorActionRuntime,
        command: &HostActionCommand,
        request: &ReconcileEffectCommand,
    ) {
        let key = SigningKey::from_seed(&wb.governance_seed()).unwrap();
        let snapshot = super::super::execution::read_evidence(
            owner.runtime(),
            command,
            &owner.admission,
            &key,
        )
        .unwrap();
        let store = owner.runtime().kernel().store();
        let effect = store
            .list_effects(&owner.admission.instance_ref)
            .unwrap()
            .into_iter()
            .find(|effect| effect.effect_id == request.evidence.frame.effect_id)
            .unwrap();
        let original = original_save(
            &snapshot,
            store.chain_prefix(&owner.admission.instance_ref).unwrap(),
            effect,
            &request.evidence.frame.run_id,
            &dispatch_grant::NativeDispatchHistory::open(wb, key.public_key()).unwrap(),
        )
        .unwrap();
        let verifier = NativeSaveReconciliationAuthority {
            request,
            original: command,
            save: &original,
            key: key.public_key(),
        };
        let bytes = request.signing_bytes().unwrap();
        let signature = key.sign(&bytes);
        verifier
            .authenticate(request, &bytes, signature.as_bytes())
            .unwrap();
        verifier
            .authorize(request, command, &original.execution, &original.binding)
            .unwrap();
        let mut changed_request = request.clone();
        changed_request.request_id.push_str("-other");
        assert!(verifier
            .authenticate(&changed_request, &bytes, signature.as_bytes())
            .is_err());
        assert!(verifier
            .authenticate(request, b"other signing bytes", signature.as_bytes())
            .is_err());
        assert!(verifier
            .authenticate(request, &bytes, b"other proof")
            .is_err());
        assert!(verifier
            .authorize(
                &changed_request,
                command,
                &original.execution,
                &original.binding
            )
            .is_err());
        let mut changed_command = command.clone();
        changed_command.operation.push_str("-other");
        assert!(verifier
            .authorize(
                request,
                &changed_command,
                &original.execution,
                &original.binding
            )
            .is_err());
        let mut changed_execution = original.execution.clone();
        changed_execution.effect_fingerprint.push_str("-other");
        assert!(verifier
            .authorize(request, command, &changed_execution, &original.binding)
            .is_err());
        for field in ["branch", "path", "base", "draft", "principal", "label"] {
            let mut binding = original.binding.clone();
            match field {
                "branch" => binding.branch_id.push_str("-other"),
                "path" => binding.path.push_str("-other"),
                "base" => binding.base_cut_id.push_str("-other"),
                "draft" => binding.draft_hash.push_str("-other"),
                "principal" => binding.executing_principal.push_str("-other"),
                _ => binding.evidence_label.push_str("-other"),
            }
            assert!(
                verifier
                    .authorize(request, command, &original.execution, &binding)
                    .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn current_reconciliation_retains_original_evidence_and_never_repeats_the_save() {
        use gaugedesk_whip_runtime::host_actions::recovery::RecordedReconciliation;
        for lost in [false, true] {
            let Saved {
                dir,
                wb,
                command,
                inputs,
                token: _,
                admission,
                runtime,
                effect_id,
                run_id,
            } = saved(lost);
            assert!(matches!(
                ContentStore::open(dir.path().join("inputs.sqlite"))
                    .unwrap()
                    .erase(
                        &command.inputs["content"].version_ref,
                        "erase original draft"
                    )
                    .unwrap(),
                whipplescript_store::content::EraseOutcome::Erased { .. }
            ));
            assert!(inputs.resolve(&command.inputs["content"]).is_err());
            drop(inputs);
            drop(wb);
            drop(runtime);
            let shared = crate::open_workbench(dir.path()).unwrap();
            let mut wb = shared.lock_unpoisoned();
            let token = wb.mint_account_session("alice", "passkey", 3600).unwrap();
            let context = wb.authenticate_action_context(&token).unwrap();
            let inputs = NativeActionInputCustody::open(
                dir.path().join("inputs.sqlite"),
                wb.home_id().as_str(),
                4096,
            )
            .unwrap();
            let runtime = editor_runtime(&wb, &command, dir.path());
            let mut owner = wb
                .claim_editor_file_save_runtime(&context, &inputs, &command, &admission, runtime)
                .unwrap();
            let (_, _, chat): (String, String, String) =
                serde_json::from_str(&command.scope).unwrap();
            let path = wb.engagement_workspace_path(&chat, "note.txt");
            wb.engagements[&chat]
                .write_file(&path, "later recorded head")
                .unwrap();
            let later = wb.engagements[&chat]
                .commit_turn("later fixture edit")
                .unwrap()
                .unwrap()
                .0;
            wb.engagements[&chat]
                .write_file(&path, "unobserved manual edit")
                .unwrap();
            let ActionBasis::Version { version_ref: base } = &command.resources["target"].basis
            else {
                panic!("exact base")
            };
            assert_eq!(erase_fixture_base(dir.path(), base, &path), 1);
            let before = owner
                .runtime()
                .kernel()
                .store()
                .list_events(&admission.instance_ref)
                .unwrap();
            let attempt = EditorFileSaveAttempt {
                effect_id: &effect_id,
                run_id: &run_id,
            };
            let intent = || EditorFileSaveReconciliation {
                request_id: "inspect-saved-result",
                attempt,
            };
            let receipt = wb
                .reconcile_editor_file_save_attempt(
                    &context,
                    &inputs,
                    &command,
                    &admission,
                    intent(),
                    &mut owner,
                )
                .unwrap()
                .unwrap();
            let after = owner
                .runtime()
                .kernel()
                .store()
                .list_events(&admission.instance_ref)
                .unwrap();
            assert_eq!(after.len(), before.len() + 1);
            assert_eq!(&after[..before.len()], before.as_slice());
            let event = after.last().unwrap();
            assert_eq!(event.event_type, "effect.disposition.reconciled");
            let recorded: RecordedReconciliation =
                serde_json::from_str(&event.payload_json).unwrap();
            assert_eq!(recorded.command.provenance.origin, "editor.save.reconcile");
            assert_eq!(
                recorded.command.provenance.initiator,
                context.actor().as_str()
            );
            assert_eq!(recorded.command.provenance.causes.len(), 1);
            assert_eq!(
                recorded.command.provenance.causes[0].digest,
                admission.admitted_at.head_digest
            );
            assert_eq!(recorded.command.evidence.frame.run_id, run_id);
            assert_eq!(
                recorded.command.evidence.disposition,
                EvidenceDisposition::Applied
            );
            assert_eq!(recorded.command.evidence.evidence_digest.len(), 64);
            assert_reconciliation_verifier(&wb, &owner, &command, &recorded.command);
            assert_eq!(
                wb.reconcile_editor_file_save_attempt(
                    &context,
                    &inputs,
                    &command,
                    &admission,
                    intent(),
                    &mut owner
                )
                .unwrap(),
                Some(receipt)
            );
            assert_eq!(
                owner
                    .runtime()
                    .kernel()
                    .store()
                    .list_events(&admission.instance_ref)
                    .unwrap(),
                after
            );
            assert_eq!(
                wb.engagements[&chat].observe().unwrap().recorded_cut,
                Some(later)
            );
            assert_eq!(
                wb.engagements[&chat].read_file(&path).unwrap(),
                "unobserved manual edit"
            );
            let recovered = wb
                .inspect_editor_file_save_attempt(
                    &context,
                    &inputs,
                    &command,
                    &admission,
                    attempt,
                    owner.runtime(),
                )
                .unwrap()
                .unwrap();
            let replacement = editor_runtime(&wb, &command, dir.path());
            let mut current = wb
                .claim_editor_file_save_runtime(
                    &context,
                    &inputs,
                    &command,
                    &admission,
                    replacement,
                )
                .unwrap();
            assert_eq!(
                erase_fixture_result(dir.path(), &recovered.reference.content_hash),
                1
            );
            let error = wb
                .reconcile_editor_file_save_attempt(
                    &context,
                    &inputs,
                    &command,
                    &admission,
                    intent(),
                    &mut owner,
                )
                .unwrap_err();
            assert!(error.contains("ownership is stale"), "{error}");
            let error = wb
                .reconcile_editor_file_save_attempt(
                    &context,
                    &inputs,
                    &command,
                    &admission,
                    intent(),
                    &mut current,
                )
                .unwrap_err();
            assert!(error.contains("evidence is unavailable"), "{error}");
            wb.revoke_account_session(&token);
            assert!(wb
                .reconcile_editor_file_save_attempt(
                    &context,
                    &inputs,
                    &command,
                    &admission,
                    intent(),
                    &mut current
                )
                .is_err());
            assert_eq!(
                current
                    .runtime()
                    .kernel()
                    .store()
                    .list_events(&admission.instance_ref)
                    .unwrap(),
                after
            );
        }
    }

    #[test]
    fn original_save_refuses_changed_history_execution_and_projected_input() {
        let fixture = saved(true);
        let mut wb = fixture.wb.lock_unpoisoned();
        let context = wb.authenticate_action_context(&fixture.token).unwrap();
        let snapshot = wb
            .read_editor_file_save_result(
                &context,
                &fixture.inputs,
                &fixture.command,
                &fixture.admission,
                &fixture.runtime,
            )
            .unwrap();
        let store = fixture.runtime.kernel().store();
        let prefix = store.chain_prefix(&fixture.admission.instance_ref).unwrap();
        let effect = store
            .list_effects(&fixture.admission.instance_ref)
            .unwrap()
            .into_iter()
            .find(|effect| effect.effect_id == fixture.effect_id)
            .unwrap();
        let key = SigningKey::from_seed(&wb.governance_seed()).unwrap();
        let history = dispatch_grant::NativeDispatchHistory::open(&wb, key.public_key()).unwrap();
        assert!(original_save(
            &snapshot,
            prefix.clone(),
            effect.clone(),
            &fixture.run_id,
            &history
        )
        .is_ok());
        let mut changed = prefix.clone();
        changed[0].payload_json.push(' ');
        assert!(original_save(
            &snapshot,
            changed,
            effect.clone(),
            &fixture.run_id,
            &history
        )
        .is_err());
        let mut changed = effect.clone();
        let mut input: serde_json::Value = serde_json::from_str(&changed.input_json).unwrap();
        input["body_ref"]["content_hash"] = "0".repeat(32).into();
        changed.input_json = input.to_string();
        assert!(original_save(
            &snapshot,
            prefix.clone(),
            changed,
            &fixture.run_id,
            &history
        )
        .is_err());
        for field in ["dispatch", "executor", "admission"] {
            let mut changed = prefix.clone();
            let start = changed
                .iter_mut()
                .find(|row| {
                    row.event_type == "effect.run_started"
                        && serde_json::from_str::<serde_json::Value>(&row.payload_json).unwrap()
                            ["run_id"]
                            == fixture.run_id
                })
                .unwrap();
            let mut payload: serde_json::Value = serde_json::from_str(&start.payload_json).unwrap();
            match field {
                "dispatch" => {
                    payload["external_dispatch"]["frame"]["effect_id"] = "other-effect".into()
                }
                "executor" => {
                    payload["metadata"]["action_execution"]["request"]["provenance"]["executor"] =
                        "other-principal".into()
                }
                _ => {
                    payload["metadata"]["action_execution"]["request"]["admission"]["fingerprint"] =
                        "other-admission".into()
                }
            }
            start.payload_json = payload.to_string();
            // Repin this deliberately corrupt fixture so the binding checks,
            // rather than the earlier chain mismatch, must reject it.
            let mut repinned = snapshot.clone();
            repinned.observed_at.head_digest =
                fold_owned(&fixture.admission.instance_ref, &changed).digest;
            assert!(
                original_save(
                    &repinned,
                    changed,
                    effect.clone(),
                    &fixture.run_id,
                    &history
                )
                .is_err(),
                "{field}"
            );
        }
    }
}

#[cfg(test)]
#[path = "file_action_dispatch_evidence_tests.rs"]
mod dispatch_evidence_tests;
