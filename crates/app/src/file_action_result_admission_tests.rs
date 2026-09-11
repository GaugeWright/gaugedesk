use super::super::tests::{erase_fixture_base, erase_fixture_result, saved, Saved};
use super::*;
use crate::file_action_factory::tests::editor_runtime;
use crate::LockUnpoisoned;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use whipplescript_store::content::{ContentBlobs, ContentStore};

struct RetentionCodec {
    content_path: std::path::PathBuf,
    observed: Arc<AtomicBool>,
    inner: Option<Arc<dyn gaugedesk_store::ContentCodec>>,
}
impl gaugedesk_store::ContentCodec for RetentionCodec {
    fn encode(&self, scope: &str, kind: &str, payload: &str) -> Result<String, String> {
        if kind == RESULT_KIND {
            let contender = rusqlite::Connection::open(&self.content_path).unwrap();
            contender.busy_timeout(std::time::Duration::ZERO).unwrap();
            assert!(
                contender.execute_batch("BEGIN IMMEDIATE").is_err(),
                "product result commit lost target retention"
            );
            self.observed.store(true, Ordering::SeqCst);
        }
        match &self.inner {
            Some(codec) => codec.encode(scope, kind, payload),
            None => Ok(payload.into()),
        }
    }
    fn decode(&self, scope: &str, kind: &str, payload: &str) -> Option<String> {
        match &self.inner {
            Some(codec) => codec.decode(scope, kind, payload),
            None => Some(payload.into()),
        }
    }
}

// Discovery is confined to this synthetic fixture. Product code gets only the
// actual workspace adapter and never searches for a content store by hash.
fn receipt_store(root: &std::path::Path, hash: &str) -> Option<std::path::PathBuf> {
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            if let Some(found) = receipt_store(&path, hash) {
                return Some(found);
            }
        } else if entry.file_name() == "content.sqlite"
            && ContentStore::open(&path)
                .unwrap()
                .get(hash)
                .unwrap()
                .is_some()
        {
            return Some(path);
        }
    }
    None
}

#[test]
fn native_saved_result_admission_recovers_interruption_and_restart_without_rewriting_work() {
    for lost in [false, true] {
        let Saved {
            dir,
            wb: shared,
            command,
            inputs,
            token,
            admission,
            runtime,
            effect_id,
            run_id,
        } = saved(lost);
        let (first, runtime_events) = {
            let mut wb = shared.lock_unpoisoned();
            let context = wb.authenticate_action_context(&token).unwrap();
            let attempt = EditorFileSaveAttempt {
                effect_id: &effect_id,
                run_id: &run_id,
            };
            let error = wb
                .admit_editor_file_save_result(
                    &context, &inputs, &command, &admission, attempt, &runtime,
                )
                .err()
                .unwrap();
            assert!(error.contains("undisputed applied"), "{error}");
            assert!(wb
                .store_ref()
                .records(&admission.instance_ref, RESULT_KIND)
                .unwrap()
                .is_empty());
            let mut owner = wb
                .claim_editor_file_save_runtime(&context, &inputs, &command, &admission, runtime)
                .unwrap();
            wb.reconcile_editor_file_save_attempt(
                &context,
                &inputs,
                &command,
                &admission,
                EditorFileSaveReconciliation {
                    request_id: "prove-save",
                    attempt,
                },
                &mut owner,
            )
            .unwrap()
            .unwrap();
            let evidence = wb
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
            let observed = Arc::new(AtomicBool::new(false));
            wb.store = wb
                .store_ref()
                .sibling()
                .unwrap()
                .with_codec(Arc::new(RetentionCodec {
                    content_path: receipt_store(dir.path(), &evidence.reference.content_hash)
                        .unwrap(),
                    observed: observed.clone(),
                    inner: wb
                        .content_vault
                        .clone()
                        .map(|vault| vault as Arc<dyn gaugedesk_store::ContentCodec>),
                }));
            let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
            fault.execute_batch("CREATE TRIGGER lose_saved_product_result BEFORE INSERT ON events WHEN NEW.kind = 'native_editor_saved_result_v1' BEGIN SELECT RAISE(ABORT, 'lost product receipt'); END;").unwrap();
            assert!(wb
                .admit_editor_file_save_result(
                    &context,
                    &inputs,
                    &command,
                    &admission,
                    attempt,
                    owner.runtime()
                )
                .is_err());
            assert!(observed.load(Ordering::SeqCst));
            assert!(wb
                .store_ref()
                .records(&admission.instance_ref, RESULT_KIND)
                .unwrap()
                .is_empty());
            fault
                .execute_batch("DROP TRIGGER lose_saved_product_result")
                .unwrap();
            let before = owner
                .runtime()
                .kernel()
                .store()
                .list_events(&admission.instance_ref)
                .unwrap();
            let accepted = wb
                .admit_editor_file_save_result(
                    &context,
                    &inputs,
                    &command,
                    &admission,
                    attempt,
                    owner.runtime(),
                )
                .unwrap()
                .unwrap();
            assert!(!accepted.replayed);
            let first = accepted.result;
            assert_eq!(first.provenance.initiator, "alice");
            assert_eq!(first.provenance.executor, "alice");
            assert_eq!(first.provenance.origin, "editor.save.result");
            assert_eq!(first.provenance.causes.len(), 2);
            assert_eq!(
                first.provenance.causes[0].digest,
                admission.admitted_at.head_digest
            );
            assert_eq!(first.reconciliation.kind, "effect.disposition.reconciled");
            assert_eq!(first.evidence_handle, "result");
            assert_eq!(
                first.evidence_label_ref,
                format!("policy:{}:result", command.policy.envelope_hash)
            );
            assert_eq!(first.result_reference, evidence.reference);
            assert_eq!(
                first.cut_id,
                whipplescript_store::vcs_file_save::save_cut_id(
                    &admission.instance_ref,
                    &effect_id
                )
            );
            assert_eq!(
                first.content_hash,
                whipplescript_store::stable_hash_hex("private editor draft")
            );
            let payload = serde_json::to_string(&first).unwrap();
            assert!(!payload.contains("private editor draft"));
            assert_eq!(
                wb.store_ref()
                    .records(&admission.instance_ref, RESULT_KIND)
                    .unwrap(),
                vec![payload]
            );
            assert_eq!(
                owner
                    .runtime()
                    .kernel()
                    .store()
                    .list_events(&admission.instance_ref)
                    .unwrap(),
                before
            );
            // A later separately admitted observation must not change the first
            // acknowledgment's causal identity on retry.
            wb.reconcile_editor_file_save_attempt(
                &context,
                &inputs,
                &command,
                &admission,
                EditorFileSaveReconciliation {
                    request_id: "prove-save-again",
                    attempt,
                },
                &mut owner,
            )
            .unwrap()
            .unwrap();
            let events = owner
                .runtime()
                .kernel()
                .store()
                .list_events(&admission.instance_ref)
                .unwrap();
            let (.., chat): (String, String, String) =
                serde_json::from_str(&command.scope).unwrap();
            let path = wb.engagement_workspace_path(&chat, "note.txt");
            wb.engagements[&chat]
                .write_file(&path, "later accepted version")
                .unwrap();
            let later = wb.engagements[&chat]
                .commit_turn("later fixture edit")
                .unwrap()
                .unwrap()
                .0;
            wb.engagements[&chat]
                .write_file(&path, "unobserved manual edit")
                .unwrap();
            ContentStore::open(dir.path().join("inputs.sqlite"))
                .unwrap()
                .erase(
                    &command.inputs["content"].version_ref,
                    "erase draft fixture",
                )
                .unwrap();
            let ActionBasis::Version { version_ref: base } = &command.resources["target"].basis
            else {
                panic!("exact base")
            };
            assert_eq!(erase_fixture_base(dir.path(), base, &path), 1);
            let replay = wb
                .admit_editor_file_save_result(
                    &context,
                    &inputs,
                    &command,
                    &admission,
                    attempt,
                    owner.runtime(),
                )
                .unwrap()
                .unwrap();
            assert!(replay.replayed);
            assert_eq!(replay.result, first);
            assert_eq!(
                wb.engagements[&chat].observe().unwrap().recorded_cut,
                Some(later)
            );
            assert_eq!(
                wb.engagements[&chat].read_file(&path).unwrap(),
                "unobserved manual edit"
            );
            assert_eq!(
                owner
                    .runtime()
                    .kernel()
                    .store()
                    .list_events(&admission.instance_ref)
                    .unwrap(),
                events
            );
            (first, events)
        };
        drop(inputs);
        drop(shared);
        let shared = crate::open_workbench(dir.path()).unwrap();
        let mut wb = shared.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let inputs = NativeActionInputCustody::open(
            dir.path().join("inputs.sqlite"),
            wb.home_id().as_str(),
            4096,
        )
        .unwrap();
        let runtime = editor_runtime(&wb, &command, dir.path());
        let attempt = EditorFileSaveAttempt {
            effect_id: &effect_id,
            run_id: &run_id,
        };
        let replay = wb
            .admit_editor_file_save_result(
                &context, &inputs, &command, &admission, attempt, &runtime,
            )
            .unwrap()
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.result, first);
        assert_eq!(
            runtime
                .kernel()
                .store()
                .list_events(&admission.instance_ref)
                .unwrap(),
            runtime_events
        );
        wb.revoke_account_session(&token);
        assert!(wb
            .admit_editor_file_save_result(
                &context, &inputs, &command, &admission, attempt, &runtime
            )
            .is_err());
        let replacement = wb.mint_account_session("alice", "passkey", 3600).unwrap();
        let context = wb.authenticate_action_context(&replacement).unwrap();
        assert_eq!(
            erase_fixture_result(dir.path(), &first.result_reference.content_hash),
            1
        );
        assert!(wb
            .admit_editor_file_save_result(
                &context, &inputs, &command, &admission, attempt, &runtime
            )
            .is_err());
        assert_eq!(
            wb.store_ref()
                .records(&admission.instance_ref, RESULT_KIND)
                .unwrap()
                .len(),
            1
        );
    }
}

#[test]
fn native_saved_result_admission_refuses_changed_proof_and_disputed_runtime_evidence() {
    let Saved {
        dir,
        wb: shared,
        command,
        inputs,
        token,
        admission,
        runtime,
        effect_id,
        run_id,
    } = saved(false);
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let attempt = EditorFileSaveAttempt {
        effect_id: &effect_id,
        run_id: &run_id,
    };
    let mut owner = wb
        .claim_editor_file_save_runtime(&context, &inputs, &command, &admission, runtime)
        .unwrap();
    wb.reconcile_editor_file_save_attempt(
        &context,
        &inputs,
        &command,
        &admission,
        EditorFileSaveReconciliation {
            request_id: "prove-save",
            attempt,
        },
        &mut owner,
    )
    .unwrap()
    .unwrap();
    let fault = rusqlite::Connection::open(dir.path().join("runtime.sqlite")).unwrap();
    let (id, original): (String, String) = fault.query_row("SELECT event_id, payload_json FROM events WHERE event_type = 'effect.disposition.reconciled'", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
    for (field, value) in [
        (
            "/command/evidence/evidence_digest",
            serde_json::json!("changed digest"),
        ),
        (
            "/command/evidence/authority_ref",
            serde_json::json!("another issuer"),
        ),
        (
            "/command/evidence/evidence_ref",
            serde_json::json!("another target"),
        ),
        ("/command/issuer", serde_json::json!("another issuer")),
        ("/command/scope", serde_json::json!("another scope")),
        (
            "/command/policy/epoch",
            serde_json::json!(command.policy.epoch + 1),
        ),
        (
            "/command/evidence_label_ref",
            serde_json::json!("another label"),
        ),
        (
            "/diagnostic",
            serde_json::json!({
                "code": "runtime.recovery_uncertain", "effect_id": effect_id,
                "run_id": run_id, "message": "disputed fixture evidence", "evidence_refs": [],
            }),
        ),
    ] {
        let mut payload: serde_json::Value = serde_json::from_str(&original).unwrap();
        *payload.pointer_mut(field).unwrap() = value;
        fault
            .execute(
                "UPDATE events SET payload_json = ?1 WHERE event_id = ?2",
                rusqlite::params![payload.to_string(), id],
            )
            .unwrap();
        assert!(
            wb.admit_editor_file_save_result(
                &context,
                &inputs,
                &command,
                &admission,
                attempt,
                owner.runtime()
            )
            .is_err(),
            "{field}"
        );
        assert!(wb
            .store_ref()
            .records(&admission.instance_ref, RESULT_KIND)
            .unwrap()
            .is_empty());
    }
    fault
        .execute(
            "UPDATE events SET payload_json = ?1 WHERE event_id = ?2",
            rusqlite::params![original, id],
        )
        .unwrap();
    let recorded: RecordedReconciliation = serde_json::from_str(&original).unwrap();
    let mut contrary = recorded.command.evidence;
    contrary.disposition = EvidenceDisposition::NotApplied;
    contrary.evidence_digest = "contradictory fixture proof".into();
    owner
        .runtime
        .kernel_mut()
        .store_mut()
        .append_event(whipplescript_store::NewEvent {
            instance_id: &admission.instance_ref,
            event_type: "effect.disposition.recorded",
            payload_json: &serde_json::to_string(&contrary).unwrap(),
            source: "kernel",
            causation_id: Some(&run_id),
            correlation_id: None,
            idempotency_key: Some("contradictory fixture evidence"),
        })
        .unwrap();
    let error = wb
        .admit_editor_file_save_result(
            &context,
            &inputs,
            &command,
            &admission,
            attempt,
            owner.runtime(),
        )
        .err()
        .unwrap();
    assert!(error.contains("undisputed applied"), "{error}");
    assert!(wb
        .store_ref()
        .records(&admission.instance_ref, RESULT_KIND)
        .unwrap()
        .is_empty());
}

#[test]
fn native_saved_result_admission_records_the_merged_body_instead_of_the_original_draft() {
    use crate::file_action_factory::tests::{admitted_content_fixture, configure_native_files};
    let dir = tempfile::tempdir().unwrap();
    let draft = "alpha changed\nbravo base\ncharlie base\n";
    let merged = "alpha changed\nbravo base\ncharlie changed\n";
    let (shared, command, inputs, token) =
        admitted_content_fixture(dir.path(), "alpha base\nbravo base\ncharlie base\n", draft);
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    configure_native_files(runtime.kernel().store());
    let admission = wb
        .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
        .unwrap()
        .receipt;
    let read = wb
        .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
        .unwrap()
        .remove(0);
    wb.execute_editor_file_save_effect(
        &context,
        &inputs,
        &command,
        &admission,
        &read,
        &mut runtime,
    )
    .unwrap();
    let write = wb
        .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
        .unwrap()
        .remove(0);
    let (.., chat): (String, String, String) = serde_json::from_str(&command.scope).unwrap();
    let path = wb.engagement_workspace_path(&chat, "note.txt");
    wb.engagements[&chat]
        .write_file(&path, "alpha base\nbravo base\ncharlie changed\n")
        .unwrap();
    wb.engagements[&chat]
        .commit_turn("concurrent fixture edit")
        .unwrap();
    wb.execute_editor_file_save_effect(
        &context,
        &inputs,
        &command,
        &admission,
        &write,
        &mut runtime,
    )
    .unwrap();
    let snapshot = wb
        .read_editor_file_save_result(&context, &inputs, &command, &admission, &runtime)
        .unwrap();
    let run = &snapshot
        .effects
        .iter()
        .find(|effect| effect.effect_id == write)
        .unwrap()
        .attempts[0]
        .run_id;
    let attempt = EditorFileSaveAttempt {
        effect_id: &write,
        run_id: run,
    };
    let mut owner = wb
        .claim_editor_file_save_runtime(&context, &inputs, &command, &admission, runtime)
        .unwrap();
    wb.reconcile_editor_file_save_attempt(
        &context,
        &inputs,
        &command,
        &admission,
        EditorFileSaveReconciliation {
            request_id: "prove-merged-save",
            attempt,
        },
        &mut owner,
    )
    .unwrap()
    .unwrap();
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
    assert_eq!(recovered.accepted_content, merged);
    let result = wb
        .admit_editor_file_save_result(
            &context,
            &inputs,
            &command,
            &admission,
            attempt,
            owner.runtime(),
        )
        .unwrap()
        .unwrap();
    assert!(result.result.merged);
    assert_eq!(
        result.result.content_hash,
        whipplescript_store::stable_hash_hex(merged)
    );
    assert_ne!(
        result.result.content_hash,
        whipplescript_store::stable_hash_hex(draft)
    );
    assert_eq!(result.result.result_reference, recovered.reference);
    let payload = serde_json::to_string(&result.result).unwrap();
    assert!(!payload.contains("alpha changed"));
    assert!(!payload.contains("charlie changed"));
    assert_eq!(
        wb.engagements[&chat].read_file(&path).unwrap(),
        "alpha base\nbravo base\ncharlie changed\n"
    );
}
