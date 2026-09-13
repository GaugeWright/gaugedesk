use super::*;
use crate::file_action_factory::tests::membership;
use crate::file_action_factory::{EditorCorrectionReconciliation, EditorCorrectionResultRequest};
use gaugedesk_whip_runtime::host_actions::{action_result::ActionWorkflowStatus, RuntimeStore};
use whipplescript_store::effect_recovery::ExternalDisposition;

fn admit(
    wb: &mut Workbench,
    context: &AuthenticatedActionContext,
    storage: &NativeActionStorage,
    saved: &HostActionCommand,
    cause: &ActionCause,
) -> HostActionCommand {
    let (chat, path) = coordinates(saved);
    wb.admit_saved_source_corrections(
        context,
        storage,
        &EditorCorrections {
            chat_id: &chat,
            request_id: "derived-journey",
            path: &path,
            corrections: &input(),
        },
        cause,
    )
    .unwrap()
    .command
}

#[test]
fn derived_correction_executes_and_recovers_independently_after_source_erasure() {
    for interrupted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        // The source save remains Unknown throughout the correction's journey.
        let fixture = save_fixture(dir.path(), true);
        let mut wb = fixture.shared.lock_unpoisoned();
        let alice = wb.authenticate_action_context(&fixture.token).unwrap();
        let storage = storage(&wb);
        let source = source(
            &mut wb,
            &alice,
            &storage,
            &fixture.command,
            &fixture.admission,
            fixture.attempt(),
        );
        let (_, historical) = original(&wb, source.cause());
        let (bob, token) = reader(&mut wb);
        wb.revoke_account_session(&fixture.token);
        let command = admit(&mut wb, &bob, &storage, &fixture.command, source.cause());
        let inputs = ContentStore::open(dir.path().join("actions/inputs.sqlite")).unwrap();
        inputs
            .erase(&source.input().version_ref, "erase earlier saved input")
            .unwrap();
        let mut targets = Vec::new();
        target_databases(dir.path(), &mut targets);
        for path in targets {
            let content = ContentStore::open(path).unwrap();
            if content
                .get(&historical.statement.content_hash)
                .unwrap()
                .is_some()
            {
                content
                    .erase(
                        &historical.statement.content_hash,
                        "erase earlier saved body",
                    )
                    .unwrap();
            }
        }
        assert!(storage.inputs().resolve(source.input()).is_err());
        let (chat, _) = coordinates(&fixture.command);
        let before_head = wb.engagements[&chat].observe().unwrap().recorded_cut;
        let mut runtime = wb
            .open_editor_corrections_runtime(&bob, &storage, &command)
            .unwrap();
        let acknowledgment = wb
            .deliver_editor_corrections(&bob, storage.inputs(), &command, &mut runtime)
            .unwrap();
        let admission = acknowledgment.receipt;
        assert_eq!(
            wb.deliver_editor_corrections(&bob, storage.inputs(), &command, &mut runtime)
                .unwrap()
                .receipt,
            admission
        );
        let pending = wb
            .advance_editor_corrections(&bob, storage.inputs(), &command, &admission, &mut runtime)
            .unwrap();
        assert_eq!(pending.len(), 1);
        let fault =
            rusqlite::Connection::open(dir.path().join("actions/native/runtime.sqlite")).unwrap();
        if interrupted {
            fault.execute_batch("CREATE TRIGGER lose_derived_terminal BEFORE INSERT ON events WHEN NEW.event_type = 'effect.terminal' BEGIN SELECT RAISE(ABORT, 'lost derived settlement'); END;").unwrap();
        }
        let executed = wb.execute_editor_corrections_effect(
            &bob,
            storage.inputs(),
            &command,
            &admission,
            &pending[0],
            &mut runtime,
        );
        if interrupted {
            assert!(executed.is_err());
            fault
                .execute_batch("DROP TRIGGER lose_derived_terminal")
                .unwrap();
        } else {
            executed.unwrap();
            wb.advance_editor_corrections(
                &bob,
                storage.inputs(),
                &command,
                &admission,
                &mut runtime,
            )
            .unwrap();
        }
        let runs = runtime
            .kernel()
            .store()
            .list_runs(&admission.instance_ref)
            .unwrap();
        assert_eq!(runs.len(), 1);
        let run = runs[0].run_id.clone();
        let before = wb
            .read_editor_corrections_result(&bob, storage.inputs(), &command, &admission, &runtime)
            .unwrap();
        if interrupted {
            assert_eq!(
                before.effects[0].attempts[0].disposition,
                ExternalDisposition::Unknown
            );
        } else {
            assert_eq!(
                before.terminal.as_ref().unwrap().status,
                ActionWorkflowStatus::Completed
            );
        }
        assert_eq!(
            wb.engagements[&chat].observe().unwrap().recorded_cut,
            before_head
        );
        inputs
            .erase(
                &command.inputs["corrections"].version_ref,
                "erase recorded correction",
            )
            .unwrap();
        wb.revoke_account_session(&token);
        membership(&mut wb, "charlie", "owner");
        let investigator_token = wb.mint_account_session("charlie", "passkey", 3600).unwrap();
        drop(runtime);
        drop(wb);
        let reopened = crate::open_workbench(dir.path()).unwrap();
        let mut wb = reopened.lock_unpoisoned();
        let investigator = wb.authenticate_action_context(&investigator_token).unwrap();
        let observed = wb
            .inspect_editor_correction_attempt(
                &investigator,
                &command,
                &admission,
                &pending[0],
                &run,
            )
            .unwrap();
        let recording = observed.receipt.unwrap();
        assert_eq!(observed.binding.batch().actor, "bob");
        if interrupted {
            assert_eq!(
                observed.evidence.effects[0].attempts[0].disposition,
                ExternalDisposition::Unknown
            );
        }
        let reconciliation = wb
            .admit_editor_correction_reconciliation(
                &investigator,
                &command,
                &admission,
                &EditorCorrectionReconciliation {
                    request_id: "derived-recovery",
                    effect_id: &pending[0],
                    run_id: &run,
                },
            )
            .unwrap()
            .command;
        let mut owner = wb
            .claim_editor_correction_reconciliation(
                &investigator,
                &command,
                &admission,
                &reconciliation,
            )
            .unwrap();
        let acknowledged = wb
            .deliver_editor_correction_reconciliation(
                &investigator,
                &command,
                &admission,
                &reconciliation,
                &mut owner,
            )
            .unwrap();
        assert_eq!(
            wb.deliver_editor_correction_reconciliation(
                &investigator,
                &command,
                &admission,
                &reconciliation,
                &mut owner
            )
            .unwrap()
            .receipt,
            acknowledged.receipt
        );
        let result = wb
            .admit_editor_correction_result(
                &investigator,
                &command,
                &admission,
                &EditorCorrectionResultRequest {
                    request_id: "derived-result",
                    reconciliation_request_id: "derived-recovery",
                },
            )
            .unwrap()
            .result;
        assert_eq!(result.binding.batch().actor, "bob");
        assert_eq!(result.recording, recording);
        assert_eq!(result.provenance.initiator, "charlie");
        assert_eq!(
            wb.read_editor_correction_result(&investigator, &command, &admission, "derived-result")
                .unwrap(),
            Some(result.clone())
        );
        let after = wb
            .read_editor_corrections_evidence(&investigator, &command, &admission)
            .unwrap();
        assert_eq!(
            after.terminal.as_ref().map(|t| &t.status),
            before.terminal.as_ref().map(|t| &t.status)
        );
        assert_eq!(after.effects[0].attempts.len(), 1);
        assert_eq!(
            after.effects[0].attempts[0].disposition,
            ExternalDisposition::Applied
        );
        assert_eq!(
            original(&wb, source.cause()).1.statement,
            historical.statement
        );
        assert_eq!(
            historical.statement.attempt.disposition,
            ExternalDisposition::Unknown
        );
        assert_eq!(
            wb.engagements[&chat].observe().unwrap().recorded_cut,
            before_head
        );
        assert!(storage.inputs().resolve(source.input()).is_err());
        assert!(storage
            .inputs()
            .resolve(&command.inputs["corrections"])
            .is_err());
        let checkout = wb.engagements[&chat].path().to_path_buf();
        drop(owner);
        drop(wb);
        std::fs::remove_dir_all(&checkout).unwrap();
        let missing_projection = crate::open_workbench(dir.path()).unwrap();
        let mut wb = missing_projection.lock_unpoisoned();
        let investigator = wb.authenticate_action_context(&investigator_token).unwrap();
        assert_eq!(
            wb.read_editor_correction_result(&investigator, &command, &admission, "derived-result")
                .unwrap(),
            Some(result)
        );
        assert!(!checkout.exists());
    }
}

#[test]
fn derived_continuation_refuses_corrupt_causal_metadata_and_fences_its_scope() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let storage = storage(&wb);
    let source = source(
        &mut wb,
        &context,
        &storage,
        &fixture.command,
        &fixture.admission,
        fixture.attempt(),
    );
    let command = admit(
        &mut wb,
        &context,
        &storage,
        &fixture.command,
        source.cause(),
    );
    let (scope, mut historical) = original(&wb, source.cause());
    let record = serde_json::to_string(&historical).unwrap();
    historical.signature[0] ^= 1;
    let product = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    assert_eq!(
        product
            .execute(
                "UPDATE events SET payload = ?1 WHERE scope_id = ?2 AND kind = ?3",
                rusqlite::params![serde_json::to_string(&historical).unwrap(), scope, KIND]
            )
            .unwrap(),
        1
    );
    let runtime_before = std::fs::read(dir.path().join("actions/native/runtime.sqlite")).unwrap();
    assert!(wb
        .open_editor_corrections_runtime(&context, &storage, &command)
        .is_err());
    assert_eq!(
        std::fs::read(dir.path().join("actions/native/runtime.sqlite")).unwrap(),
        runtime_before
    );
    product
        .execute(
            "UPDATE events SET payload = ?1 WHERE scope_id = ?2 AND kind = ?3",
            rusqlite::params![record, scope, KIND],
        )
        .unwrap();
    let prepared = wb
        .prepare_native_corrections(&context, storage.inputs(), &command, &command.policy)
        .unwrap();
    wb.store_mut()
        .admit_record_facts(
            &scope,
            "source-fence-change",
            "{}",
            &[CommandRecordFact {
                scope_id: scope.clone(),
                kind: "source-fence-marker".into(),
                payload: "{}".into(),
            }],
        )
        .unwrap();
    let mut entered = false;
    assert!(wb
        .store_mut()
        .with_dispatch_basis(&prepared.basis, || entered = true)
        .is_err());
    assert!(!entered);
    let mut runtime = wb
        .open_editor_corrections_runtime(&context, &storage, &command)
        .unwrap();
    let admission = wb
        .deliver_editor_corrections(&context, storage.inputs(), &command, &mut runtime)
        .unwrap()
        .receipt;
    assert_eq!(
        product
            .execute(
                "DELETE FROM command_receipts WHERE scope_id = ?1 AND command_key = ?2",
                rusqlite::params![scope, KEY]
            )
            .unwrap(),
        1
    );
    assert!(wb
        .deliver_editor_corrections(&context, storage.inputs(), &command, &mut runtime)
        .is_err());
    assert!(wb
        .read_editor_corrections_evidence(&context, &command, &admission)
        .is_err());
    assert!(runtime
        .kernel()
        .store()
        .list_runs(&admission.instance_ref)
        .unwrap()
        .is_empty());
}

#[test]
fn derived_execution_requires_live_correction_input_and_current_actor() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, token) = reader(&mut wb);
    let storage = storage(&wb);
    let source = source(
        &mut wb,
        &context,
        &storage,
        &fixture.command,
        &fixture.admission,
        fixture.attempt(),
    );
    let command = admit(
        &mut wb,
        &context,
        &storage,
        &fixture.command,
        source.cause(),
    );
    let mut runtime = wb
        .open_editor_corrections_runtime(&context, &storage, &command)
        .unwrap();
    let admission = wb
        .deliver_editor_corrections(&context, storage.inputs(), &command, &mut runtime)
        .unwrap()
        .receipt;
    let pending = wb
        .advance_editor_corrections(
            &context,
            storage.inputs(),
            &command,
            &admission,
            &mut runtime,
        )
        .unwrap();
    ContentStore::open(dir.path().join("actions/inputs.sqlite"))
        .unwrap()
        .erase(
            &command.inputs["corrections"].version_ref,
            "erase unexecuted derived input",
        )
        .unwrap();
    assert!(wb
        .execute_editor_corrections_effect(
            &context,
            storage.inputs(),
            &command,
            &admission,
            &pending[0],
            &mut runtime
        )
        .is_err());
    assert!(runtime
        .kernel()
        .store()
        .list_runs(&admission.instance_ref)
        .unwrap()
        .is_empty());
    wb.read_editor_corrections_evidence(&context, &command, &admission)
        .unwrap();
    wb.revoke_account_session(&token);
    assert!(wb
        .read_editor_corrections_evidence(&context, &command, &admission)
        .is_err());
    assert!(wb
        .advance_editor_corrections(
            &context,
            storage.inputs(),
            &command,
            &admission,
            &mut runtime
        )
        .is_err());
}
