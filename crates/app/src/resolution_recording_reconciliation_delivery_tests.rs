//! Recovery traverses the real Home outbox, runtime and retained target batch.
use super::*;
use crate::file_action_factory::CorrectionReconciliationAcknowledgment;

const ACK_KIND: &str = "native_correction_reconciliation_ack_v1";

#[test]
fn reconciliation_ownership_stays_with_its_actual_home() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded(dir.path(), &[""], true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let command = request(&mut wb, &context, &fixture);
    let mut owner = wb
        .claim_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &command,
        )
        .unwrap();
    let other = tempfile::tempdir().unwrap();
    let foreign = crate::open_workbench(other.path()).unwrap();
    let error = foreign
        .lock_unpoisoned()
        .deliver_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &command,
            &mut owner,
        )
        .unwrap_err();
    assert!(error.contains("different Home root"), "{error}");
    assert!(acknowledgments(&wb, &fixture).is_empty());
    // The refused cross-Home use did not consume or replace the actual owner.
    wb.deliver_editor_correction_reconciliation(
        &context,
        &fixture.command,
        &fixture.admission,
        &command,
        &mut owner,
    )
    .unwrap();
}

fn request(
    wb: &mut Workbench,
    context: &AuthenticatedActionContext,
    fixture: &Recorded,
) -> ReconcileEffectCommand {
    wb.admit_editor_correction_reconciliation(
        context,
        &fixture.command,
        &fixture.admission,
        &intent(fixture, "deliver-recovery"),
    )
    .unwrap()
    .command
}

fn observation(
    wb: &mut Workbench,
    context: &AuthenticatedActionContext,
    fixture: &Recorded,
) -> crate::file_action_factory::EditorCorrectionObservation {
    wb.inspect_editor_correction_attempt(
        context,
        &fixture.command,
        &fixture.admission,
        &fixture.effect,
        &fixture.run,
    )
    .unwrap()
}

fn acknowledgments(wb: &Workbench, fixture: &Recorded) -> Vec<String> {
    wb.store_ref()
        .records(&scope(&fixture.command, "deliver-recovery"), ACK_KIND)
        .unwrap()
}

#[test]
fn lost_reconciliation_acknowledgment_recovers_without_recording_or_advancing_again() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded(dir.path(), &[""], true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    wb.revoke_account_session(&fixture.author_token);
    read_only(&mut wb, &fixture.command);
    deny(&mut wb, Action::Run);
    let input_path = dir.path().join("actions/inputs.sqlite");
    ContentStore::open(&input_path)
        .unwrap()
        .erase(
            &fixture.command.inputs["corrections"].version_ref,
            "erase before reconciliation delivery",
        )
        .unwrap();
    forget_database(&input_path);
    let command = request(&mut wb, &context, &fixture);
    let before = observation(&mut wb, &context, &fixture);
    assert_eq!(
        before.evidence.effects[0].attempts[0].disposition,
        ExternalDisposition::Unknown
    );
    let mut owner = wb
        .claim_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &command,
        )
        .unwrap();
    assert_eq!(
        observation(&mut wb, &context, &fixture).evidence,
        before.evidence
    );
    let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    fault.execute_batch("CREATE TRIGGER lose_reconciliation_ack BEFORE INSERT ON events WHEN NEW.kind = 'native_correction_reconciliation_ack_v1' BEGIN SELECT RAISE(ABORT, 'lost reconciliation acknowledgment'); END;").unwrap();
    assert!(wb
        .deliver_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &command,
            &mut owner,
        )
        .is_err());
    assert!(acknowledgments(&wb, &fixture).is_empty());
    let applied = observation(&mut wb, &context, &fixture);
    assert_eq!(
        applied.evidence.effects[0].attempts[0].disposition,
        ExternalDisposition::Applied
    );
    assert_eq!(
        applied.evidence.instance_status,
        before.evidence.instance_status
    );
    assert_eq!(applied.evidence.terminal, before.evidence.terminal);
    assert_eq!(applied.binding, before.binding);
    assert_eq!(applied.receipt, before.receipt);
    assert_eq!(applied.binding.batch().actor, "alice");
    assert_eq!(applied.evidence.effects[0].attempts.len(), 1);
    assert_eq!(
        applied
            .evidence
            .evidence
            .iter()
            .filter(|event| event.kind == "effect.disposition.reconciled")
            .count(),
        1
    );
    fault
        .execute_batch("DROP TRIGGER lose_reconciliation_ack")
        .unwrap();
    drop(fault);
    drop(owner);
    drop(wb);
    let reopened = crate::open_workbench(dir.path()).unwrap();
    let mut wb = reopened.lock_unpoisoned();
    let token = wb.mint_account_session("bob", "passkey", 3600).unwrap();
    let context = wb.authenticate_action_context(&token).unwrap();
    let mut owner = wb
        .claim_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &command,
        )
        .unwrap();
    let ack = wb
        .deliver_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &command,
            &mut owner,
        )
        .unwrap();
    let repeated = wb
        .deliver_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &command,
            &mut owner,
        )
        .unwrap();
    assert_eq!(ack, repeated);
    assert_eq!(ack.receipt.fingerprint, command.fingerprint().unwrap());
    assert_eq!(ack.receipt.request_key, command.request_key().unwrap());
    assert_eq!(ack.receipt.recorded_at, applied.evidence.observed_at);
    assert_eq!(ack.runtime_ref, format!("{}:native", wb.home_id()));
    let records = acknowledgments(&wb, &fixture);
    assert_eq!(records.len(), 1);
    assert_eq!(
        serde_json::from_str::<CorrectionReconciliationAcknowledgment>(&records[0]).unwrap(),
        ack
    );
    assert_eq!(
        observation(&mut wb, &context, &fixture).evidence,
        applied.evidence
    );
    assert!(!input_path.exists());
}

#[test]
fn superseded_reconciliation_owner_refuses_before_target_evidence_reads() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded(dir.path(), &[""], true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let command = request(&mut wb, &context, &fixture);
    let mut first = wb
        .claim_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &command,
        )
        .unwrap();
    let _second = wb
        .claim_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &command,
        )
        .unwrap();
    let mut branches = vec![];
    named_files(dir.path(), "branches.sqlite", &mut branches);
    assert!(!branches.is_empty());
    for path in branches {
        forget_database(&path);
    }
    let error = wb
        .deliver_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &command,
            &mut first,
        )
        .unwrap_err();
    assert!(
        error.contains("ownership is stale or mismatched"),
        "{error}"
    );
    assert!(acknowledgments(&wb, &fixture).is_empty());
    let evidence = wb
        .read_editor_corrections_evidence(&context, &fixture.command, &fixture.admission)
        .unwrap();
    assert_eq!(
        evidence.effects[0].attempts[0].disposition,
        ExternalDisposition::Unknown
    );
}

#[test]
fn reconciliation_delivery_rechecks_current_actor_and_original_outbox() {
    for fault_kind in ["partial-outbox", "absent-admission", "revoked-session"] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = recorded(dir.path(), &[""], true);
        let mut wb = fixture.shared.lock_unpoisoned();
        let (context, token) = reader(&mut wb);
        let command = request(&mut wb, &context, &fixture);
        let mut owner = wb
            .claim_editor_correction_reconciliation(
                &context,
                &fixture.command,
                &fixture.admission,
                &command,
            )
            .unwrap();
        let runtime_path = dir.path().join("actions/native/runtime.sqlite");
        let before = std::fs::read(&runtime_path).unwrap();
        if fault_kind == "revoked-session" {
            wb.revoke_account_session(&token);
        } else {
            let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
            assert_eq!(fault.execute("DELETE FROM events WHERE scope_id = ?1 AND kind = 'runtime_command_dispatch_v1'", [scope(&fixture.command, "deliver-recovery")]).unwrap(), 1);
            if fault_kind == "absent-admission" {
                let scope = scope(&fixture.command, "deliver-recovery");
                // Model loss of the complete admission, retaining its separately
                // scoped policy. A caller-held command cannot reconstruct it.
                for table in ["command_receipts", "commands", "events"] {
                    assert!(
                        fault
                            .execute(
                                &format!("DELETE FROM {table} WHERE scope_id = ?1"),
                                [&scope]
                            )
                            .unwrap()
                            > 0
                    );
                }
            }
        }
        assert!(wb
            .deliver_editor_correction_reconciliation(
                &context,
                &fixture.command,
                &fixture.admission,
                &command,
                &mut owner,
            )
            .is_err());
        assert!(wb
            .claim_editor_correction_reconciliation(
                &context,
                &fixture.command,
                &fixture.admission,
                &command,
            )
            .is_err());
        assert_eq!(std::fs::read(&runtime_path).unwrap(), before);
        assert!(acknowledgments(&wb, &fixture).is_empty());
    }
}

#[test]
fn missing_original_runtime_does_not_create_a_reconciliation_history() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded(dir.path(), &[""], true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let command = request(&mut wb, &context, &fixture);
    let runtime_path = dir.path().join("actions/native/runtime.sqlite");
    forget_database(&runtime_path);
    for name in ["coord.sqlite", "items.sqlite"] {
        forget_database(&dir.path().join("actions/native").join(name));
    }
    assert!(wb
        .claim_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &command,
        )
        .is_err());
    for name in ["runtime.sqlite", "coord.sqlite", "items.sqlite"] {
        assert!(!dir.path().join("actions/native").join(name).exists());
    }
    assert!(acknowledgments(&wb, &fixture).is_empty());
}

#[test]
fn missing_target_receipt_after_intent_cannot_publish_applied() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded(dir.path(), &[""], true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let command = request(&mut wb, &context, &fixture);
    let mut owner = wb
        .claim_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &command,
        )
        .unwrap();
    let mut branches = vec![];
    named_files(dir.path(), "branches.sqlite", &mut branches);
    let removed: usize = branches
        .into_iter()
        .map(|path| {
            rusqlite::Connection::open(path)
                .unwrap()
                .execute(
                    "DELETE FROM resolution_batches WHERE operation_id = ?1",
                    [&fixture.original.batch().operation_id],
                )
                .unwrap()
        })
        .sum();
    assert_eq!(removed, 1);
    assert!(wb
        .deliver_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &command,
            &mut owner,
        )
        .is_err());
    assert!(acknowledgments(&wb, &fixture).is_empty());
    let observed = observation(&mut wb, &context, &fixture);
    assert!(observed.receipt.is_none());
    assert_eq!(
        observed.evidence.effects[0].attempts[0].disposition,
        ExternalDisposition::Unknown
    );
    assert!(!observed
        .evidence
        .evidence
        .iter()
        .any(|event| event.kind == "effect.disposition.reconciled"));
}

#[path = "resolution_recording_result_tests.rs"]
mod result;
