//! Real Home intent admission is distinct from observing or publishing a result.
use super::*;
use crate::file_action_factory::EditorCorrectionReconciliation;
use gaugedesk_core::host_action_admission::HostActionAdmission;
use gaugedesk_whip_runtime::host_actions::recovery::ReconcileEffectCommand;
use sha2::{Digest, Sha256};

type Admission = HostActionAdmission<ReconcileEffectCommand>;

fn scope(original: &HostActionCommand, request: &str) -> String {
    serde_json::to_string(&(
        "gaugedesk.editor-corrections.reconcile.v1",
        original.instance_ref().unwrap(),
        &original.issuer,
        &original.scope,
        request,
    ))
    .unwrap()
}

fn intent<'a>(fixture: &'a Recorded, request: &'a str) -> EditorCorrectionReconciliation<'a> {
    EditorCorrectionReconciliation {
        request_id: request,
        effect_id: &fixture.effect,
        run_id: &fixture.run,
    }
}

#[test]
fn current_investigator_admits_an_exact_recoverable_intent_without_publishing_a_disposition() {
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
            "erase original correction",
        )
        .unwrap();
    forget_database(&input_path);
    let before = wb
        .inspect_editor_correction_attempt(
            &context,
            &fixture.command,
            &fixture.admission,
            &fixture.effect,
            &fixture.run,
        )
        .unwrap();
    let runtime_path = dir.path().join("actions/native/runtime.sqlite");
    let runtime_bytes = std::fs::read(&runtime_path).unwrap();
    let admitted = wb
        .admit_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &intent(&fixture, "investigate"),
        )
        .unwrap();
    assert!(!admitted.replayed);
    let command = &admitted.command;
    assert_eq!(command.provenance.initiator, "bob");
    assert_eq!(command.provenance.executor, "bob");
    assert_eq!(command.provenance.origin, "editor.corrections.reconcile");
    assert!(command.provenance.delegation.is_empty());
    assert_eq!(command.provenance.causes.len(), 1);
    let cause = &command.provenance.causes[0];
    assert_eq!(cause.authority, fixture.command.issuer);
    assert_eq!(cause.digest, fixture.admission.admitted_at.head_digest);
    assert_eq!(
        cause.record_ref,
        serde_json::to_string(&(
            &fixture.admission.instance_ref,
            fixture.admission.admitted_at.sequence,
        ))
        .unwrap()
    );
    assert_ne!(command.policy, fixture.command.policy);
    assert_eq!(
        command.evidence.frame,
        before.evidence.effects[0].attempts[0]
            .dispatch
            .as_ref()
            .unwrap()
            .frame
    );
    assert_eq!(
        command.evidence.evidence_ref,
        fixture.command.resources["resolutions"].resource.handle
    );
    assert_eq!(
        command.evidence_label_ref,
        fixture.command.resources["resolutions"].label_ref
    );
    assert_eq!(
        command.evidence.evidence_digest,
        hex::encode(Sha256::digest(
            before
                .receipt
                .as_ref()
                .unwrap()
                .encode()
                .unwrap()
                .0
                .as_bytes(),
        ))
    );
    let command_scope = scope(&fixture.command, "investigate");
    let dispatch = wb
        .store_mut()
        .committed_dispatch::<Admission>(&command_scope, "investigate")
        .unwrap()
        .unwrap();
    assert_eq!(dispatch.command, *command);
    assert_eq!(
        dispatch.dispatch.runtime_ref,
        format!("{}:native", wb.home_id())
    );
    assert_eq!(
        dispatch.dispatch.command_ref,
        hex::encode(Sha256::digest(command.signing_bytes().unwrap()))
    );
    assert_eq!(std::fs::read(&runtime_path).unwrap(), runtime_bytes);
    assert!(!input_path.exists());
    let after = wb
        .inspect_editor_correction_attempt(
            &context,
            &fixture.command,
            &fixture.admission,
            &fixture.effect,
            &fixture.run,
        )
        .unwrap();
    assert_eq!(after.evidence, before.evidence);
    assert_eq!(after.binding, before.binding);
    assert_eq!(after.receipt, before.receipt);
    assert_eq!(after.binding.batch().actor, "alice");
    assert_eq!(
        after.evidence.effects[0].attempts[0].disposition,
        ExternalDisposition::Unknown
    );
    assert!(after.evidence.terminal.is_none());
    drop(wb);
    let reopened = crate::open_workbench(dir.path()).unwrap();
    let mut wb = reopened.lock_unpoisoned();
    let token = wb.mint_account_session("bob", "passkey", 3600).unwrap();
    let context = wb.authenticate_action_context(&token).unwrap();
    let replay = wb
        .admit_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &intent(&fixture, "investigate"),
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.command, admitted.command);
    assert_eq!(
        wb.store_ref()
            .records(&command_scope, Admission::KIND)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        wb.store_ref()
            .records(
                &command_scope,
                gaugedesk_store::command_dispatch::DISPATCH_KIND
            )
            .unwrap()
            .len(),
        1
    );
    assert_eq!(std::fs::read(&runtime_path).unwrap(), runtime_bytes);
    wb.revoke_account_session(&token);
    assert!(wb
        .admit_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &intent(&fixture, "investigate"),
        )
        .is_err());
}

#[test]
fn correction_reconciliation_admission_rolls_back_when_its_outbox_cannot_commit() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded(dir.path(), &[""], true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    fault.execute_batch("CREATE TRIGGER lose_reconciliation_outbox BEFORE INSERT ON events WHEN NEW.kind = 'runtime_command_dispatch_v1' BEGIN SELECT RAISE(ABORT, 'lost reconciliation outbox'); END;").unwrap();
    let command_scope = scope(&fixture.command, "recover-after-failure");
    assert!(wb
        .admit_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &intent(&fixture, "recover-after-failure"),
        )
        .is_err());
    assert!(wb
        .store_ref()
        .records(&command_scope, Admission::KIND)
        .unwrap()
        .is_empty());
    assert!(wb
        .store_mut()
        .committed_dispatch::<Admission>(&command_scope, "recover-after-failure")
        .unwrap()
        .is_none());
    fault
        .execute_batch("DROP TRIGGER lose_reconciliation_outbox")
        .unwrap();
    let admitted = wb
        .admit_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &intent(&fixture, "recover-after-failure"),
        )
        .unwrap();
    assert!(!admitted.replayed);
    let replay = wb
        .admit_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &intent(&fixture, "recover-after-failure"),
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.command, admitted.command);
}

#[test]
fn missing_correction_receipt_cannot_become_an_applied_reconciliation_intent() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded(dir.path(), &[""], true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
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
    let command_scope = scope(&fixture.command, "missing-evidence");
    assert!(wb
        .admit_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &intent(&fixture, "missing-evidence"),
        )
        .unwrap_err()
        .contains("outcome remains unknown"));
    assert!(wb
        .store_ref()
        .records(&command_scope, Admission::KIND)
        .unwrap()
        .is_empty());
    assert!(wb
        .store_mut()
        .committed_dispatch::<Admission>(&command_scope, "missing-evidence")
        .unwrap()
        .is_none());
    let observed = wb
        .read_editor_corrections_evidence(&context, &fixture.command, &fixture.admission)
        .unwrap();
    assert_eq!(
        observed.effects[0].attempts[0].disposition,
        ExternalDisposition::Unknown
    );
}

#[test]
fn a_spent_reconciliation_identity_cannot_replace_its_original_investigator() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded(dir.path(), &[""], true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (bob, _) = reader(&mut wb);
    let first = wb
        .admit_editor_correction_reconciliation(
            &bob,
            &fixture.command,
            &fixture.admission,
            &intent(&fixture, "one-request"),
        )
        .unwrap();
    membership(&mut wb, "charlie", "owner");
    let token = wb.mint_account_session("charlie", "passkey", 3600).unwrap();
    let charlie = wb.authenticate_action_context(&token).unwrap();
    // Charlie is a valid current investigator of the same original evidence.
    wb.inspect_editor_correction_attempt(
        &charlie,
        &fixture.command,
        &fixture.admission,
        &fixture.effect,
        &fixture.run,
    )
    .unwrap();
    assert!(wb
        .admit_editor_correction_reconciliation(
            &charlie,
            &fixture.command,
            &fixture.admission,
            &intent(&fixture, "one-request"),
        )
        .is_err());
    let retained = wb
        .store_mut()
        .committed_dispatch::<Admission>(&scope(&fixture.command, "one-request"), "one-request")
        .unwrap()
        .unwrap();
    assert_eq!(retained.command, first.command);
    let distinct = wb
        .admit_editor_correction_reconciliation(
            &charlie,
            &fixture.command,
            &fixture.admission,
            &intent(&fixture, "charlie-request"),
        )
        .unwrap();
    assert_eq!(distinct.command.provenance.executor, "charlie");
}

#[test]
fn correction_reconciliation_refuses_authority_changed_after_its_read_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded(dir.path(), &[""], true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let (chat, _) = coordinates(&fixture.command);
    let library = crate::library::Library::rebuild(wb.store_ref()).unwrap();
    let id = &library.current_target_set(&chat).unwrap().members[0].target_id;
    let mut target = library.work_targets[id].clone();
    target.capabilities.read = false;
    let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    fault
        .execute_batch(
            "CREATE TABLE reconciliation_authority_fault(scope_id TEXT, kind TEXT, payload TEXT);",
        )
        .unwrap();
    fault
        .execute(
            "INSERT INTO reconciliation_authority_fault VALUES (?1, ?2, ?3)",
            rusqlite::params![
                LIBRARY_SCOPE,
                "work_target",
                serde_json::to_string(&target).unwrap()
            ],
        )
        .unwrap();
    // Policy retention is between the factory's final authority read and its
    // product admission. Commit a real revocation at exactly that boundary.
    fault.execute_batch("CREATE TRIGGER revoke_during_reconciliation_preparation AFTER INSERT ON events WHEN NEW.kind = 'host_action_policy_v1' BEGIN INSERT INTO events(scope_id, position, kind, payload) SELECT staged.scope_id, COALESCE((SELECT MAX(position) FROM events WHERE scope_id = staged.scope_id), -1) + 1, staged.kind, staged.payload FROM reconciliation_authority_fault AS staged; END;").unwrap();
    let error = wb
        .admit_editor_correction_reconciliation(
            &context,
            &fixture.command,
            &fixture.admission,
            &intent(&fixture, "stale-preparation"),
        )
        .unwrap_err();
    assert!(
        error.contains("dispatch authorization changed during preparation"),
        "{error}"
    );
    let command_scope = scope(&fixture.command, "stale-preparation");
    assert!(wb
        .store_ref()
        .records(&command_scope, Admission::KIND)
        .unwrap()
        .is_empty());
    assert!(wb
        .store_mut()
        .committed_dispatch::<Admission>(&command_scope, "stale-preparation")
        .unwrap()
        .is_none());
    assert!(
        !crate::library::Library::rebuild(wb.store_ref())
            .unwrap()
            .work_targets[id]
            .capabilities
            .read
    );
}

#[path = "resolution_recording_reconciliation_delivery_tests.rs"]
mod delivery;
