//! Product admission and read-only retrieval of the owner's historical batch.
use super::*;
use crate::file_action_factory::{EditorCorrectionResultRequest, NativeEditorCorrectionResult};

fn result_request() -> EditorCorrectionResultRequest<'static> {
    EditorCorrectionResultRequest {
        request_id: "recorded-result",
        reconciliation_request_id: "deliver-recovery",
    }
}

fn reconcile(wb: &mut Workbench, context: &AuthenticatedActionContext, fixture: &Recorded) {
    let command = request(wb, context, fixture);
    let mut owner = wb
        .claim_editor_correction_reconciliation(
            context,
            &fixture.command,
            &fixture.admission,
            &command,
        )
        .unwrap();
    wb.deliver_editor_correction_reconciliation(
        context,
        &fixture.command,
        &fixture.admission,
        &command,
        &mut owner,
    )
    .unwrap();
}

fn admit_result(
    wb: &mut Workbench,
    context: &AuthenticatedActionContext,
    fixture: &Recorded,
) -> NativeEditorCorrectionResult {
    wb.admit_editor_correction_result(
        context,
        &fixture.command,
        &fixture.admission,
        &result_request(),
    )
    .unwrap()
    .result
}

fn read_result(
    wb: &mut Workbench,
    context: &AuthenticatedActionContext,
    fixture: &Recorded,
) -> NativeEditorCorrectionResult {
    wb.read_editor_correction_result(
        context,
        &fixture.command,
        &fixture.admission,
        "recorded-result",
    )
    .unwrap()
    .unwrap()
}

#[test]
fn correction_result_preserves_original_outcomes_under_an_independent_admitting_reader() {
    let dir = tempfile::tempdir().unwrap();
    let corrections = ResolutionRecordingInput::new(vec![
        RegionResolution {
            base_text: "base".into(),
            ours_text: "ours".into(),
            theirs_text: "theirs".into(),
            resolution_text: "".into(),
        },
        RegionResolution {
            base_text: "base".into(),
            ours_text: "ours".into(),
            theirs_text: "theirs".into(),
            resolution_text: "ignored later choice".into(),
        },
    ])
    .unwrap();
    let fixture = recorded_input(dir.path(), &[""], true, &corrections, false);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (bob, bob_token) = reader(&mut wb);
    reconcile(&mut wb, &bob, &fixture);
    let before = observation(&mut wb, &bob, &fixture);
    wb.revoke_account_session(&fixture.author_token);
    wb.revoke_account_session(&bob_token);
    membership(&mut wb, "charlie", "owner");
    let token = wb.mint_account_session("charlie", "passkey", 3600).unwrap();
    let charlie = wb.authenticate_action_context(&token).unwrap();
    read_only(&mut wb, &fixture.command);
    deny(&mut wb, Action::Run);
    let inputs = dir.path().join("actions/inputs.sqlite");
    ContentStore::open(&inputs)
        .unwrap()
        .erase(
            &fixture.command.inputs["corrections"].version_ref,
            "erase input before result",
        )
        .unwrap();
    forget_database(&inputs);
    let result = admit_result(&mut wb, &charlie, &fixture);
    assert_eq!(result.recording, before.receipt.unwrap());
    assert_eq!(result.recording.request.actor, "alice");
    // The owner retains both merge orientations for each submitted region.
    assert_eq!(result.recording.outcomes.len(), 4);
    assert_eq!(
        result
            .recording
            .outcomes
            .iter()
            .map(|outcome| outcome.inserted)
            .collect::<Vec<_>>(),
        [true, true, false, false]
    );
    assert!(result
        .recording
        .outcomes
        .iter()
        .all(|outcome| outcome.resolution == result.recording.outcomes[0].resolution));
    assert_ne!(
        result.recording.request.entries[2].resolution,
        result.recording.outcomes[2].resolution
    );
    assert_eq!(result.reconciliation.provenance.initiator, "bob");
    assert_eq!(result.provenance.initiator, "charlie");
    assert_eq!(result.provenance.causes.len(), 2);
    assert_eq!(result.observed_at, before.evidence.observed_at);
    let replay = wb
        .admit_editor_correction_result(
            &charlie,
            &fixture.command,
            &fixture.admission,
            &result_request(),
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.result, result);
    let after = observation(&mut wb, &charlie, &fixture).evidence;
    assert_eq!(after.observed_at, before.evidence.observed_at);
    assert_eq!(after.effects, before.evidence.effects);
    assert_eq!(after.terminal, before.evidence.terminal);
    assert_eq!(after.instance_status, before.evidence.instance_status);
    assert_ne!(after.read_policy, before.evidence.read_policy);
    assert_eq!(after.read_policy, result.policy);
    assert!(!inputs.exists());
    drop(wb);
    let reopened = crate::open_workbench(dir.path()).unwrap();
    let mut wb = reopened.lock_unpoisoned();
    let token = wb.mint_account_session("charlie", "passkey", 3600).unwrap();
    let charlie = wb.authenticate_action_context(&token).unwrap();
    assert_eq!(read_result(&mut wb, &charlie, &fixture), result);
}

#[test]
fn correction_result_commit_failure_retries_without_reconciling_or_recording_again() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded(dir.path(), &[""], true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    reconcile(&mut wb, &context, &fixture);
    let before = observation(&mut wb, &context, &fixture);
    let runtime_path = dir.path().join("actions/native/runtime.sqlite");
    let runtime_bytes = std::fs::read(&runtime_path).unwrap();
    let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    fault.execute_batch("CREATE TRIGGER lose_correction_result BEFORE INSERT ON events WHEN NEW.kind = 'native_correction_result_v1' BEGIN SELECT RAISE(ABORT, 'lost correction product result'); END;").unwrap();
    assert!(wb
        .admit_editor_correction_result(
            &context,
            &fixture.command,
            &fixture.admission,
            &result_request()
        )
        .is_err());
    assert!(wb
        .read_editor_correction_result(
            &context,
            &fixture.command,
            &fixture.admission,
            "recorded-result"
        )
        .unwrap()
        .is_none());
    assert_eq!(std::fs::read(&runtime_path).unwrap(), runtime_bytes);
    fault
        .execute_batch("DROP TRIGGER lose_correction_result")
        .unwrap();
    let result = admit_result(&mut wb, &context, &fixture);
    assert_eq!(result.recording, before.receipt.unwrap());
    assert_eq!(
        observation(&mut wb, &context, &fixture).evidence,
        before.evidence
    );
    assert_eq!(std::fs::read(&runtime_path).unwrap(), runtime_bytes);
    let changed = EditorCorrectionResultRequest {
        request_id: "recorded-result",
        reconciliation_request_id: "another-reconciliation",
    };
    assert!(wb
        .admit_editor_correction_result(&context, &fixture.command, &fixture.admission, &changed)
        .is_err());
}

#[test]
fn correction_result_requires_actual_reconciliation_and_target_evidence() {
    for missing in ["reconciliation", "ack", "target"] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = recorded(dir.path(), &[""], true);
        let mut wb = fixture.shared.lock_unpoisoned();
        let (context, _) = reader(&mut wb);
        let mut foreign = fixture.admission.clone();
        foreign.instance_ref.push_str("-foreign");
        assert!(wb
            .read_editor_correction_result(&context, &fixture.command, &foreign, "recorded-result")
            .is_err());
        if missing == "reconciliation" {
            request(&mut wb, &context, &fixture);
        } else {
            reconcile(&mut wb, &context, &fixture);
        }
        if missing == "ack" {
            let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
            assert_eq!(fault.execute("DELETE FROM events WHERE scope_id = ?1 AND kind = 'native_correction_reconciliation_ack_v1'", [scope(&fixture.command, "deliver-recovery")]).unwrap(), 1);
        } else if missing == "target" {
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
        }
        assert!(
            wb.admit_editor_correction_result(
                &context,
                &fixture.command,
                &fixture.admission,
                &result_request()
            )
            .is_err(),
            "{missing}"
        );
        assert!(wb
            .read_editor_correction_result(
                &context,
                &fixture.command,
                &fixture.admission,
                "recorded-result"
            )
            .unwrap()
            .is_none());
    }
}

#[test]
fn correction_result_reads_are_current_authorized_metadata_without_runtime_initialization() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded(dir.path(), &[""], true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, token) = reader(&mut wb);
    reconcile(&mut wb, &context, &fixture);
    let result = admit_result(&mut wb, &context, &fixture);
    wb.revoke_account_session(&token);
    assert!(wb
        .read_editor_correction_result(
            &context,
            &fixture.command,
            &fixture.admission,
            "recorded-result"
        )
        .is_err());
    membership(&mut wb, "charlie", "owner");
    let token = wb.mint_account_session("charlie", "passkey", 3600).unwrap();
    let charlie = wb.authenticate_action_context(&token).unwrap();
    let mut removed = vec![];
    for name in [
        "runtime.sqlite",
        "inputs.sqlite",
        "coord.sqlite",
        "items.sqlite",
        "branches.sqlite",
        "content.sqlite",
    ] {
        named_files(dir.path(), name, &mut removed);
    }
    for path in &removed {
        forget_database(path);
    }
    let product_bytes = std::fs::read(wb.store_ref().path()).unwrap();
    assert_eq!(read_result(&mut wb, &charlie, &fixture), result);
    assert_eq!(std::fs::read(wb.store_ref().path()).unwrap(), product_bytes);
    assert!(removed.iter().all(|path| !path.exists()));
    assert!(wb
        .admit_editor_correction_result(
            &charlie,
            &fixture.command,
            &fixture.admission,
            &result_request()
        )
        .is_err());
    assert_eq!(result.provenance.initiator, "bob");
    let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    assert_eq!(fault.execute("DELETE FROM command_receipts WHERE scope_id IN (SELECT scope_id FROM events WHERE kind = 'native_correction_result_v1')", []).unwrap(), 1);
    let error = wb
        .read_editor_correction_result(
            &charlie,
            &fixture.command,
            &fixture.admission,
            "recorded-result",
        )
        .unwrap_err();
    assert!(error.contains("no committed receipt"), "{error}");
}

#[test]
fn correction_results_retain_investigation_restrictions_after_target_policy_relaxes() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded_input(dir.path(), &[""], true, &input(""), true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let (chat, _) = coordinates(&fixture.command);
    recording_classification(
        &mut wb,
        &chat,
        gaugedesk_core::abac::Classification::Regulated,
    );
    reconcile(&mut wb, &context, &fixture);
    let result = admit_result(&mut wb, &context, &fixture);
    recording_classification(&mut wb, &chat, gaugedesk_core::abac::Classification::Public);
    membership(&mut wb, "charlie", "viewer");
    let (_, project, _, _): (String, String, String, String) =
        serde_json::from_str(&fixture.command.scope).unwrap();
    let grant = crate::org::MemberGrantRecord {
        id: crate::org::MemberGrantRecord::make_id("charlie", &project),
        op: crate::org::RecordOp::Upsert,
        authority: "charlie".into(),
        project_id: project,
    };
    wb.store_mut()
        .append_record(
            ORG_SCOPE,
            "member_grant",
            &serde_json::to_string(&grant).unwrap(),
        )
        .unwrap();
    let token = wb.mint_account_session("charlie", "passkey", 3600).unwrap();
    let charlie = wb.authenticate_action_context(&token).unwrap();
    // Today's target and original action are public and independently readable.
    observation(&mut wb, &charlie, &fixture);
    let error = wb
        .read_editor_correction_result(
            &charlie,
            &fixture.command,
            &fixture.admission,
            "recorded-result",
        )
        .unwrap_err();
    assert!(
        error.contains("retained correction result restrictions"),
        "{error}"
    );
    let new = EditorCorrectionResultRequest {
        request_id: "new-result",
        reconciliation_request_id: "deliver-recovery",
    };
    let error = wb
        .admit_editor_correction_result(&charlie, &fixture.command, &fixture.admission, &new)
        .err()
        .unwrap();
    assert!(
        error.contains("retained correction result restrictions"),
        "{error}"
    );
    assert_eq!(read_result(&mut wb, &context, &fixture), result);
}

#[test]
fn correction_result_refuses_a_later_dispute_of_the_acknowledged_attempt() {
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
    wb.deliver_editor_correction_reconciliation(
        &context,
        &fixture.command,
        &fixture.admission,
        &command,
        &mut owner,
    )
    .unwrap();
    drop(owner);
    let mut contrary = command.evidence;
    contrary.disposition = whipplescript_store::effect_recovery::EvidenceDisposition::NotApplied;
    contrary.evidence_digest = "contradictory fixture evidence".into();
    let store =
        whipplescript_store::SqliteStore::open(dir.path().join("actions/native/runtime.sqlite"))
            .unwrap();
    store
        .append_event(whipplescript_store::NewEvent {
            instance_id: &fixture.admission.instance_ref,
            event_type: "effect.disposition.recorded",
            payload_json: &serde_json::to_string(&contrary).unwrap(),
            source: "kernel",
            causation_id: Some(&fixture.run),
            correlation_id: None,
            idempotency_key: Some("contrary correction fixture"),
        })
        .unwrap();
    let error = wb
        .admit_editor_correction_result(
            &context,
            &fixture.command,
            &fixture.admission,
            &result_request(),
        )
        .err()
        .unwrap();
    assert!(error.contains("undisputed Applied"), "{error}");
    assert!(wb
        .read_editor_correction_result(
            &context,
            &fixture.command,
            &fixture.admission,
            "recorded-result"
        )
        .unwrap()
        .is_none());
}
