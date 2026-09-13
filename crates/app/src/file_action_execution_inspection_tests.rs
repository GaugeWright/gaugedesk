use super::tests::{forget, reader, save_fixture, saved};
use crate::file_action_factory::{tests::home_storage_fixture, NativeActionStorageConfig};
use crate::LockUnpoisoned;
use whipplescript_kernel::file_lease::FileLeasePolicy;
use whipplescript_store::{effect_recovery::ExternalDisposition, SqliteStore};

fn config() -> NativeActionStorageConfig {
    NativeActionStorageConfig {
        input_byte_limit: 4096,
        file_lease: FileLeasePolicy::new(17).unwrap(),
    }
}

#[test]
fn execution_observation_without_acknowledgment_preserves_the_evidence_gap_without_initialization()
{
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, storage, token) = home_storage_fixture(dir.path(), config());
    drop(storage);
    let mut wb = shared.lock_unpoisoned();
    let (context, reader_token) = reader(&mut wb);
    wb.revoke_account_session(&token);
    forget(&dir.path().join("actions/inputs.sqlite"));
    assert!(!dir.path().join("actions/native").exists());
    let scope = command.instance_ref().unwrap();
    let before = wb.store_ref().retained_events(&scope).unwrap();
    let observation = wb
        .observe_editor_file_save_execution(&context, &command)
        .unwrap();
    assert_eq!(observation.command(), &command);
    assert!(observation.runtime().is_none());
    assert_eq!(observation.observer(), "bob");
    assert!(!observation.restrictions().reader.is_empty());
    assert!(observation.restrictions().writer.is_empty());
    assert_eq!(wb.store_ref().retained_events(&scope).unwrap(), before);
    for name in [
        "inputs.sqlite",
        "native/runtime.sqlite",
        "native/coord.sqlite",
        "native/items.sqlite",
    ] {
        assert!(
            !dir.path().join("actions").join(name).exists(),
            "initialized {name}"
        );
    }
    assert!(!dir.path().join("actions/native").exists());
    let mut forged = command.clone();
    forged.provenance.initiator = "bob".into();
    forged.provenance.executor = "bob".into();
    assert!(wb
        .observe_editor_file_save_execution(&context, &forged)
        .is_err());
    wb.revoke_account_session(&reader_token);
    assert!(wb
        .observe_editor_file_save_execution(&context, &command)
        .is_err());
}

#[test]
fn execution_observation_recovers_a_lost_response_before_any_effect_without_driving_work() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, storage, token) = home_storage_fixture(dir.path(), config());
    let mut wb = shared.lock_unpoisoned();
    let original = wb.authenticate_action_context(&token).unwrap();
    let grant = wb
        .authorize_editor_file_save_dispatch(
            &original,
            storage.inputs(),
            &command,
            "inspect-pending",
        )
        .unwrap();
    let driver = wb
        .start_editor_file_save_driver(&storage, &command, &grant.grant_ref)
        .unwrap();
    drop(driver);
    drop(storage);
    let (context, _) = reader(&mut wb);
    wb.revoke_account_session(&token);
    forget(&dir.path().join("actions/inputs.sqlite"));
    let path = dir.path().join("actions/native/runtime.sqlite");
    let runtime = SqliteStore::open_read_only(&path).unwrap();
    let scope = command.instance_ref().unwrap();
    let before = runtime.list_events(&scope).unwrap();
    let first = wb
        .observe_editor_file_save_execution(&context, &command)
        .unwrap();
    let observed = first.runtime().unwrap();
    assert_eq!(observed.command, command);
    assert_eq!(
        observed.instance_status,
        gaugedesk_whip_runtime::host_actions::action_result::ActionInstanceStatus::Running
    );
    assert!(observed.terminal.is_none());
    assert!(observed.effects.is_empty());
    assert_eq!(first.observer(), "bob");
    assert_eq!(observed.command.provenance.initiator, "alice");
    assert_eq!(runtime.list_events(&scope).unwrap(), before);
    let repeated = wb
        .observe_editor_file_save_execution(&context, &command)
        .unwrap();
    assert_eq!(repeated.runtime(), first.runtime());
    assert_eq!(runtime.list_events(&scope).unwrap(), before);
    assert!(!dir.path().join("actions/inputs.sqlite").exists());
}

#[test]
fn execution_observation_reports_completed_and_unknown_history_without_reconciling() {
    for interrupted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = save_fixture(dir.path(), interrupted);
        let mut wb = fixture.shared.lock_unpoisoned();
        let (context, _) = reader(&mut wb);
        let scope = fixture.command.instance_ref().unwrap();
        let runtime =
            SqliteStore::open_read_only(dir.path().join("actions/native/runtime.sqlite")).unwrap();
        let before = runtime.list_events(&scope).unwrap();
        let product_before = wb.store_ref().retained_events(&scope).unwrap();
        let exact = wb
            .observe_editor_file_save(
                &context,
                &fixture.command,
                &fixture.admission,
                fixture.attempt(),
            )
            .unwrap();
        let observation = wb
            .observe_editor_file_save_execution(&context, &fixture.command)
            .unwrap();
        assert_eq!(observation.runtime(), Some(exact.evidence()));
        if interrupted {
            assert!(observation
                .runtime()
                .unwrap()
                .effects
                .iter()
                .flat_map(|e| &e.attempts)
                .any(|a| a.disposition == ExternalDisposition::Unknown));
            assert!(exact.saved().is_some());
        } else {
            assert!(observation.runtime().unwrap().terminal.is_some());
        }
        assert_eq!(runtime.list_events(&scope).unwrap(), before);
        assert_eq!(
            wb.store_ref().retained_events(&scope).unwrap(),
            product_before
        );
    }
}

#[test]
fn execution_observation_refuses_revocation_and_missing_acknowledged_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, token) = reader(&mut wb);
    wb.revoke_account_session(&token);
    assert!(wb
        .observe_editor_file_save_execution(&context, &fixture.command)
        .is_err());
    let (context, _) = reader(&mut wb);
    let runtime_path = dir.path().join("actions/native/runtime.sqlite");
    forget(&runtime_path);
    assert!(wb
        .observe_editor_file_save_execution(&context, &fixture.command)
        .is_err());
    assert!(!runtime_path.exists());
}

#[test]
fn execution_observation_refuses_an_acknowledgment_fact_without_its_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let scope = fixture.command.instance_ref().unwrap();
    let runtime =
        SqliteStore::open_read_only(dir.path().join("actions/native/runtime.sqlite")).unwrap();
    let before = runtime.list_events(&scope).unwrap();
    let sql = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    assert_eq!(
        sql.execute(
            "DELETE FROM command_receipts WHERE scope_id = ?1 AND command_key = 'admitted'",
            [format!("host-action-runtime-ack:{scope}")],
        )
        .unwrap(),
        1
    );
    assert!(wb
        .observe_editor_file_save_execution(&context, &fixture.command)
        .err()
        .unwrap()
        .contains("acknowledgment has no committed receipt"));
    assert_eq!(runtime.list_events(&scope).unwrap(), before);
}

#[test]
fn execution_observation_does_not_redeliver_after_runtime_admission_loses_its_acknowledgment() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, storage, token) = home_storage_fixture(dir.path(), config());
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let grant = wb
        .authorize_editor_file_save_dispatch(
            &context,
            storage.inputs(),
            &command,
            "lose-runtime-ack",
        )
        .unwrap();
    let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    fault.execute_batch("CREATE TRIGGER lose_execution_ack BEFORE INSERT ON events WHEN NEW.kind = 'host_action_runtime_admission_v1' BEGIN SELECT RAISE(ABORT, 'lost runtime acknowledgment'); END;").unwrap();
    assert!(wb
        .start_editor_file_save_driver(&storage, &command, &grant.grant_ref)
        .is_err());
    fault
        .execute_batch("DROP TRIGGER lose_execution_ack")
        .unwrap();
    let scope = command.instance_ref().unwrap();
    let runtime =
        SqliteStore::open_read_only(dir.path().join("actions/native/runtime.sqlite")).unwrap();
    let before = runtime.list_events(&scope).unwrap();
    assert!(!before.is_empty());
    let product_before = wb.store_ref().retained_events(&scope).unwrap();
    let observation = wb
        .observe_editor_file_save_execution(&context, &command)
        .unwrap();
    assert!(observation.runtime().is_none());
    assert_eq!(observation.command(), &command);
    assert_eq!(runtime.list_events(&scope).unwrap(), before);
    assert_eq!(
        wb.store_ref().retained_events(&scope).unwrap(),
        product_before
    );
    assert!(wb
        .store_ref()
        .committed_record_snapshot(&format!("host-action-runtime-ack:{scope}"), "admitted",)
        .unwrap()
        .is_none());
}

#[test]
fn execution_observation_checks_the_runtime_prefix_even_for_a_consistent_product_acknowledgment() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let scope = fixture.command.instance_ref().unwrap();
    let acknowledgment_scope = format!("host-action-runtime-ack:{scope}");
    let snapshot = wb
        .store_ref()
        .committed_record_snapshot(&acknowledgment_scope, "admitted")
        .unwrap()
        .unwrap();
    let mut acknowledgment: crate::host_action_delivery::RuntimeAcknowledgment =
        serde_json::from_str(&snapshot).unwrap();
    acknowledgment.receipt.admitted_at.head_digest =
        "syntactically-valid-but-not-the-runtime-prefix".into();
    acknowledgment
        .receipt
        .validate_for(&fixture.command)
        .unwrap();
    let forged = serde_json::to_string(&acknowledgment).unwrap();
    let sql = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    assert_eq!(sql.execute(
        "UPDATE commands SET snapshot_json = ?1 WHERE scope_id = ?2 AND idempotency_key = 'admitted'",
        [&forged, &acknowledgment_scope],
    ).unwrap(), 1);
    assert_eq!(sql.execute(
        "UPDATE events SET payload = ?1 WHERE scope_id = ?2 AND kind = 'host_action_runtime_admission_v1'",
        [&forged, &scope],
    ).unwrap(), 1);
    let delivery = wb
        .store_mut()
        .committed_dispatch::<gaugedesk_whip_runtime::host_actions::ProductActionAdmission>(
            &scope,
            &fixture.command.request_id,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        crate::host_action_delivery::retained_runtime_acknowledgment(wb.store_ref(), &delivery,)
            .unwrap(),
        Some(acknowledgment)
    );
    let runtime =
        SqliteStore::open_read_only(dir.path().join("actions/native/runtime.sqlite")).unwrap();
    let before = runtime.list_events(&scope).unwrap();
    assert!(wb
        .observe_editor_file_save_execution(&context, &fixture.command)
        .is_err());
    assert_eq!(runtime.list_events(&scope).unwrap(), before);
}
