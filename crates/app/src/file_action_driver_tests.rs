use super::*;
use crate::{file_action_factory::tests::home_storage_fixture, LockUnpoisoned};
use gaugedesk_whip_runtime::host_actions::{action_result::ActionWorkflowStatus, RuntimeStore};
use whipplescript_kernel::file_lease::FileLeasePolicy;
use whipplescript_store::content::{ContentBlobs, ContentStore};

fn config() -> NativeActionStorageConfig {
    NativeActionStorageConfig {
        input_byte_limit: 4096,
        file_lease: FileLeasePolicy::new(17).unwrap(),
    }
}

fn start(
    wb: &mut Workbench,
    storage: &NativeActionStorage,
    command: &HostActionCommand,
    token: &str,
) -> (String, NativeEditorSaveDriver) {
    let context = wb.authenticate_action_context(token).unwrap();
    let grant = wb
        .authorize_editor_file_save_dispatch(&context, storage.inputs(), command, "driver-1")
        .unwrap();
    let driver = wb
        .start_editor_file_save_driver(storage, command, &grant.grant_ref)
        .unwrap();
    (grant.grant_ref, driver)
}

fn step(wb: &mut Workbench, storage: &NativeActionStorage, driver: &mut NativeEditorSaveDriver) {
    assert!(matches!(
        wb.step_editor_file_save_driver(storage, driver).unwrap(),
        NativeEditorSaveProgress::Advanced
    ));
}

fn saved(
    wb: &mut Workbench,
    storage: &NativeActionStorage,
    driver: &mut NativeEditorSaveDriver,
) -> AdmittedEditorSavedResult {
    match wb.step_editor_file_save_driver(storage, driver).unwrap() {
        NativeEditorSaveProgress::Saved(result) => *result,
        NativeEditorSaveProgress::Unresolved(snapshot) => {
            panic!("unexpected unresolved save: {snapshot:?}")
        }
        NativeEditorSaveProgress::Advanced => panic!("unexpected extra step"),
    }
}

fn snapshot(
    wb: &mut Workbench,
    storage: &NativeActionStorage,
    driver: &NativeEditorSaveDriver,
) -> ActionResultSnapshot {
    wb.read_editor_file_save_result(
        &driver.authority.context,
        storage.inputs(),
        &driver.command,
        &driver.owner.admission,
        driver.owner.runtime(),
    )
    .unwrap()
}

fn events(driver: &NativeEditorSaveDriver) -> Vec<whipplescript_store::EventView> {
    driver
        .owner
        .runtime()
        .kernel()
        .store()
        .list_events(&driver.owner.admission.instance_ref)
        .unwrap()
}

#[test]
fn native_driver_completes_once_and_reopens_after_input_erasure() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, storage, token) = home_storage_fixture(dir.path(), config());
    let mut wb = shared.lock_unpoisoned();
    let (grant, mut driver) = start(&mut wb, &storage, &command, &token);
    step(&mut wb, &storage, &mut driver);
    step(&mut wb, &storage, &mut driver);
    let result = saved(&mut wb, &storage, &mut driver);
    assert!(!result.replayed);
    let observed = snapshot(&mut wb, &storage, &driver);
    assert_eq!(
        observed.terminal.unwrap().status,
        ActionWorkflowStatus::Completed
    );
    assert_eq!(observed.effects.len(), 2);
    assert!(observed
        .effects
        .iter()
        .all(|effect| effect.attempts.len() == 1));
    assert_eq!(
        result.result.content_hash,
        whipplescript_store::stable_hash_hex("private editor draft")
    );
    assert_eq!(
        result.result.provenance.causes.len(),
        command.provenance.causes.len() + 3
    );
    let before = events(&driver);
    let replay = saved(&mut wb, &storage, &mut driver);
    assert!(replay.replayed);
    assert_eq!(result.result, replay.result);
    assert_eq!(events(&driver), before);
    let (_, _, chat): (String, String, String) = serde_json::from_str(&command.scope).unwrap();
    let path = wb.engagement_workspace_path(&chat, "note.txt");
    assert_eq!(
        wb.engagements[&chat].read_file(&path).unwrap(),
        "recorded base"
    );
    ContentStore::open(dir.path().join("actions/inputs.sqlite"))
        .unwrap()
        .erase(
            &command.inputs["content"].version_ref,
            "erase fixture input",
        )
        .unwrap();
    drop(driver);
    drop(wb);
    drop(storage);
    drop(shared);
    let shared = crate::open_workbench(dir.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let storage = wb.open_native_action_storage(config()).unwrap();
    assert!(storage
        .inputs()
        .resolve(&command.inputs["content"])
        .is_err());
    let mut driver = wb
        .start_editor_file_save_driver(&storage, &command, &grant)
        .unwrap();
    let replay = saved(&mut wb, &storage, &mut driver);
    assert!(replay.replayed);
    assert_eq!(replay.result, result.result);
    assert_eq!(events(&driver), before);
    let replacement = wb
        .start_editor_file_save_driver(&storage, &command, &grant)
        .unwrap();
    let old_snapshot = snapshot(&mut wb, &storage, &driver);
    let write = old_snapshot
        .effects
        .iter()
        .find(|effect| {
            effect.attempts[0]
                .dispatch
                .as_ref()
                .is_some_and(|dispatch| dispatch.frame.kind == "file.write")
        })
        .unwrap();
    assert!(wb
        .admit_editor_file_save_result_fenced(
            &driver.authority.context,
            storage.inputs(),
            &command,
            &driver.owner.admission,
            EditorFileSaveAttempt {
                effect_id: &write.effect_id,
                run_id: &write.attempts[0].run_id
            },
            driver.owner.runtime(),
            Some(driver.owner.epoch)
        )
        .err()
        .unwrap()
        .contains("ownership is stale"));
    assert_eq!(events(&replacement), before);
}

#[test]
fn native_driver_takeover_and_revocation_refuse_old_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, storage, token) = home_storage_fixture(dir.path(), config());
    let mut wb = shared.lock_unpoisoned();
    let (grant, mut old) = start(&mut wb, &storage, &command, &token);
    step(&mut wb, &storage, &mut old);
    let mut current = wb
        .start_editor_file_save_driver(&storage, &command, &grant)
        .unwrap();
    let before = events(&current);
    assert!(wb
        .step_editor_file_save_driver(&storage, &mut old)
        .err()
        .unwrap()
        .contains("ownership is stale"));
    assert_eq!(events(&current), before);
    // Exercise the mutation boundary itself, independently of the driver's
    // earlier ownership read. A takeover between those points must also refuse.
    assert!(wb
        .advance_editor_file_save_fenced(
            &old.authority.context,
            storage.inputs(),
            &command,
            &old.owner.admission,
            &mut old.owner.runtime,
            Some(old.owner.epoch)
        )
        .is_err());
    assert_eq!(events(&current), before);
    let pending = wb
        .advance_editor_file_save_fenced(
            &current.authority.context,
            storage.inputs(),
            &command,
            &current.owner.admission,
            &mut current.owner.runtime,
            Some(current.owner.epoch),
        )
        .unwrap();
    assert_eq!(pending.len(), 1);
    let before = events(&current);
    assert!(wb
        .execute_editor_file_save_effect_fenced(
            &old.authority.context,
            storage.inputs(),
            &command,
            &old.owner.admission,
            &pending[0],
            &mut old.owner.runtime,
            Some(old.owner.epoch)
        )
        .is_err());
    assert_eq!(events(&current), before);
    let context = wb.authenticate_action_context(&token).unwrap();
    wb.revoke_editor_file_save_dispatch(&context, storage.inputs(), &command, &grant)
        .unwrap();
    assert!(wb
        .step_editor_file_save_driver(&storage, &mut current)
        .is_err());
    assert!(wb
        .start_editor_file_save_driver(&storage, &command, &grant)
        .is_err());
    assert_eq!(events(&current), before);
    let renewed = wb
        .authorize_editor_file_save_dispatch(&context, storage.inputs(), &command, "driver-2")
        .unwrap();
    let mut resumed = wb
        .start_editor_file_save_driver(&storage, &command, &renewed.grant_ref)
        .unwrap();
    step(&mut wb, &storage, &mut resumed);
    saved(&mut wb, &storage, &mut resumed);
    let observed = snapshot(&mut wb, &storage, &resumed);
    assert_eq!(observed.effects.len(), 2);
    assert!(observed
        .effects
        .iter()
        .all(|effect| effect.attempts.len() == 1));
}

#[test]
fn native_driver_recovers_lost_write_settlement_without_retry_or_continuation() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, storage, token) = home_storage_fixture(dir.path(), config());
    let mut wb = shared.lock_unpoisoned();
    let (grant, mut driver) = start(&mut wb, &storage, &command, &token);
    step(&mut wb, &storage, &mut driver);
    let fault =
        rusqlite::Connection::open(dir.path().join("actions/native/runtime.sqlite")).unwrap();
    fault.execute_batch("CREATE TRIGGER lose_driver_terminal BEFORE INSERT ON events WHEN NEW.event_type = 'effect.terminal' BEGIN SELECT RAISE(ABORT, 'lost settlement'); END;").unwrap();
    assert!(wb
        .step_editor_file_save_driver(&storage, &mut driver)
        .is_err());
    fault
        .execute_batch("DROP TRIGGER lose_driver_terminal")
        .unwrap();
    let before = snapshot(&mut wb, &storage, &driver);
    assert!(before.terminal.is_none());
    let (_, _, chat): (String, String, String) = serde_json::from_str(&command.scope).unwrap();
    let path = wb.engagement_workspace_path(&chat, "note.txt");
    let ActionBasis::Version { version_ref: base } = &command.resources["target"].basis else {
        panic!("fixture requires a retained base");
    };
    assert_eq!(
        super::super::recovery::tests::erase_fixture_base(dir.path(), base, &path),
        1
    );
    ContentStore::open(dir.path().join("actions/inputs.sqlite"))
        .unwrap()
        .erase(
            &command.inputs["content"].version_ref,
            "erase fixture input",
        )
        .unwrap();
    drop(fault);
    drop(driver);
    drop(wb);
    drop(storage);
    drop(shared);
    let shared = crate::open_workbench(dir.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let storage = wb.open_native_action_storage(config()).unwrap();
    let mut driver = wb
        .start_editor_file_save_driver(&storage, &command, &grant)
        .unwrap();
    let result = saved(&mut wb, &storage, &mut driver);
    assert_eq!(
        result.result.content_hash,
        whipplescript_store::stable_hash_hex("private editor draft")
    );
    let after = snapshot(&mut wb, &storage, &driver);
    assert!(after.terminal.is_none());
    assert_eq!(after.instance_status, before.instance_status);
    assert_eq!(after.effects.len(), before.effects.len());
    for (old, new) in before.effects.iter().zip(&after.effects) {
        assert_eq!(old.effect_id, new.effect_id);
        assert_eq!(old.attempts.len(), new.attempts.len());
        assert_eq!(old.attempts[0].run_id, new.attempts[0].run_id);
        assert_eq!(
            old.attempts[0].terminal_status,
            new.attempts[0].terminal_status
        );
    }
    let before = events(&driver);
    assert!(saved(&mut wb, &storage, &mut driver).replayed);
    assert_eq!(events(&driver), before);
}

#[test]
fn native_driver_keeps_conflicts_unresolved_without_new_attempts() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, storage, token) = home_storage_fixture(dir.path(), config());
    let mut wb = shared.lock_unpoisoned();
    let (_, mut driver) = start(&mut wb, &storage, &command, &token);
    step(&mut wb, &storage, &mut driver);
    let (_, _, chat): (String, String, String) = serde_json::from_str(&command.scope).unwrap();
    let path = wb.engagement_workspace_path(&chat, "note.txt");
    wb.engagements[&chat]
        .write_file(&path, "conflicting manual edit")
        .unwrap();
    let head = wb.engagements[&chat]
        .commit_turn("concurrent fixture edit")
        .unwrap()
        .unwrap()
        .0;
    step(&mut wb, &storage, &mut driver);
    let before = events(&driver);
    for _ in 0..2 {
        assert!(matches!(
            wb.step_editor_file_save_driver(&storage, &mut driver)
                .unwrap(),
            NativeEditorSaveProgress::Unresolved(_)
        ));
        assert_eq!(events(&driver), before);
        assert_eq!(
            wb.engagements[&chat].observe().unwrap().recorded_cut,
            Some(head.clone())
        );
    }
}

#[test]
fn native_driver_refuses_missing_acknowledgment_receipt_without_redelivery() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, storage, token) = home_storage_fixture(dir.path(), config());
    let mut wb = shared.lock_unpoisoned();
    let (grant, driver) = start(&mut wb, &storage, &command, &token);
    let before = events(&driver);
    let sql = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    let scope = format!(
        "host-action-runtime-ack:{}",
        command.instance_ref().unwrap()
    );
    assert_eq!(
        sql.execute(
            "DELETE FROM command_receipts WHERE scope_id = ?1 AND command_key = 'admitted'",
            [&scope]
        )
        .unwrap(),
        1
    );
    assert!(wb
        .start_editor_file_save_driver(&storage, &command, &grant)
        .err()
        .unwrap()
        .contains("acknowledgment has no committed receipt"));
    assert_eq!(events(&driver), before);
    driver
        .owner
        .require_current(&driver.owner.admission)
        .unwrap();
}
