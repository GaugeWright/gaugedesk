use super::*;
use crate::file_action_factory::tests::home_storage_fixture;
use crate::LockUnpoisoned;
use gaugedesk_whip_runtime::host_actions::{
    action_result::ActionWorkflowStatus, LogAppend, RuntimeStore,
};

fn config(seconds: u32) -> NativeActionStorageConfig {
    NativeActionStorageConfig {
        input_byte_limit: 4096,
        file_lease: FileLeasePolicy::new(seconds).unwrap(),
    }
}

fn epoch_seconds(value: &str) -> i64 {
    // SQLite uses the same RFC3339 clock representation as the runtime owner.
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    connection
        .query_row("SELECT unixepoch(?1)", [value], |row| row.get(0))
        .unwrap()
}

#[test]
fn home_native_initialization_executes_shipped_files_and_reopens_without_advancing() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, storage, token) = home_storage_fixture(dir.path(), config(17));
    let (admission, read_events, pending, owner_epoch) = {
        let mut wb = shared.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        assert!(!storage.home_root.join("actions/native").exists());
        let mut runtime = wb
            .open_editor_file_save_runtime(&context, &storage, &command)
            .unwrap();
        assert_eq!(runtime.policy_ref(), &command.policy);
        assert!(runtime
            .kernel()
            .store()
            .list_instances()
            .unwrap()
            .is_empty());
        let admission = wb
            .deliver_editor_file_save(&context, storage.inputs(), &command, &mut runtime)
            .unwrap()
            .receipt;
        let pending = wb
            .advance_editor_file_save(
                &context,
                storage.inputs(),
                &command,
                &admission,
                &mut runtime,
            )
            .unwrap();
        assert_eq!(pending.len(), 1);
        let before = runtime.kernel().store().resolve_clock("now").unwrap();
        wb.execute_editor_file_save_effect(
            &context,
            storage.inputs(),
            &command,
            &admission,
            &pending[0],
            &mut runtime,
        )
        .unwrap();
        assert_lease(&runtime, &admission.instance_ref, &before, 17);
        let pending = wb
            .advance_editor_file_save(
                &context,
                storage.inputs(),
                &command,
                &admission,
                &mut runtime,
            )
            .unwrap();
        assert_eq!(pending.len(), 1);
        let events = runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap();
        let epoch = runtime
            .kernel()
            .store()
            .instance_owner_epoch(&admission.instance_ref)
            .unwrap();
        (admission, events, pending, epoch)
    };
    drop(storage);
    drop(shared);
    let shared = crate::open_workbench(dir.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let storage = wb.open_native_action_storage(config(29)).unwrap();
    let mut runtime = wb
        .open_editor_file_save_runtime(&context, &storage, &command)
        .unwrap();
    assert_eq!(
        runtime
            .kernel()
            .store()
            .instance_owner_epoch(&admission.instance_ref)
            .unwrap(),
        owner_epoch
    );
    assert_eq!(
        runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap(),
        read_events
    );
    let before = runtime.kernel().store().resolve_clock("now").unwrap();
    wb.execute_editor_file_save_effect(
        &context,
        storage.inputs(),
        &command,
        &admission,
        &pending[0],
        &mut runtime,
    )
    .unwrap();
    assert_lease(&runtime, &admission.instance_ref, &before, 29);
    wb.advance_editor_file_save(
        &context,
        storage.inputs(),
        &command,
        &admission,
        &mut runtime,
    )
    .unwrap();
    let result = wb
        .read_editor_file_save_result(&context, storage.inputs(), &command, &admission, &runtime)
        .unwrap();
    assert_eq!(
        result.terminal.unwrap().status,
        ActionWorkflowStatus::Completed
    );
    let (.., chat): (String, String, String) = serde_json::from_str(&command.scope).unwrap();
    let (.., path): (String, String, String) = serde_json::from_str(
        command.resources["target"]
            .resource
            .selector
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        wb.engagements[&chat].read_file(&path).unwrap(),
        "recorded base"
    );
    let events = runtime
        .kernel()
        .store()
        .list_events(&admission.instance_ref)
        .unwrap();
    assert_eq!(&events[..read_events.len()], &read_events);
    drop(runtime);
    // Initialization and authorized metadata reads do not reconstruct erased inputs.
    use whipplescript_store::content::{ContentBlobs, ContentStore};
    ContentStore::open(storage.home_root.join("actions/inputs.sqlite"))
        .unwrap()
        .erase(
            &command.inputs["content"].version_ref,
            "2026-09-09T12:00:00Z",
        )
        .unwrap();
    let runtime = wb
        .open_editor_file_save_runtime(&context, &storage, &command)
        .unwrap();
    assert_eq!(
        runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap(),
        events
    );
    wb.read_editor_file_save_result(&context, storage.inputs(), &command, &admission, &runtime)
        .unwrap();
}

fn assert_lease(
    runtime: &GovernedHostFacade<NativeStores>,
    instance: &str,
    before: &str,
    seconds: i64,
) {
    let after = runtime.kernel().store().resolve_clock("now").unwrap();
    let events = runtime.kernel().store().list_events(instance).unwrap();
    let event = events
        .iter()
        .rev()
        .find(|event| event.event_type == "effect.run_started")
        .unwrap();
    let payload: serde_json::Value = serde_json::from_str(&event.payload_json).unwrap();
    assert_eq!(payload["provider"], "files");
    let deadline = epoch_seconds(payload["lease_expires_at"].as_str().unwrap());
    assert!(deadline >= epoch_seconds(before) + seconds);
    assert!(deadline <= epoch_seconds(&after) + seconds);
}

#[test]
fn home_native_initialization_refuses_foreign_storage_changed_command_and_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let other_dir = tempfile::tempdir().unwrap();
    let (shared, command, storage, token) = home_storage_fixture(dir.path(), config(17));
    let other = crate::open_workbench(other_dir.path()).unwrap();
    let foreign_storage = other
        .lock_unpoisoned()
        .open_native_action_storage(config(17))
        .unwrap();
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let error = wb
        .open_editor_file_save_runtime(&context, &foreign_storage, &command)
        .err()
        .unwrap();
    assert!(error.contains("different Home"), "{error}");
    assert!(!foreign_storage.home_root.join("actions/native").exists());
    for field in 0..3 {
        let mut changed = command.clone();
        match field {
            0 => changed.request_id.push_str("-different"),
            1 => changed.policy.epoch += 1,
            _ => changed.provenance.initiator = "mallory".into(),
        }
        assert!(wb
            .open_editor_file_save_runtime(&context, &storage, &changed)
            .is_err());
        assert!(!storage.home_root.join("actions/native").exists());
    }
    wb.revoke_account_session(&token);
    assert!(wb
        .open_editor_file_save_runtime(&context, &storage, &command)
        .is_err());
    assert!(!storage.home_root.join("actions/native").exists());
}

#[test]
fn home_native_input_connections_share_retention_exclusion_and_enforce_configured_budget() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, storage, _token) = home_storage_fixture(dir.path(), config(17));
    let wb = shared.lock_unpoisoned();
    let second = wb.open_native_action_storage(config(29)).unwrap();
    let reference = &command.inputs["content"];
    assert_eq!(
        storage.inputs().resolve(reference).unwrap().content,
        second.inputs().resolve(reference).unwrap().content
    );
    let connection =
        rusqlite::Connection::open(storage.home_root.join("actions/inputs.sqlite")).unwrap();
    connection.busy_timeout(std::time::Duration::ZERO).unwrap();
    second
        .inputs()
        .with_resolved(reference, |_| {
            assert!(connection.execute_batch("BEGIN IMMEDIATE").is_err());
            Ok(())
        })
        .unwrap();
    connection
        .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
        .unwrap();
    let smaller = wb
        .open_native_action_storage(NativeActionStorageConfig {
            input_byte_limit: 1,
            ..config(17)
        })
        .unwrap();
    assert!(smaller.inputs().prepare("input", "label", "xx").is_err());
    assert!(smaller.inputs().resolve(reference).is_err());
}

#[test]
fn home_native_initialization_requires_home_identity_and_initialized_root() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, mut storage, token) = home_storage_fixture(dir.path(), config(17));
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    storage.home_id = gaugedesk_core::ids::HomeId::new("home:other");
    let error = wb
        .open_editor_file_save_runtime(&context, &storage, &command)
        .err()
        .unwrap();
    assert!(error.contains("different Home"), "{error}");
    assert!(!storage.home_root.join("actions/native").exists());
    wb.root = PathBuf::new();
    let error = wb.open_native_action_storage(config(17)).err().unwrap();
    assert!(error.contains("initialized Home root"), "{error}");
}
