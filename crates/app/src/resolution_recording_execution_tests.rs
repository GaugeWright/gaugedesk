//! Real Home storage, pinned package and actual native correction target.
use super::*;
use gaugedesk_whip_runtime::host_actions::{
    action_result::ActionWorkflowStatus, facade::GovernedHostFacade, NativeStores, RuntimeStore,
};
use whipplescript_kernel::file_lease::FileLeasePolicy;
use whipplescript_store::{
    content::{ContentBlobs, ContentStore},
    effect_recovery::ExternalDisposition,
    vcs_resolution_recording::{read_committed_resolution_recording, ResolutionRecordingBinding},
};

fn config() -> NativeActionStorageConfig {
    NativeActionStorageConfig {
        input_byte_limit: 4096,
        file_lease: FileLeasePolicy::new(17).unwrap(),
    }
}
fn fixture(
    root: &std::path::Path,
) -> (
    SharedWorkbench,
    HostActionCommand,
    NativeActionStorage,
    String,
) {
    let (shared, file, token) = setup(root);
    let (command, storage) = {
        let mut wb = shared.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let storage = wb.open_native_action_storage(config()).unwrap();
        let command = wb
            .admit_editor_corrections(
                &context,
                storage.inputs(),
                &EditorCorrections {
                    chat_id: &file.chat_id,
                    request_id: "correction-1",
                    path: "never-created.txt",
                    corrections: &input(""),
                },
            )
            .unwrap()
            .command;
        (command, storage)
    };
    (shared, command, storage, token)
}
fn coordinates(command: &HostActionCommand) -> (String, String) {
    let (_, _, chat, path): (String, String, String, String) =
        serde_json::from_str(&command.scope).unwrap();
    (chat, path)
}
fn binding(
    runtime: &GovernedHostFacade<NativeStores>,
    command: &HostActionCommand,
) -> ResolutionRecordingBinding {
    let events = runtime
        .kernel()
        .store()
        .list_events(&command.instance_ref().unwrap())
        .unwrap();
    let dispatch = events
        .iter()
        .find(|e| e.event_type == "effect.run_started")
        .unwrap();
    let payload: serde_json::Value = serde_json::from_str(&dispatch.payload_json).unwrap();
    serde_json::from_value(payload["metadata"]["resolution_recording"].clone()).unwrap()
}
fn receipt(
    wb: &Workbench,
    command: &HostActionCommand,
    binding: &ResolutionRecordingBinding,
) -> whipplescript_store::branches::resolution_batch::ResolutionMemoryReceipt {
    let (chat, path) = coordinates(command);
    wb.engagements[&chat]
        .native_resolution_recording_evidence_target(&path, binding.scope().clone())
        .unwrap()
        .observe(binding, |workspace| {
            read_committed_resolution_recording(workspace, binding)
        })
        .unwrap()
        .unwrap()
}

#[test]
fn home_correction_execution_records_exact_first_winner_without_changing_files() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, mut command, storage, token) = fixture(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let mut context = wb.authenticate_action_context(&token).unwrap();
    membership(&mut wb, "bob", "owner");
    let bob = wb.mint_account_session("bob", "passkey", 3600).unwrap();
    let (chat, path) = coordinates(&command);
    let before = wb.engagements[&chat].observe().unwrap().recorded_cut;
    assert!(!dir.path().join("actions/native").exists());
    let mut winner = None;
    let mut first_evidence = None;
    for inserted in [true, false] {
        let mut runtime = wb
            .open_editor_corrections_runtime(&context, &storage, &command)
            .unwrap();
        let admission = wb
            .deliver_editor_corrections(&context, storage.inputs(), &command, &mut runtime)
            .unwrap()
            .receipt;
        assert!(runtime
            .kernel()
            .store()
            .runtime
            .capability_bindings_for("unadmitted-program", "vcs.record_resolutions")
            .unwrap()
            .is_empty());
        let pending = wb
            .advance_editor_corrections(
                &context,
                storage.inputs(),
                &command,
                &admission,
                &mut runtime,
            )
            .unwrap();
        let store = runtime.kernel().store();
        let program = store
            .get_instance(&admission.instance_ref)
            .unwrap()
            .unwrap()
            .program_id;
        let bindings = store
            .runtime
            .capability_bindings_for(&admission.instance_ref, "vcs.record_resolutions")
            .unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].program_id.as_deref(), Some(program.as_str()));
        assert_eq!(bindings[0].provider.as_deref(), Some("resolution-memory"));
        assert_eq!(bindings[0].config_json, "{}");
        assert!(store
            .runtime
            .capability_bindings_for("unadmitted-program", "vcs.record_resolutions")
            .unwrap()
            .is_empty());
        assert_eq!(pending.len(), 1);
        let before_attempt = runtime.kernel().store().resolve_clock("now").unwrap();
        wb.execute_editor_corrections_effect(
            &context,
            storage.inputs(),
            &command,
            &admission,
            &pending[0],
            &mut runtime,
        )
        .unwrap();
        let after_attempt = runtime.kernel().store().resolve_clock("now").unwrap();
        let started = runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap()
            .into_iter()
            .find(|e| e.event_type == "effect.run_started")
            .unwrap();
        let start: serde_json::Value = serde_json::from_str(&started.payload_json).unwrap();
        assert_eq!(start["provider"], "resolution-memory");
        let clock = rusqlite::Connection::open_in_memory().unwrap();
        let epoch = |value: &str| -> i64 {
            clock
                .query_row("SELECT unixepoch(?1)", [value], |row| row.get(0))
                .unwrap()
        };
        let expires = epoch(start["lease_expires_at"].as_str().unwrap());
        assert!(expires >= epoch(&before_attempt) + 17);
        assert!(expires <= epoch(&after_attempt) + 17);
        let original = binding(&runtime, &command);
        let recorded = receipt(&wb, &command, &original);
        assert_eq!(
            original.input_hash(),
            storage
                .inputs()
                .resolve(&command.inputs["corrections"])
                .unwrap()
                .content_hash
        );
        assert_eq!(
            original.input_label(),
            command.inputs["corrections"].label_ref
        );
        assert_eq!(
            recorded.request.actor,
            if inserted { "alice" } else { "bob" }
        );
        assert_eq!(recorded.request.intent, command.fingerprint().unwrap());
        assert_eq!(recorded.outcomes[0].inserted, inserted);
        if inserted {
            assert_eq!(
                recorded.outcomes[0].resolution,
                whipplescript_store::stable_hash_hex("")
            );
            winner = Some(recorded.outcomes[0].resolution.clone());
            first_evidence = Some((original.clone(), recorded.clone()));
        } else {
            let (binding, first) = first_evidence.as_ref().unwrap();
            assert_eq!(&receipt(&wb, &command, binding), first);
        }
        assert_eq!(Some(&recorded.outcomes[0].resolution), winner.as_ref());
        assert_eq!(
            wb.engagements[&chat].observe().unwrap().recorded_cut,
            before
        );
        assert!(wb.engagements[&chat].read_file(&path).is_err());
        assert!(wb
            .advance_editor_corrections(
                &context,
                storage.inputs(),
                &command,
                &admission,
                &mut runtime
            )
            .unwrap()
            .is_empty());
        let result = wb
            .read_editor_corrections_result(
                &context,
                storage.inputs(),
                &command,
                &admission,
                &runtime,
            )
            .unwrap();
        assert_eq!(
            result.terminal.unwrap().status,
            ActionWorkflowStatus::Completed
        );
        let events = runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
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
            .unwrap_err()
            .contains("already attempted"));
        drop(runtime);
        let runtime = wb
            .open_editor_corrections_runtime(&context, &storage, &command)
            .unwrap();
        assert_eq!(
            runtime
                .kernel()
                .store()
                .list_events(&admission.instance_ref)
                .unwrap(),
            events
        );
        if inserted {
            context = wb.authenticate_action_context(&bob).unwrap();
            command = wb
                .admit_editor_corrections(
                    &context,
                    storage.inputs(),
                    &EditorCorrections {
                        chat_id: &chat,
                        request_id: "correction-2",
                        path: &path,
                        corrections: &input("later correction"),
                    },
                )
                .unwrap()
                .command;
        }
    }
}

#[test]
fn correction_runtime_initialization_refuses_foreign_storage_and_unadmitted_changes() {
    let dir = tempfile::tempdir().unwrap();
    let other_dir = tempfile::tempdir().unwrap();
    let (shared, command, storage, token) = fixture(dir.path());
    let other = crate::open_workbench(other_dir.path()).unwrap();
    let foreign = other
        .lock_unpoisoned()
        .open_native_action_storage(config())
        .unwrap();
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    assert!(wb
        .open_editor_corrections_runtime(&context, &foreign, &command)
        .err()
        .unwrap()
        .contains("different Home"));
    for change in 0..4 {
        let mut changed = command.clone();
        match change {
            0 => changed.request_id.push_str("-unadmitted"),
            1 => changed.policy.epoch += 1,
            2 => changed.provenance.initiator = "other actor".into(),
            _ => {
                changed
                    .resources
                    .get_mut("resolutions")
                    .unwrap()
                    .resource
                    .writable = Some(false)
            }
        }
        assert!(wb
            .open_editor_corrections_runtime(&context, &storage, &changed)
            .is_err());
    }
    wb.revoke_account_session(&token);
    assert!(wb
        .open_editor_corrections_runtime(&context, &storage, &command)
        .is_err());
    assert!(!dir.path().join("actions/native").exists());
    assert!(!other_dir.path().join("actions/native").exists());
}

#[test]
fn correction_execution_rechecks_current_authority_and_retained_input_before_dispatch() {
    for case in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let (shared, command, storage, token) = fixture(dir.path());
        let mut wb = shared.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
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
        let before = runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap();
        match case {
            0 => {
                wb.revoke_account_session(&token);
            }
            1 => membership(&mut wb, "alice", "consultant"),
            2 => {
                let (chat, _) = coordinates(&command);
                let target_id = wb.library.current_target_set(&chat).unwrap().members[0]
                    .target_id
                    .clone();
                let mut target = wb.library.work_targets[&target_id].clone();
                target.capabilities.propose = false;
                wb.store_mut()
                    .append_record(
                        LIBRARY_SCOPE,
                        "work_target",
                        &serde_json::to_string(&target).unwrap(),
                    )
                    .unwrap();
                assert!(wb.library.work_targets[&target_id].capabilities.propose);
            }
            _ => {
                ContentStore::open(dir.path().join("actions/inputs.sqlite"))
                    .unwrap()
                    .erase(
                        &command.inputs["corrections"].version_ref,
                        "erased before execution",
                    )
                    .unwrap();
            }
        }
        assert!(
            wb.execute_editor_corrections_effect(
                &context,
                storage.inputs(),
                &command,
                &admission,
                &pending[0],
                &mut runtime
            )
            .is_err(),
            "case {case}"
        );
        assert_eq!(
            runtime
                .kernel()
                .store()
                .list_events(&admission.instance_ref)
                .unwrap(),
            before
        );
        assert!(runtime
            .kernel()
            .store()
            .list_runs(&admission.instance_ref)
            .unwrap()
            .is_empty());
    }
}

#[test]
fn interrupted_correction_settlement_remains_unknown_after_restart_and_input_erasure() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, storage, token) = fixture(dir.path());
    let (admission, effect, original, recorded, events) = {
        let mut wb = shared.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
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
        let fault =
            rusqlite::Connection::open(dir.path().join("actions/native/runtime.sqlite")).unwrap();
        fault.execute_batch("CREATE TRIGGER lose_correction_terminal BEFORE INSERT ON events WHEN NEW.event_type = 'effect.terminal' BEGIN SELECT RAISE(ABORT, 'lost correction settlement'); END;").unwrap();
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
        fault
            .execute_batch("DROP TRIGGER lose_correction_terminal")
            .unwrap();
        let original = binding(&runtime, &command);
        let recorded = receipt(&wb, &command, &original);
        assert!(recorded.outcomes[0].inserted);
        assert!(wb
            .execute_editor_corrections_effect(
                &context,
                storage.inputs(),
                &command,
                &admission,
                &pending[0],
                &mut runtime
            )
            .unwrap_err()
            .contains("already attempted"));
        let result = wb
            .read_editor_corrections_result(
                &context,
                storage.inputs(),
                &command,
                &admission,
                &runtime,
            )
            .unwrap();
        assert!(result.terminal.is_none());
        assert_eq!(
            result.effects[0].attempts[0].disposition,
            ExternalDisposition::Unknown
        );
        let events = runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap();
        (admission, pending[0].clone(), original, recorded, events)
    };
    ContentStore::open(dir.path().join("actions/inputs.sqlite"))
        .unwrap()
        .erase(
            &command.inputs["corrections"].version_ref,
            "erased after dispatch",
        )
        .unwrap();
    drop(storage);
    drop(shared);
    let shared = crate::open_workbench(dir.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let token = wb.mint_account_session("alice", "passkey", 3600).unwrap();
    let context = wb.authenticate_action_context(&token).unwrap();
    let storage = wb.open_native_action_storage(config()).unwrap();
    let mut runtime = wb
        .open_editor_corrections_runtime(&context, &storage, &command)
        .unwrap();
    let result = wb
        .read_editor_corrections_result(&context, storage.inputs(), &command, &admission, &runtime)
        .unwrap();
    assert_eq!(
        result.effects[0].attempts[0].disposition,
        ExternalDisposition::Unknown
    );
    assert!(result.terminal.is_none());
    assert_eq!(receipt(&wb, &command, &original), recorded);
    let key = SigningKey::from_seed(&wb.governance_seed()).unwrap();
    let mapping = crate::action_input_binding::load_input_binding(
        wb.store_ref(),
        &command.issuer,
        wb.home_id().as_str(),
        &command.inputs["corrections"],
        &key.public_key(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(mapping.content_hash(), original.input_hash());
    assert_eq!(mapping.input().label_ref, original.input_label());

    assert!(storage
        .inputs()
        .resolve(&command.inputs["corrections"])
        .is_err());
    assert!(wb
        .execute_editor_corrections_effect(
            &context,
            storage.inputs(),
            &command,
            &admission,
            &effect,
            &mut runtime
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

#[test]
fn correction_execution_requires_the_original_home_mapping_before_dispatch() {
    for case in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let (shared, command, storage, token) = fixture(dir.path());
        let mut wb = shared.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
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
        assert_eq!(pending.len(), 1);
        let before = runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap();
        let input = &command.inputs["corrections"];
        let scope =
            crate::action_input_binding::input_binding_scope(&command.issuer, input).unwrap();
        let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
        let raw: String = fault
            .query_row(
                "SELECT payload FROM events WHERE scope_id = ?1",
                [&scope],
                |row| row.get(0),
            )
            .unwrap();
        let mut signed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        match case {
            0 => {
                // Legacy evidence may be read, but an absent mapping must never
                // be manufactured on an execution or recovery path.
                fault
                    .execute("DELETE FROM events WHERE scope_id = ?1", [&scope])
                    .unwrap();
                fault
                    .execute("DELETE FROM command_receipts WHERE scope_id = ?1", [&scope])
                    .unwrap();
                assert!(wb
                    .read_editor_corrections_result(
                        &context,
                        storage.inputs(),
                        &command,
                        &admission,
                        &runtime
                    )
                    .is_ok());
            }
            1 => {
                fault
                    .execute("DELETE FROM command_receipts WHERE scope_id = ?1", [&scope])
                    .unwrap();
            }
            2 | 3 => {
                signed["statement"]["content_hash"] = "0".repeat(32).into();
                let key = SigningKey::from_seed(&wb.governance_seed()).unwrap();
                if case == 3 {
                    // Even a correctly signed statement must match the bytes
                    // resolved for this attempt. Signing cannot replace that check.
                    let mut bytes = b"gaugedesk:action-input-binding:v1\0".to_vec();
                    bytes.extend(
                        serde_json::to_vec(&whipplescript_store::effect_recovery::canonical_value(
                            &signed["statement"],
                        ))
                        .unwrap(),
                    );
                    signed["signature"] = serde_json::json!(key.sign(&bytes).as_bytes());
                }
                let snapshot =
                    serde_json::to_string(&whipplescript_store::effect_recovery::canonical_value(
                        &serde_json::json!([signed["statement"], key.public_key().as_str()]),
                    ))
                    .unwrap();
                fault
                    .execute(
                        "UPDATE events SET payload = ?1 WHERE scope_id = ?2",
                        rusqlite::params![serde_json::to_string(&signed).unwrap(), scope],
                    )
                    .unwrap();
                fault
                    .execute(
                        "UPDATE commands SET snapshot_json = ?1 WHERE scope_id = ?2",
                        rusqlite::params![snapshot, scope],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            wb.execute_editor_corrections_effect(
                &context,
                storage.inputs(),
                &command,
                &admission,
                &pending[0],
                &mut runtime
            )
            .is_err(),
            "case {case}"
        );
        assert_eq!(
            runtime
                .kernel()
                .store()
                .list_events(&admission.instance_ref)
                .unwrap(),
            before
        );
        assert!(runtime
            .kernel()
            .store()
            .list_runs(&admission.instance_ref)
            .unwrap()
            .is_empty());
    }
}

#[path = "resolution_recording_inspection_tests.rs"]
mod inspection;
