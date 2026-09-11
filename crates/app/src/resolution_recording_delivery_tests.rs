//! Actual product admission, native runtime and failed-acknowledgment recovery.
use super::*;
use crate::host_action_delivery::ACKNOWLEDGMENT_KIND;
use gaugedesk_whip_runtime::host_actions::RuntimeStore;
use whipplescript_store::content::{ContentBlobs, ContentStore};

fn fixture(
    root: &std::path::Path,
) -> (
    SharedWorkbench,
    HostActionCommand,
    NativeActionInputCustody,
    String,
) {
    let (shared, file, token) = setup(root);
    let (command, inputs) = {
        let mut wb = shared.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let inputs =
            NativeActionInputCustody::open(root.join("inputs.sqlite"), wb.home_id().as_str(), 4096)
                .unwrap();
        let corrections = input("");
        let command = wb
            .admit_editor_corrections(
                &context,
                &inputs,
                &EditorCorrections {
                    chat_id: &file.chat_id,
                    request_id: "correction-1",
                    path: "never-created.txt",
                    corrections: &corrections,
                },
            )
            .unwrap()
            .command;
        (command, inputs)
    };
    (shared, command, inputs, token)
}

#[test]
fn correction_delivery_recovers_a_lost_acknowledgment_without_a_new_runtime_action() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, inputs, token) = fixture(dir.path());
    let scope = command.instance_ref().unwrap();
    let before = {
        let mut wb = shared.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let mut runtime = editor_runtime(&wb, &command, dir.path());
        let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
        fault
            .execute_batch(
                "CREATE TRIGGER fail_correction_ack BEFORE INSERT ON events
            WHEN NEW.kind = 'host_action_runtime_admission_v1'
            BEGIN SELECT RAISE(ABORT, 'lost product acknowledgment'); END;",
            )
            .unwrap();
        let error = wb
            .deliver_editor_corrections(&context, &inputs, &command, &mut runtime)
            .unwrap_err();
        assert!(error.contains("acknowledgment"), "{error}");
        assert_eq!(runtime.kernel().store().list_instances().unwrap().len(), 1);
        assert!(runtime
            .kernel()
            .store()
            .list_effects(&scope)
            .unwrap()
            .is_empty());
        assert!(wb
            .store_ref()
            .records(&scope, ACKNOWLEDGMENT_KIND)
            .unwrap()
            .is_empty());
        fault
            .execute_batch("DROP TRIGGER fail_correction_ack")
            .unwrap();
        runtime.kernel().store().list_events(&scope).unwrap()
    };
    drop(shared);
    let shared = crate::open_workbench(dir.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let token = wb.mint_account_session("alice", "passkey", 3600).unwrap();
    let context = wb.authenticate_action_context(&token).unwrap();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    let acknowledgment = wb
        .deliver_editor_corrections(&context, &inputs, &command, &mut runtime)
        .unwrap();
    assert_eq!(
        wb.deliver_editor_corrections(&context, &inputs, &command, &mut runtime)
            .unwrap(),
        acknowledgment
    );
    assert_eq!(
        runtime.kernel().store().list_events(&scope).unwrap(),
        before
    );
    assert!(runtime
        .kernel()
        .store()
        .list_effects(&scope)
        .unwrap()
        .is_empty());
    assert_eq!(
        wb.store_ref()
            .records(&scope, ACKNOWLEDGMENT_KIND)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        acknowledgment.receipt.fingerprint,
        command.fingerprint().unwrap()
    );
    let (_, _, chat, path): (String, String, String, String) =
        serde_json::from_str(&command.scope).unwrap();
    assert!(wb.engagements[&chat].read_file(&path).is_err());
}

#[test]
fn correction_delivery_refuses_changed_commands_revocation_and_stale_target_authority() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, inputs, token) = fixture(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    let context = wb.authenticate_action_context(&token).unwrap();
    for mutation in 0..7 {
        let mut changed = command.clone();
        match mutation {
            0 => changed.inputs.get_mut("corrections").unwrap().version_ref = "unadmitted".into(),
            1 => changed.request_id = "missing admission".into(),
            2 => changed.provenance.executor = "another actor".into(),
            3 => changed.program_version_ref = "other executable".into(),
            4 => {
                changed
                    .resources
                    .get_mut("resolutions")
                    .unwrap()
                    .resource
                    .writable = Some(false)
            }
            5 => {
                changed.inputs.get_mut("corrections").unwrap().label_ref = "unadmitted label".into()
            }
            _ => changed.provenance.causes.push(ActionCause {
                authority: command.issuer.clone(),
                record_ref: "invented earlier authorship".into(),
                digest: "00".repeat(32),
            }),
        }
        assert!(
            wb.deliver_editor_corrections(&context, &inputs, &changed, &mut runtime)
                .is_err(),
            "mutation {mutation}"
        );
    }
    wb.revoke_account_session(&token);
    assert!(wb
        .deliver_editor_corrections(&context, &inputs, &command, &mut runtime)
        .is_err());
    let token = wb.mint_account_session("alice", "passkey", 3600).unwrap();
    let context = wb.authenticate_action_context(&token).unwrap();
    membership(&mut wb, "alice", "consultant");
    assert!(wb
        .deliver_editor_corrections(&context, &inputs, &command, &mut runtime)
        .is_err());
    membership(&mut wb, "alice", "owner");
    let (_, _, chat, _): (String, String, String, String) =
        serde_json::from_str(&command.scope).unwrap();
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
    assert!(
        wb.library.work_targets[&target_id].capabilities.propose,
        "cache intentionally stale"
    );
    assert!(wb
        .deliver_editor_corrections(&context, &inputs, &command, &mut runtime)
        .is_err());
    assert!(runtime
        .kernel()
        .store()
        .list_instances()
        .unwrap()
        .is_empty());
}

#[test]
fn correction_delivery_refuses_erased_input_changed_compartments_and_foreign_custody() {
    for case in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let (shared, command, inputs, token) = fixture(dir.path());
        let mut wb = shared.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let mut runtime = editor_runtime(&wb, &command, dir.path());
        let foreign =
            NativeActionInputCustody::open(dir.path().join("foreign.sqlite"), "other-home", 4096)
                .unwrap();
        match case {
            0 => {
                ContentStore::open(dir.path().join("inputs.sqlite"))
                    .unwrap()
                    .erase(
                        &command.inputs["corrections"].version_ref,
                        "erase admitted input",
                    )
                    .unwrap();
            }
            1 => {
                let (_, _, chat, _): (String, String, String, String) =
                    serde_json::from_str(&command.scope).unwrap();
                let target_id = wb.library.current_target_set(&chat).unwrap().members[0]
                    .target_id
                    .clone();
                let mut target = wb.library.work_targets[&target_id].clone();
                target.attributes.classification = gaugedesk_core::abac::Classification::Public;
                wb.store_mut()
                    .append_record(
                        LIBRARY_SCOPE,
                        "work_target",
                        &serde_json::to_string(&target).unwrap(),
                    )
                    .unwrap();
            }
            _ => {}
        }
        let custody = if case == 2 { &foreign } else { &inputs };
        let error = wb
            .deliver_editor_corrections(&context, custody, &command, &mut runtime)
            .unwrap_err();
        if case == 1 {
            assert!(error.contains("admitted ceiling"), "{error}");
        }
        assert!(runtime
            .kernel()
            .store()
            .list_instances()
            .unwrap()
            .is_empty());
    }
}

#[test]
fn correction_delivery_requires_original_history_beside_the_receipt_and_outbox() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, inputs, token) = fixture(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    let scope = command.instance_ref().unwrap();
    // Inject history loss while leaving projections and both receipts intact.
    let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    fault
        .execute(
            "DELETE FROM events WHERE scope_id = ?1 AND kind = ?2",
            rusqlite::params![scope, ProductActionAdmission::KIND],
        )
        .unwrap();
    assert!(wb
        .store_mut()
        .committed_dispatch::<ProductActionAdmission>(&scope, &command.request_id)
        .unwrap()
        .is_some());
    let error = wb
        .deliver_editor_corrections(&context, &inputs, &command, &mut runtime)
        .unwrap_err();
    assert!(error.contains("original admission"), "{error}");
    assert!(runtime
        .kernel()
        .store()
        .list_instances()
        .unwrap()
        .is_empty());
}
