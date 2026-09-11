//! Real Home observation, with the original writer and current reader separated.
use super::*;
use gaugedesk_core::abac::{Action, Condition, Constraint, Policy, Rule};

struct Recorded {
    shared: SharedWorkbench,
    command: HostActionCommand,
    admission: ActionAdmissionReceipt,
    effect: String,
    run: String,
    original: ResolutionRecordingBinding,
    author_token: String,
}

fn path_ceiling(wb: &mut Workbench, chat: &str, ceiling: &[&str]) {
    let library = crate::library::Library::rebuild(wb.store_ref()).unwrap();
    let mut selection = library.current_target_set(chat).unwrap().clone();
    let mut target = library.work_targets[&selection.members[0].target_id].clone();
    target.path_scope = ceiling.iter().map(|path| (*path).to_owned()).collect();
    wb.store_mut()
        .append_record(
            LIBRARY_SCOPE,
            "work_target",
            &serde_json::to_string(&target).unwrap(),
        )
        .unwrap();
    // Startup validates both bindings against the target's literal path set.
    // Keep them consistent even when equivalent root spelling changes.
    let mut binding = library.chat_targets[chat].clone();
    binding.path_scope = target.path_scope.clone();
    wb.store_mut()
        .append_record(
            LIBRARY_SCOPE,
            "chat_target",
            &serde_json::to_string(&binding).unwrap(),
        )
        .unwrap();
    selection.revision += 1;
    selection.members[0].path_scope = target.path_scope.clone();
    wb.store_mut()
        .append_record(
            LIBRARY_SCOPE,
            "chat_target_set",
            &serde_json::to_string(&selection).unwrap(),
        )
        .unwrap();
}

fn recorded(root: &std::path::Path, ceiling: &[&str], interrupted: bool) -> Recorded {
    recorded_input(root, ceiling, interrupted, &input(""), false)
}

fn recording_classification(
    wb: &mut Workbench,
    chat: &str,
    classification: gaugedesk_core::abac::Classification,
) {
    let library = crate::library::Library::rebuild(wb.store_ref()).unwrap();
    let selected = library.current_target_set(chat).unwrap();
    let mut target = library.work_targets[&selected.members[0].target_id].clone();
    target.attributes.classification = classification;
    wb.store_mut()
        .append_record(
            LIBRARY_SCOPE,
            "work_target",
            &serde_json::to_string(&target).unwrap(),
        )
        .unwrap();
}

fn recorded_input(
    root: &std::path::Path,
    ceiling: &[&str],
    interrupted: bool,
    corrections: &ResolutionRecordingInput,
    public: bool,
) -> Recorded {
    recorded_input_with_call_shape(root, ceiling, interrupted, corrections, public, false)
}

fn recorded_input_with_call_shape(
    root: &std::path::Path,
    ceiling: &[&str],
    interrupted: bool,
    corrections: &ResolutionRecordingInput,
    public: bool,
    legacy_call: bool,
) -> Recorded {
    let (shared, file, token) = setup(root);
    let mut wb = shared.lock_unpoisoned();
    path_ceiling(&mut wb, &file.chat_id, ceiling);
    if public {
        recording_classification(
            &mut wb,
            &file.chat_id,
            gaugedesk_core::abac::Classification::Public,
        );
    }
    let context = wb.authenticate_action_context(&token).unwrap();
    let storage = wb.open_native_action_storage(config()).unwrap();
    let command = wb
        .admit_editor_corrections(
            &context,
            storage.inputs(),
            &EditorCorrections {
                chat_id: &file.chat_id,
                request_id: "inspect-original",
                path: "notes/correction.txt",
                corrections,
            },
        )
        .unwrap()
        .command;
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
    let fault = rusqlite::Connection::open(root.join("actions/native/runtime.sqlite")).unwrap();
    if legacy_call {
        // Model the pending call shape emitted before arguments were retained.
        // The real owner then executes and records its dispatch from this shape.
        assert_eq!(fault.execute(
            "UPDATE effects SET input_json = json_remove(input_json, '$.argument_exprs', '$.arguments') WHERE instance_id = ?1 AND effect_id = ?2",
            rusqlite::params![admission.instance_ref, pending[0]],
        ).unwrap(), 1);
    }
    if interrupted {
        fault.execute_batch("CREATE TRIGGER lose_inspected_terminal BEFORE INSERT ON events WHEN NEW.event_type = 'effect.terminal' BEGIN SELECT RAISE(ABORT, 'lost inspected settlement'); END;").unwrap();
    }
    let result = wb.execute_editor_corrections_effect(
        &context,
        storage.inputs(),
        &command,
        &admission,
        &pending[0],
        &mut runtime,
    );
    if interrupted {
        assert!(result.is_err());
        fault
            .execute_batch("DROP TRIGGER lose_inspected_terminal")
            .unwrap();
    } else {
        result.unwrap();
    }
    let original = binding(&runtime, &command);
    let run = runtime
        .kernel()
        .store()
        .list_runs(&admission.instance_ref)
        .unwrap()
        .into_iter()
        .find(|run| run.effect_id == pending[0])
        .unwrap()
        .run_id;
    drop(wb);
    Recorded {
        shared,
        command,
        admission,
        effect: pending[0].clone(),
        run,
        original,
        author_token: token,
    }
}

fn deny(wb: &mut Workbench, action: Action) {
    let policy = crate::org::PolicyRecord {
        id: crate::org::ORG_ID.into(),
        op: crate::org::RecordOp::Upsert,
        policy: Policy {
            rules: vec![Rule {
                when: Condition::Always,
                require: Constraint::DenyAction(action),
            }],
        },
    };
    wb.store_mut()
        .append_record(
            ORG_SCOPE,
            "policy",
            &serde_json::to_string(&policy).unwrap(),
        )
        .unwrap();
}

fn read_only(wb: &mut Workbench, command: &HostActionCommand) {
    let (chat, _) = coordinates(command);
    let library = crate::library::Library::rebuild(wb.store_ref()).unwrap();
    let mut selection = library.current_target_set(&chat).unwrap().clone();
    let mut target = library.work_targets[&selection.members[0].target_id].clone();
    target.capabilities.propose = false;
    wb.store_mut()
        .append_record(
            LIBRARY_SCOPE,
            "work_target",
            &serde_json::to_string(&target).unwrap(),
        )
        .unwrap();
    selection.revision += 1;
    selection.members[0].participation = crate::library::TargetParticipationMode::ReadOnly;
    selection.members[0].capability_ceiling.propose = false;
    // Keep the singular compatibility binding valid when the Home reopens.
    // It cannot retain a capability that the actual target has revoked.
    let mut binding = library.chat_targets[&chat].clone();
    binding.capabilities.propose = false;
    wb.store_mut()
        .append_record(
            LIBRARY_SCOPE,
            "chat_target",
            &serde_json::to_string(&binding).unwrap(),
        )
        .unwrap();
    wb.store_mut()
        .append_record(
            LIBRARY_SCOPE,
            "chat_target_set",
            &serde_json::to_string(&selection).unwrap(),
        )
        .unwrap();
}

fn reader(wb: &mut Workbench) -> (AuthenticatedActionContext, String) {
    membership(wb, "bob", "owner");
    let token = wb.mint_account_session("bob", "passkey", 3600).unwrap();
    (wb.authenticate_action_context(&token).unwrap(), token)
}

fn forget_database(path: &std::path::Path) {
    for suffix in ["", "-wal", "-shm"] {
        let file = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
        if file.exists() {
            std::fs::remove_file(file).unwrap();
        }
    }
}

#[test]
fn independent_read_only_correction_inspection_preserves_the_revoked_authors_erased_history() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded(dir.path(), &[""], true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    wb.revoke_account_session(&fixture.author_token);
    read_only(&mut wb, &fixture.command);
    deny(&mut wb, Action::Run);
    let inputs = dir.path().join("actions/inputs.sqlite");
    ContentStore::open(&inputs)
        .unwrap()
        .erase(
            &fixture.command.inputs["corrections"].version_ref,
            "erase original correction",
        )
        .unwrap();
    forget_database(&inputs);
    // Independent observation cannot require or recreate execution infrastructure.
    let coord = dir.path().join("actions/native/coord.sqlite");
    let items = dir.path().join("actions/native/items.sqlite");
    forget_database(&coord);
    forget_database(&items);
    let runtime_path = dir.path().join("actions/native/runtime.sqlite");
    let runtime_bytes = std::fs::read(&runtime_path).unwrap();
    let product = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    let event_count = || {
        product
            .query_row("SELECT COUNT(*) FROM events", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
    };
    let before = event_count();
    let evidence = wb
        .read_editor_corrections_evidence(&context, &fixture.command, &fixture.admission)
        .unwrap();
    let observed = wb
        .inspect_editor_correction_attempt(
            &context,
            &fixture.command,
            &fixture.admission,
            &fixture.effect,
            &fixture.run,
        )
        .unwrap();
    assert_eq!(evidence, observed.evidence);
    assert_eq!(observed.binding, fixture.original);
    assert_eq!(observed.receipt.as_ref().unwrap().request.actor, "alice");
    assert_eq!(observed.evidence.command.provenance.executor, "alice");
    assert_eq!(
        observed.evidence.effects[0].attempts[0].disposition,
        ExternalDisposition::Unknown
    );
    assert!(observed.evidence.terminal.is_none());
    assert_ne!(observed.evidence.read_policy, fixture.command.policy);
    let encoded = serde_json::to_string(&serde_json::json!([
        observed.evidence,
        observed.binding,
        observed.receipt
    ]))
    .unwrap();
    assert!(!encoded.contains("asserted base"));
    assert_eq!(event_count(), before);
    assert_eq!(std::fs::read(&runtime_path).unwrap(), runtime_bytes);
    for path in [&inputs, &coord, &items] {
        assert!(!path.exists(), "{}", path.display());
    }
}

#[test]
fn correction_inspection_rechecks_current_read_authority_despite_stale_caches() {
    for case in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let fixture = recorded(dir.path(), &[""], true);
        let mut wb = fixture.shared.lock_unpoisoned();
        let (context, token) = reader(&mut wb);
        match case {
            0 => {
                wb.revoke_account_session(&token);
            }
            1 => {
                membership(&mut wb, "bob", "member");
            }
            2 => {
                let (chat, _) = coordinates(&fixture.command);
                let id = wb.library.current_target_set(&chat).unwrap().members[0]
                    .target_id
                    .clone();
                let mut target = wb.library.work_targets[&id].clone();
                target.capabilities.read = false;
                wb.store_mut()
                    .append_record(
                        LIBRARY_SCOPE,
                        "work_target",
                        &serde_json::to_string(&target).unwrap(),
                    )
                    .unwrap();
                assert!(wb.library.work_targets[&id].capabilities.read);
            }
            _ => deny(&mut wb, Action::Access),
        }
        let before = std::fs::read(dir.path().join("actions/native/runtime.sqlite")).unwrap();
        assert!(
            wb.read_editor_corrections_evidence(&context, &fixture.command, &fixture.admission)
                .is_err(),
            "case {case}"
        );
        assert!(
            wb.inspect_editor_correction_attempt(
                &context,
                &fixture.command,
                &fixture.admission,
                &fixture.effect,
                &fixture.run
            )
            .is_err(),
            "case {case}"
        );
        assert_eq!(
            std::fs::read(dir.path().join("actions/native/runtime.sqlite")).unwrap(),
            before
        );
    }
}

#[test]
fn current_read_grants_cover_the_original_namespace_without_replacing_it() {
    for widening in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = recorded(dir.path(), if widening { &["notes"] } else { &[""] }, false);
        let mut wb = fixture.shared.lock_unpoisoned();
        let (context, _) = reader(&mut wb);
        let (chat, _) = coordinates(&fixture.command);
        path_ceiling(&mut wb, &chat, if widening { &[""] } else { &["notes"] });
        let result = wb.inspect_editor_correction_attempt(
            &context,
            &fixture.command,
            &fixture.admission,
            &fixture.effect,
            &fixture.run,
        );
        if widening {
            let observed = result.unwrap();
            assert_eq!(observed.binding.scope(), fixture.original.scope());
            assert!(observed.receipt.unwrap().outcomes[0].inserted);
        } else {
            assert!(result
                .err()
                .unwrap()
                .contains("original recording namespace"));
        }
    }
}

#[test]
fn missing_runtime_is_unavailable_and_observation_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded(dir.path(), &[""], true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let path = dir.path().join("actions/native/runtime.sqlite");
    forget_database(&path);
    assert!(wb
        .read_editor_corrections_evidence(&context, &fixture.command, &fixture.admission)
        .is_err());
    assert!(!path.exists());
    assert!(wb
        .inspect_editor_correction_attempt(
            &context,
            &fixture.command,
            &fixture.admission,
            &fixture.effect,
            &fixture.run
        )
        .is_err());
    assert!(!path.exists());
}

#[test]
fn correction_inspection_rejects_a_dispatch_hash_that_its_receipt_cannot_attest() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded(dir.path(), &[""], true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let runtime_path = dir.path().join("actions/native/runtime.sqlite");
    let fault = rusqlite::Connection::open(&runtime_path).unwrap();
    let raw: String = fault.query_row("SELECT payload_json FROM events WHERE instance_id = ?1 AND event_type = 'effect.run_started'", [&fixture.admission.instance_ref], |row| row.get(0)).unwrap();
    let mut payload: serde_json::Value = serde_json::from_str(&raw).unwrap();
    payload["metadata"]["resolution_recording"]["input_hash"] = "0".repeat(32).into();
    fault.execute("UPDATE events SET payload_json = ?1 WHERE instance_id = ?2 AND event_type = 'effect.run_started'", rusqlite::params![serde_json::to_string(&payload).unwrap(), fixture.admission.instance_ref]).unwrap();
    // Its original target receipt still exists, but contains no whole-input
    // hash and therefore cannot define the historical opaque-input mapping.
    assert_eq!(
        receipt(&wb, &fixture.command, &fixture.original).request,
        *fixture.original.batch()
    );
    assert!(wb
        .inspect_editor_correction_attempt(
            &context,
            &fixture.command,
            &fixture.admission,
            &fixture.effect,
            &fixture.run
        )
        .is_err());
}

fn named_files(root: &std::path::Path, name: &str, result: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            named_files(&entry.path(), name, result);
        } else if kind.is_file() && entry.file_name() == name {
            result.push(entry.path());
        }
    }
}

#[test]
fn unavailable_correction_receipts_and_mappings_remain_unknown_or_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded(dir.path(), &[""], true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let first = wb
        .inspect_editor_correction_attempt(
            &context,
            &fixture.command,
            &fixture.admission,
            &fixture.effect,
            &fixture.run,
        )
        .unwrap();
    assert!(first.receipt.is_some());
    let mut branches = Vec::new();
    named_files(dir.path(), "branches.sqlite", &mut branches);
    let mut removed = 0;
    for path in branches {
        let fault = rusqlite::Connection::open(path).unwrap();
        removed += fault
            .execute(
                "DELETE FROM resolution_batches WHERE operation_id = ?1",
                [&fixture.original.batch().operation_id],
            )
            .unwrap();
    }
    assert_eq!(removed, 1);
    let missing = wb
        .inspect_editor_correction_attempt(
            &context,
            &fixture.command,
            &fixture.admission,
            &fixture.effect,
            &fixture.run,
        )
        .unwrap();
    assert_eq!(missing.evidence, first.evidence);
    assert!(missing.receipt.is_none());
    assert_eq!(
        missing.evidence.effects[0].attempts[0].disposition,
        ExternalDisposition::Unknown
    );
    let scope = crate::action_input_binding::input_binding_scope(
        &fixture.command.issuer,
        &fixture.command.inputs["corrections"],
    )
    .unwrap();
    let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    fault
        .execute("DELETE FROM events WHERE scope_id = ?1", [&scope])
        .unwrap();
    fault
        .execute("DELETE FROM command_receipts WHERE scope_id = ?1", [&scope])
        .unwrap();
    let before: i64 = fault
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        wb.read_editor_corrections_evidence(&context, &fixture.command, &fixture.admission)
            .unwrap(),
        first.evidence
    );
    assert!(wb
        .inspect_editor_correction_attempt(
            &context,
            &fixture.command,
            &fixture.admission,
            &fixture.effect,
            &fixture.run
        )
        .is_err());
    assert_eq!(
        fault
            .query_row("SELECT COUNT(*) FROM events", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        before
    );
}

#[path = "resolution_recording_reconciliation_tests.rs"]
mod reconciliation;

#[test]
fn correction_inspection_preserves_the_legacy_pending_call_shape() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = recorded_input_with_call_shape(dir.path(), &[""], true, &input(""), false, true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let observed = wb
        .inspect_editor_correction_attempt(
            &context,
            &fixture.command,
            &fixture.admission,
            &fixture.effect,
            &fixture.run,
        )
        .unwrap();
    assert_eq!(observed.binding, fixture.original);
    assert_eq!(observed.receipt.unwrap().request, *fixture.original.batch());
}
