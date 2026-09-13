use super::*;
use crate::file_action_factory::EditorCorrections;
use whipplescript_store::{
    text_merge::RegionResolution, vcs_resolution_recording::ResolutionRecordingInput,
};

fn input() -> ResolutionRecordingInput {
    ResolutionRecordingInput::new(vec![RegionResolution {
        base_text: "private editor draft".into(),
        ours_text: "asserted local".into(),
        theirs_text: "asserted remote".into(),
        resolution_text: "derived correction".into(),
    }])
    .unwrap()
}

fn dispatch_count(wb: &Workbench) -> i64 {
    rusqlite::Connection::open(wb.store_ref().path())
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM events WHERE kind = ?1",
            [gaugedesk_store::command_dispatch::DISPATCH_KIND],
            |row| row.get(0),
        )
        .unwrap()
}

fn coordinates(command: &HostActionCommand) -> (String, String) {
    let (_, _, chat): (String, String, String) = serde_json::from_str(&command.scope).unwrap();
    let (_, _, path): (String, String, String) = serde_json::from_str(
        command.resources["target"]
            .resource
            .selector
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    (chat, path)
}

fn source(
    wb: &mut Workbench,
    context: &AuthenticatedActionContext,
    storage: &NativeActionStorage,
    command: &HostActionCommand,
    admission: &ActionAdmissionReceipt,
    attempt: EditorFileSaveAttempt<'_>,
) -> RetainedEditorFileSaveSource {
    let observed = wb
        .observe_editor_file_save(context, command, admission, attempt)
        .unwrap();
    wb.retain_editor_file_save_source(context, storage, "saved-for-correction", &observed, attempt)
        .unwrap()
}

fn original(wb: &Workbench, cause: &ActionCause) -> (String, SignedSource) {
    let (scope, key): (String, String) = serde_json::from_str(&cause.record_ref).unwrap();
    assert_eq!(key, KEY);
    let records = wb.store_ref().records(&scope, KIND).unwrap();
    assert_eq!(records.len(), 1);
    (scope, serde_json::from_str(&records[0]).unwrap())
}

#[test]
fn derived_correction_keeps_original_attribution_unknown_and_restart_safe_outbox() {
    for interrupted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = save_fixture(dir.path(), interrupted);
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
        let (context, token) = reader(&mut wb);
        wb.revoke_account_session(&fixture.token);
        let (chat, path) = coordinates(&fixture.command);
        let input = input();
        let request = EditorCorrections {
            chat_id: &chat,
            request_id: "derive",
            path: &path,
            corrections: &input,
        };
        let before_runtime =
            std::fs::read(dir.path().join("actions/native/runtime.sqlite")).unwrap();
        let (scope, before_source) = original(&wb, source.cause());
        let admitted = wb
            .admit_saved_source_corrections(&context, &storage, &request, source.cause())
            .unwrap();
        assert!(!admitted.replayed);
        assert_eq!(admitted.command.provenance.initiator, "bob");
        assert_eq!(admitted.command.provenance.executor, "bob");
        assert_eq!(
            admitted.command.provenance.origin,
            "editor.corrections.derived"
        );
        assert_eq!(
            admitted.command.provenance.causes,
            vec![source.cause().clone()]
        );
        assert!(admitted.command.provenance.delegation.is_empty());
        assert!(!serde_json::to_string(&admitted.command)
            .unwrap()
            .contains("derived correction"));
        let committed = wb
            .store_mut()
            .committed_dispatch::<ProductActionAdmission>(
                &admitted.command.instance_ref().unwrap(),
                "derive",
            )
            .unwrap()
            .unwrap();
        assert_eq!(committed.command, admitted.command);
        assert_eq!(
            before_source.statement.original_provenance.initiator,
            "alice"
        );
        assert_eq!(before_source.statement.observer, "alice");
        if interrupted {
            assert_eq!(
                before_source.statement.attempt.disposition,
                whipplescript_store::effect_recovery::ExternalDisposition::Unknown
            );
        }
        assert_eq!(
            original(&wb, source.cause()).1.statement,
            before_source.statement
        );
        assert_eq!(
            std::fs::read(dir.path().join("actions/native/runtime.sqlite")).unwrap(),
            before_runtime
        );
        drop(wb);
        let reopened = crate::open_workbench(dir.path()).unwrap();
        let mut wb = reopened.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let replay = wb
            .admit_saved_source_corrections(&context, &storage, &request, source.cause())
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.command, admitted.command);
        assert_eq!(
            wb.store_ref()
                .records(
                    &admitted.command.instance_ref().unwrap(),
                    gaugedesk_store::command_dispatch::DISPATCH_KIND
                )
                .unwrap()
                .len(),
            1
        );
        assert_eq!(wb.store_ref().records(&scope, KIND).unwrap().len(), 1);
    }
}

#[test]
fn derived_correction_refuses_substituted_causes_and_current_reader_revocation() {
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
    let (chat, path) = coordinates(&fixture.command);
    let input = input();
    let request = EditorCorrections {
        chat_id: &chat,
        request_id: "refused-derived",
        path: &path,
        corrections: &input,
    };
    let before = dispatch_count(&wb);
    for field in ["authority", "digest", "record", "key"] {
        let mut changed = source.cause().clone();
        match field {
            "authority" => changed.authority = "foreign-home".into(),
            "digest" => changed.digest = "0".repeat(64),
            "record" => changed.record_ref = serde_json::to_string(&("missing", KEY)).unwrap(),
            "key" => {
                let (scope, _): (String, String) =
                    serde_json::from_str(&changed.record_ref).unwrap();
                changed.record_ref = serde_json::to_string(&(scope, "other")).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            wb.admit_saved_source_corrections(&context, &storage, &request, &changed)
                .is_err(),
            "{field}"
        );
    }
    wb.revoke_account_session(&token);
    assert!(wb
        .admit_saved_source_corrections(&context, &storage, &request, source.cause())
        .is_err());
    assert_eq!(dispatch_count(&wb), before);
}

#[test]
fn derived_correction_never_recreates_erased_source_or_derived_input() {
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
    let (chat, path) = coordinates(&fixture.command);
    let input = input();
    let request = EditorCorrections {
        chat_id: &chat,
        request_id: "erase-derived",
        path: &path,
        corrections: &input,
    };
    let admitted = wb
        .admit_saved_source_corrections(&context, &storage, &request, source.cause())
        .unwrap();
    let derived = &admitted.command.inputs["corrections"];
    ContentStore::open(dir.path().join("actions/inputs.sqlite"))
        .unwrap()
        .erase(&derived.version_ref, "erase-derived")
        .unwrap();
    assert!(wb
        .admit_saved_source_corrections(&context, &storage, &request, source.cause())
        .is_err());
    assert!(storage.inputs().resolve(derived).is_err());
    ContentStore::open(dir.path().join("actions/inputs.sqlite"))
        .unwrap()
        .erase(&source.input().version_ref, "erase-source")
        .unwrap();
    let next = EditorCorrections {
        request_id: "after-source-erasure",
        ..request
    };
    assert!(wb
        .admit_saved_source_corrections(&context, &storage, &next, source.cause())
        .is_err());
    assert!(storage.inputs().resolve(source.input()).is_err());
    assert_eq!(
        wb.store_ref()
            .records(
                &admitted.command.instance_ref().unwrap(),
                gaugedesk_store::command_dispatch::DISPATCH_KIND
            )
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn derived_correction_rejects_stricter_retained_labels_after_current_policy_relaxes() {
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
    let (_, original) = original(&wb, source.cause());
    // A valid Home-attested older source carries a compartment absent from the
    // current target. Build that retained fixture without changing any history.
    let mut statement = original.statement;
    statement.request_id = "historical-source-policy".into();
    statement
        .restrictions
        .reader
        .insert("residency:earlier-source".into());
    statement.input = storage
        .inputs()
        .prepare_unerased(
            "saved_source",
            &label(&statement.restrictions).unwrap(),
            "private editor draft",
        )
        .unwrap();
    let scope = source_scope(wb.home_id().as_str(), "bob", &statement.request_id).unwrap();
    let snapshot = statement.snapshot().unwrap();
    let key = SigningKey::from_seed(&wb.governance_seed()).unwrap();
    let signed = SignedSource {
        signature: key
            .sign(&statement.signing_bytes().unwrap())
            .as_bytes()
            .to_vec(),
        statement,
    };
    wb.store_mut()
        .admit_record_facts(
            &scope,
            KEY,
            &snapshot,
            &[CommandRecordFact {
                scope_id: scope.clone(),
                kind: KIND.into(),
                payload: serde_json::to_string(&signed).unwrap(),
            }],
        )
        .unwrap();
    let cause = ActionCause {
        authority: wb.authority().as_str().into(),
        record_ref: serde_json::to_string(&(&scope, KEY)).unwrap(),
        digest: digest(snapshot.as_bytes()),
    };
    let (chat, path) = coordinates(&fixture.command);
    let input = input();
    let request = EditorCorrections {
        chat_id: &chat,
        request_id: "restricted-derived",
        path: &path,
        corrections: &input,
    };
    let error = match wb.admit_saved_source_corrections(&context, &storage, &request, &cause) {
        Ok(_) => panic!("discarded historical source restriction"),
        Err(error) => error,
    };
    assert!(
        error.contains("retained saved-source restrictions"),
        "{error}"
    );
}

#[test]
fn derived_correction_publication_requires_live_original_target_retention() {
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
    let (_, statement) = original(&wb, source.cause());
    let hash = &statement.statement.content_hash;
    let mut paths = Vec::new();
    target_databases(dir.path(), &mut paths);
    let paths: Vec<_> = paths
        .into_iter()
        .filter(|path| {
            ContentStore::open(path)
                .unwrap()
                .get(hash)
                .unwrap()
                .is_some()
        })
        .collect();
    assert_eq!(paths.len(), 1);
    let (chat, path) = coordinates(&fixture.command);
    let input = input();
    let request = EditorCorrections {
        chat_id: &chat,
        request_id: "held-derived",
        path: &path,
        corrections: &input,
    };
    let before = dispatch_count(&wb);
    let eraser = rusqlite::Connection::open(&paths[0]).unwrap();
    eraser.execute_batch("BEGIN IMMEDIATE").unwrap();
    let denied = wb.admit_saved_source_corrections(&context, &storage, &request, source.cause());
    eraser.execute_batch("ROLLBACK").unwrap();
    assert!(
        denied.is_err(),
        "derived command published without original target retention"
    );
    assert_eq!(dispatch_count(&wb), before);
    let admitted = wb
        .admit_saved_source_corrections(&context, &storage, &request, source.cause())
        .unwrap();
    assert!(!admitted.replayed);
    assert_eq!(dispatch_count(&wb), before + 1);
    ContentStore::open(&paths[0])
        .unwrap()
        .erase(hash, "erase original target")
        .unwrap();
    let later = EditorCorrections {
        request_id: "erased-target-derived",
        ..request
    };
    assert!(storage.inputs().resolve(source.input()).is_ok());
    assert!(wb
        .admit_saved_source_corrections(&context, &storage, &later, source.cause())
        .is_err());
    assert_eq!(dispatch_count(&wb), before + 1);
    assert!(ContentStore::open(&paths[0])
        .unwrap()
        .get(hash)
        .unwrap()
        .is_none());
}

#[test]
fn derived_correction_failed_outbox_publication_retries_without_duplicate_sources() {
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
    let (chat, path) = coordinates(&fixture.command);
    let input = input();
    let request = EditorCorrections {
        chat_id: &chat,
        request_id: "failed-derived",
        path: &path,
        corrections: &input,
    };
    let before = dispatch_count(&wb);
    let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    fault.execute_batch("CREATE TRIGGER lose_derived_outbox BEFORE INSERT ON events WHEN NEW.kind = 'runtime_command_dispatch_v1' BEGIN SELECT RAISE(ABORT, 'lost derived outbox'); END;").unwrap();
    assert!(wb
        .admit_saved_source_corrections(&context, &storage, &request, source.cause())
        .is_err());
    assert_eq!(dispatch_count(&wb), before);
    fault
        .execute_batch("DROP TRIGGER lose_derived_outbox")
        .unwrap();
    let admitted = wb
        .admit_saved_source_corrections(&context, &storage, &request, source.cause())
        .unwrap();
    assert!(!admitted.replayed);
    let replay = wb
        .admit_saved_source_corrections(&context, &storage, &request, source.cause())
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.command, admitted.command);
    assert_eq!(dispatch_count(&wb), before + 1);
    original(&wb, source.cause());
}

#[path = "file_action_derived_delivery_tests.rs"]
mod delivery;
