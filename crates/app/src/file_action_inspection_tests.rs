use super::*;
use crate::{
    file_action_factory::{
        tests::{home_storage_fixture, membership},
        NativeActionStorageConfig, NativeEditorSaveProgress,
    },
    LockUnpoisoned, SharedWorkbench,
};
use whipplescript_kernel::file_lease::FileLeasePolicy;
use whipplescript_store::SqliteStore;

pub(super) struct Fixture {
    pub(super) shared: SharedWorkbench,
    pub(super) command: HostActionCommand,
    pub(super) admission: ActionAdmissionReceipt,
    effect: String,
    run: String,
    pub(super) token: String,
}
impl Fixture {
    pub(super) fn attempt(&self) -> EditorFileSaveAttempt<'_> {
        EditorFileSaveAttempt {
            effect_id: &self.effect,
            run_id: &self.run,
        }
    }
}
pub(super) fn saved(root: &std::path::Path) -> Fixture {
    save_fixture(root, false)
}
pub(super) fn save_fixture(root: &std::path::Path, interrupted: bool) -> Fixture {
    let (shared, command, storage, token) = home_storage_fixture(
        root,
        NativeActionStorageConfig {
            input_byte_limit: 4096,
            file_lease: FileLeasePolicy::new(17).unwrap(),
        },
    );
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let grant = wb
        .authorize_editor_file_save_dispatch(&context, storage.inputs(), &command, "observed-save")
        .unwrap();
    let mut driver = wb
        .start_editor_file_save_driver(&storage, &command, &grant.grant_ref)
        .unwrap();
    assert!(matches!(
        wb.step_editor_file_save_driver(&storage, &mut driver)
            .unwrap(),
        NativeEditorSaveProgress::Advanced
    ));
    let fault = rusqlite::Connection::open(root.join("actions/native/runtime.sqlite")).unwrap();
    if interrupted {
        fault.execute_batch("CREATE TRIGGER lose_observed_terminal BEFORE INSERT ON events WHEN NEW.event_type = 'effect.terminal' BEGIN SELECT RAISE(ABORT, 'lost observed settlement'); END;").unwrap();
        assert!(wb
            .step_editor_file_save_driver(&storage, &mut driver)
            .is_err());
        fault
            .execute_batch("DROP TRIGGER lose_observed_terminal")
            .unwrap();
    } else {
        assert!(matches!(
            wb.step_editor_file_save_driver(&storage, &mut driver)
                .unwrap(),
            NativeEditorSaveProgress::Advanced
        ));
        assert!(matches!(
            wb.step_editor_file_save_driver(&storage, &mut driver)
                .unwrap(),
            NativeEditorSaveProgress::Saved(_)
        ));
    }
    let acknowledgments = wb
        .store_ref()
        .records(
            &command.instance_ref().unwrap(),
            crate::host_action_delivery::ACKNOWLEDGMENT_KIND,
        )
        .unwrap();
    let acknowledgment: crate::host_action_delivery::RuntimeAcknowledgment =
        serde_json::from_str(&acknowledgments[0]).unwrap();
    let admission = acknowledgment.receipt;
    drop(driver);
    let runtime = SqliteStore::open_read_only(root.join("actions/native/runtime.sqlite")).unwrap();
    let effect = runtime
        .list_effects(&admission.instance_ref)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == "file.write")
        .unwrap()
        .effect_id;
    let run = runtime
        .list_runs(&admission.instance_ref)
        .unwrap()
        .into_iter()
        .find(|r| r.effect_id == effect)
        .unwrap()
        .run_id;
    drop(wb);
    Fixture {
        shared,
        command,
        admission,
        effect,
        run,
        token,
    }
}
pub(super) fn reader(wb: &mut Workbench) -> (AuthenticatedActionContext, String) {
    membership(wb, "bob", "owner");
    let token = wb.mint_account_session("bob", "passkey", 3600).unwrap();
    (wb.authenticate_action_context(&token).unwrap(), token)
}
fn forget(path: &std::path::Path) {
    for suffix in ["", "-wal", "-shm"] {
        let path = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
        if path.exists() {
            std::fs::remove_file(path).unwrap();
        }
    }
}

#[test]
fn independent_saved_input_observation_preserves_original_bytes_and_author_after_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    wb.revoke_account_session(&fixture.token);
    // No input store is needed to inspect a completed save.
    forget(&dir.path().join("actions/inputs.sqlite"));
    let runtime_path = dir.path().join("actions/native/runtime.sqlite");
    let before = std::fs::read(&runtime_path).unwrap();
    let observation = wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt(),
        )
        .unwrap();
    assert_eq!(observation.observer(), "bob");
    assert_eq!(observation.evidence().command.provenance.initiator, "alice");
    assert_eq!(
        observation.saved().unwrap().accepted_content,
        "private editor draft"
    );
    assert!(observation.restrictions().writer.is_empty());
    assert!(!observation.restrictions().reader.is_empty());
    assert_eq!(std::fs::read(&runtime_path).unwrap(), before);
    assert!(!dir.path().join("actions/inputs.sqlite").exists());
    let replay = wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt(),
        )
        .unwrap();
    assert_eq!(replay.evidence(), observation.evidence());
    assert_eq!(
        replay.saved().unwrap().receipt_json,
        observation.saved().unwrap().receipt_json
    );
}

#[test]
fn independent_saved_input_observation_refuses_revoked_reader_and_substituted_history() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, token) = reader(&mut wb);
    for change in ["input", "scope", "actor"] {
        let mut command = fixture.command.clone();
        match change {
            "input" => {
                command.inputs.get_mut("content").unwrap().version_ref = "substituted".into()
            }
            "scope" => command.scope = "another-target".into(),
            "actor" => command.provenance.initiator = "bob".into(),
            _ => unreachable!(),
        }
        assert!(
            wb.observe_editor_file_save(&context, &command, &fixture.admission, fixture.attempt())
                .is_err(),
            "{change}"
        );
    }
    assert!(wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            EditorFileSaveAttempt {
                effect_id: &fixture.effect,
                run_id: "another-run"
            }
        )
        .is_err());
    wb.revoke_account_session(&token);
    assert!(wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt()
        )
        .is_err());
    let (context, _) = reader(&mut wb);
    let runtime_path = dir.path().join("actions/native/runtime.sqlite");
    forget(&runtime_path);
    assert!(wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt()
        )
        .is_err());
    assert!(!runtime_path.exists());
}

#[test]
fn saved_input_read_policy_preserves_stricter_original_input_compartments() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let (_, _, chat): (String, String, String) =
        serde_json::from_str(&fixture.command.scope).unwrap();
    let (_, _, path): (String, String, String) = serde_json::from_str(
        fixture.command.resources["target"]
            .resource
            .selector
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    let mut current = current_target_authority(
        wb.store_ref(),
        wb.home_id(),
        &context,
        &NativeTargetIntent {
            chat_id: &chat,
            request_id: "inspect-policy",
            path: &path,
        },
        NativeActionKind::InspectHistory,
    )
    .unwrap();
    let original_scope = resolution_scope::original(&fixture.command).unwrap();
    let mut original = current.policy.clone();
    original
        .resources
        .get_mut("file:/action/input")
        .unwrap()
        .reader
        .insert("retained-private-input".into());
    assert!(read_policy(&current, &original_scope, &original).is_err());
    current
        .read_clearances
        .insert("retained-private-input".into());
    let (policy, restrictions) = read_policy(&current, &original_scope, &original).unwrap();
    assert!(restrictions.reader.contains("retained-private-input"));
    assert!(restrictions.writer.is_empty());
    assert!(policy.capabilities.is_empty());
    assert!(policy
        .resources
        .values()
        .all(|resource| resource == &restrictions));
}

#[test]
fn saved_input_read_survives_restart_with_read_only_target_and_denied_execution() {
    use gaugedesk_core::abac::{Action, Condition, Constraint, Policy, Rule};
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let (_, _, chat): (String, String, String) =
        serde_json::from_str(&fixture.command.scope).unwrap();
    let (_, _, path): (String, String, String) = serde_json::from_str(
        fixture.command.resources["target"]
            .resource
            .selector
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    let mut wb = fixture.shared.lock_unpoisoned();
    let (_, token) = reader(&mut wb);
    let library = Library::rebuild(wb.store_ref()).unwrap();
    let mut selection = library.current_target_set(&chat).unwrap().clone();
    let mut target = library.work_targets[&selection.members[0].target_id].clone();
    target.capabilities.propose = false;
    let mut binding = library.chat_targets[&chat].clone();
    binding.capabilities.propose = false;
    selection.revision += 1;
    selection.members[0].participation = TargetParticipationMode::ReadOnly;
    selection.members[0].capability_ceiling.propose = false;
    for (kind, value) in [
        ("work_target", serde_json::to_string(&target).unwrap()),
        ("chat_target", serde_json::to_string(&binding).unwrap()),
        (
            "chat_target_set",
            serde_json::to_string(&selection).unwrap(),
        ),
    ] {
        wb.store_mut()
            .append_record(LIBRARY_SCOPE, kind, &value)
            .unwrap();
    }
    let deny = |action| crate::org::PolicyRecord {
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
            &serde_json::to_string(&deny(Action::Run)).unwrap(),
        )
        .unwrap();
    drop(wb);
    let reopened = crate::open_workbench(dir.path()).unwrap();
    let mut wb = reopened.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    // A manual materialization remains different from the retained saved cut.
    wb.engagements[&chat]
        .write_file(&path, "manual materialization")
        .unwrap();
    let observation = wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt(),
        )
        .unwrap();
    assert_eq!(
        observation.saved().unwrap().accepted_content,
        "private editor draft"
    );
    assert_eq!(
        wb.engagements[&chat].read_file(&path).unwrap(),
        "manual materialization"
    );
    wb.store_mut()
        .append_record(
            ORG_SCOPE,
            "policy",
            &serde_json::to_string(&deny(Action::Access)).unwrap(),
        )
        .unwrap();
    assert!(wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt()
        )
        .is_err());
}

#[test]
fn saved_input_observation_keeps_interrupted_outcome_unknown_and_cannot_restore_erased_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = save_fixture(dir.path(), true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let observation = wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt(),
        )
        .unwrap();
    let attempt = observation
        .evidence()
        .effects
        .iter()
        .find(|effect| effect.effect_id == fixture.effect)
        .unwrap()
        .attempts
        .iter()
        .find(|attempt| attempt.run_id == fixture.run)
        .unwrap();
    assert_eq!(
        attempt.disposition,
        whipplescript_store::effect_recovery::ExternalDisposition::Unknown
    );
    let recovered = observation.saved().unwrap();
    assert_eq!(recovered.accepted_content, "private editor draft");
    let hash = whipplescript_store::stable_hash_hex(&recovered.accepted_content);
    assert_eq!(
        super::super::tests::erase_fixture_result(dir.path(), &hash),
        1
    );
    assert!(wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt()
        )
        .is_err());
}
