use super::super::tests::{forget, reader, save_fixture, saved};
use super::*;
use crate::{
    file_action_factory::{tests::home_storage_fixture, NativeActionStorageConfig},
    LockUnpoisoned,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use whipplescript_kernel::file_lease::FileLeasePolicy;

fn identity(command: &HostActionCommand) -> EditorFileSaveRequest<'_> {
    EditorFileSaveRequest {
        issuer: &command.issuer,
        scope: &command.scope,
        request_id: &command.request_id,
    }
}

#[test]
fn saved_content_request_returns_the_admitted_cut_without_importing_newer_files() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let request = identity(&fixture.command);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, token) = reader(&mut wb);
    wb.revoke_account_session(&fixture.token);
    let facts = wb
        .observe_editor_file_saved_results_by_request(&context, request)
        .unwrap();
    let expected = facts.results()[0].result.clone();
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
    wb.engagements[&chat]
        .write_file(&path, "newer physical content")
        .unwrap();
    let newer = wb.engagements[&chat]
        .commit_turn("newer fixture revision")
        .unwrap()
        .unwrap()
        .0;
    assert_ne!(newer, expected.cut_id);
    wb.engagements[&chat]
        .write_file(&path, "uncommitted external text")
        .unwrap();
    let workspace_before = wb.engagements[&chat].observe().unwrap();
    assert_eq!(
        workspace_before.recorded_cut.as_deref(),
        Some(newer.as_str())
    );
    assert!(!workspace_before.changed_paths.is_empty());
    for file in [
        "inputs.sqlite",
        "native/coord.sqlite",
        "native/items.sqlite",
    ] {
        forget(&dir.path().join("actions").join(file));
    }
    let history = wb
        .store_ref()
        .retained_events(&fixture.command.instance_ref().unwrap())
        .unwrap();
    let read = wb
        .observe_editor_file_saved_content_by_request(&context, request, &expected.cut_id)
        .unwrap();
    assert_eq!(read.content(), "private editor draft");
    assert_eq!(read.result(), &expected);
    assert_eq!(read.observer(), "bob");
    assert_eq!(read.restrictions(), facts.restrictions());
    assert_eq!(
        wb.engagements[&chat].read_file(&path).unwrap(),
        "uncommitted external text"
    );
    assert_eq!(
        wb.engagements[&chat].observe().unwrap(),
        workspace_before,
        "saved-content read imported or materialized external files"
    );
    assert_eq!(
        wb.store_ref()
            .retained_events(&fixture.command.instance_ref().unwrap())
            .unwrap(),
        history
    );
    assert!(!dir.path().join("actions/inputs.sqlite").exists());
    assert!(wb
        .observe_editor_file_saved_content_by_request(&context, request, &newer)
        .is_err());
    wb.revoke_account_session(&token);
    assert!(wb
        .observe_editor_file_saved_content_by_request(&context, request, &expected.cut_id)
        .is_err());
}

#[test]
fn saved_content_request_requires_product_admission_even_when_target_bytes_exist() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = save_fixture(dir.path(), true);
    let request = identity(&fixture.command);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let observed = wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt(),
        )
        .unwrap();
    let saved = observed.saved().unwrap();
    assert_eq!(saved.accepted_content, "private editor draft");
    let cut = match &saved.receipt.result {
        whipplescript_store::vcs_file_save::SaveResult::Written { cut_id, .. }
        | whipplescript_store::vcs_file_save::SaveResult::Merged { cut_id, .. } => cut_id.clone(),
        _ => panic!("fixture did not write"),
    };
    assert!(wb
        .observe_editor_file_saved_results_by_request(&context, request)
        .unwrap()
        .results()
        .is_empty());
    assert!(wb
        .observe_editor_file_saved_content_by_request(&context, request, &cut)
        .is_err());
    assert!(wb
        .observe_editor_file_saved_results_by_request(&context, request)
        .unwrap()
        .results()
        .is_empty());
}

#[test]
fn saved_content_request_refuses_erasure_without_hiding_the_saved_fact() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let request = identity(&fixture.command);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let facts = wb
        .observe_editor_file_saved_results_by_request(&context, request)
        .unwrap();
    let expected = facts.results()[0].result.clone();
    assert_eq!(
        super::super::super::tests::erase_fixture_result(dir.path(), &expected.content_hash),
        1
    );
    assert!(wb
        .observe_editor_file_saved_content_by_request(&context, request, &expected.cut_id)
        .is_err());
    assert_eq!(
        wb.observe_editor_file_saved_results_by_request(&context, request)
            .unwrap()
            .results()[0]
            .result,
        expected
    );
    forget(&dir.path().join("actions/native/runtime.sqlite"));
    assert!(wb
        .observe_editor_file_saved_content_by_request(&context, request, &expected.cut_id)
        .is_err());
    assert!(!dir.path().join("actions/native/runtime.sqlite").exists());
    assert_eq!(
        wb.observe_editor_file_saved_results_by_request(&context, request)
            .unwrap()
            .results()[0]
            .result,
        expected
    );
}

#[test]
fn request_observation_recovers_original_command_and_saved_fact_without_execution_storage() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let request = identity(&fixture.command);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, token) = reader(&mut wb);
    wb.revoke_account_session(&fixture.token);
    let history = wb
        .store_ref()
        .retained_events(&fixture.command.instance_ref().unwrap())
        .unwrap();
    let observed = wb
        .observe_editor_file_save_request(&context, request)
        .unwrap();
    assert_eq!(observed.command(), &fixture.command);
    assert_eq!(observed.observer(), "bob");
    assert_eq!(observed.command().provenance.initiator, "alice");
    assert_eq!(observed.command().provenance.executor, "alice");
    assert!(!observed.restrictions().reader.is_empty());
    assert!(observed.restrictions().writer.is_empty());
    let execution = wb
        .observe_editor_file_save_execution_by_request(&context, request)
        .unwrap();
    assert!(execution.runtime().is_some());
    assert_eq!(execution.command(), observed.command());
    assert_eq!(execution.restrictions(), observed.restrictions());
    let expected = wb
        .observe_editor_file_saved_results_by_request(&context, request)
        .unwrap();
    assert_eq!(expected.results().len(), 1);
    for file in [
        "inputs.sqlite",
        "native/runtime.sqlite",
        "native/coord.sqlite",
        "native/items.sqlite",
    ] {
        forget(&dir.path().join("actions").join(file));
    }
    wb.engagements.clear();
    for _ in 0..2 {
        let recovered = wb
            .observe_editor_file_save_request(&context, request)
            .unwrap();
        assert_eq!(recovered.command(), observed.command());
        assert_eq!(recovered.restrictions(), observed.restrictions());
        let product = wb
            .observe_editor_file_saved_results_by_request(&context, request)
            .unwrap();
        assert_eq!(product.results()[0].result, expected.results()[0].result);
        assert_eq!(
            product.results()[0].position,
            expected.results()[0].position
        );
        assert_eq!(product.restrictions(), observed.restrictions());
        assert!(wb
            .observe_editor_file_save_execution_by_request(&context, request)
            .is_err());
    }
    assert_eq!(
        wb.store_ref()
            .retained_events(&fixture.command.instance_ref().unwrap())
            .unwrap(),
        history
    );
    assert!(!dir.path().join("actions/inputs.sqlite").exists());
    assert!(!dir.path().join("actions/native/runtime.sqlite").exists());
    assert!(wb.engagements.is_empty());
    wb.revoke_account_session(&token);
    assert_eq!(
        wb.observe_editor_file_save_request(&context, request).err(),
        Some(unavailable())
    );
    assert!(wb
        .observe_editor_file_saved_results_by_request(&context, request)
        .is_err());
}

#[test]
fn request_observation_preserves_pending_and_interrupted_evidence_without_redelivery() {
    for interrupted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (shared, command) = if interrupted {
            let fixture = save_fixture(dir.path(), true);
            (fixture.shared, fixture.command)
        } else {
            let (shared, command, storage, _) = home_storage_fixture(
                dir.path(),
                NativeActionStorageConfig {
                    input_byte_limit: 4096,
                    file_lease: FileLeasePolicy::new(17).unwrap(),
                },
            );
            drop(storage);
            (shared, command)
        };
        let mut wb = shared.lock_unpoisoned();
        let (context, _) = reader(&mut wb);
        let scope = command.instance_ref().unwrap();
        let before = wb.store_ref().retained_events(&scope).unwrap();
        let runtime_path = dir.path().join("actions/native/runtime.sqlite");
        let runtime_before = std::fs::read(&runtime_path).ok();
        let request = identity(&command);
        let execution = wb
            .observe_editor_file_save_execution_by_request(&context, request)
            .unwrap();
        assert_eq!(execution.runtime().is_some(), interrupted);
        if interrupted {
            assert!(execution
                .runtime()
                .unwrap()
                .effects
                .iter()
                .flat_map(|effect| &effect.attempts)
                .any(|attempt| attempt.disposition
                    == whipplescript_store::effect_recovery::ExternalDisposition::Unknown));
        }
        assert!(wb
            .observe_editor_file_saved_results_by_request(&context, request)
            .unwrap()
            .results()
            .is_empty());
        assert_eq!(wb.store_ref().retained_events(&scope).unwrap(), before);
        assert_eq!(std::fs::read(runtime_path).ok(), runtime_before);
    }
}

#[test]
fn request_observation_does_not_fall_back_from_original_identity_or_disclose_refusal_details() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, token) = reader(&mut wb);
    let request = identity(&fixture.command);
    let alternate_scope = format!(" {}", request.scope);
    for other in [
        EditorFileSaveRequest {
            issuer: "",
            ..request
        },
        EditorFileSaveRequest {
            issuer: "another-home",
            ..request
        },
        EditorFileSaveRequest {
            scope: "",
            ..request
        },
        EditorFileSaveRequest {
            scope: &alternate_scope,
            ..request
        },
        EditorFileSaveRequest {
            request_id: "",
            ..request
        },
        EditorFileSaveRequest {
            request_id: "response-never-retained",
            ..request
        },
    ] {
        assert_eq!(
            wb.observe_editor_file_save_request(&context, other).err(),
            Some(unavailable())
        );
    }
    assert!(wb
        .observe_editor_file_save_request(&context, request)
        .is_ok());
    wb.revoke_account_session(&token);
    assert_eq!(
        wb.observe_editor_file_save_request(&context, request).err(),
        Some(unavailable())
    );
}

#[test]
fn request_observation_refuses_missing_admission_receipt_or_outbox_without_repair() {
    for damage in ["receipt", "command", "admission", "outbox"] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = saved(dir.path());
        let mut wb = fixture.shared.lock_unpoisoned();
        let (context, _) = reader(&mut wb);
        let scope = fixture.command.instance_ref().unwrap();
        let sql = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
        match damage {
            "receipt" => sql.execute("DELETE FROM command_receipts WHERE scope_id = ?1", [&scope]),
            "command" => sql.execute("DELETE FROM commands WHERE scope_id = ?1", [&scope]),
            "admission" => sql.execute(
                "DELETE FROM events WHERE scope_id = ?1 AND kind = 'host_action_admission_v1'",
                [&scope],
            ),
            "outbox" => sql.execute(
                "DELETE FROM events WHERE scope_id = ?1 AND kind = 'runtime_command_dispatch_v1'",
                [&scope],
            ),
            _ => unreachable!(),
        }
        .unwrap();
        let history = wb.store_ref().retained_events(&scope).unwrap();
        assert_eq!(
            wb.observe_editor_file_save_request(&context, identity(&fixture.command))
                .err(),
            Some(unavailable()),
            "{damage}"
        );
        assert_eq!(wb.store_ref().retained_events(&scope).unwrap(), history);
    }
}

#[test]
fn request_observation_refuses_receipted_aliases_of_another_original_identity() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let request = identity(&fixture.command);
    let original = wb
        .store_mut()
        .committed_dispatch::<ProductActionAdmission>(
            &fixture.command.instance_ref().unwrap(),
            request.request_id,
        )
        .unwrap()
        .unwrap();
    for alias in [
        EditorFileSaveRequest {
            issuer: "alias-issuer",
            ..request
        },
        EditorFileSaveRequest {
            scope: "alias-scope",
            ..request
        },
        EditorFileSaveRequest {
            request_id: "alias-request",
            ..request
        },
    ] {
        let scope = HostActionCommand::instance_ref_for_request(
            alias.issuer,
            alias.scope,
            alias.request_id,
        )
        .unwrap();
        // A valid store receipt/outbox is not sufficient: its embedded command
        // must name the exact request that was looked up. The original remains
        // authorized and readable, so only the identity binding rejects this.
        wb.store_mut()
            .admit_with_dispatch::<ProductActionAdmission>(
                &scope,
                alias.request_id,
                fixture.command.clone(),
                &original.dispatch,
            )
            .unwrap();
        assert!(wb
            .store_mut()
            .committed_dispatch::<ProductActionAdmission>(&scope, alias.request_id)
            .unwrap()
            .is_some());
        assert_eq!(
            wb.observe_editor_file_save_request(&context, alias).err(),
            Some(unavailable())
        );
    }
    assert!(wb
        .observe_editor_file_save_request(&context, request)
        .is_ok());
}

struct ReadCodec {
    path: String,
    fired: Arc<AtomicBool>,
    unavailable: bool,
    inner: Option<Arc<dyn gaugedesk_store::ContentCodec>>,
}
impl gaugedesk_store::ContentCodec for ReadCodec {
    fn encode(&self, scope: &str, kind: &str, payload: &str) -> Result<String, String> {
        match &self.inner {
            Some(inner) => inner.encode(scope, kind, payload),
            None => Ok(payload.into()),
        }
    }
    fn decode(&self, scope: &str, kind: &str, payload: &str) -> Option<String> {
        if kind == "host_action_policy_v1" && !self.fired.swap(true, Ordering::SeqCst) {
            if self.unavailable {
                return None;
            }
            let contender = rusqlite::Connection::open(&self.path).unwrap();
            contender.execute("INSERT INTO events (scope_id, position, kind, payload) SELECT ?1, COALESCE(MAX(position), -1) + 1, 'request_lookup_stale', '{}' FROM events WHERE scope_id = ?1", [ORG_SCOPE]).unwrap();
        }
        match &self.inner {
            Some(inner) => inner.decode(scope, kind, payload),
            None => Some(payload.into()),
        }
    }
}

#[test]
fn request_observation_refuses_stale_authority_and_unavailable_original_policy() {
    for unavailable_history in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = saved(dir.path());
        let mut wb = fixture.shared.lock_unpoisoned();
        let (context, _) = reader(&mut wb);
        let fired = Arc::new(AtomicBool::new(false));
        wb.store = wb
            .store_ref()
            .sibling()
            .unwrap()
            .with_codec(Arc::new(ReadCodec {
                path: wb.store_ref().path().into(),
                fired: fired.clone(),
                unavailable: unavailable_history,
                inner: wb
                    .content_vault
                    .clone()
                    .map(|vault| vault as Arc<dyn gaugedesk_store::ContentCodec>),
            }));
        assert_eq!(
            wb.observe_editor_file_save_request(&context, identity(&fixture.command))
                .err(),
            Some(unavailable())
        );
        assert!(fired.load(Ordering::SeqCst));
        // Once the injected change is reflected in a fresh authority basis,
        // the exact original request is readable again.
        assert!(wb
            .observe_editor_file_save_request(&context, identity(&fixture.command))
            .is_ok());
    }
}
