use super::super::tests::{reader, save_fixture, saved};
use super::*;
use crate::{file_action_factory::NativeActionStorageConfig, LockUnpoisoned};
use whipplescript_kernel::file_lease::FileLeasePolicy;
use whipplescript_store::content::{ContentBlobs, ContentStore};

#[path = "file_action_derived_source_tests.rs"]
mod derived;

fn storage(wb: &Workbench) -> NativeActionStorage {
    wb.open_native_action_storage(NativeActionStorageConfig {
        input_byte_limit: 4096,
        file_lease: FileLeasePolicy::new(17).unwrap(),
    })
    .unwrap()
}
fn recorded(wb: &Workbench, request: &str) -> (String, SignedSource) {
    let scope = source_scope(wb.home_id().as_str(), "bob", request).unwrap();
    let facts = wb.store_ref().records(&scope, KIND).unwrap();
    assert_eq!(facts.len(), 1);
    assert!(!facts[0].contains("private editor draft"));
    (scope, serde_json::from_str(&facts[0]).unwrap())
}

fn target_databases(root: &std::path::Path, paths: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            target_databases(&entry.path(), paths);
        } else if entry.file_name() == "content.sqlite" && root.join("branches.sqlite").is_file() {
            paths.push(entry.path());
        }
    }
}

#[test]
fn saved_source_retains_exact_bytes_labels_original_author_and_idempotent_cause() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, token) = reader(&mut wb);
    let storage = storage(&wb);
    let observation = wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt(),
        )
        .unwrap();
    wb.revoke_account_session(&fixture.token);
    let runtime_path = dir.path().join("actions/native/runtime.sqlite");
    let before = std::fs::read(&runtime_path).unwrap();
    let retained = wb
        .retain_editor_file_save_source(
            &context,
            &storage,
            "derive-1",
            &observation,
            fixture.attempt(),
        )
        .unwrap();
    assert!(!retained.replayed());
    let bytes = storage.inputs().resolve(retained.input()).unwrap();
    assert_eq!(bytes.content, "private editor draft");
    let (scope, source) = recorded(&wb, "derive-1");
    assert_eq!(source.statement.original_provenance.initiator, "alice");
    assert_eq!(source.statement.observer, "bob");
    assert_eq!(
        source.statement.observed_at,
        observation.evidence().observed_at
    );
    assert_eq!(&source.statement.restrictions, observation.restrictions());
    assert!(source.statement.restrictions.writer.is_empty());
    assert_eq!(source.statement.input, *retained.input());
    assert_eq!(source.statement.content_hash, bytes.content_hash);
    assert_eq!(
        source.statement.receipt_digest,
        digest(observation.saved().unwrap().receipt_json.as_bytes())
    );
    let key = SigningKey::from_seed(&wb.governance_seed()).unwrap();
    assert!(
        original_source(wb.store_ref(), &scope, &source.statement, &key.public_key())
            .unwrap()
            .is_some()
    );
    assert_eq!(std::fs::read(&runtime_path).unwrap(), before);
    drop(wb);
    let reopened = crate::open_workbench(dir.path()).unwrap();
    let mut wb = reopened.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let retry = wb
        .retain_editor_file_save_source(
            &context,
            &storage,
            "derive-1",
            &observation,
            fixture.attempt(),
        )
        .unwrap();
    assert!(retry.replayed());
    assert_eq!(retry.cause(), retained.cause());
    assert_eq!(retry.input(), retained.input());
    assert_eq!(std::fs::read(runtime_path).unwrap(), before);
    assert_eq!(wb.store_ref().records(&scope, KIND).unwrap().len(), 1);
}

#[test]
fn saved_source_refuses_stale_reader_substituted_attempt_and_wrong_home() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, token) = reader(&mut wb);
    let storage = storage(&wb);
    let observation = wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt(),
        )
        .unwrap();
    assert!(wb
        .retain_editor_file_save_source(
            &context,
            &storage,
            "wrong-attempt",
            &observation,
            EditorFileSaveAttempt {
                effect_id: fixture.attempt().effect_id,
                run_id: "substituted"
            }
        )
        .is_err());
    let other_dir = tempfile::tempdir().unwrap();
    let other = saved(other_dir.path());
    let other_storage = self::storage(&other.shared.lock_unpoisoned());
    assert!(wb
        .retain_editor_file_save_source(
            &context,
            &other_storage,
            "wrong-home",
            &observation,
            fixture.attempt()
        )
        .is_err());
    wb.revoke_account_session(&token);
    assert!(wb
        .retain_editor_file_save_source(
            &context,
            &storage,
            "revoked",
            &observation,
            fixture.attempt()
        )
        .is_err());
    for id in ["wrong-attempt", "wrong-home", "revoked"] {
        assert!(wb
            .store_ref()
            .records(
                &source_scope(wb.home_id().as_str(), "bob", id).unwrap(),
                KIND
            )
            .unwrap()
            .is_empty());
    }
}

#[test]
fn saved_source_does_not_restore_erased_source_or_custodied_input_from_observation() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let storage = storage(&wb);
    let observation = wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt(),
        )
        .unwrap();
    let retained = wb
        .retain_editor_file_save_source(
            &context,
            &storage,
            "erased-input",
            &observation,
            fixture.attempt(),
        )
        .unwrap();
    ContentStore::open(dir.path().join("actions/inputs.sqlite"))
        .unwrap()
        .erase(&retained.input().version_ref, "erase")
        .unwrap();
    assert!(wb
        .retain_editor_file_save_source(
            &context,
            &storage,
            "erased-input",
            &observation,
            fixture.attempt()
        )
        .is_err());
    assert!(storage.inputs().resolve(retained.input()).is_err());
    assert!(wb
        .retain_editor_file_save_source(
            &context,
            &storage,
            "new-request-same-erased-input",
            &observation,
            fixture.attempt()
        )
        .is_err());
    assert!(storage.inputs().resolve(retained.input()).is_err());
    let hash = whipplescript_store::stable_hash_hex(&observation.saved().unwrap().accepted_content);
    assert_eq!(
        super::super::super::tests::erase_fixture_result(dir.path(), &hash),
        1
    );
    assert!(wb
        .retain_editor_file_save_source(
            &context,
            &storage,
            "erased-source",
            &observation,
            fixture.attempt()
        )
        .is_err());
    assert!(wb
        .store_ref()
        .records(
            &source_scope(wb.home_id().as_str(), "bob", "erased-source").unwrap(),
            KIND
        )
        .unwrap()
        .is_empty());
}

#[test]
fn saved_source_retains_unknown_disposition_and_rejects_changed_preparation_meaning() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = save_fixture(dir.path(), true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let storage = storage(&wb);
    let observation = wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt(),
        )
        .unwrap();
    let retained = wb
        .retain_editor_file_save_source(
            &context,
            &storage,
            "unknown",
            &observation,
            fixture.attempt(),
        )
        .unwrap();
    let (scope, source) = recorded(&wb, "unknown");
    assert_eq!(
        source.statement.attempt.disposition,
        whipplescript_store::effect_recovery::ExternalDisposition::Unknown
    );
    let key = SigningKey::from_seed(&wb.governance_seed()).unwrap();
    for field in ["input", "label", "author", "pin"] {
        let mut changed = source.statement.clone();
        match field {
            "input" => changed.input.version_ref = "other".into(),
            "label" => changed.restrictions.reader.clear(),
            "author" => changed.original_provenance.initiator = "bob".into(),
            "pin" => changed.observed_at.head_digest = "other".into(),
            _ => unreachable!(),
        }
        assert!(original_source(wb.store_ref(), &scope, &changed, &key.public_key()).is_err());
    }
    assert_eq!(
        retained.cause().digest,
        digest(source.statement.snapshot().unwrap().as_bytes())
    );
}

#[test]
fn saved_source_publication_requires_original_target_retention() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let storage = storage(&wb);
    let observation = wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt(),
        )
        .unwrap();
    let mut paths = Vec::new();
    target_databases(dir.path(), &mut paths);
    let hash = whipplescript_store::stable_hash_hex(&observation.saved().unwrap().accepted_content);
    let paths: Vec<_> = paths
        .into_iter()
        .filter(|path| {
            ContentStore::open(path)
                .unwrap()
                .get(&hash)
                .unwrap()
                .is_some()
        })
        .collect();
    assert_eq!(paths.len(), 1);
    let eraser = rusqlite::Connection::open(&paths[0]).unwrap();
    eraser.execute_batch("BEGIN IMMEDIATE").unwrap();
    let refused = wb.retain_editor_file_save_source(
        &context,
        &storage,
        "held-target",
        &observation,
        fixture.attempt(),
    );
    eraser.execute_batch("ROLLBACK").unwrap();
    assert!(
        refused.is_err(),
        "a source must not publish while a competing target erasure owns retention"
    );
    let scope = source_scope(wb.home_id().as_str(), "bob", "held-target").unwrap();
    assert!(wb.store_ref().records(&scope, KIND).unwrap().is_empty());
    let retained = wb
        .retain_editor_file_save_source(
            &context,
            &storage,
            "held-target",
            &observation,
            fixture.attempt(),
        )
        .unwrap();
    assert!(!retained.replayed());
}

#[test]
fn saved_source_retry_never_recreates_missing_input_custody() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let input_storage = storage(&wb);
    let observation = wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt(),
        )
        .unwrap();
    let retained = wb
        .retain_editor_file_save_source(
            &context,
            &input_storage,
            "missing-input",
            &observation,
            fixture.attempt(),
        )
        .unwrap();
    drop(input_storage);
    for suffix in ["", "-wal", "-shm"] {
        let path = dir.path().join(format!("actions/inputs.sqlite{suffix}"));
        if path.exists() {
            std::fs::remove_file(path).unwrap();
        }
    }
    let input_storage = storage(&wb);
    assert!(wb
        .retain_editor_file_save_source(
            &context,
            &input_storage,
            "missing-input",
            &observation,
            fixture.attempt()
        )
        .is_err());
    assert!(input_storage.inputs().resolve(retained.input()).is_err());
    let (scope, _) = recorded(&wb, "missing-input");
    assert_eq!(wb.store_ref().records(&scope, KIND).unwrap().len(), 1);
}

#[test]
fn saved_source_replay_refuses_corrupt_attestation_or_receipt_without_repair() {
    for corruption in ["signature", "snapshot", "receipt"] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = saved(dir.path());
        let mut wb = fixture.shared.lock_unpoisoned();
        let (context, _) = reader(&mut wb);
        let storage = storage(&wb);
        let observation = wb
            .observe_editor_file_save(
                &context,
                &fixture.command,
                &fixture.admission,
                fixture.attempt(),
            )
            .unwrap();
        wb.retain_editor_file_save_source(
            &context,
            &storage,
            "corrupted",
            &observation,
            fixture.attempt(),
        )
        .unwrap();
        let (scope, mut signed) = recorded(&wb, "corrupted");
        let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
        match corruption {
            "signature" => {
                signed.signature[0] ^= 1;
                let changed = serde_json::to_string(&signed).unwrap();
                assert_eq!(
                    fault
                        .execute(
                            "UPDATE events SET payload = ?1 WHERE scope_id = ?2 AND kind = ?3",
                            rusqlite::params![changed, scope, KIND]
                        )
                        .unwrap(),
                    1
                );
                assert_eq!(wb.store_ref().records(&scope, KIND).unwrap(), vec![changed]);
            }
            "snapshot" => {
                assert_eq!(
                    fault
                        .execute(
                            "UPDATE commands SET snapshot_json = '{}' WHERE scope_id = ?1",
                            [&scope]
                        )
                        .unwrap(),
                    1
                );
            }
            "receipt" => {
                assert_eq!(
                    fault
                        .execute("DELETE FROM command_receipts WHERE scope_id = ?1", [&scope])
                        .unwrap(),
                    1
                );
            }
            _ => unreachable!(),
        }
        let records = wb.store_ref().records(&scope, KIND).unwrap();
        assert!(
            wb.retain_editor_file_save_source(
                &context,
                &storage,
                "corrupted",
                &observation,
                fixture.attempt()
            )
            .is_err(),
            "{corruption}"
        );
        assert_eq!(wb.store_ref().records(&scope, KIND).unwrap(), records);
    }
}

#[test]
fn saved_source_history_reopens_without_its_erased_body_or_checkout() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = save_fixture(dir.path(), true);
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, token) = reader(&mut wb);
    let storage = storage(&wb);
    let observed = wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt(),
        )
        .unwrap();
    let source = wb
        .retain_editor_file_save_source(
            &context,
            &storage,
            "restart-erased-source",
            &observed,
            fixture.attempt(),
        )
        .unwrap();
    let (_, _, chat): (String, String, String) =
        serde_json::from_str(&fixture.command.scope).unwrap();
    let checkout = wb.engagements[&chat].path().to_path_buf();
    let hash =
        whipplescript_store::stable_hash_hex(&observed.saved.as_ref().unwrap().accepted_content);
    let mut targets = Vec::new();
    target_databases(dir.path(), &mut targets);
    let mut erased = Vec::new();
    for path in targets {
        let content = ContentStore::open(&path).unwrap();
        if content.get(&hash).unwrap().is_some() {
            content
                .erase(&hash, "erase historical workspace body")
                .unwrap();
            erased.push(path);
        }
    }
    assert_eq!(erased.len(), 1);
    std::fs::remove_dir_all(&checkout).unwrap();
    let branch_path = erased[0].with_file_name("branches.sqlite");
    let branch_rows = || {
        let db = rusqlite::Connection::open_with_flags(
            &branch_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let names = db
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        names
            .into_iter()
            .map(|name| {
                let mut query = db
                    .prepare(&format!("SELECT * FROM \"{}\"", name.replace('"', "\"\"")))
                    .unwrap();
                let columns = query.column_count();
                let mut values = query
                    .query_map([], |row| {
                        (0..columns)
                            .map(|i| row.get::<_, rusqlite::types::Value>(i))
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .unwrap()
                    .map(|row| format!("{:?}", row.unwrap()))
                    .collect::<Vec<_>>();
                values.sort();
                (name, digest(values.join("\n").as_bytes()))
            })
            .collect::<BTreeMap<_, _>>()
    };
    let branches_before = branch_rows();
    drop(wb);
    let reopened = crate::open_workbench(dir.path()).unwrap();
    let mut wb = reopened.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    assert_eq!(wb.engagements[&chat].path(), checkout);
    assert!(wb.engagement_tree(&chat).unwrap().is_err());
    assert!(!checkout.exists());
    assert_eq!(branch_rows(), branches_before);
    let (scope, _): (String, String) = serde_json::from_str(&source.cause().record_ref).unwrap();
    let key = SigningKey::from_seed(&wb.governance_seed()).unwrap();
    let retained = load_source(wb.store_ref(), &scope, &key.public_key())
        .unwrap()
        .unwrap();
    assert_eq!(retained.statement.input, *source.input());
    assert_eq!(
        retained.statement.attempt.disposition,
        whipplescript_store::effect_recovery::ExternalDisposition::Unknown
    );
    assert!(wb
        .observe_editor_file_save(
            &context,
            &fixture.command,
            &fixture.admission,
            fixture.attempt()
        )
        .is_err());
    assert!(ContentStore::open(&erased[0])
        .unwrap()
        .get(&hash)
        .unwrap()
        .is_none());
    assert!(!checkout.exists());
}
