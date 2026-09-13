use super::super::super::tests::erase_fixture_result;
use super::{forget, reader, save_fixture, saved};
use crate::file_action_factory::{tests::home_storage_fixture, NativeActionStorageConfig};
use crate::LockUnpoisoned;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use whipplescript_kernel::file_lease::FileLeasePolicy;
const KIND: &str = "native_editor_saved_result_v1";

#[test]
fn saved_product_observation_survives_erasure_without_execution_or_live_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, reader_token) = reader(&mut wb);
    let before = wb
        .observe_editor_file_saved_results(&context, &fixture.command)
        .unwrap();
    assert_eq!(before.results().len(), 1);
    let expected = before.results()[0].result.clone();
    assert_eq!(before.results()[0].effect_id, fixture.attempt().effect_id);
    assert_eq!(before.results()[0].run_id, fixture.attempt().run_id);
    assert!(before.results()[0].position >= 0);
    assert_eq!(expected.provenance.initiator, "alice");
    assert_eq!(before.observer(), "bob");
    assert!(!before.restrictions().reader.is_empty());
    assert!(before.restrictions().writer.is_empty());
    wb.revoke_account_session(&fixture.token);
    assert_eq!(
        erase_fixture_result(dir.path(), &expected.result_reference.content_hash),
        1
    );
    assert_eq!(erase_fixture_result(dir.path(), &expected.content_hash), 1);
    for file in [
        "inputs.sqlite",
        "native/runtime.sqlite",
        "native/coord.sqlite",
        "native/items.sqlite",
    ] {
        forget(&dir.path().join("actions").join(file));
    }
    wb.engagements.clear();
    let scope = fixture.command.instance_ref().unwrap();
    let history = wb.store_ref().retained_events(&scope).unwrap();
    for _ in 0..2 {
        let read = wb
            .observe_editor_file_saved_results(&context, &fixture.command)
            .unwrap();
        assert_eq!(read.results()[0].result, expected);
        assert_eq!(read.observer(), "bob");
        assert_eq!(read.restrictions(), before.restrictions());
    }
    assert_eq!(wb.store_ref().retained_events(&scope).unwrap(), history);
    assert!(wb.engagements.is_empty());
    assert!(!dir.path().join("actions/native/runtime.sqlite").exists());
    assert!(!dir.path().join("actions/inputs.sqlite").exists());
    let mut forged = fixture.command.clone();
    forged.provenance.initiator = "bob".into();
    forged.provenance.executor = "bob".into();
    assert!(wb
        .observe_editor_file_saved_results(&context, &forged)
        .is_err());
    wb.revoke_account_session(&reader_token);
    assert!(wb
        .observe_editor_file_saved_results(&context, &fixture.command)
        .is_err());
}

#[test]
fn saved_product_observation_empty_does_not_claim_non_execution_or_initialize_storage() {
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
        let (context, token) = reader(&mut wb);
        let scope = command.instance_ref().unwrap();
        let history = wb.store_ref().retained_events(&scope).unwrap();
        let read = wb
            .observe_editor_file_saved_results(&context, &command)
            .unwrap();
        assert!(read.results().is_empty());
        assert_eq!(wb.store_ref().retained_events(&scope).unwrap(), history);
        if !interrupted {
            assert!(!dir.path().join("actions/native").exists());
        }
        wb.revoke_account_session(&token);
        assert!(wb
            .observe_editor_file_saved_results(&context, &command)
            .is_err());
    }
}

#[test]
fn saved_product_observation_refuses_orphaned_or_duplicate_evidence_without_repair() {
    for damage in [
        "receipt",
        "command",
        "fact",
        "duplicate",
        "key",
        "ack_receipt",
        "ack_fact",
        "position",
        "grant_receipt",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = saved(dir.path());
        let mut wb = fixture.shared.lock_unpoisoned();
        let (context, _) = reader(&mut wb);
        let scope = fixture.command.instance_ref().unwrap();
        let result_scope = format!("host-action-native-save-result:{scope}");
        let sql = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
        match damage {
            "receipt" => {
                sql.execute(
                    "DELETE FROM command_receipts WHERE scope_id = ?1",
                    [&result_scope],
                )
                .unwrap();
            }
            "command" => {
                sql.execute("DELETE FROM commands WHERE scope_id = ?1", [&result_scope])
                    .unwrap();
            }
            "fact" => {
                sql.execute(
                    "DELETE FROM events WHERE scope_id = ?1 AND kind = ?2",
                    [&scope, KIND],
                )
                .unwrap();
            }
            "duplicate" => {
                let payload = wb.store_ref().records(&scope, KIND).unwrap().remove(0);
                wb.store_mut()
                    .append_record(&scope, KIND, &payload)
                    .unwrap();
            }
            "key" => {
                sql.execute("UPDATE commands SET command_id = ?1, idempotency_key = 'bad' WHERE scope_id = ?2", [format!("record-command:{}:{result_scope}bad", result_scope.len()), result_scope.clone()]).unwrap();
                sql.execute(
                    "UPDATE command_receipts SET command_key = 'bad' WHERE scope_id = ?1",
                    [&result_scope],
                )
                .unwrap();
            }
            "position" => {
                sql.execute(
                    "UPDATE command_receipts SET applied_at = applied_at + 1 WHERE scope_id = ?1",
                    [&result_scope],
                )
                .unwrap();
            }
            "ack_receipt" => {
                sql.execute(
                    "DELETE FROM command_receipts WHERE scope_id = ?1",
                    [format!("host-action-runtime-ack:{scope}")],
                )
                .unwrap();
            }
            "ack_fact" => {
                sql.execute(
                    "DELETE FROM events WHERE scope_id = ?1 AND kind = ?2",
                    [&scope, crate::host_action_delivery::ACKNOWLEDGMENT_KIND],
                )
                .unwrap();
            }
            "grant_receipt" => {
                let payload = wb.store_ref().records(&scope, KIND).unwrap().remove(0);
                let result: crate::file_action_factory::NativeEditorSavedResult =
                    serde_json::from_str(&payload).unwrap();
                assert_eq!(result.provenance.causes.len(), 3);
                let (_, grant_scope, _): (String, String, String) =
                    serde_json::from_str(&result.provenance.causes[2].record_ref).unwrap();
                assert_eq!(
                    sql.execute(
                        "DELETE FROM command_receipts WHERE scope_id = ?1",
                        [grant_scope]
                    )
                    .unwrap(),
                    1
                );
            }
            _ => unreachable!(),
        }
        let before = wb.store_ref().retained_events(&scope).unwrap();
        assert!(
            wb.observe_editor_file_saved_results(&context, &fixture.command)
                .is_err(),
            "{damage}"
        );
        assert_eq!(wb.store_ref().retained_events(&scope).unwrap(), before);
    }
}

#[test]
fn saved_product_observation_checks_bound_metadata_even_when_receipt_and_fact_agree() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let mut wb = fixture.shared.lock_unpoisoned();
    let (context, _) = reader(&mut wb);
    let scope = fixture.command.instance_ref().unwrap();
    let result_scope = format!("host-action-native-save-result:{scope}");
    let original = wb
        .store_ref()
        .committed_record_snapshots(&result_scope)
        .unwrap()
        .remove(0)
        .snapshot_json;
    let sql = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    for field in [
        "protocol",
        "issuer",
        "product_command_id",
        "runtime_ref",
        "evidence_handle",
        "evidence_label_ref",
        "cut_id",
        "operation_id",
        "content_hash",
        "policy",
        "author",
        "cause",
        "schema",
        "label",
        "admission",
    ] {
        let mut value: serde_json::Value = serde_json::from_str(&original).unwrap();
        match field {
            "policy" => value["policy"]["envelope_hash"] = "other".into(),
            "author" => value["provenance"]["initiator"] = "bob".into(),
            "cause" => value["provenance"]["causes"][1]["record_ref"] = "foreign".into(),
            "schema" => value["result_reference"]["schema_ref"] = "foreign".into(),
            "label" => value["result_reference"]["label_ref"] = "foreign".into(),
            "admission" => value["admission"]["fingerprint"] = "foreign".into(),
            other => value[other] = "".into(),
        }
        let payload = serde_json::to_string(&value).unwrap();
        sql.execute(
            "UPDATE commands SET snapshot_json = ?1 WHERE scope_id = ?2",
            [&payload, &result_scope],
        )
        .unwrap();
        sql.execute(
            "UPDATE events SET payload = ?1 WHERE scope_id = ?2 AND kind = ?3",
            [&payload, &scope, KIND],
        )
        .unwrap();
        assert!(
            wb.observe_editor_file_saved_results(&context, &fixture.command)
                .is_err(),
            "{field}"
        );
    }
    sql.execute(
        "UPDATE commands SET snapshot_json = ?1, status = 'expired' WHERE scope_id = ?2",
        [&original, &result_scope],
    )
    .unwrap();
    sql.execute(
        "UPDATE events SET payload = ?1 WHERE scope_id = ?2 AND kind = ?3",
        [&original, &scope, KIND],
    )
    .unwrap();
    assert_eq!(
        wb.observe_editor_file_saved_results(&context, &fixture.command)
            .unwrap()
            .results()
            .len(),
        1
    );
    let status: String = sql
        .query_row(
            "SELECT status FROM commands WHERE scope_id = ?1",
            [&result_scope],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(status, "expired");
}

struct ReadCodec {
    path: String,
    reads: Arc<AtomicUsize>,
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
        if kind == KIND {
            let prior = self.reads.fetch_add(1, Ordering::SeqCst);
            if self.unavailable {
                return None;
            }
            if prior > 0 {
                let contender = rusqlite::Connection::open(&self.path).unwrap();
                contender.busy_timeout(std::time::Duration::ZERO).unwrap();
                assert!(
                    contender.execute_batch("BEGIN IMMEDIATE").is_err(),
                    "product result read lost its current authority fence"
                );
            }
        }
        match &self.inner {
            Some(inner) => inner.decode(scope, kind, payload),
            None => Some(payload.into()),
        }
    }
}

#[test]
fn saved_product_observation_fences_reads_and_refuses_unavailable_history() {
    for unavailable in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = saved(dir.path());
        let mut wb = fixture.shared.lock_unpoisoned();
        let (context, _) = reader(&mut wb);
        let reads = Arc::new(AtomicUsize::new(0));
        wb.store = wb
            .store_ref()
            .sibling()
            .unwrap()
            .with_codec(Arc::new(ReadCodec {
                path: wb.store_ref().path().into(),
                reads: reads.clone(),
                unavailable,
                inner: wb
                    .content_vault
                    .clone()
                    .map(|vault| vault as Arc<dyn gaugedesk_store::ContentCodec>),
            }));
        let read = wb.observe_editor_file_saved_results(&context, &fixture.command);
        if unavailable {
            assert!(read.is_err());
        } else {
            assert_eq!(read.unwrap().results().len(), 1);
            assert!(reads.load(Ordering::SeqCst) >= 2);
        }
    }
}
