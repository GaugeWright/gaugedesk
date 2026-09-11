use super::*;
use crate::{CommandRecordFact, ContentCodec};
use std::sync::Arc;

fn facts() -> Vec<CommandRecordFact> {
    vec![
        CommandRecordFact {
            scope_id: "action".into(),
            kind: "saved".into(),
            payload: "retained-result-reference".into(),
        },
        CommandRecordFact {
            scope_id: "chat".into(),
            kind: "acknowledged".into(),
            payload: "saved-result-reference".into(),
        },
    ]
}

#[test]
fn retained_admission_commits_under_both_exclusions_and_recovers_lost_callback_response() {
    let mut product = Store::open_in_memory().unwrap();
    let observer = product.sibling().unwrap();
    let competing = rusqlite::Connection::open(product.path()).unwrap();
    competing.busy_timeout(std::time::Duration::ZERO).unwrap();
    // This generic store boundary accepts any bounded retention publisher. A
    // second SQLite authority models its real writer exclusion without adding a
    // runtime/content dependency to the product store.
    let mut retained = Store::open_in_memory().unwrap();
    let eraser = rusqlite::Connection::open(retained.path()).unwrap();
    eraser.busy_timeout(std::time::Duration::ZERO).unwrap();
    let (_, basis) = product.read_for_dispatch(&["grants"], |_| Ok(())).unwrap();
    let response = product
        .with_dispatch_record_admission(&basis, |writer| {
            assert!(competing.execute_batch("BEGIN IMMEDIATE").is_err());
            let retention = retained
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let receipt = writer
                .commit("result-admission", "save-1", "exact intent", &facts())
                .unwrap();
            assert!(!receipt.replayed);
            assert_eq!(receipt.positions, vec![0, 0]);
            // The real product commit has happened while erasure is excluded,
            // not after the caller releases its retention callback.
            assert_eq!(observer.records("action", "saved").unwrap().len(), 1);
            assert_eq!(observer.records("chat", "acknowledged").unwrap().len(), 1);
            assert!(eraser.execute_batch("BEGIN IMMEDIATE").is_err());
            retention.commit().unwrap();
            Err::<(), _>("lost response after product commit")
        })
        .unwrap();
    assert_eq!(response, Err("lost response after product commit"));
    competing
        .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
        .unwrap();
    eraser.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
    let receipt = product
        .with_dispatch_record_admission(&basis, |writer| {
            writer.commit("result-admission", "save-1", "exact intent", &facts())
        })
        .unwrap()
        .unwrap();
    assert!(receipt.replayed);
    assert_eq!(observer.records("action", "saved").unwrap().len(), 1);
    assert_eq!(observer.records("chat", "acknowledged").unwrap().len(), 1);
    assert!(product
        .with_dispatch_record_admission(&basis, |writer| {
            writer.commit("result-admission", "save-1", "changed intent", &facts())
        })
        .unwrap()
        .is_err());
}

#[test]
fn retained_admission_refuses_stale_expired_and_foreign_authority_before_publication() {
    let mut product = Store::open_in_memory().unwrap();
    let mut other = Store::open_in_memory().unwrap();
    let (_, stale) = product.read_for_dispatch(&["grants"], |_| Ok(())).unwrap();
    product.append_record("grants", "grant", "revoked").unwrap();
    assert!(product
        .with_dispatch_record_admission(&stale, |_| panic!("stale evidence read"))
        .is_err());
    let (_, current) = product.read_for_dispatch(&["grants"], |_| Ok(())).unwrap();
    assert!(other
        .with_dispatch_record_admission(&current, |_| panic!("foreign evidence read"))
        .is_err());
    let expired = current.with_deadline(std::time::UNIX_EPOCH);
    assert!(product
        .with_dispatch_record_admission(&expired, |_| panic!("expired evidence read"))
        .is_err());
    assert!(product
        .command_for_key("result-admission", "save-1")
        .unwrap()
        .is_none());
    assert!(product.records("action", "saved").unwrap().is_empty());
}

#[test]
fn retained_admission_abandonment_and_partial_append_failure_publish_nothing() {
    let mut product = Store::open_in_memory().unwrap();
    let (_, basis) = product.read_for_dispatch(&["grants"], |_| Ok(())).unwrap();
    let unavailable = product
        .with_dispatch_record_admission(&basis, |writer| {
            drop(writer);
            Err::<(), _>("result was erased")
        })
        .unwrap();
    assert_eq!(unavailable, Err("result was erased"));
    assert!(product
        .command_for_key("result-admission", "save-1")
        .unwrap()
        .is_none());
    product.conn.execute_batch("CREATE TRIGGER lose_result_admission BEFORE INSERT ON events WHEN NEW.scope_id = 'chat' BEGIN SELECT RAISE(ABORT, 'lost second fact'); END;").unwrap();
    assert!(product
        .with_dispatch_record_admission(&basis, |writer| {
            writer.commit("result-admission", "save-1", "exact intent", &facts())
        })
        .unwrap()
        .is_err());
    assert!(product.records("action", "saved").unwrap().is_empty());
    assert!(product.records("chat", "acknowledged").unwrap().is_empty());
    assert!(product
        .command_for_key("result-admission", "save-1")
        .unwrap()
        .is_none());
    product
        .conn
        .execute_batch("DROP TRIGGER lose_result_admission")
        .unwrap();
    let receipt = product
        .with_dispatch_record_admission(&basis, |writer| {
            writer.commit("result-admission", "save-1", "exact intent", &facts())
        })
        .unwrap()
        .unwrap();
    assert!(!receipt.replayed);
}

struct Codec;
impl ContentCodec for Codec {
    fn encode(&self, _: &str, _: &str, payload: &str) -> Result<String, String> {
        if payload == "cannot encode" {
            return Err("encoding refused".into());
        }
        Ok(format!("protected:{payload}"))
    }
    fn decode(&self, _: &str, _: &str, payload: &str) -> Option<String> {
        payload.strip_prefix("protected:").map(str::to_owned)
    }
}

#[test]
fn retained_admission_preserves_the_configured_codec_and_rolls_back_encoding_failure() {
    let mut product = Store::open_in_memory().unwrap().with_codec(Arc::new(Codec));
    let (_, basis) = product.read_for_dispatch(&["grants"], |_| Ok(())).unwrap();
    let mut bad = facts();
    bad[1].payload = "cannot encode".into();
    assert!(matches!(
        product
            .with_dispatch_record_admission(&basis, |writer| {
                writer.commit("result-admission", "save-1", "exact intent", &bad)
            })
            .unwrap(),
        Err(AdmitError::Codec(_))
    ));
    assert!(product
        .command_for_key("result-admission", "save-1")
        .unwrap()
        .is_none());
    product
        .with_dispatch_record_admission(&basis, |writer| {
            writer.commit("result-admission", "save-1", "exact intent", &facts())
        })
        .unwrap()
        .unwrap();
    let raw: String = product
        .conn
        .query_row(
            "SELECT payload FROM events WHERE scope_id = 'action'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(raw, "protected:retained-result-reference");
    assert_eq!(
        product.records("action", "saved").unwrap()[0],
        "retained-result-reference"
    );
}

#[test]
fn committed_record_snapshot_requires_the_receipt_and_original_identity_without_repair() {
    let mut store = Store::open_in_memory().unwrap();
    assert_eq!(
        store
            .committed_record_snapshot("grant", "authorize")
            .unwrap(),
        None
    );
    store
        .admit_record_facts("grant", "authorize", "original grant", &[])
        .unwrap();
    store
        .conn
        .execute(
            "UPDATE commands SET status = 'expired' WHERE scope_id = 'grant'",
            [],
        )
        .unwrap();
    let (snapshot, _) = store
        .read_for_dispatch(&["grant"], |store| {
            store.committed_record_snapshot("grant", "authorize")
        })
        .unwrap();
    assert_eq!(snapshot.as_deref(), Some("original grant"));
    assert_eq!(
        store
            .command_for_key("grant", "authorize")
            .unwrap()
            .unwrap()
            .status,
        "expired"
    );
    store
        .conn
        .execute("DELETE FROM command_receipts WHERE scope_id = 'grant'", [])
        .unwrap();
    store
        .conn
        .execute(
            "UPDATE commands SET status = 'applied' WHERE scope_id = 'grant'",
            [],
        )
        .unwrap();
    assert_eq!(
        store
            .committed_record_snapshot("grant", "authorize")
            .unwrap(),
        None
    );
    store
        .conn
        .execute(
            "INSERT INTO command_receipts VALUES ('grant', 'authorize', 0)",
            [],
        )
        .unwrap();
    store
        .conn
        .execute(
            "UPDATE commands SET command_id = 'forged' WHERE scope_id = 'grant'",
            [],
        )
        .unwrap();
    assert!(store
        .committed_record_snapshot("grant", "authorize")
        .is_err());
    store
        .conn
        .execute("DELETE FROM commands WHERE scope_id = 'grant'", [])
        .unwrap();
    assert!(store
        .committed_record_snapshot("grant", "authorize")
        .is_err());
}

struct ErasedRevocation;
impl ContentCodec for ErasedRevocation {
    fn encode(&self, _: &str, _: &str, payload: &str) -> Result<String, String> {
        Ok(payload.into())
    }
    fn decode(&self, _: &str, kind: &str, payload: &str) -> Option<String> {
        (kind != "revoked").then(|| payload.to_owned())
    }
}

#[test]
fn authority_history_refuses_an_unavailable_revocation_instead_of_reactivating_the_grant() {
    let mut store = Store::open_in_memory().unwrap();
    store.append_record("authority", "grant", "active").unwrap();
    store
        .append_record("authority", "revoked", "revoked")
        .unwrap();
    assert_eq!(store.retained_events("authority").unwrap().len(), 2);
    let store = store.with_codec(Arc::new(ErasedRevocation));
    assert_eq!(
        store.events("authority").unwrap(),
        vec![(0, "grant".into(), "active".into())]
    );
    assert!(matches!(
        store.read_for_dispatch(&["authority"], |store| store.retained_events("authority")),
        Err(AdmitError::Codec(_))
    ));
}
