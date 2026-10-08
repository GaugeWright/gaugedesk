use super::*;
use crate::{
    command_dispatch::{DispatchReadBasis, MaterializedTaskInputPrefix},
    Store,
};
use gaugedesk_core::run::{RunCommand, RunState};
fn key() -> String {
    format!("office-http:v1:{}", digest(b"key"))
}
fn snapshot() -> String {
    serde_json::json!({"body_sha256":"ab".repeat(32)}).to_string()
}
fn link() -> TaskInputLink {
    TaskInputLink {
        body_digest: "ab".repeat(32),
    }
}
fn facts() -> Vec<CommandRecordFact> {
    vec![CommandRecordFact { scope_id:"chat".into(),kind:"transcript".into(),payload:serde_json::json!({"type":"user","text":"input","chat_id":"chat","client_request_id":"key","home_id":"verified-home","actor_id":"verified-requester"}).to_string() }]
}
fn batch() -> LifecycleBatch<RunState> {
    LifecycleBatch {
        scope: "chat".into(),
        commands: vec![
            RunCommand::RequestRun,
            RunCommand::AdmitRun,
            RunCommand::StartRun,
        ],
    }
}
fn basis(store: &Store) -> DispatchReadBasis {
    store
        .read_for_dispatch(&["authority"], |_| Ok(()))
        .expect("read basis")
        .1
}
fn pending(store: &mut Store) {
    store
        .claim_command("original", "http-task", &key(), &snapshot())
        .expect("real pending claim");
}
fn commit(
    store: &mut Store,
    supplied: &[CommandRecordFact],
    supplied_link: &TaskInputLink,
) -> Result<MaterializedTaskInputPrefix, AdmitError> {
    let b = basis(store);
    store
        .with_dispatch_record_admission(&b, |writer| {
            writer.commit_claimed_task_input_prefix(
                "original",
                "http-task",
                &key(),
                &snapshot(),
                "startup",
                batch(),
                supplied,
                supplied_link,
            )
        })
        .expect("writer")
}
type EventRow = (i64, String, String, String);
type CommandRow = (String, String, String, String, String, String);
type ReceiptRow = (String, String, i64);
type Snapshot = (Vec<EventRow>, Vec<ReceiptRow>, Vec<CommandRow>);
fn all(store: &Store) -> Snapshot {
    let events = store
        .conn
        .prepare("SELECT position,scope_id,kind,payload FROM events ORDER BY position")
        .expect("events")
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .expect("rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("read rows");
    let receipts = store.conn.prepare("SELECT scope_id,command_key,applied_at FROM command_receipts ORDER BY scope_id,command_key").expect("receipts").query_map([], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).expect("receipt rows").collect::<Result<Vec<_>,_>>().expect("all receipts");
    let commands = store.conn.prepare("SELECT command_id,scope_id,idempotency_key,status,snapshot_json,updated_at FROM commands ORDER BY command_id").expect("commands").query_map([], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).expect("command rows").collect::<Result<Vec<_>,_>>().expect("all commands");
    (events, receipts, commands)
}
#[test]
fn task_input_links_actual_user_position_and_replays_after_advance() {
    let mut store = Store::open_in_memory().expect("store");
    pending(&mut store);
    let first = commit(&mut store, &facts(), &link()).expect("admit");
    assert!(!first.prefix.replayed);
    assert_eq!(first.companion_position, 0); // Positions are scope-local.
    let rows = store
        .records("http-task-attempt::original", "task_correlation_attempt")
        .expect("private link");
    let value: serde_json::Value = serde_json::from_str(&rows[0]).expect("link json");
    assert_eq!(
        value,
        serde_json::json!({"chat_id":"chat","user_entry_id":first.user_position,"command_id":"original","body_digest":link().body_digest})
    );
    store
        .append_record("later", "note", "advance")
        .expect("advance");
    let before = all(&store);
    let retry = commit(&mut store, &facts(), &link()).expect("retry");
    assert!(retry.prefix.replayed);
    assert_eq!(retry.prefix.positions, first.prefix.positions);
    assert_eq!(retry.user_position, first.user_position);
    assert_eq!(all(&store), before);
}
#[test]
fn task_input_refuses_mismatched_coordinates_without_any_append() {
    for field in [
        "chat_id",
        "client_request_id",
        "home_id",
        "actor_id",
        "type",
    ] {
        let mut store = Store::open_in_memory().expect("store");
        pending(&mut store);
        let before = all(&store);
        let mut f = facts();
        let mut user: serde_json::Value = serde_json::from_str(&f[0].payload).expect("json");
        user[field] = serde_json::json!(if matches!(field, "home_id" | "actor_id") {
            ""
        } else {
            "wrong"
        });
        f[0].payload = user.to_string();
        assert!(commit(&mut store, &f, &link()).is_err(), "{field}");
        assert_eq!(all(&store), before);
    }
    let mut store = Store::open_in_memory().expect("store");
    pending(&mut store);
    let before = all(&store);
    assert!(commit(
        &mut store,
        &facts(),
        &TaskInputLink {
            body_digest: "cd".repeat(32)
        }
    )
    .is_err());
    assert_eq!(all(&store), before);
    let mut f = facts();
    f[0].scope_id = "other".into();
    assert!(commit(&mut store, &f, &link()).is_err());
    assert_eq!(all(&store), before);
}
#[test]
fn task_input_late_companion_and_receipt_failures_roll_back_entire_prefix() {
    for sql in ["CREATE TRIGGER refusal BEFORE INSERT ON events WHEN NEW.kind='task_correlation_attempt' BEGIN SELECT RAISE(ABORT,'companion unavailable'); END;","CREATE TRIGGER refusal BEFORE INSERT ON command_receipts BEGIN SELECT RAISE(ABORT,'receipt unavailable'); END;"] {
  let mut store=Store::open_in_memory().expect("store");pending(&mut store);let before=all(&store);store.conn.execute_batch(sql).expect("install actual late trigger");assert!(commit(&mut store,&facts(),&link()).is_err());assert_eq!(all(&store),before);store.conn.execute_batch("DROP TRIGGER refusal").expect("restore");commit(&mut store,&facts(),&link()).expect("restored admission");
 }
}
#[test]
fn task_input_missing_or_tampered_retained_link_cannot_repair_or_replay() {
    for tamper in [
        "DELETE FROM events WHERE kind='task_correlation_attempt'",
        "UPDATE events SET payload='{}' WHERE kind='task_correlation_attempt'",
        "DELETE FROM events WHERE kind='transcript'",
    ] {
        let mut store = Store::open_in_memory().expect("store");
        pending(&mut store);
        commit(&mut store, &facts(), &link()).expect("admit");
        store.conn.execute_batch(tamper).expect("fault");
        let before = all(&store);
        assert!(commit(&mut store, &facts(), &link()).is_err());
        assert_eq!(all(&store), before);
    }
}

#[test]
fn task_input_recorded_parent_read_keeps_private_scope_separate_and_ordinary_refusal() {
    use gaugedesk_core::merge::{MergeCommand, MergeState};
    let mut store = Store::open_in_memory().expect("store");
    pending(&mut store);
    let admitted = commit(&mut store, &facts(), &link()).expect("admit");
    let observed = basis(&store);
    store
        .with_dispatch_record_admission(&observed, |writer| {
            writer.commit_recorded_claimed_lifecycle_pair(
                "original",
                "http-task",
                &key(),
                &snapshot(),
                LifecycleBatch::<RunState> {
                    scope: "chat".into(),
                    commands: vec![RunCommand::RecordObservation, RunCommand::CompleteRun],
                },
                LifecycleBatch::<MergeState> {
                    scope: "chat".into(),
                    commands: vec![MergeCommand::StartMerge, MergeCommand::WorkspaceClean],
                },
                |_| {
                    Ok(vec![CommandRecordFact {
                        scope_id: "chat".into(),
                        kind: "workspace_result".into(),
                        payload: "retained native result".into(),
                    }])
                },
            )
        })
        .expect("writer")
        .expect("recorded completion");
    let before = all(&store);
    let observed = basis(&store);
    let restored = store
        .with_dispatch_record_admission(&observed, |writer| {
            writer.require_recorded_task_input_prefix::<RunState, RunState, MergeState>(
                "original",
                "http-task",
                &key(),
                &snapshot(),
                "startup",
                &batch(),
                &facts(),
                &link(),
            )
        })
        .expect("writer")
        .expect("exact recorded phase");
    assert_eq!(restored.prefix.positions, admitted.prefix.positions);
    assert_eq!(restored.user_position, admitted.user_position);
    assert_eq!(all(&store), before);
    let mut unrelated = facts();
    unrelated[0].scope_id = "private-arbitrary".into();
    let observed = basis(&store);
    assert!(store
        .with_dispatch_record_admission(&observed, |writer| writer
            .require_recorded_lifecycle_prefix::<RunState, RunState, MergeState>(
                "original",
                "http-task",
                &key(),
                &snapshot(),
                "startup",
                &batch(),
                &unrelated
            ))
        .expect("writer")
        .is_err());
    assert_eq!(all(&store), before);
}

#[test]
fn office_task_input_refuses_plain_parent_and_transformed_user_ids() {
    let mut store = Store::open_in_memory().expect("store");
    store
        .claim_command("original", "http-task", "key", &snapshot())
        .expect("plain legacy parent");
    let before = all(&store);
    let observed = basis(&store);
    assert!(store
        .with_dispatch_record_admission(&observed, |writer| writer
            .commit_claimed_task_input_prefix(
                "original",
                "http-task",
                "key",
                &snapshot(),
                "startup",
                batch(),
                &facts(),
                &link()
            ))
        .expect("writer")
        .is_err());
    assert_eq!(all(&store), before);
    let mut store = Store::open_in_memory().expect("store");
    pending(&mut store);
    let before = all(&store);
    let mut transformed = facts();
    let mut user: serde_json::Value = serde_json::from_str(&transformed[0].payload).expect("user");
    user["client_request_id"] = serde_json::json!(key());
    transformed[0].payload = user.to_string();
    assert!(commit(&mut store, &transformed, &link()).is_err());
    assert_eq!(all(&store), before);
}
