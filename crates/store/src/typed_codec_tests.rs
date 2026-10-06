//! Exercise the actual typed entry points, including retained owner receipts.
use super::*;
use command_dispatch::{CommandDispatch, LifecycleBatch};
use gaugedesk_core::{
    merge::{MergeCommand, MergePhase, MergeState},
    run::{RunCommand, RunPhase, RunState},
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Default)]
struct Codec {
    unavailable: AtomicBool,
    remaining: AtomicUsize,
}
impl ContentCodec for Codec {
    fn encode(&self, scope: &str, kind: &str, body: &str) -> Result<String, String> {
        let remaining = self.remaining.load(Ordering::SeqCst);
        if remaining == 1 {
            return Err("synthetic encode refusal".into());
        }
        if remaining > 1 {
            self.remaining.fetch_sub(1, Ordering::SeqCst);
        }
        Ok(serde_json::to_string(&(scope, kind, body)).unwrap())
    }
    fn decode(&self, scope: &str, kind: &str, body: &str) -> Option<String> {
        if self.unavailable.load(Ordering::SeqCst) {
            return None;
        }
        let (s, k, p): (String, String, String) = serde_json::from_str(body).ok()?;
        (s == scope && k == kind).then_some(p)
    }
}
fn store() -> (Store, Arc<Codec>) {
    let codec = Arc::new(Codec::default());
    (
        Store::open_in_memory().unwrap().with_codec(codec.clone()),
        codec,
    )
}
fn batch(commands: Vec<RunCommand>) -> LifecycleBatch<RunState> {
    LifecycleBatch {
        scope: "chat".into(),
        commands,
    }
}
fn dispatch() -> CommandDispatch {
    CommandDispatch {
        runtime_ref: "runtime".into(),
        command_ref: "native-command".into(),
    }
}
fn raw(store: &Store) -> Vec<(String, String, String)> {
    store
        .conn
        .prepare("SELECT scope_id,kind,payload FROM events ORDER BY scope_id,position")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}
fn assert_encoded(store: &Store, codec: &Codec) {
    let rows = raw(store);
    assert!(!rows.is_empty());
    for (scope, kind, body) in rows {
        assert!(codec.decode(&scope, &kind, &body).is_some());
        assert!(serde_json::from_str::<gaugedesk_core::run::RunEvent>(&body).is_err());
    }
}
#[test]
fn direct_keyed_materialized_request_and_dispatch_use_codec_and_replay_facts() {
    for path in [
        "direct",
        "keyed",
        "materialized",
        "request",
        "dispatch",
        "retained-dispatch",
    ] {
        let (mut store, codec) = store();
        let mut submit = |command| match path {
            "direct" => store.admit::<RunState>("chat", command).map(|_| false),
            "keyed" => store
                .admit_with_key::<RunState>("chat", "key", command)
                .map(|_| false),
            "materialized" => store
                .admit_materialized::<RunState>("chat", "key", command)
                .map(|r| r.replayed),
            "request" => store
                .admit_request::<RunState, _>("chat", "key", &"intent", |_| Ok(()), |_| Ok(command))
                .map(|r| r.replayed),
            "dispatch" => store
                .admit_with_dispatch::<RunState>("chat", "key", command, &dispatch())
                .map(|r| r.replayed),
            _ => store
                .with_record_admission(|writer| {
                    writer.commit_dispatch::<RunState>("chat", "key", command, &dispatch())
                })
                .unwrap()
                .map(|r| r.replayed),
        };
        assert!(!submit(RunCommand::RequestRun).unwrap(), "{path}");
        if path != "direct" {
            submit(RunCommand::RequestRun).unwrap();
        }
        assert_encoded(&store, &codec);
        assert_eq!(
            store.fold::<RunState>("chat").unwrap().phase,
            RunPhase::Requested
        );
        let before = raw(&store);
        codec.unavailable.store(true, Ordering::SeqCst);
        assert!(store.fold::<RunState>("chat").is_err(), "{path}");
        assert!(store
            .admit::<RunState>("chat", RunCommand::AdmitRun)
            .is_err());
        assert_eq!(raw(&store), before);
    }
}
#[test]
fn typed_folds_refuse_reclassified_protected_history_instead_of_omitting_it() {
    let (mut store, _) = store();
    store
        .admit::<RunState>("chat", RunCommand::RequestRun)
        .unwrap();
    store
        .conn
        .execute("UPDATE events SET kind='other-kind'", [])
        .unwrap();
    assert!(store.fold::<RunState>("chat").is_err());
    assert!(store
        .admit_with_key::<RunState>("chat", "key", RunCommand::RequestRun)
        .is_err());
    assert!(store
        .admit_request::<RunState, _>(
            "chat",
            "request",
            &"intent",
            |_| panic!("unavailable facts reached authorization"),
            |_| Ok(RunCommand::RequestRun)
        )
        .is_err());
    assert!(store
        .admit_with_dispatch::<RunState>("chat", "dispatch", RunCommand::RequestRun, &dispatch())
        .is_err());
    assert_eq!(raw(&store).len(), 1);
}
#[test]
fn retained_prefix_pair_and_completed_owner_observe_encoded_immutable_events() {
    for recorded in [false, true] {
        let (mut store, codec) = store();
        store
            .claim_command("original", "task", "key", "input")
            .unwrap();
        let start = batch(vec![
            RunCommand::RequestRun,
            RunCommand::AdmitRun,
            RunCommand::StartRun,
        ]);
        let prefix = store
            .with_record_admission(|writer| {
                writer.commit_claimed_lifecycle_prefix(
                    "original",
                    "task",
                    "key",
                    "input",
                    "start",
                    start,
                    &[],
                )
            })
            .unwrap()
            .unwrap();
        assert_eq!(prefix.positions.len(), 3);
        let replay = store
            .with_record_admission(|writer| {
                writer.commit_claimed_lifecycle_prefix(
                    "original",
                    "task",
                    "key",
                    "input",
                    "start",
                    batch(vec![
                        RunCommand::RequestRun,
                        RunCommand::AdmitRun,
                        RunCommand::StartRun,
                    ]),
                    &[],
                )
            })
            .unwrap()
            .unwrap();
        assert_eq!(replay.positions, prefix.positions);
        assert!(replay.replayed);
        let complete = batch(vec![RunCommand::RecordObservation, RunCommand::CompleteRun]);
        let merge = LifecycleBatch::<MergeState> {
            scope: "chat".into(),
            commands: vec![MergeCommand::StartMerge, MergeCommand::WorkspaceClean],
        };
        store
            .with_record_admission(|writer| {
                if recorded {
                    writer.commit_recorded_claimed_lifecycle_pair(
                        "original",
                        "task",
                        "key",
                        "input",
                        complete,
                        merge,
                        |_| Ok(Vec::new()),
                    )
                } else {
                    writer.commit_claimed_lifecycle_pair(
                        "original",
                        "task",
                        "key",
                        "input",
                        complete,
                        merge,
                        |_| Ok(Vec::new()),
                    )
                }
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            store.fold::<RunState>("chat").unwrap().phase,
            RunPhase::Completed
        );
        assert_eq!(
            store.fold::<MergeState>("chat").unwrap().phase,
            MergePhase::Clean
        );
        assert_encoded(&store, &codec);
        if recorded {
            store
                .with_record_admission(|writer| {
                    let origin = writer
                        .require_recorded_claimed_lifecycle_pair::<RunState, MergeState>(
                            "original", "task", "key", "input", "chat",
                        )
                        .unwrap();
                    assert_eq!(origin.first_events().len(), 2);
                    writer
                        .require_recorded_lifecycle_prefix::<RunState, RunState, MergeState>(
                            "original",
                            "task",
                            "key",
                            "input",
                            "start",
                            &batch(vec![
                                RunCommand::RequestRun,
                                RunCommand::AdmitRun,
                                RunCommand::StartRun,
                            ]),
                            &[],
                        )
                        .unwrap();
                })
                .unwrap();
        }
    }
}
#[test]
fn encode_failure_rolls_back_typed_batches_and_transactional_receipts() {
    let (mut store, codec) = store();
    store
        .claim_command("original", "task", "key", "input")
        .unwrap();
    codec.remaining.store(2, Ordering::SeqCst);
    assert!(store
        .with_record_admission(|writer| writer.commit_claimed_lifecycle_prefix(
            "original",
            "task",
            "key",
            "input",
            "start",
            batch(vec![RunCommand::RequestRun, RunCommand::AdmitRun]),
            &[]
        ))
        .unwrap()
        .is_err());
    assert!(raw(&store).is_empty());
    assert!(!store
        .claimed_lifecycle_prefix_recorded("original", "start")
        .unwrap());
    codec.remaining.store(1, Ordering::SeqCst);
    assert!(store
        .admit_with_key::<RunState>("chat", "direct", RunCommand::RequestRun)
        .is_err());
    assert!(store
        .admit_request::<RunState, _>(
            "chat",
            "request",
            &"intent",
            |_| Ok(()),
            |_| Ok(RunCommand::RequestRun)
        )
        .is_err());
    assert!(store
        .admit_with_dispatch::<RunState>("chat", "dispatch", RunCommand::RequestRun, &dispatch())
        .is_err());
    assert!(raw(&store).is_empty());
    for key in ["direct", "request", "dispatch"] {
        assert!(store
            .conn
            .query_row(
                "SELECT 1 FROM command_receipts WHERE scope_id='chat' AND command_key=?1",
                [key],
                |_| Ok(())
            )
            .optional()
            .unwrap()
            .is_none());
    }
}

#[test]
fn claimed_single_lifecycle_uses_codec_and_commits_only_once() {
    let (mut store, codec) = store();
    store
        .claim_command("original", "task", "key", "input")
        .unwrap();
    for _ in 0..2 {
        store
            .with_record_admission(|writer| {
                writer.commit_claimed_lifecycle(
                    "original",
                    "task",
                    "key",
                    "input",
                    batch(vec![RunCommand::RequestRun, RunCommand::AdmitRun]),
                    &[],
                )
            })
            .unwrap()
            .unwrap();
    }
    assert_eq!(
        store.fold::<RunState>("chat").unwrap().phase,
        RunPhase::Admitted
    );
    assert_eq!(raw(&store).len(), 2);
    assert_encoded(&store, &codec);
}

#[test]
fn legacy_untransformed_prefix_keeps_original_identity_and_obeys_decoder_policy() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .claim_command("original", "task", "key", "input")
        .unwrap();
    let first = store
        .with_record_admission(|writer| {
            writer.commit_claimed_lifecycle_prefix(
                "original",
                "task",
                "key",
                "input",
                "start",
                batch(vec![RunCommand::RequestRun]),
                &[],
            )
        })
        .unwrap()
        .unwrap();
    let scope = Store::claimed_lifecycle_prefix_scope("original", "start");
    let body = store
        .records(&scope, "command_prefix_result_v1")
        .unwrap()
        .remove(0);
    let mut marker: serde_json::Value = serde_json::from_str(&body).unwrap();
    marker["revision"] = "claimed-lifecycle-prefix/v1".into();
    for event in marker["events"].as_array_mut().unwrap() {
        event["encoded"] = false.into();
    }
    store
        .conn
        .execute(
            "UPDATE events SET payload=?1 WHERE scope_id=?2",
            params![marker.to_string(), scope],
        )
        .unwrap();
    let before = raw(&store);
    let replay = store
        .with_record_admission(|writer| {
            writer.commit_claimed_lifecycle_prefix(
                "original",
                "task",
                "key",
                "input",
                "start",
                batch(vec![RunCommand::RequestRun]),
                &[],
            )
        })
        .unwrap()
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.positions, first.positions);
    assert_eq!(raw(&store), before);
    store.codec = Some(Arc::new(Codec::default()));
    assert!(store
        .with_record_admission(|writer| writer.commit_claimed_lifecycle_prefix(
            "original",
            "task",
            "key",
            "input",
            "start",
            batch(vec![RunCommand::RequestRun]),
            &[],
        ))
        .unwrap()
        .is_err());
    assert_eq!(raw(&store), before);
}
