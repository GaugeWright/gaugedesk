//! Fold checkpoints (SCALE-1): a checkpointed fold equals the full replay, and
//! every doubt about a checkpoint is a full replay.
use super::*;
use gaugedesk_core::run::{RunCommand, RunPhase, RunState};
use gaugedesk_core::SnapshotCodec;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Tally {
    total: i64,
    seen: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum Added {
    Added(i64),
}

enum Add {
    Burst(Vec<i64>),
    Refuse,
}

fn decide(_: &Tally, command: Add) -> Result<Vec<Added>, Rejection> {
    match command {
        Add::Burst(values) => Ok(values.into_iter().map(Added::Added).collect()),
        Add::Refuse => Err(Rejection { reason: "refused" }),
    }
}

fn evolve(state: &Tally, Added::Added(value): Added) -> Tally {
    Tally {
        total: state.total + value,
        seen: state.seen + 1,
    }
}

/// Checkpointed every three events.
struct Checkpointed;
impl Lifecycle for Checkpointed {
    type State = Tally;
    type Command = Add;
    type Event = Added;
    const KIND: &'static str = "tally";
    fn decide(state: &Tally, command: Add) -> Result<Vec<Added>, Rejection> {
        decide(state, command)
    }
    fn evolve(state: &Tally, event: Added) -> Tally {
        evolve(state, event)
    }
    fn snapshot_codec() -> Option<SnapshotCodec<Tally>> {
        Some(SnapshotCodec::serde("tally", 1).every(3))
    }
}

/// The same reducer after a version raise.
struct Raised;
impl Lifecycle for Raised {
    type State = Tally;
    type Command = Add;
    type Event = Added;
    const KIND: &'static str = "tally";
    fn decide(state: &Tally, command: Add) -> Result<Vec<Added>, Rejection> {
        decide(state, command)
    }
    fn evolve(state: &Tally, event: Added) -> Tally {
        evolve(state, event)
    }
    fn snapshot_codec() -> Option<SnapshotCodec<Tally>> {
        Some(SnapshotCodec::serde("tally", 2).every(3))
    }
}

/// The same reducer with no codec: the full replay, as the reference.
struct Replayed;
impl Lifecycle for Replayed {
    type State = Tally;
    type Command = Add;
    type Event = Added;
    const KIND: &'static str = "tally";
    fn decide(state: &Tally, command: Add) -> Result<Vec<Added>, Rejection> {
        decide(state, command)
    }
    fn evolve(state: &Tally, event: Added) -> Tally {
        evolve(state, event)
    }
}

fn snapshots(store: &Store, scope: &str) -> Vec<(i64, i64, String)> {
    store
        .conn
        .prepare(
            "SELECT codec_version, position, state FROM scope_snapshots
             WHERE scope_id = ?1 ORDER BY codec_version",
        )
        .unwrap()
        .query_map([scope], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn event_count(store: &Store, scope: &str) -> i64 {
    store
        .conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE scope_id = ?1",
            [scope],
            |r| r.get(0),
        )
        .unwrap()
}

/// Replace the stored checkpoint with a state no replay could produce, so a
/// fold that returns it proves it resumed from the checkpoint.
fn plant(store: &Store, scope: &str, state: &Tally) {
    let encoded = (SnapshotCodec::<Tally>::serde("tally", 1).encode)(state).unwrap();
    store
        .conn
        .execute(
            "UPDATE scope_snapshots SET state = ?1 WHERE scope_id = ?2",
            params![encoded, scope],
        )
        .unwrap();
}

const PLANTED: Tally = Tally {
    total: 1_000_000,
    seen: 0,
};

#[test]
fn checkpointed_fold_equals_full_replay_at_every_length() {
    let mut store = Store::open_in_memory().unwrap();
    for n in 1..=20_i64 {
        let state = store
            .admit::<Checkpointed>("scope", Add::Burst(vec![n]))
            .unwrap();
        assert_eq!(state, store.fold::<Replayed>("scope").unwrap());
        assert_eq!(state, store.fold::<Checkpointed>("scope").unwrap());
    }
    // The interval is three events: the newest checkpoint follows event 18
    // (position 17), and exactly one row is kept.
    let rows = snapshots(&store, "scope");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, 17);
}

#[test]
fn a_fold_resumes_from_the_checkpoint_and_evolves_only_the_tail() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .admit::<Checkpointed>("scope", Add::Burst(vec![1, 2, 3]))
        .unwrap();
    store
        .admit::<Checkpointed>("scope", Add::Burst(vec![10]))
        .unwrap();
    plant(&store, "scope", &PLANTED);
    let resumed = store.fold::<Checkpointed>("scope").unwrap();
    assert_eq!(resumed.total, 1_000_010, "planted state plus the tail");
    assert_eq!(
        store.fold::<Replayed>("scope").unwrap().total,
        16,
        "a lifecycle without a codec never reads a checkpoint"
    );
}

#[test]
fn a_raised_version_ignores_the_old_checkpoint_and_replaces_it() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .admit::<Checkpointed>("scope", Add::Burst(vec![1, 2, 3]))
        .unwrap();
    plant(&store, "scope", &PLANTED);
    assert_eq!(store.fold::<Raised>("scope").unwrap().total, 6);
    store
        .admit::<Raised>("scope", Add::Burst(vec![4, 5, 6]))
        .unwrap();
    let rows = snapshots(&store, "scope");
    assert_eq!(rows.len(), 1, "the raised version replaced the old row");
    assert_eq!(rows[0].0, 2);
    // The old reducer finds no checkpoint of its own and replays in full.
    assert_eq!(store.fold::<Checkpointed>("scope").unwrap().total, 21);
}

#[test]
fn a_checkpoint_from_another_reducer_build_is_ignored() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .admit::<Checkpointed>("scope", Add::Burst(vec![1, 2, 3]))
        .unwrap();
    plant(&store, "scope", &PLANTED);
    store
        .conn
        .execute(
            "UPDATE scope_snapshots SET reducer_build = 'older-release'",
            [],
        )
        .unwrap();
    assert_eq!(store.fold::<Checkpointed>("scope").unwrap().total, 6);
}

#[test]
fn a_checkpoint_whose_anchor_moved_is_ignored() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .admit::<Checkpointed>("scope", Add::Burst(vec![1, 2, 3]))
        .unwrap();
    plant(&store, "scope", &PLANTED);
    // The anchored event's stored bytes change underneath the checkpoint.
    store
        .conn
        .execute(
            "UPDATE events SET payload = ?1 WHERE scope_id = 'scope' AND position = 2",
            [serde_json::to_string(&Added::Added(30)).unwrap()],
        )
        .unwrap();
    assert_eq!(store.fold::<Checkpointed>("scope").unwrap().total, 33);
    // And when the history is gone entirely.
    store
        .conn
        .execute("DELETE FROM events WHERE scope_id = 'scope'", [])
        .unwrap();
    assert_eq!(
        store.fold::<Checkpointed>("scope").unwrap(),
        Tally::default()
    );
}

#[test]
fn an_undecodable_checkpoint_is_a_full_replay() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .admit::<Checkpointed>("scope", Add::Burst(vec![1, 2, 3]))
        .unwrap();
    store
        .conn
        .execute("UPDATE scope_snapshots SET state = 'not cbor'", [])
        .unwrap();
    assert_eq!(store.fold::<Checkpointed>("scope").unwrap().total, 6);
}

#[test]
fn a_rejected_admission_writes_no_checkpoint() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .admit::<Checkpointed>("scope", Add::Burst(vec![1, 2]))
        .unwrap();
    assert!(store.admit::<Checkpointed>("scope", Add::Refuse).is_err());
    assert!(snapshots(&store, "scope").is_empty());
    assert_eq!(event_count(&store, "scope"), 2);
}

#[test]
fn a_rolled_back_transaction_takes_its_checkpoint_with_it() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .admit::<Checkpointed>("scope", Add::Burst(vec![1, 2]))
        .unwrap();
    {
        let tx = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute(
            "INSERT INTO events (scope_id, position, kind, payload) VALUES ('scope', 2, 'tally', ?1)",
            [serde_json::to_string(&Added::Added(3)).unwrap()],
        )
        .unwrap();
        let state = snapshot::fold::<Checkpointed>(&tx, None, "scope").unwrap();
        snapshot::checkpoint::<Checkpointed>(&tx, None, "scope", &state).unwrap();
        let written: i64 = tx
            .query_row("SELECT COUNT(*) FROM scope_snapshots", [], |r| r.get(0))
            .unwrap();
        assert_eq!(written, 1, "the checkpoint is staged in the transaction");
        // Dropped without commit.
    }
    assert!(snapshots(&store, "scope").is_empty());
    assert_eq!(store.fold::<Checkpointed>("scope").unwrap().total, 3);
}

#[test]
fn a_replayed_command_key_appends_nothing_and_folds_the_same_state() {
    let mut store = Store::open_in_memory().unwrap();
    let first = store
        .admit_with_key::<Checkpointed>("scope", "key", Add::Burst(vec![1, 2, 3]))
        .unwrap();
    let rows = snapshots(&store, "scope");
    let replay = store
        .admit_with_key::<Checkpointed>("scope", "key", Add::Burst(vec![1, 2, 3]))
        .unwrap();
    assert_eq!(first, replay);
    assert_eq!(event_count(&store, "scope"), 3);
    assert_eq!(snapshots(&store, "scope"), rows);
    assert_eq!(replay, store.fold::<Replayed>("scope").unwrap());
}

#[test]
fn checkpoints_are_per_scope() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .admit::<Checkpointed>("a", Add::Burst(vec![1, 2, 3]))
        .unwrap();
    store
        .admit::<Checkpointed>("b", Add::Burst(vec![5]))
        .unwrap();
    plant(&store, "a", &PLANTED);
    assert_eq!(store.fold::<Checkpointed>("b").unwrap().total, 5);
    assert!(snapshots(&store, "b").is_empty());
}

/// Wraps every payload so a test can see that a checkpoint was encoded, and
/// can make one kind's history unavailable.
#[derive(Default)]
struct Sealing {
    hide_notes: AtomicBool,
}
impl ContentCodec for Sealing {
    fn encode(&self, _scope: &str, kind: &str, payload: &str) -> Result<String, String> {
        Ok(format!("sealed:{kind}:{payload}"))
    }
    fn decode(&self, _scope: &str, kind: &str, payload: &str) -> Option<String> {
        if kind == "note" && self.hide_notes.load(Ordering::SeqCst) {
            return None;
        }
        payload
            .strip_prefix(&format!("sealed:{kind}:"))
            .map(str::to_owned)
    }
}

#[test]
fn a_checkpoint_is_sealed_by_the_content_codec() {
    let codec = Arc::new(Sealing::default());
    let mut store = Store::open_in_memory().unwrap().with_codec(codec);
    store
        .admit::<Checkpointed>("scope", Add::Burst(vec![1, 2, 3, 4]))
        .unwrap();
    let rows = snapshots(&store, "scope");
    assert!(rows[0].2.starts_with("sealed:tally:"), "{:?}", rows[0].2);
    assert_eq!(store.fold::<Checkpointed>("scope").unwrap().total, 10);
}

#[test]
fn unavailable_history_before_a_checkpoint_still_refuses_the_fold() {
    let codec = Arc::new(Sealing::default());
    let mut store = Store::open_in_memory().unwrap().with_codec(codec.clone());
    store.append_record("scope", "note", "{}").unwrap();
    store
        .admit::<Checkpointed>("scope", Add::Burst(vec![1, 2, 3, 4]))
        .unwrap();
    assert_eq!(snapshots(&store, "scope").len(), 1);
    codec.hide_notes.store(true, Ordering::SeqCst);
    assert!(matches!(
        store.fold::<Checkpointed>("scope"),
        Err(AdmitError::Codec(_))
    ));
}

#[test]
fn run_lifecycle_checkpoints_and_folds_identically() {
    let mut store = Store::open_in_memory().unwrap();
    for command in [
        RunCommand::RequestRun,
        RunCommand::AdmitRun,
        RunCommand::StartRun,
    ] {
        store.admit::<RunState>("run", command).unwrap();
    }
    let every = i64::from(gaugedesk_core::DEFAULT_SNAPSHOT_INTERVAL);
    for _ in 0..every {
        store
            .admit::<RunState>("run", RunCommand::RecordObservation)
            .unwrap();
    }
    assert_eq!(snapshots(&store, "run").len(), 1);
    let state = store.fold::<RunState>("run").unwrap();
    assert_eq!(state.phase, RunPhase::Running);
    assert_eq!(i64::from(state.observations), every);
    store
        .conn
        .execute("DELETE FROM scope_snapshots", [])
        .unwrap();
    assert_eq!(store.fold::<RunState>("run").unwrap(), state);
}
