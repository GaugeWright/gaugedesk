//! Process-local standing accompanies the event-plane read basis to publication.
use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[test]
fn revoked_process_standing_refuses_runtime_and_record_publication_without_event_changes() {
    let mut store = Store::open_in_memory().unwrap();
    let alive = Arc::new(AtomicBool::new(true));
    let (_, basis) = store.read_for_dispatch(&["authority"], |_| Ok(())).unwrap();
    let captured = alive.clone();
    let basis = basis.with_process_guard(move || captured.load(Ordering::Acquire));
    store.with_dispatch_basis(&basis, || ()).unwrap();
    alive.store(false, Ordering::Release);
    assert!(store
        .with_dispatch_basis(&basis, || panic!("revoked runtime operation ran"))
        .is_err());
    assert!(store
        .with_dispatch_record_admission(&basis, |_| panic!("revoked facts published"))
        .is_err());
    assert!(store.retained_events("authority").unwrap().is_empty());
}

#[test]
fn combining_bases_preserves_every_process_condition() {
    for revoked in 0..2 {
        let mut store = Store::open_in_memory().unwrap();
        let left = Arc::new(AtomicBool::new(true));
        let right = Arc::new(AtomicBool::new(true));
        let (_, first) = store.read_for_dispatch(&["left"], |_| Ok(())).unwrap();
        let (_, second) = store.read_for_dispatch(&["right"], |_| Ok(())).unwrap();
        let captured_left = left.clone();
        let captured_right = right.clone();
        let basis = first
            .with_process_guard(move || captured_left.load(Ordering::Acquire))
            .combine(second.with_process_guard(move || captured_right.load(Ordering::Acquire)))
            .unwrap();
        store.with_dispatch_basis(&basis, || ()).unwrap();
        if revoked == 0 {
            left.store(false, Ordering::Release);
        } else {
            right.store(false, Ordering::Release);
        }
        assert!(store
            .with_dispatch_basis(&basis, || panic!("combined standing was discarded"))
            .is_err());
    }
}

#[test]
fn monotonic_expiry_refuses_even_with_a_future_wall_clock_deadline() {
    let mut store = Store::open_in_memory().unwrap();
    let (_, basis) = store.read_for_dispatch(&["authority"], |_| Ok(())).unwrap();
    let end = std::time::Instant::now();
    let basis = basis
        .with_deadline(std::time::SystemTime::now() + std::time::Duration::from_secs(3600))
        .with_process_guard(move || std::time::Instant::now() < end);
    assert!(store
        .with_dispatch_basis(&basis, || panic!("expired monotonic standing ran"))
        .is_err());
}

#[test]
fn standing_is_rechecked_at_commit_after_external_retention() {
    for lifecycle in [false, true] {
        let mut store = Store::open_in_memory().unwrap();
        let alive = Arc::new(AtomicBool::new(true));
        let (_, basis) = store.read_for_dispatch(&["authority"], |_| Ok(())).unwrap();
        let captured = alive.clone();
        let basis = basis.with_process_guard(move || captured.load(Ordering::Acquire));
        if lifecycle {
            let result = store
                .with_dispatch_record_admission(&basis, |writer| {
                    alive.store(false, Ordering::Release);
                    writer.commit_dispatch::<gaugedesk_core::run::RunState>(
                        "published",
                        "request",
                        gaugedesk_core::run::RunCommand::RequestRun,
                        &CommandDispatch {
                            runtime_ref: "runtime".into(),
                            command_ref: "command".into(),
                        },
                    )
                })
                .unwrap();
            assert!(result.is_err());
        } else {
            let result = store
                .with_dispatch_record_admission(&basis, |writer| {
                    alive.store(false, Ordering::Release);
                    writer.commit(
                        "published",
                        "request",
                        "{}",
                        &[crate::CommandRecordFact {
                            scope_id: "published".into(),
                            kind: "fact".into(),
                            payload: "{}".into(),
                        }],
                    )
                })
                .unwrap();
            assert!(result.is_err());
        }
        assert!(store
            .command_for_key("published", "request")
            .unwrap()
            .is_none());
        assert!(store.retained_events("published").unwrap().is_empty());
    }
}

#[test]
fn final_dispatch_refusal_rolls_back_lifecycle_outbox_and_receipt_repair() {
    use gaugedesk_core::run::{RunCommand, RunState};
    let mut store = Store::open_in_memory().unwrap();
    let dispatch = CommandDispatch {
        runtime_ref: "native".into(),
        command_ref: "exact command".into(),
    };
    let refuse = || {
        Err(AdmitError::Rejected(Rejection {
            reason: "final standing ended",
        }))
    };
    let prepared =
        PreparedDispatch::<RunState>::new("scope", "key", RunCommand::RequestRun, &dispatch)
            .unwrap();
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    assert!(commit_dispatch::<RunState>(tx, prepared, refuse).is_err());
    assert!(store.retained_events("scope").unwrap().is_empty());
    assert!(store.command_for_key("scope", "key").unwrap().is_none());
    store
        .admit_with_dispatch::<RunState>("scope", "key", RunCommand::RequestRun, &dispatch)
        .unwrap();
    let original = store.command_for_key("scope", "key").unwrap().unwrap();
    let events = store.retained_events("scope").unwrap();
    store
        .set_command_status(&original.command_id, "processing")
        .unwrap();
    let prepared =
        PreparedDispatch::<RunState>::new("scope", "key", RunCommand::RequestRun, &dispatch)
            .unwrap();
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    assert!(commit_dispatch::<RunState>(tx, prepared, refuse).is_err());
    assert_eq!(
        store
            .command_for_key("scope", "key")
            .unwrap()
            .unwrap()
            .status,
        "processing"
    );
    assert_eq!(store.retained_events("scope").unwrap().len(), events.len());
}

#[test]
fn revocation_during_event_encoding_refuses_public_fenced_dispatch() {
    #[derive(serde::Serialize)]
    struct Command {
        #[serde(skip)]
        alive: Arc<AtomicBool>,
    }
    #[derive(Clone)]
    struct Event(Arc<AtomicBool>);
    impl serde::Serialize for Event {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            // Simulate process termination while the final event is encoded,
            // after entry authorization, before the transaction commits.
            self.0.store(false, Ordering::Release);
            serializer.serialize_bool(true)
        }
    }
    impl<'de> serde::Deserialize<'de> for Event {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let alive = <bool as serde::Deserialize>::deserialize(deserializer)?;
            Ok(Self(Arc::new(AtomicBool::new(alive))))
        }
    }
    struct EncodingLifecycle;
    impl Lifecycle for EncodingLifecycle {
        type State = ();
        type Command = Command;
        type Event = Event;
        const KIND: &'static str = "encoding-fixture";
        fn decide(_: &(), command: Command) -> Result<Vec<Event>, Rejection> {
            Ok(vec![Event(command.alive)])
        }
        fn evolve(_: &(), _: Event) {}
    }
    for retained in [false, true] {
        let mut store = Store::open_in_memory().unwrap();
        let alive = Arc::new(AtomicBool::new(true));
        let captured = alive.clone();
        let (_, basis) = store.read_for_dispatch(&["authority"], |_| Ok(())).unwrap();
        let basis = basis.with_process_guard(move || captured.load(Ordering::Acquire));
        let dispatch = CommandDispatch {
            runtime_ref: "native".into(),
            command_ref: "original".into(),
        };
        let result = if retained {
            store
                .with_dispatch_record_admission(&basis, |writer| {
                    writer.admit_with_dispatch_against::<EncodingLifecycle>(
                        "scope",
                        "key",
                        Command {
                            alive: alive.clone(),
                        },
                        &dispatch,
                        &basis,
                    )
                })
                .unwrap()
        } else {
            store.admit_with_dispatch_against::<EncodingLifecycle>(
                "scope",
                "key",
                Command {
                    alive: alive.clone(),
                },
                &dispatch,
                &basis,
            )
        };
        assert!(result.is_err(), "retained={retained}");
        assert!(!alive.load(Ordering::Acquire));
        assert!(store.command_for_key("scope", "key").unwrap().is_none());
        assert!(store.retained_events("scope").unwrap().is_empty());
    }
}
