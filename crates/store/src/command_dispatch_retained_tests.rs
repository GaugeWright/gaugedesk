use super::*;
use gaugedesk_core::run::{RunCommand, RunPhase, RunState};

fn dispatch() -> CommandDispatch {
    CommandDispatch {
        runtime_ref: "home:native".into(),
        command_ref: "derived-command-reference".into(),
    }
}

fn assert_unpublished(store: &Store) {
    assert!(store.command_for_key("action", "derive").unwrap().is_none());
    assert!(store.records("action", RunState::KIND).unwrap().is_empty());
    assert!(store.records("action", DISPATCH_KIND).unwrap().is_empty());
    let receipts: i64 = store
        .conn
        .query_row(
            "SELECT COUNT(*) FROM command_receipts WHERE scope_id = 'action'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(receipts, 0);
}

#[test]
fn retained_dispatch_commits_inside_retention_and_recovers_a_lost_response() {
    let mut product = Store::open_in_memory().unwrap();
    let mut observer = product.sibling().unwrap();
    let competing = rusqlite::Connection::open(product.path()).unwrap();
    competing.busy_timeout(std::time::Duration::ZERO).unwrap();
    let mut retained = Store::open_in_memory().unwrap();
    let eraser = rusqlite::Connection::open(retained.path()).unwrap();
    eraser.busy_timeout(std::time::Duration::ZERO).unwrap();
    let (_, source) = product
        .read_for_dispatch(&["source-grants"], |_| Ok(()))
        .unwrap();
    let (_, destination) = product
        .read_for_dispatch(&["destination-grants"], |_| Ok(()))
        .unwrap();
    let response = product
        .with_dispatch_record_admission(&source, |writer| {
            assert!(competing.execute_batch("BEGIN IMMEDIATE").is_err());
            let retention = retained
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let admitted = writer
                .admit_with_dispatch_against::<RunState>(
                    "action",
                    "derive",
                    RunCommand::RequestRun,
                    &dispatch(),
                    &destination,
                )
                .unwrap();
            assert!(!admitted.replayed);
            assert_eq!(admitted.state.phase, RunPhase::Requested);
            let committed = observer
                .committed_dispatch::<RunState>("action", "derive")
                .unwrap()
                .unwrap();
            assert_eq!(committed.command, RunCommand::RequestRun);
            assert_eq!(committed.dispatch, dispatch());
            assert_eq!(
                observer.fold::<RunState>("action").unwrap().phase,
                RunPhase::Requested
            );
            assert!(eraser.execute_batch("BEGIN IMMEDIATE").is_err());
            retention.commit().unwrap();
            Err::<(), _>("response lost after the actual commit")
        })
        .unwrap();
    assert_eq!(response, Err("response lost after the actual commit"));
    competing
        .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
        .unwrap();
    eraser.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
    let replay = product
        .with_dispatch_record_admission(&source, |writer| {
            writer.admit_with_dispatch_against::<RunState>(
                "action",
                "derive",
                RunCommand::RequestRun,
                &dispatch(),
                &destination,
            )
        })
        .unwrap()
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.state.phase, RunPhase::Requested);
    assert_eq!(product.records("action", DISPATCH_KIND).unwrap().len(), 1);
    let mut changed = dispatch();
    changed.command_ref = "different-command-reference".into();
    assert!(product
        .with_dispatch_record_admission(&source, |writer| {
            writer.admit_with_dispatch_against::<RunState>(
                "action",
                "derive",
                RunCommand::RequestRun,
                &changed,
                &destination,
            )
        })
        .unwrap()
        .is_err());
    assert_eq!(product.records("action", DISPATCH_KIND).unwrap().len(), 1);
}

#[test]
fn retained_dispatch_obeys_the_pure_lifecycle_without_reserving_a_rejected_key() {
    let mut product = Store::open_in_memory().unwrap();
    let (_, source) = product
        .read_for_dispatch(&["source-grants"], |_| Ok(()))
        .unwrap();
    let (_, destination) = product
        .read_for_dispatch(&["destination-grants"], |_| Ok(()))
        .unwrap();
    let refused = product
        .with_dispatch_record_admission(&source, |writer| {
            writer.admit_with_dispatch_against::<RunState>(
                "action",
                "derive",
                RunCommand::CompleteRun,
                &dispatch(),
                &destination,
            )
        })
        .unwrap();
    assert!(matches!(refused, Err(AdmitError::Rejected(_))));
    assert_unpublished(&product);
    let admitted = product
        .with_dispatch_record_admission(&source, |writer| {
            writer.admit_with_dispatch_against::<RunState>(
                "action",
                "derive",
                RunCommand::RequestRun,
                &dispatch(),
                &destination,
            )
        })
        .unwrap()
        .unwrap();
    assert!(!admitted.replayed);
    assert_eq!(admitted.state.phase, RunPhase::Requested);
    assert_eq!(
        product.fold::<RunState>("action").unwrap().phase,
        RunPhase::Requested
    );
}

#[test]
fn retained_dispatch_checks_destination_standing_inside_the_source_fence() {
    for case in ["stale", "expired", "foreign"] {
        let mut product = Store::open_in_memory().unwrap();
        let other = Store::open_in_memory().unwrap();
        let (_, source) = product
            .read_for_dispatch(&["source-grants"], |_| Ok(()))
            .unwrap();
        let (_, destination) = product
            .read_for_dispatch(&["destination-grants"], |_| Ok(()))
            .unwrap();
        let destination = match case {
            "stale" => {
                product
                    .append_record("destination-grants", "grant", "revoked")
                    .unwrap();
                destination
            }
            "expired" => destination.with_deadline(std::time::UNIX_EPOCH),
            "foreign" => {
                other
                    .read_for_dispatch(&["destination-grants"], |_| Ok(()))
                    .unwrap()
                    .1
            }
            _ => unreachable!(),
        };
        let entered = std::cell::Cell::new(false);
        let result = product
            .with_dispatch_record_admission(&source, |writer| {
                entered.set(true);
                writer.admit_with_dispatch_against::<RunState>(
                    "action",
                    "derive",
                    RunCommand::RequestRun,
                    &dispatch(),
                    &destination,
                )
            })
            .unwrap();
        assert!(entered.get());
        assert!(result.is_err(), "{case}");
        assert_unpublished(&product);
        let (_, current) = product
            .read_for_dispatch(&["destination-grants"], |_| Ok(()))
            .unwrap();
        let admitted = product
            .with_dispatch_record_admission(&source, |writer| {
                writer.admit_with_dispatch_against::<RunState>(
                    "action",
                    "derive",
                    RunCommand::RequestRun,
                    &dispatch(),
                    &current,
                )
            })
            .unwrap()
            .unwrap();
        assert!(!admitted.replayed);
    }
}

#[test]
fn retained_dispatch_abandonment_and_partial_failure_leave_no_admission() {
    for failure in [
        "BEFORE INSERT ON events WHEN NEW.kind = 'runtime_command_dispatch_v1'",
        "BEFORE INSERT ON command_receipts",
        "BEFORE UPDATE ON commands WHEN NEW.status = 'applied'",
    ] {
        let mut product = Store::open_in_memory().unwrap();
        let (_, source) = product
            .read_for_dispatch(&["source-grants"], |_| Ok(()))
            .unwrap();
        let (_, destination) = product
            .read_for_dispatch(&["destination-grants"], |_| Ok(()))
            .unwrap();
        product
            .with_dispatch_record_admission(&source, |_writer| {})
            .unwrap();
        assert_unpublished(&product);
        product.conn.execute_batch(&format!(
            "CREATE TRIGGER interrupt_dispatch {failure} BEGIN SELECT RAISE(ABORT, 'interrupted publication'); END;"
        )).unwrap();
        assert!(product
            .with_dispatch_record_admission(&source, |writer| {
                writer.admit_with_dispatch_against::<RunState>(
                    "action",
                    "derive",
                    RunCommand::RequestRun,
                    &dispatch(),
                    &destination,
                )
            })
            .unwrap()
            .is_err());
        assert_unpublished(&product);
        product
            .conn
            .execute_batch("DROP TRIGGER interrupt_dispatch")
            .unwrap();
        let admitted = product
            .with_dispatch_record_admission(&source, |writer| {
                writer.admit_with_dispatch_against::<RunState>(
                    "action",
                    "derive",
                    RunCommand::RequestRun,
                    &dispatch(),
                    &destination,
                )
            })
            .unwrap()
            .unwrap();
        assert!(!admitted.replayed);
        assert!(product
            .committed_dispatch::<RunState>("action", "derive")
            .unwrap()
            .is_some());
    }
}

#[test]
fn current_reader_observes_positioned_records_under_the_actual_writer() {
    let mut store = Store::open_in_memory().unwrap();
    let first = store
        .append_record("chat", "resource", "old-output")
        .unwrap();
    store
        .append_record("foreign-chat", "resource", "foreign-output")
        .unwrap();
    store
        .append_record("chat", "other-kind", "not-a-resource")
        .unwrap();
    let (before, basis) = store
        .read_for_dispatch(&["chat"], |reader| reader.records("chat", "resource"))
        .unwrap();
    assert_eq!(before, vec!["old-output"]);
    let competing = rusqlite::Connection::open(store.path()).unwrap();
    competing.busy_timeout(std::time::Duration::ZERO).unwrap();
    // Even an out-of-contract raw replacement at the same position is observed
    // within the writer; a previously selected latest projection is insufficient.
    competing
        .execute(
            "UPDATE events SET payload='changed-output' WHERE scope_id='chat' AND kind='resource'",
            [],
        )
        .unwrap();
    store
        .with_dispatch_record_admission(&basis, |writer| {
            assert_eq!(
                writer.read_retained_records("chat", "resource").unwrap(),
                vec![(first, "changed-output".into())]
            );
            assert!(competing.execute_batch("BEGIN IMMEDIATE").is_err());
            assert!(writer
                .read_retained_records("chat", "absent")
                .unwrap()
                .is_empty());
        })
        .unwrap();
    competing
        .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
        .unwrap();
    assert!(store.command_for_key("chat", "read").unwrap().is_none());
}

#[test]
fn current_reader_unavailable_record_or_ended_parent_cannot_be_revived() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    struct ReaderCodec(Arc<AtomicBool>);
    impl crate::ContentCodec for ReaderCodec {
        fn encode(&self, _: &str, _: &str, payload: &str) -> Result<String, String> {
            Ok(format!("sealed:{payload}"))
        }
        fn decode(&self, _: &str, _: &str, payload: &str) -> Option<String> {
            self.0
                .load(Ordering::Acquire)
                .then(|| payload.strip_prefix("sealed:").map(str::to_owned))
                .flatten()
        }
    }
    let available = Arc::new(AtomicBool::new(true));
    let mut store = Store::open_in_memory()
        .unwrap()
        .with_codec(Arc::new(ReaderCodec(available.clone())));
    store
        .append_record("chat", "consent", "withdrawal")
        .unwrap();
    let (_, basis) = store.read_for_dispatch(&["chat"], |_| Ok(())).unwrap();
    store
        .with_dispatch_record_admission(&basis, |writer| {
            available.store(false, Ordering::Release);
            assert!(matches!(
                writer.read_retained_records("chat", "consent"),
                Err(AdmitError::Codec(_))
            ));
            available.store(true, Ordering::Release);
            assert!(writer.read_retained_records("chat", "consent").is_err());
            assert!(writer.with_native_check(|_| ()).is_err());
        })
        .unwrap();
    let active = Arc::new(AtomicBool::new(true));
    let observed = active.clone();
    let (_, basis) = store.read_for_dispatch(&["chat"], |_| Ok(())).unwrap();
    let basis = basis.with_process_guard(move || observed.load(Ordering::Acquire));
    store
        .with_dispatch_record_admission(&basis, |writer| {
            active.store(false, Ordering::Release);
            assert!(writer.read_retained_records("chat", "consent").is_err());
            active.store(true, Ordering::Release);
            assert!(writer.read_retained_records("chat", "consent").is_err());
        })
        .unwrap();
    let (_, fresh) = store.read_for_dispatch(&["chat"], |_| Ok(())).unwrap();
    store
        .with_dispatch_record_admission(&fresh, |writer| {
            assert_eq!(
                writer.read_retained_records("chat", "consent").unwrap()[0].1,
                "withdrawal"
            )
        })
        .unwrap();
}

#[test]
fn failed_domain_observation_ends_the_retained_writer_even_when_caught() {
    let mut store = Store::open_in_memory().unwrap();
    let (_, basis) = store.read_for_dispatch(&["authority"], |_| Ok(())).unwrap();
    store
        .with_dispatch_record_admission(&basis, |writer| {
            let error = writer.with_retained_observation(|| {
                Err::<(), _>(AdmitError::Rejected(Rejection {
                    reason: "malformed domain facts",
                }))
            });
            assert!(error.is_err());
            assert!(writer.with_retained_observation(|| Ok(())).is_err());
            assert!(writer
                .with_native_check(|_| panic!("caught decoder error restored native work"))
                .is_err());
            assert!(writer
                .commit_claimed("missing", "scope", "key", "{}", &[])
                .is_err());
        })
        .unwrap();
    store
        .with_dispatch_record_admission(&basis, |writer| {
            writer.with_retained_observation(|| Ok(())).unwrap();
            writer
                .with_native_check(|check| check.check_current().unwrap())
                .unwrap();
        })
        .unwrap();
}

#[test]
fn protected_request_without_codec_refuses_before_materializing() {
    let mut store = Store::open_in_memory().unwrap();
    let (_, basis) = store.read_for_dispatch(&["authority"], |_| Ok(())).unwrap();
    let result = store
        .with_dispatch_record_admission(&basis, |writer| {
            writer.commit_protected_request::<RunState, _>(
                "scope",
                "key",
                &serde_json::json!({"actor":"alice"}),
                |_| panic!("unprotected request was authorized"),
                |_| panic!("unprotected request was materialized"),
            )
        })
        .unwrap();
    assert!(result.is_err());
    assert!(store.command_for_key("scope", "key").unwrap().is_none());
    assert!(store.records("scope", RunState::KIND).unwrap().is_empty());
}

#[test]
fn protected_request_refuses_a_passthrough_codec_without_publishing() {
    struct Passthrough;
    impl crate::ContentCodec for Passthrough {
        fn encode(&self, _: &str, _: &str, payload: &str) -> Result<String, String> {
            Ok(payload.into())
        }
        fn decode(&self, _: &str, _: &str, payload: &str) -> Option<String> {
            Some(payload.into())
        }
    }
    let mut store = Store::open_in_memory()
        .unwrap()
        .with_codec(std::sync::Arc::new(Passthrough));
    let (_, basis) = store.read_for_dispatch(&["authority"], |_| Ok(())).unwrap();
    let result = store
        .with_dispatch_record_admission(&basis, |writer| {
            writer.commit_protected_request::<RunState, _>(
                "scope",
                "key",
                &serde_json::json!({"private":"synthetic patient"}),
                |_| Ok(()),
                |_| Ok(RunCommand::RequestRun),
            )
        })
        .unwrap();
    assert!(result.is_err());
    assert!(store.command_for_key("scope", "key").unwrap().is_none());
    assert!(store.records("scope", RunState::KIND).unwrap().is_empty());
    let receipts: i64 = store
        .conn
        .query_row("SELECT COUNT(*) FROM command_receipts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(receipts, 0);
}

#[test]
fn protected_request_encrypts_exact_intent_and_replays_only_under_current_authority() {
    use crate::ContentCodec;
    use ring::{
        aead,
        rand::{SecureRandom, SystemRandom},
    };
    struct Codec;
    impl Codec {
        fn key() -> aead::LessSafeKey {
            aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &[19; 32]).unwrap())
        }
        fn aad(scope: &str, kind: &str) -> Vec<u8> {
            serde_json::to_vec(&("synthetic-storage.v1", scope, kind)).unwrap()
        }
    }
    impl crate::ContentCodec for Codec {
        fn encode(&self, scope: &str, kind: &str, plain: &str) -> Result<String, String> {
            let mut nonce = [0; 12];
            SystemRandom::new().fill(&mut nonce).unwrap();
            let mut body = plain.as_bytes().to_vec();
            Self::key()
                .seal_in_place_append_tag(
                    aead::Nonce::assume_unique_for_key(nonce),
                    aead::Aad::from(Self::aad(scope, kind)),
                    &mut body,
                )
                .map_err(|_| "synthetic seal failed".to_owned())?;
            Ok(format!(
                "protected:{}",
                hex::encode([nonce.to_vec(), body].concat())
            ))
        }
        fn decode(&self, scope: &str, kind: &str, sealed: &str) -> Option<String> {
            let bytes = hex::decode(sealed.strip_prefix("protected:")?).ok()?;
            let nonce = bytes.get(..12)?.try_into().ok()?;
            let mut body = bytes.get(12..)?.to_vec();
            let plain = Self::key()
                .open_in_place(
                    aead::Nonce::assume_unique_for_key(nonce),
                    aead::Aad::from(Self::aad(scope, kind)),
                    &mut body,
                )
                .ok()?
                .to_vec();
            String::from_utf8(plain).ok()
        }
    }
    let mut store = Store::open_in_memory()
        .unwrap()
        .with_codec(std::sync::Arc::new(Codec));
    let intent = serde_json::json!({"private":"synthetic patient consent text"});
    let (_, basis) = store.read_for_dispatch(&["scope"], |_| Ok(())).unwrap();
    let admitted = store
        .with_dispatch_record_admission(&basis, |writer| {
            writer.commit_protected_request::<RunState, _>(
                "scope",
                "opaque-key",
                &intent,
                |_| Ok(()),
                |_| Ok(RunCommand::RequestRun),
            )
        })
        .unwrap()
        .unwrap();
    assert!(!admitted.replayed);
    let snapshot = store
        .command_for_key("scope", "opaque-key")
        .unwrap()
        .unwrap()
        .snapshot_json;
    assert!(snapshot.starts_with("protected:"));
    assert!(!snapshot.contains("synthetic patient consent text"));
    let decoded: serde_json::Value =
        serde_json::from_str(&Codec.decode("scope", RunState::KIND, &snapshot).unwrap()).unwrap();
    assert_eq!(decoded["v"], 2);
    assert_eq!(
        decoded["binding"],
        serde_json::json!({"scope":"scope","key":"opaque-key"})
    );
    assert_eq!(decoded["request"], intent);
    assert!(Codec
        .decode("different-scope", RunState::KIND, &snapshot)
        .is_none());
    let original_events = store.retained_events("scope").unwrap();
    let (_, basis) = store.read_for_dispatch(&["scope"], |_| Ok(())).unwrap();
    let replay = store
        .with_dispatch_record_admission(&basis, |writer| {
            writer.commit_protected_request::<RunState, _>(
                "scope",
                "opaque-key",
                &intent,
                |_| Ok(()),
                |_| panic!("exact retry re-materialized"),
            )
        })
        .unwrap()
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(store.retained_events("scope").unwrap(), original_events);
    let (_, basis) = store.read_for_dispatch(&["scope"], |_| Ok(())).unwrap();
    assert!(store
        .with_dispatch_record_admission(&basis, |writer| {
            writer.commit_protected_request::<RunState, _>(
                "scope",
                "opaque-key",
                &intent,
                |_| {
                    Err(Rejection {
                        reason: "current authority removed",
                    })
                },
                |_| panic!("denied retry materialized"),
            )
        })
        .unwrap()
        .is_err());
    assert_eq!(store.retained_events("scope").unwrap(), original_events);
    store.conn.execute("INSERT INTO commands(command_id,scope_id,idempotency_key,status,snapshot_json) VALUES('forged','scope','other-key','applied',?1)", [&snapshot]).unwrap();
    store.conn.execute("INSERT INTO command_receipts(scope_id,command_key,applied_at) VALUES('scope','other-key',0)", []).unwrap();
    let (_, basis) = store.read_for_dispatch(&["scope"], |_| Ok(())).unwrap();
    assert!(store
        .with_dispatch_record_admission(&basis, |writer| {
            writer.commit_protected_request::<RunState, _>(
                "scope",
                "other-key",
                &intent,
                |_| Ok(()),
                |_| panic!("copied receipt materialized"),
            )
        })
        .unwrap()
        .is_err());
    assert_eq!(store.retained_events("scope").unwrap(), original_events);
    assert_eq!(
        store
            .command_for_key("scope", "opaque-key")
            .unwrap()
            .unwrap()
            .snapshot_json,
        snapshot
    );
}
