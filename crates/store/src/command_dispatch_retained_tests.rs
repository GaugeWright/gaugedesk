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
