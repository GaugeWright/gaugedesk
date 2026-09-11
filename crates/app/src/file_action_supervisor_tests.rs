use super::*;
use crate::file_action_factory::tests::home_storage_fixture;
use std::time::Duration;
use whipplescript_kernel::file_lease::FileLeasePolicy;

fn config() -> NativeEditorSupervisorConfig {
    NativeEditorSupervisorConfig {
        storage: NativeActionStorageConfig {
            input_byte_limit: 4096,
            file_lease: FileLeasePolicy::new(17).unwrap(),
        },
        discovery_page_size: NonZeroUsize::new(1).unwrap(),
    }
}
fn authorize(
    wb: &SharedWorkbench,
    storage: &NativeActionStorage,
    command: &HostActionCommand,
    token: &str,
    key: &str,
) -> String {
    let mut wb = wb.lock_unpoisoned();
    let context = wb.authenticate_action_context(token).unwrap();
    wb.authorize_editor_file_save_dispatch(&context, storage.inputs(), command, key)
        .unwrap()
        .grant_ref
}
async fn notice(
    receiver: &mut mpsc::Receiver<NativeEditorDispatchNotice>,
) -> NativeEditorDispatchNotice {
    tokio::time::timeout(Duration::from_secs(20), receiver.recv())
        .await
        .expect("supervisor did not produce a notice")
        .expect("notice channel closed")
}
async fn stop(sender: watch::Sender<bool>, task: tokio::task::JoinHandle<Result<(), String>>) {
    sender.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
fn runtime_effect_count(root: &std::path::Path, instance: &str) -> usize {
    let store =
        whipplescript_store::SqliteStore::open(root.join("actions/native/runtime.sqlite")).unwrap();
    store.list_effects(instance).unwrap().len()
}

#[tokio::test]
async fn restart_discovers_retained_grants_without_command_or_wakeup_memory() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, storage, token) = home_storage_fixture(dir.path(), config().storage);
    let grant = authorize(&wb, &storage, &command, &token, "restart");
    let instance = command.instance_ref().unwrap();
    drop(storage);
    drop(wb);
    let wb = crate::open_workbench(dir.path()).unwrap();
    let (shutdown, signal) = watch::channel(false);
    let (sender, mut receiver) = mpsc::channel(8);
    let task = tokio::spawn(supervise_native_editor_dispatch(
        wb.clone(),
        config(),
        signal,
        sender,
    ));
    let first = notice(&mut receiver).await;
    assert_eq!(first.grant_ref, grant);
    let NativeEditorDispatchOutcome::Saved {
        cut_id, replayed, ..
    } = first.outcome
    else {
        panic!("unexpected startup outcome: {:?}", first.outcome);
    };
    assert!(!replayed);
    assert!(!cut_id.is_empty());
    assert_eq!(runtime_effect_count(dir.path(), &instance), 2);
    stop(shutdown, task).await;
    drop(wb);
    let wb = crate::open_workbench(dir.path()).unwrap();
    let (shutdown, signal) = watch::channel(false);
    let (sender, mut receiver) = mpsc::channel(8);
    let task = tokio::spawn(supervise_native_editor_dispatch(
        wb,
        config(),
        signal,
        sender,
    ));
    let repeated = notice(&mut receiver).await;
    assert!(
        matches!(repeated.outcome, NativeEditorDispatchOutcome::Saved { cut_id: current, replayed: true, .. } if current == cut_id)
    );
    assert_eq!(runtime_effect_count(dir.path(), &instance), 2);
    stop(shutdown, task).await;
}

#[tokio::test]
async fn grant_commit_restarts_discovery_before_its_cursor_and_refuses_a_second_supervisor() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, storage, token) = home_storage_fixture(dir.path(), config().storage);
    wb.lock_unpoisoned()
        .store_mut()
        .append_record("zz-startup-sentinel", dispatch_grant::GRANT_KIND, "{}")
        .unwrap();
    let (shutdown, signal) = watch::channel(false);
    let (sender, mut receiver) = mpsc::channel(8);
    let task = tokio::spawn(supervise_native_editor_dispatch(
        wb.clone(),
        config(),
        signal.clone(),
        sender.clone(),
    ));
    // This final startup candidate sorts after every real grant. A new grant
    // admitted after its notice can only be found by another discovery pass.
    let sentinel = notice(&mut receiver).await;
    assert_eq!(sentinel.grant_ref, "zz-startup-sentinel");
    assert!(
        supervise_native_editor_dispatch(wb.clone(), config(), signal, sender)
            .await
            .unwrap_err()
            .contains("already running")
    );
    let grant = authorize(&wb, &storage, &command, &token, "wake");
    let received = notice(&mut receiver).await;
    assert_eq!(received.grant_ref, grant);
    assert!(matches!(
        received.outcome,
        NativeEditorDispatchOutcome::Saved { .. }
    ));
    stop(shutdown, task).await;
    assert!(!wb
        .lock_unpoisoned()
        .native_editor_dispatch_running
        .load(Ordering::Acquire));
}

#[tokio::test]
async fn malformed_and_revoked_grants_do_not_block_later_valid_candidates() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, storage, token) = home_storage_fixture(dir.path(), config().storage);
    let revoked = authorize(&wb, &storage, &command, &token, "a-revoked");
    let valid = authorize(&wb, &storage, &command, &token, "z-valid");
    {
        let mut wb = wb.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        wb.revoke_editor_file_save_dispatch(&context, storage.inputs(), &command, &revoked)
            .unwrap();
        wb.store_mut()
            .append_record("a-malformed", dispatch_grant::GRANT_KIND, "{}")
            .unwrap();
    }
    let (shutdown, signal) = watch::channel(false);
    let (sender, mut receiver) = mpsc::channel(8);
    let task = tokio::spawn(supervise_native_editor_dispatch(
        wb.clone(),
        config(),
        signal,
        sender,
    ));
    let malformed = notice(&mut receiver).await;
    assert_eq!(malformed.grant_ref, "a-malformed");
    assert!(
        matches!(malformed.outcome, NativeEditorDispatchOutcome::NeedsAttention { detail } if detail.contains("no committed receipt"))
    );
    let inactive = notice(&mut receiver).await;
    assert_eq!(inactive.grant_ref, revoked);
    assert_eq!(inactive.outcome, NativeEditorDispatchOutcome::Inactive);
    let saved = notice(&mut receiver).await;
    assert_eq!(saved.grant_ref, valid);
    assert!(matches!(
        saved.outcome,
        NativeEditorDispatchOutcome::Saved { .. }
    ));
    stop(shutdown, task).await;
    assert_eq!(
        runtime_effect_count(dir.path(), &command.instance_ref().unwrap()),
        2
    );
}

#[test]
fn discovery_requires_both_receipts_and_exact_signed_grant_history() {
    for corrupt in [
        "outbox receipt",
        "grant receipt",
        "grant signature",
        "grant event",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (wb, command, storage, token) = home_storage_fixture(dir.path(), config().storage);
        let grant = authorize(&wb, &storage, &command, &token, "discover");
        let mut wb = wb.lock_unpoisoned();
        assert_eq!(
            wb.discover_editor_file_save_dispatch(&grant).unwrap(),
            Some(command.clone())
        );
        let sql = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
        match corrupt {
            "outbox receipt" => {
                sql.execute(
                    "DELETE FROM command_receipts WHERE scope_id = ?1",
                    [command.instance_ref().unwrap()],
                )
                .unwrap();
            }
            "grant receipt" => {
                sql.execute("DELETE FROM command_receipts WHERE scope_id = ?1", [&grant])
                    .unwrap();
            }
            "grant signature" => {
                let raw = wb
                    .store_ref()
                    .committed_record_snapshot(&grant, "authorize")
                    .unwrap()
                    .unwrap();
                let mut value: serde_json::Value = serde_json::from_str(&raw).unwrap();
                value["body"]["actor"] = "mallory".into();
                sql.execute(
                    "UPDATE commands SET snapshot_json = ?1 WHERE scope_id = ?2",
                    rusqlite::params![value.to_string(), grant],
                )
                .unwrap();
            }
            "grant event" => {
                sql.execute("DELETE FROM events WHERE scope_id = ?1", [&grant])
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            wb.discover_editor_file_save_dispatch(&grant).is_err(),
            "{corrupt}"
        );
        assert!(!dir.path().join("actions/native/runtime.sqlite").exists());
    }
}

#[test]
fn cancelled_worker_keeps_exclusion_until_it_exits_and_cannot_start_an_effect() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, storage, token) = home_storage_fixture(dir.path(), config().storage);
    let grant = authorize(&wb, &storage, &command, &token, "cancel");
    let running = Arc::new(AtomicBool::new(true));
    let lease = Arc::new(SupervisorLease {
        running: running.clone(),
        cancelled: AtomicBool::new(false),
    });
    let guard = SupervisorGuard(lease.clone());
    let (_shutdown, signal) = watch::channel(false);
    drop(guard);
    assert!(running.load(Ordering::Acquire));
    assert!(drive_candidate(&wb, &grant, config(), &signal, &lease)
        .unwrap()
        .is_none());
    assert!(!dir.path().join("actions/native/runtime.sqlite").exists());
    drop(lease);
    assert!(!running.load(Ordering::Acquire));
}

#[tokio::test]
async fn a_revoked_authentication_source_cannot_execute_a_discovered_grant() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, storage, token) = home_storage_fixture(dir.path(), config().storage);
    let grant = authorize(&wb, &storage, &command, &token, "source-revoked");
    wb.lock_unpoisoned().revoke_account_session(&token);
    let (shutdown, signal) = watch::channel(false);
    let (sender, mut receiver) = mpsc::channel(8);
    let task = tokio::spawn(supervise_native_editor_dispatch(
        wb,
        config(),
        signal,
        sender,
    ));
    let observed = notice(&mut receiver).await;
    assert_eq!(observed.grant_ref, grant);
    assert!(matches!(
        observed.outcome,
        NativeEditorDispatchOutcome::NeedsAttention { .. }
    ));
    stop(shutdown, task).await;
    assert!(!dir.path().join("actions/native/runtime.sqlite").exists());
}

#[tokio::test]
async fn a_closed_notice_channel_does_not_prevent_durable_result_admission() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, storage, token) = home_storage_fixture(dir.path(), config().storage);
    authorize(&wb, &storage, &command, &token, "no-listener");
    let instance = command.instance_ref().unwrap();
    let (shutdown, signal) = watch::channel(false);
    let (sender, receiver) = mpsc::channel(1);
    drop(receiver);
    let task = tokio::spawn(supervise_native_editor_dispatch(
        wb.clone(),
        config(),
        signal,
        sender,
    ));
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let saved = wb
                .lock_unpoisoned()
                .store_ref()
                .retained_events(&instance)
                .unwrap()
                .iter()
                .any(|(_, kind, _)| kind == "native_editor_saved_result_v1");
            if saved {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    stop(shutdown, task).await;
    assert_eq!(runtime_effect_count(dir.path(), &instance), 2);
    assert_eq!(
        wb.lock_unpoisoned()
            .store_ref()
            .retained_events(&instance)
            .unwrap()
            .iter()
            .filter(|(_, kind, _)| kind == "native_editor_saved_result_v1")
            .count(),
        1
    );
}

#[tokio::test]
async fn restart_recovers_a_lost_write_settlement_without_another_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, storage, token) = home_storage_fixture(dir.path(), config().storage);
    let grant = authorize(&wb, &storage, &command, &token, "interrupted");
    {
        let mut wb = wb.lock_unpoisoned();
        let mut driver = wb
            .start_editor_file_save_driver(&storage, &command, &grant)
            .unwrap();
        assert!(matches!(
            wb.step_editor_file_save_driver(&storage, &mut driver)
                .unwrap(),
            NativeEditorSaveProgress::Advanced
        ));
        let fault =
            rusqlite::Connection::open(dir.path().join("actions/native/runtime.sqlite")).unwrap();
        fault.execute_batch("CREATE TRIGGER lose_supervised_terminal BEFORE INSERT ON events WHEN NEW.event_type = 'effect.terminal' BEGIN SELECT RAISE(ABORT, 'lost settlement'); END;").unwrap();
        assert!(wb
            .step_editor_file_save_driver(&storage, &mut driver)
            .is_err());
        fault
            .execute_batch("DROP TRIGGER lose_supervised_terminal")
            .unwrap();
    }
    let instance = command.instance_ref().unwrap();
    let path = dir.path().join("actions/native/runtime.sqlite");
    let before = whipplescript_store::SqliteStore::open(&path)
        .unwrap()
        .list_effects(&instance)
        .unwrap();
    drop(storage);
    drop(wb);
    let wb = crate::open_workbench(dir.path()).unwrap();
    let (shutdown, signal) = watch::channel(false);
    let (sender, mut receiver) = mpsc::channel(8);
    let task = tokio::spawn(supervise_native_editor_dispatch(
        wb,
        config(),
        signal,
        sender,
    ));
    let observed = notice(&mut receiver).await;
    assert_eq!(observed.grant_ref, grant);
    assert!(matches!(
        observed.outcome,
        NativeEditorDispatchOutcome::Saved { .. }
    ));
    stop(shutdown, task).await;
    let after = whipplescript_store::SqliteStore::open(&path)
        .unwrap()
        .list_effects(&instance)
        .unwrap();
    assert_eq!(before, after);
}

#[tokio::test]
async fn dropping_the_supervisor_cancels_its_already_dispatched_worker_before_effects() {
    use std::{
        future::Future,
        task::{Context, Poll},
    };
    struct Wake(tokio::sync::Notify);
    impl futures::task::ArcWake for Wake {
        fn wake_by_ref(value: &Arc<Self>) {
            value.0.notify_one();
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, storage, token) = home_storage_fixture(dir.path(), config().storage);
    authorize(&wb, &storage, &command, &token, "drop-worker");
    let (_shutdown, signal) = watch::channel(false);
    let (sender, _receiver) = mpsc::channel(8);
    let wake = Arc::new(Wake(tokio::sync::Notify::new()));
    let waker = futures::task::waker_ref(&wake);
    let mut context = Context::from_waker(&waker);
    let mut supervisor = Box::pin(supervise_native_editor_dispatch(
        wb.clone(),
        config(),
        signal,
        sender,
    ));
    assert!(matches!(
        supervisor.as_mut().poll(&mut context),
        Poll::Pending
    ));
    // The first wait is the actual discovery worker's completion, not a delay.
    tokio::time::timeout(Duration::from_secs(20), wake.0.notified())
        .await
        .unwrap();
    let running = {
        let guard = wb.lock_unpoisoned();
        // Resume the completed page with the Workbench held: the dispatched
        // driver cannot enter its authority boundary before cancellation.
        assert!(matches!(
            supervisor.as_mut().poll(&mut context),
            Poll::Pending
        ));
        drop(supervisor);
        guard.native_editor_dispatch_running.clone()
    };
    tokio::time::timeout(Duration::from_secs(20), async {
        while running.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!dir.path().join("actions/native/runtime.sqlite").exists());
}
