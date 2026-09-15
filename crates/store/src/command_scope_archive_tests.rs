use super::*;
use crate::command_dispatch::CommandDispatch;
use gaugedesk_core::run::{RunCommand, RunState};

fn dispatch() -> CommandDispatch {
    CommandDispatch {
        runtime_ref: "workspace:one".into(),
        command_ref: "original-fingerprint".into(),
    }
}

fn seed(store: &mut Store, scope: &str) {
    store
        .admit_with_dispatch::<RunState>(scope, "launch", RunCommand::RequestRun, &dispatch())
        .unwrap();
}

#[test]
fn relocation_preserves_original_dispatch_and_replay_across_reopening() {
    let mut source = Store::open_in_memory().unwrap();
    seed(&mut source, "project::one::run");
    seed(&mut source, "project::two::run");
    source
        .claim_command(
            "pending",
            "project::one::pending",
            "retry",
            "exact pending intent",
        )
        .unwrap();
    let archive = source
        .export_command_scopes(|scope| scope.starts_with("project::one::"))
        .unwrap();
    let encoded = serde_json::to_vec(&archive).unwrap();
    let archive: CommandScopeArchive = serde_json::from_slice(&encoded).unwrap();
    let mut destination = Store::open_in_memory().unwrap();
    destination
        .import_command_scopes(&archive, |scope| scope.starts_with("project::one::"))
        .unwrap();
    destination
        .import_command_scopes(&archive, |_| true)
        .unwrap();
    let mut reopened = destination.sibling().unwrap();
    assert_eq!(
        source
            .committed_dispatch::<RunState>("project::one::run", "launch")
            .unwrap(),
        reopened
            .committed_dispatch::<RunState>("project::one::run", "launch")
            .unwrap()
    );
    assert_eq!(
        source.retained_events("project::one::run").unwrap(),
        reopened.retained_events("project::one::run").unwrap()
    );
    assert_eq!(
        reopened
            .command_for_key("project::one::pending", "retry")
            .unwrap()
            .unwrap()
            .status,
        "processing"
    );
    assert!(reopened
        .command_for_key("project::two::run", "launch")
        .unwrap()
        .is_none());
    assert!(
        reopened
            .admit_with_dispatch::<RunState>(
                "project::one::run",
                "launch",
                RunCommand::RequestRun,
                &dispatch()
            )
            .unwrap()
            .replayed
    );
    let changed = CommandDispatch {
        command_ref: "different".into(),
        ..dispatch()
    };
    assert!(reopened
        .admit_with_dispatch::<RunState>(
            "project::one::run",
            "launch",
            RunCommand::RequestRun,
            &changed
        )
        .is_err());
}

#[test]
fn foreign_conflicting_and_incomplete_imports_leave_no_partial_scope() {
    let mut source = Store::open_in_memory().unwrap();
    seed(&mut source, "a");
    seed(&mut source, "b");
    let archive = source.export_command_scopes(|_| true).unwrap();
    let mut target = Store::open_in_memory().unwrap();
    assert!(target
        .import_command_scopes(&archive, |scope| scope == "a")
        .is_err());
    assert!(target.scope_ids().unwrap().is_empty());
    target
        .append_record("b", "existing", "different authority")
        .unwrap();
    assert!(target.import_command_scopes(&archive, |_| true).is_err());
    assert!(target.events("a").unwrap().is_empty());
    assert!(target.command_for_key("a", "launch").unwrap().is_none());
    let mut damaged = archive.clone();
    damaged.scopes[0].receipts.clear();
    let mut empty = Store::open_in_memory().unwrap();
    assert!(empty.import_command_scopes(&damaged, |_| true).is_err());
    assert!(empty.scope_ids().unwrap().is_empty());
    damaged = archive.clone();
    let mut earlier = damaged.scopes[0].commands[0].clone();
    earlier.id = "earlier".into();
    earlier.key = "aaa".into();
    earlier.status = "received".into();
    damaged.scopes[0].commands.push(earlier);
    assert!(empty.import_command_scopes(&damaged, |_| true).is_err());
    damaged = archive.clone();
    damaged.scopes[0].receipts.push(("aaa".into(), 0));
    assert!(empty.import_command_scopes(&damaged, |_| true).is_err());
    damaged = archive.clone();
    damaged.protocol = "future".into();
    assert!(empty.import_command_scopes(&damaged, |_| true).is_err());
    damaged = archive.clone();
    damaged.scopes.push(archive.scopes[0].clone());
    assert!(empty.import_command_scopes(&damaged, |_| true).is_err());
}

#[test]
fn codec_failure_rolls_back_commands_and_missing_retained_evidence_refuses_export() {
    struct Unavailable;
    impl ContentCodec for Unavailable {
        fn encode(&self, _: &str, _: &str, _: &str) -> Result<String, String> {
            Err("unavailable key".into())
        }
        fn decode(&self, _: &str, _: &str, _: &str) -> Option<String> {
            None
        }
    }
    let mut source = Store::open_in_memory().unwrap();
    seed(&mut source, "action");
    let archive = source.export_command_scopes(|_| true).unwrap();
    let mut target = Store::open_in_memory()
        .unwrap()
        .with_codec(Arc::new(Unavailable));
    assert!(target.import_command_scopes(&archive, |_| true).is_err());
    assert!(target.scope_ids().unwrap().is_empty());
    assert!(target
        .command_for_key("action", "launch")
        .unwrap()
        .is_none());
    assert!(source
        .with_codec(Arc::new(Unavailable))
        .export_command_scopes(|_| true)
        .is_err());
}

#[test]
fn staged_archive_rolls_back_with_publication_or_final_admission_failure() {
    let mut source = Store::open_in_memory().unwrap();
    seed(&mut source, "project::one::run");
    let archive = source.export_command_scopes(|_| true).unwrap();
    for fail_commit in [false, true] {
        let mut target = Store::open_in_memory().unwrap();
        let observer = target.sibling().unwrap();
        let (_, basis) = target
            .read_for_dispatch(&["authority"], |_| Ok(()))
            .unwrap();
        if fail_commit {
            // Fail after both imported rows and the new receiving facts were
            // written, at the final receiving receipt, not during validation.
            target
                .conn
                .execute_batch(
                    "CREATE TRIGGER reject_receiving_receipt BEFORE INSERT ON command_receipts
                 WHEN NEW.scope_id = 'receive'
                 BEGIN SELECT RAISE(ABORT, 'receiving receipt failed'); END;",
                )
                .unwrap();
        }
        let result = target
            .with_dispatch_record_admission(&basis, |writer| {
                let writer = writer.import_command_scopes(&archive, |_| true)?;
                assert!(observer.events("project::one::run").unwrap().is_empty());
                if !fail_commit {
                    drop(writer);
                    return Err(AdmitError::Codec("workspace publication failed".into()));
                }
                writer.commit(
                    "receive",
                    "one",
                    "original offer",
                    &[CommandRecordFact {
                        scope_id: "library".into(),
                        kind: "project".into(),
                        payload: "new home".into(),
                    }],
                )
            })
            .unwrap();
        assert!(result.is_err());
        assert!(target.scope_ids().unwrap().is_empty());
        assert!(target
            .command_for_key("project::one::run", "launch")
            .unwrap()
            .is_none());
        assert!(target.command_for_key("receive", "one").unwrap().is_none());
        let receipts: i64 = target
            .conn
            .query_row("SELECT COUNT(*) FROM command_receipts", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(receipts, 0);
    }
}

#[test]
fn staged_archive_commits_original_evidence_with_receiving_facts_despite_lost_reply() {
    struct ReceivingCodec;
    impl ContentCodec for ReceivingCodec {
        fn encode(&self, _: &str, kind: &str, payload: &str) -> Result<String, String> {
            Ok(if kind == "private" {
                format!("receiving:{payload}")
            } else {
                payload.into()
            })
        }
        fn decode(&self, _: &str, kind: &str, payload: &str) -> Option<String> {
            if kind == "private" {
                payload.strip_prefix("receiving:").map(str::to_owned)
            } else {
                Some(payload.into())
            }
        }
    }
    let mut source = Store::open_in_memory().unwrap();
    seed(&mut source, "project::one::run");
    source
        .append_record("project::one::run", "private", "retained content")
        .unwrap();
    let archive = source.export_command_scopes(|_| true).unwrap();
    let mut target = Store::open_in_memory()
        .unwrap()
        .with_codec(Arc::new(ReceivingCodec));
    let observer = target.sibling().unwrap();
    let competitor = Connection::open(target.path()).unwrap();
    competitor.busy_timeout(std::time::Duration::ZERO).unwrap();
    let (_, basis) = target
        .read_for_dispatch(&["authority"], |_| Ok(()))
        .unwrap();
    let result = target
        .with_dispatch_record_admission(&basis, |writer| {
            let writer =
                writer.import_command_scopes(&archive, |scope| scope == "project::one::run")?;
            // Repeated staging is exact, and retains the same writer exclusion.
            let writer = writer.import_command_scopes(&archive, |_| true)?;
            assert!(matches!(competitor.execute_batch("BEGIN IMMEDIATE"),
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::DatabaseBusy));
            assert!(observer.scope_ids().unwrap().is_empty());
            let receipt = writer.commit(
                "receive",
                "one",
                "original offer",
                &[CommandRecordFact {
                    scope_id: "library".into(),
                    kind: "project".into(),
                    payload: "new home".into(),
                }],
            )?;
            assert!(!receipt.replayed);
            assert_eq!(
                observer.records("library", "project").unwrap(),
                vec!["new home"]
            );
            Err::<(), _>(AdmitError::Codec("reply lost after commit".into()))
        })
        .unwrap();
    assert!(result.is_err());
    let mut reopened = target.sibling().unwrap();
    assert_eq!(
        source
            .committed_dispatch::<RunState>("project::one::run", "launch")
            .unwrap(),
        reopened
            .committed_dispatch::<RunState>("project::one::run", "launch")
            .unwrap()
    );
    assert_eq!(
        reopened
            .export_command_scopes(|scope| scope == "project::one::run")
            .unwrap(),
        archive
    );
    assert_eq!(
        reopened
            .committed_record_snapshot("receive", "one")
            .unwrap()
            .as_deref(),
        Some("original offer")
    );
    let raw: String = target
        .conn
        .query_row(
            "SELECT payload FROM events WHERE scope_id = 'project::one::run' AND kind = 'private'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(raw.starts_with("receiving:"));
    competitor
        .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
        .unwrap();
}

#[test]
fn staged_archive_refuses_stale_authority_and_abandons_partial_conflicting_import() {
    let mut source = Store::open_in_memory().unwrap();
    seed(&mut source, "a");
    seed(&mut source, "b");
    let archive = source.export_command_scopes(|_| true).unwrap();
    let mut target = Store::open_in_memory().unwrap();
    let (_, stale) = target
        .read_for_dispatch(&["authority"], |_| Ok(()))
        .unwrap();
    target
        .append_record("authority", "grant", "revoked")
        .unwrap();
    assert!(target
        .with_dispatch_record_admission(&stale, |_| panic!("stale import entered"))
        .is_err());
    target
        .append_record("b", "existing", "different authority")
        .unwrap();
    let before = target.export_command_scopes(|_| true).unwrap();
    let (_, current) = target
        .read_for_dispatch(&["authority"], |_| Ok(()))
        .unwrap();
    for allow_b in [false, true] {
        target
            .with_dispatch_record_admission(&current, |writer| {
                // Validation refusal and a conflict after importing `a` both consume
                // the handle. Swallowing the error cannot commit that partial import.
                assert!(writer
                    .import_command_scopes(&archive, |scope| scope != "b" || allow_b)
                    .is_err());
            })
            .unwrap();
        assert_eq!(target.export_command_scopes(|_| true).unwrap(), before);
        assert!(target.command_for_key("a", "launch").unwrap().is_none());
    }
}
