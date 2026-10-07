use super::*;
use crate::{library::LIBRARY_SCOPE, LockUnpoisoned};
use rusqlite::Connection;

fn open(root: &std::path::Path, key: u8) -> std::io::Result<SharedWorkbench> {
    open_workbench_for_home_with_protected_library(
        root,
        HomeId::new("synthetic-office-home"),
        AuthorityId::new("synthetic-office-owner"),
        |_| Ok(Box::new(at_rest::LoopbackKeyWrap::new([key; 32]))),
    )
}
fn rows(root: &std::path::Path) -> Vec<(i64, String, String)> {
    let db = Connection::open(root.join("gaugewright.db")).unwrap();
    let retained = db
        .prepare("SELECT position,kind,payload FROM events WHERE scope_id=?1 ORDER BY position")
        .unwrap()
        .query_map([LIBRARY_SCOPE], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    retained
}
fn key_path(root: &std::path::Path) -> std::path::PathBuf {
    root.join("content-keys")
        .join(format!("{}.dek", crate::org::sha256_hex(LIBRARY_SCOPE)))
}

#[test]
fn protected_library_startup_seals_seed_and_private_titles_before_rehydration() {
    let dir = tempfile::tempdir().unwrap();
    let wb = open(dir.path(), 37).unwrap();
    let chat;
    {
        let mut guard = wb.lock_unpoisoned();
        let mut project = guard
            .library
            .projects
            .get(crate::DEFAULT_PROJECT)
            .unwrap()
            .clone();
        project.name = "synthetic patient project title".into();
        project.extra.insert(
            "future_clinical_metadata".into(),
            serde_json::json!("synthetic patient description"),
        );
        guard
            .store_mut()
            .append_record(
                LIBRARY_SCOPE,
                "project",
                &serde_json::to_string(&project).unwrap(),
            )
            .unwrap();
        guard.rebuild_library();
        guard.hold_session_for_tests(crate::DEFAULT_PROJECT);
        chat = guard
            .create_chat_in_instance(crate::DEFAULT_INSTANCE, "synthetic patient chat title")
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        guard
            .store_mut()
            .append_record(
                LIBRARY_SCOPE,
                "future_metadata_kind",
                "synthetic patient future metadata",
            )
            .unwrap();
        assert_eq!(
            guard.library.chats.get(&chat).unwrap().title,
            "synthetic patient chat title"
        );
    }
    let retained = rows(dir.path());
    assert!(!retained.is_empty());
    for (_, _, payload) in &retained {
        assert!(!payload.contains("synthetic patient"));
        assert!(
            serde_json::from_str::<serde_json::Value>(payload).is_err(),
            "library payload remained JSON: {payload}"
        );
    }
    for path in [
        dir.path().join("gaugewright.db"),
        dir.path().join("gaugewright.db-wal"),
    ] {
        if let Ok(bytes) = std::fs::read(path) {
            assert!(!bytes
                .windows(b"synthetic patient".len())
                .any(|part| part == b"synthetic patient"));
        }
    }
    drop(wb);
    let reopened = open(dir.path(), 37).unwrap();
    let guard = reopened.lock_unpoisoned();
    assert_eq!(
        guard
            .library
            .projects
            .get(crate::DEFAULT_PROJECT)
            .unwrap()
            .name,
        "synthetic patient project title"
    );
    assert_eq!(
        guard.library.chats.get(&chat).unwrap().title,
        "synthetic patient chat title"
    );
    assert_eq!(
        guard
            .store_ref()
            .records(LIBRARY_SCOPE, "future_metadata_kind")
            .unwrap(),
        ["synthetic patient future metadata"]
    );
    assert_eq!(rows(dir.path()), retained);
}

#[test]
fn protected_library_startup_refuses_lost_wrong_and_reclassified_custody_without_seeding() {
    let dir = tempfile::tempdir().unwrap();
    drop(open(dir.path(), 37).unwrap());
    let retained = rows(dir.path());
    assert!(open(dir.path(), 38).is_err());
    assert_eq!(rows(dir.path()), retained);
    assert!(open_workbench_for_home_with_content_keywrap(
        dir.path(),
        HomeId::new("synthetic-office-home"),
        AuthorityId::new("synthetic-office-owner"),
        |_| Ok(Box::new(at_rest::LoopbackKeyWrap::new([37; 32])))
    )
    .is_err());
    assert_eq!(rows(dir.path()), retained);
    let wrapped = std::fs::read(key_path(dir.path())).unwrap();
    std::fs::remove_file(key_path(dir.path())).unwrap();
    assert!(open(dir.path(), 37).is_err());
    assert!(
        !key_path(dir.path()).exists(),
        "startup replaced missing custody"
    );
    assert_eq!(rows(dir.path()), retained);
    std::fs::write(key_path(dir.path()), wrapped).unwrap();
    let db = Connection::open(dir.path().join("gaugewright.db")).unwrap();
    let (position, kind, _) = &retained[0];
    db.execute(
        "UPDATE events SET kind='reclassified_metadata' WHERE scope_id=?1 AND position=?2",
        rusqlite::params![LIBRARY_SCOPE, position],
    )
    .unwrap();
    let damaged = rows(dir.path());
    assert!(open(dir.path(), 37).is_err());
    assert_eq!(rows(dir.path()), damaged);
    db.execute(
        "UPDATE events SET kind=?3 WHERE scope_id=?1 AND position=?2",
        rusqlite::params![LIBRARY_SCOPE, position, kind],
    )
    .unwrap();
    drop(open(dir.path(), 37).unwrap());
    assert_eq!(rows(dir.path()), retained);
}

#[test]
fn protected_library_startup_refuses_plaintext_history_without_adoption() {
    let dir = tempfile::tempdir().unwrap();
    drop(
        open_workbench_with_content_keywrap(dir.path(), |_| {
            Ok(Box::new(at_rest::LoopbackKeyWrap::new([37; 32])))
        })
        .unwrap(),
    );
    let retained = rows(dir.path());
    assert!(!retained.is_empty());
    assert!(open(dir.path(), 37).is_err());
    assert_eq!(rows(dir.path()), retained);
    assert!(!key_path(dir.path()).exists());
    assert!(
        open_workbench_with_content_keywrap(dir.path(), |_| Ok(Box::new(
            at_rest::LoopbackKeyWrap::new([37; 32])
        )))
        .is_ok()
    );
}

#[test]
fn protected_library_startup_refuses_optout_in_isolated_process() {
    const PROBE: &str = "GAUGEDESK_TEST_LIBRARY_OPTOUT_PROBE";
    if std::env::var_os(PROBE).is_some() {
        let dir = tempfile::tempdir().unwrap();
        let result = open_workbench_for_home_with_protected_library(
            dir.path(),
            HomeId::new("synthetic-home"),
            AuthorityId::new("synthetic-owner"),
            |_| panic!("opt-out acquired key wrapping"),
        );
        assert!(result.is_err());
        assert!(rows(dir.path()).is_empty());
        assert!(!key_path(dir.path()).exists());
        let existing_root = std::path::PathBuf::from(
            std::env::var_os("GAUGEDESK_TEST_LIBRARY_EXISTING_ROOT").unwrap(),
        );
        let retained = rows(&existing_root);
        assert!(!retained.is_empty());
        assert!(open_workbench_for_home_with_content_keywrap(
            &existing_root,
            HomeId::new("synthetic-office-home"),
            AuthorityId::new("synthetic-office-owner"),
            |_| panic!("ordinary opt-out acquired key wrapping"),
        )
        .is_err());
        assert_eq!(rows(&existing_root), retained);
        return;
    }
    let existing = tempfile::tempdir().unwrap();
    let wb = open(existing.path(), 37).unwrap();
    wb.lock_unpoisoned()
        .store_mut()
        .append_record(
            LIBRARY_SCOPE,
            "future_metadata_kind",
            "synthetic patient future metadata",
        )
        .unwrap();
    drop(wb);
    Connection::open(existing.path().join("gaugewright.db"))
        .unwrap()
        .execute(
            "DELETE FROM events WHERE scope_id=?1 AND kind!='future_metadata_kind'",
            [LIBRARY_SCOPE],
        )
        .unwrap();
    let retained = rows(existing.path());
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "workbench_state::protected_library_startup_tests::protected_library_startup_refuses_optout_in_isolated_process", "--nocapture"])
        .env(PROBE, "1")
        .env("GAUGEDESK_ENCRYPT_CONTENT", "false")
        .env("GAUGEDESK_TEST_LIBRARY_EXISTING_ROOT", existing.path())
        .output().unwrap();
    assert_eq!(rows(existing.path()), retained);
    assert!(String::from_utf8_lossy(&result.stdout).contains("running 1 test"));
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn protected_library_startup_refuses_unavailable_provider_without_seeding() {
    let dir = tempfile::tempdir().unwrap();
    let result = open_workbench_for_home_with_protected_library(
        dir.path(),
        HomeId::new("synthetic-home"),
        AuthorityId::new("synthetic-owner"),
        |_| Err(std::io::Error::other("synthetic provider unavailable")),
    );
    assert!(result.is_err());
    assert!(rows(dir.path()).is_empty());
    assert!(!key_path(dir.path()).exists());
}
