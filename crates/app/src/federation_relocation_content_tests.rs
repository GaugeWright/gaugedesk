//! WHIP-3: a missing workspace must not become a successful partial handoff.

use super::*;
use gaugedesk_workspace::Instance;
use std::sync::Mutex;

fn fixture(root: &Path, peer_root: &Path) -> SharedWorkbench {
    let peer = AuthorityId::new("bob");
    let peer_key = FileKeyStore::new(peer_root.join("keys")).signing_key(&peer);
    let peer_fed = Federation::open(peer, peer_root, "wss://127.0.0.1:1".into()).unwrap();
    let ticket = peer_fed.mint_ticket(peer_key.public_key(), "bridge:invoke".into(), Some(3600));
    let authority = AuthorityId::new("alice");
    let mut fed = Federation::open(authority.clone(), root, "wss://127.0.0.1:1".into()).unwrap();
    fed.accept_ticket(&ticket, "grant-content-test".into());
    let mut wb = Workbench::new(Store::open_in_memory().unwrap())
        .with_authority(authority)
        .with_root(root)
        .with_federation(fed);
    for (kind, record) in [
        (
            "project",
            serde_json::json!({
                "id": "project-1", "op": "upsert", "name": "Project",
                "is_default": false, "home_id": "home:alice", "network_isolated": false
            }),
        ),
        (
            "work_target",
            serde_json::json!({
                "id": "target-1", "op": "upsert", "name": "Files",
                "owner": {"kind": "project", "project_id": "project-1"},
                "kind": "managed", "authority": "alice", "parties": ["alice"],
                "locator_handle": "managed:target-1", "adapter": "whipplescript",
                "adapter_family": "whipplescript-v1", "vcs_posture": "managed",
                "current_basis": null, "path_scope": ["."],
                "capabilities": {"read": true, "propose": true, "apply": true,
                    "publish": false, "release": false}, "status": "available"
            }),
        ),
        (
            "project_collaboration_workspace",
            serde_json::json!({
                "project_id": "project-1", "workspace_id": "workspace-1",
                "home_id": "home:alice", "substrate": "whipplescript-workspace-v1",
                "host_contract_revision": "fixture", "host_contract_digest": "fixture"
            }),
        ),
    ] {
        wb.store_mut()
            .append_record(LIBRARY_SCOPE, kind, &record.to_string())
            .unwrap();
    }
    wb.rebuild_library();
    let target = Instance::init_at(root.join("targets/target-1")).unwrap();
    target
        .seed_main(&[("target.txt", "target content")])
        .unwrap();
    wb.register_target("target-1", Box::new(target));
    let workspace = Instance::init_at(root.join("collaboration-workspaces/workspace-1")).unwrap();
    workspace
        .seed_main(&[("tutorial.whip", "tutorial source")])
        .unwrap();
    wb.collaboration_workspaces
        .insert("workspace-1".into(), Box::new(workspace));
    Arc::new(Mutex::new(wb))
}

#[tokio::test]
async fn incomplete_workspace_exports_never_offer_a_handoff() {
    for (collaboration, missing) in [(false, true), (true, true), (false, false), (true, false)] {
        let root = tempfile::tempdir().unwrap();
        let peer_root = tempfile::tempdir().unwrap();
        let wb = fixture(root.path(), peer_root.path());
        {
            let mut guard = wb.lock_unpoisoned();
            let complete = collect_project_content(&guard, "project-1").unwrap();
            assert_eq!(complete.len(), 2);
            assert!(complete.iter().any(|bundle| bundle.collaboration));
            assert!(complete.iter().any(|bundle| !bundle.collaboration));
            if missing {
                if collaboration {
                    guard
                        .collaboration_workspaces
                        .remove("workspace-1")
                        .unwrap();
                } else {
                    guard.targets.remove("target-1").unwrap();
                }
            } else {
                let directory = if collaboration {
                    "collaboration-workspaces/workspace-1"
                } else {
                    "targets/target-1"
                };
                // A directory in place of the existing SQLite file is a portable
                // read failure even when the test process may bypass file modes.
                let database = root
                    .path()
                    .join(directory)
                    .join(".repo.whipplescript/branches.sqlite");
                std::fs::remove_file(&database).unwrap();
                std::fs::create_dir(&database).unwrap();
            }
            let error = collect_project_content(&guard, "project-1")
                .expect_err("incomplete export refused");
            let expected = match (collaboration, missing) {
                (false, true) => "no live store for target target-1",
                (true, true) => "project collaboration workspace workspace-1 is not open",
                (false, false) => "cannot bundle target target-1:",
                (true, false) => "cannot bundle collaboration workspace workspace-1:",
            };
            assert!(error.to_string().contains(expected), "{error}");
        }
        let (status, body) = drive_relocate(&wb, "project-1", &AuthorityId::new("bob")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(
            body["error"],
            "project content is unavailable for relocation"
        );
        let guard = wb.lock_unpoisoned();
        assert_eq!(
            load_handoff(guard.store_ref(), "project-1").phase,
            HandoffPhase::Draft
        );
        assert!(unresolved_outgoing(guard.store_ref(), "bob").is_empty());
        assert_eq!(
            guard.project_home_id("project-1").unwrap().as_str(),
            "home:alice"
        );
    }
}

#[test]
fn handoff_snapshot_excludes_product_writers_until_the_offer_is_committed() {
    let root = tempfile::tempdir().unwrap();
    let peer_root = tempfile::tempdir().unwrap();
    let shared = fixture(root.path(), peer_root.path());
    let wb = shared.lock_unpoisoned();
    let store = wb.store_ref();
    let scope = handoff_scope("project-1");
    let mut contender = store.sibling().unwrap();
    let (_, basis) = contender
        .read_for_dispatch(&[&scope, LIBRARY_SCOPE], |store| {
            require_project_writes_available(store, "project-1")
        })
        .unwrap();
    let probe = rusqlite::Connection::open(store.path()).unwrap();
    probe.busy_timeout(std::time::Duration::ZERO).unwrap();
    let bundles = capture_handoff_offer(store, "project-1", "bob", None, |_| {
        assert!(matches!(
            probe.execute_batch("BEGIN IMMEDIATE"),
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::DatabaseBusy
        ));
        // The original connection remains readable while its sibling owns the
        // writer exclusion. This is the actual complete workspace exporter.
        assert_eq!(
            retained_handoff(store, "project-1").unwrap().phase,
            HandoffPhase::Draft
        );
        assert!(!collect_project_log(store, "project-1").is_empty());
        collect_project_content(&wb, "project-1")
    })
    .unwrap();
    assert_eq!(bundles.len(), 2);
    assert_eq!(
        retained_handoff(store, "project-1").unwrap().phase,
        HandoffPhase::Offered
    );
    assert_eq!(
        unresolved_outgoing(store, "bob"),
        vec!["project-1".to_string()]
    );
    assert!(contender
        .with_dispatch_basis(&basis, || {
            panic!("an action prepared before the snapshot entered after its offer")
        })
        .is_err());
    assert!(require_project_writes_available(&contender, "project-1").is_err());
    // No SQLite lock spans the subsequent wire transfer or human consent.
    probe.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
}

#[test]
fn handoff_snapshot_or_offer_commit_failure_leaves_no_partial_offer() {
    for fail_content in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let peer_root = tempfile::tempdir().unwrap();
        let shared = fixture(root.path(), peer_root.path());
        let wb = shared.lock_unpoisoned();
        let store = wb.store_ref();
        let probe = rusqlite::Connection::open(store.path()).unwrap();
        if !fail_content {
            probe
                .execute_batch(
                    "CREATE TRIGGER reject_outgoing BEFORE INSERT ON events
                 WHEN NEW.scope_id = 'handoff::outgoing'
                 BEGIN SELECT RAISE(ABORT, 'outgoing offer fault'); END;",
                )
                .unwrap();
        }
        let before = store.scope_high_water_marks().unwrap();
        let result = capture_handoff_offer(store, "project-1", "bob", None, |_| {
            if fail_content {
                Err(std::io::Error::other("content snapshot fault"))
            } else {
                collect_project_content(&wb, "project-1")
            }
        });
        assert!(if fail_content {
            matches!(result, Err(HandoffOfferError::Content(_)))
        } else {
            matches!(result, Err(HandoffOfferError::Store(_)))
        });
        assert_eq!(store.scope_high_water_marks().unwrap(), before);
        assert_eq!(
            retained_handoff(store, "project-1").unwrap().phase,
            HandoffPhase::Draft
        );
        assert!(unresolved_outgoing(store, "bob").is_empty());
        probe
            .execute_batch("DROP TRIGGER IF EXISTS reject_outgoing")
            .unwrap();
        // The failed admission did not consume the one offer or leave a lock.
        let bundles = capture_handoff_offer(store, "project-1", "bob", None, |_| {
            collect_project_content(&wb, "project-1")
        })
        .unwrap();
        assert_eq!(bundles.len(), 2);
    }
}

#[test]
fn project_command_archives_refuse_missing_consent_evidence_and_foreign_scopes() {
    let mut source = Store::open_in_memory().unwrap();
    source
        .append_record("project::one::a", "evidence", "original")
        .unwrap();
    source
        .append_record("project::one::b", "evidence", "second")
        .unwrap();
    source
        .append_record("project::two::a", "evidence", "private")
        .unwrap();
    let log = collect_project_log(&source, "one");
    let complete = source
        .export_command_scopes(|scope| is_project_scope(scope, "one"))
        .unwrap();
    assert!(project_commands_match_log("one", &log, &complete));
    let partial = source
        .export_command_scopes(|scope| scope == "project::one::a")
        .unwrap();
    assert!(!project_commands_match_log("one", &log, &partial));
    let foreign = source.export_command_scopes(|_| true).unwrap();
    assert!(!project_commands_match_log("one", &log, &foreign));
}

#[test]
fn home_commit_rebinds_the_workspace_atomically_before_tracker_admission() {
    let root = tempfile::tempdir().unwrap();
    let peer_root = tempfile::tempdir().unwrap();
    let source = fixture(root.path(), peer_root.path());
    let source = source.lock_unpoisoned();
    let home = HomeId::new("home:bob");
    let mut target = Workbench::new(source.store_ref().sibling().unwrap())
        .with_authority(AuthorityId::new("bob"))
        .with_home_id(home.clone())
        .with_root(peer_root.path());
    target.rebuild_library();
    let original = target.library.project_collaboration_workspaces["project-1"].clone();
    let member = crate::org::MembershipRecord {
        id: "bob".into(),
        op: crate::org::RecordOp::Upsert,
        org_id: crate::org::ORG_ID.into(),
        authority: "bob".into(),
        email: String::new(),
        role: "owner".into(),
        status: crate::org::MembershipStatus::Active,
        managed_by_scim: false,
        team: None,
    };
    target
        .store_mut()
        .append_record(
            crate::org::ORG_SCOPE,
            "membership",
            &serde_json::to_string(&member).unwrap(),
        )
        .unwrap();
    let token = target.mint_account_session("bob", "passkey", 3600).unwrap();
    let context = target.authenticate_action_context(&token).unwrap();
    assert!(
        target
            .declare_project_tracker(
                &context,
                "project-1",
                "tutorials",
                "declare",
                Default::default(),
            )
            .is_err(),
        "receiving custody does not establish current Home"
    );
    apply_handoff(
        target.store_mut(),
        "project-1",
        HandoffCommand::OfferHandoff,
    )
    .unwrap();
    apply_handoff(target.store_mut(), "project-1", HandoffCommand::SyncLog).unwrap();
    let before = target.store_ref().scope_high_water_marks().unwrap();
    let probe = rusqlite::Connection::open(target.store_ref().path()).unwrap();
    probe
        .execute_batch(
            "CREATE TRIGGER reject_workspace_home BEFORE INSERT ON events
         WHEN NEW.scope_id = 'library' AND NEW.kind = 'project_collaboration_workspace'
         BEGIN SELECT RAISE(ABORT, 'workspace Home binding fault'); END;",
        )
        .unwrap();
    assert!(commit_handoff_and_rebind(&mut target, "project-1", home.clone()).is_err());
    assert_eq!(target.store_ref().scope_high_water_marks().unwrap(), before);
    assert_eq!(
        retained_handoff(target.store_ref(), "project-1")
            .unwrap()
            .phase,
        HandoffPhase::LogSynced
    );
    assert_eq!(
        target.library.projects["project-1"].home_id,
        original.home_id
    );
    assert_eq!(
        target.library.project_collaboration_workspaces["project-1"],
        original
    );
    probe
        .execute_batch("DROP TRIGGER reject_workspace_home")
        .unwrap();
    commit_handoff_and_rebind(&mut target, "project-1", home.clone()).unwrap();
    let mut expected = original;
    expected.home_id = home.clone();
    assert_eq!(target.library.projects["project-1"].home_id, home);
    assert_eq!(
        target.library.project_collaboration_workspaces["project-1"],
        expected
    );
    target.rebuild_library();
    assert_eq!(
        target.library.project_collaboration_workspaces["project-1"],
        expected
    );
    let tracker = target
        .declare_project_tracker(
            &context,
            "project-1",
            "tutorials",
            "declare",
            Default::default(),
        )
        .unwrap();
    assert_eq!(tracker.workspace_id, expected.workspace_id);
}
