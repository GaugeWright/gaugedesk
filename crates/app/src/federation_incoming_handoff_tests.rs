use super::*;
use gaugedesk_workspace::Instance;

fn fixture() -> (
    SharedWorkbench,
    HandoffWire,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    fixture_with_protection(false)
}

fn fixture_with_protection(
    protected: bool,
) -> (
    SharedWorkbench,
    HandoffWire,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    let (wb, mut wire, source_dir, target_dir) = super::super::handoff_consent_tests::fixture();
    let mut source = Store::open_in_memory().unwrap();
    for record in &wire.log {
        source
            .append_record(&record.scope, &record.kind, &record.payload)
            .unwrap();
    }
    source
        .admit_record_facts(
            "project::p1::original-command",
            "original",
            "original action",
            &[CommandRecordFact {
                scope_id: "project::p1::original-command".into(),
                kind: "original_fact".into(),
                payload: "retained action evidence".into(),
            }],
        )
        .unwrap();
    source.append_record(LIBRARY_SCOPE, "project_collaboration_workspace", &serde_json::json!({
        "project_id":"p1", "workspace_id":"workspace-p1", "home_id":"home:alice",
        "substrate":"whipplescript-workspace-v1", "host_contract_revision":"fixture", "host_contract_digest":"fixture"
    }).to_string()).unwrap();
    let workspace = Instance::init_at(source_dir.path().join("workspace")).unwrap();
    workspace
        .seed_main(&[("tutorial.whip", "ordinary source")])
        .unwrap();
    let (format, bundle, workflow_key) = if protected {
        use crate::{
            at_rest::LoopbackKeyWrap,
            content_vault::{ContentVault, LocalFileErasureLedger},
        };
        let vault = |dir: &std::path::Path, kek| {
            Arc::new(
                ContentVault::new(dir, Box::new(LoopbackKeyWrap::new([kek; 32]))).with_ledger(
                    Box::new(LocalFileErasureLedger::new(dir.join("erased.ledger"))),
                ),
            )
        };
        let source_vault = vault(&source_dir.path().join("content-keys"), 7);
        let scope = crate::project_workflow::content_scope("p1").unwrap();
        source_vault.initialize_scope_key(&scope).unwrap();
        let protection = gaugedesk_workspace::WorkflowProtection::new(
            "workspace-p1",
            Arc::new(source_vault.prepare_scope_key(&scope).unwrap()),
        )
        .unwrap();
        drop(
            workspace
                .native_workflow_storage()
                .initialize_protected(&protection)
                .unwrap(),
        );
        let mut guard = wb.lock_unpoisoned();
        guard.content_vault = Some(vault(&target_dir.path().join("content-keys"), 8));
        let recipient = federation_root_signing_key(&guard).public_key();
        let transfer = source_vault
            .prepare_scope_transfer(&scope, &recipient)
            .unwrap();
        let (export, capsule) = transfer
            .with_retained::<_, std::io::Error>(|_, capsule| {
                Ok((
                    workspace.export_protected_workflow(&protection).unwrap(),
                    capsule.clone(),
                ))
            })
            .unwrap();
        wire.kind = HandoffMsgKind::OfferWithWorkflowKeys;
        (
            gaugedesk_workspace::PROTECTED_EXPORT_FORMAT.into(),
            export.0,
            Some(capsule),
        )
    } else {
        drop(
            workspace
                .native_workflow_storage()
                .initialize("workspace-p1")
                .unwrap(),
        );
        (
            workspace.export_format().into(),
            workspace.export().unwrap().0,
            None,
        )
    };
    wire.content.push(HandoffContentBundle {
        target_id: "workspace-p1".into(),
        collaboration: true,
        workflow_key,
        format,
        bundle,
    });
    wire.log = collect_project_log(&source, "p1");
    wire.project_commands = Some(
        source
            .export_command_scopes(|scope| is_project_scope(scope, "p1"))
            .unwrap(),
    );
    assert_eq!(admit_handoff(&wb, &wire)["pending"], true);
    (wb, wire, source_dir, target_dir)
}

#[tokio::test]
async fn late_receiving_failure_rolls_back_authority_and_reuses_installed_workspace() {
    for (failure, protected) in [("home", false), ("receipt", false), ("receipt", true)] {
        let (wb, wire, _source, target) = fixture_with_protection(protected);
        assert_eq!(admit_handoff(&wb, &wire)["pending"], true);
        let probe = rusqlite::Connection::open(wb.lock_unpoisoned().store_ref().path()).unwrap();
        probe.execute_batch(match failure {
            "home" => "CREATE TRIGGER reject_receive BEFORE INSERT ON events WHEN NEW.kind = 'project_collaboration_workspace' AND NEW.payload LIKE '%home:bob%' BEGIN SELECT RAISE(ABORT, 'Home fault'); END;",
            _ => "CREATE TRIGGER reject_receive BEFORE INSERT ON command_receipts WHEN NEW.scope_id = 'handoff::p1' AND NEW.command_key = 'receive' BEGIN SELECT RAISE(ABORT, 'receipt fault'); END;",
        }).unwrap();
        let before = wb
            .lock_unpoisoned()
            .store_ref()
            .scope_high_water_marks()
            .unwrap();
        let request = || HandoffConsentRequest {
            project: "p1".into(),
            source: "alice".into(),
        };
        let response = post_handoff_accept(
            State(wb.clone()),
            axum::http::HeaderMap::new(),
            Json(request()),
        )
        .await
        .into_response();
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{failure}"
        );
        {
            let guard = wb.lock_unpoisoned();
            assert_eq!(guard.store_ref().scope_high_water_marks().unwrap(), before);
            assert!(guard
                .store_ref()
                .committed_record_snapshot("project::p1::original-command", "original")
                .unwrap()
                .is_none());
            assert_eq!(
                retained_handoff(guard.store_ref(), "p1").unwrap().phase,
                HandoffPhase::Draft
            );
            assert!(guard.project_home_id("p1").is_none());
            assert!(!guard.collaboration_workspaces.contains_key("workspace-p1"));
            assert_eq!(pending_incoming(guard.store_ref()).len(), 1);
        }
        // Files may be published, but they confer no receiving authority.
        let path = target.path().join("collaboration-workspaces/workspace-p1");
        let installed = Instance::open_at(&path);
        if protected {
            let guard = wb.lock_unpoisoned();
            let key = guard
                .content_vault
                .as_ref()
                .unwrap()
                .prepare_scope_key(&crate::project_workflow::content_scope("p1").unwrap())
                .unwrap();
            let protection =
                gaugedesk_workspace::WorkflowProtection::new("workspace-p1", Arc::new(key))
                    .unwrap();
            drop(
                installed
                    .native_workflow_storage()
                    .open_existing_protected(&protection)
                    .unwrap(),
            );
        } else {
            drop(
                installed
                    .native_workflow_storage()
                    .open_existing("workspace-p1")
                    .unwrap(),
            );
        }
        std::fs::write(installed.repo().join("tutorial.whip"), "unsaved local edit").unwrap();
        probe.execute_batch("DROP TRIGGER reject_receive").unwrap();
        let response = post_handoff_accept(
            State(wb.clone()),
            axum::http::HeaderMap::new(),
            Json(request()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK, "{failure}");
        let guard = wb.lock_unpoisoned();
        assert_eq!(guard.project_home_id("p1"), Some(guard.home_id()));
        assert_eq!(
            guard.library.project_collaboration_workspaces["p1"].home_id,
            *guard.home_id()
        );
        assert_eq!(
            guard
                .store_ref()
                .committed_record_snapshot("project::p1::original-command", "original")
                .unwrap()
                .as_deref(),
            Some("original action")
        );
        assert!(guard
            .store_ref()
            .committed_record_snapshot("handoff::p1", "receive")
            .unwrap()
            .is_some());
        assert!(pending_incoming(guard.store_ref()).is_empty());
        assert_eq!(participants_of(guard.store_ref(), "p1").len(), 2);
        assert_eq!(
            std::fs::read_to_string(installed.repo().join("tutorial.whip")).unwrap(),
            "unsaved local edit"
        );
    }
}

#[test]
fn receiving_receipt_recovers_before_reimporting_later_workspace_history() {
    let (wb, wire, _source, target) = fixture();
    let mut guard = wb.lock_unpoisoned();
    commit(&mut guard, &wire, Consent::Pending).unwrap();
    let before = guard.store_ref().scope_high_water_marks().unwrap();
    let path = target.path().join("collaboration-workspaces/workspace-p1");
    let installed = Instance::open_at(&path);
    installed
        .seed_main(&[("later.txt", "new receiving history")])
        .unwrap();
    assert!(
        Instance::from_export_at(&path, &wire.content[0].bundle).is_err(),
        "the installation is no longer the unchanged import"
    );
    commit(&mut guard, &wire, Consent::Pending).unwrap();
    assert_eq!(guard.store_ref().scope_high_water_marks().unwrap(), before);
    assert_eq!(
        std::fs::read_to_string(installed.repo().join("later.txt")).unwrap(),
        "new receiving history"
    );
    let mut substituted = wire.clone();
    substituted.log.push(HandoffLogRecord {
        scope: "project::p1::notes".into(),
        kind: "note".into(),
        payload: "changed offer".into(),
    });
    assert!(commit(&mut guard, &substituted, Consent::Pending).is_err());
    assert_eq!(guard.store_ref().scope_high_water_marks().unwrap(), before);
}

#[test]
fn missing_duplicate_foreign_and_escaping_content_refuse_before_publication() {
    for damage in [
        "missing",
        "duplicate",
        "foreign",
        "path",
        "ambiguous_home",
        "foreign_project",
        "foreign_scope",
        "foreign_library_kind",
    ] {
        let (wb, mut wire, _source, target) = fixture();
        match damage {
            "missing" => wire.content.clear(),
            "duplicate" => wire.content.push(wire.content[0].clone()),
            "foreign" => wire.content[0].target_id = "another-workspace".into(),
            "path" => {
                wire.content[0].target_id = "../outside".into();
                let record = wire
                    .log
                    .iter_mut()
                    .find(|record| record.kind == "project_collaboration_workspace")
                    .unwrap();
                let mut value: serde_json::Value = serde_json::from_str(&record.payload).unwrap();
                value["workspace_id"] = serde_json::json!("../outside");
                record.payload = value.to_string();
            }
            "ambiguous_home" => wire.log.push(
                wire.log
                    .iter()
                    .find(|record| record.kind == "project")
                    .unwrap()
                    .clone(),
            ),
            "foreign_scope" => wire.log.push(HandoffLogRecord {
                scope: "org".into(),
                kind: "membership".into(),
                payload: "{}".into(),
            }),
            "foreign_library_kind" => wire.log.push(HandoffLogRecord {
                scope: LIBRARY_SCOPE.into(),
                kind: "foreign".into(),
                payload: "{}".into(),
            }),
            "foreign_project" => {
                let mut record = wire
                    .log
                    .iter()
                    .find(|record| record.kind == "project")
                    .unwrap()
                    .clone();
                let mut value: serde_json::Value = serde_json::from_str(&record.payload).unwrap();
                value["id"] = serde_json::json!("foreign");
                record.payload = value.to_string();
                wire.log.push(record);
            }
            _ => unreachable!(),
        }
        let mut guard = wb.lock_unpoisoned();
        let before = guard.store_ref().scope_high_water_marks().unwrap();
        assert!(
            commit(&mut guard, &wire, Consent::Pending).is_err(),
            "{damage}"
        );
        assert_eq!(guard.store_ref().scope_high_water_marks().unwrap(), before);
        assert!(!target.path().join("collaboration-workspaces").exists());
    }
}

#[test]
fn one_shot_consent_commits_with_receiving_authority_and_receipt_replays_without_it() {
    let (wb, wire, _source, _target) = fixture();
    {
        let mut guard = wb.lock_unpoisoned();
        handoff_oneshot_arm(
            guard.store_mut(),
            "alice",
            "p1",
            "one-offer",
            now_secs() + 3600,
        );
    }
    let probe = rusqlite::Connection::open(wb.lock_unpoisoned().store_ref().path()).unwrap();
    probe.execute_batch("CREATE TRIGGER reject_receive BEFORE INSERT ON command_receipts WHEN NEW.scope_id = 'handoff::p1' AND NEW.command_key = 'receive' BEGIN SELECT RAISE(ABORT, 'receipt fault'); END;").unwrap();
    let before = wb
        .lock_unpoisoned()
        .store_ref()
        .scope_high_water_marks()
        .unwrap();
    assert_eq!(admit_handoff(&wb, &wire)["committed"], false);
    {
        let guard = wb.lock_unpoisoned();
        assert_eq!(guard.store_ref().scope_high_water_marks().unwrap(), before);
        assert!(handoff_oneshot_available(guard.store_ref(), "alice", "p1").is_some());
    }
    probe.execute_batch("DROP TRIGGER reject_receive").unwrap();
    assert_eq!(admit_handoff(&wb, &wire)["committed"], true);
    let after = {
        let guard = wb.lock_unpoisoned();
        assert!(handoff_oneshot_available(guard.store_ref(), "alice", "p1").is_none());
        guard.store_ref().scope_high_water_marks().unwrap()
    };
    assert_eq!(admit_handoff(&wb, &wire)["committed"], true);
    assert_eq!(
        wb.lock_unpoisoned()
            .store_ref()
            .scope_high_water_marks()
            .unwrap(),
        after
    );
}

#[test]
fn a_workspace_owned_by_another_local_project_cannot_be_rebound_by_an_offer() {
    let (wb, wire, _source, target) = fixture();
    let mut guard = wb.lock_unpoisoned();
    let record = wire
        .log
        .iter()
        .find(|record| record.kind == "project_collaboration_workspace")
        .unwrap();
    let mut existing: serde_json::Value = serde_json::from_str(&record.payload).unwrap();
    existing["project_id"] = serde_json::json!("local-project");
    guard
        .store_mut()
        .append_record(LIBRARY_SCOPE, &record.kind, &existing.to_string())
        .unwrap();
    let before = guard.store_ref().scope_high_water_marks().unwrap();
    assert!(commit(&mut guard, &wire, Consent::Pending).is_err());
    assert_eq!(guard.store_ref().scope_high_water_marks().unwrap(), before);
    assert!(!target.path().join("collaboration-workspaces").exists());
}

#[tokio::test]
async fn protected_offers_refuse_missing_erased_or_mismatched_custody_before_authority() {
    for failure in ["missing-vault", "erased", "wrong-scope", "wrong-recipient"] {
        let (wb, mut wire, _source, target) = fixture_with_protection(true);
        {
            let mut guard = wb.lock_unpoisoned();
            match failure {
                "missing-vault" => guard.content_vault = None,
                "erased" => {
                    guard
                        .content_vault
                        .as_ref()
                        .unwrap()
                        .erase_scope_key(&crate::project_workflow::content_scope("p1").unwrap())
                        .unwrap();
                }
                "wrong-scope" | "wrong-recipient" => {
                    let mut capsule =
                        serde_json::to_value(wire.content[0].workflow_key.as_ref().unwrap())
                            .unwrap();
                    if failure == "wrong-scope" {
                        capsule["scope"] = serde_json::json!("foreign");
                    } else {
                        capsule["recipient"] = serde_json::to_value(
                            SigningKey::from_seed(&[99; 32]).unwrap().public_key(),
                        )
                        .unwrap();
                    }
                    wire.content[0].workflow_key = Some(serde_json::from_value(capsule).unwrap());
                }
                _ => unreachable!(),
            }
        }
        // Persist the exact malformed envelope so consent cannot fail only on a
        // changed pending snapshot, masking the custody boundary being tested.
        assert_eq!(admit_handoff(&wb, &wire)["pending"], true);
        let mut guard = wb.lock_unpoisoned();
        let before = guard.store_ref().scope_high_water_marks().unwrap();
        assert!(
            commit(&mut guard, &wire, Consent::Pending).is_err(),
            "{failure}"
        );
        assert_eq!(guard.store_ref().scope_high_water_marks().unwrap(), before);
        assert!(guard.project_home_id("p1").is_none());
        assert!(!target
            .path()
            .join("collaboration-workspaces/workspace-p1/.repo.whipplescript")
            .exists());
    }
}

#[test]
fn protected_carriage_requires_the_explicit_offer_kind_and_one_matching_bundle() {
    let (_wb, original, _source, _target) = fixture_with_protection(true);
    assert!(workflow_keys::validate(&original).is_ok());
    for failure in [
        "legacy",
        "missing-key",
        "plain-format",
        "not-collaboration",
        "duplicate",
        "empty",
    ] {
        let mut wire = original.clone();
        match failure {
            "legacy" => wire.kind = HandoffMsgKind::OfferWithCommands,
            "missing-key" => wire.content[0].workflow_key = None,
            "plain-format" => wire.content[0].format = "whipplescript-vcs-export-v3".into(),
            "not-collaboration" => wire.content[0].collaboration = false,
            "duplicate" => wire.content.push(wire.content[0].clone()),
            "empty" => wire.content.clear(),
            _ => unreachable!(),
        }
        assert!(workflow_keys::validate(&wire).is_err(), "{failure}");
    }
}
