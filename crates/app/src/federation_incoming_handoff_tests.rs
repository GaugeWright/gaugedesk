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

#[test]
fn task_correlation_signed_incoming_private_metadata_refuses_before_commit() {
    for (scope, kind) in [
        (
            "project::p1::notes",
            crate::engine::TASK_CORRELATION_ATTEMPT_KIND,
        ),
        (
            "correlation-chat",
            crate::engine::TASK_CORRELATION_ATTEMPT_KIND,
        ),
        ("http-task-attempt::foreign-claim", "note"),
    ] {
        let (wb, mut wire, _source, target) = fixture();
        wire.log.push(HandoffLogRecord {
            scope: LIBRARY_SCOPE.into(),
            kind: "instance".into(),
            payload: serde_json::json!({"id":"correlation-placement","kind":"using","agent_id":"synthetic-agent","project_id":"p1"}).to_string(),
        });
        wire.log.push(HandoffLogRecord {
            scope: LIBRARY_SCOPE.into(),
            kind: "chat".into(),
            payload: serde_json::json!({"id":"correlation-chat","instance_id":"correlation-placement","title":"Synthetic history"}).to_string(),
        });
        wire.log.push(HandoffLogRecord {
            scope: scope.into(),
            kind: kind.into(),
            payload: "{}".into(),
        });
        // Keep the original-command archive consistent with the offered log;
        // the refusal must come from private metadata, not archive mismatch.
        let mut offered = Store::open_in_memory().unwrap();
        for record in &wire.log {
            offered
                .append_record(&record.scope, &record.kind, &record.payload)
                .unwrap();
        }
        wire.project_commands = Some(
            offered
                .export_command_scopes(|scope| is_project_scope(scope, "p1"))
                .unwrap(),
        );
        wire.log
            .retain(|record| !is_project_scope(&record.scope, "p1"));
        wire.log
            .extend(wire.project_commands.as_ref().unwrap().events().map(
                |(scope, _, kind, payload)| HandoffLogRecord {
                    scope: scope.into(),
                    kind: kind.into(),
                    payload: payload.into(),
                },
            ));
        let before = {
            let mut guard = wb.lock_unpoisoned();
            assert!(
                verify_handoff(&guard, &wire).is_ok(),
                "signed source authority must remain valid: {:?}",
                verify_handoff(&guard, &wire).err()
            );
            handoff_oneshot_arm(
                guard.store_mut(),
                "alice",
                "p1",
                "private-metadata-offer",
                now_secs() + 3600,
            );
            guard.store_ref().scope_high_water_marks().unwrap()
        };
        assert_eq!(
            admit_handoff(&wb, &wire)["committed"],
            false,
            "{scope}/{kind}"
        );
        let guard = wb.lock_unpoisoned();
        assert_eq!(guard.store_ref().scope_high_water_marks().unwrap(), before);
        assert!(!target.path().join("collaboration-workspaces").exists());
        assert!(guard.store_ref().events(scope).unwrap().is_empty());
    }
}

#[test]
fn task_correlation_multi_turn_chat_export_import_preserves_summary_and_boundary_positions() {
    let (wb, mut wire, _source, _target) = fixture();
    let mut source = Store::open_in_memory().unwrap();
    for record in &wire.log {
        source
            .append_record(&record.scope, &record.kind, &record.payload)
            .unwrap();
    }
    source.append_record(LIBRARY_SCOPE,"instance",&serde_json::json!({"id":"correlation-placement","kind":"using","agent_id":"synthetic-agent","project_id":"p1"}).to_string()).unwrap();
    source.append_record(LIBRARY_SCOPE,"chat",&serde_json::json!({"id":"correlation-chat","instance_id":"correlation-placement","title":"Synthetic correlation history"}).to_string()).unwrap();
    let mut coordinates = Vec::new();
    for turn in 0..2 {
        let claim = format!("synthetic-claim:{turn}");
        let attempt_scope = crate::engine::task_attempt_scope(&claim);
        let user=source.append_record_with_linked_record("correlation-chat","transcript",&serde_json::json!({"type":"user","text":format!("turn {turn}"),"home_id":"home:alice","actor_id":"alice","chat_id":"correlation-chat","client_request_id":format!("composed:{turn}")}).to_string(),&attempt_scope,crate::engine::TASK_CORRELATION_ATTEMPT_KIND,|position|Ok(serde_json::json!({"chat_id":"correlation-chat","user_entry_id":position,"command_id":claim,"body_digest":format!("private-input:{turn}")}).to_string())).unwrap();
        let assistant = source
            .append_record(
                "correlation-chat",
                "transcript",
                &serde_json::json!({"type":"assistant","text":format!("settled {turn}")})
                    .to_string(),
            )
            .unwrap();
        crate::turn_summary::append(
            &mut source,
            "correlation-chat",
            &crate::turn_summary::TurnSummary {
                user_entry_id: user,
                ..Default::default()
            },
        )
        .unwrap();
        let boundary = crate::engine::TurnBoundaryRecord {
            user_entry_id: user,
            assistant_entry_id: assistant,
            before_workspace_cut: format!("before:{turn}"),
            after_workspace_cut: format!("after:{turn}"),
            runtime_before: gaugedesk_harness::RuntimePosition {
                instance_ref: "synthetic-runtime".into(),
                sequence: turn * 2,
            },
            runtime_after: gaugedesk_harness::RuntimePosition {
                instance_ref: "synthetic-runtime".into(),
                sequence: turn * 2 + 1,
            },
            reads_before: vec![],
            reads_after: vec![],
            fork_snapshot: None,
        };
        source
            .append_record(
                "correlation-chat",
                crate::engine::TURN_BOUNDARY_KIND,
                &serde_json::to_string(&boundary).unwrap(),
            )
            .unwrap();
        coordinates.push((user, assistant));
    }
    wire.log = collect_project_log(&source, "p1");
    assert!(!wire
        .log
        .iter()
        .any(|record| crate::engine::is_task_attempt_scope(&record.scope)
            || record.kind == crate::engine::TASK_CORRELATION_ATTEMPT_KIND
            || record.payload.contains("private-input:")));
    {
        let mut guard = wb.lock_unpoisoned();
        handoff_oneshot_arm(
            guard.store_mut(),
            "alice",
            "p1",
            "correlation-offer",
            now_secs() + 3600,
        );
    }
    assert_eq!(admit_handoff(&wb, &wire)["committed"], true);
    let guard = wb.lock_unpoisoned();
    let imported = guard.store_ref().events("correlation-chat").unwrap();
    assert_eq!(
        imported,
        source.events("correlation-chat").unwrap(),
        "full chat ordinals and original records must survive actual receiving admission"
    );
    let summaries = guard
        .store_ref()
        .records("correlation-chat", crate::turn_summary::TURN_SUMMARY_KIND)
        .unwrap();
    let boundaries = guard
        .store_ref()
        .records("correlation-chat", crate::engine::TURN_BOUNDARY_KIND)
        .unwrap();
    assert_eq!(summaries.len(), 2);
    assert_eq!(boundaries.len(), 2);
    for (index, (user, assistant)) in coordinates.into_iter().enumerate() {
        let summary: crate::turn_summary::TurnSummary =
            serde_json::from_str(&summaries[index]).unwrap();
        let boundary: crate::engine::TurnBoundaryRecord =
            serde_json::from_str(&boundaries[index]).unwrap();
        assert_eq!(summary.user_entry_id, user);
        assert_eq!(
            (boundary.user_entry_id, boundary.assistant_entry_id),
            (user, assistant)
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&imported[user as usize].2).unwrap()["type"],
            "user"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&imported[assistant as usize].2).unwrap()
                ["type"],
            "assistant"
        );
    }
    assert!(!guard
        .store_ref()
        .scope_ids()
        .unwrap()
        .iter()
        .any(|scope| crate::engine::is_task_attempt_scope(scope)));
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

fn authority_fixture() -> (
    SharedWorkbench,
    HandoffWire,
    Workbench,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    use crate::{
        at_rest::LoopbackKeyWrap,
        content_vault::{ContentVault, LocalFileErasureLedger},
    };
    let (wb, mut wire, source_dir, target_dir) = fixture_with_protection(true);
    let recipient = federation_root_signing_key(&wb.lock_unpoisoned()).public_key();
    let target_ticket = wb.lock_unpoisoned().federation_ref().unwrap().mint_ticket(
        recipient.clone(),
        "bridge:invoke".into(),
        Some(3600),
    );
    let mut federation = Federation::open(
        AuthorityId::new("alice"),
        source_dir.path(),
        "wss://127.0.0.1:1".into(),
    )
    .unwrap();
    federation.accept_ticket(&target_ticket, "target".into());
    let dir = source_dir.path().join("content-keys");
    let vault = Arc::new(
        ContentVault::new(&dir, Box::new(LoopbackKeyWrap::new([7; 32]))).with_ledger(Box::new(
            LocalFileErasureLedger::new(dir.join("erased.ledger")),
        )),
    );
    let mut store =
        Store::open(source_dir.path().join("product.sqlite").to_str().unwrap()).unwrap();
    for record in &wire.log {
        store
            .append_record(&record.scope, &record.kind, &record.payload)
            .unwrap();
    }
    let mut source = Workbench::new(store)
        .with_authority(AuthorityId::new("alice"))
        .with_root(source_dir.path())
        .with_content_vault(vault)
        .with_federation(federation);
    source.rebuild_library();
    source.initialize_project_authority("p1").unwrap();
    wire.project_authority = project_authority::prepare(&source, "p1", "bob", &recipient).unwrap();
    wire.kind = HandoffMsgKind::OfferWithProjectAuthority;
    resign_authority_offer(&mut wire, source_dir.path());
    assert_eq!(admit_handoff(&wb, &wire)["pending"], true);
    (wb, wire, source, source_dir, target_dir)
}

fn resign_authority_offer(wire: &mut HandoffWire, source: &std::path::Path) {
    let id = AuthorityId::new("alice");
    let root = FileKeyStore::new(source.join("keys")).signing_key(&id);
    let (key, _) = device_identity(source, &id, &root);
    wire.signed_bytes = project_authority::signed_bytes(wire).unwrap();
    wire.signature = key.sign(&wire.signed_bytes);
}

#[test]
fn staged_authority_survives_failed_receiving_commit_without_granting_use() {
    let (wb, wire, source, _source_dir, _target_dir) = authority_fixture();
    let public = source.project_authority_identity("p1").unwrap().1;
    let mut guard = wb.lock_unpoisoned();
    let conn = rusqlite::Connection::open(guard.store_ref().path()).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_authority_receive BEFORE INSERT ON command_receipts WHEN NEW.scope_id = 'handoff::p1' AND NEW.command_key = 'receive' BEGIN SELECT RAISE(ABORT, 'receipt fault'); END;").unwrap();
    assert!(commit(&mut guard, &wire, Consent::Pending).is_err());
    assert!(guard
        .store_ref()
        .project_authority_key("p1")
        .unwrap()
        .is_some());
    assert!(guard.project_signing_key("p1").is_err());
    assert!(guard.project_home_id("p1").is_none());
    // Even a local creation reusing this id cannot activate staged signing
    // custody without the receiving admission which retains the transfer.
    let record: crate::library::ProjectRecord = serde_json::from_str(
        &wire
            .log
            .iter()
            .find(|r| r.kind == "project")
            .unwrap()
            .payload,
    )
    .unwrap();
    let mut local = record;
    local.home_id = guard.home_id().clone();
    guard.library.projects.insert("p1".into(), local);
    assert!(guard.initialize_project_authority("p1").is_err());
    assert!(guard.project_authority_identity("p1").is_err());
    guard.rebuild_library();
    conn.execute_batch("DROP TRIGGER fail_authority_receive")
        .unwrap();
    commit(&mut guard, &wire, Consent::Pending).unwrap();
    assert_eq!(
        guard.project_signing_key("p1").unwrap().public_key(),
        public
    );
    let retained = guard
        .store_ref()
        .project_authority_key("p1")
        .unwrap()
        .unwrap();
    commit(&mut guard, &wire, Consent::Pending).unwrap();
    assert!(
        guard
            .store_ref()
            .project_authority_key("p1")
            .unwrap()
            .unwrap()
            == retained
    );
}

#[test]
fn authority_offer_binds_complete_state_and_refuses_partial_or_foreign_custody() {
    for failure in [
        "missing",
        "legacy",
        "tampered-log",
        "recipient",
        "project",
        "public-key",
        "ciphertext",
        "payload-context",
        "missing-vault",
    ] {
        let (wb, mut wire, _source, source_dir, _target_dir) = authority_fixture();
        let mut capsule = serde_json::to_value(&wire.project_authority).unwrap();
        match failure {
            "missing" => wire.project_authority = None,
            "legacy" => wire.kind = HandoffMsgKind::OfferWithWorkflowKeys,
            "tampered-log" => wire.log[0].payload.push(' '),
            "recipient" => {
                capsule["recipient"] =
                    serde_json::to_value(SigningKey::from_seed(&[99; 32]).unwrap().public_key())
                        .unwrap()
            }
            "project" => capsule["project"] = serde_json::json!("another-project"),
            "public-key" => {
                let public = SigningKey::from_seed(&[99; 32]).unwrap().public_key();
                capsule["authority"] =
                    serde_json::to_value(crate::project_authority::authority(&public)).unwrap();
                capsule["public_key"] = serde_json::to_value(public).unwrap();
            }
            "ciphertext" => capsule["sealed"]["ciphertext"] = serde_json::json!("00"),
            "payload-context" => {
                let recipient = federation_root_signing_key(&wb.lock_unpoisoned()).public_key();
                capsule["sealed"] =
                    serde_json::to_value(seal_to_subkey(&recipient, &[3; 64]).unwrap()).unwrap();
            }
            "missing-vault" => wb.lock_unpoisoned().content_vault = None,
            _ => unreachable!(),
        }
        if !matches!(
            failure,
            "missing" | "legacy" | "tampered-log" | "missing-vault"
        ) {
            wire.project_authority = Some(serde_json::from_value(capsule).unwrap());
            // Current source transport legitimately signs malformed custody:
            // the receiving cryptographic checks must still refuse it.
            resign_authority_offer(&mut wire, source_dir.path());
        }
        let admitted = admit_handoff(&wb, &wire);
        if admitted["pending"] == true {
            assert!(
                commit(&mut wb.lock_unpoisoned(), &wire, Consent::Pending).is_err(),
                "{failure}"
            );
        } else {
            assert_eq!(admitted["ok"], false, "{failure}");
        }
        let guard = wb.lock_unpoisoned();
        assert!(guard.project_home_id("p1").is_none(), "{failure}");
        assert!(
            guard
                .store_ref()
                .project_authority_key("p1")
                .unwrap()
                .is_none(),
            "{failure}"
        );
    }
}

#[test]
fn committed_authority_recovery_refuses_missing_custody_without_repairing_it() {
    let (wb, wire, _source, _source_dir, target_dir) = authority_fixture();
    let mut guard = wb.lock_unpoisoned();
    commit(&mut guard, &wire, Consent::Pending).unwrap();
    let file = target_dir
        .path()
        .join("content-keys/projects")
        .join(format!("{}.key", crate::org::sha256_hex("p1")));
    std::fs::remove_file(&file).unwrap();
    assert!(commit(&mut guard, &wire, Consent::Pending).is_err());
    assert!(guard.project_signing_key("p1").is_err());
    assert!(!file.exists());
}

fn workflow_member(wb: &mut Workbench) -> crate::identity::AuthenticatedActionContext {
    let member = crate::org::MembershipRecord {
        id: "member".into(),
        op: crate::org::RecordOp::Upsert,
        org_id: crate::org::ORG_ID.into(),
        authority: "member".into(),
        email: String::new(),
        role: "owner".into(),
        status: crate::org::MembershipStatus::Active,
        managed_by_scim: false,
        team: None,
    };
    wb.store_mut()
        .append_record(
            crate::org::ORG_SCOPE,
            "membership",
            &serde_json::to_string(&member).unwrap(),
        )
        .unwrap();
    let token = wb.mint_account_session("member", "passkey", 3600).unwrap();
    wb.authenticate_action_context(&token).unwrap()
}

fn workflow_project_grant(wb: &mut Workbench, project: &str) {
    let grant = crate::org::MemberGrantRecord {
        id: crate::org::MemberGrantRecord::make_id("member", project),
        authority: "member".into(),
        project_id: project.into(),
        op: crate::org::RecordOp::Upsert,
    };
    wb.store_mut()
        .append_record(
            crate::org::ORG_SCOPE,
            "member_grant",
            &serde_json::to_string(&grant).unwrap(),
        )
        .unwrap();
}

#[test]
fn actual_project_signed_workflow_moves_and_resumes_under_same_authority_after_restart() {
    use crate::project_workflow::{ProjectWorkflowLaunch, ProjectWorkflowLimits};
    use crate::{
        at_rest::LoopbackKeyWrap,
        content_vault::{ContentVault, LocalFileErasureLedger},
    };
    let (wb, mut wire, mut source, source_dir, target_dir) = authority_fixture();
    crate::library_routes::create_named_project(&mut source, "p1", "Incoming project").unwrap();
    let context = workflow_member(&mut source);
    let target = crate::library_state::managed_project_target_id("p1");
    let mut record = source.library.work_targets[&target].clone();
    record.authority = "member".into();
    record.parties = vec!["member".into()];
    source
        .store_mut()
        .append_record(
            LIBRARY_SCOPE,
            "work_target",
            &serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
    source.rebuild_library();
    let workspace = source.targets.get(&target).unwrap();
    workspace.seed_main(&[("hello.whip", "workflow Greeting(learner: Learner) -> string\nclass Learner { authority string }\nrule greet\n  when Learner as learner\n=> { complete result learner.authority }\n")]).unwrap();
    let cut = workspace.current_main_cut().unwrap().unwrap();
    let limits = ProjectWorkflowLimits {
        source_bytes: 256 * 1024,
        input_bytes: 64 * 1024,
    };
    let request = ProjectWorkflowLaunch {
        project: "p1".into(),
        target,
        path: "hello.whip".into(),
        cut,
        request_id: "move-workflow".into(),
        inputs: BTreeMap::from([("learner".into(), serde_json::json!({"authority":"member"}))]),
    };
    assert!(source
        .launch_project_workflow(&context, &request, limits)
        .is_err());
    workflow_project_grant(&mut source, "p1");
    let original = source
        .launch_project_workflow(&context, &request, limits)
        .unwrap();
    let identity = source.project_authority_identity("p1").unwrap();
    assert_eq!(original.command.issuer, identity.0.as_str());
    let recipient = federation_root_signing_key(&wb.lock_unpoisoned()).public_key();
    let (workspace, transfer) = workflow_keys::prepare(&source, "p1", "bob", &recipient)
        .unwrap()
        .unwrap();
    let (log, content, commands, capsule) = capture_handoff_offer(
        source.store_ref(),
        "p1",
        "bob",
        Some(&transfer),
        |custody| {
            let (key, key_capsule) = custody.unwrap();
            let protection =
                gaugedesk_workspace::WorkflowProtection::new(&workspace, key.clone()).unwrap();
            Ok((
                collect_project_log(source.store_ref(), "p1"),
                collect_project_content_with_custody(
                    &source,
                    "p1",
                    Some(&protection),
                    Some(key_capsule),
                )?,
                source
                    .store_ref()
                    .export_command_scopes(|scope| is_project_scope(scope, "p1"))
                    .unwrap(),
                project_authority::prepare(&source, "p1", "bob", &recipient)?,
            ))
        },
    )
    .unwrap();
    wire.log = log;
    wire.content = content;
    wire.project_commands = Some(commands);
    wire.project_authority = capsule;
    resign_authority_offer(&mut wire, source_dir.path());
    let mut partial = wire.clone();
    partial.project_authority = None;
    partial.kind = HandoffMsgKind::OfferWithWorkflowKeys;
    resign_authority_offer(&mut partial, source_dir.path());
    assert_eq!(admit_handoff(&wb, &partial)["ok"], false);
    assert_eq!(admit_handoff(&wb, &wire)["pending"], true);
    {
        let mut guard = wb.lock_unpoisoned();
        commit(&mut guard, &wire, Consent::Pending).unwrap();
        let target_context = workflow_member(&mut guard);
        assert_eq!(guard.project_authority_identity("p1").unwrap(), identity);
        assert!(guard
            .resume_project_workflow(&target_context, "p1", "move-workflow", limits)
            .is_err());
        workflow_project_grant(&mut guard, "p1");
        let resumed = guard
            .resume_project_workflow(&target_context, "p1", "move-workflow", limits)
            .unwrap();
        assert_eq!(resumed.command, original.command);
        assert_eq!(resumed.admission, original.admission);
        guard
            .step_project_workflow(&target_context, "p1", "move-workflow", limits)
            .unwrap();
    }
    // Reopen product/workspace/custody state with a fresh key cache.
    drop(wb);
    let dir = target_dir.path().join("content-keys");
    let vault = Arc::new(
        ContentVault::new(&dir, Box::new(LoopbackKeyWrap::new([8; 32]))).with_ledger(Box::new(
            LocalFileErasureLedger::new(dir.join("erased.ledger")),
        )),
    );
    let mut reopened = Workbench::new(
        Store::open(target_dir.path().join("events.sqlite").to_str().unwrap()).unwrap(),
    )
    .with_authority(AuthorityId::new("bob"))
    .with_root(target_dir.path())
    .with_content_vault(vault);
    reopened.rebuild_library();
    reopened
        .ensure_project_collaboration_workspace("p1")
        .unwrap();
    let context = workflow_member(&mut reopened);
    assert_eq!(reopened.project_authority_identity("p1").unwrap(), identity);
    let resumed = reopened
        .resume_project_workflow(&context, "p1", "move-workflow", limits)
        .unwrap();
    assert_eq!(resumed.command, original.command);
    assert_eq!(resumed.admission, original.admission);
}

#[test]
fn retained_authority_offer_signature_refuses_changed_carriage() {
    let (wb, mut wire, _source, _source_dir, _target_dir) = authority_fixture();
    assert!(verify_handoff(&wb.lock_unpoisoned(), &wire).is_ok());
    let mut capsule = serde_json::to_value(&wire.project_authority).unwrap();
    capsule["sealed"]["ciphertext"] = serde_json::json!("00");
    wire.project_authority = Some(serde_json::from_value(capsule).unwrap());
    assert!(verify_handoff(&wb.lock_unpoisoned(), &wire).is_err());
}

#[test]
fn receiving_authority_refuses_conflicting_retention_and_missing_committed_registry() {
    for fault in ["different-authority", "missing-registry"] {
        let (wb, wire, _source, _source_dir, _target_dir) = authority_fixture();
        let mut guard = wb.lock_unpoisoned();
        if fault == "different-authority" {
            guard
                .stage_project_authority("p1", &SigningKey::from_seed(&[99; 32]).unwrap(), false)
                .unwrap();
        } else {
            commit(&mut guard, &wire, Consent::Pending).unwrap();
            let conn = rusqlite::Connection::open(guard.store_ref().path()).unwrap();
            conn.execute_batch("DROP TRIGGER project_authority_no_delete; DELETE FROM project_authority_keys WHERE project_id = 'p1'").unwrap();
        }
        let retained = guard.store_ref().project_authority_key("p1").unwrap();
        assert!(
            commit(&mut guard, &wire, Consent::Pending).is_err(),
            "{fault}"
        );
        assert!(
            guard.store_ref().project_authority_key("p1").unwrap() == retained,
            "{fault}"
        );
        assert!(guard.project_signing_key("p1").is_err(), "{fault}");
    }
}

/// A Home's library as the product seeds it, and an offer's library holding one
/// placement of that Home's seeded Default Agent in project `p1`.
fn seeded_default_offer() -> (Library, Library, tempfile::TempDir) {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::workbench_state::open_lean_workbench(root.path()).unwrap();
    let current = wb.lock_unpoisoned().library.clone();
    let mut incoming = Library::default();
    incoming.apply_agent(current.agents[crate::app_support::DEFAULT_AGENT].clone());
    let mut placement = current.instances[crate::app_support::DEFAULT_PLACEMENT].clone();
    placement.id = "inst-general-p1".into();
    placement.project_id = Some("p1".into());
    incoming.apply_instance(placement);
    (current, incoming, root)
}

fn refusal(result: Result<(), AdmitError>) -> &'static str {
    match result {
        Err(AdmitError::Rejected(rejection)) => rejection.reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_seeded_agent_placement_binds_to_the_receivers_own_seed_at_its_pinned_version() {
    let (current, incoming, _root) = seeded_default_offer();
    compatible_library(&current, &incoming).unwrap();

    // The receiver's own seed differs from the offered record in what it does
    // not pin — another Home's authoring basis or later version — and still binds.
    let mut moved_on = current.clone();
    let mut agent = moved_on.agents[crate::app_support::DEFAULT_AGENT].clone();
    agent.current_version = 2;
    agent.versions.insert(2, agent.versions[&1].clone());
    moved_on.apply_agent(agent);
    compatible_library(&moved_on, &incoming).unwrap();

    let mut other_version = incoming.clone();
    let mut agent = other_version.agents[crate::app_support::DEFAULT_AGENT].clone();
    agent.versions.get_mut(&1).unwrap().package_ref = "another-release".into();
    other_version.apply_agent(agent);
    assert_eq!(
        refusal(compatible_library(&current, &other_version)),
        "incoming project pins a built-in Agent version this Home does not hold"
    );

    let mut unseeded = current.clone();
    unseeded.agents.remove(crate::app_support::DEFAULT_AGENT);
    assert_eq!(
        refusal(compatible_library(&unseeded, &incoming)),
        "incoming project uses a built-in Agent this Home has not seeded"
    );
}

#[test]
fn an_offer_carrying_another_homes_seed_of_a_built_in_agent_is_refused() {
    let (_wb, wire, _source, _target) = fixture();
    let root = tempfile::tempdir().unwrap();
    let seeded = crate::workbench_state::open_lean_workbench(root.path()).unwrap();
    let library = seeded.lock_unpoisoned().library.clone();
    let seed_target = library
        .authoring_target_for(crate::app_support::DEFAULT_AGENT)
        .unwrap()
        .clone();
    let mut placement = library.instances[crate::app_support::DEFAULT_PLACEMENT].clone();
    placement.id = "inst-general-p1".into();
    placement.project_id = Some("p1".into());
    let record = |kind: &str, value: serde_json::Value| HandoffLogRecord {
        scope: LIBRARY_SCOPE.into(),
        kind: kind.into(),
        payload: value.to_string(),
    };
    let mut referenced = wire.clone();
    referenced.log.extend([
        record("instance", serde_json::to_value(&placement).unwrap()),
        record(
            "agent",
            serde_json::to_value(&library.agents[crate::app_support::DEFAULT_AGENT]).unwrap(),
        ),
    ]);
    incoming_library(&referenced).unwrap();

    let mut carried = referenced.clone();
    carried.log.push(record(
        "work_target",
        serde_json::to_value(&seed_target).unwrap(),
    ));
    assert_eq!(
        refusal(incoming_library(&carried).map(|_| ())),
        "incoming log carries another Home's seed of a built-in Agent"
    );
    let mut carried = referenced;
    carried.log.push(record(
        "instance",
        serde_json::to_value(&library.instances[crate::app_support::DEFAULT_INSTANCE]).unwrap(),
    ));
    assert_eq!(
        refusal(incoming_library(&carried).map(|_| ())),
        "incoming log carries another Home's seed of a built-in Agent"
    );
}

#[test]
fn a_seeded_agent_travels_only_as_a_reference_to_its_pinned_version() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::workbench_state::open_lean_workbench(root.path()).unwrap();
    let mut guard = wb.lock_unpoisoned();
    let mut agent = guard.library.agents[crate::app_support::DEFAULT_AGENT].clone();
    agent.config = r#"{"model":"this Home's own choice"}"#.into();
    agent.name = "Renamed here".into();
    agent.authoring_owner = Some("local-user".into());
    agent.versions.insert(2, agent.versions[&1].clone());
    agent.current_version = 2;
    let mut placement = guard.library.instances[crate::app_support::DEFAULT_PLACEMENT].clone();
    placement.id = "inst-general-p1".into();
    placement.project_id = Some("p1".into());
    placement.version = 1;
    let store = guard.store_mut();
    store
        .append_record(
            LIBRARY_SCOPE,
            "agent",
            &serde_json::to_string(&agent).unwrap(),
        )
        .unwrap();
    store
        .append_record(
            LIBRARY_SCOPE,
            "instance",
            &serde_json::to_string(&placement).unwrap(),
        )
        .unwrap();
    let log = collect_project_log(guard.store_ref(), "p1");
    let shipped: Vec<crate::library::AgentRecord> = log
        .iter()
        .filter(|record| record.scope == LIBRARY_SCOPE && record.kind == "agent")
        .map(|record| serde_json::from_str(&record.payload).unwrap())
        .collect();
    assert_eq!(shipped.len(), 1);
    let reference = &shipped[0];
    assert_eq!(reference.id, crate::app_support::DEFAULT_AGENT);
    assert_eq!(reference.config, "{}");
    assert_eq!(reference.name, "Default");
    assert_eq!(reference.authoring_owner, None);
    assert_eq!(reference.instance_id, "");
    assert_eq!(
        reference.versions.keys().copied().collect::<Vec<_>>(),
        vec![1]
    );
    assert_eq!(
        serde_json::to_value(&reference.versions[&1]).unwrap(),
        serde_json::to_value(&agent.versions[&1]).unwrap()
    );
    assert!(!log
        .iter()
        .any(|record| record.kind == "work_target" && record.payload.contains("\"archetype\"")));
}
