use super::*;
use crate::engine::office_authority::OfficeTaskAuthority;
use axum::{extract::Path, routing::post};
#[path = "office_turn_answers_tests.rs"]
mod answers;
#[path = "office_turn_payload_tests.rs"]
mod payloads;
#[path = "office_turn_result_tests.rs"]
mod result_publication;

fn chat(wb: &SharedWorkbench) -> String {
    // Direct workbench calls in this fixture are an admitted session on shared.
    wb.lock_unpoisoned().hold_session_for_tests("shared");
    wb.lock_unpoisoned()
        .create_chat_in_instance_on_target(
            &crate::library_routes::general_placement_id("shared"),
            "Clinical work",
            None,
        )
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .into()
}

fn context(wb: &SharedWorkbench, admission: &str) -> AuthenticatedActionContext {
    let guard = wb.lock_unpoisoned();
    guard
        .office_staff_action_context(
            &guard.office_staff_lease(ALICE).unwrap(),
            &crate::home_admission::HomeAdmissionToken::parse(admission).unwrap(),
        )
        .unwrap()
}

/// Capture the actual deciding middleware claim, then abort its handler before
/// response settlement. No constructed token or private tracker/store is used.
async fn pending_runtime_parent(
    wb: &SharedWorkbench,
    chat: &str,
) -> crate::command_idempotency::ClaimedHttpCommand {
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let app = Router::new()
        .route(
            "/chats/{id}/task",
            post(
                move |axum::extract::Extension(parent): axum::extract::Extension<
                    crate::command_idempotency::ClaimedHttpCommand,
                >| {
                    let send = send.clone();
                    async move {
                        send.send(parent).unwrap();
                        std::future::pending::<StatusCode>().await
                    }
                },
            ),
        )
        .layer(axum::middleware::from_fn_with_state(
            wb.clone(),
            crate::command_idempotency::guard,
        ));
    let request = Request::builder()
        .method("POST")
        .uri(format!("/chats/{chat}/task"))
        .header("idempotency-key", "runtime-original-parent")
        .body(Body::from("synthetic runtime parent"))
        .unwrap();
    let invocation = tokio::spawn(app.oneshot(request));
    let parent = tokio::time::timeout(std::time::Duration::from_secs(5), receive.recv())
        .await
        .unwrap()
        .unwrap();
    invocation.abort();
    assert!(invocation.await.unwrap_err().is_cancelled());
    parent
        .verify_pending(wb.lock_unpoisoned().store_ref())
        .unwrap();
    parent
}

#[tokio::test]
async fn office_task_requires_exact_context_actor_and_original_client_declaration() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&app, ALICE).await;
    let chat = chat(&wb);
    let context = context(&wb, &admission);
    let client = crate::client_admission::ClientBuild::default();
    assert!(
        OfficeTaskAuthority::for_turn(&wb, &chat, None, Some(&client), None, Some(ALICE)).is_err()
    );
    assert!(OfficeTaskAuthority::for_turn(&wb, &chat, Some(&context), None, None, None).is_err());
    assert!(OfficeTaskAuthority::for_turn(
        &wb,
        &chat,
        Some(&context),
        Some(&client),
        Some(&AuthorityId::new("bob")),
        None
    )
    .is_err());
    assert!(OfficeTaskAuthority::for_turn(
        &wb,
        &chat,
        Some(&context),
        Some(&client),
        Some(context.actor()),
        Some(ALICE)
    )
    .unwrap()
    .is_some());
}

#[tokio::test]
async fn office_task_startup_checkpoints_refuse_removed_access() {
    for change in [
        "grant", "member", "home", "source", "rotation", "software", "project",
    ] {
        let root = tempfile::tempdir().unwrap();
        let (wb, app, _, _) = fixture(root.path());
        let hub = hub().await;
        install(&wb, &hub);
        let admission = admit(&app, ALICE).await;
        let chat = chat(&wb);
        let context = context(&wb, &admission);
        let authority = OfficeTaskAuthority::for_turn(
            &wb,
            &chat,
            Some(&context),
            Some(&Default::default()),
            None,
            Some(ALICE),
        )
        .unwrap()
        .unwrap();
        assert!(
            authority
                .claim_upload_command(&wb, "valid-upload", "upload", "valid-key", "input")
                .unwrap()
                .1
        );
        match change {
            "grant" => grant(&wb, "alice", crate::library::RecordOp::Tombstone),
            "member" => membership(&wb, "alice", crate::org::MembershipStatus::Deprovisioned),
            "rotation" => {
                let _ = admit(&app, ALICE).await;
            }
            "home" => {
                let mut guard = wb.lock_unpoisoned();
                let home = guard.home_id().clone();
                guard
                    .home_admissions
                    .revoke(&home, &AuthorityId::new("alice"));
            }
            "source" => {
                let mut guard = wb.lock_unpoisoned();
                let source = guard.office_staff_verifier().unwrap();
                assert!(guard
                    .observe_office_staff_check(
                        &source,
                        &crate::account_session::session_id(ALICE),
                        source::SourceCheck::Refused
                    )
                    .is_err());
            }
            "software" => {
                let policy = crate::org::SoftwarePolicyRecord {
                    id: "software".into(),
                    op: crate::library::RecordOp::Upsert,
                    policy: crate::client_admission::SoftwarePolicy {
                        minimum_protocol: 2,
                        ..Default::default()
                    },
                };
                wb.lock_unpoisoned()
                    .store_mut()
                    .append_record(
                        ORG_SCOPE,
                        "software_policy",
                        &serde_json::to_string(&policy).unwrap(),
                    )
                    .unwrap();
            }
            "project" => {
                let mut guard = wb.lock_unpoisoned();
                let mut record = guard.library.instances
                    [&crate::library_routes::general_placement_id("shared")]
                    .clone();
                record.project_id = Some("other".into());
                guard.write_instance_record(record);
            }
            _ => unreachable!(),
        }
        assert!(authority.checkpoint(&wb).is_err(), "{change}");
        assert!(
            authority
                .claim_upload_command(&wb, "refused-upload", "upload", "key", "input")
                .is_err(),
            "{change}"
        );
        assert!(
            wb.lock_unpoisoned()
                .store_ref()
                .command("refused-upload")
                .unwrap()
                .is_none(),
            "{change}"
        );
    }
}

#[tokio::test]
async fn restored_local_standing_cannot_revive_an_original_office_task() {
    for change in ["grant", "member", "privileged"] {
        let root = tempfile::tempdir().unwrap();
        let (wb, app, _, _) = fixture(root.path());
        let hub = hub().await;
        install(&wb, &hub);
        let admission = admit(&app, ALICE).await;
        let chat = chat(&wb);
        let set_role = |role: &str| {
            let mut guard = wb.lock_unpoisoned();
            let mut member = crate::org::Org::rebuild(guard.store_ref())
                .unwrap()
                .member_by_authority("alice")
                .unwrap()
                .clone();
            member.role = role.into();
            guard
                .store_mut()
                .append_record(
                    ORG_SCOPE,
                    "membership",
                    &serde_json::to_string(&member).unwrap(),
                )
                .unwrap();
        };
        if change == "privileged" {
            set_role("admin");
            grant(&wb, "alice", crate::library::RecordOp::Tombstone);
        }
        let captured = context(&wb, &admission);
        let original = OfficeTaskAuthority::for_turn(
            &wb,
            &chat,
            Some(&captured),
            Some(&Default::default()),
            None,
            Some(ALICE),
        )
        .unwrap()
        .unwrap();
        let parent = pending_runtime_parent(&wb, &chat).await;
        let access = original.runtime_access(&wb, &parent);
        // Other people's changes and an active membership update preserve it.
        grant(&wb, "bob", crate::library::RecordOp::Tombstone);
        membership(&wb, "bob", crate::org::MembershipStatus::Deprovisioned);
        set_role(if change == "privileged" {
            "admin"
        } else {
            "member"
        });
        assert!(original.checkpoint(&wb).is_ok());
        assert!(access.check_current().is_ok());
        match change {
            "privileged" => {
                set_role("member");
                set_role("admin");
            }
            "grant" => {
                grant(&wb, "alice", crate::library::RecordOp::Tombstone);
                grant(&wb, "alice", crate::library::RecordOp::Upsert);
            }
            "member" => {
                membership(&wb, "alice", crate::org::MembershipStatus::Deprovisioned);
                membership(&wb, "alice", crate::org::MembershipStatus::Active);
            }
            _ => unreachable!(),
        }
        // No original check ran during the revoked interval.
        assert!(original.checkpoint(&wb).is_err(), "{change}");
        assert!(access.check_current().is_err(), "runtime: {change}");
        assert!(
            original
                .claim_upload_command(&wb, "revived-old-command", "upload", "key", "input",)
                .is_err(),
            "{change}"
        );
        assert!(wb
            .lock_unpoisoned()
            .store_ref()
            .command("revived-old-command")
            .unwrap()
            .is_none());
        assert!(
            OfficeTaskAuthority::for_turn(
                &wb,
                &chat,
                Some(&captured),
                Some(&Default::default()),
                None,
                Some(ALICE),
            )
            .unwrap()
            .is_some(),
            "fresh submission: {change}"
        );
    }
}

#[tokio::test]
async fn cold_reopen_refuses_original_startup_even_after_fresh_staff_admission() {
    let root = tempfile::tempdir().unwrap();
    let (wb, admission_app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&admission_app, ALICE).await;
    let chat_id = chat(&wb);
    let old_context = context(&wb, &admission);
    let initial_context = old_context.clone();
    let (captured, mut retained) = tokio::sync::mpsc::unbounded_channel();
    let task_app = Router::new()
        .route(
            "/chats/{id}/task",
            post(
                move |axum::extract::State(wb): axum::extract::State<SharedWorkbench>,
                      Path(chat): Path<String>,
                      axum::extract::Extension(original): axum::extract::Extension<
                    crate::command_idempotency::ClaimedHttpCommand,
                >| {
                    let context = initial_context.clone();
                    let captured = captured.clone();
                    async move {
                        {
                            let authority = OfficeTaskAuthority::for_turn(
                                &wb,
                                &chat,
                                Some(&context),
                                Some(&Default::default()),
                                Some(context.actor()),
                                Some(ALICE),
                            )
                            .unwrap()
                            .unwrap();
                            let office = crate::engine::office_turn_startup::OfficeTurnContext {
                                wb: &wb,
                                authority: &authority,
                                original: &original,
                            };
                            let engagement = wb.lock_unpoisoned().engagements[&chat].boxed_clone();
                            let mut fork = None;
                            crate::engine::office_turn_startup::admit_startup(
                                &office,
                                engagement.as_ref(),
                                &chat,
                                "synthetic interrupted startup",
                                &mut fork,
                            )
                            .unwrap();
                        }
                        captured.send(original).unwrap();
                        std::future::pending::<StatusCode>().await
                    }
                },
            ),
        )
        .layer(axum::middleware::from_fn_with_state(
            wb.clone(),
            crate::command_idempotency::guard,
        ))
        .with_state(wb.clone());
    let request = Request::builder()
        .method("POST")
        .uri(format!("/chats/{chat_id}/task"))
        .header("idempotency-key", "cold-original-startup")
        .body(Body::from("synthetic interrupted startup"))
        .unwrap();
    let invocation = tokio::spawn(task_app.clone().oneshot(request));
    let original = tokio::time::timeout(std::time::Duration::from_secs(5), retained.recv())
        .await
        .unwrap()
        .unwrap();
    let before_close = wb
        .lock_unpoisoned()
        .store_ref()
        .retained_events(&chat_id)
        .unwrap();
    original
        .verify_pending(wb.lock_unpoisoned().store_ref())
        .unwrap();
    invocation.abort();
    assert!(invocation.await.unwrap_err().is_cancelled());
    drop(task_app);
    drop(admission_app);
    assert_eq!(Arc::strong_count(&wb), 1, "old Home still has a live owner");
    drop(wb);

    let reopened = crate::open_workbench(root.path()).unwrap();
    reopened.lock_unpoisoned().hold_session_for_tests("shared");
    assert_eq!(
        reopened
            .lock_unpoisoned()
            .store_ref()
            .retained_events(&chat_id)
            .unwrap(),
        before_close
    );
    original
        .verify_pending(reopened.lock_unpoisoned().store_ref())
        .unwrap();
    install(&reopened, &hub);
    let admission_app = router(reopened.clone());
    let fresh_admission = admit(&admission_app, ALICE).await;
    let fresh_context = context(&reopened, &fresh_admission);
    assert!(OfficeTaskAuthority::for_turn(
        &reopened,
        &chat_id,
        Some(&fresh_context),
        Some(&Default::default()),
        Some(fresh_context.actor()),
        Some(ALICE)
    )
    .unwrap()
    .is_some());
    for (case, context) in [("old", &old_context), ("fresh", &fresh_context)] {
        let (location, before, native_before) = {
            let mut guard = reopened.lock_unpoisoned();
            let location = guard.engagement_task_context(&chat_id).unwrap();
            (
                location,
                guard.store_ref().retained_events(&chat_id).unwrap(),
                guard.engagements[&chat_id].observe().unwrap(),
            )
        };
        let result = crate::engine::run_engagement_turn(
            &reopened,
            &chat_id,
            &location.worktree,
            &location.sender,
            crate::engine::EngagementTurnInput {
                task: "synthetic interrupted startup",
                images: &[],
                mode: location.mode,
                authenticated_actor: Some(context.actor()),
                authenticated_context: Some(context),
                client_build: Some(&Default::default()),
                local_operator: false,
                contribution_by: None,
                account_scope: "account",
                tenant_scope: ORG_SCOPE,
                account_bearer: Some(ALICE),
                runtime_command_id: None,
                original_http_command: Some(&original),
                harness_factory: None,
            },
        );
        assert!(result.is_err(), "restart replaced original task standing");
        if case == "fresh" {
            assert!(
                matches!(&result, Err(crate::engine::EngineError::Admit(
                gaugedesk_store::AdmitError::Rejected(rejection)
            )) if rejection.reason == "office startup has no exact retained original snapshot or phase"),
                "fresh admission refused for a different reason: {result:?}"
            );
        }
        let guard = reopened.lock_unpoisoned();
        assert_eq!(guard.store_ref().retained_events(&chat_id).unwrap(), before);
        assert_eq!(
            guard.engagements[&chat_id].observe().unwrap(),
            native_before
        );
        original.verify_pending(guard.store_ref()).unwrap();
        assert!(!crate::engine::turn_is_live(&chat_id));
    }
}

#[tokio::test]
async fn office_task_original_ceiling_cannot_be_extended_by_source_recheck() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&app, ALICE).await;
    let chat = chat(&wb);
    {
        let mut guard = wb.lock_unpoisoned();
        let source = guard.office_staff_verifier().unwrap();
        let now = crate::account::session_now_ms();
        guard
            .observe_office_staff_check(
                &source,
                &crate::account_session::session_id(ALICE),
                source::SourceCheck::Verified(source::VerifiedSourceSession::for_test(
                    source.issuer(),
                    "alice",
                    crate::account_session::AccountSessionEvidence {
                        session_ref: crate::account_session::session_id(ALICE),
                        method: "passkey".into(),
                        issued_at_ms: hub.state.minted,
                        expires_at_ms: now + 1000,
                    },
                    now,
                )),
            )
            .unwrap();
    }
    let captured = context(&wb, &admission);
    let authority = OfficeTaskAuthority::for_turn(
        &wb,
        &chat,
        Some(&captured),
        Some(&Default::default()),
        None,
        Some(ALICE),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(ALICE),
            Some(&admission)
        )
        .await
        .0,
        StatusCode::OK
    );
    tokio::time::sleep(std::time::Duration::from_millis(1050)).await;
    assert!(wb.lock_unpoisoned().office_staff_lease(ALICE).is_some());
    assert!(authority.checkpoint(&wb).is_err());
    assert!(authority
        .claim_upload_command(&wb, "expired-upload", "upload", "key", "input")
        .is_err());
    assert!(wb
        .lock_unpoisoned()
        .store_ref()
        .command("expired-upload")
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn engine_rejects_revoked_office_task_before_durable_turn_or_harness() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&app, ALICE).await;
    let chat = chat(&wb);
    let context = context(&wb, &admission);
    let (task, before) = {
        let mut guard = wb.lock_unpoisoned();
        let task = guard.engagement_task_context(&chat).unwrap();
        let before = guard.store_ref().retained_events(&chat).unwrap().len();
        let home = guard.home_id().clone();
        guard
            .home_admissions
            .revoke(&home, &AuthorityId::new("alice"));
        (task, before)
    };
    let result = crate::engine::run_engagement_turn(
        &wb,
        &chat,
        &task.worktree,
        &task.sender,
        crate::engine::EngagementTurnInput {
            task: "synthetic patient prompt must not run",
            images: &[],
            mode: task.mode,
            authenticated_actor: Some(context.actor()),
            authenticated_context: Some(&context),
            client_build: Some(&Default::default()),
            local_operator: false,
            contribution_by: None,
            account_scope: "account",
            tenant_scope: ORG_SCOPE,
            account_bearer: Some(ALICE),
            runtime_command_id: None,
            original_http_command: None,
            harness_factory: None,
        },
    );
    assert!(matches!(result, Err(crate::engine::EngineError::Admit(_))));
    assert_eq!(
        before,
        wb.lock_unpoisoned()
            .store_ref()
            .retained_events(&chat)
            .unwrap()
            .len()
    );
    assert!(!crate::engine::turn_is_live(&chat));
}

#[tokio::test]
async fn office_runtime_binding_observes_original_revocation_and_never_revives() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&app, ALICE).await;
    let chat = chat(&wb);
    let context = context(&wb, &admission);
    let original = OfficeTaskAuthority::for_turn(
        &wb,
        &chat,
        Some(&context),
        Some(&Default::default()),
        None,
        Some(ALICE),
    )
    .unwrap()
    .unwrap();
    let parent = pending_runtime_parent(&wb, &chat).await;
    let access = original.runtime_access(&wb, &parent);
    assert!(access.check_current().is_ok());
    // Restoration of standing must not revive a submitted binding after refusal.
    grant(&wb, "alice", crate::library::RecordOp::Tombstone);
    assert_eq!(
        access.check_current().unwrap_err(),
        "office task authority ended"
    );
    grant(&wb, "alice", crate::library::RecordOp::Upsert);
    assert!(original.checkpoint(&wb).is_err());
    assert!(access.check_current().is_err());
}

#[test]
fn unsupported_harness_refuses_an_office_access_binding() {
    let mut harness = gaugedesk_harness::testing::ScriptedHarness::new(Vec::new());
    struct Access;
    impl gaugedesk_harness::TurnAccess for Access {
        fn check_current(&self) -> Result<(), String> {
            Ok(())
        }
    }
    assert_eq!(
        gaugedesk_harness::Harness::bind_turn_access(
            &mut harness,
            Some(std::sync::Arc::new(Access)),
        )
        .unwrap_err()
        .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    gaugedesk_harness::Harness::bind_turn_access(&mut harness, None).unwrap();
    struct Payloads;
    impl gaugedesk_harness::WorkspacePayloadRetention for Payloads {
        fn retain(
            &self,
            _: &gaugedesk_harness::PreparedWorkspaceFile,
            _: &[u8],
        ) -> Result<(), String> {
            Ok(())
        }
    }
    assert_eq!(
        gaugedesk_harness::Harness::bind_workspace_payload_retention(
            &mut harness,
            Some(Arc::new(Payloads))
        )
        .unwrap_err()
        .kind(),
        std::io::ErrorKind::Unsupported
    );
    gaugedesk_harness::Harness::bind_workspace_payload_retention(&mut harness, None).unwrap();
}

#[tokio::test]
async fn office_runtime_binding_requires_exact_pending_http_parent_and_never_revives() {
    for case in [
        "status",
        "command_id",
        "scope_id",
        "idempotency_key",
        "snapshot_json",
        "missing",
        "receipted-processing",
    ] {
        let root = tempfile::tempdir().unwrap();
        let (wb, app, _, _) = fixture(root.path());
        let hub = hub().await;
        install(&wb, &hub);
        let admission = admit(&app, ALICE).await;
        let chat = chat(&wb);
        let captured = context(&wb, &admission);
        let authority = OfficeTaskAuthority::for_turn(
            &wb,
            &chat,
            Some(&captured),
            Some(&Default::default()),
            None,
            Some(ALICE),
        )
        .unwrap()
        .unwrap();
        let parent = pending_runtime_parent(&wb, &chat).await;
        let access = authority.runtime_access(&wb, &parent);
        assert!(access.check_current().is_ok(), "{case}");
        let before = wb
            .lock_unpoisoned()
            .store_ref()
            .retained_events(&chat)
            .unwrap();
        let db = rusqlite::Connection::open(wb.lock_unpoisoned().store_ref().path()).unwrap();
        match case {
            "receipted-processing" => {
                let mut guard = wb.lock_unpoisoned();
                let basis = authority.prepare_basis(&guard).unwrap();
                guard
                    .store_mut()
                    .with_dispatch_record_admission(&basis, |writer| {
                        writer.commit_claimed(
                            parent.command_id(),
                            parent.scope(),
                            parent.key(),
                            parent.snapshot(),
                            &[],
                        )
                    })
                    .unwrap()
                    .unwrap();
                guard
                    .store_mut()
                    .set_command_status(parent.command_id(), "processing")
                    .unwrap();
            }
            "missing" => {
                db.execute(
                    "DELETE FROM commands WHERE command_id=?1",
                    [parent.command_id()],
                )
                .unwrap();
            }
            column => {
                let replacement = if column == "status" {
                    "applied"
                } else {
                    "substituted-original-parent"
                };
                db.execute(
                    &format!("UPDATE commands SET {column}=?1 WHERE command_id=?2"),
                    rusqlite::params![replacement, parent.command_id()],
                )
                .unwrap();
            }
        }
        // Staff standing is unchanged; the exact original parent independently
        // stops this already-bound live harness, before any model/tool checkpoint.
        assert!(authority.checkpoint(&wb).is_ok());
        assert_eq!(
            access.check_current().unwrap_err(),
            "office task authority ended",
            "{case}"
        );
        assert_eq!(
            before,
            wb.lock_unpoisoned()
                .store_ref()
                .retained_events(&chat)
                .unwrap()
        );
        if case != "receipted-processing" {
            if case == "missing" {
                assert!(
                    wb.lock_unpoisoned()
                        .store_mut()
                        .claim_command(
                            parent.command_id(),
                            parent.scope(),
                            parent.key(),
                            parent.snapshot()
                        )
                        .unwrap()
                        .1
                );
            } else {
                let original = match case {
                    "status" => "processing",
                    "command_id" => parent.command_id(),
                    "scope_id" => parent.scope(),
                    "idempotency_key" => parent.key(),
                    "snapshot_json" => parent.snapshot(),
                    _ => unreachable!(),
                };
                let current_id = if case == "command_id" {
                    "substituted-original-parent"
                } else {
                    parent.command_id()
                };
                db.execute(
                    &format!("UPDATE commands SET {case}=?1 WHERE command_id=?2"),
                    rusqlite::params![original, current_id],
                )
                .unwrap();
            }
            parent
                .verify_pending(wb.lock_unpoisoned().store_ref())
                .unwrap();
        }
        assert!(
            access.check_current().is_err(),
            "{case}: restoration revived binding"
        );
    }
}

#[tokio::test]
async fn engine_refuses_office_work_without_original_http_claim_before_factory() {
    struct NeverFactory;
    impl gaugedesk_harness::HarnessFactory for NeverFactory {
        fn kind(&self) -> &'static str {
            "scripted-fake"
        }
        fn create(
            &self,
            _: &gaugedesk_harness::HarnessSpec,
        ) -> std::io::Result<Box<dyn gaugedesk_harness::Harness>> {
            panic!("office work without original HTTP claim created a harness")
        }
        fn credential_status(
            &self,
            _: &str,
            _: Option<&dyn gaugedesk_harness::CredentialCapability>,
        ) -> gaugedesk_harness::CredentialProbe {
            gaugedesk_harness::CredentialProbe::Ready
        }
    }

    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&app, ALICE).await;
    let chat = chat(&wb);
    let context = context(&wb, &admission);
    let (task, before) = {
        let mut guard = wb.lock_unpoisoned();
        (
            guard.engagement_task_context(&chat).unwrap(),
            guard
                .store_ref()
                .records(&chat, "transcript")
                .unwrap()
                .len(),
        )
    };
    let result = crate::engine::run_engagement_turn(
        &wb,
        &chat,
        &task.worktree,
        &task.sender,
        crate::engine::EngagementTurnInput {
            task: "synthetic clinical prompt",
            images: &[],
            mode: task.mode,
            authenticated_actor: Some(context.actor()),
            authenticated_context: Some(&context),
            client_build: Some(&Default::default()),
            local_operator: false,
            contribution_by: None,
            account_scope: "account",
            tenant_scope: ORG_SCOPE,
            account_bearer: Some(ALICE),
            runtime_command_id: None,
            original_http_command: None,
            harness_factory: Some(crate::harness_select::TurnHarnessFactory::Custom(
                std::sync::Arc::new(NeverFactory),
            )),
        },
    );
    assert!(
        matches!(result, Err(crate::engine::EngineError::Message(ref error))
        if error == "office task has no original HTTP claim"),
        "{result:?}"
    );
    assert_eq!(
        wb.lock_unpoisoned()
            .store_ref()
            .records(&chat, "transcript")
            .unwrap()
            .len(),
        before
    );
    assert!(!crate::engine::turn_is_live(&chat));
}

#[tokio::test]
async fn original_office_writer_joins_witnessed_cut_typed_completion_and_receipt() {
    use gaugedesk_core::merge::{MergeCommand, MergePhase, MergeState};
    use gaugedesk_core::run::{RunCommand, RunPhase, RunState};
    use gaugedesk_store::command_dispatch::LifecycleBatch;
    use gaugedesk_workspace::{NativeTurnFileWitness, WorkspaceError};
    use sha2::{Digest, Sha256};
    use whipplescript_store::vcs::recorded_review::RecordedMergeOutcome;
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&app, ALICE).await;
    let chat = chat(&wb);
    let context = context(&wb, &admission);
    let authority = OfficeTaskAuthority::for_turn(
        &wb,
        &chat,
        Some(&context),
        Some(&Default::default()),
        None,
        Some(ALICE),
    )
    .unwrap()
    .unwrap();
    authority
        .claim_upload_command(
            &wb,
            "original-task",
            "task-completion",
            "original-key",
            "original-input",
        )
        .unwrap();
    let prefix = wb
        .lock_unpoisoned()
        .engagement_context_target_root(&chat, None)
        .unwrap();
    let target_path = |name: &str| {
        prefix
            .as_ref()
            .map_or_else(|| name.to_owned(), |prefix| format!("{prefix}/{name}"))
    };
    let base_path = target_path("base.txt");
    let result_path = target_path("result.txt");
    let unrelated_path = target_path("unrelated.txt");
    let engagement = {
        let guard = wb.lock_unpoisoned();
        let engagement = guard.engagements[&chat].boxed_clone();
        engagement.write_file(&base_path, "synthetic base").unwrap();
        engagement
    };
    engagement
        .write_file(&result_path, "synthetic result")
        .unwrap();
    engagement
        .write_file(&unrelated_path, "unsubmitted edit")
        .unwrap();
    engagement
        .write_file("artifacts/report.txt", "original artifact")
        .unwrap();
    let witness = [
        NativeTurnFileWitness {
            path: result_path.clone(),
            kind: "add".into(),
            sha256: hex::encode(Sha256::digest(b"synthetic result")),
            bytes: 16,
        },
        NativeTurnFileWitness {
            path: "artifacts/report.txt".into(),
            kind: "add".into(),
            sha256: hex::encode(Sha256::digest(b"original artifact")),
            bytes: 17,
        },
    ];
    let mut original_prefix_positions = Vec::new();
    let mut base = String::new();
    for replay in [false, true] {
        let mut guard = wb.lock_unpoisoned();
        let basis = authority.prepare_basis(&guard).unwrap();
        let before = guard.store_ref().retained_events(&chat).unwrap();
        let prefix = guard
            .store_mut()
            .with_dispatch_record_admission(&basis, |writer| {
                writer
                    .require_pending_claim(
                        "original-task",
                        "task-completion",
                        "original-key",
                        "original-input",
                    )
                    .unwrap();
                let native_base = writer
                    .with_native_check(|check| {
                        engagement.witnessed_turn_start_guarded(
                            authority.actor(),
                            "original-task",
                            &mut || {
                                check.check_current().map_err(|error| WorkspaceError {
                                    message: format!("{error:?}"),
                                })
                            },
                        )
                    })
                    .unwrap()
                    .unwrap();
                if replay {
                    assert_eq!(base, native_base.base_cut());
                }
                base = native_base.base_cut().to_owned();
                native_base.publish_base_retained(|| {
                    writer
                        .commit_claimed_lifecycle_prefix(
                            "original-task",
                            "task-completion",
                            "original-key",
                            "original-input",
                            "startup",
                            LifecycleBatch::<RunState> {
                                scope: chat.clone(),
                                commands: vec![
                                    RunCommand::RequestRun,
                                    RunCommand::AdmitRun,
                                    RunCommand::StartRun,
                                ],
                            },
                            &[
                                gaugedesk_store::CommandRecordFact {
                                    scope_id: chat.clone(),
                                    kind: "office_turn_base".into(),
                                    payload: native_base.base_cut().to_owned(),
                                },
                                gaugedesk_store::CommandRecordFact {
                                    scope_id: chat.clone(),
                                    kind: "transcript".into(),
                                    payload: "synthetic original submitted task".into(),
                                },
                            ],
                        )
                        .map_err(|error| {
                            whipplescript_store::StoreError::Conflict(format!("{error:?}"))
                        })
                })
            })
            .unwrap()
            .unwrap();
        assert_eq!(prefix.replayed, replay);
        assert!(guard
            .store_ref()
            .pending_command_matches(
                "original-task",
                "task-completion",
                "original-key",
                "original-input",
            )
            .unwrap());
        assert_eq!(
            guard.store_ref().fold::<RunState>(&chat).unwrap().phase,
            RunPhase::Running
        );
        if replay {
            assert_eq!(prefix.positions, original_prefix_positions);
            assert_eq!(guard.store_ref().retained_events(&chat).unwrap(), before);
        } else {
            original_prefix_positions = prefix.positions;
        }
    }
    let mut original_cut = String::new();
    let mut original_local_result = String::new();
    for replay in [false, true] {
        let target = engagement.witnessed_turn_target_at(&base).unwrap();
        let mut guard = wb.lock_unpoisoned();
        let basis = authority.prepare_basis(&guard).unwrap();
        let before = guard.store_ref().retained_events(&chat).unwrap();
        let result = guard
            .store_mut()
            .with_dispatch_record_admission(&basis, |writer| {
                let native = writer
                    .with_native_check(|check| {
                        target.import_result_guarded(
                            &witness,
                            "original-owner-cut",
                            authority.actor(),
                            "original-task",
                            &mut || {
                                check.check_current().map_err(|error| WorkspaceError {
                                    message: format!("{error:?}"),
                                })
                            },
                        )
                    })
                    .unwrap()
                    .unwrap();
                if replay {
                    assert_eq!(native.cut(), original_cut);
                }
                original_cut = native.cut().to_owned();
                let local_result = serde_json::to_string(&(
                    native.result_evidence().unwrap(),
                    native.local_files(),
                    native.local_removed(),
                ))
                .unwrap();
                if replay {
                    assert_eq!(local_result, original_local_result);
                }
                original_local_result = local_result.clone();
                let facts = [
                    gaugedesk_store::CommandRecordFact {
                        scope_id: chat.clone(),
                        kind: "workspace_result".into(),
                        payload: native.cut().to_owned(),
                    },
                    gaugedesk_store::CommandRecordFact {
                        scope_id: chat.clone(),
                        kind: "workspace_local_result".into(),
                        payload: local_result,
                    },
                ];
                let reviewed = writer
                    .with_native_check(|check| {
                        native.prepare_recorded_review_guarded(&mut || {
                            check.check_current().map_err(|error| WorkspaceError {
                                message: format!("{error:?}"),
                            })
                        })
                    })
                    .unwrap()
                    .unwrap();
                reviewed.publish_retained(|review, _| {
                    assert_eq!(review.target_branch_id, engagement.target());
                    assert!(!review.diff.iter().any(|entry| {
                        entry.path == unrelated_path || entry.path.starts_with("artifacts/")
                    }));
                    let merge_command = match &review.outcome {
                        RecordedMergeOutcome::UpToDate | RecordedMergeOutcome::Clean { .. } => {
                            MergeCommand::WorkspaceClean
                        }
                        RecordedMergeOutcome::Conflicted { .. } => MergeCommand::WorkspaceConflict,
                    };
                    writer
                        .commit_claimed_lifecycle_pair(
                            "original-task",
                            "task-completion",
                            "original-key",
                            "original-input",
                            LifecycleBatch::<RunState> {
                                scope: chat.clone(),
                                commands: vec![
                                    RunCommand::RecordObservation,
                                    RunCommand::CompleteRun,
                                ],
                            },
                            LifecycleBatch::<MergeState> {
                                scope: chat.clone(),
                                commands: vec![MergeCommand::StartMerge, merge_command],
                            },
                            |next| {
                                let mut facts = facts.to_vec();
                                facts.push(gaugedesk_store::CommandRecordFact {
                                    scope_id: chat.clone(),
                                    kind: "transcript".into(),
                                    payload: "synthetic original qualified answer".into(),
                                });
                                facts.push(gaugedesk_store::CommandRecordFact {
                                    scope_id: chat.clone(),
                                    kind: "fixture_result_boundary".into(),
                                    payload: (next + 2).to_string(),
                                });
                                Ok(facts)
                            },
                        )
                        .map_err(|error| {
                            whipplescript_store::StoreError::Conflict(format!("{error:?}"))
                        })
                })
            })
            .unwrap()
            .unwrap();
        assert_eq!(result.replayed, replay);
        assert_eq!(
            guard.store_ref().fold::<MergeState>(&chat).unwrap().phase,
            MergePhase::Clean
        );
        let boundary = guard
            .store_ref()
            .records(&chat, "fixture_result_boundary")
            .unwrap();
        assert_eq!(boundary.len(), 1);
        let assistant_position: i64 = boundary[0].parse().unwrap();
        let rows = guard.store_ref().retained_events(&chat).unwrap();
        let assistant = rows.iter().find(|row| row.0 == assistant_position).unwrap();
        assert_eq!(assistant.1, "transcript");
        assert_eq!(assistant.2, "synthetic original qualified answer");
        assert_eq!(
            guard.store_ref().fold::<RunState>(&chat).unwrap().phase,
            RunPhase::Completed
        );
        assert_eq!(
            guard
                .store_ref()
                .records(&chat, "workspace_result")
                .unwrap(),
            vec![original_cut.clone()]
        );
        assert_eq!(
            guard
                .store_ref()
                .command("original-task")
                .unwrap()
                .unwrap()
                .status,
            "applied"
        );
        assert_eq!(
            guard
                .store_ref()
                .records(&chat, "workspace_local_result")
                .unwrap(),
            vec![original_local_result.clone()]
        );
        if replay {
            assert_eq!(guard.store_ref().retained_events(&chat).unwrap(), before);
        }
        drop(guard);
        engagement
            .write_file(&result_path, "later synthetic work")
            .unwrap();
        engagement
            .write_file("artifacts/report.txt", "later artifact projection")
            .unwrap();
    }
    assert_eq!(
        engagement.read_file(&unrelated_path).unwrap(),
        "unsubmitted edit"
    );
    grant(&wb, "alice", crate::library::RecordOp::Tombstone);
    let guard = wb.lock_unpoisoned();
    assert!(authority.prepare_basis(&guard).is_err());
}

#[tokio::test]
async fn middleware_original_task_identity_reaches_the_office_harness_binding() {
    use gaugedesk_harness::{Harness, HarnessFactory, HarnessSpec};
    struct Probe(std::sync::Arc<std::sync::Mutex<Option<String>>>);
    impl Harness for Probe {
        fn bind_runtime_command_id(&mut self, id: Option<&str>) {
            *self.0.lock().unwrap() = id.map(str::to_owned);
        }
        fn run_turn(
            &mut self,
            _: &dyn gaugedesk_harness::EgressGate,
            _: &str,
            _: &[gaugedesk_harness::ImageContent],
            _: &mut dyn FnMut(&gaugedesk_harness::Observation),
        ) -> std::io::Result<gaugedesk_harness::TurnOutcome> {
            panic!("unsupported office harness must not execute");
        }
    }
    impl HarnessFactory for Probe {
        fn kind(&self) -> &'static str {
            "scripted-fake"
        }
        fn create(&self, _: &HarnessSpec) -> std::io::Result<Box<dyn Harness>> {
            Ok(Box::new(Probe(self.0.clone())))
        }
        fn reuse_across_turns(&self) -> bool {
            false
        }
        fn credential_status(
            &self,
            _: &str,
            _: Option<&dyn gaugedesk_harness::CredentialCapability>,
        ) -> gaugedesk_harness::CredentialProbe {
            gaugedesk_harness::CredentialProbe::Ready
        }
    }
    for mismatch in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (wb, admission_app, _, _) = fixture(root.path());
        let hub = hub().await;
        install(&wb, &hub);
        let admission = admit(&admission_app, ALICE).await;
        let chat = chat(&wb);
        let captured = context(&wb, &admission);
        let bound = std::sync::Arc::new(std::sync::Mutex::new(None));
        let output = bound.clone();
        let original_id = std::sync::Arc::new(std::sync::Mutex::new(None));
        let id_output = original_id.clone();
        let app = Router::new().route("/chats/{id}/task", post(move |
            State(wb): State<SharedWorkbench>, Path(chat): Path<String>,
            axum::extract::Extension(original): axum::extract::Extension<crate::command_idempotency::ClaimedHttpCommand>| {
            let captured = captured.clone();
            let output = output.clone();
            let id_output = id_output.clone();
            async move {
                original.verify_pending(wb.lock_unpoisoned().store_ref()).unwrap();
                *id_output.lock().unwrap() = Some(original.command_id().to_owned());
                let task = wb.lock_unpoisoned().engagement_task_context(&chat).unwrap();
                let result = crate::engine::run_engagement_turn(&wb, &chat, &task.worktree, &task.sender,
                    crate::engine::EngagementTurnInput {
                        task: "synthetic clinical task", images: &[], mode: task.mode,
                        authenticated_actor: Some(captured.actor()), authenticated_context: Some(&captured),
                        client_build: Some(&Default::default()), local_operator: false, contribution_by: None,
                        account_scope: "account", tenant_scope: ORG_SCOPE, account_bearer: Some(ALICE),
                        runtime_command_id: mismatch.then_some("substituted-command"), original_http_command: Some(&original),
                        harness_factory: Some(crate::harness_select::TurnHarnessFactory::Custom(std::sync::Arc::new(Probe(output)))),
                    });
                if mismatch {
                    assert!(matches!(result, Err(crate::engine::EngineError::Admit(gaugedesk_store::AdmitError::Rejected(ref rejection)))
                        if rejection.reason == "runtime command differs from original HTTP task"), "{result:?}");
                } else {
                    assert!(matches!(result, Err(crate::engine::EngineError::Harness(ref error))
                        if error.to_string() == "turn access unsupported"), "{result:?}");
                }
                assert!(wb.lock_unpoisoned().store_ref().records(&chat, "transcript").unwrap().is_empty());
                StatusCode::FORBIDDEN
            }
        })).layer(axum::middleware::from_fn_with_state(wb.clone(), crate::command_idempotency::guard)).with_state(wb.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/chats/{chat}/task"))
                    .header("idempotency-key", "original-task-key")
                    .body(Body::from("synthetic clinical task"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        if mismatch {
            assert!(bound.lock().unwrap().is_none());
        } else {
            assert_eq!(*bound.lock().unwrap(), *original_id.lock().unwrap());
        }
        assert!(!crate::engine::turn_is_live(&chat));
    }
}

#[tokio::test]
async fn office_foreground_task_route_refuses_a_missing_middleware_claim() {
    let root = tempfile::tempdir().unwrap();
    let (wb, admission_app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&admission_app, ALICE).await;
    let chat = chat(&wb);
    let captured = context(&wb, &admission);
    let response = crate::engagement_routes::post_task(
        State(wb.clone()),
        Path(chat.clone()),
        axum::http::HeaderMap::new(),
        None,
        Some(axum::extract::Extension(captured)),
        None,
        None,
        axum::Json(
            serde_json::from_value::<crate::engagement_routes::TaskBody>(serde_json::json!({
                "prompt": "synthetic clinical task", "images": []
            }))
            .unwrap(),
        ),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(wb
        .lock_unpoisoned()
        .store_ref()
        .records(&chat, "transcript")
        .unwrap()
        .is_empty());
    assert!(!crate::engine::turn_is_live(&chat));
}

#[tokio::test]
async fn production_office_startup_uses_original_http_claim_and_recorded_native_base() {
    use gaugedesk_core::run::{RunCommand, RunPhase, RunState};
    use sha2::Digest;
    #[derive(Clone)]
    struct StartupProbe {
        wb: SharedWorkbench,
        chat: String,
        original: crate::command_idempotency::ClaimedHttpCommand,
        reached: Arc<AtomicBool>,
        created: Arc<AtomicBool>,
        access: Option<Arc<dyn gaugedesk_harness::TurnAccess>>,
        revoke: bool,
    }
    impl gaugedesk_harness::Harness for StartupProbe {
        fn bind_workspace_payload_retention(
            &mut self,
            retention: Option<Arc<dyn gaugedesk_harness::WorkspacePayloadRetention>>,
        ) -> std::io::Result<()> {
            assert!(
                retention.is_some(),
                "original office startup needs custody binding"
            );
            Ok(())
        }
        fn prepare_runtime_turn(
            &mut self,
            prompt: &str,
            images: &[gaugedesk_harness::ImageContent],
        ) -> std::io::Result<gaugedesk_harness::RuntimeTurnPreparation> {
            self.access
                .as_ref()
                .unwrap()
                .check_current()
                .map_err(std::io::Error::other)?;
            Ok(gaugedesk_harness::RuntimeTurnPreparation {
                input_digest: gaugedesk_harness::runtime_input_digest(prompt, images),
                command_json: serde_json::json!({"synthetic_command": self.original.command_id(), "input": prompt}).to_string(),
                start_position: gaugedesk_harness::RuntimePosition { instance_ref: "synthetic-runtime".into(), sequence: 4 },
                start_head_digest: "synthetic-original-digest".into(), workspace_targets: Vec::new(),
            })
        }

        fn bind_turn_access(
            &mut self,
            access: Option<Arc<dyn gaugedesk_harness::TurnAccess>>,
        ) -> std::io::Result<()> {
            self.access = access;
            Ok(())
        }
        fn run_turn(
            &mut self,
            _: &dyn gaugedesk_harness::EgressGate,
            _: &str,
            _: &[gaugedesk_harness::ImageContent],
            _: &mut dyn FnMut(&gaugedesk_harness::Observation),
        ) -> std::io::Result<gaugedesk_harness::TurnOutcome> {
            self.access.as_ref().unwrap().check_current().unwrap();
            let guard = self.wb.lock_unpoisoned();
            assert_eq!(
                guard
                    .store_ref()
                    .fold::<RunState>(&self.chat)
                    .unwrap()
                    .phase,
                RunPhase::Running
            );
            assert!(guard
                .store_ref()
                .pending_command_matches(
                    self.original.command_id(),
                    self.original.scope(),
                    self.original.key(),
                    self.original.snapshot()
                )
                .unwrap());
            assert_eq!(
                guard
                    .store_ref()
                    .records(
                        &self.chat,
                        crate::engine::office_turn_startup::RUNTIME_SNAPSHOT_KIND
                    )
                    .unwrap()
                    .len(),
                1
            );
            assert!(guard
                .store_ref()
                .claimed_lifecycle_prefix_recorded(
                    self.original.command_id(),
                    "runtime-preparation"
                )
                .unwrap());
            assert_eq!(
                guard
                    .store_ref()
                    .records(&self.chat, "office_turn_base")
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                guard
                    .store_ref()
                    .records(
                        &self.chat,
                        crate::target_change_set::TURN_PROCESS_DECLARATION_KIND
                    )
                    .unwrap()
                    .len(),
                1
            );
            drop(guard);
            if self.revoke {
                membership(
                    &self.wb,
                    "alice",
                    crate::org::MembershipStatus::Deprovisioned,
                );
            }
            self.reached.store(true, Ordering::Release);
            Err(std::io::Error::other(
                "qualification stops after production startup",
            ))
        }
    }
    impl gaugedesk_harness::HarnessFactory for StartupProbe {
        fn kind(&self) -> &'static str {
            "scripted-fake"
        }
        fn create(
            &self,
            _: &gaugedesk_harness::HarnessSpec,
        ) -> std::io::Result<Box<dyn gaugedesk_harness::Harness>> {
            self.created.store(true, Ordering::Release);
            Ok(Box::new(self.clone()))
        }
        fn reuse_across_turns(&self) -> bool {
            false
        }
        fn credential_status(
            &self,
            _: &str,
            _: Option<&dyn gaugedesk_harness::CredentialCapability>,
        ) -> gaugedesk_harness::CredentialProbe {
            gaugedesk_harness::CredentialProbe::Ready
        }
    }
    struct RecordedProbe {
        observed: Arc<AtomicBool>,
        command: String,
        policy: String,
    }
    impl gaugedesk_harness::HarnessFactory for RecordedProbe {
        fn kind(&self) -> &'static str {
            "recorded-probe"
        }
        fn create(
            &self,
            _: &gaugedesk_harness::HarnessSpec,
        ) -> std::io::Result<Box<dyn gaugedesk_harness::Harness>> {
            panic!("recovery constructed an ordinary harness")
        }
        fn credential_status(
            &self,
            _: &str,
            _: Option<&dyn gaugedesk_harness::CredentialCapability>,
        ) -> gaugedesk_harness::CredentialProbe {
            panic!("recovery probed provider credentials")
        }
        fn recorded_policy_epoch(
            &self,
            preparation: &gaugedesk_harness::RuntimeTurnPreparation,
        ) -> std::io::Result<u64> {
            assert_eq!(
                preparation.command_json,
                "synthetic original runtime intent"
            );
            Ok(1)
        }
        fn observe_recorded_runtime(
            &self,
            spec: &gaugedesk_harness::RecordedRuntimeSpec<'_>,
        ) -> std::io::Result<gaugedesk_harness::TurnOutcome> {
            spec.access.check_current().unwrap();
            assert_eq!(spec.command_id, self.command);
            assert_eq!(spec.signed_policy_envelope, self.policy);
            assert_eq!(spec.preparation.start_position.sequence, 4);
            self.observed.store(true, Ordering::Release);
            Err(std::io::Error::other(
                "qualification stops at original recorded reader",
            ))
        }
    }
    for case in [
        "fresh",
        "running",
        "revoked",
        "wrong-chat",
        "engine",
        "engine-revoked",
        "replay",
        "changed-input",
        "duplicate",
        "standing-v2",
        "standing-loss",
        "standing-actor",
        "standing-chat",
        "standing-project",
        "standing-client",
        "standing-member",
        "standing-role",
        "standing-grants",
        "standing-revocations",
        "standing-source",
        "standing-epoch",
        "standing-admission",
        "standing-deadline",
        "lineage-v1",
        "lineage-loss",
        "lineage-parent",
        "lineage-divergence",
        "unreadable",
        "snapshot-loss",
        "phase-command-loss",
        "phase-input-change",
        "prefix-loss",
        "receipt-loss",
        "orphan",
        "retained-loss",
        "retained-never",
        "process-loss",
        "process-duplicate",
        "process-receipt-loss",
        "process-orphan",
        "restored",
        "completed",
        "write-failure",
        "runtime-repeat",
        "runtime-engine-read",
        "runtime-unreceipted",
        "runtime-input",
        "runtime-changed",
        "runtime-duplicate",
        "runtime-loss",
        "runtime-receipt-loss",
        "runtime-orphan",
        "runtime-unreadable",
        "runtime-v1",
        "runtime-missing-input",
        "runtime-empty-input",
        "runtime-write-failure",
        "runtime-revoked",
        "runtime-restored",
        "runtime-completed",
        "runtime-process",
    ] {
        let root = tempfile::tempdir().unwrap();
        let (wb, admission_app, _, _) = fixture(root.path());
        let hub = hub().await;
        install(&wb, &hub);
        let admission = admit(&admission_app, ALICE).await;
        let chat = chat(&wb);
        let captured = context(&wb, &admission);
        let reached = Arc::new(AtomicBool::new(false));
        let reached_output = reached.clone();
        let app = Router::new()
            .route(
                "/chats/{id}/task",
                post(
                    move |State(wb): State<SharedWorkbench>,
                          Path(chat): Path<String>,
                          axum::extract::Extension(original): axum::extract::Extension<
                        crate::command_idempotency::ClaimedHttpCommand,
                    >| {
                        let captured = captured.clone();
                        let reached = reached_output.clone();
                        async move {
                            let authority = OfficeTaskAuthority::for_turn(
                                &wb,
                                &chat,
                                Some(&captured),
                                Some(&Default::default()),
                                None,
                                Some(ALICE),
                            )
                            .unwrap()
                            .unwrap();
                            let (engagement, mut snapshot, pending_path, before) = {
                                let mut guard = wb.lock_unpoisoned();
                                if case == "running" {
                                    for command in [
                                        RunCommand::RequestRun,
                                        RunCommand::AdmitRun,
                                        RunCommand::StartRun,
                                    ] {
                                        guard
                                            .store_mut()
                                            .admit::<RunState>(&chat, command)
                                            .unwrap();
                                    }
                                }
                                let engagement = guard.engagements[&chat].boxed_clone();
                                let prefix =
                                    guard.engagement_context_target_root(&chat, None).unwrap();
                                let path = prefix.map_or_else(
                                    || "unsubmitted.txt".to_owned(),
                                    |prefix| format!("{prefix}/unsubmitted.txt"),
                                );
                                engagement
                                    .write_file(&path, "unsubmitted original edit")
                                    .unwrap();
                                let process = guard
                                    .prepare_turn_process_declaration(
                                        &chat,
                                        "qualification",
                                        None,
                                        0,
                                        None,
                                    )
                                    .unwrap();
                                assert!(process.is_some());
                                let snapshot = guard
                                    .turn_fork_snapshot(&chat, None, None, process)
                                    .unwrap();
                                assert!(snapshot.is_some());
                                let before = guard.store_ref().retained_events(&chat).unwrap();
                                (engagement, snapshot, path, before)
                            };
                            if matches!(case, "engine" | "engine-revoked") {
                                let (worktree, sender, mode) = wb.lock_unpoisoned().engagement_turn_location(&chat).unwrap();
                                let probe = StartupProbe { wb: wb.clone(), chat: chat.clone(), original: original.clone(), reached: reached.clone(), created: Arc::new(AtomicBool::new(false)), access: None, revoke: case == "engine-revoked" };
                                let result = crate::engine::run_engagement_turn(&wb, &chat, &worktree, &sender,
                                    crate::engine::EngagementTurnInput {
                                        task: "synthetic original task", images: &[], mode,
                                        authenticated_actor: Some(captured.actor()), authenticated_context: Some(&captured),
                                        client_build: Some(&Default::default()), local_operator: false, contribution_by: None,
                                        account_scope: "account", tenant_scope: ORG_SCOPE, account_bearer: Some(ALICE),
                                        runtime_command_id: None, original_http_command: Some(&original),
                                        harness_factory: Some(crate::harness_select::TurnHarnessFactory::Custom(Arc::new(probe))),
                                    });
                                if case == "engine-revoked" {
                                    assert!(matches!(result, Err(crate::engine::EngineError::Admit(_))), "{result:?}");
                                } else {
                                    assert!(matches!(result, Err(crate::engine::EngineError::Harness(ref error)) if error.to_string() == "qualification stops after production startup"), "{result:?}");
                                }
                                assert!(reached.load(Ordering::Acquire));
                                let guard = wb.lock_unpoisoned();
                                let bases = guard.store_ref().records(&chat, "office_turn_base").unwrap();
                                assert_eq!(bases.len(), 1);
                                assert!(engagement.recorded_streamed_file_hash(&pending_path, &bases[0],
                                    &hex::encode(sha2::Sha256::digest(b"unsubmitted original edit")),
                                    b"unsubmitted original edit".len() as u64).unwrap().is_none(), "engine imported pending bytes into its original base");
                                assert_eq!(engagement.observe().unwrap().recorded_cut.as_deref(), Some(bases[0].as_str()), "transport failure imported mutable workspace history");
                                if case == "engine-revoked" {
                                    assert!(guard.store_ref().pending_command_matches(original.command_id(), original.scope(), original.key(), original.snapshot()).unwrap());
                                    assert_eq!(guard.store_ref().fold::<RunState>(&chat).unwrap().phase, RunPhase::Running);
                                    assert!(guard.store_ref().records(&chat, "office_turn_result_gap").unwrap().is_empty());
                                    assert!(crate::turn_summary::latest(guard.store_ref(), &chat).unwrap().is_none());
                                    assert_eq!(guard.store_ref().records(&chat, "transcript").unwrap().len(), 1);
                                } else {
                                    assert!(!guard.store_ref().pending_command_matches(original.command_id(), original.scope(), original.key(), original.snapshot()).unwrap());
                                    assert_eq!(guard.store_ref().command(original.command_id()).unwrap().unwrap().status, "applied");
                                    let receipts: i64 = rusqlite::Connection::open(guard.store_ref().path()).unwrap().query_row(
                                        "SELECT COUNT(*) FROM command_receipts r JOIN commands c ON c.scope_id=r.scope_id AND c.idempotency_key=r.command_key WHERE r.scope_id=?1 AND r.command_key=?2 AND c.command_id=?3 AND c.snapshot_json=?4",
                                        rusqlite::params![original.scope(), original.key(), original.command_id(), original.snapshot()], |row| row.get(0)).unwrap();
                                    assert_eq!(receipts, 1);
                                    assert_eq!(guard.store_ref().fold::<RunState>(&chat).unwrap().phase, RunPhase::Failed);
                                    let gaps = guard.store_ref().records(&chat, "office_turn_result_gap").unwrap();
                                    assert_eq!(gaps.len(), 1);
                                    let gap: serde_json::Value = serde_json::from_str(&gaps[0]).unwrap();
                                    assert_eq!(gap["base_cut"], bases[0]);
                                    assert_eq!(gap["reason"], "transport_failed_without_qualified_runtime_outcome");
                                    assert_eq!(crate::turn_summary::latest(guard.store_ref(), &chat).unwrap().unwrap().receipt_status, crate::turn_summary::ReceiptStatus::Failed);
                                }
                                return StatusCode::FORBIDDEN;
                            }
                            if case == "revoked" {
                                membership(
                                    &wb,
                                    "alice",
                                    crate::org::MembershipStatus::Deprovisioned,
                                );
                            }
                            let office = crate::engine::office_turn_startup::OfficeTurnContext {
                                wb: &wb,
                                authority: &authority,
                                original: &original,
                            };
                            let scope = if case == "wrong-chat" {
                                "substituted-chat"
                            } else {
                                &chat
                            };
                            if case == "replay" {
                                crate::resource_store::record_reads(wb.lock_unpoisoned().store_mut(), &chat,
                                    &[gaugedesk_core::resource::ResourceId::new("original-read")]).unwrap();
                            }
                            if case == "write-failure" {
                                let db = rusqlite::Connection::open(wb.lock_unpoisoned().store_ref().path()).unwrap();
                                db.execute_batch("CREATE TRIGGER reject_startup_snapshot BEFORE INSERT ON events WHEN NEW.kind='office_turn_startup' BEGIN SELECT RAISE(ABORT, 'synthetic startup snapshot write failure'); END;").unwrap();
                            }
                            if case == "retained-never" {
                                assert!(crate::engine::office_turn_startup::admit_retained_startup(&office, engagement.as_ref(), scope, "synthetic original task", &mut snapshot).is_err());
                                assert_eq!(wb.lock_unpoisoned().store_ref().retained_events(&chat).unwrap(), before);
                                reached.store(true, Ordering::Release);
                                return StatusCode::FORBIDDEN;
                            }
                            let unbound_original_fork = snapshot.clone();
                            let result = crate::engine::office_turn_startup::admit_startup(
                                &office,
                                engagement.as_ref(),
                                scope,
                                "synthetic original task",
                                &mut snapshot,
                            );
                            if case.starts_with("runtime-") {
                                use crate::engine::office_turn_startup::{recorded_policy, recorded_runtime, retain_runtime, RUNTIME_SNAPSHOT_KIND};
                                let mut startup = result.unwrap();
                                let original_read_access = office.recorded_access();
                                assert!(gaugedesk_harness::TurnAccess::check_current(&original_read_access).is_ok());
                                let mut policy_input = crate::policy_compiler::PolicyCompilationInput {
                                    chat_id: chat.clone(), project_id: Some(authority.project().into()),
                                    actor: authority.actor().into(), actor_attributes: gaugedesk_core::abac::AuthorityAttributes { clearance: gaugedesk_core::abac::Clearance(3), ..Default::default() },
                                    org_policy: Default::default(), turn_purpose: None, package_capabilities: Default::default(),
                                    provider: "openai".into(), model: "synthetic-model".into(), base_url: "https://api.openai.com".into(),
                                    credential_ref: "credential:synthetic-policy-fixture".into(), private_model_broker: None,
                                    wire: "openai-responses".into(), placement_kind: "local".into(), command_network: false,
                                    resources: Vec::new(), task_tracker: None, target_bindings: Vec::new(), advancement_scopes: Vec::new(),
                                };
                                let original_policy = wb.lock_unpoisoned().compile_whipple_policy(policy_input.clone()).unwrap().signed_envelope;
                                let policy_before = wb.lock_unpoisoned().store_ref().retained_events(&chat).unwrap();
                                assert_eq!(recorded_policy(&office, &startup, 1).unwrap().0, original_policy);
                                assert!(recorded_policy(&office, &startup, 0).is_err());
                                assert!(recorded_policy(&office, &startup, 2).is_err());
                                assert_eq!(wb.lock_unpoisoned().store_ref().retained_events(&chat).unwrap(), policy_before);
                                policy_input.model = "synthetic-later-model".into();
                                wb.lock_unpoisoned().compile_whipple_policy(policy_input).unwrap();
                                assert_eq!(recorded_policy(&office, &startup, 1).unwrap().0, original_policy);

                                let mut preparation = gaugedesk_harness::RuntimeTurnPreparation {
                                    input_digest: gaugedesk_harness::runtime_input_digest("synthetic original task", &[]),
                                    command_json: "synthetic original runtime intent".into(),
                                    start_position: gaugedesk_harness::RuntimePosition { instance_ref: "synthetic-runtime".into(), sequence: 4 },
                                    start_head_digest: "original-digest".into(), workspace_targets: Vec::new(),
                                };
                                let db = rusqlite::Connection::open(wb.lock_unpoisoned().store_ref().path()).unwrap();
                                let raw_events = || db.prepare("SELECT position,scope_id,kind,payload FROM events ORDER BY position").unwrap()
                                    .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)))
                                    .unwrap().collect::<Result<Vec<_>, _>>().unwrap();
                                if case == "runtime-unreceipted" {
                                    let body = serde_json::json!({
                                        "revision": "office-turn-runtime/v2", "command": original.command_id(),
                                        "actor": authority.actor(), "chat": chat,
                                        "input_position": startup.user_entry_id,
                                        "process": snapshot.as_ref().and_then(|fork| fork.process_declaration.clone()),
                                        "preparation": preparation,
                                    }).to_string();
                                    wb.lock_unpoisoned().store_mut().append_record(&chat, RUNTIME_SNAPSHOT_KIND, &body).unwrap();
                                    assert!(!wb.lock_unpoisoned().store_ref().claimed_lifecycle_prefix_recorded(original.command_id(), "runtime-preparation").unwrap());
                                    let before = raw_events();
                                    assert!(recorded_runtime(&office, &startup, snapshot.as_ref()).is_err());
                                    assert_eq!(raw_events(), before);
                                    reached.store(true, Ordering::Release);
                                    return StatusCode::FORBIDDEN;
                                }
                                if case == "runtime-write-failure" {
                                    db.execute_batch("CREATE TRIGGER reject_runtime_snapshot BEFORE INSERT ON events WHEN NEW.kind='office_turn_runtime' BEGIN SELECT RAISE(ABORT, 'synthetic runtime snapshot failure'); END;").unwrap();
                                    let before = raw_events();
                                    assert!(retain_runtime(&office, &startup, snapshot.as_ref(), preparation).is_err());
                                    assert_eq!(raw_events(), before);
                                    assert!(!wb.lock_unpoisoned().store_ref().claimed_lifecycle_prefix_recorded(original.command_id(), "runtime-preparation").unwrap());
                                    reached.store(true, Ordering::Release);
                                    return StatusCode::FORBIDDEN;
                                }
                                assert!(recorded_runtime(&office, &startup, snapshot.as_ref()).is_err());
                                retain_runtime(&office, &startup, snapshot.as_ref(), preparation.clone()).unwrap();
                                let original_preparation = preparation.clone();
                                let observed_before = raw_events();
                                assert_eq!(recorded_runtime(&office, &startup, snapshot.as_ref()).unwrap(), original_preparation);
                                assert_eq!(raw_events(), observed_before);
                                let raw: String = db.query_row("SELECT payload FROM events WHERE kind=?1 AND scope_id=?2", rusqlite::params![RUNTIME_SNAPSHOT_KIND, chat], |row| row.get(0)).unwrap();
                                assert!(raw.starts_with("gwenc:1:"));
                                assert!(wb.lock_unpoisoned().store_ref().pending_command_matches(original.command_id(), original.scope(), original.key(), original.snapshot()).unwrap());
                                let phase = gaugedesk_store::Store::claimed_lifecycle_prefix_scope(original.command_id(), "runtime-preparation");
                                match case {
                                    "runtime-repeat" | "runtime-engine-read" => { engagement.commit_turn("later independently submitted work").unwrap(); engagement.write_file(&pending_path, "unsubmitted replacement").unwrap(); },
                                    "runtime-changed" => { preparation.start_position.sequence += 1; },
                                    "runtime-input" => { startup.user_entry_id += 1; },
                                    "runtime-process" => { snapshot.as_mut().unwrap().process_declaration = None; },
                                    "runtime-completed" => {
                                        let mut guard = wb.lock_unpoisoned();
                                        let (_, basis) = guard.store_ref().read_for_dispatch(&[&chat], |_| Ok(())).unwrap();
                                        guard.store_mut().with_dispatch_record_admission(&basis, |writer| writer.commit_claimed(original.command_id(), original.scope(), original.key(), original.snapshot(),
                                            &[gaugedesk_store::CommandRecordFact { scope_id: chat.clone(), kind: "synthetic-completion".into(), payload: "completed".into() }])).unwrap().unwrap();
                                    },
                                    "runtime-duplicate" => { let mut guard = wb.lock_unpoisoned(); let body = guard.store_ref().records(&chat, RUNTIME_SNAPSHOT_KIND).unwrap().pop().unwrap(); guard.store_mut().append_record(&chat, RUNTIME_SNAPSHOT_KIND, &body).unwrap(); },
                                    "runtime-loss" => { db.execute("DELETE FROM events WHERE kind=?1 AND scope_id=?2", rusqlite::params![RUNTIME_SNAPSHOT_KIND, chat]).unwrap(); },
                                    "runtime-receipt-loss" => { db.execute("DELETE FROM command_receipts WHERE scope_id=?1", [&phase]).unwrap(); },
                                    "runtime-orphan" => { db.execute("DELETE FROM command_receipts WHERE scope_id=?1", [&phase]).unwrap(); db.execute("DELETE FROM events WHERE scope_id=?1", [&phase]).unwrap(); },
                                    "runtime-v1" | "runtime-missing-input" | "runtime-empty-input" => {
                                        let mut guard = wb.lock_unpoisoned();
                                        let body = guard.store_ref().records(&chat, RUNTIME_SNAPSHOT_KIND).unwrap().pop().unwrap();
                                        let mut body: serde_json::Value = serde_json::from_str(&body).unwrap();
                                        match case {
                                            "runtime-v1" => body["revision"] = "office-turn-runtime/v1".into(),
                                            "runtime-missing-input" => { body["preparation"].as_object_mut().unwrap().remove("input_digest"); },
                                            "runtime-empty-input" => body["preparation"]["input_digest"] = "".into(),
                                            _ => unreachable!(),
                                        }
                                        db.execute("DELETE FROM events WHERE kind=?1 AND scope_id=?2", rusqlite::params![RUNTIME_SNAPSHOT_KIND, chat]).unwrap();
                                        guard.store_mut().append_record(&chat, RUNTIME_SNAPSHOT_KIND, &body.to_string()).unwrap();
                                    },
                                    "runtime-unreadable" => { db.execute("UPDATE events SET payload='gwenc:1:damaged' WHERE kind=?1 AND scope_id=?2", rusqlite::params![RUNTIME_SNAPSHOT_KIND, chat]).unwrap(); },
                                    "runtime-revoked" | "runtime-restored" => { membership(&wb, "alice", crate::org::MembershipStatus::Deprovisioned); if case == "runtime-restored" { membership(&wb, "alice", crate::org::MembershipStatus::Active); } },
                                    _ => unreachable!(),
                                }
                                let before = raw_events();
                                let native_head = engagement.observe().unwrap().recorded_cut;
                                let access = gaugedesk_harness::TurnAccess::check_current(&original_read_access);
                                if matches!(case, "runtime-revoked" | "runtime-restored" | "runtime-completed" | "runtime-unreadable") {
                                    assert_eq!(access.unwrap_err(), "original office runtime access ended");
                                    assert!(gaugedesk_harness::TurnAccess::check_current(&original_read_access).is_err());
                                } else { access.unwrap_or_else(|error| panic!("{case}: {error}")); }
                                let observed_policy = recorded_policy(&office, &startup, 1);
                                if matches!(case, "runtime-revoked" | "runtime-restored" | "runtime-completed" | "runtime-unreadable") {
                                    assert!(observed_policy.is_err(), "{case} released original policy");
                                } else {
                                    assert_eq!(observed_policy.unwrap().0, original_policy);
                                }
                                let observed = recorded_runtime(&office, &startup, snapshot.as_ref());
                                if matches!(case, "runtime-repeat" | "runtime-engine-read" | "runtime-changed") {
                                    assert_eq!(observed.unwrap(), original_preparation);
                                } else {
                                    assert!(observed.is_err(), "{case} unexpectedly released runtime evidence");
                                }
                                assert_eq!(raw_events(), before);
                                assert_eq!(engagement.observe().unwrap().recorded_cut, native_head);
                                let retry = retain_runtime(&office, &startup, snapshot.as_ref(), preparation);
                                if matches!(case, "runtime-repeat" | "runtime-engine-read") { retry.unwrap(); assert_eq!(engagement.read_file(&pending_path).unwrap(), "unsubmitted replacement"); }
                                else { assert!(retry.is_err(), "{case} unexpectedly retained changed runtime evidence"); }
                                assert_eq!(raw_events(), before);
                                if case == "runtime-engine-read" {
                                    let observed = Arc::new(AtomicBool::new(false));
                                    let (worktree, sender, mode) = wb.lock_unpoisoned().engagement_turn_location(&chat).unwrap();
                                    let engine_retry = crate::engine::run_engagement_turn(&wb, &chat, &worktree, &sender,
                                        crate::engine::EngagementTurnInput {
                                            task: "synthetic original task", images: &[], mode,
                                            authenticated_actor: Some(captured.actor()), authenticated_context: Some(&captured),
                                            client_build: Some(&Default::default()), local_operator: false, contribution_by: None,
                                            account_scope: "account", tenant_scope: ORG_SCOPE, account_bearer: Some(ALICE),
                                            runtime_command_id: None, original_http_command: Some(&original),
                                            harness_factory: Some(crate::harness_select::TurnHarnessFactory::Custom(Arc::new(RecordedProbe { observed: observed.clone(), command: original.command_id().into(), policy: original_policy.clone() }))),
                                        });
                                    assert!(matches!(engine_retry, Err(crate::engine::EngineError::Harness(ref error)) if error.to_string() == "qualification stops at original recorded reader"));
                                    assert!(observed.load(Ordering::Acquire));
                                    assert_eq!(raw_events(), before);
                                    assert_eq!(engagement.observe().unwrap().recorded_cut, native_head);
                                }
                                reached.store(true, Ordering::Release);
                                    return StatusCode::FORBIDDEN;
                            }
                            if !matches!(case, "fresh" | "running" | "revoked" | "wrong-chat" | "write-failure") {
                                let first = result.unwrap();
                                let original_fork = snapshot.clone();
                                let original_events = wb.lock_unpoisoned().store_ref().retained_events(&chat).unwrap();
                                let db = rusqlite::Connection::open(wb.lock_unpoisoned().store_ref().path()).unwrap();
                                let raw: String = db.query_row("SELECT payload FROM events WHERE kind='office_turn_startup' AND scope_id=?1", [&chat], |row| row.get(0)).unwrap();
                                assert!(raw.starts_with("gwenc:1:"));
                                let phase = gaugedesk_store::Store::claimed_lifecycle_prefix_scope(original.command_id(), "startup");
                                let process_phase = gaugedesk_store::Store::claimed_lifecycle_prefix_scope(original.command_id(), "startup-process-declaration");
                                match case {
                                    case if case.starts_with("standing-") => {
                                        let mut guard = wb.lock_unpoisoned();
                                        let mut body: serde_json::Value = serde_json::from_str(&guard.store_ref().records(&chat, crate::engine::office_turn_startup::SNAPSHOT_KIND).unwrap()[0]).unwrap();
                                        assert_eq!(body["revision"], "office-turn-startup/v3");
                                        match case {
                                            "standing-v2" => { body["revision"] = "office-turn-startup/v2".into(); body.as_object_mut().unwrap().remove("standing"); },
                                            "standing-loss" => { body.as_object_mut().unwrap().remove("standing"); },
                                            "standing-actor" => body["standing"]["actor"] = "other-staff".into(),
                                            "standing-chat" => body["standing"]["chat"] = "other-chat".into(),
                                            "standing-project" => body["standing"]["project"] = "other-project".into(),
                                            "standing-client" => body["standing"]["client"]["version"] = "999.0.0".into(),
                                            "standing-member" => body["standing"]["standing"]["member_id"] = "other-member".into(),
                                            "standing-role" => body["standing"]["standing"]["privileged"] = (!body["standing"]["standing"]["privileged"].as_bool().unwrap()).into(),
                                            "standing-grants" => body["standing"]["standing"]["grant_ids"] = serde_json::json!(["replacement-grant"]),
                                            "standing-revocations" => body["standing"]["standing"]["revocations"] = serde_json::json!(["replacement-denial"]),
                                            "standing-source" => body["standing"]["source_reference"] = "replacement-source".into(),
                                            "standing-epoch" => body["standing"]["process_epoch"] = "replacement-epoch".into(),
                                            "standing-admission" => body["standing"]["admission_reference"] = "replacement-admission".into(),
                                            "standing-deadline" => body["standing"]["deadline_ms"] = (body["standing"]["deadline_ms"].as_u64().unwrap() + 1).into(),
                                            _ => unreachable!(),
                                        }
                                        db.execute("DELETE FROM events WHERE scope_id=?1 AND kind='office_turn_startup'", [&chat]).unwrap();
                                        guard.store_mut().append_record(&chat, crate::engine::office_turn_startup::SNAPSHOT_KIND, &body.to_string()).unwrap();
                                        drop(guard);
                                        assert!(crate::engine::office_turn_startup::recorded_startup(&office, "synthetic original task").is_err(), "{case}: changed standing accepted for recovery routing");
                                        use gaugedesk_harness::TurnAccess;
                                        assert!(office.recorded_access().check_current().is_err(), "{case}: changed standing accepted for native observation");
                                    },
                                    "lineage-v1" | "lineage-loss" | "lineage-parent" | "lineage-divergence" => {
                                        let mut guard = wb.lock_unpoisoned();
                                        let mut body: serde_json::Value = serde_json::from_str(&guard.store_ref().records(&chat, crate::engine::office_turn_startup::SNAPSHOT_KIND).unwrap()[0]).unwrap();
                                        assert_eq!(body["revision"], "office-turn-startup/v3");
                                        match case {
                                            "lineage-v1" => body["revision"] = "office-turn-startup/v1".into(),
                                            "lineage-loss" => { body.as_object_mut().unwrap().remove("lineage"); },
                                            "lineage-parent" => body["lineage"]["parent_branch_id"] = serde_json::Value::Null,
                                            "lineage-divergence" => body["lineage"]["branch_point_manifest_hash"] = "changed".into(),
                                            _ => unreachable!(),
                                        }
                                        db.execute("DELETE FROM events WHERE scope_id=?1 AND kind='office_turn_startup'", [&chat]).unwrap();
                                        guard.store_mut().append_record(&chat, crate::engine::office_turn_startup::SNAPSHOT_KIND, &body.to_string()).unwrap();
                                    },
                                    "duplicate" => {
                                        let mut guard = wb.lock_unpoisoned();
                                        let body = guard.store_ref().records(&chat, crate::engine::office_turn_startup::SNAPSHOT_KIND).unwrap().pop().unwrap();
                                        guard.store_mut().append_record(&chat, crate::engine::office_turn_startup::SNAPSHOT_KIND, &body).unwrap();
                                    },
                                    "unreadable" => { db.execute("UPDATE events SET payload='gwenc:1:damaged' WHERE scope_id=?1 AND kind='office_turn_startup'", [&chat]).unwrap(); },
                                    "snapshot-loss" => { db.execute("DELETE FROM events WHERE kind='office_turn_startup' AND scope_id=?1", [&chat]).unwrap(); },
                                    "phase-command-loss" => {
                                        db.execute("DELETE FROM commands WHERE scope_id=?1", [&phase]).unwrap();
                                        use gaugedesk_harness::TurnAccess;
                                        assert!(office.recorded_access().check_current().is_err(), "missing startup command allowed native observation");
                                    },
                                    "phase-input-change" => {
                                        let mut guard = wb.lock_unpoisoned();
                                        let mut body: serde_json::Value = serde_json::from_str(&guard.store_ref().records(&chat, crate::engine::office_turn_startup::SNAPSHOT_KIND).unwrap()[0]).unwrap();
                                        body["task"] = "substituted retained startup input".into();
                                        db.execute("DELETE FROM events WHERE scope_id=?1 AND kind='office_turn_startup'", [&chat]).unwrap();
                                        guard.store_mut().append_record(&chat, crate::engine::office_turn_startup::SNAPSHOT_KIND, &body.to_string()).unwrap();
                                        drop(guard);
                                        use gaugedesk_harness::TurnAccess;
                                        assert!(office.recorded_access().check_current().is_err(), "changed startup phase allowed native observation");
                                    },
                                    "prefix-loss" => { db.execute("DELETE FROM events WHERE scope_id=?1", [&phase]).unwrap(); },
                                    "receipt-loss" => { db.execute("DELETE FROM command_receipts WHERE scope_id=?1", [&phase]).unwrap(); },
                                    "orphan" => { db.execute("DELETE FROM events WHERE scope_id=?1", [&phase]).unwrap(); db.execute("DELETE FROM command_receipts WHERE scope_id=?1", [&phase]).unwrap(); },
                                    "retained-loss" => { snapshot = unbound_original_fork.clone(); db.execute("DELETE FROM events WHERE scope_id=?1", [&phase]).unwrap(); db.execute("DELETE FROM command_receipts WHERE scope_id=?1", [&phase]).unwrap(); db.execute("DELETE FROM events WHERE scope_id=?1 AND kind='office_turn_startup'", [&chat]).unwrap(); },
                                    "process-duplicate" => {
                                        let mut guard = wb.lock_unpoisoned();
                                        let body = guard.store_ref().records(&chat, crate::target_change_set::TURN_PROCESS_DECLARATION_KIND).unwrap().pop().unwrap();
                                        guard.store_mut().append_record(&chat, crate::target_change_set::TURN_PROCESS_DECLARATION_KIND, &body).unwrap();
                                    },
                                    "process-loss" => { db.execute("DELETE FROM events WHERE kind=?1 AND scope_id=?2", rusqlite::params![crate::target_change_set::TURN_PROCESS_DECLARATION_KIND, chat]).unwrap(); },
                                    "process-receipt-loss" => { db.execute("DELETE FROM command_receipts WHERE scope_id=?1", [&process_phase]).unwrap(); },
                                    "process-orphan" => { db.execute("DELETE FROM events WHERE scope_id=?1", [&process_phase]).unwrap(); db.execute("DELETE FROM command_receipts WHERE scope_id=?1", [&process_phase]).unwrap(); },
                                    "completed" => {
                                        let mut guard = wb.lock_unpoisoned();
                                        let (_, basis) = guard.store_ref().read_for_dispatch(&[&chat], |_| Ok(())).unwrap();
                                        guard.store_mut().with_dispatch_record_admission(&basis, |writer| writer.commit_claimed(
                                            original.command_id(), original.scope(), original.key(), original.snapshot(),
                                            &[gaugedesk_store::CommandRecordFact { scope_id: chat.clone(), kind: "synthetic-completion".into(), payload: "completed".into() }],
                                        )).unwrap().unwrap();
                                    },
                                    "restored" => {
                                        membership(&wb, "alice", crate::org::MembershipStatus::Deprovisioned);
                                        membership(&wb, "alice", crate::org::MembershipStatus::Active);
                                    },
                                    "replay" => {
                                        let later = engagement.commit_turn("later independently submitted work").unwrap().unwrap().0;
                                        assert_ne!(later, first.native_base.base_cut());
                                        engagement.write_file(&pending_path, "unsubmitted replacement").unwrap();
                                        crate::resource_store::record_reads(wb.lock_unpoisoned().store_mut(), &chat,
                                            &[gaugedesk_core::resource::ResourceId::new("later-read")]).unwrap();
                                        snapshot.as_mut().unwrap().process_declaration.as_mut().unwrap().executable = "changed fresh process".into();
                                    },
                                    "changed-input" => {},
                                    _ => unreachable!(),
                                }
                                let raw_events = || {
                                    db.prepare("SELECT position,kind,payload FROM events WHERE scope_id=?1 ORDER BY position").unwrap()
                                        .query_map([&chat], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))
                                        .unwrap().collect::<Result<Vec<_>, _>>().unwrap()
                                };
                                let mut before_retry = raw_events();
                                let head = engagement.observe().unwrap().recorded_cut;
                                let admit = if case == "retained-loss" { crate::engine::office_turn_startup::admit_retained_startup } else { crate::engine::office_turn_startup::admit_startup };
                                let retry = admit(&office, engagement.as_ref(), scope,
                                    if case == "changed-input" { "substituted original task" } else { "synthetic original task" }, &mut snapshot);
                                if case == "replay" {
                                    let retry = retry.unwrap();
                                    assert_eq!(retry.user_entry_id, first.user_entry_id);
                                    assert_eq!(retry.native_base.base_cut(), first.native_base.base_cut());
                                    assert_eq!(retry.reads_before, ["original-read"]);
                                    assert_eq!(retry.reads_before, first.reads_before);
                                    assert_eq!(snapshot, original_fork);
                                    assert_eq!(engagement.read_file(&pending_path).unwrap(), "unsubmitted replacement");
                                    assert!(original_events.len() < before_retry.len());
                                    assert_eq!(raw_events(), before_retry);
                                    assert_eq!(engagement.observe().unwrap().recorded_cut, head);
                                    let model_called = Arc::new(AtomicBool::new(false));
                                    let (worktree, sender, mode) = wb.lock_unpoisoned().engagement_turn_location(&chat).unwrap();
                                    let created = Arc::new(AtomicBool::new(false));
                                    let probe = StartupProbe { wb: wb.clone(), chat: chat.clone(), original: original.clone(), reached: model_called.clone(), created: created.clone(), access: None, revoke: false };
                                    let engine_retry = crate::engine::run_engagement_turn(&wb, &chat, &worktree, &sender,
                                        crate::engine::EngagementTurnInput {
                                            task: "synthetic original task", images: &[], mode,
                                            authenticated_actor: Some(captured.actor()), authenticated_context: Some(&captured),
                                            client_build: Some(&Default::default()), local_operator: false, contribution_by: None,
                                            account_scope: "account", tenant_scope: ORG_SCOPE, account_bearer: Some(ALICE),
                                            runtime_command_id: None, original_http_command: Some(&original), harness_factory: Some(crate::harness_select::TurnHarnessFactory::Custom(Arc::new(probe))),
                                        });
                                    assert!(engine_retry.is_err(), "recovery without sealed original runtime preparation succeeded");
                                    assert!(!model_called.load(Ordering::Acquire));
                                    assert!(!created.load(Ordering::Acquire), "recovered task created a fresh runtime harness");
                                    // The engine may admit its empty answer phase before startup;
                                    // it creates no second startup/process phase or model execution.
                                    before_retry = raw_events();

                                } else { assert!(retry.is_err(), "incomplete or unauthorized original startup replayed: {case}"); }
                                assert_eq!(engagement.observe().unwrap().recorded_cut, head);
                                let guard = wb.lock_unpoisoned();
                                assert_eq!(raw_events(), before_retry);
                                assert_eq!(guard.store_ref().pending_command_matches(original.command_id(), original.scope(), original.key(), original.snapshot()).unwrap(), case != "completed");
                                reached.store(true, Ordering::Release);
                                return StatusCode::FORBIDDEN;
                            }
                            let guard = wb.lock_unpoisoned();
                            assert!(guard
                                .store_ref()
                                .pending_command_matches(
                                    original.command_id(),
                                    original.scope(),
                                    original.key(),
                                    original.snapshot()
                                )
                                .unwrap());
                            if matches!(case, "revoked" | "wrong-chat" | "write-failure") {
                                assert!(result.is_err());
                                assert_eq!(
                                    guard.store_ref().retained_events(&chat).unwrap(),
                                    before
                                );
                                assert!(guard
                                    .store_ref()
                                    .records("substituted-chat", "transcript")
                                    .unwrap()
                                    .is_empty());
                            } else {
                                let startup = result.unwrap();
                                assert_eq!(
                                    guard.store_ref().fold::<RunState>(&chat).unwrap().phase,
                                    RunPhase::Running
                                );
                                let input = guard
                                    .store_ref()
                                    .retained_events(&chat)
                                    .unwrap()
                                    .into_iter()
                                    .find(|row| row.0 == startup.user_entry_id)
                                    .unwrap();
                                assert_eq!(input.1, "transcript");
                                assert_eq!(
                                    input.2,
                                    crate::stream::ServerEvent::User {
                                        text: "synthetic original task".into()
                                    }
                                    .to_json()
                                );
                                assert_eq!(
                                    guard
                                        .store_ref()
                                        .records(&chat, "office_turn_base")
                                        .unwrap(),
                                    [startup.native_base.base_cut()]
                                );
                                let declarations = guard
                                    .store_ref()
                                    .records(
                                        &chat,
                                        crate::target_change_set::TURN_PROCESS_DECLARATION_KIND,
                                    )
                                    .unwrap();
                                assert_eq!(declarations.len(), 1);
                                let declared: crate::target_change_set::TurnProcessDeclaration =
                                    serde_json::from_str(&declarations[0]).unwrap();
                                assert_eq!(
                                    declared.run_ref,
                                    format!("{chat}:{}", startup.user_entry_id)
                                );
                                assert_eq!(
                                    declared,
                                    snapshot.unwrap().process_declaration.unwrap()
                                );
                                assert!(
                                    engagement
                                        .recorded_streamed_file_hash(
                                            &pending_path,
                                            startup.native_base.base_cut(),
                                            &hex::encode(sha2::Sha256::digest(
                                                b"unsubmitted original edit"
                                            )),
                                            b"unsubmitted original edit".len() as u64,
                                        )
                                        .unwrap()
                                        .is_none(),
                                    "pending bytes entered the original recorded base"
                                );
                                assert_eq!(
                                    engagement.read_file(&pending_path).unwrap(),
                                    "unsubmitted original edit"
                                );
                            }
                            reached.store(true, Ordering::Release);
                            StatusCode::FORBIDDEN
                        }
                    },
                ),
            )
            .layer(axum::middleware::from_fn_with_state(
                wb.clone(),
                crate::command_idempotency::guard,
            ))
            .with_state(wb.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/chats/{chat}/task"))
                    .header("idempotency-key", "production-startup")
                    .body(Body::from("synthetic original task"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(reached.load(Ordering::Acquire));
    }
}
