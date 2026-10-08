//! DR0444: actual HTTP requester/claim coordinates at original Office startup.
//! No runtime/provider outcome, grant or requester revocation history is invented.
use super::*;
use crate::engine::office_turn_startup::{self, OfficeTurnContext};
use crate::stream::{ServerEvent, TaskAuthor};
use axum::http::{HeaderMap, Method};

const TASK: &str = "synthetic original addressed Office task";
const KEY: &str = "office-requester-correlation-control";

#[tokio::test]
async fn office_original_http_requester_is_retained_with_exact_user_and_attempt_positions() {
    for scenario in ["replay", "missing-user-row", "legacy-v3"] {
        let root = tempfile::tempdir().unwrap();
        let (wb, admission_app, _, _) = fixture(root.path());
        let hub = hub().await;
        install(&wb, &hub);
        let staff_admission = admit(&admission_app, ALICE).await;
        let requester_admission = admit(&admission_app, BOB).await;
        let chat = chat(&wb);
        // The actual authenticated requester is Bob; Alice independently holds
        // the original Office runtime/staff standing. They are not aliases.
        let staff_context = context(&wb, &staff_admission);
        let observed = Arc::new(AtomicBool::new(false));
        let reached = observed.clone();
        let app = Router::new()
            .route(
                "/chats/{id}/task",
                post(
                    move |State(wb): State<SharedWorkbench>,
                          Path(chat): Path<String>,
                          headers: HeaderMap,
                          Extension(original): Extension<
                        crate::command_idempotency::ClaimedHttpCommand,
                    >,
                          Extension(attempt): Extension<
                        crate::command_idempotency::TaskAttempt,
                    >| {
                        let staff_context = staff_context.clone();
                        let reached = reached.clone();
                        async move {
                            let path = format!("/chats/{chat}/task");
                            let author = crate::engine::verified_task_author(
                                &mut wb.lock_unpoisoned(),
                                &headers,
                                &Method::POST,
                                &path,
                            )
                            .expect("actual current HTTP Home/requester proof");
                            let raw_key = crate::command_idempotency::caller_idempotency_key(&headers)
                                .expect("actual caller request key");
                            assert_eq!(raw_key, KEY);
                            assert_eq!(author.actor_id, "bob");
                            assert_eq!(staff_context.actor().as_str(), "alice");
                            let authority = OfficeTaskAuthority::for_turn(
                                &wb,
                                &chat,
                                Some(&staff_context),
                                Some(&Default::default()),
                                None,
                                Some(ALICE),
                            )
                            .unwrap()
                            .unwrap();
                            let (engagement, mut fork) = {
                                let guard = wb.lock_unpoisoned();
                                let engagement = guard.engagements[&chat].boxed_clone();
                                let process = guard
                                    .prepare_turn_process_declaration(
                                        &chat,
                                        "correlation qualification",
                                        None,
                                        0,
                                        None,
                                    )
                                    .unwrap();
                                let fork = guard
                                    .turn_fork_snapshot(&chat, None, None, process)
                                    .unwrap();
                                (engagement, fork)
                            };
                            let office = OfficeTurnContext {
                                wb: &wb,
                                authority: &authority,
                                original: &original,
                            };
                            assert_eq!(attempt.command_id, original.command_id());
                            assert_eq!(
                                original.key(),
                                crate::command_idempotency::office_retry_key(&raw_key)
                            );
                            let command_body: serde_json::Value =
                                serde_json::from_str(original.snapshot()).unwrap();
                            assert_eq!(command_body["body_sha256"], attempt.body_digest);
                            let first = if scenario == "legacy-v3" {
                                office_turn_startup::admit_startup(
                                    &office,
                                    engagement.as_ref(),
                                    &chat,
                                    TASK,
                                    &mut fork,
                                )
                            } else {
                                office_turn_startup::test_admit_startup_with_client(
                                    &office,
                                    engagement.as_ref(),
                                    &chat,
                                    TASK,
                                    &mut fork,
                                    &author,
                                    &attempt,
                                    raw_key.as_str(),
                                    None,
                                    false,
                                )
                            }
                            .expect("original governed startup");
                            let user_position = first.user_entry_id;
                            let before = wb
                                .lock_unpoisoned()
                                .store_ref()
                                .retained_events(&chat)
                                .unwrap();
                            let user = before
                                .iter()
                                .find(|event| event.0 == user_position)
                                .unwrap();
                            assert_eq!(user.1, "transcript");
                            let expected = ServerEvent::User {
                                text: TASK.into(),
                                client_request_id: (scenario != "legacy-v3")
                                    .then(|| raw_key.as_str().into()),
                                chat_id: (scenario != "legacy-v3").then(|| chat.clone()),
                                home_id: (scenario != "legacy-v3").then(|| author.home_id.clone()),
                                actor_id: (scenario != "legacy-v3")
                                    .then(|| author.actor_id.clone()),
                            }
                            .to_json();
                            assert_eq!(user.2, expected);
                            let snapshot = wb
                                .lock_unpoisoned()
                                .store_ref()
                                .records(&chat, office_turn_startup::SNAPSHOT_KIND)
                                .unwrap();
                            assert_eq!(snapshot.len(), 1);
                            let value: serde_json::Value =
                                serde_json::from_str(&snapshot[0]).unwrap();
                            let companions = wb
                                .lock_unpoisoned()
                                .store_ref()
                                .records(
                                    &crate::engine::task_attempt_scope(original.command_id()),
                                    crate::engine::TASK_CORRELATION_ATTEMPT_KIND,
                                )
                                .unwrap();
                            if scenario == "legacy-v3" {
                                assert_eq!(value["revision"], "office-turn-startup/v3");
                                assert!(
                                    value.get("client").is_none(),
                                    "v3 None encoding must remain byte-compatible"
                                );
                                assert!(companions.is_empty());
                                let old: FrozenV3Startup = serde_json::from_str(&snapshot[0])
                                    .expect("old v3 codec reads actual retained snapshot");
                                assert_eq!(serde_json::to_string(&old).unwrap(), snapshot[0],
                                    "original v3 field order and nested encoding unchanged");
                            } else {
                                assert_eq!(value["revision"], "office-turn-startup/v4");
                                assert!(serde_json::from_str::<FrozenV3Startup>(&snapshot[0]).is_err(),
                                    "strict old codec does not accept a v4 client field");
                                assert_eq!(value["actor"], "alice");
                                assert_eq!(value["client"]["actor_id"], "bob");
                                assert_eq!(value["client"]["home_id"], author.home_id);
                                assert_eq!(value["client"]["chat_id"], chat);
                                assert_eq!(value["client"]["client_request_id"], raw_key.as_str());
                                assert_eq!(companions.len(), 1);
                                let companion: serde_json::Value =
                                    serde_json::from_str(&companions[0]).unwrap();
                                assert_eq!(companion["user_entry_id"], user_position);
                                assert_eq!(companion["chat_id"], chat);
                                assert_eq!(companion["command_id"], attempt.command_id);
                                assert_eq!(companion["body_digest"], attempt.body_digest);
                                assert!(user_position > 0);
                                assert!(
                                    before.iter().any(|e| e.0 > user_position),
                                    "User position is not the later process suffix"
                                );
                                // A User/companion is not settlement: no synthesized
                                // summary or successful runtime outcome is admitted.
                                assert!(crate::engine::task_correlation(
                                    wb.lock_unpoisoned().store_ref(),
                                    &chat,
                                    raw_key.as_str(),
                                    &author,
                                    Some(&attempt),
                                )
                                .is_none());
                            }
                            let retried = office_turn_startup::test_admit_startup_with_client(
                                &office,
                                engagement.as_ref(),
                                &chat,
                                TASK,
                                &mut fork,
                                &author,
                                &attempt,
                                raw_key.as_str(),
                                None,
                                true,
                            )
                            .expect("exact original retry");
                            assert_eq!(retried.user_entry_id, user_position);
                            assert_eq!(
                                wb.lock_unpoisoned()
                                    .store_ref()
                                    .retained_events(&chat)
                                    .unwrap(),
                                before
                            );
                            assert_eq!(
                                wb.lock_unpoisoned()
                                    .store_ref()
                                    .records(&chat, office_turn_startup::SNAPSHOT_KIND,)
                                    .unwrap(),
                                snapshot,
                                "legacy/current snapshot bytes cannot be rebound on retry"
                            );
                            if scenario != "legacy-v3" {
                                let wrong_author = TaskAuthor {
                                    actor_id: "alice".into(),
                                    ..author.clone()
                                };
                                let changed_attempt = crate::command_idempotency::TaskAttempt {
                                    body_digest: "0".repeat(64),
                                    ..attempt.clone()
                                };
                                for (candidate_author, candidate_attempt, candidate_key) in [
                                    (&wrong_author, &attempt, raw_key.as_str()),
                                    (&author, &changed_attempt, raw_key.as_str()),
                                    (&author, &attempt, "substituted-request-key"),
                                ] {
                                    assert!(office_turn_startup::test_admit_startup_with_client(
                                        &office,
                                        engagement.as_ref(),
                                        &chat,
                                        TASK,
                                        &mut fork,
                                        candidate_author,
                                        candidate_attempt,
                                        candidate_key,
                                        None,
                                        true,
                                    )
                                    .is_err());
                                    assert_eq!(
                                        wb.lock_unpoisoned()
                                            .store_ref()
                                            .retained_events(&chat)
                                            .unwrap(),
                                        before
                                    );
                                }
                            }
                            if scenario == "missing-user-row" {
                                let db = rusqlite::Connection::open(
                                    wb.lock_unpoisoned().store_ref().path(),
                                )
                                .unwrap();
                                assert_eq!(
                                    db.execute(
                                        "DELETE FROM events WHERE scope_id=?1 AND position=?2",
                                        rusqlite::params![chat, user_position]
                                    )
                                    .unwrap(),
                                    1
                                );
                                let erased = wb
                                    .lock_unpoisoned()
                                    .store_ref()
                                    .retained_events(&chat)
                                    .unwrap();
                                assert!(
                                    office_turn_startup::test_admit_startup_with_client(
                                        &office,
                                        engagement.as_ref(),
                                        &chat,
                                        TASK,
                                        &mut fork,
                                        &author,
                                        &attempt,
                                        raw_key.as_str(),
                                        None,
                                        true,
                                    )
                                    .is_err(),
                                    "surviving companion cannot reconstruct a missing/corrupt User row"
                                );
                                assert_eq!(
                                    wb.lock_unpoisoned()
                                        .store_ref()
                                        .retained_events(&chat)
                                        .unwrap(),
                                    erased
                                );
                                assert_eq!(
                                    wb.lock_unpoisoned()
                                        .store_ref()
                                        .records(
                                            &crate::engine::task_attempt_scope(
                                                original.command_id()
                                            ),
                                            crate::engine::TASK_CORRELATION_ATTEMPT_KIND,
                                        )
                                        .unwrap(),
                                    companions
                                );
                            }
                            if scenario == "replay" {
                                // Fault injection uses the owning failed-attempt
                                // admission, not a fabricated provider receipt or
                                // directly appended summary.
                                office_turn_startup::admit_failed_attempt(
                                    &office,
                                    &first,
                                    &chat,
                                    "qualification injected transport failure without runtime receipt",
                                )
                                .expect("guarded original Office failure admission");
                                let guard = wb.lock_unpoisoned();
                                let summaries = guard.store_ref().records(
                                    &chat, crate::turn_summary::TURN_SUMMARY_KIND,
                                ).unwrap();
                                assert_eq!(summaries.len(), 1);
                                let summary: crate::turn_summary::TurnSummary =
                                    serde_json::from_str(&summaries[0]).unwrap();
                                assert_eq!(summary.user_entry_id, user_position);
                                assert!(matches!(summary.receipt_status,
                                    crate::turn_summary::ReceiptStatus::Failed));
                                assert_eq!(guard.store_ref().records(
                                    &chat, "office_turn_result_gap",
                                ).unwrap().len(), 1);
                                let correlation = crate::engine::task_correlation(
                                    guard.store_ref(), &chat, raw_key.as_str(), &author,
                                    Some(&attempt),
                                ).expect("owning summary repairs original requester attempt");
                                assert_eq!(correlation.actor_id, "bob");
                                assert_eq!(correlation.home_id, author.home_id);
                                assert_eq!(correlation.chat_id, chat);
                                assert_eq!(correlation.client_request_id, raw_key.as_str());
                                let wrong_author = TaskAuthor {
                                    actor_id: "alice".into(), ..author.clone()
                                };
                                let wrong_attempt = crate::command_idempotency::TaskAttempt {
                                    body_digest: "0".repeat(64), ..attempt.clone()
                                };
                                assert!(crate::engine::task_correlation(
                                    guard.store_ref(), &chat, raw_key.as_str(), &wrong_author,
                                    Some(&attempt),
                                ).is_none());
                                assert!(crate::engine::task_correlation(
                                    guard.store_ref(), &chat, raw_key.as_str(), &author,
                                    Some(&wrong_attempt),
                                ).is_none());
                                assert_eq!(guard.store_ref().records(
                                    &chat, office_turn_startup::SNAPSHOT_KIND,
                                ).unwrap(), snapshot);
                            }
                            reached.store(true, Ordering::Release);
                            StatusCode::NO_CONTENT
                        }
                    },
                ),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                wb.clone(),
                crate::command_idempotency::guard,
            ))
            .route_layer(axum::middleware::from_fn_with_state(
                wb.clone(),
                crate::office_home_admission::require_office_home_admission,
            ))
            .with_state(wb.clone());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/chats/{chat}/task"))
                    .header("authorization", format!("Bearer {BOB}"))
                    .header(
                        crate::home_admission::HOME_ADMISSION_HEADER,
                        requester_admission.clone(),
                    )
                    .header("idempotency-key", KEY)
                    .body(Body::from(
                        serde_json::json!({"prompt":TASK,"images":[]}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT, "{scenario}");
        assert!(
            observed.load(Ordering::Acquire),
            "{scenario}: actual admitted HTTP handler was not reached"
        );
        if scenario == "replay" {
            let before = wb
                .lock_unpoisoned()
                .store_ref()
                .retained_events(&chat)
                .unwrap();
            let snapshot_before = wb
                .lock_unpoisoned()
                .store_ref()
                .records(&chat, office_turn_startup::SNAPSHOT_KIND)
                .unwrap();
            // A duplicate must stop in the normal guard, not re-enter the
            // handler and manufacture another startup or summary.
            observed.store(false, Ordering::Release);
            let duplicate = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/chats/{chat}/task"))
                        .header("authorization", format!("Bearer {BOB}"))
                        .header(
                            crate::home_admission::HOME_ADMISSION_HEADER,
                            requester_admission,
                        )
                        .header("idempotency-key", KEY)
                        .body(Body::from(
                            serde_json::json!({"prompt":TASK,"images":[]}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(duplicate.status(), StatusCode::CONFLICT);
            let bytes = axum::body::to_bytes(duplicate.into_body(), 16384)
                .await
                .unwrap();
            let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                response["correlation"]["client_request_id"], KEY,
                "normal guard repairs with original raw caller key, not stored Office key"
            );
            assert_eq!(response["correlation"]["actor_id"], "bob");
            assert_eq!(response["correlation"]["chat_id"], chat);
            assert_eq!(response["correlation"]["outcome"], "settled");
            assert!(
                !observed.load(Ordering::Acquire),
                "duplicate handler ran again"
            );
            assert_eq!(
                wb.lock_unpoisoned()
                    .store_ref()
                    .retained_events(&chat)
                    .unwrap(),
                before
            );
            assert_eq!(
                wb.lock_unpoisoned()
                    .store_ref()
                    .records(&chat, office_turn_startup::SNAPSHOT_KIND)
                    .unwrap(),
                snapshot_before
            );
        }
    }
}

/// Exercise the actual producer route after the normal claim guard, isolating
/// its requester check from the earlier Home middleware check. The Office
/// extension is obtained from a genuine admitted staff context.
#[tokio::test]
async fn office_task_correlation_http_producer_refuses_missing_or_invalid_requester() {
    for invalid in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (wb, admission_app, _, _) = fixture(root.path());
        let hub = hub().await;
        install(&wb, &hub);
        let admission = admit(&admission_app, ALICE).await;
        let captured = context(&wb, &admission);
        let chat = chat(&wb);
        let before = wb
            .lock_unpoisoned()
            .store_ref()
            .retained_events(&chat)
            .unwrap();
        let app = Router::new()
            .route(
                "/chats/{id}/task",
                post(crate::engagement_routes::post_task),
            )
            .layer(Extension(captured))
            .layer(axum::middleware::from_fn_with_state(
                wb.clone(),
                crate::command_idempotency::guard,
            ))
            .with_state(wb.clone());
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/chats/{chat}/task"))
            .header("content-type", "application/json")
            .header("idempotency-key", KEY);
        if invalid {
            request = request
                .header("authorization", "Bearer invalid-requester")
                .header(
                    crate::home_admission::HOME_ADMISSION_HEADER,
                    "invalid-home-admission",
                );
        }
        let response = app
            .oneshot(
                request
                    .body(Body::from(
                        serde_json::json!({"prompt":TASK,"images":[]}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            body.as_ref(),
            b"office task requires verified HTTP requester"
        );
        assert_eq!(
            wb.lock_unpoisoned()
                .store_ref()
                .retained_events(&chat)
                .unwrap(),
            before
        );
        assert!(wb
            .lock_unpoisoned()
            .store_ref()
            .records(&chat, office_turn_startup::SNAPSHOT_KIND,)
            .unwrap()
            .is_empty());
        assert!(!crate::engine::turn_is_live(&chat));
    }
}

// Independently retained pre-client v3 codec layout, applied only to real
// admitted legacy payloads, never used to construct authority or history.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenV3Startup {
    revision: String,
    command: String,
    actor: String,
    standing: crate::engine::office_authority::OriginalOfficeTaskBinding,
    chat: String,
    task: String,
    base_cut: String,
    lineage: whipplescript_store::branches::BranchRow,
    phase: gaugedesk_core::run::RunPhase,
    reads_before: Vec<String>,
    fork: Option<crate::engine::TurnForkSnapshot>,
}

#[derive(Clone)]
struct StopBeforeRuntimeReceipt(Arc<AtomicBool>);
impl gaugedesk_harness::Harness for StopBeforeRuntimeReceipt {
    fn bind_workspace_payload_retention(
        &mut self,
        retention: Option<Arc<dyn gaugedesk_harness::WorkspacePayloadRetention>>,
    ) -> std::io::Result<()> {
        assert!(retention.is_some());
        Ok(())
    }
    fn bind_turn_access(
        &mut self,
        access: Option<Arc<dyn gaugedesk_harness::TurnAccess>>,
    ) -> std::io::Result<()> {
        access
            .expect("real Office access binding")
            .check_current()
            .map_err(std::io::Error::other)
    }
    fn prepare_runtime_turn(
        &mut self,
        _: &str,
        _: &[gaugedesk_harness::ImageContent],
    ) -> std::io::Result<gaugedesk_harness::RuntimeTurnPreparation> {
        self.0.store(true, Ordering::Release);
        Err(std::io::Error::other(
            "qualification stops after genuine engine startup before runtime receipt",
        ))
    }
    fn run_turn(
        &mut self,
        _: &dyn gaugedesk_harness::EgressGate,
        _: &str,
        _: &[gaugedesk_harness::ImageContent],
        _: &mut dyn FnMut(&gaugedesk_harness::Observation),
    ) -> std::io::Result<gaugedesk_harness::TurnOutcome> {
        panic!("qualification must not execute provider/runtime")
    }
}
impl gaugedesk_harness::HarnessFactory for StopBeforeRuntimeReceipt {
    fn kind(&self) -> &'static str {
        "scripted-fake"
    }
    fn create(
        &self,
        _: &gaugedesk_harness::HarnessSpec,
    ) -> std::io::Result<Box<dyn gaugedesk_harness::Harness>> {
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

#[tokio::test]
async fn office_task_correlation_normal_http_guard_engine_retains_raw_requester_identity() {
    let root = tempfile::tempdir().unwrap();
    let (wb, admission_app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let staff_admission = admit(&admission_app, ALICE).await;
    let requester_admission = admit(&admission_app, BOB).await;
    let staff = context(&wb, &staff_admission);
    let chat = chat(&wb);
    let prepared = Arc::new(AtomicBool::new(false));
    let observed = prepared.clone();
    let app = Router::new().route("/chats/{id}/task", post(move |
        State(wb): State<SharedWorkbench>, Path(chat): Path<String>, headers: HeaderMap,
        Extension(original): Extension<crate::command_idempotency::ClaimedHttpCommand>,
        Extension(attempt): Extension<crate::command_idempotency::TaskAttempt>,
    | {
        let staff = staff.clone(); let prepared = prepared.clone();
        async move {
            let raw = crate::command_idempotency::caller_idempotency_key(&headers).unwrap();
            assert_eq!(raw, KEY);
            assert_eq!(original.key(), crate::command_idempotency::office_retry_key(&raw));
            let author = crate::engine::verified_task_author(&mut wb.lock_unpoisoned(),
                &headers, &Method::POST, &format!("/chats/{chat}/task")).unwrap();
            assert_eq!(author.actor_id, "bob");
            assert_eq!(staff.actor().as_str(), "alice");
            let (worktree, sender, mode) = wb.lock_unpoisoned().engagement_turn_location(&chat).unwrap();
            let result = crate::engine::run_engagement_turn(&wb, &chat, &worktree, &sender,
                crate::engine::EngagementTurnInput {
                    task: TASK, images: &[], mode,
                    authenticated_actor: Some(staff.actor()), authenticated_context: Some(&staff),
                    client_build: Some(&Default::default()), local_operator: false, contribution_by: None,
                    account_scope: "account", tenant_scope: ORG_SCOPE, account_bearer: Some(ALICE),
                    client_request_id: Some(&raw), client_author: Some(&author), client_attempt: Some(&attempt),
                    runtime_command_id: None, original_http_command: Some(&original),
                    harness_factory: Some(crate::harness_select::TurnHarnessFactory::Custom(
                        Arc::new(StopBeforeRuntimeReceipt(prepared.clone())))),
                });
            assert!(matches!(result, Err(crate::engine::EngineError::Harness(ref error))
                if error.to_string() == "qualification stops after genuine engine startup before runtime receipt"), "{result:?}");
            assert!(prepared.load(Ordering::Acquire));
            let guard = wb.lock_unpoisoned();
            let events = guard.store_ref().retained_events(&chat).unwrap();
            let users: Vec<_> = events.iter().filter(|e| e.1 == "transcript")
                .filter_map(|e| serde_json::from_str::<serde_json::Value>(&e.2).ok().map(|v| (e.0, v)))
                .filter(|(_, v)| v["type"] == "user").collect();
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].1["client_request_id"], raw);
            assert_eq!(users[0].1["actor_id"], "bob");
            let snapshots = guard.store_ref().records(&chat, office_turn_startup::SNAPSHOT_KIND).unwrap();
            assert_eq!(snapshots.len(), 1);
            let snapshot: serde_json::Value = serde_json::from_str(&snapshots[0]).unwrap();
            assert_eq!(snapshot["client"]["client_request_id"], raw);
            assert_eq!(snapshot["actor"], "alice");
            let companions = guard.store_ref().records(
                &crate::engine::task_attempt_scope(original.command_id()),
                crate::engine::TASK_CORRELATION_ATTEMPT_KIND).unwrap();
            assert_eq!(companions.len(), 1);
            let companion: serde_json::Value = serde_json::from_str(&companions[0]).unwrap();
            assert_eq!(companion["user_entry_id"], users[0].0);
            assert_eq!(companion["command_id"], attempt.command_id);
            assert_eq!(companion["body_digest"], attempt.body_digest);
            assert!(crate::turn_summary::latest(guard.store_ref(), &chat).unwrap().is_none(),
                "preparation stop is not a witnessed runtime settlement");
            StatusCode::NO_CONTENT
        }
    })).route_layer(axum::middleware::from_fn_with_state(wb.clone(), crate::command_idempotency::guard))
       .route_layer(axum::middleware::from_fn_with_state(wb.clone(), crate::office_home_admission::require_office_home_admission))
       .with_state(wb.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/chats/{chat}/task"))
                .header("authorization", format!("Bearer {BOB}"))
                .header(
                    crate::home_admission::HOME_ADMISSION_HEADER,
                    requester_admission,
                )
                .header("idempotency-key", KEY)
                .body(Body::from(
                    serde_json::json!({"prompt":TASK,"images":[]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(observed.load(Ordering::Acquire));
}
