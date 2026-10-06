//! Most fixtures use owner-schema receipts. The joined recovery fixtures below
//! execute and reopen an actual native turn through a local scripted model driver.
use super::*;
use gaugedesk_core::{
    merge::{MergePhase, MergeState},
    run::{RunPhase, RunState},
};
use gaugedesk_harness::{
    Harness, HarnessFactory, HarnessSpec, Observation, RuntimePosition, RuntimeWorkspaceWitness,
    TurnOutcome, WorkspaceWriteWitness,
};
use sha2::{Digest, Sha256};

#[test]
fn office_output_preparation_preserves_unresolved_dependencies_without_publishing() {
    let mut store = gaugedesk_store::Store::open_in_memory().unwrap();
    let known = crate::resource_store::mint_context(
        &mut store,
        "chat",
        "input-owner",
        "input",
        "input-cut",
    )
    .unwrap();
    crate::resource_store::revoke_access(&mut store, "chat", &known.resource.id).unwrap();
    let before = store.retained_events("chat").unwrap();
    let prepared = crate::resource_store::prepare_office_output(
        &store,
        "chat",
        "output-owner",
        &[gaugedesk_harness::OutputFieldFlow {
            field: "assistant".into(),
            read_handles: vec![
                "resource:missing-input".into(),
                "future-data-bearing-handle".into(),
            ],
        }],
    )
    .unwrap();
    assert_eq!(store.retained_events("chat").unwrap(), before);
    let facts = prepared.facts_at("original-result-cut").unwrap();
    let output: gaugedesk_core::resource::ResourceRecord = serde_json::from_str(
        &facts
            .iter()
            .find(|fact| fact.kind == "resource")
            .unwrap()
            .payload,
    )
    .unwrap();
    for id in [
        known.resource.id.as_str(),
        "missing-input",
        "future-data-bearing-handle",
    ] {
        assert!(
            output
                .resource
                .provenance
                .contains(&gaugedesk_core::resource::ResourceId::new(id)),
            "{id}"
        );
    }
    assert!(output
        .stakeholders
        .contains(&gaugedesk_core::boundary::Authority::from("<unresolved>")));
    assert!(output
        .stakeholders
        .contains(&gaugedesk_core::boundary::Authority::from("input-owner")));
}
use whipplescript_kernel::host_protocol::{
    EventPosition, PolicyEpochRef, RuntimeEvidencePointer, TurnReceipt, TurnStatus, HOST_PROTOCOL,
};

#[derive(Clone)]
struct ResultProbe {
    wb: SharedWorkbench,
    chat: String,
    original: crate::command_idempotency::ClaimedHttpCommand,
    path: String,
    resource: String,
    case: &'static str,
    access: Option<Arc<dyn gaugedesk_harness::TurnAccess>>,
    payloads: Option<Arc<dyn gaugedesk_harness::WorkspacePayloadRetention>>,
    questions: Option<gaugedesk_harness::ExternalToolHandler>,
    captured_questions: Arc<std::sync::Mutex<Option<gaugedesk_harness::ExternalToolHandler>>>,
    filing: bool,
    enrolled: bool,
    interrupt_filing: bool,
    original_context: AuthenticatedActionContext,
    filer: Option<Arc<dyn gaugedesk_harness::TaskFiler>>,
    captured_filer: Arc<std::sync::Mutex<Option<Arc<dyn gaugedesk_harness::TaskFiler>>>>,
}
impl Harness for ResultProbe {
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

    fn bind_task_filer(&mut self, filer: Option<Arc<dyn gaugedesk_harness::TaskFiler>>) {
        *self.captured_filer.lock().unwrap() = filer.clone();
        self.filer = filer;
    }

    fn bind_external_tool_handler(
        &mut self,
        handler: Option<gaugedesk_harness::ExternalToolHandler>,
    ) {
        *self.captured_questions.lock().unwrap() = handler.clone();
        self.questions = handler;
    }

    fn bind_turn_access(
        &mut self,
        access: Option<Arc<dyn gaugedesk_harness::TurnAccess>>,
    ) -> std::io::Result<()> {
        self.access = access;
        Ok(())
    }
    fn bind_workspace_payload_retention(
        &mut self,
        retention: Option<Arc<dyn gaugedesk_harness::WorkspacePayloadRetention>>,
    ) -> std::io::Result<()> {
        self.payloads = retention;
        Ok(())
    }
    fn run_turn(
        &mut self,
        _: &dyn gaugedesk_harness::EgressGate,
        task: &str,
        _: &[gaugedesk_harness::ImageContent],
        _: &mut dyn FnMut(&Observation),
    ) -> std::io::Result<TurnOutcome> {
        self.access.as_ref().unwrap().check_current().unwrap();
        assert!(
            self.payloads.is_some(),
            "production shell must bind original payload custody"
        );
        assert!(task.contains("Synthetic production answer"));
        let guard = self.wb.lock_unpoisoned();
        let snapshots = guard
            .store_ref()
            .records(&self.chat, crate::engine::office_turn_answers::KIND)
            .unwrap();
        assert_eq!(snapshots.len(), 1);
        let snapshot: serde_json::Value = serde_json::from_str(&snapshots[0]).unwrap();
        assert_eq!(snapshot["command"], self.original.command_id());
        assert_eq!(snapshot["answers"].as_array().unwrap().len(), 1);
        drop(guard);
        if !self.filing {
            assert!(
                self.filer.is_none(),
                "outside context cannot flow to office tracker"
            );
        }
        if self.filing && !self.enrolled {
            let filer = self.filer.as_ref().expect("production task filer bound");
            assert!(filer
                .file_task("unenrolled", "Synthetic task", None)
                .is_err());
        }
        if self.filing
            && self.enrolled
            && matches!(self.case, "clean" | "failed" | "repeated-writes")
        {
            let filer = self.filer.as_ref().expect("production task filer bound");
            assert!(!filer.assignable_recipients().is_empty());
            let interrupted_item = if self.interrupt_filing {
                let database = self.wb.lock_unpoisoned().store_ref().path().to_owned();
                let fault = rusqlite::Connection::open(database).unwrap();
                fault.execute_batch("CREATE TRIGGER reject_office_filing_phase BEFORE INSERT ON events WHEN NEW.kind='office_task_filing' BEGIN SELECT RAISE(ABORT, 'synthetic publication interruption'); END;").unwrap();
                assert!(filer
                    .file_task(
                        "original-filing",
                        "Synthetic office task\nOriginal task details",
                        Some("me")
                    )
                    .is_err());
                let guard = self.wb.lock_unpoisoned();
                assert!(guard
                    .store_ref()
                    .records(&self.chat, "office_task_filing")
                    .unwrap()
                    .is_empty());
                self.original.verify_pending(guard.store_ref()).unwrap();
                let project = guard.library_project_of_chat(&self.chat).unwrap();
                let tasks = guard
                    .read_project_tracker_tasks(
                        &self.original_context,
                        &project,
                        crate::project_tracker::PROJECT_TASKS,
                    )
                    .unwrap();
                assert_eq!(tasks.backlog.issues.len(), 1);
                let item = tasks.backlog.issues[0].id.clone();
                drop(guard);
                assert!(filer
                    .file_task("original-filing", "Changed task", Some("me"))
                    .is_err());
                fault
                    .execute_batch("DROP TRIGGER reject_office_filing_phase;")
                    .unwrap();
                Some(item)
            } else {
                None
            };
            let first = filer
                .file_task(
                    "original-filing",
                    "Synthetic office task\nOriginal task details",
                    Some("me"),
                )
                .unwrap();
            if let Some(item) = interrupted_item {
                assert_eq!(first, item);
            }
            assert_eq!(
                first,
                filer
                    .file_task(
                        "original-filing",
                        "Synthetic office task\nOriginal task details",
                        Some("alice")
                    )
                    .unwrap()
            );
            assert!(filer
                .file_task("original-filing", "Changed task", Some("me"))
                .is_err());
            assert!(filer
                .file_task(
                    "original-filing",
                    "Synthetic office task\nOriginal task details",
                    None
                )
                .is_err());
            assert!(filer
                .file_task("outsider-filing", "Synthetic office task", Some("outsider"))
                .is_err());
        }
        let ask = self.questions.as_ref().expect("production callback bound");
        let request =
            serde_json::json!({"to":"alice", "questions":[{"prompt":"Synthetic staff question"}]});
        let first = ask("original-question", "ask_choices", &request).unwrap();
        assert_eq!(
            first,
            ask("original-question", "ask_choices", &request).unwrap()
        );
        assert!(self
            .original
            .verify_pending(self.wb.lock_unpoisoned().store_ref())
            .is_ok());
        let changed =
            serde_json::json!({"to":"alice", "questions":[{"prompt":"Changed question"}]});
        assert!(ask("original-question", "ask_choices", &changed).is_err());
        let alias = serde_json::json!({"to":"alice@example.test", "questions":[{"prompt":"Synthetic staff question"}]});
        assert!(ask("original-question", "ask_choices", &alias).is_err());
        let outsider =
            serde_json::json!({"to":"unknown", "questions":[{"prompt":"Synthetic question"}]});
        assert!(ask("outsider", "ask_choices", &outsider).is_err());
        membership(&self.wb, "recipient", crate::org::MembershipStatus::Active);
        let other = serde_json::json!({"to":"recipient@example.test", "questions":[{"prompt":"Synthetic colleague question"}]});
        assert!(ask("colleague", "ask_choices", &other).is_err());
        grant(&self.wb, "recipient", crate::library::RecordOp::Upsert);
        let colleague = ask("colleague", "ask_choices", &other).unwrap();
        assert!(ask("original-question", "ask_choices", &other).is_err());
        grant(&self.wb, "recipient", crate::library::RecordOp::Tombstone);
        assert!(ask("colleague", "ask_choices", &other).is_err());
        grant(&self.wb, "recipient", crate::library::RecordOp::Upsert);
        assert_eq!(colleague, ask("colleague", "ask_choices", &other).unwrap());
        let cards =
            crate::choice_prompt::list(self.wb.lock_unpoisoned().store_ref(), &self.chat).unwrap();
        assert_eq!(cards.len(), 2);
        assert!(cards
            .iter()
            .all(|card| card.asked_by.as_deref() == Some("alice")
                && card.origin_command_id.as_deref() == Some(self.original.command_id())));
        for (path, body) in [
            (&self.path[..], b"qualified original bytes".as_slice()),
            ("artifacts/report.txt", b"qualified local bytes".as_slice()),
        ] {
            self.payloads
                .as_ref()
                .unwrap()
                .retain(
                    &gaugedesk_harness::PreparedWorkspaceFile {
                        path: path.into(),
                        kind: "add".into(),
                        sha256: hex::encode(Sha256::digest(body)),
                        bytes: body.len() as u64,
                    },
                    body,
                )
                .unwrap();
        }
        let guard = self.wb.lock_unpoisoned();
        let engagement = &guard.engagements[&self.chat];
        engagement
            .write_file(&self.path, "qualified original bytes")
            .unwrap();
        engagement
            .write_file("artifacts/report.txt", "qualified local bytes")
            .unwrap();
        drop(guard);
        // The model has read this input; revocation cannot erase its output
        // dependency even though no further read of that resource is allowed.
        crate::resource_store::revoke_access(
            self.wb.lock_unpoisoned().store_mut(),
            &self.chat,
            &gaugedesk_core::resource::ResourceId::new(&self.resource),
        )
        .unwrap();
        if matches!(self.case, "revoked" | "question-revoked-restored") {
            membership(
                &self.wb,
                "alice",
                crate::org::MembershipStatus::Deprovisioned,
            );
        }
        if matches!(self.case, "revoked" | "question-revoked-restored") {
            if self.filing {
                let filer = self.filer.as_ref().unwrap();
                assert!(filer
                    .file_task("revoked-filing", "Synthetic task", None)
                    .is_err());
                assert!(filer.assignable_recipients().is_empty());
            }
            assert!(ask("original-question", "ask_choices", &request).is_err());
            assert!(ask("new-question", "ask_choices", &request).is_err());
            if self.case == "question-revoked-restored" {
                membership(&self.wb, "alice", crate::org::MembershipStatus::Active);
                if self.filing {
                    let filer = self.filer.as_ref().unwrap();
                    assert!(filer
                        .file_task("restored-filing", "Synthetic task", None)
                        .is_err());
                    assert!(filer.assignable_recipients().is_empty());
                }
                assert!(ask("original-question", "ask_choices", &request).is_err());
                assert!(ask("new-question", "ask_choices", &request).is_err());
            }
        }
        let receipt = TurnReceipt {
            protocol: HOST_PROTOCOL.into(),
            command_id: if self.case == "wrong-receipt" {
                "another-command".into()
            } else {
                self.original.command_id().into()
            },
            run_ref: "fixture-run".into(),
            instance_ref: "fixture-instance".into(),
            policy: PolicyEpochRef {
                epoch: 1,
                envelope_hash: "fixture-policy".into(),
                signer: "fixture-signer".into(),
                key_id: None,
            },
            terminal_position: EventPosition {
                instance_ref: "fixture-instance".into(),
                sequence: 3,
            },
            status: if self.case == "failed" {
                TurnStatus::Failed
            } else {
                TurnStatus::Completed
            },
            output_handle: Some("fixture-output".into()),
            usage_ref: "fixture-usage".into(),
            guarantee_report_ref: "fixture-guarantees".into(),
            workspace_cut_ref: Some("fixture-runtime-cut".into()),
        };
        let mut writes: Vec<_> = [
            (&self.path[..], b"qualified original bytes".as_slice()),
            ("artifacts/report.txt", b"qualified local bytes".as_slice()),
        ]
        .into_iter()
        .map(|(path, bytes)| WorkspaceWriteWitness {
            path: path.into(),
            kind: "add".into(),
            content_hash: hex::encode(Sha256::digest(bytes)),
            bytes: bytes.len() as u64,
        })
        .collect();
        if self.case == "repeated-writes" {
            writes.push(writes[0].clone());
        }
        if self.case == "creation-write-refused" {
            let database = self.wb.lock_unpoisoned().store_ref().path().to_owned();
            rusqlite::Connection::open(database).unwrap().execute_batch(
                "CREATE TRIGGER refuse_creation BEFORE INSERT ON events WHEN NEW.kind='office_turn_creation' BEGIN SELECT RAISE(ABORT,'synthetic creation retention failure'); END;"
            ).unwrap();
        }
        if self.case == "wrong-bytes" {
            writes[0].content_hash = hex::encode(Sha256::digest(b"different unwritten bytes"));
        }
        let witness = RuntimeWorkspaceWitness {
            receipt_json: serde_json::to_string(&receipt).unwrap(),
            writes,
            reads: vec!["fixture-input.txt".into()],
        };
        Ok(TurnOutcome {
            assistant_text: "final answer".into(),
            observations: vec![
                Observation {
                    kind: "assistant",
                    detail: "first narration".into(),
                    tool: None,
                },
                Observation {
                    kind: "egress",
                    detail: "workspace.write".into(),
                    tool: None,
                },
                Observation {
                    kind: "assistant",
                    detail: "final answer".into(),
                    tool: None,
                },
            ],
            runtime_workspace_witness: (self.case != "missing-witness").then_some(witness),
            runtime_evidence_pointers: vec![serde_json::to_string(
                &RuntimeEvidencePointer::TurnReceipt(receipt),
            )
            .unwrap()],
            output_flow_signature: vec![gaugedesk_harness::OutputFieldFlow {
                field: "assistant".into(),
                read_handles: vec![format!("resource:{}", self.resource)],
            }],
            runtime_start_position: Some(RuntimePosition {
                instance_ref: "fixture-instance".into(),
                sequence: 0,
            }),
            runtime_terminal_position: Some(RuntimePosition {
                instance_ref: "fixture-instance".into(),
                sequence: 3,
            }),
            error: (self.case == "failed").then(|| "qualified runtime failure".into()),
            ..Default::default()
        })
    }
}
impl HarnessFactory for ResultProbe {
    fn kind(&self) -> &'static str {
        // Exercise the actual native package policy and callback binding.
        // Execution and receipt provenance remain explicitly scripted fixtures.
        "whip"
    }
    fn create(&self, _: &HarnessSpec) -> std::io::Result<Box<dyn Harness>> {
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
async fn production_office_result_joins_original_http_receipt_native_review_and_ordered_transcript()
{
    exercise_original_office_result(false, false, false).await;
}

#[tokio::test]
async fn production_office_filing_retains_original_claim_and_native_receipt() {
    exercise_original_office_result(true, true, false).await;
}

#[tokio::test]
async fn production_office_filing_requires_explicit_protected_enrollment() {
    exercise_original_office_result(true, false, false).await;
}

#[tokio::test]
async fn production_office_filing_recovers_original_native_item_after_product_publication_failure()
{
    exercise_original_office_result(true, true, true).await;
}

async fn exercise_original_office_result(
    filing_enabled: bool,
    enrolled: bool,
    interrupt_filing: bool,
) {
    for case in [
        "clean",
        "failed",
        "revoked",
        "question-revoked-restored",
        "wrong-receipt",
        "missing-witness",
        "wrong-bytes",
        "repeated-writes",
        "creation-write-refused",
    ] {
        if interrupt_filing && case != "clean" {
            continue;
        }
        let root = tempfile::tempdir().unwrap();
        let (wb, admission_app, _, _) = fixture(root.path());
        let hub = hub().await;
        install(&wb, &hub);
        let admission = admit(&admission_app, ALICE).await;
        let chat = chat(&wb);
        let captured = context(&wb, &admission);
        // Explicit fixture enrollment happens before the submitted task. The
        // production office callback may only open these existing stores.
        if filing_enabled && enrolled {
            let guard = wb.lock_unpoisoned();
            let project = guard.library_project_of_chat(&chat).unwrap();
            let (tracker, _, _, _) = guard
                .prepare_project_tracker_recipients(
                    &captured,
                    &project,
                    crate::project_tracker::PROJECT_TASKS,
                )
                .unwrap();
            let key = guard
                .workflow_key(&project, &tracker.workspace_id, true)
                .unwrap();
            let protection =
                gaugedesk_workspace::WorkflowProtection::new(&tracker.workspace_id, key).unwrap();
            guard
                .workflow_storage(&tracker.workspace_id)
                .unwrap()
                .initialize_protected(&protection)
                .unwrap();
        }
        let (previous, resource) = {
            let mut guard = wb.lock_unpoisoned();
            let input_owner = captured.actor().as_str().to_owned();
            let earlier_owner = if filing_enabled {
                input_owner.as_str()
            } else {
                "earlier-owner"
            };
            let current_owner = if filing_enabled {
                input_owner.as_str()
            } else {
                "current-owner"
            };
            let previous = crate::resource_store::mint_context(
                guard.store_mut(),
                &chat,
                earlier_owner,
                "earlier-input",
                "earlier-cut",
            )
            .unwrap()
            .resource
            .id;
            crate::resource_store::record_reads(
                guard.store_mut(),
                &chat,
                std::slice::from_ref(&previous),
            )
            .unwrap();
            crate::resource_store::tombstone(guard.store_mut(), &chat, &previous).unwrap();
            let current = crate::resource_store::mint_context(
                guard.store_mut(),
                &chat,
                current_owner,
                "current-input",
                "current-cut",
            )
            .unwrap()
            .resource
            .id;
            (previous.as_str().to_owned(), current.as_str().to_owned())
        };
        {
            let mut guard = wb.lock_unpoisoned();
            let question = guard
                .ask_question(&chat, "Synthetic production question", &[], None, false)
                .unwrap();
            guard
                .answer_question(&chat, &question, "Synthetic production answer", "alice")
                .unwrap();
        }
        let app = Router::new().route("/chats/{id}/task", post(move |
            State(wb): State<SharedWorkbench>, Path(chat): Path<String>,
            axum::extract::Extension(original): axum::extract::Extension<crate::command_idempotency::ClaimedHttpCommand>| {
            let captured = captured.clone();
            let resource = resource.clone(); let previous = previous.clone();
            async move {
                let (engagement, path, pending) = {
                    let guard = wb.lock_unpoisoned();
                    let engagement = guard.engagements[&chat].boxed_clone();
                    let prefix = guard.engagement_context_target_root(&chat, None).unwrap().unwrap_or_default();
                    let path = if prefix.is_empty() { "result.txt".into() } else { format!("{prefix}/result.txt") };
                    let pending = if prefix.is_empty() { "pending.txt".into() } else { format!("{prefix}/pending.txt") };
                    engagement.write_file(&pending, "never submitted").unwrap();
                    (engagement, path, pending)
                };
                let (worktree, sender, mode) = wb.lock_unpoisoned().engagement_turn_location(&chat).unwrap();
                let captured_questions = Arc::new(std::sync::Mutex::new(None));
                let captured_filer = Arc::new(std::sync::Mutex::new(None));
                let probe = ResultProbe { wb: wb.clone(), chat: chat.clone(), original: original.clone(), path: path.clone(), resource: resource.clone(), case, access: None, payloads: None, questions: None, captured_questions: captured_questions.clone(), filer: None, captured_filer: captured_filer.clone(), filing: filing_enabled, enrolled, interrupt_filing, original_context: captured.clone() };
                let result = crate::engine::run_engagement_turn(&wb, &chat, &worktree, &sender, crate::engine::EngagementTurnInput {
                    task: "synthetic original task", images: &[], mode,
                    authenticated_actor: Some(captured.actor()), authenticated_context: Some(&captured),
                    client_build: Some(&Default::default()), local_operator: false, contribution_by: None,
                    account_scope: "account", tenant_scope: ORG_SCOPE, account_bearer: Some(ALICE),
                    runtime_command_id: None, original_http_command: Some(&original), harness_factory: Some(crate::harness_select::TurnHarnessFactory::Custom(Arc::new(probe))),
                });
                if matches!(case, "clean" | "failed" | "repeated-writes") {
                    if filing_enabled {
                    let filer = captured_filer.lock().unwrap().clone().unwrap();
                    assert!(filer.file_task("original-filing", "Synthetic office task\nOriginal task details", Some("me")).is_err());
                    assert!(filer.file_task("late-filing", "Late task", None).is_err());
                    assert!(filer.assignable_recipients().is_empty());
                    }
                    let callback = captured_questions.lock().unwrap().clone().unwrap();
                    let request = serde_json::json!({"to":"alice", "questions":[{"prompt":"Synthetic staff question"}]});
                    assert!(callback("original-question", "ask_choices", &request).is_err());
                    assert!(callback("late-question", "ask_choices", &request).is_err());
                }
                let mut guard = wb.lock_unpoisoned();
                assert_eq!(crate::choice_prompt::list(guard.store_ref(), &chat).unwrap().len(), 2);
                if matches!(case, "clean" | "failed" | "repeated-writes") {
                    let result = result.unwrap();
                    assert_eq!(result.run_phase, if case == "failed" { RunPhase::Failed } else { RunPhase::Completed });
                    assert_eq!(result.merge_phase, MergePhase::Advanced);
                    assert_eq!(guard.store_ref().fold::<RunState>(&chat).unwrap().phase, result.run_phase);
                    assert_eq!(guard.store_ref().fold::<MergeState>(&chat).unwrap().phase, result.merge_phase);
                    let cut = result.commit.unwrap();
                    assert!(result.diff.contains(&path)); assert!(!result.diff.contains(&pending)); assert!(!result.diff.contains("artifacts/report.txt"));
                    assert!(engagement.recorded_streamed_file_hash(&pending, &cut, &hex::encode(Sha256::digest(b"never submitted")), 15).unwrap().is_none());
                    assert_eq!(guard.store_ref().command(original.command_id()).unwrap().unwrap().status, "applied");
                    let receipts: i64 = rusqlite::Connection::open(guard.store_ref().path()).unwrap().query_row(
                        "SELECT COUNT(*) FROM command_receipts r JOIN commands c ON c.scope_id=r.scope_id AND c.idempotency_key=r.command_key WHERE r.scope_id=?1 AND r.command_key=?2 AND c.command_id=?3 AND c.snapshot_json=?4",
                        rusqlite::params![original.scope(), original.key(), original.command_id(), original.snapshot()], |row| row.get(0)).unwrap();
                    assert_eq!(receipts, 1);
                    let boundaries = guard.store_ref().records(&chat, crate::engine::TURN_BOUNDARY_KIND).unwrap(); assert_eq!(boundaries.len(), 1);
                    let boundary: crate::engine::TurnBoundaryRecord = serde_json::from_str(&boundaries[0]).unwrap();
                    let rows = guard.store_ref().retained_events(&chat).unwrap();
                    let assistant = rows.iter().find(|row| row.0 == boundary.assistant_entry_id).unwrap();
                    assert_eq!(serde_json::from_str::<serde_json::Value>(&assistant.2).unwrap()["text"], "final answer");
                    let transcript: Vec<serde_json::Value> = guard.store_ref().records(&chat, "transcript").unwrap().iter().map(|row| serde_json::from_str(row).unwrap()).collect();
                    assert_eq!(transcript[1]["text"], "first narration"); assert_eq!(transcript[2]["type"], "tool"); assert_eq!(transcript[3]["text"], "final answer");
                    assert!(boundary.fork_snapshot.is_some());
                    let output = crate::resource_store::get(guard.store_ref(), &chat, &crate::resource_store::output_id(&chat)).unwrap().unwrap();
                    // Independent completed provenance reads the original rows,
                    // without the old task's pending authority or any release grant.
                    let proof = guard.store_mut().with_record_admission(|writer| {
                        writer.require_recorded_claimed_lifecycle_pair::<RunState,MergeState>(
                            original.command_id(),original.scope(),original.key(),original.snapshot(),&chat)
                    }).unwrap().unwrap();
                    assert!(matches!(proof.first_events().last(),Some(gaugedesk_core::run::RunEvent::RunCompleted)) == (case != "failed"));
                    let recorded_output: gaugedesk_core::resource::ResourceRecord = serde_json::from_str(
                        &proof.facts().iter().find(|fact| fact.kind == "resource").unwrap().payload).unwrap();
                    assert_eq!(recorded_output,output);
                    assert!(proof.facts().iter().any(|fact| fact.kind == "workspace_result" && fact.payload == cut));
                    let creation_facts: Vec<_> = proof.facts().iter().filter(|fact| fact.kind == crate::engine::office_turn_result::CREATION_KIND).collect();
                    assert_eq!(creation_facts.len(),1);
                    let creation: crate::engine::office_turn_result::OfficeCreationRecord = serde_json::from_str(&creation_facts[0].payload).unwrap();
                    assert_eq!(creation.revision,"office-result-creation/v1");
                    assert_eq!(creation.command,original.command_id());
                    assert_eq!(creation.actor,captured.actor().as_str()); assert_eq!(creation.chat,chat);
                    assert_eq!(creation.input_position,boundary.user_entry_id);
                    assert_eq!(creation.base_cut,boundary.before_workspace_cut);
                    assert_eq!(creation.result_cut,cut);
                    assert_eq!(creation.runtime_start,boundary.runtime_before);
                    assert_eq!(creation.runtime_terminal,boundary.runtime_after);
                    assert_eq!(creation.ordered_writes.len(),if case == "repeated-writes" {3} else {2});
                    if case == "repeated-writes" { assert_eq!(creation.ordered_writes[0],creation.ordered_writes[2]); }
                    assert_eq!(creation.ordered_writes[0].path,path);
                    assert_eq!(creation.ordered_writes[0].sha256,hex::encode(Sha256::digest(b"qualified original bytes")));
                    assert_eq!(creation.ordered_writes[1].path,"artifacts/report.txt");
                    let writes: Vec<_> = creation.ordered_writes.iter().map(|file| gaugedesk_workspace::NativeTurnFileWitness {
                        path:file.path.clone(),kind:file.kind.clone(),sha256:file.sha256.clone(),bytes:file.bytes,
                    }).collect();
                    // Only original metadata is observed. No current staff read
                    // permission or byte publication is inferred from this proof.
                    guard.store_mut().with_record_admission(|writer| writer.with_native_check(|check| {
                        let mut current = || check.check_current().map_err(|e| gaugedesk_workspace::WorkspaceError { message: format!("{e:?}") });
                        engagement.witnessed_turn_target_at(&creation.base_cut).unwrap()
                            .with_retained_lineage(creation.lineage.clone()).unwrap()
                            .observe_saved_result_guarded(&writes,&creation.runtime_cut,&creation.actor,&creation.command,&creation.result_cut,&creation.evidence,&mut current).unwrap();
                    })).unwrap().unwrap();


                    assert!(output.resource.provenance.contains(&gaugedesk_core::resource::ResourceId::new(&previous)));
                    assert!(output.resource.provenance.contains(&gaugedesk_core::resource::ResourceId::new(&resource)));
                    for owner in if filing_enabled { vec![captured.actor().as_str()] } else { vec!["earlier-owner", "current-owner"] } {
                        assert!(output.stakeholders.contains(&gaugedesk_core::boundary::Authority::from(owner)));
                    }
                    assert!(boundary.reads_after.contains(&resource)); assert!(boundary.reads_after.contains(&previous));
                    assert!(matches!(output.locator, gaugedesk_core::resource::ContentLocator::Workspace { commit, .. } if commit == cut));
                    assert!(crate::turn_summary::latest(guard.store_ref(), &chat).unwrap().is_some());
                    assert_eq!(guard.store_ref().records(&chat, "workspace_local_result").unwrap().len(), 1);
                    let filings = guard.store_ref().records(&chat, "office_task_filing").unwrap();
                    if filing_enabled && enrolled {
                    assert_eq!(filings.len(), 1);
                    let filing: serde_json::Value = serde_json::from_str(&filings[0]).unwrap();
                    assert_eq!(filing["command_id"], original.command_id());
                    assert_eq!(filing["request"]["actor"], captured.actor().as_str());
                    assert_eq!(filing["request"]["assigned_to"], captured.actor().as_str());
                    let project = guard.library_project_of_chat(&chat).unwrap();
                    let tasks = guard.read_project_tracker_tasks(&captured, &project, crate::project_tracker::PROJECT_TASKS).unwrap();
                    assert_eq!(tasks.backlog.issues.len(), 1);
                    assert_eq!(tasks.backlog.issues[0].id, filing["receipt"]["item_id"]);
                    assert_eq!(tasks.backlog.issues[0].filed_by.as_deref(), Some(captured.actor().as_str()));
                    assert_eq!(tasks.backlog.issues[0].title, "Synthetic office task");
                    } else { assert!(filings.is_empty()); }

                    let settlement = guard.store_ref().records(&chat, "office_native_settlement").unwrap();
                    assert_eq!(settlement.len(), 1);
                    let settlement: serde_json::Value = serde_json::from_str(&settlement[0]).unwrap();
                    assert_eq!(settlement["command_id"], original.command_id());
                    assert_eq!(settlement["result_cut"], cut); assert_eq!(settlement["evidence_kind"], "current-applied");
                    assert_eq!(settlement["settlement_cut"]["actor"], captured.actor().as_str());
                    assert_eq!(settlement["operation"]["kind"], "merge-keep");
                    let native_cut = settlement["settlement_cut"]["cut_id"].as_str().unwrap();
                    assert_eq!(engagement.read_line_file(&path).unwrap().as_deref(), Some("qualified original bytes"));
                    assert!(engagement.read_line_file(&pending).unwrap().is_none());
                    assert_ne!(native_cut, cut);
                    assert_eq!(guard.store_ref().records(&chat, "office_turn_settlement_gap").unwrap().len(), 1);
                    StatusCode::OK
                } else {
                    assert!(result.is_err(), "{case}");
                    assert_eq!(guard.store_ref().fold::<RunState>(&chat).unwrap().phase, RunPhase::Running);
                    assert!(guard.store_ref().pending_command_matches(original.command_id(), original.scope(), original.key(), original.snapshot()).unwrap());
                    assert!(guard.store_ref().records(&chat, "workspace_result").unwrap().is_empty());
                    assert!(guard.store_ref().records(&chat,crate::engine::office_turn_result::CREATION_KIND).unwrap().is_empty());
                    if case == "creation-write-refused" {
                        assert_eq!(guard.store_ref().fold::<MergeState>(&chat).unwrap(),MergeState::default());
                        let bindings: i64 = rusqlite::Connection::open(guard.store_ref().path()).unwrap().query_row(
                            "SELECT COUNT(*) FROM command_pair_results WHERE command_id=?1",[original.command_id()],|row| row.get(0)).unwrap();
                        assert_eq!(bindings,0);
                        assert!(guard.store_ref().committed_record_snapshot(original.scope(),original.key()).unwrap().is_none());
                    }

                    assert!(guard.store_ref().records(&chat, crate::engine::TURN_BOUNDARY_KIND).unwrap().is_empty());
                    assert_eq!(guard.store_ref().records(&chat, "transcript").unwrap().len(), 1);
                    StatusCode::FORBIDDEN
                }
            }
        })).with_state(wb.clone()).layer(axum::middleware::from_fn_with_state(wb.clone(), crate::command_idempotency::guard));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/chats/{chat}/task"))
                    .header("idempotency-key", "production-result")
                    .body(Body::from("synthetic original task"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if matches!(case, "clean" | "failed" | "repeated-writes") {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            }
        );
    }
}

#[tokio::test]
async fn original_engine_recovers_a_genuinely_saved_native_execution() {
    genuinely_saved_native_recovery(true, true, false, RecoveryPublication::None).await;
}

#[tokio::test]
async fn original_engine_recovers_saved_bytes_after_pending_replacement() {
    genuinely_saved_native_recovery(false, true, false, RecoveryPublication::None).await;
}

#[tokio::test]
async fn original_engine_recovers_intact_genuinely_saved_native_execution() {
    genuinely_saved_native_recovery(false, false, false, RecoveryPublication::None).await;
}

#[tokio::test]
async fn original_prepared_payloads_match_genuine_saved_native_witness_after_later_work() {
    genuinely_saved_native_recovery(true, true, true, RecoveryPublication::None).await;
}

#[tokio::test]
async fn original_engine_recovers_interrupted_publication_after_later_native_work() {
    genuinely_saved_native_recovery(true, true, false, RecoveryPublication::Interrupted).await;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecoveryPublication {
    None,
    Interrupted,
    InterruptedRevoked,
    InterruptedRevokedRestored,
    InterruptedCold,
}

#[tokio::test]
async fn original_engine_refuses_interrupted_publication_after_access_loss_or_restoration() {
    for mode in [
        RecoveryPublication::InterruptedRevoked,
        RecoveryPublication::InterruptedRevokedRestored,
    ] {
        genuinely_saved_native_recovery(true, true, false, mode).await;
    }
}

#[tokio::test]
async fn original_engine_refuses_saved_native_completion_after_cold_home_reopen() {
    genuinely_saved_native_recovery(true, true, false, RecoveryPublication::InterruptedCold).await;
}

async fn genuinely_saved_native_recovery(
    later_work: bool,
    replace_pending: bool,
    custody_only: bool,
    publication: RecoveryPublication,
) {
    use gaugedesk_whip_runtime::{
        AuthoredAgentPackage, CredentialRef, GovernedHostRuntime, ModelProvider,
        NativeWorkspaceResolver, OpenInstanceCommand, ProviderBindingRef, ResolvedImage,
        ResolvedProviderBinding, ResourceRef, ResourceResolver, SecretResolver, StartTurnCommand,
        ToolCall, TurnInput, TurnWitness, HOST_PROTOCOL,
    };
    use whipplescript_kernel::sansio::{HostDriver, HttpResponse, IoRequest, IoResult};
    struct Provider;
    impl SecretResolver for Provider {
        fn resolve_provider(
            &self,
            _: &ProviderBindingRef,
            _: &str,
        ) -> Result<ResolvedProviderBinding, String> {
            Ok(ResolvedProviderBinding::new(
                ModelProvider::OpenAi,
                "synthetic-never-transmitted",
                "synthetic-model",
                "https://api.openai.com",
                1000,
                std::time::Duration::from_secs(1),
            ))
        }
    }
    struct Driver(std::cell::RefCell<std::collections::VecDeque<serde_json::Value>>);
    impl HostDriver for Driver {
        fn fulfill(&self, _: &IoRequest) -> IoResult {
            IoResult::Http(Ok(HttpResponse {
                status: 200,
                body: self
                    .0
                    .borrow_mut()
                    .pop_front()
                    .expect("local scripted model response"),
            }))
        }
    }
    struct OriginalResources<'a> {
        workspace: NativeWorkspaceResolver,
        access: &'a dyn gaugedesk_harness::TurnAccess,
        images: &'a [gaugedesk_harness::ImageContent],
    }
    impl ResourceResolver for OriginalResources<'_> {
        fn check_live_access(&self) -> Result<(), String> {
            self.access.check_current()
        }
        fn resolve_image(&self, image: &ResourceRef) -> Result<ResolvedImage, String> {
            use base64::Engine as _;
            let index: usize = image
                .selector
                .as_deref()
                .ok_or("missing image index")?
                .parse()
                .map_err(|_| "invalid image index")?;
            let image = self.images.get(index).ok_or("missing original image")?;
            Ok(ResolvedImage {
                media_type: image.mime_type.clone(),
                bytes: base64::engine::general_purpose::STANDARD
                    .decode(&image.data)
                    .map_err(|_| "invalid original image")?,
            })
        }
        fn execute_tool(
            &self,
            admitted: &[ResourceRef],
            call: &ToolCall,
        ) -> Result<String, String> {
            self.access.check_current()?;
            if call.name == "ask" {
                assert!(admitted.iter().any(|resource| resource.kind == "question"));
                assert_eq!(call.arguments["question"], "Synthetic original question");
                return Ok("{\"asked\":true}".into());
            }
            self.workspace.execute_tool(admitted, call)
        }
        fn take_turn_witness(&self) -> TurnWitness {
            self.workspace.take_turn_witness()
        }
        fn take_workspace_reads(&self) -> Vec<whipplescript_kernel::whip_shell::ShellRead> {
            self.workspace.take_workspace_reads()
        }
    }
    let root = tempfile::tempdir().unwrap();
    let (wb, admission_app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&admission_app, ALICE).await;
    let chat = chat(&wb);
    let captured = context(&wb, &admission);
    let (cold_ready, mut cold_recovery) = tokio::sync::mpsc::unbounded_channel();
    let app = Router::new().route("/chats/{id}/task", post(move |
        State(wb): State<SharedWorkbench>, Path(chat): Path<String>,
        axum::extract::Extension(original): axum::extract::Extension<crate::command_idempotency::ClaimedHttpCommand>| {
        let captured = captured.clone();
        let cold_ready = cold_ready.clone();
        async move {
            let authority = OfficeTaskAuthority::for_turn(&wb, &chat, Some(&captured),
                Some(&Default::default()), Some(captured.actor()), Some(ALICE)).unwrap().unwrap();
            let office = crate::engine::office_turn_startup::OfficeTurnContext { wb: &wb, authority: &authority, original: &original };
            let (engagement, worktree, sender, mode, project, path) = {
                let mut guard = wb.lock_unpoisoned();
                let engagement = guard.engagements[&chat].boxed_clone();
                let (worktree, sender, mode) = guard.engagement_turn_location(&chat).unwrap();
                let prefix = guard.engagement_context_target_root(&chat, None).unwrap().unwrap_or_default();
                let path = if prefix.is_empty() { "result.txt".into() } else { format!("{prefix}/result.txt") };
                (engagement, worktree, sender, mode, guard.library_project_of_chat(&chat).unwrap(), path)
            };
            let task = "synthetic original task";
            let mut fork = None;
            let startup = crate::engine::office_turn_startup::admit_startup(&office, engagement.as_ref(), &chat, task, &mut fork).unwrap();
            let policy_input = crate::policy_compiler::PolicyCompilationInput {
                chat_id: chat.clone(), project_id: Some(project), actor: captured.actor().as_str().into(),
                actor_attributes: gaugedesk_core::abac::AuthorityAttributes { clearance: gaugedesk_core::abac::Clearance(3), ..Default::default() },
                org_policy: Default::default(), turn_purpose: None,
                package_capabilities: std::collections::BTreeSet::from(["workspace.read".into(), "workspace.write".into(), "question.ask".into()]),
                provider: "openai".into(), model: "synthetic-model".into(), base_url: "https://api.openai.com".into(),
                credential_ref: "credential:synthetic-native-fixture".into(), private_model_broker: None, wire: "openai-responses".into(),
                placement_kind: "local".into(), command_network: false, resources: Vec::new(), task_tracker: None,
                target_bindings: Vec::new(), advancement_scopes: Vec::new(),
            };
            let policy = wb.lock_unpoisoned().compile_whipple_policy(policy_input.clone()).unwrap();
            let package = AuthoredAgentPackage::from_documents(
                r#"{"schema":"whipplescript.agent_package.v0","source":"method.whip","workflow":"Method","agent":"assistant","system_prompt":"persona.md","capabilities":["workspace.read","workspace.write","question.ask"],"agent_abilities":["workspace.read","workspace.write","question.ask"],"external_tools":[{"name":"ask","capability":"question.ask","description":"Ask a synthetic question","input_schema":{"type":"object","properties":{"question":{"type":"string"}}}}],"max_steps":4}"#,
                r#"file store project { root "." allow read ["**"] allow write ["**"] }
workflow Method {
 agent assistant { provider owned profile "writer" capacity 1 capabilities ["workspace.read", "workspace.write", "question.ask"] }
 rule converse when started => { tell assistant requires ["workspace.read", "workspace.write", "question.ask"] with access to project { read ["**"] write ["**"] } "Run." }
}"#, "Synthetic fixture persona").unwrap();
            let (database, verifier) = {
                let guard = wb.lock_unpoisoned();
                (guard.root_path().join("whip-runtimes").join(format!("{}.sqlite", hex::encode(chat.as_bytes()))), policy.policy_root.clone())
            };
            std::fs::create_dir_all(database.parent().unwrap()).unwrap();
            let mut native = GovernedHostRuntime::open_with_verifier(&database, policy.epoch, &policy.signed_envelope, &verifier).unwrap();
            let instance = native.open_instance(&OpenInstanceCommand { protocol: HOST_PROTOCOL.into(), request_id: "synthetic-original-instance".into(),
                package_version_ref: package.version_ref().into(), policy: native.policy_ref().clone() }, &package).unwrap();
            let start = native.pinned_position(&instance.instance_ref).unwrap();
            let images = vec![gaugedesk_harness::ImageContent { kind: gaugedesk_harness::ImageKind::Image, data: "AA==".into(), mime_type: "image/png".into() }];
            let command = StartTurnCommand { protocol: HOST_PROTOCOL.into(), command_id: original.command_id().into(),
                run_ref: format!("gaugedesk:run:{}", original.command_id()), instance_ref: instance.instance_ref,
                package_version_ref: package.version_ref().into(), policy: native.policy_ref().clone(), actor_ref: captured.actor().as_str().into(),
                input: TurnInput { text: task.into(), images: vec![ResourceRef { handle: "turn_images".into(), kind: "image".into(), selector: Some("0".into()), writable: None, presented_as: None }] },
                resources: vec![ResourceRef { handle: "project".into(), kind: "file_store".into(), selector: None, writable: None, presented_as: None }, ResourceRef { handle: "question".into(), kind: "question".into(), selector: None, writable: None, presented_as: None }],
                provider_binding: ProviderBindingRef { binding_id: "model".into(), credential: CredentialRef { credential_id: "credential:synthetic-native-fixture".into() } },
                placement_ceiling_ref: "local".into() };
            let preparation = gaugedesk_harness::RuntimeTurnPreparation { input_digest: gaugedesk_harness::runtime_input_digest(task, &images),
                command_json: serde_json::to_string(&command).unwrap(), start_position: RuntimePosition { instance_ref: start.instance_ref, sequence: start.sequence },
                start_head_digest: start.head_digest, workspace_targets: Vec::new() };
            crate::engine::office_turn_startup::retain_runtime(&office, &startup, None, preparation).unwrap();
            let original_access = office.recorded_access();
            let retain = crate::engine::office_turn_payload::callback(&office, &startup, None);
            let resources = OriginalResources { workspace: NativeWorkspaceResolver::new(&worktree).unwrap().with_payload_retention(move |file, body| {
                retain.retain(&gaugedesk_harness::PreparedWorkspaceFile {
                    path: file.path.clone(), kind: file.kind.clone(), sha256: file.content_hash.clone(), bytes: file.bytes,
                }, body)
            }), access: &original_access, images: &images };
            let driver = Driver(std::cell::RefCell::new(std::collections::VecDeque::from([
                serde_json::json!({ "output": [{ "type":"function_call", "call_id":"write-original", "name":"write", "arguments":serde_json::json!({"path": path, "content":"original native result"}).to_string() }], "usage":{"input_tokens":10,"output_tokens":2} }),
                serde_json::json!({ "output": [{ "type":"function_call", "call_id":"ask-original", "name":"ask", "arguments":serde_json::json!({"question":"Synthetic original question", "choices":["yes", "no"], "blocking":true}).to_string() }], "usage":{"input_tokens":11,"output_tokens":2} }),
                serde_json::json!({ "output_text":"original native reply", "usage":{"input_tokens":12,"output_tokens":3} }),
            ])));
            let execution = native.run_turn_with_driver(&command, &package, &Provider, &resources, &driver).unwrap();
            assert!(driver.0.borrow().is_empty());
            assert_eq!(execution.receipt.as_ref().unwrap().status, gaugedesk_whip_runtime::TurnStatus::Completed);
            let head = native.pinned_position(&command.instance_ref).unwrap();
            drop(native); drop(resources);
            original.verify_pending(wb.lock_unpoisoned().store_ref()).unwrap();
            let original_database = std::fs::read(&database).unwrap();
            let mut later_policy_input = policy_input;
            later_policy_input.model = "later-settings-model".into();
            let later_policy = wb.lock_unpoisoned().compile_whipple_policy(later_policy_input).unwrap();
            assert!(later_policy.epoch > policy.epoch);
            let later_path = path.replace("result.txt", "later.txt");
            let pending_path = path.replace("result.txt", "pending.txt");
            if later_work {
                engagement.write_file(&later_path, "later independently submitted work").unwrap();
                engagement.commit_turn("later independently submitted work").unwrap();
            }
            // The original owner outcome must survive a later unsubmitted edit,
            // including when no commit has incidentally cached the result bytes.
            if replace_pending {
                engagement.write_file(&path, "later unsubmitted replacement").unwrap();
            }
            engagement.write_file(&pending_path, "never submitted pending edit").unwrap();

            let sealed = crate::engine::office_turn_startup::recorded_runtime(&office, &startup, None).unwrap();
            let factory = wb.lock_unpoisoned().recorded_whip_harness_factory().unwrap().with_policy_root(policy.policy_root.clone());
            let read_access = office.recorded_access();
            let observed = factory.observe_recorded_runtime(&gaugedesk_harness::RecordedRuntimeSpec {
                chat_id: &chat, command_id: original.command_id(), policy_epoch: policy.epoch,
                signed_policy_envelope: &policy.signed_envelope, preparation: &sealed, images: &images, access: &read_access,
            }).unwrap();
            assert_eq!(observed.assistant_text, "original native reply");
            assert_eq!(observed.asked_questions[0].question, "Synthetic original question");
            let witness = observed.runtime_workspace_witness.as_ref().unwrap();
            assert_eq!(witness.writes.len(), 1);
            let before_payload_read = engagement.observe().unwrap();
            for file in &witness.writes {
                let retained = crate::engine::office_turn_payload::recorded(&office, &startup, None,
                    &crate::engine::office_turn_payload::PreparedFile {
                        path: file.path.clone(), kind: file.kind.clone(), sha256: file.content_hash.clone(), bytes: file.bytes,
                    }).unwrap();
                assert_eq!(retained, b"original native result");
            }
            assert_eq!(engagement.observe().unwrap(), before_payload_read);
            {
                let files: Vec<_> = witness.writes.iter().map(|file| crate::engine::office_turn_payload::PreparedFile {
                    path: file.path.clone(), kind: file.kind.clone(), sha256: file.content_hash.clone(), bytes: file.bytes,
                }).collect();
                let plan = crate::engine::office_turn_payload::ResultPayloadPlan::new(&office, &startup, &sealed, &files).unwrap();
                let scopes = plan.scopes();
                let scopes: Vec<_> = scopes.iter().map(String::as_str).collect();
                let mut held = wb.lock_unpoisoned();
                let authority = office.authority.prepare_basis(&held).unwrap();
                let key = held.content_vault.as_ref().unwrap().prepare_scope_key(&chat).unwrap();
                let (payloads, basis) = held.store_ref().read_for_dispatch(&scopes, |reader| plan.observe(reader)).unwrap();
                let basis = authority.combine(basis).unwrap();
                held.store_mut().with_dispatch_record_admission(&basis, |writer| {
                    payloads.consume(writer, &key, &original, |writer, bodies| {
                        writer.with_native_check(|check| check.check_current())??;
                        assert_eq!(bodies.len(), 1);
                        assert_eq!(bodies[&files[0].path], b"original native result");
                        Ok(())
                    })
                }).unwrap().unwrap();
            }
            assert_eq!(engagement.observe().unwrap(), before_payload_read);
            original.verify_pending(wb.lock_unpoisoned().store_ref()).unwrap();
            let context = observed.context_reading.unwrap();
            assert_eq!(context.model, "synthetic-model"); assert_eq!(context.last_input_tokens, 12);
            assert_eq!(std::fs::read(&database).unwrap(), original_database);
            for substitution in ["body", "mime"] {
                let before = wb.lock_unpoisoned().store_ref().retained_events(&chat).unwrap();
                let mut changed = images.clone();
                if substitution == "body" { changed[0].data = "AQ==".into(); } else { changed[0].mime_type = "image/jpeg".into(); }
                let refused = crate::engine::run_engagement_turn(&wb, &chat, &worktree, &sender, crate::engine::EngagementTurnInput {
                    task, images: &changed, mode, authenticated_actor: Some(captured.actor()), authenticated_context: Some(&captured),
                    client_build: Some(&Default::default()), local_operator: false, contribution_by: None,
                    account_scope: "account", tenant_scope: ORG_SCOPE, account_bearer: Some(ALICE), runtime_command_id: None,
                    original_http_command: Some(&original), harness_factory: None,
                }).unwrap_err();
                assert!(refused.to_string().contains("original runtime preparation changed"));
                assert_eq!(wb.lock_unpoisoned().store_ref().retained_events(&chat).unwrap(), before);
                assert_eq!(std::fs::read(&database).unwrap(), original_database);
                original.verify_pending(wb.lock_unpoisoned().store_ref()).unwrap();
            }
            if custody_only {
                assert_eq!(engagement.read_file(&path).unwrap(), "later unsubmitted replacement");
                assert_eq!(engagement.read_file(&later_path).unwrap(), "later independently submitted work");
                assert_eq!(engagement.read_file(&pending_path).unwrap(), "never submitted pending edit");
                assert_eq!(std::fs::read(&database).unwrap(), original_database);
                original.verify_pending(wb.lock_unpoisoned().store_ref()).unwrap();
                return StatusCode::OK;
            }
            let mut interrupted = None;
            if publication != RecoveryPublication::None {
                let (product_path, native_root) = {
                    let guard = wb.lock_unpoisoned();
                    (guard.store_ref().path().to_owned(), guard.root_path().join("collaboration-workspaces")
                        .join(&guard.engagement_index[&chat]).join(".repo.whipplescript"))
                };
                let fault = rusqlite::Connection::open(product_path).unwrap();
                fault.execute_batch("CREATE TRIGGER lose_original_product_completion BEFORE INSERT ON events WHEN NEW.kind='workspace_result' BEGIN SELECT RAISE(ABORT, 'synthetic original completion interruption'); END;").unwrap();
                let product_before = wb.lock_unpoisoned().store_ref().retained_events(&chat).unwrap();
                let source_before = engagement.observe().unwrap().recorded_cut;
                let failed = crate::engine::run_engagement_turn(&wb, &chat, &worktree, &sender, crate::engine::EngagementTurnInput {
                    task, images: &images, mode, authenticated_actor: Some(captured.actor()), authenticated_context: Some(&captured),
                    client_build: Some(&Default::default()), local_operator: false, contribution_by: None,
                    account_scope: "account", tenant_scope: ORG_SCOPE, account_bearer: Some(ALICE), runtime_command_id: None,
                    original_http_command: Some(&original), harness_factory: None,
                });
                assert!(failed.is_err());
                assert_eq!(wb.lock_unpoisoned().store_ref().retained_events(&chat).unwrap(), product_before);
                original.verify_pending(wb.lock_unpoisoned().store_ref()).unwrap();
                assert_eq!(engagement.observe().unwrap().recorded_cut, source_before);
                assert_eq!(engagement.read_line_file(&path).unwrap().as_deref(), Some("original native result"));
                assert_eq!(engagement.read_file(&path).unwrap(), "later unsubmitted replacement");
                assert_eq!(std::fs::read(&database).unwrap(), original_database);
                fault.execute_batch("DROP TRIGGER lose_original_product_completion").unwrap();
                let lineage = startup.native_base.original_lineage().unwrap();
                let parent = lineage.parent_branch_id.as_ref().unwrap().clone();
                let mut native = whipplescript_store::vcs::NativeWorkspaceVcs::open_for_recorded_review(
                    native_root.join("branches.sqlite"), native_root.join("content.sqlite")).unwrap();
                let home_cut_id = native.get_branch(&parent).unwrap().unwrap().head_cut_id.unwrap();
                let home_cut = native.get_cut(&home_cut_id).unwrap().unwrap();
                assert_eq!(home_cut.actor.as_deref(), Some(captured.actor().as_str()));
                assert_eq!(home_cut.intent.as_deref(), Some(original.command_id()));
                let home_op = native.get_op(&format!("op-{home_cut_id}")).unwrap().unwrap();
                assert_eq!(home_op.kind, "merge-keep");
                let candidates: Vec<_> = native.list_branches(None).unwrap().into_iter()
                    .filter(|row| row.branch_id.starts_with("original-candidate-")).collect();
                assert_eq!(candidates.len(), 1);
                let candidate = candidates[0].branch_id.clone();
                let result_cuts = native.list_cuts(&candidate, 100).unwrap();
                assert_eq!(result_cuts.len(), 1);
                let original_result = result_cuts[0].cut_id.clone();
                let home_after_path = path.replace("result.txt", "home-after-interruption.txt");
                let candidate_after_path = path.replace("result.txt", "candidate-after-interruption.txt");
                native.set_actor(Some("later-native-staff".into()));
                native.set_intent(Some("later-native-command".into()));
                native.write(&parent, &home_after_path, Some("Home after original settlement"), "later-home-after-interruption", "later-home-after-interruption").unwrap();
                native.write(&candidate, &candidate_after_path, Some("candidate after original settlement"), "later-candidate-after-interruption", "later-candidate-after-interruption").unwrap();
                let branches_after = native.list_branches(None).unwrap();
                let ops_after = native.list_ops(200).unwrap();
                interrupted = Some((native_root, original_result, home_cut, home_op, branches_after, ops_after));
            }
            if publication == RecoveryPublication::InterruptedCold {
                cold_ready.send((original.clone(), captured.clone(), images.clone(), database.clone(),
                    original_database.clone(), path.clone(), pending_path.clone(),
                    wb.lock_unpoisoned().store_ref().retained_events(&chat).unwrap(), interrupted.unwrap())).unwrap();
                return std::future::pending::<StatusCode>().await;
            }
            if matches!(publication, RecoveryPublication::InterruptedRevoked | RecoveryPublication::InterruptedRevokedRestored) {
                membership(&wb, "alice", crate::org::MembershipStatus::Deprovisioned);
                if publication == RecoveryPublication::InterruptedRevokedRestored {
                    // Both events precede the next checkpoint. The denial
                    // history, not only the latest active row, governs old work.
                    membership(&wb, "alice", crate::org::MembershipStatus::Active);
                }
                let before = wb.lock_unpoisoned().store_ref().retained_events(&chat).unwrap();
                let source = engagement.observe().unwrap();
                let refused = crate::engine::run_engagement_turn(&wb, &chat, &worktree, &sender, crate::engine::EngagementTurnInput {
                    task, images: &images, mode, authenticated_actor: Some(captured.actor()), authenticated_context: Some(&captured),
                    client_build: Some(&Default::default()), local_operator: false, contribution_by: None,
                    account_scope: "account", tenant_scope: ORG_SCOPE, account_bearer: Some(ALICE), runtime_command_id: None,
                    original_http_command: Some(&original), harness_factory: None,
                });
                assert!(refused.is_err(), "original native settlement revived old office work");
                assert_eq!(wb.lock_unpoisoned().store_ref().retained_events(&chat).unwrap(), before);
                assert_eq!(engagement.observe().unwrap(), source);
                assert_eq!(std::fs::read(&database).unwrap(), original_database);
                assert_eq!(engagement.read_file(&path).unwrap(), "later unsubmitted replacement");
                assert_eq!(engagement.read_file(&pending_path).unwrap(), "never submitted pending edit");
                let (native_root, _, _, _, branches_after, ops_after) = interrupted.unwrap();
                let native = whipplescript_store::vcs::NativeWorkspaceVcs::open_read_only(
                    native_root.join("branches.sqlite"), native_root.join("content.sqlite")).unwrap();
                assert_eq!(native.list_branches(None).unwrap(), branches_after);
                assert_eq!(native.list_ops(200).unwrap(), ops_after);
                original.verify_pending(wb.lock_unpoisoned().store_ref()).unwrap();
                return StatusCode::FORBIDDEN;
            }
            let before_recovery = engagement.observe().unwrap();
            let later_line_before = engagement.read_line_file(&later_path).unwrap();
            let before_product = wb.lock_unpoisoned().store_ref().retained_events(&chat).unwrap();
            let recovered = crate::engine::run_engagement_turn(&wb, &chat, &worktree, &sender, crate::engine::EngagementTurnInput {
                task, images: &images, mode, authenticated_actor: Some(captured.actor()), authenticated_context: Some(&captured),
                client_build: Some(&Default::default()), local_operator: false, contribution_by: None,
                account_scope: "account", tenant_scope: ORG_SCOPE, account_bearer: Some(ALICE), runtime_command_id: None,
                original_http_command: Some(&original), harness_factory: None,
            });
            // Refusal must preserve both the native recorded basis and later
            // mutable files. Keep this regression red until recovery succeeds.
            if recovered.is_err() {
                assert_eq!(engagement.observe().unwrap(), before_recovery);
                assert_eq!(wb.lock_unpoisoned().store_ref().retained_events(&chat).unwrap(), before_product);
                assert_eq!(engagement.read_file(&path).unwrap(), "later unsubmitted replacement");
                assert_eq!(engagement.read_file(&pending_path).unwrap(), "never submitted pending edit");
                assert_eq!(std::fs::read(&database).unwrap(), original_database);
                original.verify_pending(wb.lock_unpoisoned().store_ref()).unwrap();
            }
            let recovered = recovered.unwrap();
            assert_eq!(recovered.assistant_text, "original native reply");
            assert_eq!(recovered.run_phase, RunPhase::Completed);
            assert_eq!(std::fs::read(&database).unwrap(), original_database);
            assert!(head.sequence > 0);
            assert_eq!(engagement.observe().unwrap().recorded_cut, before_recovery.recorded_cut);
            if later_work {
                // commit_turn recorded this on the source branch, not Home.
                // Keep its immutable current cut and physical bytes; original
                // recovery must not additionally promote that later work.
                assert_eq!(engagement.read_file(&later_path).unwrap(), "later independently submitted work");
                assert_eq!(engagement.read_line_file(&later_path).unwrap(), later_line_before);
            }
            assert_eq!(engagement.read_file(&path).unwrap(), if replace_pending { "later unsubmitted replacement" } else { "original native result" });
            assert_eq!(engagement.read_file(&pending_path).unwrap(), "never submitted pending edit");
            assert!(engagement.read_line_file(&pending_path).unwrap().is_none());
            let guard = wb.lock_unpoisoned();
            let readings = guard.store_ref().records(&chat, crate::engine::CONTEXT_READING_KIND).unwrap();
            assert_eq!(readings.len(), 1);
            let reading: gaugedesk_harness::ContextWindowReading = serde_json::from_str(&readings[0]).unwrap();
            assert_eq!(reading.provider, "openai"); assert_eq!(reading.model, "synthetic-model"); assert_eq!(reading.last_input_tokens, 12);
            let local = guard.store_ref().records(&chat, "workspace_local_result").unwrap();
            assert_eq!(local.len(), 1);
            let local: serde_json::Value = serde_json::from_str(&local[0]).unwrap();
            assert_eq!(local["pending_questions"][0]["question"], "Synthetic original question");
            let creations = guard.store_ref().records(&chat, crate::engine::office_turn_result::CREATION_KIND).unwrap();
            assert_eq!(creations.len(),1);
            let creation: crate::engine::office_turn_result::OfficeCreationRecord = serde_json::from_str(&creations[0]).unwrap();
            assert_eq!(creation.command,original.command_id());
            assert_eq!(creation.result_cut,recovered.commit.as_ref().unwrap().as_str());
            assert_eq!(creation.runtime_cut,witness.receipt_json.as_str().parse::<serde_json::Value>().unwrap()["workspace_cut_ref"].as_str().unwrap());
            assert_eq!(creation.ordered_writes, witness.writes.iter().map(|file| crate::engine::office_turn_payload::PreparedFile {
                path:file.path.clone(),kind:file.kind.clone(),sha256:file.content_hash.clone(),bytes:file.bytes,
            }).collect::<Vec<_>>());

            if let Some((native_root, original_result, home_cut, home_op, branches_after, ops_after)) = interrupted {
                assert_eq!(recovered.commit.as_deref(), Some(original_result.as_str()));
                let settlements = guard.store_ref().records(&chat, "office_native_settlement").unwrap();
                assert_eq!(settlements.len(), 1);
                let settlement: serde_json::Value = serde_json::from_str(&settlements[0]).unwrap();
                assert_eq!(settlement["evidence_kind"], "original-history");
                assert_eq!(settlement["settlement_cut"], serde_json::to_value(home_cut).unwrap());
                assert_eq!(settlement["operation"], serde_json::to_value(home_op).unwrap());
                let native = whipplescript_store::vcs::NativeWorkspaceVcs::open_read_only(
                    native_root.join("branches.sqlite"), native_root.join("content.sqlite")).unwrap();
                assert_eq!(native.list_branches(None).unwrap(), branches_after);
                assert_eq!(native.list_ops(200).unwrap(), ops_after);
            }
            drop(guard);
            assert!(original.verify_pending(wb.lock_unpoisoned().store_ref()).is_err());
            StatusCode::OK
        }
    })).with_state(wb.clone()).layer(axum::middleware::from_fn_with_state(wb.clone(), crate::command_idempotency::guard));
    if publication == RecoveryPublication::InterruptedCold {
        let invocation = tokio::spawn(
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/chats/{chat}/task"))
                    .header("idempotency-key", "genuine-native-recovery")
                    .body(Body::from("synthetic original task"))
                    .unwrap(),
            ),
        );
        let (
            original,
            old_context,
            images,
            database,
            native_database,
            path,
            pending_path,
            product_before,
            (native_root, _, _, _, branches_before, ops_before),
        ) = tokio::time::timeout(std::time::Duration::from_secs(30), cold_recovery.recv())
            .await
            .unwrap()
            .unwrap();
        invocation.abort();
        assert!(invocation.await.unwrap_err().is_cancelled());
        drop(admission_app);
        assert_eq!(Arc::strong_count(&wb), 1, "old Home still has a live owner");
        drop(wb);
        let reopened = crate::open_workbench(root.path()).unwrap();
        reopened.lock_unpoisoned().hold_session_for_tests("shared");
        assert_eq!(
            reopened
                .lock_unpoisoned()
                .store_ref()
                .retained_events(&chat)
                .unwrap(),
            product_before
        );
        original
            .verify_pending(reopened.lock_unpoisoned().store_ref())
            .unwrap();
        install(&reopened, &hub);
        let admission_app = router(reopened.clone());
        let admission = admit(&admission_app, ALICE).await;
        let fresh_context = context(&reopened, &admission);
        for (case, context) in [("old", &old_context), ("fresh", &fresh_context)] {
            let (worktree, sender, mode, source_before, product_before) = {
                let mut guard = reopened.lock_unpoisoned();
                let (worktree, sender, mode) = guard.engagement_turn_location(&chat).unwrap();
                (
                    worktree,
                    sender,
                    mode,
                    guard.engagements[&chat].observe().unwrap(),
                    guard.store_ref().retained_events(&chat).unwrap(),
                )
            };
            let result = crate::engine::run_engagement_turn(
                &reopened,
                &chat,
                &worktree,
                &sender,
                crate::engine::EngagementTurnInput {
                    task: "synthetic original task",
                    images: &images,
                    mode,
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
            assert!(result.is_err(), "cold reopen revived original native task");
            if case == "fresh" {
                assert!(
                    matches!(&result, Err(crate::engine::EngineError::Admit(
                    gaugedesk_store::AdmitError::Rejected(rejection)
                )) if rejection.reason == "office startup has no exact retained original snapshot or phase"),
                    "fresh admission refused for a different reason: {result:?}"
                );
            }
            let guard = reopened.lock_unpoisoned();
            assert_eq!(
                guard.store_ref().retained_events(&chat).unwrap(),
                product_before
            );
            assert_eq!(guard.engagements[&chat].observe().unwrap(), source_before);
            assert_eq!(
                guard.engagements[&chat].read_file(&path).unwrap(),
                "later unsubmitted replacement"
            );
            assert_eq!(
                guard.engagements[&chat].read_file(&pending_path).unwrap(),
                "never submitted pending edit"
            );
            original.verify_pending(guard.store_ref()).unwrap();
            assert_eq!(std::fs::read(&database).unwrap(), native_database);
            let native = whipplescript_store::vcs::NativeWorkspaceVcs::open_read_only(
                native_root.join("branches.sqlite"),
                native_root.join("content.sqlite"),
            )
            .unwrap();
            assert_eq!(native.list_branches(None).unwrap(), branches_before);
            assert_eq!(native.list_ops(200).unwrap(), ops_before);
        }
        return;
    }
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/chats/{chat}/task"))
                .header("idempotency-key", "genuine-native-recovery")
                .body(Body::from("synthetic original task"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        if matches!(
            publication,
            RecoveryPublication::InterruptedRevoked
                | RecoveryPublication::InterruptedRevokedRestored
        ) {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::OK
        }
    );
}
