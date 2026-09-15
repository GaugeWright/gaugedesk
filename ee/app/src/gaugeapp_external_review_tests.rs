// Included in the route test module so these exercise the actual authenticated
// HTTP router and its ordinary session/proposal/review helpers.

struct ReviewWriteFault(std::sync::atomic::AtomicU8);
impl gaugedesk_store::ContentCodec for ReviewWriteFault {
    fn encode(&self, _scope: &str, kind: &str, payload: &str) -> Result<String, String> {
        let mode = self.0.load(std::sync::atomic::Ordering::SeqCst);
        let status = serde_json::from_str::<Value>(payload)
            .ok()
            .and_then(|value| value["status"].as_str().map(str::to_owned));
        if kind == GAUGEAPP_CHANGE_KIND
            && ((mode == 1 && status.as_deref() == Some("applying"))
                || (mode == 2 && status.as_deref() == Some("applied")))
        {
            return Err("synthetic review write failure".into());
        }
        Ok(payload.into())
    }
    fn decode(&self, _scope: &str, _kind: &str, payload: &str) -> Option<String> {
        Some(payload.into())
    }
}

struct ReviewAuthorityFixture {
    store: Mutex<Store>,
    workbench: Mutex<Option<std::sync::Weak<Mutex<Workbench>>>>,
    pause: Mutex<Option<Arc<ReviewPause>>>,
    apply_calls: std::sync::atomic::AtomicUsize,
    recovery_calls: std::sync::atomic::AtomicUsize,
    // 0: commit then lose response; 1: pending before commit; 2: terminal refusal;
    // 3: ordinary acknowledged result. These are transport fixtures, not policies.
    mode: std::sync::atomic::AtomicU8,
}

struct ReviewPause {
    entered: tokio::sync::Notify,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl ReviewAuthorityFixture {
    fn new(path: &std::path::Path) -> Self {
        Self {
            store: Mutex::new(Store::open(path.to_str().unwrap()).unwrap()),
            workbench: Mutex::new(None),
            pause: Mutex::new(None),
            apply_calls: 0.into(),
            recovery_calls: 0.into(),
            mode: 0.into(),
        }
    }
    fn plan_result() -> MutationPlan {
        MutationPlan {
            facts: Vec::new(),
            notices: Vec::new(),
            audit_action: "backup.enable",
            audit_target: "external-test".into(),
            transient_result: Some(json!({ "confirmed": true })),
        }
    }
    fn effects(&self) -> usize {
        self.store
            .lock()
            .unwrap()
            .records("remote", "result")
            .unwrap()
            .len()
    }
    fn assert_durable_unlocked_approval(
        &self,
        scope: &str,
        approved: &ApprovedAdministrationChange,
    ) {
        let wb = self
            .workbench
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .upgrade()
            .unwrap();
        let start = std::time::Instant::now();
        let guard = loop {
            if let Ok(guard) = wb.try_lock() {
                break guard;
            }
            assert!(
                start.elapsed() < std::time::Duration::from_secs(2),
                "the authority must be able to query Desk while its review is in flight"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        let change = fold_gaugeapp_changes(guard.store_ref(), scope)
            .unwrap()
            .remove(approved.operation_key())
            .unwrap();
        assert_eq!(
            change.status,
            GaugeAppChangeStatus::Applying,
            "approval must commit before contacting the authority"
        );
        assert_eq!(change.reviewed_by.as_deref(), Some(approved.actor()));
    }

    fn pause_next(&self) -> (Arc<ReviewPause>, std::sync::mpsc::Sender<()>) {
        let (release, wait) = std::sync::mpsc::channel();
        let pause = Arc::new(ReviewPause {
            entered: tokio::sync::Notify::new(),
            release: Mutex::new(wait),
        });
        *self.pause.lock().unwrap() = Some(pause.clone());
        (pause, release)
    }

    fn pause_once(&self) {
        let pause = self.pause.lock().unwrap().take();
        if let Some(pause) = pause {
            pause.entered.notify_one();
            pause
                .release
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("test releases its in-flight authority call");
        }
    }
}
impl AdministrationGaugeAppExtension for ReviewAuthorityFixture {
    fn requires_external_review(&self, command: &str) -> bool {
        command == "backup.enable"
    }
    fn project(
        &self,
        _wb: &Workbench,
        _tenant: &str,
        _scope: &str,
        _actor: &str,
        capabilities: &[Capability],
    ) -> Result<Vec<AdministrationExtensionPage>, AdministrationExtensionError> {
        if !capabilities.contains(&Capability::ConfigureSecurity) {
            return Ok(Vec::new());
        }
        Ok(vec![AdministrationExtensionPage {
            id: "backups".into(),
            read_model: "BackupsPageV1".into(),
            version: 1,
            freshness: "authority-live".into(),
            model: json!({ "revision": self.effects() }),
            commands: vec![AdministrationExtensionCommand {
                id: "backup.enable".into(),
                capability: Capability::ConfigureSecurity,
                review: ReviewPolicy::Human,
            }],
        }])
    }
    fn plan(
        &self,
        _wb: &Workbench,
        _tenant: &str,
        _scope: &str,
        _actor: &str,
        command: &GaugeAppCommandEnvelope,
    ) -> Result<Option<MutationPlan>, AdministrationExtensionError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Payload {
            name: String,
        }
        if command.command_id != "backup.enable" {
            return Ok(None);
        }
        let value: Payload = serde_json::from_value(command.payload.clone()).map_err(|_| {
            AdministrationExtensionError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid closed command",
            )
        })?;
        if value.name != "approved name" {
            return Err(AdministrationExtensionError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid fixture name",
            ));
        }
        Ok(Some(Self::plan_result()))
    }
    fn apply_external_review(
        &self,
        _tenant: &str,
        scope: &str,
        approved: &ApprovedAdministrationChange,
        plan: MutationPlan,
    ) -> Result<ExternalReviewOutcome, AdministrationExtensionError> {
        self.apply_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.assert_durable_unlocked_approval(scope, approved);
        if self.mode.load(std::sync::atomic::Ordering::SeqCst) == 1 {
            return Err(AdministrationExtensionError::new(
                StatusCode::BAD_GATEWAY,
                "synthetic transport interruption",
            ));
        }
        let snapshot = serde_json::to_string(approved).unwrap();
        self.store
            .lock()
            .unwrap()
            .admit_record_facts(
                "remote",
                approved.operation_key(),
                &snapshot,
                &[CommandRecordFact {
                    scope_id: "remote".into(),
                    kind: "result".into(),
                    payload: snapshot.clone(),
                }],
            )
            .unwrap();
        self.pause_once();
        if self.mode.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            return Err(AdministrationExtensionError::new(
                StatusCode::BAD_GATEWAY,
                "must-not-echo-provider-secret",
            ));
        }
        Ok(ExternalReviewOutcome::Applied(plan))
    }
    fn recover_external_review(
        &self,
        _tenant: &str,
        scope: &str,
        approved: &ApprovedAdministrationChange,
    ) -> Result<ExternalReviewOutcome, AdministrationExtensionError> {
        self.recovery_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.assert_durable_unlocked_approval(scope, approved);
        if self.mode.load(std::sync::atomic::Ordering::SeqCst) == 2 {
            return Ok(ExternalReviewOutcome::Rejected);
        }
        let Some(record) = self
            .store
            .lock()
            .unwrap()
            .command_for_key("remote", approved.operation_key())
            .unwrap()
        else {
            self.pause_once();
            return Ok(ExternalReviewOutcome::Pending);
        };
        assert_eq!(
            record.snapshot_json,
            serde_json::to_string(approved).unwrap(),
            "recovery must retain original actor, review key, payload and basis"
        );
        self.pause_once();
        Ok(ExternalReviewOutcome::Applied(Self::plan_result()))
    }
}

fn persistent_review_app(
    root: &std::path::Path,
    remote: Arc<ReviewAuthorityFixture>,
    fault: Arc<ReviewWriteFault>,
) -> (SharedWorkbench, Router) {
    let instance = if root.join("repo").exists() {
        Instance::open(root.join("repo"), root.join("wt"))
    } else {
        Instance::init(root.join("repo"), root.join("wt")).unwrap()
    };
    let idp = LoopbackIdentityProvider::new().enroll(
        "owner-token",
        AuthorityId::new("authority:owner"),
        AuthorityAttributes::default(),
    );
    let mut wb = Workbench::with_target(
        "external-review-test",
        instance,
        Store::open(root.join("desk.sqlite").to_str().unwrap())
            .unwrap()
            .with_codec(fault),
    )
    .with_identity_provider(Arc::new(idp));
    if Org::rebuild_in(wb.store_ref(), ORG_SCOPE)
        .unwrap()
        .members
        .is_empty()
    {
        let owner = MembershipRecord {
            id: "owner".into(),
            op: RecordOp::Upsert,
            org_id: ORG_ID.into(),
            authority: "authority:owner".into(),
            email: "owner@example.test".into(),
            role: "owner".into(),
            status: MembershipStatus::Active,
            managed_by_scim: false,
            team: None,
        };
        wb.store_mut()
            .append_record(
                ORG_SCOPE,
                "membership",
                &serde_json::to_string(&owner).unwrap(),
            )
            .unwrap();
    }
    let shared = Arc::new(Mutex::new(wb));
    *remote.workbench.lock().unwrap() = Some(Arc::downgrade(&shared));
    let extension: AdministrationGaugeAppExtensionHandle = remote;
    let app = routes()
        .layer(Extension(extension))
        .with_state(shared.clone());
    (shared, app)
}

fn external_command(session: &Value, key: &str) -> Value {
    let page = session["pages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|page| page["id"] == "backups")
        .unwrap();
    json!({
        "session_id": session["id"], "generation": session["generation"], "app": "administration", "scope": session["scope"],
        "page_id": "backups", "command_id": "backup.enable", "expected_basis": page["resource_basis"], "idempotency_key": key, "payload": { "name": "approved name" }, "client": "web",
    })
}

async fn external_proposal(app: &Router, key: &str) -> (Value, String) {
    let session = open(app).await;
    let (status, response) = request(
        app,
        Method::POST,
        "/gaugeapps/administration/commands",
        external_command(&session, key),
        Some(key),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["receipt"]["status"], "proposed");
    (
        session,
        format!(
            "/gaugeapps/administration/proposals/{}/review",
            response["proposal"]["id"].as_str().unwrap()
        ),
    )
}

async fn external_review_request(
    app: &Router,
    session: &Value,
    path: &str,
    decision: &str,
    client: &str,
    key: &str,
) -> (StatusCode, Value) {
    request(app, Method::POST, path, json!({ "session_id": session["id"], "generation": session["generation"], "app": "administration", "scope": session["scope"], "decision": decision, "client": client }), Some(key)).await
}

#[tokio::test]
async fn external_review_recovers_committed_effect_after_restart_and_changed_page_basis() {
    let dir = tempfile::tempdir().unwrap();
    let remote = Arc::new(ReviewAuthorityFixture::new(
        &dir.path().join("remote.sqlite"),
    ));
    let faults = Arc::new(ReviewWriteFault(0.into()));
    let (shared, app) = persistent_review_app(dir.path(), remote.clone(), faults.clone());
    let (session, path) = external_proposal(&app, "prepare-external").await;
    let (status, pending) =
        external_review_request(&app, &session, &path, "accept", "web", "original-review").await;
    assert_eq!(status, StatusCode::ACCEPTED, "{pending}");
    assert_eq!(pending["proposal"]["status"], "applying");
    assert!(!pending.to_string().contains("must-not-echo"));
    assert_eq!(remote.effects(), 1);
    let original_receipt = pending["receipt"]["id"].clone();
    drop(app);
    drop(shared);
    drop(remote);
    let remote = Arc::new(ReviewAuthorityFixture::new(
        &dir.path().join("remote.sqlite"),
    ));
    let (_shared, app) = persistent_review_app(dir.path(), remote.clone(), faults);
    let current = open(&app).await;
    assert_ne!(current["update_cursor"], session["update_cursor"]);
    let (status, applied) =
        external_review_request(&app, &current, &path, "accept", "web", "retry-review").await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(applied["proposal"]["status"], "applied");
    assert_eq!(applied["receipt"]["id"], original_receipt);
    assert_eq!(remote.effects(), 1);
    assert_eq!(
        remote.apply_calls.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    let (status, replay) = external_review_request(
        &app,
        &current,
        &path,
        "accept",
        "web",
        "another-observation",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["receipt"], applied["receipt"]);
    assert_eq!(
        remote
            .recovery_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[tokio::test]
async fn external_review_never_calls_the_authority_before_approval_commits() {
    let dir = tempfile::tempdir().unwrap();
    let remote = Arc::new(ReviewAuthorityFixture::new(
        &dir.path().join("remote.sqlite"),
    ));
    let faults = Arc::new(ReviewWriteFault(1.into()));
    let (shared, app) = persistent_review_app(dir.path(), remote.clone(), faults);
    let (session, path) = external_proposal(&app, "prepare").await;
    let (status, _) =
        external_review_request(&app, &session, &path, "accept", "web", "review").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        remote.apply_calls.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert!(shared
        .lock()
        .unwrap()
        .store_ref()
        .records(ORG_SCOPE, "gaugeapp_external_review")
        .unwrap()
        .is_empty());
    assert!(
        fold_gaugeapp_changes(shared.lock().unwrap().store_ref(), ORG_SCOPE)
            .unwrap()
            .values()
            .all(|change| change.status == GaugeAppChangeStatus::Proposed)
    );
}

#[tokio::test]
async fn external_review_recovers_when_local_completion_cannot_commit() {
    let dir = tempfile::tempdir().unwrap();
    let remote = Arc::new(ReviewAuthorityFixture::new(
        &dir.path().join("remote.sqlite"),
    ));
    remote.mode.store(3, std::sync::atomic::Ordering::SeqCst);
    let faults = Arc::new(ReviewWriteFault(2.into()));
    let (_shared, app) = persistent_review_app(dir.path(), remote.clone(), faults.clone());
    let (session, path) = external_proposal(&app, "prepare").await;
    let (status, _) =
        external_review_request(&app, &session, &path, "accept", "web", "review").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(remote.effects(), 1);
    faults.0.store(0, std::sync::atomic::Ordering::SeqCst);
    let current = open(&app).await;
    let (status, applied) =
        external_review_request(&app, &current, &path, "accept", "web", "recover").await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(remote.effects(), 1);
    assert_eq!(
        remote.apply_calls.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[tokio::test]
async fn external_review_unknown_outcome_is_not_discarded_or_reexecuted() {
    let dir = tempfile::tempdir().unwrap();
    let remote = Arc::new(ReviewAuthorityFixture::new(
        &dir.path().join("remote.sqlite"),
    ));
    remote.mode.store(1, std::sync::atomic::Ordering::SeqCst);
    let (_shared, app) = persistent_review_app(
        dir.path(),
        remote.clone(),
        Arc::new(ReviewWriteFault(0.into())),
    );
    let (session, path) = external_proposal(&app, "prepare").await;
    assert_eq!(
        external_review_request(&app, &session, &path, "accept", "web", "review")
            .await
            .0,
        StatusCode::ACCEPTED
    );
    for client in ["web", "agent"] {
        assert_eq!(
            external_review_request(&app, &session, &path, "reject", client, "discard")
                .await
                .0,
            if client == "agent" {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::CONFLICT
            }
        );
    }
    let (status, pending) =
        external_review_request(&app, &session, &path, "accept", "web", "recover").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(pending["proposal"]["status"], "applying");
    assert_eq!(remote.effects(), 0);
    assert_eq!(
        remote.apply_calls.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    remote.mode.store(2, std::sync::atomic::Ordering::SeqCst);
    let (status, rejected) =
        external_review_request(&app, &session, &path, "accept", "web", "resolve").await;
    assert_eq!(status, StatusCode::CONFLICT, "{rejected}");
    assert_eq!(rejected["proposal"]["status"], "conflict");
}

#[tokio::test]
async fn external_review_recovery_rechecks_membership_and_rejects_agent_approval() {
    let dir = tempfile::tempdir().unwrap();
    let remote = Arc::new(ReviewAuthorityFixture::new(
        &dir.path().join("remote.sqlite"),
    ));
    let (shared, app) = persistent_review_app(
        dir.path(),
        remote.clone(),
        Arc::new(ReviewWriteFault(0.into())),
    );
    let (session, path) = external_proposal(&app, "prepare").await;
    assert_eq!(
        external_review_request(&app, &session, &path, "reject", "agent", "agent-discard")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        external_review_request(&app, &session, &path, "accept", "agent", "agent-review")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        remote.apply_calls.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        external_review_request(&app, &session, &path, "accept", "web", "human-review")
            .await
            .0,
        StatusCode::ACCEPTED
    );
    {
        let mut wb = shared.lock().unwrap();
        let mut member =
            Org::rebuild_in(wb.store_ref(), ORG_SCOPE).unwrap().members["owner"].clone();
        member.role = "member".into();
        wb.store_mut()
            .append_record(
                ORG_SCOPE,
                "membership",
                &serde_json::to_string(&member).unwrap(),
            )
            .unwrap();
    }
    let (status, _) =
        external_review_request(&app, &session, &path, "accept", "web", "removed-capability").await;
    assert!(matches!(
        status,
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED
    ));
    assert_eq!(
        remote
            .recovery_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(remote.effects(), 1);
}

#[tokio::test]
async fn external_review_cannot_reuse_one_request_for_a_different_proposal() {
    let dir = tempfile::tempdir().unwrap();
    let remote = Arc::new(ReviewAuthorityFixture::new(
        &dir.path().join("remote.sqlite"),
    ));
    remote.mode.store(1, std::sync::atomic::Ordering::SeqCst);
    let (shared, app) = persistent_review_app(
        dir.path(),
        remote.clone(),
        Arc::new(ReviewWriteFault(0.into())),
    );
    let (session, first) = external_proposal(&app, "prepare-first").await;
    let (_, second) = external_proposal(&app, "prepare-second").await;
    assert_ne!(first, second);
    assert_eq!(
        external_review_request(&app, &session, &first, "accept", "web", "one-review-key")
            .await
            .0,
        StatusCode::ACCEPTED
    );
    // Same actor, page, payload and basis; only the proposal differs. Its
    // ordinary envelope is identical, so the atomic approval claim must refuse.
    let (status, _) =
        external_review_request(&app, &session, &second, "accept", "web", "one-review-key").await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        remote.apply_calls.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    let wb = shared.lock().unwrap();
    let changes = fold_gaugeapp_changes(wb.store_ref(), ORG_SCOPE).unwrap();
    assert_eq!(
        changes
            .values()
            .filter(|change| change.status == GaugeAppChangeStatus::Applying)
            .count(),
        1
    );
    assert_eq!(
        changes
            .values()
            .filter(|change| change.status == GaugeAppChangeStatus::Proposed)
            .count(),
        1
    );
    assert_eq!(
        wb.store_ref()
            .records(ORG_SCOPE, "gaugeapp_external_review")
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn external_review_submission_retry_retains_its_receipt_with_current_pending_state() {
    let dir = tempfile::tempdir().unwrap();
    let remote = Arc::new(ReviewAuthorityFixture::new(
        &dir.path().join("remote.sqlite"),
    ));
    let (_shared, app) = persistent_review_app(
        dir.path(),
        remote.clone(),
        Arc::new(ReviewWriteFault(0.into())),
    );
    let (session, path) = external_proposal(&app, "prepare").await;
    assert_eq!(
        external_review_request(&app, &session, &path, "accept", "web", "review")
            .await
            .0,
        StatusCode::ACCEPTED
    );
    let (status, replay) = request(
        &app,
        Method::POST,
        "/gaugeapps/administration/commands",
        external_command(&session, "prepare"),
        Some("prepare"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(
        replay["receipt"]["status"], "proposed",
        "the original submission did not execute anything"
    );
    assert_eq!(
        replay["proposal"]["status"], "applying",
        "the proposal is read again, never invented from the submission receipt"
    );
    assert_eq!(
        remote.apply_calls.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[tokio::test]
async fn external_review_rejects_unknown_payload_before_journaling_and_stale_unapproved_basis() {
    let dir = tempfile::tempdir().unwrap();
    let remote = Arc::new(ReviewAuthorityFixture::new(
        &dir.path().join("remote.sqlite"),
    ));
    let (shared, app) = persistent_review_app(
        dir.path(),
        remote.clone(),
        Arc::new(ReviewWriteFault(0.into())),
    );
    let session = open(&app).await;
    for field in ["api_key", "unrecognized"] {
        let mut command = external_command(&session, field);
        command["payload"][field] = json!("synthetic-must-not-journal");
        let (status, _) = request(
            &app,
            Method::POST,
            "/gaugeapps/administration/commands",
            command,
            Some(field),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert!(
        fold_gaugeapp_changes(shared.lock().unwrap().store_ref(), ORG_SCOPE)
            .unwrap()
            .is_empty()
    );
    let (_, path) = external_proposal(&app, "prepare").await;
    // An unrelated remote change moves the page basis BEFORE approval. Recovery
    // is only for durable approved intents, not a way to accept stale proposals.
    remote
        .store
        .lock()
        .unwrap()
        .append_record("remote", "result", "{}")
        .unwrap();
    let current = open(&app).await;
    let (status, response) =
        external_review_request(&app, &current, &path, "accept", "web", "stale-review").await;
    assert_eq!(status, StatusCode::CONFLICT, "{response}");
    assert_eq!(
        remote.apply_calls.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        remote
            .recovery_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert!(shared
        .lock()
        .unwrap()
        .store_ref()
        .records(ORG_SCOPE, "gaugeapp_external_review")
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn external_review_does_not_block_desk_and_hides_confirmation_after_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let remote = Arc::new(ReviewAuthorityFixture::new(
        &dir.path().join("remote.sqlite"),
    ));
    remote.mode.store(3, std::sync::atomic::Ordering::SeqCst);
    let (shared, app) = persistent_review_app(
        dir.path(),
        remote.clone(),
        Arc::new(ReviewWriteFault(0.into())),
    );
    let (session, path) = external_proposal(&app, "prepare").await;
    let (pause, release) = remote.pause_next();
    let reviewing_app = app.clone();
    let review = tokio::spawn(async move {
        external_review_request(&reviewing_app, &session, &path, "accept", "web", "review").await
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), pause.entered.notified())
        .await
        .unwrap();
    // The remote outcome is already committed, but its response is in flight.
    // Another HTTP request and the actual membership authority remain usable.
    let current = tokio::time::timeout(std::time::Duration::from_secs(1), open(&app))
        .await
        .unwrap();
    assert_eq!(current["actor"], "authority:owner");
    {
        let mut wb = shared.try_lock().unwrap();
        let mut member =
            Org::rebuild_in(wb.store_ref(), ORG_SCOPE).unwrap().members["owner"].clone();
        member.role = "member".into();
        wb.store_mut()
            .append_record(
                ORG_SCOPE,
                "membership",
                &serde_json::to_string(&member).unwrap(),
            )
            .unwrap();
    }
    release.send(()).unwrap();
    let (status, response) = review.await.unwrap();
    assert!(
        matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
        "{response}"
    );
    assert!(response.get("result").is_none());
    assert_eq!(remote.effects(), 1);
    let changes = fold_gaugeapp_changes(shared.lock().unwrap().store_ref(), ORG_SCOPE).unwrap();
    assert!(
        changes
            .values()
            .all(|change| change.status == GaugeAppChangeStatus::Applied),
        "revoking the viewer must not erase a confirmed effect from history"
    );
}

#[tokio::test]
async fn external_review_late_pending_cannot_replace_a_concurrent_terminal_result() {
    let dir = tempfile::tempdir().unwrap();
    let remote = Arc::new(ReviewAuthorityFixture::new(
        &dir.path().join("remote.sqlite"),
    ));
    remote.mode.store(1, std::sync::atomic::Ordering::SeqCst);
    let (shared, app) = persistent_review_app(
        dir.path(),
        remote.clone(),
        Arc::new(ReviewWriteFault(0.into())),
    );
    let (session, path) = external_proposal(&app, "prepare").await;
    assert_eq!(
        external_review_request(&app, &session, &path, "accept", "web", "review")
            .await
            .0,
        StatusCode::ACCEPTED
    );
    let (pause, release) = remote.pause_next();
    let pending_app = app.clone();
    let pending_session = session.clone();
    let pending_path = path.clone();
    let pending = tokio::spawn(async move {
        external_review_request(
            &pending_app,
            &pending_session,
            &pending_path,
            "accept",
            "web",
            "pending-observation",
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), pause.entered.notified())
        .await
        .unwrap();
    let approved = shared
        .lock()
        .unwrap()
        .store_ref()
        .records(ORG_SCOPE, "gaugeapp_external_review")
        .unwrap()
        .remove(0);
    let value: Value = serde_json::from_str(&approved).unwrap();
    remote
        .store
        .lock()
        .unwrap()
        .admit_record_facts(
            "remote",
            value["change_id"].as_str().unwrap(),
            &approved,
            &[CommandRecordFact {
                scope_id: "remote".into(),
                kind: "result".into(),
                payload: approved.clone(),
            }],
        )
        .unwrap();
    let (status, completed) = external_review_request(
        &app,
        &session,
        &path,
        "accept",
        "web",
        "confirmed-observation",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{completed}");
    release.send(()).unwrap();
    let (status, late) = pending.await.unwrap();
    assert_eq!(status, StatusCode::OK, "{late}");
    assert_eq!(late["receipt"], completed["receipt"]);
    assert_eq!(late["proposal"]["status"], "applied");
    assert_eq!(
        shared
            .lock()
            .unwrap()
            .store_ref()
            .records(ORG_SCOPE, GAUGEAPP_CHANGE_KIND)
            .unwrap()
            .len(),
        3,
        "proposed, applying, applied only"
    );
}

#[tokio::test]
async fn external_review_terminal_refusal_fences_an_already_prepared_approval() {
    for refuse_as_stale in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let remote = Arc::new(ReviewAuthorityFixture::new(
            &dir.path().join("remote.sqlite"),
        ));
        let (shared, app) = persistent_review_app(
            dir.path(),
            remote.clone(),
            Arc::new(ReviewWriteFault(0.into())),
        );
        let (session, path) = external_proposal(&app, "prepare").await;
        let stale_change = fold_gaugeapp_changes(shared.lock().unwrap().store_ref(), ORG_SCOPE)
            .unwrap()
            .into_values()
            .next()
            .unwrap();
        if refuse_as_stale {
            remote
                .store
                .lock()
                .unwrap()
                .append_record("remote", "result", "{}")
                .unwrap();
        }
        let current = open(&app).await;
        let (status, _) = external_review_request(
            &app,
            &current,
            &path,
            if refuse_as_stale { "accept" } else { "reject" },
            "web",
            "terminal-review",
        )
        .await;
        assert_eq!(
            status,
            if refuse_as_stale {
                StatusCode::CONFLICT
            } else {
                StatusCode::OK
            }
        );
        // A competing worker may already have read Proposed. Model that stale
        // read explicitly: the Store claim must still stop it before any effect.
        let command = serde_json::from_value(external_command(&session, "late-approval")).unwrap();
        let session = serde_json::from_value(session).unwrap();
        let extension: AdministrationGaugeAppExtensionHandle = remote.clone();
        let response = external_review::begin(
            &mut shared.lock().unwrap(),
            &HeaderMap::new(),
            &session,
            &command,
            "late-approval",
            &stale_change,
            &extension,
            ReviewAuthorityFixture::plan_result(),
        );
        assert!(matches!(response, Err(response) if response.status() == StatusCode::CONFLICT));
        let wb = shared.lock().unwrap();
        assert!(wb
            .store_ref()
            .records(ORG_SCOPE, "gaugeapp_external_review")
            .unwrap()
            .is_empty());
        assert!(fold_gaugeapp_changes(wb.store_ref(), ORG_SCOPE)
            .unwrap()
            .values()
            .all(|change| change.status
                == if refuse_as_stale {
                    GaugeAppChangeStatus::Conflict
                } else {
                    GaugeAppChangeStatus::Rejected
                }));
        assert_eq!(
            remote.apply_calls.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }
}

#[tokio::test]
async fn external_review_service_lookup_cannot_mint_or_rewrite_approval() {
    let dir = tempfile::tempdir().unwrap();
    let remote = Arc::new(ReviewAuthorityFixture::new(
        &dir.path().join("remote.sqlite"),
    ));
    let (shared, app) =
        persistent_review_app(dir.path(), remote, Arc::new(ReviewWriteFault(0.into())));
    let (session, path) = external_proposal(&app, "prepare").await;
    let id = fold_gaugeapp_changes(shared.lock().unwrap().store_ref(), ORG_SCOPE)
        .unwrap()
        .into_keys()
        .next()
        .unwrap();
    assert!(
        stored_administration_approval(shared.lock().unwrap().store_ref(), ORG_SCOPE, &id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        external_review_request(&app, &session, &path, "accept", "web", "review")
            .await
            .0,
        StatusCode::ACCEPTED
    );
    let mut wb = shared.lock().unwrap();
    let approved = stored_administration_approval(wb.store_ref(), ORG_SCOPE, &id)
        .unwrap()
        .unwrap();
    assert_eq!(approved.actor(), "authority:owner");
    assert_eq!(approved.command().idempotency_key, "review");
    assert!(
        stored_administration_approval(wb.store_ref(), "another-organization", &id)
            .unwrap()
            .is_none()
    );
    let mut change = fold_gaugeapp_changes(wb.store_ref(), ORG_SCOPE)
        .unwrap()
        .remove(&id)
        .unwrap();
    change.payload = json!({"name":"rewritten"});
    wb.store_mut()
        .append_record(
            ORG_SCOPE,
            GAUGEAPP_CHANGE_KIND,
            &serde_json::to_string(&change).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        stored_administration_approval(wb.store_ref(), ORG_SCOPE, &id),
        Err(AdmitError::Rejected(_))
    ));
    change.status = GaugeAppChangeStatus::Conflict;
    wb.store_mut()
        .append_record(
            ORG_SCOPE,
            GAUGEAPP_CHANGE_KIND,
            &serde_json::to_string(&change).unwrap(),
        )
        .unwrap();
    assert!(
        stored_administration_approval(wb.store_ref(), ORG_SCOPE, &id)
            .unwrap()
            .is_none()
    );
}
