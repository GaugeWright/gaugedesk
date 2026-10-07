use super::*;
#[path = "office_chat_stream_tests.rs"]
mod chat_stream;
#[path = "office_task_authority_tests.rs"]
mod task_authority;
#[path = "office_upload_tests.rs"]
mod upload;
#[path = "office_workspace_stream_tests.rs"]
mod workspace_stream;
use std::sync::{
    atomic::{AtomicBool, AtomicU16, Ordering},
    Arc, Mutex,
};

const ALICE: &str = "native-hub-alice-session";
const BOB: &str = "native-hub-bob-session";

#[derive(Clone)]
struct HubState {
    status: Arc<AtomicU16>,
    requests: Arc<Mutex<Vec<String>>>,
    minted: u64,
    hold: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    proceed: Arc<tokio::sync::Notify>,
}
struct Hub {
    state: HubState,
    address: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Hub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn hub() -> Hub {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let state = HubState {
        status: Arc::new(AtomicU16::new(200)),
        requests: Arc::new(Mutex::new(Vec::new())),
        minted: crate::account::session_now_ms().saturating_sub(1000),
        hold: Arc::new(AtomicBool::new(false)),
        entered: Arc::new(tokio::sync::Notify::new()),
        proceed: Arc::new(tokio::sync::Notify::new()),
    };
    let app = Router::new()
        .route(
            "/account/identity",
            get(
                |axum::extract::State(state): axum::extract::State<HubState>,
                 request: Request<Body>| async move {
                    assert_eq!(request.uri().to_string(), "/account/identity");
                    for name in ["cookie", "x-gaugewright-tenant", HOME_ADMISSION_HEADER] {
                        assert!(!request.headers().contains_key(name));
                    }
                    let bearer = crate::net_http::bearer(request.headers())
                        .unwrap()
                        .to_owned();
                    state.requests.lock().unwrap().push(bearer.clone());
                    let actor = match bearer.as_str() {
                        ALICE => "alice",
                        BOB => "bob",
                        _ => return StatusCode::UNAUTHORIZED.into_response(),
                    };
                    let status =
                        StatusCode::from_u16(state.status.load(Ordering::Acquire)).unwrap();
                    if status != StatusCode::OK {
                        return status.into_response();
                    }
                    if state.hold.load(Ordering::Acquire) {
                        state.entered.notify_one();
                        state.proceed.notified().await;
                    }
                    let response = crate::account_identity::AccountIdentity {
                        holds_email: None,
                        account: actor.into(),
                        session: Some(crate::account_session::AccountSessionEvidence {
                            session_ref: crate::account_session::session_id(&bearer),
                            method: "passkey".into(),
                            issued_at_ms: state.minted,
                            expires_at_ms: state.minted + 7_200_000,
                        }),
                    };
                    ([("cache-control", "no-store")], Json(response)).into_response()
                },
            ),
        )
        .with_state(state.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Hub {
        state,
        address,
        task,
    }
}

fn install(wb: &SharedWorkbench, hub: &Hub) {
    wb.lock_unpoisoned()
        .enroll_office_profile_for_test("office-admin");
    wb.lock_unpoisoned()
        .configure_office_staff_source(source::HubStaffSource::at(&hub.address).unwrap())
        .unwrap();
}

#[tokio::test]
async fn native_staff_share_one_home_and_outage_neither_admits_new_staff_nor_renews_proof() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let alice = admit(&app, ALICE).await;
    let original = wb.lock_unpoisoned().office_staff_lease(ALICE).unwrap();
    hub.state.status.store(503, Ordering::Release);
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(ALICE),
            Some(&alice)
        )
        .await,
        (StatusCode::OK, "alice".into())
    );
    assert_eq!(
        wb.lock_unpoisoned()
            .office_staff_lease(ALICE)
            .unwrap()
            .deadline_ms(),
        original.deadline_ms()
    );
    assert_eq!(
        send(&app, "POST", "/home/admissions", Some(BOB), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    hub.state.status.store(200, Ordering::Release);
    let bob = admit(&app, BOB).await;
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(BOB),
            Some(&bob)
        )
        .await
        .1,
        "bob"
    );
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(BOB),
            Some(&alice)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let guard = wb.lock_unpoisoned();
    assert!(guard.authenticate_action_context(ALICE).is_none());
    assert!(crate::account_session::durable_evidence(
        guard.store_ref(),
        &crate::account_session::session_id(ALICE),
        "alice",
        crate::account::session_now_ms()
    )
    .unwrap()
    .is_none());
    assert_eq!(guard.actor(Some(BOB)), "bob");
    assert_ne!(
        original.reference(),
        guard.office_staff_lease(BOB).unwrap().reference()
    );
    assert!(crate::audit::list(guard.store_ref())
        .iter()
        .any(|row| row.actor == "bob"));
}

#[tokio::test]
async fn source_refusal_is_terminal_and_a_local_bearer_never_substitutes_for_native_staff() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, local_alice, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    assert_eq!(
        send(&app, "POST", "/home/admissions", Some(&local_alice), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let admission = admit(&app, ALICE).await;
    wb.lock_unpoisoned().set_identity_provider(Some(Arc::new(
        crate::identity::LoopbackIdentityProvider::new().enroll(
            ALICE,
            AuthorityId::new("owner-substitute"),
            gaugedesk_core::abac::AuthorityAttributes::default(),
        ),
    )));
    hub.state.status.store(401, Ordering::Release);
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
        StatusCode::UNAUTHORIZED
    );
    hub.state.status.store(503, Ordering::Release);
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
        StatusCode::UNAUTHORIZED
    );
    hub.state.status.store(200, Ordering::Release);
    assert_eq!(
        send(&app, "POST", "/home/admissions", Some(ALICE), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let guard = wb.lock_unpoisoned();
    assert!(guard.idp.as_ref().unwrap().authenticate(ALICE).is_some());
    assert!(guard.authenticate_bearer(ALICE).is_none());
    assert!(guard.authenticate_action_context(ALICE).is_none());
}

#[tokio::test]
async fn native_work_rechecks_local_membership_and_project_standing_during_outage() {
    for remove_member in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (wb, app, _, _) = fixture(root.path());
        let hub = hub().await;
        install(&wb, &hub);
        let admission = admit(&app, ALICE).await;
        hub.state.status.store(503, Ordering::Release);
        if remove_member {
            membership(&wb, "alice", crate::org::MembershipStatus::Deprovisioned);
        } else {
            grant(&wb, "alice", crate::library::RecordOp::Tombstone);
        }
        let result = send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(ALICE),
            Some(&admission),
        )
        .await;
        assert!(
            matches!(result.0, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED),
            "{result:?}"
        );
        assert!(!result.1.contains("Shared"));
    }
}

#[tokio::test]
async fn native_restart_needs_fresh_source_proof_and_new_exact_home_admission() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let old = admit(&app, ALICE).await;
    drop(app);
    drop(wb);
    let wb = crate::open_workbench(root.path()).unwrap();
    install(&wb, &hub);
    let app = router(wb.clone());
    hub.state.status.store(503, Ordering::Release);
    assert_eq!(
        send(&app, "POST", "/home/admissions", Some(ALICE), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    hub.state.status.store(200, Ordering::Release);
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(ALICE),
            Some(&old)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let fresh = admit(&app, ALICE).await;
    assert_ne!(fresh, old);
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(ALICE),
            Some(&fresh)
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn slow_native_verification_does_not_hold_the_home_mutex() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    hub.state.hold.store(true, Ordering::Release);
    let pending =
        tokio::spawn(
            async move { send(&app, "POST", "/home/admissions", Some(ALICE), None).await },
        );
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        hub.state.entered.notified(),
    )
    .await
    .unwrap();
    assert!(
        wb.try_lock().is_ok(),
        "source verification held the Home mutex"
    );
    hub.state.proceed.notify_one();
    assert_eq!(pending.await.unwrap().0, StatusCode::CREATED);
}

#[tokio::test]
async fn native_clients_obey_current_software_policy_even_during_sign_in_outage() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&app, ALICE).await;
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
    hub.state.status.store(503, Ordering::Release);
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
        StatusCode::UPGRADE_REQUIRED
    );
    assert_eq!(
        send(&app, "POST", "/home/admissions", Some(ALICE), None)
            .await
            .0,
        StatusCode::UPGRADE_REQUIRED
    );
}

#[tokio::test]
async fn native_admission_ceremony_supplies_identity_without_action_authority() {
    let root = tempfile::tempdir().unwrap();
    let (wb, _, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let app = Router::new()
        .route(
            "/home/admissions",
            axum::routing::post(
                |Extension(actor): Extension<crate::identity::AuthenticatedActor>,
                 context: Option<Extension<AuthenticatedActionContext>>| async move {
                    assert!(context.is_none());
                    actor.0.as_str().to_owned()
                },
            ),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            wb.clone(),
            require_office_home_admission,
        ))
        .with_state(wb.clone());
    assert_eq!(
        send(&app, "POST", "/home/admissions", Some(ALICE), None).await,
        (StatusCode::OK, "alice".into())
    );
    assert!(wb
        .lock_unpoisoned()
        .authenticate_action_context(ALICE)
        .is_none());
}

#[tokio::test]
async fn a_legacy_admission_for_the_same_person_cannot_become_office_work_authority() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, local_alice, _) = fixture(root.path());
    let legacy = admit(&app, &local_alice).await;
    let hub = hub().await;
    install(&wb, &hub);
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(ALICE),
            Some(&legacy)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let fresh = admit(&app, ALICE).await;
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(ALICE),
            Some(&fresh)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(wb
        .lock_unpoisoned()
        .configure_office_staff_source(source::HubStaffSource::at(&hub.address).unwrap())
        .is_err());
}

#[tokio::test]
async fn office_admission_holds_only_its_named_project_through_the_actual_response() {
    let root = tempfile::tempdir().unwrap();
    let (wb, admission_app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&admission_app, ALICE).await;
    let vault = wb.lock_unpoisoned().content_vault.clone().unwrap();
    assert_eq!(vault.live_sessions("shared"), 0);
    let app = Router::new()
        .route(
            "/projects/{project}/held",
            get(
                |axum::extract::State(wb): axum::extract::State<SharedWorkbench>,
                 Extension(context): Extension<AuthenticatedActionContext>| async move {
                    assert_eq!(context.actor().as_str(), "alice");
                    let vault = wb.lock_unpoisoned().content_vault.clone().unwrap();
                    assert_eq!(vault.live_sessions("shared"), 1);
                    assert_eq!(vault.live_sessions("unrelated"), 0);
                    "synthetic response"
                },
            ),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            wb.clone(),
            require_office_home_admission,
        ))
        .with_state(wb.clone());
    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/projects/shared/held")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(vault.live_sessions("shared"), 0);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/projects/shared/held")
                .header("authorization", format!("Bearer {ALICE}"))
                .header(HOME_ADMISSION_HEADER, admission)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        vault.live_sessions("shared"),
        1,
        "response still owns the hold"
    );
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(body.as_ref(), b"synthetic response");
    assert_eq!(vault.live_sessions("shared"), 0);
    assert_eq!(vault.live_sessions("unrelated"), 0);
}
