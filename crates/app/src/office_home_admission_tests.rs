use super::*;
use axum::{body::Body, http::Request, routing::get, Extension, Router};
use gaugedesk_core::ids::{AuthorityId, HomeId};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::{home_admission::HOME_ADMISSION_HEADER, org::ORG_SCOPE};

fn membership(wb: &SharedWorkbench, actor: &str, status: crate::org::MembershipStatus) {
    let record = crate::org::MembershipRecord {
        id: actor.into(),
        op: crate::library::RecordOp::Upsert,
        org_id: crate::org::ORG_ID.into(),
        authority: actor.into(),
        email: format!("{actor}@example.test"),
        role: "member".into(),
        status,
        managed_by_scim: false,
        team: None,
    };
    wb.lock_unpoisoned()
        .store_mut()
        .append_record(
            ORG_SCOPE,
            "membership",
            &serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
}

fn grant(wb: &SharedWorkbench, actor: &str, op: crate::library::RecordOp) {
    let record = crate::org::MemberGrantRecord {
        id: crate::org::MemberGrantRecord::make_id(actor, "shared"),
        op,
        authority: actor.into(),
        project_id: "shared".into(),
    };
    wb.lock_unpoisoned()
        .store_mut()
        .append_record(
            ORG_SCOPE,
            "member_grant",
            &serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
}

fn fixture(root: &std::path::Path) -> (SharedWorkbench, Router, String, String) {
    let wb = crate::open_workbench(root).unwrap();
    let (alice, bob) = {
        let mut guard = wb.lock_unpoisoned();
        crate::library_routes::create_named_project(&mut guard, "shared", "Shared").unwrap();
        (
            guard.mint_account_session("alice", "passkey", 60).unwrap(),
            guard.mint_account_session("bob", "passkey", 60).unwrap(),
        )
    };
    for actor in ["alice", "bob"] {
        membership(&wb, actor, crate::org::MembershipStatus::Active);
        grant(&wb, actor, crate::library::RecordOp::Upsert);
    }
    let app = router(wb.clone());
    (wb, app, alice, bob)
}

fn router(wb: SharedWorkbench) -> Router {
    Router::new()
        .merge(crate::home_routes::routes())
        .route(
            "/projects/{project}/inspect",
            get(
                |Extension(context): Extension<AuthenticatedActionContext>,
                 Extension(actor): Extension<crate::identity::AuthenticatedActor>,
                 headers: axum::http::HeaderMap| async move {
                    assert_eq!(crate::workbench_auth::req_scope(&headers), ORG_SCOPE);
                    for name in [
                        "cookie",
                        "x-gaugewright-machine-session",
                        "cf-connecting-ip",
                        "x-forwarded-for",
                    ] {
                        assert!(!headers.contains_key(name));
                    }
                    assert_eq!(context.actor(), &actor.0);
                    actor.0.as_str().to_owned()
                },
            ),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            wb.clone(),
            require_office_home_admission,
        ))
        .with_state(wb)
}

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    admission: Option<&str>,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    if let Some(admission) = admission {
        builder = builder.header(HOME_ADMISSION_HEADER, admission);
    }
    // Forged upstream identity and alternative credentials must never win.
    let response = app
        .clone()
        .oneshot(
            builder
                .header("cookie", "gw_session=forged")
                .header("x-gaugewright-tenant", "other-office")
                .header("cf-connecting-ip", "203.0.113.1")
                .header("x-forwarded-for", "203.0.113.2")
                .header("x-gaugewright-machine-session", "forged")
                .extension(crate::identity::AuthenticatedActor(AuthorityId::new(
                    "operator",
                )))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn admit(app: &Router, bearer: &str) -> String {
    let (status, body) = send(app, "POST", "/home/admissions", Some(bearer), None).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    serde_json::from_str::<serde_json::Value>(&body).unwrap()["admission"]
        .as_str()
        .unwrap()
        .into()
}

#[tokio::test]
async fn two_staff_keep_their_identity_and_cannot_exchange_home_admissions() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, alice, bob) = fixture(root.path());
    let a = admit(&app, &alice).await;
    let b = admit(&app, &bob).await;
    let (a_work, b_work) = tokio::join!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(&alice),
            Some(&a)
        ),
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(&bob),
            Some(&b)
        ),
    );
    assert_eq!(a_work, (StatusCode::OK, "alice".into()));
    assert_eq!(b_work, (StatusCode::OK, "bob".into()));
    assert_ne!(wb.lock_unpoisoned().authority().as_str(), "alice");
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(&alice),
            Some(&b)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&app, "GET", "/projects/shared/inspect", Some(&alice), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, "GET", "/projects/shared/inspect", None, Some(&a))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/other/inspect",
            Some(&alice),
            Some(&a)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let foreign = wb
        .lock_unpoisoned()
        .home_admissions
        .open(HomeId::new("foreign"), AuthorityId::new("alice"))
        .encode();
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(&alice),
            Some(&foreign)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn staff_boundary_refuses_operator_bootstrap_and_inactive_members() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, alice, _) = fixture(root.path());
    assert_eq!(
        send(&app, "POST", "/home/admissions", None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, "POST", "/home/admissions", Some("invalid"), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    membership(&wb, "alice", crate::org::MembershipStatus::Invited);
    assert_eq!(
        send(&app, "POST", "/home/admissions", Some(&alice), None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let empty_root = tempfile::tempdir().unwrap();
    let empty = crate::open_workbench(empty_root.path()).unwrap();
    let token = empty
        .lock_unpoisoned()
        .mint_account_session("unprovisioned", "passkey", 60)
        .unwrap();
    assert_eq!(
        send(
            &router(empty),
            "POST",
            "/home/admissions",
            Some(&token),
            None
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn each_request_rechecks_membership_project_grant_and_session() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, alice, _) = fixture(root.path());
    let a = admit(&app, &alice).await;
    grant(&wb, "alice", crate::library::RecordOp::Tombstone);
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(&alice),
            Some(&a)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    grant(&wb, "alice", crate::library::RecordOp::Upsert);
    membership(&wb, "alice", crate::org::MembershipStatus::Invited);
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(&alice),
            Some(&a)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    membership(&wb, "alice", crate::org::MembershipStatus::Active);
    wb.lock_unpoisoned()
        .account_sessions()
        .revoke_id(&crate::account_session::session_id(&alice));
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(&alice),
            Some(&a)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn stale_clients_cannot_open_or_use_staff_admissions() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, alice, _) = fixture(root.path());
    let a = admit(&app, &alice).await;
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
    for (method, path, admission) in [
        ("POST", "/home/admissions", None),
        ("GET", "/projects/shared/inspect", Some(a.as_str())),
    ] {
        assert_eq!(
            send(&app, method, path, Some(&alice), admission).await.0,
            StatusCode::UPGRADE_REQUIRED
        );
    }
}

#[tokio::test]
async fn restart_preserves_membership_but_requires_a_new_home_admission() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, alice, _) = fixture(root.path());
    let a = admit(&app, &alice).await;
    drop(app);
    drop(wb);
    let restored = crate::open_workbench(root.path()).unwrap();
    let app = router(restored);
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(&alice),
            Some(&a)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let a = admit(&app, &alice).await;
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(&alice),
            Some(&a)
        )
        .await,
        (StatusCode::OK, "alice".into())
    );
}

#[tokio::test]
async fn verified_provider_identity_and_admission_revocation_use_the_same_staff_actor() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    wb.lock_unpoisoned()
        .set_identity_provider(Some(std::sync::Arc::new(
            crate::identity::LoopbackIdentityProvider::new().enroll(
                "alice-provider",
                AuthorityId::new("alice"),
                gaugedesk_core::abac::AuthorityAttributes::default(),
            ),
        )));
    let a = admit(&app, "alice-provider").await;
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some("alice-provider"),
            Some(&a)
        )
        .await,
        (StatusCode::OK, "alice".into())
    );
    assert_eq!(
        send(
            &app,
            "DELETE",
            "/home/admissions",
            Some("alice-provider"),
            Some(&a)
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some("alice-provider"),
            Some(&a)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn durable_session_revocation_refuses_cached_staff_with_an_existing_home_admission() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, alice, bob) = fixture(root.path());
    let a = admit(&app, &alice).await;
    let b = admit(&app, &bob).await;
    {
        let mut guard = wb.lock_unpoisoned();
        let mut record = crate::account_auth::AccountAuth::rebuild(guard.store_ref())
            .unwrap()
            .sessions[&crate::account_session::session_id(&alice)]
            .clone();
        record.op = crate::account_auth::RecordOp::Tombstone;
        crate::account_auth::append_facts(
            guard.store_mut(),
            &[crate::account_auth::AccountAuthFact::Session(record)],
        )
        .unwrap();
        assert!(guard.account_sessions().resolve_now(&alice).is_some());
    }
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(&alice),
            Some(&a)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, "POST", "/home/admissions", Some(&alice), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(&bob),
            Some(&b)
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn expired_staff_session_does_not_become_the_local_operator() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, alice, _) = fixture(root.path());
    let a = admit(&app, &alice).await;
    wb.lock_unpoisoned().account_sessions().insert_loaded(
        &crate::account_session::session_id(&alice),
        "alice",
        "passkey",
        1,
    );
    assert_eq!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(&alice),
            Some(&a)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, "POST", "/home/admissions", Some(&alice), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn admitted_staff_reads_persist_distinct_actors_without_query_or_credential_content() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, alice, bob) = fixture(root.path());
    let a = admit(&app, &alice).await;
    let b = admit(&app, &bob).await;
    let (a_work, b_work) = tokio::join!(
        send(
            &app,
            "GET",
            "/projects/shared/inspect?patient=synthetic-sensitive-canary",
            Some(&alice),
            Some(&a)
        ),
        send(
            &app,
            "GET",
            "/projects/shared/inspect",
            Some(&bob),
            Some(&b)
        ),
    );
    assert_eq!(a_work.0, StatusCode::OK);
    assert_eq!(b_work.0, StatusCode::OK);
    let guard = wb.lock_unpoisoned();
    let entries = crate::audit::list(guard.store_ref());
    let mut readers: Vec<_> = entries
        .iter()
        .filter(|entry| entry.action == "home.read.admitted:/projects/{project}/inspect")
        .map(|entry| {
            assert_eq!(entry.target, "shared");
            entry.actor.as_str()
        })
        .collect();
    readers.sort();
    assert_eq!(readers, ["alice", "bob"]);
    let json = serde_json::to_string(&entries).unwrap();
    for secret in [
        "synthetic-sensitive-canary",
        alice.as_str(),
        bob.as_str(),
        a.as_str(),
        b.as_str(),
    ] {
        assert!(!json.contains(secret));
    }
    assert!(crate::audit::verify(guard.store_ref(), Some(&guard.governance_public_key())).ok);
}

#[tokio::test]
async fn unavailable_audit_storage_refuses_staff_work_before_the_handler_runs() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };
    struct UnavailableAudit;
    impl gaugedesk_store::ContentCodec for UnavailableAudit {
        fn encode(&self, scope: &str, _kind: &str, payload: &str) -> Result<String, String> {
            if scope == crate::audit::AUDIT_SCOPE {
                Err("audit storage unavailable".into())
            } else {
                Ok(payload.into())
            }
        }
        fn decode(&self, _scope: &str, _kind: &str, payload: &str) -> Option<String> {
            Some(payload.into())
        }
    }
    let store = gaugedesk_store::Store::open_in_memory()
        .unwrap()
        .with_codec(Arc::new(UnavailableAudit));
    let wb = Arc::new(Mutex::new(crate::Workbench::new(store)));
    membership(&wb, "alice", crate::org::MembershipStatus::Active);
    let (alice, admission) = {
        let mut guard = wb.lock_unpoisoned();
        let alice = guard.mint_account_session("alice", "passkey", 60).unwrap();
        let home = guard.home_id().clone();
        let admission = guard
            .home_admissions
            .open(home, AuthorityId::new("alice"))
            .encode();
        (alice, admission)
    };
    let ran = Arc::new(AtomicBool::new(false));
    let inspect = ran.clone();
    let app = Router::new()
        .route(
            "/workspace",
            get(move || {
                let ran = inspect.clone();
                async move {
                    ran.store(true, Ordering::SeqCst);
                    StatusCode::NO_CONTENT
                }
            }),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            wb.clone(),
            require_office_home_admission,
        ));
    let (status, body) = send(&app, "GET", "/workspace", Some(&alice), Some(&admission)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("office audit unavailable"));
    assert!(!ran.load(Ordering::SeqCst));
    assert!(crate::audit::list(wb.lock_unpoisoned().store_ref()).is_empty());
}

#[tokio::test]
async fn unadmitted_audit_streaming_never_receives_staff_request_metadata() {
    use std::sync::{Arc, Mutex};
    let sink = Arc::new(crate::audit::BufferAuditSink::new());
    let workbench = crate::Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap())
        .with_audit_sink(sink.clone());
    let wb = Arc::new(Mutex::new(workbench));
    membership(&wb, "alice", crate::org::MembershipStatus::Active);
    let alice = wb
        .lock_unpoisoned()
        .mint_account_session("alice", "passkey", 60)
        .unwrap();
    let app = router(wb.clone());
    let (status, body) = send(&app, "POST", "/home/admissions", Some(&alice), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("office audit streaming destination has not been admitted"));
    assert!(sink.entries().is_empty());
    assert!(crate::audit::list(wb.lock_unpoisoned().store_ref()).is_empty());
}
