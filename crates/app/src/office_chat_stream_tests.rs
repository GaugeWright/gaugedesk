use super::*;
use crate::ServerEvent;

async fn stream(wb: &SharedWorkbench, admission: &str, chat: &str) -> Body {
    let app = Router::new()
        .route(
            "/chats/{id}/events",
            get(crate::engagement_routes::engagement_events),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            wb.clone(),
            require_office_home_admission,
        ))
        .with_state(wb.clone());
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/chats/{chat}/events"))
                .header("authorization", format!("Bearer {ALICE}"))
                .header(HOME_ADMISSION_HEADER, admission)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    response.into_body()
}

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

async fn next(body: &mut Body) -> Option<String> {
    tokio::time::timeout(std::time::Duration::from_secs(3), body.frame())
        .await
        .expect("stream did not recheck quiet authority")
        .map(|frame| String::from_utf8(frame.unwrap().into_data().unwrap().to_vec()).unwrap())
}

#[tokio::test]
async fn office_chat_stream_checks_current_parents_before_buffered_disclosure() {
    for change in [
        "home",
        "source",
        "member",
        "grant",
        "placement",
        "software",
        "rotation",
        "project_home",
    ] {
        let root = tempfile::tempdir().unwrap();
        let (wb, app, _, _) = fixture(root.path());
        let hub = hub().await;
        install(&wb, &hub);
        let admission = admit(&app, ALICE).await;
        let chat = chat(&wb);
        let mut body = stream(&wb, &admission, &chat).await;
        assert!(next(&mut body).await.unwrap().contains("keepalive"));
        let sender = wb.lock_unpoisoned().sender(&chat);
        sender
            .send(ServerEvent::User {
                text: "synthetic clinical event".into(),
            })
            .unwrap();
        assert!(next(&mut body)
            .await
            .unwrap()
            .contains("synthetic clinical event"));
        // Queue work before access is removed: a ready broadcast is not authority.
        sender
            .send(ServerEvent::User {
                text: "must remain undisclosed".into(),
            })
            .unwrap();
        match change {
            "home" => {
                let mut guard = wb.lock_unpoisoned();
                let home = guard.home_id().clone();
                assert!(guard
                    .home_admissions
                    .revoke(&home, &AuthorityId::new("alice")));
            }
            "source" => {
                let mut guard = wb.lock_unpoisoned();
                let source = guard.office_staff_verifier().unwrap();
                let reference = crate::account_session::session_id(ALICE);
                assert!(guard
                    .observe_office_staff_check(&source, &reference, source::SourceCheck::Refused)
                    .is_err());
            }
            "member" => membership(&wb, "alice", crate::org::MembershipStatus::Deprovisioned),
            "grant" => grant(&wb, "alice", crate::library::RecordOp::Tombstone),
            "placement" => {
                let mut guard = wb.lock_unpoisoned();
                let mut record = guard.library.instances
                    [&crate::library_routes::general_placement_id("shared")]
                    .clone();
                record.project_id = Some("different".into());
                guard.write_instance_record(record);
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
            "rotation" => {
                let _ = admit(&app, ALICE).await;
            }
            "project_home" => {
                let mut guard = wb.lock_unpoisoned();
                let mut project = guard.library.projects["shared"].clone();
                project.home_id = HomeId::new("other-home");
                guard.write_project_record(project);
            }
            _ => unreachable!(),
        }
        assert!(
            next(&mut body).await.is_none(),
            "{change} leaked queued work"
        );
        assert!(next(&mut body).await.is_none());
    }
}

#[tokio::test]
async fn office_chat_stream_keeps_exact_parent_across_source_recheck_and_outage() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&app, ALICE).await;
    let chat = chat(&wb);
    let mut body = stream(&wb, &admission, &chat).await;
    assert!(next(&mut body).await.unwrap().contains("keepalive"));
    for status in [200, 503] {
        hub.state.status.store(status, Ordering::Release);
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
        wb.lock_unpoisoned()
            .sender(&chat)
            .send(ServerEvent::User {
                text: format!("same parent {status}"),
            })
            .unwrap();
        assert!(next(&mut body)
            .await
            .unwrap()
            .contains(&format!("same parent {status}")));
    }
}

#[tokio::test]
async fn quiet_office_chat_stream_ends_at_tightened_idle_deadline() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&app, ALICE).await;
    let chat = chat(&wb);
    let mut body = stream(&wb, &admission, &chat).await;
    assert!(next(&mut body).await.unwrap().contains("keepalive"));
    let policy = crate::org::SecurityPolicyRecord {
        id: "security".into(),
        idle_timeout_secs: 1,
        ..Default::default()
    };
    wb.lock_unpoisoned()
        .store_mut()
        .append_record(
            ORG_SCOPE,
            "security",
            &serde_json::to_string(&policy).unwrap(),
        )
        .unwrap();
    // The heartbeat may precede the exact deadline once; it cannot renew it.
    for _ in 0..3 {
        if next(&mut body).await.is_none() {
            return;
        }
    }
    panic!("quiet stream renewed its idle deadline");
}

#[tokio::test]
async fn quiet_office_chat_stream_closes_without_renewing_activity_or_source() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&app, ALICE).await;
    let chat = chat(&wb);
    let mut body = stream(&wb, &admission, &chat).await;
    let original = wb
        .lock_unpoisoned()
        .office_staff_lease(ALICE)
        .unwrap()
        .deadline_ms();
    let requests = hub.state.requests.lock().unwrap().len();
    for _ in 0..2 {
        assert!(next(&mut body).await.unwrap().contains("keepalive"));
    }
    assert_eq!(requests, hub.state.requests.lock().unwrap().len());
    assert_eq!(
        original,
        wb.lock_unpoisoned()
            .office_staff_lease(ALICE)
            .unwrap()
            .deadline_ms()
    );
    grant(&wb, "alice", crate::library::RecordOp::Tombstone);
    assert!(next(&mut body).await.is_none());
}
