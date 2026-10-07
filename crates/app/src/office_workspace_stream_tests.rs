use super::*;
use crate::ServerEvent;

async fn stream(wb: &SharedWorkbench, admission: &str) -> Body {
    let app = Router::new()
        .route(
            "/workspace/events",
            get(crate::engagement_routes::workspace_events),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            wb.clone(),
            require_office_home_admission,
        ))
        .with_state(wb.clone());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/workspace/events")
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

async fn next(body: &mut Body) -> Option<String> {
    tokio::time::timeout(std::time::Duration::from_secs(3), body.frame())
        .await
        .expect("workspace stream did not check current authority")
        .map(|frame| String::from_utf8(frame.unwrap().into_data().unwrap().to_vec()).unwrap())
}

fn notify(wb: &SharedWorkbench, record: &str, id: &str) {
    wb.lock_unpoisoned()
        .notify_library_changed(record, id, "upsert");
}

#[tokio::test]
async fn office_workspace_stream_discloses_only_current_project_references() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hidden = "synthetic-hidden-patient-project";
    let hidden_chat = {
        let mut guard = wb.lock_unpoisoned();
        crate::library_routes::create_named_project(&mut guard, hidden, hidden).unwrap();
        guard
            .create_chat_in_instance_on_target(
                &crate::library_routes::general_placement_id(hidden),
                hidden,
                None,
            )
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&app, ALICE).await;
    let mut body = stream(&wb, &admission).await;
    assert!(next(&mut body).await.unwrap().contains("keepalive"));
    for (record, id) in [
        ("project", hidden),
        ("chat", hidden_chat.as_str()),
        ("project_tracker", hidden),
        ("account", "shared"),
        ("unknown", "shared"),
    ] {
        notify(&wb, record, id);
    }
    wb.lock_unpoisoned()
        .workspace_sender()
        .send(ServerEvent::User {
            text: "synthetic PHI on wrong channel".into(),
            client_request_id: None,
            chat_id: None,
            home_id: None,
            actor_id: None,
        })
        .unwrap();
    notify(&wb, "project_tracker", "shared");
    let frame = next(&mut body).await.unwrap();
    assert!(
        frame.contains("project_tracker") && frame.contains("shared"),
        "{frame}"
    );
    assert!(!frame.contains(hidden) && !frame.contains(&hidden_chat) && !frame.contains("PHI"));
    // No hidden/account/unknown event is delivered later, either.
    assert!(next(&mut body).await.unwrap().contains("keepalive"));
}

#[tokio::test]
async fn office_workspace_stream_refuses_queued_references_after_local_grant_removal() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&app, ALICE).await;
    let mut body = stream(&wb, &admission).await;
    assert!(next(&mut body).await.unwrap().contains("keepalive"));
    notify(&wb, "project_tracker", "shared");
    grant(&wb, "alice", crate::library::RecordOp::Tombstone);
    let frame = next(&mut body).await.unwrap();
    assert!(frame.contains("workspacechanged"));
    assert!(frame.contains("\"id\":\"\""));
    assert!(!frame.contains("shared") && !frame.contains("project_tracker"));
    // Directory changes can invalidate nav even without a workspace event.
    grant(&wb, "alice", crate::library::RecordOp::Upsert);
    assert!(next(&mut body).await.unwrap().contains("\"id\":\"\""));
}

#[tokio::test]
async fn office_workspace_stream_deletion_refresh_does_not_disclose_retired_identifier() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let chat = wb
        .lock_unpoisoned()
        .create_chat_in_instance_on_target(
            &crate::library_routes::general_placement_id("shared"),
            "synthetic chat",
            None,
        )
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&app, ALICE).await;
    let mut body = stream(&wb, &admission).await;
    assert!(next(&mut body).await.unwrap().contains("keepalive"));
    {
        let mut guard = wb.lock_unpoisoned();
        let mut record = guard.library.chats[&chat].clone();
        record.op = crate::library::RecordOp::Tombstone;
        guard.write_chat_record(record);
    }
    let frame = next(&mut body).await.unwrap();
    assert!(frame.contains("\"id\":\"\""));
    assert!(!frame.contains(&chat));
}

#[tokio::test]
async fn office_workspace_stream_closes_when_exact_admission_is_revoked() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&app, ALICE).await;
    let mut body = stream(&wb, &admission).await;
    assert!(next(&mut body).await.unwrap().contains("keepalive"));
    {
        let mut guard = wb.lock_unpoisoned();
        let home = guard.home_id().clone();
        assert!(guard
            .home_admissions
            .revoke(&home, &AuthorityId::new("alice")));
    }
    assert!(next(&mut body).await.is_none());
}

#[tokio::test]
async fn office_workspace_stream_repairs_missed_notifications_without_identifiers() {
    let root = tempfile::tempdir().unwrap();
    let (wb, app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&app, ALICE).await;
    let mut body = stream(&wb, &admission).await;
    assert!(next(&mut body).await.unwrap().contains("keepalive"));
    for _ in 0..300 {
        notify(&wb, "account", "hidden-account");
    }
    let frame = next(&mut body).await.unwrap();
    assert!(frame.contains("\"id\":\"\""));
    assert!(!frame.contains("hidden-account"));
}
