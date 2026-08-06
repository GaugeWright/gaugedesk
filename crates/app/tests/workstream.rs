//! Workstream collaboration, end to end (`WS-D`/`WS-E`). Drives the mounted
//! `control_plane` through the whole flow: create a named workstream in a placement,
//! home two chats to it, run a member's turn, and assert the greedy auto-sync — the
//! member's work lands on the stream main, the sibling picks it up, the member's merge
//! auto-advances (no human review), the placement mainline stays isolated until an
//! explicit promote, and archiving re-homes the members.
//!
//! This lives in its own test binary (its own process). The fake runtime is enabled
//! once for that process so parallel tests cannot race a set/remove environment pair.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

use gaugedesk_app::open_control_plane;
use gaugedesk_app::Workbench;
use gaugedesk_store::Store;
use gaugedesk_workspace::Instance;

fn workbench() -> (tempfile::TempDir, Router) {
    static FAKE_RUNTIME: Once = Once::new();
    FAKE_RUNTIME.call_once(|| std::env::set_var("GAUGEDESK_FAKE_AGENT", "1"));
    let dir = tempfile::tempdir().unwrap();
    let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
    let store = Store::open_in_memory().unwrap();
    let wb = Workbench::with_target("inst-test", instance, store);
    (dir, open_control_plane(Arc::new(Mutex::new(wb))))
}

async fn send(app: &Router, method: &str, uri: &str, body: Option<&str>) -> (StatusCode, String) {
    static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
    let mut builder = Request::builder().method(method).uri(uri);
    if method != "GET" && method != "HEAD" && method != "OPTIONS" {
        builder = builder.header(
            "idempotency-key",
            format!(
                "workstream-test-{}",
                NEXT_KEY.fetch_add(1, Ordering::Relaxed)
            ),
        );
    }
    let req = match body {
        Some(b) => builder
            .header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

/// Create a workstream in the default placement and home both chats to it; returns its id.
async fn workstream_with_members(app: &Router, chats: &[&str]) -> String {
    for c in chats {
        let (s, b) = send(app, "POST", "/chats", Some(&format!(r#"{{"id":"{c}"}}"#))).await;
        assert_eq!(s, StatusCode::CREATED, "create chat {c}: {b}");
    }
    let (s, body) = send(
        app,
        "POST",
        "/placements/inst-test/workstreams",
        Some(r#"{"name":"feature","target_id":"inst-test"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "create ws: {body}");
    let ws: serde_json::Value = serde_json::from_str(&body).unwrap();
    let ws_id = ws["id"].as_str().unwrap().to_string();
    for c in chats {
        let (s, b) = send(
            app,
            "POST",
            &format!("/workstreams/{ws_id}/join"),
            Some(&format!(r#"{{"chat":"{c}"}}"#)),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "join {c}: {b}");
    }
    ws_id
}

async fn create_workstream(app: &Router, name: &str) -> String {
    let (s, body) = send(
        app,
        "POST",
        "/placements/inst-test/workstreams",
        Some(&format!(r#"{{"name":"{name}","target_id":"inst-test"}}"#)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "create {name}: {body}");
    serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn listed_members(app: &Router, workstream_id: &str) -> Vec<String> {
    let (s, body) = send(app, "GET", "/placements/inst-test/workstreams", None).await;
    assert_eq!(s, StatusCode::OK, "list workstreams: {body}");
    let list: serde_json::Value = serde_json::from_str(&body).unwrap();
    list["workstreams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == workstream_id)
        .unwrap_or_else(|| panic!("missing workstream {workstream_id}: {list}"))["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member.as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn switching_workstreams_transfers_membership_and_leave_returns_to_mainline() {
    let (_d, app) = workbench();
    let (s, body) = send(&app, "POST", "/chats", Some(r#"{"id":"switcher"}"#)).await;
    assert_eq!(s, StatusCode::CREATED, "create chat: {body}");
    let first = create_workstream(&app, "first").await;
    let second = create_workstream(&app, "second").await;

    for workstream_id in [&first, &second] {
        let (s, body) = send(
            &app,
            "POST",
            &format!("/workstreams/{workstream_id}/join"),
            Some(r#"{"chat":"switcher"}"#),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "join {workstream_id}: {body}");
    }

    assert!(
        !listed_members(&app, &first)
            .await
            .contains(&"switcher".to_string()),
        "joining a second stream removes the first membership"
    );
    assert!(
        listed_members(&app, &second)
            .await
            .contains(&"switcher".to_string()),
        "the chat belongs to the selected stream"
    );

    let (s, body) = send(
        &app,
        "POST",
        &format!("/workstreams/{second}/leave"),
        Some(r#"{"chat":"switcher"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "leave second: {body}");
    assert!(
        !listed_members(&app, &first)
            .await
            .contains(&"switcher".to_string())
            && !listed_members(&app, &second)
                .await
                .contains(&"switcher".to_string()),
        "leaving returns the chat to implicit Main, not an earlier stream"
    );

    let (s, body) = send(&app, "POST", "/chats", Some(r#"{"id":"main-peer"}"#)).await;
    assert_eq!(s, StatusCode::CREATED, "create Main peer: {body}");

    let (s, body) = send(
        &app,
        "POST",
        "/chats/switcher/task",
        Some(r#"{"prompt":"mainline after leave"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "mainline task: {body}");
    let (_s, merge) = send(&app, "GET", "/chats/switcher/merge", None).await;
    assert!(
        merge.contains("Advanced"),
        "after leave, a Main chat auto-syncs its clean turn: {merge}"
    );
    let (s, file) = send(
        &app,
        "GET",
        "/chats/main-peer/file?path=agent-note.txt",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "Main peer sees the settled line: {file}");
    assert!(
        file.contains("mainline after leave"),
        "Main siblings converge: {file}"
    );
}

#[tokio::test]
async fn switching_lines_rematerializes_destination_and_refuses_a_live_candidate() {
    let (_d, app) = workbench();
    for chat in ["moving", "other"] {
        let (status, body) = send(
            &app,
            "POST",
            "/chats",
            Some(&format!(r#"{{"id":"{chat}"}}"#)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "create {chat}: {body}");
    }
    let first = create_workstream(&app, "first").await;
    let second = create_workstream(&app, "second").await;
    for (stream, chat) in [(&first, "moving"), (&second, "other")] {
        let (status, body) = send(
            &app,
            "POST",
            &format!("/workstreams/{stream}/join"),
            Some(&format!(r#"{{"chat":"{chat}"}}"#)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "join {chat}: {body}");
    }
    for (chat, prompt) in [
        ("moving", "only the first line"),
        ("other", "only the second line"),
    ] {
        let (status, body) = send(
            &app,
            "POST",
            &format!("/chats/{chat}/task"),
            Some(&format!(r#"{{"prompt":"{prompt}"}}"#)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "task {chat}: {body}");
    }

    let (status, body) = send(
        &app,
        "POST",
        &format!("/workstreams/{second}/join"),
        Some(r#"{"chat":"moving"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "settled rehome: {body}");
    let (status, file) = send(&app, "GET", "/chats/moving/file?path=agent-note.txt", None).await;
    assert_eq!(status, StatusCode::OK, "destination file: {file}");
    assert!(
        file.contains("only the second line"),
        "destination cut materialized: {file}"
    );
    assert!(
        !file.contains("only the first line"),
        "old line did not travel: {file}"
    );

    let (status, body) = send(
        &app,
        "PUT",
        "/chats/moving/file?path=private-candidate.txt",
        Some("unsettled"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "candidate edit: {body}");
    let (status, body) = send(
        &app,
        "POST",
        &format!("/workstreams/{first}/join"),
        Some(r#"{"chat":"moving"}"#),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "candidate must block rehome: {body}"
    );
    assert!(
        body.contains("unsettled workspace changes"),
        "truthful refusal: {body}"
    );
    assert!(listed_members(&app, &second)
        .await
        .contains(&"moving".to_string()));
    let (status, file) = send(
        &app,
        "GET",
        "/chats/moving/file?path=private-candidate.txt",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(file, "unsettled");
}

#[tokio::test]
async fn member_turn_auto_syncs_to_siblings_without_touching_mainline() {
    let (_d, app) = workbench();
    let ws_id = workstream_with_members(&app, &["wsa", "wsb"]).await;

    // A member's turn: the fake agent appends to agent-note.txt and commits; the greedy
    // hook promotes it into the stream main and syncs siblings.
    let (s, b) = send(
        &app,
        "POST",
        "/chats/wsa/task",
        Some(r#"{"prompt":"do the thing"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "task: {b}");

    // The sibling's worktree now carries the member's work (auto-synced via stream main).
    let (s, file) = send(&app, "GET", "/chats/wsb/file?path=agent-note.txt", None).await;
    assert_eq!(s, StatusCode::OK, "sibling file: {file}");
    assert!(
        file.contains("do the thing"),
        "sibling picked up the member's work: {file}"
    );

    // The contributing member auto-advanced — no human-review task left hanging.
    let (_s, merge) = send(&app, "GET", "/chats/wsa/merge", None).await;
    assert!(
        merge.contains("Advanced"),
        "an in-stream contribution auto-advances: {merge}"
    );

    // The mainline is still isolated: a brand-new chat off mainline does not see the work.
    send(&app, "POST", "/chats", Some(r#"{"id":"main-chat"}"#)).await;
    let (s, _) = send(
        &app,
        "GET",
        "/chats/main-chat/file?path=agent-note.txt",
        None,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "mainline is isolated from the workstream until an explicit promote"
    );

    // After an explicit promote, the mainline carries the stream's work.
    let (s, b) = send(&app, "POST", &format!("/workstreams/{ws_id}/promote"), None).await;
    assert_eq!(s, StatusCode::OK, "promote: {b}");
    let (s, file) = send(
        &app,
        "GET",
        "/chats/main-chat/file?path=agent-note.txt",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "promoted mainline file: {file}");
    assert!(
        file.contains("do the thing"),
        "promotion makes the stream's settled work visible on Main: {file}"
    );
    // A clean promotion is terminal for the named line: every member is re-homed on
    // Main and the stream no longer appears as an active navigation destination.
    let (s, workstreams) = send(&app, "GET", "/placements/inst-test/workstreams", None).await;
    assert_eq!(s, StatusCode::OK, "list after promotion: {workstreams}");
    let workstreams: serde_json::Value = serde_json::from_str(&workstreams).unwrap();
    let promoted = workstreams["workstreams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == ws_id)
        .expect("promoted stream remains as durable archived history");
    assert_eq!(promoted["status"], "archived");
    assert_eq!(promoted["members"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn archive_rehomes_members_to_mainline() {
    let (_d, app) = workbench();
    let ws_id = workstream_with_members(&app, &["arc-a"]).await;

    // Archiving re-homes the member; Main follows the same clean auto-sync contract.
    let (s, b) = send(&app, "POST", &format!("/workstreams/{ws_id}/archive"), None).await;
    assert_eq!(s, StatusCode::OK, "archive: {b}");

    let (s, _) = send(
        &app,
        "POST",
        "/chats/arc-a/task",
        Some(r#"{"prompt":"post-archive work"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_s, merge) = send(&app, "GET", "/chats/arc-a/merge", None).await;
    assert!(
        merge.contains("Advanced"),
        "a re-homed Main chat auto-syncs a clean turn: {merge}"
    );
}
