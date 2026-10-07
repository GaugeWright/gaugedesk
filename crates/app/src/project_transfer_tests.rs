//! DR-0328 §7: signed-out work moves to a signed-in account only by an
//! explicit transfer from the window.
use super::*;
use crate::library::{
    Admission, ChatRecord, InstanceKind, InstanceRecord, PlacementKind, LIBRARY_RECORD_SCHEMA,
};
use crate::project_owner::recorded_owner;
use crate::{SharedWorkbench, DEFAULT_PROJECT};
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

const ACCOUNT: &str = "acct-receiver";
const OTHER: &str = "acct-other";

fn open() -> (tempfile::TempDir, SharedWorkbench) {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    (root, wb)
}

fn project(wb: &SharedWorkbench, id: &str, extra: serde_json::Value) {
    let mut guard = wb.lock_unpoisoned();
    let home_id = guard.home_id().clone();
    guard.write_project_record(ProjectRecord {
        schema: LIBRARY_RECORD_SCHEMA,
        extra: serde_json::from_value(extra).unwrap(),
        id: id.into(),
        op: RecordOp::Upsert,
        name: format!("{id} name"),
        is_default: false,
        home_id,
        network_isolated: false,
        run_purpose: None,
        deployment_mode: None,
    });
}

fn chat(wb: &SharedWorkbench, project: &str, id: &str, owner: Option<&str>) {
    let mut guard = wb.lock_unpoisoned();
    let instance = format!("inst-{project}");
    if !guard.library.instances.contains_key(&instance) {
        guard.write_instance_record(InstanceRecord {
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: instance.clone(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Using,
            placement_kind: PlacementKind::Work,
            agent_id: "agent-default".into(),
            project_id: Some(project.into()),
            version: 1,
            admission: Admission::Active,
            collection_recipient: None,
        });
    }
    guard.write_chat_record(ChatRecord {
        owner: owner.map(str::to_owned),
        schema: LIBRARY_RECORD_SCHEMA,
        extra: Default::default(),
        id: id.into(),
        op: RecordOp::Upsert,
        instance_id: instance,
        title: id.into(),
        created_position: 1,
        forked_from: None,
        forked_from_entry: None,
        forked_from_cut: None,
    });
}

fn session(wb: &SharedWorkbench, account: &str) -> String {
    wb.lock_unpoisoned()
        .mint_account_session(account, crate::desktop_session::METHOD, 3600)
        .unwrap()
}

fn local(wb: &SharedWorkbench) -> String {
    wb.lock_unpoisoned().authority().as_str().to_owned()
}

fn owner_of(wb: &SharedWorkbench, project: &str) -> Option<String> {
    let guard = wb.lock_unpoisoned();
    recorded_owner(&guard.library.projects[project]).map(str::to_owned)
}

fn chat_owner(wb: &SharedWorkbench, chat: &str) -> Option<String> {
    wb.lock_unpoisoned().library.chats[chat].owner.clone()
}

fn sees(wb: &SharedWorkbench, bearer: Option<&str>, project: &str) -> bool {
    wb.lock_unpoisoned()
        .project_visibility(bearer)
        .allows(project)
}

/// The window: the desktop's own operator plane, as the shell serves it.
fn window(wb: &SharedWorkbench) -> axum::Router {
    crate::open_runtime::desktop_operator_plane(wb.clone())
}

/// A plane that does not mark the window, as the relay leg does not.
fn relay(wb: &SharedWorkbench) -> axum::Router {
    crate::open_control_plane(wb.clone())
}

static KEYS: AtomicUsize = AtomicUsize::new(0);

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let key = KEYS.fetch_add(1, Ordering::Relaxed);
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("idempotency-key", format!("transfer-probe-{key}"));
    if let Some(bearer) = bearer {
        request = request.header("authorization", format!("Bearer {bearer}"));
    }
    let request = match body {
        Some(body) => request
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    }
    .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn listed(body: &serde_json::Value) -> Vec<String> {
    body["projects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|project| project["id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn a_signed_in_account_receives_the_local_accounts_project_and_its_chats() {
    let (_root, wb) = open();
    let local = local(&wb);
    project(&wb, "recorded", serde_json::json!({ "owner": local }));
    project(&wb, "legacy", serde_json::json!({}));
    chat(&wb, "recorded", "chat-local", Some(&local));
    chat(&wb, "recorded", "chat-unowned", None);
    chat(&wb, "recorded", "chat-other", Some(OTHER));
    chat(&wb, "legacy", "chat-legacy", None);
    let token = session(&wb, ACCOUNT);
    let app = window(&wb);

    let (status, body) = send(&app, "GET", "/local-projects", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["account"], ACCOUNT);
    assert_eq!(listed(&body), ["legacy", "recorded"]);
    assert_eq!(body["projects"][1]["name"], "recorded name");
    assert!(sees(&wb, None, "recorded"));
    assert!(!sees(&wb, Some(&token), "recorded"));

    let (status, body) = send(
        &app,
        "POST",
        "/local-projects/transfer",
        Some(&token),
        Some(serde_json::json!({ "projects": ["recorded"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["moved"], serde_json::json!(["recorded"]));
    assert_eq!(owner_of(&wb, "recorded").as_deref(), Some(ACCOUNT));
    assert_eq!(chat_owner(&wb, "chat-local").as_deref(), Some(ACCOUNT));
    assert_eq!(chat_owner(&wb, "chat-unowned").as_deref(), Some(ACCOUNT));
    // Someone else's chat in the project stays theirs.
    assert_eq!(chat_owner(&wb, "chat-other").as_deref(), Some(OTHER));
    // A project the person left unticked stays where it was.
    assert_eq!(owner_of(&wb, "legacy"), None);
    assert_eq!(chat_owner(&wb, "chat-legacy"), None);

    assert!(!sees(&wb, None, "recorded"));
    assert!(sees(&wb, Some(&token), "recorded"));
    assert!(sees(&wb, None, "legacy"));

    // The move is durable, not a projection of this process.
    let rebuilt = crate::library::Library::rebuild(wb.lock_unpoisoned().store_ref()).unwrap();
    assert_eq!(recorded_owner(&rebuilt.projects["recorded"]), Some(ACCOUNT));

    let (_, body) = send(&app, "GET", "/local-projects", Some(&token), None).await;
    assert_eq!(listed(&body), ["legacy"]);
}

#[tokio::test]
async fn personal_an_organizations_and_another_accounts_project_never_move() {
    let (_root, wb) = open();
    let local = local(&wb);
    project(&wb, "movable", serde_json::json!({ "owner": local }));
    project(
        &wb,
        "organization",
        serde_json::json!({ "owner": local, "organization": "organization:acme" }),
    );
    project(&wb, "others", serde_json::json!({ "owner": OTHER }));
    chat(&wb, "movable", "chat-movable", None);
    assert!(wb
        .lock_unpoisoned()
        .library
        .projects
        .get(DEFAULT_PROJECT)
        .is_some_and(|personal| personal.is_default));
    let token = session(&wb, ACCOUNT);
    let app = window(&wb);

    let (_, body) = send(&app, "GET", "/local-projects", Some(&token), None).await;
    assert_eq!(listed(&body), ["movable"]);

    for refused in [DEFAULT_PROJECT, "organization", "others", "no-such-project"] {
        let (status, body) = send(
            &app,
            "POST",
            "/local-projects/transfer",
            Some(&token),
            Some(serde_json::json!({ "projects": ["movable", refused] })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{refused}: {body}");
        // Nothing was written, not even the project that could have moved.
        assert_eq!(owner_of(&wb, "movable").as_deref(), Some(local.as_str()));
        assert_eq!(chat_owner(&wb, "chat-movable"), None);
    }
    assert_eq!(owner_of(&wb, "others").as_deref(), Some(OTHER));
    assert_eq!(
        owner_of(&wb, "organization").as_deref(),
        Some(local.as_str())
    );
    assert!(!wb.lock_unpoisoned().library.projects[DEFAULT_PROJECT]
        .extra
        .contains_key(crate::project_owner::PROJECT_OWNER_EXTRA));
}

#[tokio::test]
async fn only_the_window_with_a_signed_in_account_may_move_signed_out_work() {
    let (_root, wb) = open();
    let local = local(&wb);
    project(&wb, "movable", serde_json::json!({ "owner": local }));
    let token = session(&wb, ACCOUNT);
    let transfer = || Some(serde_json::json!({ "projects": ["movable"] }));

    // The relay leg reaches the same routes as a signed-in account, but it
    // is not the window.
    let relay = relay(&wb);
    let (status, body) = send(&relay, "GET", "/local-projects", Some(&token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body["error"].as_str().unwrap().contains("own window"),
        "{body}"
    );
    let (status, body) = send(
        &relay,
        "POST",
        "/local-projects/transfer",
        Some(&token),
        transfer(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body["error"].as_str().unwrap().contains("own window"),
        "{body}"
    );
    assert_eq!(owner_of(&wb, "movable").as_deref(), Some(local.as_str()));

    // The window signed out is the local account itself, which receives
    // nothing; a session that resolves to no account is no better.
    let app = window(&wb);
    for bearer in [None, Some("not-a-session")] {
        let (status, _) = send(&app, "GET", "/local-projects", bearer, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = send(&app, "POST", "/local-projects/transfer", bearer, transfer()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(owner_of(&wb, "movable").as_deref(), Some(local.as_str()));

    let (status, _) = send(
        &app,
        "POST",
        "/local-projects/transfer",
        Some(&token),
        Some(serde_json::json!({ "projects": [] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_hosted_home_has_no_signed_out_work_to_move() {
    let (_root, wb) = open();
    wb.lock_unpoisoned().enable_hosted_home_mode();
    let token = session(&wb, ACCOUNT);
    let (status, _) = send(&window(&wb), "GET", "/local-projects", Some(&token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[test]
fn a_tutorials_project_is_not_offered_even_to_its_learner() {
    let (_root, wb) = open();
    let local = local(&wb);
    project(&wb, "movable", serde_json::json!({ "owner": local }));
    let guard = wb.lock_unpoisoned();
    let legacy = guard.legacy_project_owner();
    let record = guard.library.projects["movable"].clone();
    assert!(guard.movable_local_project(&record, &legacy));
    let mut tutorial = record.clone();
    tutorial.extra.insert(
        "product".into(),
        serde_json::json!({ "kind": "tutorials", "learner": local }),
    );
    assert!(!guard.movable_local_project(&tutorial, &legacy));
}
