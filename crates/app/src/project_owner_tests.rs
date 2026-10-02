//! DR-0268 §6, DR-0309: a project's owner, and what a desktop account reaches.
use super::*;
use crate::library::{ProjectRecord, RecordOp, LIBRARY_RECORD_SCHEMA};
use crate::org::{MemberGrantRecord, MembershipRecord, MembershipStatus, ORG_ID, ORG_SCOPE};
use crate::workbench_auth::ProjectVisibility;
use crate::{LockUnpoisoned, SharedWorkbench, DEFAULT_PROJECT};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

const CLAIMANT: &str = "acct-claimant";
const OTHER: &str = "acct-other";

fn open() -> (tempfile::TempDir, SharedWorkbench) {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    (root, wb)
}

fn append(wb: &SharedWorkbench, kind: &str, record: &impl serde::Serialize) {
    wb.lock_unpoisoned()
        .store_mut()
        .append_record(ORG_SCOPE, kind, &serde_json::to_string(record).unwrap())
        .unwrap();
}

/// The claim writes its account as the computer's one active owner, which is
/// what the legacy rule reads.
fn claim(wb: &SharedWorkbench, account: &str) {
    append(
        wb,
        "membership",
        &MembershipRecord {
            id: account.into(),
            op: RecordOp::Upsert,
            org_id: ORG_ID.into(),
            authority: account.into(),
            email: String::new(),
            role: "owner".into(),
            status: MembershipStatus::Active,
            managed_by_scim: false,
            team: None,
        },
    );
}

fn grant(wb: &SharedWorkbench, account: &str, project: &str) {
    append(
        wb,
        "member_grant",
        &MemberGrantRecord {
            id: MemberGrantRecord::make_id(account, project),
            op: RecordOp::Upsert,
            authority: account.into(),
            project_id: project.into(),
        },
    );
}

fn project(wb: &SharedWorkbench, id: &str, extra: serde_json::Value) {
    let mut guard = wb.lock_unpoisoned();
    let home_id = guard.home_id().clone();
    guard.write_project_record(ProjectRecord {
        schema: LIBRARY_RECORD_SCHEMA,
        extra: serde_json::from_value(extra).unwrap(),
        id: id.into(),
        op: RecordOp::Upsert,
        name: id.into(),
        is_default: false,
        home_id,
        network_isolated: false,
        run_purpose: None,
        deployment_mode: None,
    });
}

fn owner(wb: &SharedWorkbench, id: &str) -> ProjectOwner {
    let guard = wb.lock_unpoisoned();
    let legacy = guard.legacy_project_owner();
    guard.project_owner_with(&guard.library.projects[id], &legacy)
}

fn session(wb: &SharedWorkbench, account: &str) -> String {
    wb.lock_unpoisoned()
        .mint_account_session(account, crate::desktop_session::METHOD, 3600)
        .unwrap()
}

fn visibility(wb: &SharedWorkbench, bearer: Option<&str>) -> ProjectVisibility {
    wb.lock_unpoisoned().project_visibility(bearer)
}

#[test]
fn a_project_with_no_recorded_owner_belongs_to_the_local_account_until_a_claim() {
    let (_root, wb) = open();
    project(&wb, "p-legacy", serde_json::json!({}));
    let local = wb.lock_unpoisoned().authority().as_str().to_owned();
    assert_eq!(owner(&wb, "p-legacy"), ProjectOwner::Account(local.clone()));
    assert_eq!(owner(&wb, DEFAULT_PROJECT), ProjectOwner::Account(local));

    // The founder's choice: the claim gave the claimant the computer's
    // projects, Personal included.
    claim(&wb, CLAIMANT);
    assert_eq!(
        owner(&wb, "p-legacy"),
        ProjectOwner::Account(CLAIMANT.into())
    );
    assert_eq!(
        owner(&wb, DEFAULT_PROJECT),
        ProjectOwner::Account(CLAIMANT.into())
    );
}

#[test]
fn a_recorded_owner_an_organization_and_a_learner_each_decide_ownership() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    project(&wb, "p-other", serde_json::json!({ "owner": OTHER }));
    project(
        &wb,
        "p-org",
        serde_json::json!({ "organization": "organization:abc" }),
    );
    project(
        &wb,
        "p-tutorials",
        serde_json::json!({ "product": { "kind": "tutorials", "learner": OTHER } }),
    );
    assert_eq!(owner(&wb, "p-other"), ProjectOwner::Account(OTHER.into()));
    assert_eq!(
        owner(&wb, "p-org"),
        ProjectOwner::Organization("organization:abc".into())
    );
    assert_eq!(
        owner(&wb, "p-tutorials"),
        ProjectOwner::Account(OTHER.into())
    );
}

#[test]
fn an_owner_role_no_longer_sees_another_accounts_projects() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    project(&wb, "p-legacy", serde_json::json!({}));
    project(&wb, "p-other", serde_json::json!({ "owner": OTHER }));
    project(
        &wb,
        "p-org",
        serde_json::json!({ "organization": "organization:abc" }),
    );
    grant(&wb, CLAIMANT, "p-org");

    let claimant = session(&wb, CLAIMANT);
    let ProjectVisibility::Account(seen) = visibility(&wb, Some(&claimant)) else {
        panic!("a desktop account sees what it owns or was granted");
    };
    assert!(seen.contains("p-legacy") && seen.contains(DEFAULT_PROJECT));
    assert!(seen.contains("p-org"), "a grant reaches the project");
    assert!(
        !seen.contains("p-other"),
        "the computer's owner role does not reach another account's project"
    );

    // An account holding no role here stays limited to its own projects, so
    // routes naming no project stay closed to it (WS-580).
    let other = session(&wb, OTHER);
    assert_eq!(
        visibility(&wb, Some(&other)),
        ProjectVisibility::Only(["p-other".to_owned()].into())
    );

    // The credential-free local channel keeps its view until the local
    // account has its own Personal (WS-588).
    assert_eq!(visibility(&wb, None), ProjectVisibility::All);

    let guard = wb.lock_unpoisoned();
    assert_eq!(
        guard.admit_data_request(Some(&claimant), Some("p-other")),
        Err((StatusCode::FORBIDDEN, "not in scope for this project"))
    );
    assert!(guard
        .admit_data_request(Some(&claimant), Some("p-legacy"))
        .is_ok());
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder().method(method).uri(uri).header(
        "idempotency-key",
        format!("probe-{method}-{uri}-{bearer:?}"),
    );
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

fn gated(wb: &SharedWorkbench) -> axum::Router {
    crate::open_control_plane(wb.clone()).layer(axum::middleware::from_fn_with_state(
        wb.clone(),
        account_project_gate,
    ))
}

#[tokio::test]
async fn each_account_creates_its_own_projects_and_reaches_only_those() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let app = gated(&wb);
    let claimant = session(&wb, CLAIMANT);
    let other = session(&wb, OTHER);

    let (status, created) = send(
        &app,
        "POST",
        "/projects",
        Some(&other),
        Some(serde_json::json!({ "name": "Other's" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let theirs = created["id"].as_str().unwrap().to_owned();
    assert_eq!(owner(&wb, &theirs), ProjectOwner::Account(OTHER.into()));

    let home = |id: &str| format!("/projects/{id}/home");
    assert_eq!(
        send(&app, "GET", &home(&theirs), Some(&other), None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        send(&app, "GET", &home(&theirs), Some(&claimant), None)
            .await
            .0,
        StatusCode::FORBIDDEN,
        "the claimant does not reach another account's project"
    );
    assert_eq!(
        send(&app, "GET", &home(DEFAULT_PROJECT), Some(&other), None)
            .await
            .0,
        StatusCode::FORBIDDEN,
        "another account does not reach the claimant's Personal"
    );
    assert_eq!(
        send(&app, "GET", &home(DEFAULT_PROJECT), Some(&claimant), None)
            .await
            .0,
        StatusCode::OK
    );

    // Each account's navigator lists its own projects only.
    let listed = |workspace: &serde_json::Value| {
        workspace["projects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|project| project["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    let (_, mine) = send(&app, "GET", "/workspace", Some(&claimant), None).await;
    assert!(listed(&mine).contains(&DEFAULT_PROJECT.to_owned()));
    assert!(!listed(&mine).contains(&theirs));
    let (_, yours) = send(&app, "GET", "/workspace", Some(&other), None).await;
    assert_eq!(listed(&yours), vec![theirs.clone()]);

    // The local channel creates as the computer's local account.
    let (status, created) = send(
        &app,
        "POST",
        "/projects",
        None,
        Some(serde_json::json!({ "name": "Signed out" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let local = wb.lock_unpoisoned().authority().as_str().to_owned();
    assert_eq!(
        owner(&wb, created["id"].as_str().unwrap()),
        ProjectOwner::Account(local)
    );
}
