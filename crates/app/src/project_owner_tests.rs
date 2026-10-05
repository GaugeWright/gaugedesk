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

/// Retain the explicit claim as well as its directory membership. The role
/// alone is not project ownership evidence (DR-0309).
fn claim(wb: &SharedWorkbench, account: &str) {
    append(
        wb,
        crate::home_owner::CLAIM_KIND,
        &crate::home_owner::HomeOwnerClaim {
            account: Some(account.into()),
            session: Some("original-claim-session".into()),
            claimed_at_ms: 1,
        },
    );
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

#[test]
fn a_sole_directory_owner_does_not_own_unclaimed_legacy_projects() {
    let (_root, wb) = open();
    project(&wb, "legacy", serde_json::json!({}));
    let local = wb.lock_unpoisoned().authority().as_str().to_owned();
    append(
        &wb,
        "membership",
        &MembershipRecord {
            id: OTHER.into(),
            op: RecordOp::Upsert,
            org_id: ORG_ID.into(),
            authority: OTHER.into(),
            email: String::new(),
            role: "owner".into(),
            status: MembershipStatus::Active,
            managed_by_scim: false,
            team: None,
        },
    );
    assert_eq!(owner(&wb, "legacy"), ProjectOwner::Account(local));
    let guard = wb.lock_unpoisoned();
    assert!(guard
        .account_project_ids(OTHER, &Org::rebuild(guard.store_ref()).unwrap())
        .is_empty());
}

#[test]
fn ambiguous_or_malformed_legacy_claims_supply_no_inferred_owner() {
    for evidence in [
        vec!["not a claim".to_owned()],
        vec![
            serde_json::to_string(&crate::home_owner::HomeOwnerClaim {
                account: Some(CLAIMANT.into()),
                session: None,
                claimed_at_ms: 1,
            })
            .unwrap();
            2
        ],
    ] {
        let (_root, wb) = open();
        project(&wb, "legacy", serde_json::json!({}));
        project(&wb, "explicit", serde_json::json!({ "owner": OTHER }));
        for raw in evidence {
            wb.lock_unpoisoned()
                .store_mut()
                .append_record(ORG_SCOPE, crate::home_owner::CLAIM_KIND, &raw)
                .unwrap();
        }
        let guard = wb.lock_unpoisoned();
        assert!(guard.legacy_project_owner().is_empty());
        assert_eq!(
            guard.project_owner_with(&guard.library.projects["explicit"], ""),
            ProjectOwner::Account(OTHER.into())
        );
        assert!(!guard
            .account_project_ids(CLAIMANT, &Org::rebuild(guard.store_ref()).unwrap())
            .contains("legacy"));
    }
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
fn project_admission_reads_durable_ownership_instead_of_the_cached_owner() {
    let (_root, wb) = open();
    wb.lock_unpoisoned().enable_hosted_home_mode();
    claim(&wb, CLAIMANT);
    project(&wb, "changed", serde_json::json!({ "owner": CLAIMANT }));
    let token = session(&wb, CLAIMANT);
    let mut guard = wb.lock_unpoisoned();
    assert!(guard
        .admit_data_request(Some(&token), Some("changed"))
        .is_ok());
    let mut record = guard.library.projects["changed"].clone();
    record_owner(&mut record.extra, OTHER);
    guard
        .store_mut()
        .append_record(
            crate::library::LIBRARY_SCOPE,
            "project",
            &serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
    assert_eq!(
        recorded_owner(&guard.library.projects["changed"]),
        Some(CLAIMANT)
    );
    assert_eq!(
        guard.admit_data_request(Some(&token), Some("changed")),
        Err((StatusCode::FORBIDDEN, "not in scope for this project"))
    );
    assert!(!guard.project_visibility(Some(&token)).allows("changed"));
    assert!(guard
        .account_project_ids(OTHER, &Org::rebuild(guard.store_ref()).unwrap())
        .contains("changed"));

    // Even an explicit grant cannot rescue unreadable ownership evidence.
    guard
        .store_mut()
        .append_record(crate::library::LIBRARY_SCOPE, "project", "not a project")
        .unwrap();
    drop(guard);
    grant(&wb, CLAIMANT, "changed");
    let guard = wb.lock_unpoisoned();
    assert!(guard
        .admit_data_request(Some(&token), Some("changed"))
        .is_err());
    assert!(!guard.project_visibility(Some(&token)).allows("changed"));
}

#[test]
fn hosted_organization_owner_and_admin_reach_only_owned_or_granted_projects() {
    for role in ["owner", "admin"] {
        let (_root, wb) = open();
        wb.lock_unpoisoned().enable_hosted_home_mode();
        append(
            &wb,
            "membership",
            &MembershipRecord {
                id: CLAIMANT.into(),
                op: RecordOp::Upsert,
                org_id: ORG_ID.into(),
                authority: CLAIMANT.into(),
                email: String::new(),
                role: role.into(),
                status: MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            },
        );
        project(&wb, "owned", serde_json::json!({ "owner": CLAIMANT }));
        project(&wb, "other", serde_json::json!({ "owner": OTHER }));
        project(&wb, "legacy", serde_json::json!({}));
        project(
            &wb,
            "organization-project",
            serde_json::json!({ "organization": "organization:abc" }),
        );
        let token = session(&wb, CLAIMANT);
        {
            let guard = wb.lock_unpoisoned();
            assert!(guard
                .admit_data_request(Some(&token), Some("owned"))
                .is_ok());
            for id in ["other", "legacy", "organization-project", DEFAULT_PROJECT] {
                assert_eq!(
                    guard.admit_data_request(Some(&token), Some(id)),
                    Err((StatusCode::FORBIDDEN, "not in scope for this project")),
                    "{role} is not project standing for {id}"
                );
            }
            assert_eq!(
                guard.project_visibility(Some(&token)),
                ProjectVisibility::Account(["owned".to_owned()].into())
            );
            // Administrative admission survives without project payload access.
            assert!(guard.admit_data_request(Some(&token), None).is_ok());
            assert!(guard
                .scoped_member_route_refusal(
                    Some(&token),
                    ORG_SCOPE,
                    &axum::http::Method::GET,
                    "/admin/members",
                    None,
                )
                .is_none());
        }
        grant(&wb, CLAIMANT, "organization-project");
        {
            let guard = wb.lock_unpoisoned();
            assert!(guard
                .admit_data_request(Some(&token), Some("organization-project"))
                .is_ok());
            assert_eq!(
                guard.project_visibility(Some(&token)),
                ProjectVisibility::Account(
                    ["owned".to_owned(), "organization-project".to_owned()].into()
                )
            );
        }
        append(
            &wb,
            "member_grant",
            &MemberGrantRecord {
                id: MemberGrantRecord::make_id(CLAIMANT, "organization-project"),
                op: RecordOp::Tombstone,
                authority: CLAIMANT.into(),
                project_id: "organization-project".into(),
            },
        );
        let guard = wb.lock_unpoisoned();
        assert!(guard
            .admit_data_request(Some(&token), Some("organization-project"))
            .is_err());
        assert_eq!(
            guard.project_visibility(Some(&token)),
            ProjectVisibility::Account(["owned".to_owned()].into())
        );
    }
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
    send_with_admission(app, method, uri, bearer, body, None).await
}

async fn send_with_admission(
    app: &axum::Router,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: Option<serde_json::Value>,
    admission: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder().method(method).uri(uri).header(
        "idempotency-key",
        format!("probe-{method}-{uri}-{bearer:?}"),
    );
    if let Some(bearer) = bearer {
        request = request.header("authorization", format!("Bearer {bearer}"));
    }
    if let Some(admission) = admission {
        request = request.header(crate::home_admission::HOME_ADMISSION_HEADER, admission);
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
async fn hosted_home_routes_and_listings_recheck_current_project_standing() {
    let (_root, wb) = open();
    wb.lock_unpoisoned().enable_hosted_home_mode();
    claim(&wb, CLAIMANT);
    project(&wb, "own-project", serde_json::json!({ "owner": CLAIMANT }));
    project(&wb, "other-project", serde_json::json!({ "owner": OTHER }));
    let token = session(&wb, CLAIMANT);
    let app = crate::open_control_plane(wb.clone()).layer(axum::middleware::from_fn_with_state(
        wb.clone(),
        crate::home_routes::require_home_admission,
    ));
    let (status, admitted) = send(&app, "POST", "/home/admissions", Some(&token), None).await;
    assert_eq!(status, StatusCode::CREATED, "{admitted}");
    let admission = admitted["admission"].as_str().unwrap();
    let read = |path: &str| {
        let path = path.to_owned();
        let app = app.clone();
        let token = token.clone();
        let admission = admission.to_owned();
        async move {
            send_with_admission(&app, "GET", &path, Some(&token), None, Some(&admission)).await
        }
    };
    assert_eq!(read("/projects/own-project/home").await.0, StatusCode::OK);
    assert_eq!(
        read("/projects/other-project/home").await.0,
        StatusCode::FORBIDDEN
    );
    let (status, workspace) = read("/workspace").await;
    assert_eq!(status, StatusCode::OK, "{workspace}");
    let listed = |workspace: &serde_json::Value| {
        workspace["projects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|project| project["id"].as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>()
    };
    assert!(!listed(&workspace).contains("other-project"));
    grant(&wb, CLAIMANT, "other-project");
    assert_eq!(read("/projects/other-project/home").await.0, StatusCode::OK);
    assert!(listed(&read("/workspace").await.1).contains("other-project"));
    append(
        &wb,
        "member_grant",
        &MemberGrantRecord {
            id: MemberGrantRecord::make_id(CLAIMANT, "other-project"),
            op: RecordOp::Tombstone,
            authority: CLAIMANT.into(),
            project_id: "other-project".into(),
        },
    );
    // The earlier Home admission token cannot preserve a revoked grant.
    assert_eq!(
        read("/projects/other-project/home").await.0,
        StatusCode::FORBIDDEN
    );
    assert!(!listed(&read("/workspace").await.1).contains("other-project"));
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

fn listed_ids(workspace: &serde_json::Value, key: &str, id: &str) -> Vec<String> {
    workspace[key]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row[id].as_str().map(str::to_owned))
        .collect()
}

#[test]
fn each_account_gets_its_own_personal_and_the_claimant_keeps_the_installs() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let mut guard = wb.lock_unpoisoned();
    // DR-0309: the claimant's Personal is the one the install already had.
    assert_eq!(
        guard.ensure_account_personal(CLAIMANT).unwrap(),
        DEFAULT_PROJECT
    );

    let personal = guard.ensure_account_personal(OTHER).unwrap();
    assert_eq!(personal, personal_project_id(OTHER));
    assert!(!personal.contains(OTHER), "no account id reaches the id");
    let record = &guard.library.projects[&personal];
    assert!(record.is_default);
    assert_eq!(record.name, "Personal");
    assert_eq!(recorded_owner(record), Some(OTHER));
    let placement = guard.personal_placement_of(&personal).unwrap();
    assert_eq!(
        placement,
        crate::library_routes::general_placement_id(&personal)
    );
    for agent in [
        crate::DEFAULT_AGENT,
        crate::app_support::SOFTWARE_ENGINEER_AGENT,
        crate::app_support::OFFICE_WORKER_AGENT,
    ] {
        assert!(
            guard.library.instances.values().any(|instance| {
                instance.agent_id == agent && instance.project_id.as_deref() == Some(&personal)
            }),
            "{agent} is placed on the new Personal as on the install's"
        );
    }

    let before = guard.library.projects.len();
    assert_eq!(guard.ensure_account_personal(OTHER).unwrap(), personal);
    assert_eq!(
        guard.library.projects.len(),
        before,
        "ensuring twice makes one"
    );
}

#[tokio::test]
async fn a_quick_chat_starts_in_the_callers_own_personal() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let app = gated(&wb);
    let claimant = session(&wb, CLAIMANT);
    let other = session(&wb, OTHER);
    let project_of = |chat: &serde_json::Value| {
        wb.lock_unpoisoned()
            .library
            .project_of_chat(chat["id"].as_str().unwrap())
            .map(str::to_owned)
    };

    let (status, chat) = send(
        &app,
        "POST",
        "/chats",
        Some(&other),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{chat}");
    assert_eq!(project_of(&chat), Some(personal_project_id(OTHER)));

    let (status, chat) = send(
        &app,
        "POST",
        "/chats",
        Some(&claimant),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{chat}");
    assert_eq!(project_of(&chat).as_deref(), Some(DEFAULT_PROJECT));

    let (status, chat) = send(&app, "POST", "/chats", None, Some(serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::CREATED, "{chat}");
    assert_eq!(
        project_of(&chat).as_deref(),
        Some(DEFAULT_PROJECT),
        "the local channel keeps the install's Personal until WS-588"
    );
}

#[tokio::test]
async fn the_navigator_marks_only_the_callers_personal_and_hides_other_projects_rows() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let app = gated(&wb);
    let claimant = session(&wb, CLAIMANT);
    let other = session(&wb, OTHER);
    let personal = wb.lock_unpoisoned().ensure_account_personal(OTHER).unwrap();

    let (_, theirs) = send(&app, "GET", "/workspace", Some(&other), None).await;
    let personals: Vec<_> = theirs["projects"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|project| project["is_personal"] == true)
        .map(|project| project["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(personals, vec![personal.clone()]);
    assert_eq!(
        listed_ids(&theirs, "projects", "id")[0],
        personal,
        "Personal first"
    );
    assert_eq!(
        theirs["personal_placement"],
        crate::library_routes::general_placement_id(&personal)
    );
    let targets = listed_ids(&theirs, "work_targets", "owner_id");
    assert!(
        !targets.iter().any(|owner| owner == DEFAULT_PROJECT),
        "another account's project targets are not listed: {targets:?}"
    );

    let (_, mine) = send(&app, "GET", "/workspace", Some(&claimant), None).await;
    assert!(!listed_ids(&mine, "projects", "id").contains(&personal));
    assert!(!listed_ids(&mine, "work_targets", "owner_id").contains(&personal));
    assert_eq!(mine["personal_placement"], crate::DEFAULT_PLACEMENT);
}

#[tokio::test]
async fn an_account_reads_the_tracker_of_a_project_it_owns_without_a_role() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let app = gated(&wb);
    let other = session(&wb, OTHER);
    let personal = wb.lock_unpoisoned().ensure_account_personal(OTHER).unwrap();
    let (status, body) = send(
        &app,
        "GET",
        &format!("/projects/{personal}/trackers"),
        Some(&other),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let claimant = session(&wb, CLAIMANT);
    let (status, _) = send(
        &app,
        "GET",
        &format!("/projects/{personal}/trackers"),
        Some(&claimant),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// An Agent made before Agents recorded owners.
fn legacy_agent(wb: &SharedWorkbench) -> String {
    let mut guard = wb.lock_unpoisoned();
    let created = guard
        .create_archetype("Legacy".into(), crate::library::AgentKind::Work, None)
        .unwrap_or_else(|_| panic!("create an Agent"));
    let mut agent = guard.library.agents[&created.id].clone();
    agent.authoring_owner = None;
    guard.write_agent_record(agent);
    created.id
}

#[test]
fn an_agent_with_no_recorded_owner_follows_the_claim_and_built_ins_stay_shared() {
    let (_root, wb) = open();
    let agent = legacy_agent(&wb);
    let local = wb.lock_unpoisoned().authority().as_str().to_owned();
    assert_eq!(
        wb.lock_unpoisoned().agent_authoring_owner(&agent),
        Some(local.clone())
    );

    claim(&wb, CLAIMANT);
    let guard = wb.lock_unpoisoned();
    assert_eq!(
        guard.agent_authoring_owner(&agent),
        Some(CLAIMANT.to_owned())
    );
    assert_eq!(
        guard.agent_authoring_owner(crate::DEFAULT_AGENT),
        Some(local),
        "the built-in Agents stay the library's own"
    );
    assert!(guard.agent_placeable_by(crate::DEFAULT_AGENT, OTHER));
    assert!(guard.agent_placeable_by(&agent, CLAIMANT));
    assert!(!guard.agent_placeable_by(&agent, OTHER));
}

#[tokio::test]
async fn an_account_places_and_uses_its_own_agents_in_its_own_personal() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let theirs = legacy_agent(&wb);
    // Until the claim goes (WS-588) a desktop admits an account to act only
    // once it holds a role here, as an invited member does.
    append(
        &wb,
        "membership",
        &MembershipRecord {
            id: OTHER.into(),
            op: RecordOp::Upsert,
            org_id: ORG_ID.into(),
            authority: OTHER.into(),
            email: String::new(),
            role: "member".into(),
            status: MembershipStatus::Active,
            managed_by_scim: false,
            team: None,
        },
    );
    let app = gated(&wb);
    let other = session(&wb, OTHER);
    let personal = wb.lock_unpoisoned().ensure_account_personal(OTHER).unwrap();

    // A new Agent is placed on its owner's Personal, not the install's.
    let mine = wb
        .lock_unpoisoned()
        .create_archetype(
            "Mine".into(),
            crate::library::AgentKind::Work,
            Some(OTHER.into()),
        )
        .unwrap_or_else(|_| panic!("create an Agent"))
        .id;
    let placed_on = |agent: &str| {
        wb.lock_unpoisoned()
            .library
            .instances
            .values()
            .filter(|instance| {
                instance.agent_id == agent && instance.kind == crate::library::InstanceKind::Using
            })
            .filter_map(|instance| instance.project_id.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(placed_on(&mine), vec![personal.clone()]);

    // Another account's Agent is not this one's to place or use.
    let (status, body) = send(
        &app,
        "POST",
        &format!("/projects/{personal}/placements"),
        Some(&other),
        Some(serde_json::json!({ "agent_id": theirs })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, _) = send(
        &app,
        "POST",
        &format!("/archetypes/{theirs}/use"),
        Some(&other),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Its own Agent is used in its own Personal.
    let (status, chat) = send(
        &app,
        "POST",
        &format!("/archetypes/{mine}/use"),
        Some(&other),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{chat}");
    assert_eq!(
        wb.lock_unpoisoned()
            .library
            .project_of_chat(chat["id"].as_str().unwrap()),
        Some(personal.as_str())
    );

    // Deleting it ends its placement in that Personal too.
    assert!(wb.lock_unpoisoned().delete_agent_cascade(&mine).is_ok());
    assert!(placed_on(&mine).is_empty());
}

#[test]
fn the_claimant_keeps_the_installs_credentials_and_another_account_has_its_own() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let claimant = session(&wb, CLAIMANT);
    let other = session(&wb, OTHER);
    let guard = wb.lock_unpoisoned();
    let install = crate::account::ACCOUNT_SCOPE.to_owned();
    assert_eq!(guard.credential_scope_for(Some(&claimant)), install);
    assert_eq!(
        guard.credential_scope_for(None),
        install,
        "the local channel shares the claimant's until WS-588"
    );
    assert_eq!(
        guard.credential_scope_for(Some(&other)),
        crate::account::account_scope(OTHER)
    );
    // A turn resolves its actor's credentials the same way.
    assert_eq!(guard.account_scope_for_actor(CLAIMANT), install);
    assert_eq!(
        guard.account_scope_for_actor(OTHER),
        crate::account::account_scope(OTHER)
    );
}

#[tokio::test]
async fn an_account_sees_and_links_only_its_own_provider_credentials() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let app = gated(&wb);
    let claimant = session(&wb, CLAIMANT);
    let other = session(&wb, OTHER);
    let link =
        |provider: &'static str| serde_json::json!({ "provider": provider, "token": "sk-test" });
    let linked = |body: serde_json::Value| {
        body["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["provider"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };

    let (status, body) = send(
        &app,
        "POST",
        "/account/credentials",
        Some(&claimant),
        Some(link("anthropic")),
    )
    .await;
    assert!(status.is_success(), "{status} {body}");
    let (status, body) = send(
        &app,
        "POST",
        "/account/credentials",
        Some(&other),
        Some(link("openai")),
    )
    .await;
    assert!(status.is_success(), "{status} {body}");

    let (_, mine) = send(&app, "GET", "/account/credentials", Some(&claimant), None).await;
    assert_eq!(linked(mine), vec!["anthropic".to_owned()]);
    let (_, theirs) = send(&app, "GET", "/account/credentials", Some(&other), None).await;
    assert_eq!(linked(theirs), vec!["openai".to_owned()]);

    // The turn path picks the actor's own link and never borrows another's.
    let guard = wb.lock_unpoisoned();
    let class = crate::account::ModelExecutionClass::LocalInteractive;
    assert!(guard
        .linked_providers_in_class(&guard.account_scope_for_actor(OTHER), class)
        .contains(&"openai".to_owned()));
    assert!(!guard
        .linked_providers_in_class(&guard.account_scope_for_actor(OTHER), class)
        .contains(&"anthropic".to_owned()));
}
