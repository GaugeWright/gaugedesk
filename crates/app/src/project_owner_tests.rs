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

    // An account holding no role here is a whole account, reaching only its
    // own projects (DR-0328).
    let other = session(&wb, OTHER);
    assert_eq!(
        visibility(&wb, Some(&other)),
        ProjectVisibility::Account(["p-other".to_owned()].into())
    );

    // Signed out, the window is the local account, which owns nothing the
    // claimant does (DR-0328 §2).
    assert_eq!(
        visibility(&wb, None),
        ProjectVisibility::Account(Default::default())
    );

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
    assert_eq!(read("/projects/own-project/models").await.0, StatusCode::OK);
    assert_eq!(
        read("/projects/other-project/models").await.0,
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
    assert_eq!(
        read("/projects/other-project/models").await.0,
        StatusCode::OK
    );
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
        read("/projects/other-project/models").await.0,
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

    let models = |id: &str| format!("/projects/{id}/models");
    assert_eq!(
        send(&app, "GET", &models(&theirs), Some(&other), None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        send(&app, "GET", &models(&theirs), Some(&claimant), None)
            .await
            .0,
        StatusCode::FORBIDDEN,
        "the claimant does not reach another account's project"
    );
    assert_eq!(
        send(&app, "GET", &models(DEFAULT_PROJECT), Some(&other), None)
            .await
            .0,
        StatusCode::FORBIDDEN,
        "another account does not reach the claimant's Personal"
    );
    assert_eq!(
        send(&app, "GET", &models(DEFAULT_PROJECT), Some(&claimant), None)
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
        project_of(&chat),
        Some(personal_project_id(crate::LOCAL_AUTHORITY)),
        "signed out, the local account works in its own Personal (DR-0328 §2)"
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
    assert_eq!(
        guard
            .credential_scope_for(Some(&claimant))
            .expect("valid credential scope"),
        install
    );
    assert_eq!(
        guard
            .credential_scope_for(None)
            .expect("valid credential scope"),
        crate::account::account_scope(guard.authority().as_str()),
        "signed out, the local account has its own (DR-0328 §2)"
    );
    assert_eq!(
        guard
            .credential_scope_for(Some(&other))
            .expect("valid credential scope"),
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

#[test]
fn a_claims_ownership_is_written_down_so_it_outlives_the_claim() {
    let (_root, wb) = open();
    project(&wb, "p-legacy", serde_json::json!({}));
    project(
        &wb,
        "p-org",
        serde_json::json!({ "organization": "organization:abc" }),
    );
    project(&wb, "p-other", serde_json::json!({ "owner": OTHER }));
    let agent = legacy_agent(&wb);

    // A computer nobody claimed already defaults to the local account.
    assert_eq!(wb.lock_unpoisoned().settle_claimed_ownership().unwrap(), 0);

    claim(&wb, CLAIMANT);
    let mut guard = wb.lock_unpoisoned();
    assert!(guard.settle_claimed_ownership().unwrap() > 0);
    let recorded = |guard: &crate::Workbench, id: &str| {
        recorded_owner(&guard.library.projects[id]).map(str::to_owned)
    };
    assert_eq!(recorded(&guard, "p-legacy").as_deref(), Some(CLAIMANT));
    assert_eq!(recorded(&guard, DEFAULT_PROJECT).as_deref(), Some(CLAIMANT));
    assert_eq!(
        recorded(&guard, "p-org"),
        None,
        "an organization project keeps its owner"
    );
    assert_eq!(recorded(&guard, "p-other").as_deref(), Some(OTHER));
    assert_eq!(
        guard.library.agents[&agent].authoring_owner.as_deref(),
        Some(CLAIMANT)
    );
    assert_eq!(
        guard.library.agents[crate::DEFAULT_AGENT].authoring_owner,
        None,
        "the built-in Agents stay the library's own"
    );
    assert_eq!(guard.install_scope_owner().as_deref(), Some(CLAIMANT));
    assert_eq!(
        guard.desktop_account_store_scope(CLAIMANT),
        crate::account::ACCOUNT_SCOPE
    );
    assert_eq!(guard.settle_claimed_ownership().unwrap(), 0, "idempotent");
}

fn bearer_headers(token: &str) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    headers
}

#[test]
fn only_a_projects_owner_takes_its_owner_acts() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    project(&wb, "p-other", serde_json::json!({ "owner": OTHER }));
    project(
        &wb,
        "p-org",
        serde_json::json!({ "organization": "organization:abc" }),
    );
    let claimant = bearer_headers(&session(&wb, CLAIMANT));
    let other = bearer_headers(&session(&wb, OTHER));
    let guard = wb.lock_unpoisoned();
    let refused = |headers: &axum::http::HeaderMap, project: &str| {
        guard
            .project_owner_refusal(headers, project)
            .map(|response| response.status())
    };
    assert_eq!(refused(&claimant, DEFAULT_PROJECT), None);
    assert_eq!(
        refused(&other, DEFAULT_PROJECT),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(refused(&other, "p-other"), None);
    assert_eq!(refused(&claimant, "p-other"), Some(StatusCode::FORBIDDEN));
    assert_eq!(
        refused(&other, "p-org"),
        None,
        "an organization's project keeps its organization's own checks"
    );
    assert_eq!(
        refused(&other, "no-such-project"),
        None,
        "left to the handler's 404"
    );
    assert_eq!(
        refused(&axum::http::HeaderMap::new(), DEFAULT_PROJECT),
        None,
        "the local channel keeps its view until it is the local account"
    );
    // A placement answers for its project.
    let placement = crate::app_support::DEFAULT_PLACEMENT;
    assert_eq!(
        guard
            .placement_owner_refusal(&other, placement)
            .map(|response| response.status()),
        Some(StatusCode::FORBIDDEN)
    );
    assert!(guard
        .placement_owner_refusal(&claimant, placement)
        .is_none());
}

#[tokio::test]
async fn an_account_cannot_invite_into_another_accounts_project() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let app = crate::open_control_plane(wb.clone());
    let other = session(&wb, OTHER);
    // An organization role is not project ownership (DR-0268 §1, DR-0328 §4).
    append(
        &wb,
        "membership",
        &MembershipRecord {
            id: OTHER.into(),
            op: RecordOp::Upsert,
            org_id: ORG_ID.into(),
            authority: OTHER.into(),
            email: String::new(),
            role: "admin".into(),
            status: MembershipStatus::Active,
            managed_by_scim: false,
            team: None,
        },
    );
    let (status, body) = send(
        &app,
        "POST",
        "/home/invitations",
        Some(&other),
        Some(serde_json::json!({
            "authority": "acct-invitee",
            "project": DEFAULT_PROJECT,
            "role": "member",
            "endpoint": "https://home.example.test",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "only this project's owner may do that");
}

#[tokio::test]
async fn signed_out_the_window_is_the_local_account_on_a_claimed_computer() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    wb.lock_unpoisoned().settle_claimed_ownership().unwrap();
    let app = gated(&wb);
    let models = |id: &str| format!("/projects/{id}/models");

    // The claimant's projects, Personal included, are not the local account's.
    assert_eq!(
        send(&app, "GET", &models(DEFAULT_PROJECT), None, None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (_, workspace) = send(&app, "GET", "/workspace", None, None).await;
    assert!(!listed_ids(&workspace, "projects", "id").contains(&DEFAULT_PROJECT.to_owned()));

    // It works in a Personal of its own, and its tracker there.
    let (status, chat) = send(&app, "POST", "/chats", None, Some(serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::CREATED, "{chat}");
    let personal = personal_project_id(crate::LOCAL_AUTHORITY);
    assert_eq!(
        send(&app, "GET", &models(&personal), None, None).await.0,
        StatusCode::OK
    );
    let (_, workspace) = send(&app, "GET", "/workspace", None, None).await;
    assert_eq!(listed_ids(&workspace, "projects", "id")[0], personal);
    let guard = wb.lock_unpoisoned();
    assert!(guard.local_personal_tracker_context(&personal).is_some());
    assert!(guard
        .local_personal_tracker_context(DEFAULT_PROJECT)
        .is_none());
}

#[test]
fn an_unclaimed_computers_local_account_keeps_the_installs_personal_and_credentials() {
    let (_root, wb) = open();
    let mut guard = wb.lock_unpoisoned();
    assert_eq!(
        guard
            .request_personal(&axum::http::HeaderMap::new())
            .unwrap(),
        None,
        "the install's Personal is the local account's"
    );
    assert_eq!(
        guard
            .credential_scope_for(None)
            .expect("valid credential scope"),
        crate::account::ACCOUNT_SCOPE
    );
    assert!(guard.project_visibility(None).allows(DEFAULT_PROJECT));
}

fn join(wb: &SharedWorkbench, account: &str, role: &str) {
    append(
        wb,
        "membership",
        &MembershipRecord {
            id: account.into(),
            op: RecordOp::Upsert,
            org_id: ORG_ID.into(),
            authority: account.into(),
            email: String::new(),
            role: role.into(),
            status: MembershipStatus::Active,
            managed_by_scim: false,
            team: None,
        },
    );
}

#[test]
fn a_pairing_belongs_to_the_account_that_made_it() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let ticket = |authority: &str| crate::federation::PairingTicket {
        authority: authority.into(),
        governance_pubkey: String::new(),
        cert_fingerprint: String::new(),
        broker_addr: String::new(),
        scope: "bridge:invoke".into(),
        expiry: 0,
    };
    let mut guard = wb.lock_unpoisoned();
    crate::federation::persist_bridge(guard.store_mut(), &ticket("peer-legacy"), "g1", true);
    crate::federation::persist_bridge_for(
        guard.store_mut(),
        &ticket("peer-other"),
        "g2",
        true,
        Some(OTHER),
    );
    let bridges = crate::federation::folded_bridges(guard.store_ref());
    let owner = |id: &str| guard.bridge_owner(bridges.iter().find(|b| b.id == id).unwrap());
    assert_eq!(
        owner("peer-legacy"),
        CLAIMANT,
        "an older pairing is the legacy owner's"
    );
    assert_eq!(owner("peer-other"), OTHER);

    let signed_out = axum::http::HeaderMap::new();
    assert_eq!(
        guard.pairing_actor(&signed_out).as_deref(),
        Some(guard.authority().as_str())
    );
    let unknown = bearer_headers("not-a-session");
    assert_eq!(
        guard.pairing_actor(&unknown).as_deref(),
        Some(""),
        "a session that resolves to no account owns nothing"
    );
}

#[tokio::test]
async fn a_device_pairing_is_accepted_only_by_its_own_account() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    join(&wb, OTHER, "member");
    let app = gated(&wb);
    let claimant = session(&wb, CLAIMANT);
    let other = session(&wb, OTHER);

    let (status, pairing) = send(
        &app,
        "POST",
        "/pairing-requests",
        Some(&other),
        Some(serde_json::json!({ "device": "device-1" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{pairing}");
    let accept = format!(
        "/boundaries/{}/accept",
        pairing["pairing_id"].as_str().unwrap()
    );

    let (status, body) = send(
        &app,
        "POST",
        &accept,
        Some(&claimant),
        Some(serde_json::json!({ "participant": OTHER })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = send(
        &app,
        "POST",
        &accept,
        Some(&other),
        Some(serde_json::json!({ "participant": OTHER })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

const EDGE: &str = "https://edge.example.test";

fn bind_deployment(wb: &SharedWorkbench, deployment: &str, project: &str, publisher: Option<&str>) {
    use crate::library::{
        DeploymentAudience, DeploymentBindingStatus, DeploymentOperationalConfig,
        PublicDeploymentBindingRecord,
    };
    let mut extra = std::collections::BTreeMap::new();
    if let Some(publisher) = publisher {
        extra.insert(
            crate::agent_release::BINDING_PUBLISHER_EXTRA.to_owned(),
            serde_json::Value::String(publisher.to_owned()),
        );
    }
    wb.lock_unpoisoned()
        .write_public_deployment_record(PublicDeploymentBindingRecord {
            schema: LIBRARY_RECORD_SCHEMA,
            extra,
            id: format!("binding-{deployment}"),
            op: RecordOp::Upsert,
            project_id: project.into(),
            placement_id: "inst-panel".into(),
            hosted_deployment_id: deployment.into(),
            edge_origin: EDGE.into(),
            active_release_id: Some("sha256:release".into()),
            operational: DeploymentOperationalConfig {
                allowed_origins: vec!["https://site.example.test".into()],
                audience: DeploymentAudience::default(),
                funding_ref: "managed:plan".into(),
                credential_class: "managed".into(),
                credential_ref: String::new(),
                max_spend_cents: None,
                max_session_spend_cents: None,
                max_turn_spend_cents: None,
                per_visitor_turn_limit: 10,
                max_concurrent_sessions: 10,
                white_label: false,
                retention_idle_ttl_seconds: 600,
                retention_absolute_ttl_seconds: 3600,
            },
            status: DeploymentBindingStatus::Active,
        })
        .unwrap();
}

/// The public key and authority a credential presents to the edge.
fn presented(credential: crate::agent_release::PublisherCredential) -> (String, String) {
    (credential.public_key(), credential.authority().to_owned())
}

#[test]
fn each_account_publishes_under_its_own_key_and_the_claimant_keeps_the_installs() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    project(&wb, "p-mine", serde_json::json!({ "owner": CLAIMANT }));
    project(&wb, "p-other", serde_json::json!({ "owner": OTHER }));
    project(
        &wb,
        "p-org",
        serde_json::json!({ "organization": "organization:abc" }),
    );
    let guard = wb.lock_unpoisoned();
    let install = presented(guard.publisher_credential().unwrap());
    assert_eq!(
        install.1,
        format!("gaugedesk:{}", guard.authority().as_str()),
        "the install's authority is unchanged"
    );
    assert_eq!(install.0, guard.public_publisher_key().unwrap());

    // The claimant, and the local account, keep the install's key and
    // authority, so everything already published keeps verifying.
    for account in [CLAIMANT, guard.authority().as_str()] {
        assert_eq!(
            presented(guard.publisher_credential_for(account).unwrap()),
            install
        );
    }
    for project in [DEFAULT_PROJECT, "p-mine", "p-org"] {
        assert_eq!(
            presented(guard.project_publisher_credential(project).unwrap()),
            install,
            "{project}"
        );
    }

    // Another account has a key of its own, under its own authority, and it
    // is the same key every time.
    let other = presented(guard.project_publisher_credential("p-other").unwrap());
    assert_ne!(other.0, install.0);
    assert_eq!(other.1, format!("gaugedesk:{OTHER}"));
    assert_eq!(
        presented(guard.publisher_credential_for(OTHER).unwrap()),
        other
    );
    assert_eq!(
        presented(guard.publisher_credential_for(OTHER).unwrap()),
        other,
        "the key is kept, not minted again"
    );
}

#[test]
fn an_unclaimed_computers_local_account_keeps_the_installs_publisher() {
    let (_root, wb) = open();
    project(&wb, "p-legacy", serde_json::json!({}));
    let guard = wb.lock_unpoisoned();
    let install = presented(guard.publisher_credential().unwrap());
    assert_eq!(
        presented(guard.project_publisher_credential("p-legacy").unwrap()),
        install
    );
    assert_ne!(
        presented(guard.publisher_credential_for(OTHER).unwrap()).0,
        install.0
    );
}

#[test]
fn a_deployment_stays_with_the_key_that_published_it() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    project(&wb, "p-other", serde_json::json!({ "owner": OTHER }));
    // Published before per-account publishing: no recorded publisher.
    bind_deployment(&wb, "dep-legacy", "p-other", None);
    bind_deployment(&wb, "dep-other", "p-other", Some(OTHER));
    let guard = wb.lock_unpoisoned();
    let install = guard.publisher_credential().unwrap().public_key();
    let other = guard.publisher_credential_for(OTHER).unwrap().public_key();
    let binding = |deployment: &str| {
        guard
            .library
            .public_deployments
            .values()
            .find(|binding| binding.hosted_deployment_id == deployment)
            .unwrap()
            .clone()
    };
    assert_eq!(
        guard
            .binding_publisher_credential(&binding("dep-legacy"))
            .unwrap()
            .public_key(),
        install,
        "a deployment published before this stays with the claimant"
    );
    assert_eq!(
        guard
            .binding_publisher_credential(&binding("dep-other"))
            .unwrap()
            .public_key(),
        other
    );
    // A republish signs with the deployment's key, and a new deployment from
    // the project with its owner's.
    let publication = |deployment: &str| {
        guard
            .publication_publisher_key("inst-panel", EDGE, deployment)
            .unwrap()
    };
    assert_eq!(publication("dep-legacy"), install);
    assert_eq!(publication("dep-other"), other);
    drop(guard);
    let mut guard = wb.lock_unpoisoned();
    let personal = guard.ensure_account_personal(OTHER).unwrap();
    let placement = guard
        .personal_placement_of(&personal)
        .expect("a Personal has a placement");
    assert_eq!(
        guard
            .publication_publisher_key(&placement, EDGE, "dep-new")
            .unwrap(),
        other
    );
}

#[tokio::test]
async fn the_publisher_authority_answers_for_its_caller() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let app = gated(&wb);
    let claimant = session(&wb, CLAIMANT);
    let other = session(&wb, OTHER);
    let (install, own) = {
        let guard = wb.lock_unpoisoned();
        (
            guard.public_publisher_key().unwrap(),
            guard.publisher_credential_for(OTHER).unwrap().public_key(),
        )
    };
    let read = |bearer: Option<String>| {
        let app = app.clone();
        async move {
            let (status, body) = send(
                &app,
                "GET",
                "/public-deployments/publisher-authority",
                bearer.as_deref(),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body["public_key"].as_str().unwrap().to_owned()
        }
    };
    assert_eq!(read(Some(claimant)).await, install);
    assert_eq!(read(None).await, install, "the local channel");
    assert_ne!(own, install);
    assert_eq!(read(Some(other)).await, own);
}

/// Named a publication, the read answers with the key that publication signs
/// with, so an entitlement a remote Home's client mints for it matches the
/// key the edge sees, even when that is not the caller's own (WS-749).
#[tokio::test]
async fn the_publisher_authority_answers_for_a_named_publication() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    // Published by the claimant before per-account publishing.
    bind_deployment(&wb, "dep-legacy", "p-other", None);
    let app = gated(&wb);
    let claimant = session(&wb, CLAIMANT);
    let other = session(&wb, OTHER);
    let (install, own, placement) = {
        let mut guard = wb.lock_unpoisoned();
        let personal = guard.ensure_account_personal(OTHER).unwrap();
        (
            guard.public_publisher_key().unwrap(),
            guard.publisher_credential_for(OTHER).unwrap().public_key(),
            guard
                .personal_placement_of(&personal)
                .expect("a Personal has a placement"),
        )
    };
    let edge = "https%3A%2F%2Fedge.example.test";
    let read = |bearer: &str, query: String| {
        let app = app.clone();
        let bearer = bearer.to_owned();
        async move {
            send(
                &app,
                "GET",
                &format!("/public-deployments/publisher-authority?{query}"),
                Some(&bearer),
                None,
            )
            .await
        }
    };
    let publication = |deployment: &str| {
        format!("placement_id={placement}&edge_origin={edge}&deployment_id={deployment}")
    };

    let (status, body) = read(&other, publication("dep-legacy")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["public_key"], install,
        "a republish of a claimant's deployment signs with the install's key"
    );
    let (status, body) = read(&other, publication("dep-new")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["public_key"], own,
        "a new deployment signs with the owner's"
    );

    // Reading a publication's key is its placement owner's, as publishing is.
    let (status, body) = read(&claimant, publication("dep-new")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // A publication is named whole or not at all.
    let (status, body) = read(&other, format!("placement_id={placement}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = read(
        &other,
        format!("placement_id={placement}&edge_origin=ftp%3A%2F%2Fx&deployment_id=dep-new"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[test]
fn off_a_desktop_there_is_only_the_installs_publisher() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    project(&wb, "p-other", serde_json::json!({ "owner": OTHER }));
    let mut guard = wb.lock_unpoisoned();
    guard.enable_hosted_home_mode();
    let install = presented(guard.publisher_credential().unwrap());
    assert_eq!(
        presented(guard.publisher_credential_for(OTHER).unwrap()),
        install
    );
    assert_eq!(
        presented(guard.project_publisher_credential("p-other").unwrap()),
        install
    );
    assert_eq!(
        guard.public_publisher_key_as(Some(OTHER)).unwrap(),
        install.0
    );
}

/// A synthetic edge that admits a first BYOK publication and records the
/// publisher authority and key every command presented, and every body.
#[allow(clippy::type_complexity)]
pub(crate) fn recording_edge() -> (
    String,
    std::sync::Arc<std::sync::Mutex<Vec<(String, String, String, Vec<u8>)>>>,
) {
    use std::io::{BufRead, Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let shared = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap_or_default().to_owned();
            let path = parts.next().unwrap_or_default().to_owned();
            let (mut length, mut authority, mut key) = (0_usize, String::new(), String::new());
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header.trim().is_empty() {
                    break;
                }
                let (name, value) = header.split_once(':').unwrap_or_default();
                let value = value.trim().to_owned();
                match name.to_ascii_lowercase().as_str() {
                    "content-length" => length = value.parse().unwrap_or_default(),
                    "x-gw-publisher-authority" => authority = value,
                    "x-gw-publisher-key" => key = value,
                    _ => {}
                }
            }
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes).unwrap();
            let (status, response) = if method == "GET" && path == "/v1/public-credentials" {
                (
                    200,
                    serde_json::json!({ "credentials": [{
                        "credential_ref": "credential:public:mine:openai:key",
                        "provider": "openai",
                        "credential_class": "openai-api-key",
                    }] }),
                )
            } else if method == "GET" {
                (404, serde_json::json!({ "error": "not found" }))
            } else {
                (
                    200,
                    serde_json::json!({ "deployment": { "lifecycle": "active" } }),
                )
            };
            shared
                .lock()
                .unwrap()
                .push((format!("{method} {path}"), authority, key, bytes));
            let response = response.to_string();
            write!(
                stream,
                "HTTP/1.1 {status} Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response}",
                response.len()
            )
            .unwrap();
        }
    });
    (origin, seen)
}

#[test]
fn a_publication_from_another_accounts_project_is_signed_and_recorded_as_its() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let (edge, seen) = recording_edge();
    let own = {
        let mut guard = wb.lock_unpoisoned();
        let seeded = guard
            .seed_panel_placement("inst-panel", crate::library::PanelPublicProfile::default())
            .unwrap();
        let project = seeded["project_id"].as_str().unwrap().to_owned();
        let mut record = guard.library.projects[&project].clone();
        record_owner(&mut record.extra, OTHER);
        guard.write_project_record(record);
        guard.publisher_credential_for(OTHER).unwrap()
    };
    let mut request: crate::agent_release::PublishDeploymentRequest =
        serde_json::from_value(serde_json::json!({
            "placement_id": "inst-panel",
            "deployment_id": "theirs",
            "edge_origin": edge,
            "allowed_origins": ["https://customer.example"],
            "per_visitor_turn_limit": 5,
            "max_concurrent_sessions": 5,
            "funding_ref": "credential:public:mine:openai:key",
            "credential_ref": "credential:public:mine:openai:key",
            "audience": { "anonymous_allowed": true },
            "white_label": false,
            "end_sessions": false,
        }))
        .unwrap();
    request.work_chat_default_model = Some("gpt-5.5".to_owned());
    let mut guard = wb.lock_unpoisoned();
    let outcome = guard.publish_agent_deployment(request).unwrap();
    assert_eq!(
        guard.library.public_deployments[&outcome.binding_id].extra
            [crate::agent_release::BINDING_PUBLISHER_EXTRA],
        OTHER
    );
    guard
        .control_public_deployment(crate::agent_release::ControlDeploymentRequest {
            deployment_id: "theirs".into(),
            edge_origin: edge.clone(),
            command: "pause".into(),
            expected_revision: 1,
        })
        .unwrap();

    let seen = seen.lock().unwrap();
    assert!(seen.len() >= 4, "{seen:?}");
    for (command, authority, key, _) in seen.iter() {
        assert_eq!(authority, own.authority(), "{command}");
        assert_eq!(key, &own.public_key(), "{command}");
    }
    let release = seen
        .iter()
        .find(|(command, ..)| command.starts_with("PUT /v1/releases/"))
        .map(|(.., body)| body)
        .unwrap();
    let release: gaugedesk_core::agent_release::SignedAgentRelease =
        ciborium::from_reader(release.as_slice()).unwrap();
    assert_eq!(release.signer_key_id, own.authority());
    assert_eq!(release.signer_public_key.as_str(), own.public_key());
    assert_eq!(release.payload.host_policy.expected_signer, OTHER);
    assert_eq!(
        release.payload.host_policy.signer_public_key_hex,
        own.public_key()
    );
}

/// The token a management agent turn would run on for `actor`, or the
/// refusal it would answer with. `AgentCredential` holds a secret and so is
/// deliberately not `Debug`; this flattens it for assertions.
fn management_agent_token(
    wb: &SharedWorkbench,
    actor: &str,
) -> Result<String, crate::gaugeapp_agent::GaugeAppAgentError> {
    use crate::gaugeapp_agent::AgentCredential;
    crate::gaugeapp_agent::resolve_agent_credential(wb, actor).map(|credential| match credential {
        AgentCredential::OpenAi { token, .. } => token,
        AgentCredential::Codex { access, .. } => access,
    })
}

// DR-0313: the desktop keeps the claimant's provider links in the install's
// account scope, where the local `/account/credentials` route puts them. The
// management agent read `account::<actor>` instead, found nothing there, and
// answered every Agent settings turn 412 while the same person's chats ran.
// On a claimed computer the signed-out window is the local account, which
// has links of its own and not the claimant's (DR-0328 §2).
#[tokio::test]
async fn the_management_agent_finds_the_claimants_desktop_credentials() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let app = gated(&wb);
    let claimant = session(&wb, CLAIMANT);
    let (status, body) = send(
        &app,
        "POST",
        "/account/credentials",
        Some(&claimant),
        Some(serde_json::json!({ "provider": "openai", "token": "sk-claimant" })),
    )
    .await;
    assert!(status.is_success(), "{status} {body}");

    match management_agent_token(&wb, CLAIMANT) {
        Ok(token) => assert_eq!(token, "sk-claimant"),
        Err(error) => panic!("the claimant found no management credential: {error}"),
    }
    let local = wb.lock_unpoisoned().authority().as_str().to_owned();
    if let Ok(token) = management_agent_token(&wb, &local) {
        assert_ne!(
            token, "sk-claimant",
            "the local account ran on the claimant's key"
        );
    }
}

// On a computer nobody claimed, the signed-out window's own links are the
// install's, and its settings agents run on them.
#[tokio::test]
async fn the_management_agent_finds_an_unclaimed_computers_local_credentials() {
    let (_root, wb) = open();
    let app = gated(&wb);
    let (status, body) = send(
        &app,
        "POST",
        "/account/credentials",
        None,
        Some(serde_json::json!({ "provider": "openai", "token": "sk-local" })),
    )
    .await;
    assert!(status.is_success(), "{status} {body}");
    let local = wb.lock_unpoisoned().authority().as_str().to_owned();
    match management_agent_token(&wb, &local) {
        Ok(token) => assert_eq!(token, "sk-local"),
        Err(error) => panic!("the local account found no management credential: {error}"),
    }
}

// The desktop's own Codex login lives in the same install scope, and the
// agent's Codex path reads it through the same scope and class.
#[test]
fn the_management_agent_finds_the_desktops_codex_login_for_the_claimant() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    crate::codex_oauth::store_credential(
        &wb,
        &crate::codex_oauth::CodexOAuthCredential {
            access: "codex-access".into(),
            refresh: "codex-refresh".into(),
            expires: i64::MAX / 2,
            account_id: "codex-account".into(),
        },
    )
    .unwrap();
    match management_agent_token(&wb, CLAIMANT) {
        Ok(access) => assert_eq!(access, "codex-access"),
        Err(error) => panic!("the claimant found no Codex login: {error}"),
    }
}

// No account borrows another's (DR-0313 §2): a second account's link is in
// its own scope, so the claimant's agent does not run on it.
#[tokio::test]
async fn a_second_accounts_desktop_credential_is_not_the_claimants() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let app = gated(&wb);
    let other = session(&wb, OTHER);
    let (status, body) = send(
        &app,
        "POST",
        "/account/credentials",
        Some(&other),
        Some(serde_json::json!({ "provider": "openai", "token": "sk-other" })),
    )
    .await;
    assert!(status.is_success(), "{status} {body}");

    match management_agent_token(&wb, OTHER) {
        Ok(token) => assert_eq!(token, "sk-other"),
        Err(error) => panic!("the second account found no management credential: {error}"),
    }
    match management_agent_token(&wb, CLAIMANT) {
        Err(crate::gaugeapp_agent::GaugeAppAgentError::NoModelAccess) => {}
        Ok(token) => assert_ne!(
            token, "sk-other",
            "the claimant ran on another account's key"
        ),
        Err(error) => panic!("unexpected refusal: {error}"),
    }
}

#[test]
fn an_account_hears_only_of_changes_to_what_it_can_see() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    project(&wb, "p-other", serde_json::json!({ "owner": OTHER }));
    let claimant = session(&wb, CLAIMANT);
    let other = session(&wb, OTHER);
    let changed = |record: &str, id: &str| crate::stream::ServerEvent::WorkspaceChanged {
        record: record.into(),
        id: id.into(),
        op: "upsert".into(),
    };
    let guard = wb.lock_unpoisoned();
    assert!(guard.workspace_event_visible(Some(&other), &changed("project", "p-other")));
    assert!(!guard.workspace_event_visible(Some(&other), &changed("project", DEFAULT_PROJECT)));
    assert!(!guard.workspace_event_visible(Some(&claimant), &changed("project", "p-other")));
    assert!(guard.workspace_event_visible(Some(&claimant), &changed("project", DEFAULT_PROJECT)));
    assert!(
        guard.workspace_event_visible(Some(&other), &changed("project", "gone")),
        "a removed record crosses as its id alone"
    );
    assert!(guard.workspace_event_visible(Some(&other), &changed("agent", crate::DEFAULT_AGENT)));
}

#[tokio::test]
async fn the_people_list_shows_an_account_only_its_own_projects_people() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let app = gated(&wb);
    let other = session(&wb, OTHER);
    let people = |body: &serde_json::Value| {
        body["people"]
            .as_array()
            .unwrap()
            .iter()
            .map(|person| person["authority"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    let (_, theirs) = send(&app, "GET", "/roster", Some(&other), None).await;
    assert_eq!(people(&theirs), vec![OTHER.to_owned()]);
    let claimant = session(&wb, CLAIMANT);
    let (_, mine) = send(&app, "GET", "/roster", Some(&claimant), None).await;
    assert!(people(&mine).contains(&CLAIMANT.to_owned()));
    assert!(!people(&mine).contains(&OTHER.to_owned()));
}

#[tokio::test]
async fn a_projects_owner_invites_into_it_without_a_role() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let app = crate::open_control_plane(wb.clone());
    let other = session(&wb, OTHER);
    let personal = wb.lock_unpoisoned().ensure_account_personal(OTHER).unwrap();
    let (_, created) = send(
        &app,
        "POST",
        "/projects",
        Some(&other),
        Some(serde_json::json!({ "name": "Shared" })),
    )
    .await;
    let theirs = created["id"].as_str().unwrap().to_owned();
    assert_ne!(theirs, personal);
    let (status, body) = send(
        &app,
        "POST",
        "/home/invitations",
        Some(&other),
        Some(serde_json::json!({
            "authority": "acct-invitee",
            "project": theirs,
            "role": "member",
            "endpoint": "https://home.example.test",
        })),
    )
    .await;
    assert!(status.is_success(), "{status} {body}");
}

fn membership(
    account: &str,
    organization: &str,
    role: &str,
    status: MembershipStatus,
) -> MembershipRecord {
    MembershipRecord {
        id: account.into(),
        op: RecordOp::Upsert,
        org_id: organization.into(),
        authority: account.into(),
        email: String::new(),
        role: role.into(),
        status,
        managed_by_scim: false,
        team: None,
    }
}

/// DR-0374: an organization's owners and admins reach that organization's own
/// shared projects without a grant, and nothing else through their role.
#[test]
fn an_organizations_owner_and_admin_reach_its_shared_project_and_nothing_else() {
    const ORGANIZATION: &str = "organization:abc";
    for (role, status, reaches) in [
        ("owner", MembershipStatus::Active, true),
        ("admin", MembershipStatus::Active, true),
        ("member", MembershipStatus::Active, false),
        ("owner", MembershipStatus::Deprovisioned, false),
    ] {
        let (_root, wb) = open();
        wb.lock_unpoisoned().enable_hosted_home_mode();
        append(
            &wb,
            "membership",
            &membership(CLAIMANT, ORGANIZATION, role, status),
        );
        project(
            &wb,
            "shared",
            serde_json::json!({ "organization": ORGANIZATION }),
        );
        project(
            &wb,
            "elsewhere",
            serde_json::json!({ "organization": "organization:def" }),
        );
        project(&wb, "other", serde_json::json!({ "owner": OTHER }));
        project(&wb, "legacy", serde_json::json!({}));
        let guard = wb.lock_unpoisoned();
        let org = Org::rebuild(guard.store_ref()).unwrap();
        let reached = guard.account_project_ids(CLAIMANT, &org);
        assert_eq!(reached.contains("shared"), reaches, "{role} {status:?}");
        for id in ["elsewhere", "other", "legacy", DEFAULT_PROJECT] {
            assert!(!reached.contains(id), "{role} reaches {id} by role alone");
        }
        // The standing is the project's own membership, not a side door.
        let owners = guard.project_owner_resolver();
        let library = crate::library::Library::rebuild(guard.store_ref()).unwrap();
        let members = owners.members_in(
            &library,
            &owners.legacy_owner(guard.store_ref()),
            &library.projects["shared"],
            &org,
        );
        assert_eq!(members.contains(CLAIMANT), reaches, "{role} {status:?}");
    }
}

/// The Hub holds only an organization's reservation of its shared project,
/// which lives on a Home. Its owner reaches that project id there, read from
/// the organization's own directory, and an ordinary member does not.
#[test]
fn a_hub_admits_an_organizations_owner_to_its_reserved_shared_project() {
    let (_root, wb) = open();
    let mut guard = wb.lock_unpoisoned();
    let tenant = crate::tenancy::provision_organization(
        guard.store_mut(),
        CLAIMANT,
        &crate::account::account_scope(CLAIMANT),
        "Acme Studio",
        None,
    )
    .unwrap();
    let scope = crate::org::tenant_scope(&tenant.id);
    guard
        .store_mut()
        .append_record(
            &scope,
            "membership",
            &serde_json::to_string(&membership(
                OTHER,
                &tenant.id,
                "member",
                MembershipStatus::Active,
            ))
            .unwrap(),
        )
        .unwrap();
    let reserved = crate::tenancy::organization_project_intent(guard.store_ref(), &tenant.id)
        .unwrap()
        .unwrap()
        .project_id;
    let org = Org::rebuild_in(guard.store_ref(), &scope).unwrap();
    assert!(guard
        .account_project_ids(CLAIMANT, &org)
        .contains(&reserved));
    assert!(!guard.account_project_ids(OTHER, &org).contains(&reserved));
    // Another directory's owner role does not reach this organization's project.
    let home_directory = Org::rebuild(guard.store_ref()).unwrap();
    assert!(!guard
        .account_project_ids(CLAIMANT, &home_directory)
        .contains(&reserved));
}

const MEMBER: &str = "acct-member";
const VIEWER: &str = "acct-viewer";

/// The claimant's Agent placed in `p-shared`, another of its Agents placed
/// only in `p-private`, a member and a viewer granted `p-shared` (DR-0453).
fn shared_project_with_member_and_viewer(wb: &SharedWorkbench) -> (String, String) {
    claim(wb, CLAIMANT);
    let agents = {
        let mut guard = wb.lock_unpoisoned();
        for id in ["p-shared", "p-private"] {
            let mut extra = std::collections::BTreeMap::new();
            record_owner(&mut extra, CLAIMANT);
            crate::library_routes::create_named_project_with_extra(&mut guard, id, id, extra)
                .expect("project");
        }
        let mut agents = Vec::new();
        for (name, project) in [("Shared", "p-shared"), ("Private", "p-private")] {
            let created = guard
                .create_archetype(
                    name.into(),
                    crate::library::AgentKind::Work,
                    Some(CLAIMANT.into()),
                )
                .unwrap_or_else(|_| panic!("create {name}"));
            guard
                .bind_agent_to_project(project, &created.id, None)
                .unwrap_or_else(|_| panic!("place {name}"));
            agents.push(created.id);
        }
        agents
    };
    join(wb, MEMBER, "member");
    grant(wb, MEMBER, "p-shared");
    join(wb, VIEWER, "viewer");
    grant(wb, VIEWER, "p-shared");
    (agents[0].clone(), agents[1].clone())
}

#[test]
fn a_projects_member_authors_the_agents_placed_in_it_and_nothing_else() {
    let (_root, wb) = open();
    let (shared, private) = shared_project_with_member_and_viewer(&wb);
    {
        let guard = wb.lock_unpoisoned();
        assert_eq!(
            guard.agent_member_projects(&shared, MEMBER),
            ["p-shared".to_owned()].into()
        );
        assert!(guard.agent_authoring_visible(&shared, Some(MEMBER)));
        assert!(
            !guard.agent_authoring_owned_by(&shared, Some(MEMBER)),
            "the Agent stays its owner's"
        );
        assert!(!guard.agent_placeable_by(&shared, MEMBER));
        assert!(
            !guard.agent_authoring_visible(&private, Some(MEMBER)),
            "an Agent placed in no project of the member's"
        );
        assert!(
            !guard.agent_authoring_visible(&shared, Some(VIEWER)),
            "a viewer authors nothing"
        );
        assert!(guard.agent_member_projects(&shared, VIEWER).is_empty());
        assert!(
            !guard.agent_authoring_visible(crate::DEFAULT_AGENT, Some(MEMBER)),
            "a built-in Agent placed in the project is still no one's to edit"
        );
        assert!(
            guard.agent_member_projects(&shared, CLAIMANT).is_empty()
                && guard.agent_authoring_visible(&shared, Some(CLAIMANT)),
            "the owner authors it as its owner"
        );
        assert_eq!(
            guard.member_authorable_agents(MEMBER),
            [(shared.clone(), ["p-shared".to_owned()].into())].into()
        );
        assert!(guard.member_authorable_agents(VIEWER).is_empty());
        assert!(guard.project_member_authors("p-shared", MEMBER));
        assert!(!guard.project_member_authors("p-shared", VIEWER));
        assert!(!guard.project_member_authors("p-private", MEMBER));
    }

    // Making the member a viewer, or taking the grant away, ends it at once.
    join(&wb, MEMBER, "viewer");
    assert!(!wb
        .lock_unpoisoned()
        .agent_authoring_visible(&shared, Some(MEMBER)));
    join(&wb, MEMBER, "member");
    assert!(wb
        .lock_unpoisoned()
        .agent_authoring_visible(&shared, Some(MEMBER)));
    append(
        &wb,
        "member_grant",
        &MemberGrantRecord {
            id: MemberGrantRecord::make_id(MEMBER, "p-shared"),
            op: RecordOp::Tombstone,
            authority: MEMBER.into(),
            project_id: "p-shared".into(),
        },
    );
    assert!(!wb
        .lock_unpoisoned()
        .agent_authoring_visible(&shared, Some(MEMBER)));
}

#[test]
fn off_a_desktop_a_projects_member_authors_nothing_yet() {
    let (_root, wb) = open();
    let (shared, _) = shared_project_with_member_and_viewer(&wb);
    let mut guard = wb.lock_unpoisoned();
    guard.enable_hosted_home_mode();
    assert!(!guard.agent_authoring_visible(&shared, Some(MEMBER)));
    assert!(guard.member_authorable_agents(MEMBER).is_empty());
    assert!(!guard.project_member_authors("p-shared", MEMBER));
}

#[test]
fn a_projects_member_deploys_from_it_and_a_viewer_does_not() {
    let (_root, wb) = open();
    shared_project_with_member_and_viewer(&wb);
    let member = bearer_headers(&session(&wb, MEMBER));
    let viewer = bearer_headers(&session(&wb, VIEWER));
    let claimant = bearer_headers(&session(&wb, CLAIMANT));
    let other = bearer_headers(&session(&wb, OTHER));
    let guard = wb.lock_unpoisoned();
    let refused = |headers: &axum::http::HeaderMap, project: &str| {
        guard
            .project_deployer_refusal(headers, project)
            .map(|response| response.status())
    };
    assert_eq!(refused(&claimant, "p-shared"), None);
    assert_eq!(refused(&member, "p-shared"), None);
    assert_eq!(refused(&viewer, "p-shared"), Some(StatusCode::FORBIDDEN));
    assert_eq!(refused(&other, "p-shared"), Some(StatusCode::FORBIDDEN));
    assert_eq!(refused(&member, "p-private"), Some(StatusCode::FORBIDDEN));
    assert_eq!(
        guard
            .project_member_requester(&member, "p-shared")
            .as_deref(),
        Some(MEMBER),
        "a member's act records the member"
    );
    assert_eq!(guard.project_member_requester(&claimant, "p-shared"), None);
    assert_eq!(guard.project_member_requester(&viewer, "p-shared"), None);
}

#[tokio::test]
async fn a_members_authoring_and_settings_assistant_spend_the_projects_credentials() {
    let (_root, wb) = open();
    let (shared, private) = shared_project_with_member_and_viewer(&wb);
    let app = gated(&wb);
    let (status, body) = send(
        &app,
        "POST",
        "/projects/p-shared/credentials",
        Some(&session(&wb, CLAIMANT)),
        Some(serde_json::json!({ "provider": "openai", "token": "sk-project-key" })),
    )
    .await;
    assert!(status.is_success(), "{status} {body}");
    let chat = {
        let mut guard = wb.lock_unpoisoned();
        let chat = guard
            .create_chat_under_agent(&shared, "member edits")
            .unwrap_or_else(|_| panic!("an edit chat"))["id"]
            .as_str()
            .unwrap()
            .to_owned();
        guard.claim_chat_owner(&chat, MEMBER);
        chat
    };
    // A turn in the member's edit chat holds the shared project's keys, and
    // so does a request for the member's settings assistant: what the
    // project's credentials are read under.
    let turn = crate::key_delegation::hold_chat_project(&wb, &chat);
    assert_eq!(
        turn.iter().map(|hold| hold.project()).collect::<Vec<_>>(),
        ["p-shared"]
    );
    let member = bearer_headers(&session(&wb, MEMBER));
    let settings = crate::key_delegation::session_holds(
        &wb,
        &member,
        &axum::http::Method::POST,
        &format!("/archetypes/{shared}/settings/agent/messages"),
    );
    assert_eq!(
        settings
            .iter()
            .map(|hold| hold.project())
            .collect::<Vec<_>>(),
        ["p-shared"]
    );
    let viewer = bearer_headers(&session(&wb, VIEWER));
    assert!(crate::key_delegation::session_holds(
        &wb,
        &viewer,
        &axum::http::Method::POST,
        &format!("/archetypes/{shared}/settings/agent/messages"),
    )
    .is_empty());
    {
        let guard = wb.lock_unpoisoned();
        assert_eq!(
            guard
                .member_authoring_project_of_chat(&chat, MEMBER)
                .as_deref(),
            Some("p-shared")
        );
        assert!(
            guard
                .credential_ref_for_chat(&chat, "openai", MEMBER)
                .starts_with(&format!(
                    "credential:gaugedesk/project/{}/",
                    hex::encode("p-shared")
                )),
            "the member's edit chat runs on the project's key"
        );
        assert_eq!(
            guard.member_authoring_project_of_chat(&chat, VIEWER),
            None,
            "only the member's own edit chat"
        );
    }
    let token = |actor: &str, kind: &str, id: &str| {
        crate::gaugeapp_agent::resolve_agent_credential_in(
            &wb,
            actor,
            &crate::gaugeapp_contract::GaugeAppScope {
                kind: kind.into(),
                id: id.into(),
            },
        )
        .map(|credential| match credential {
            crate::gaugeapp_agent::AgentCredential::OpenAi { token, .. } => token,
            crate::gaugeapp_agent::AgentCredential::Codex { access, .. } => access,
        })
    };
    assert_eq!(
        token(MEMBER, "agent", &shared).ok().as_deref(),
        Some("sk-project-key")
    );
    assert_eq!(
        token(MEMBER, "project", "p-shared").ok().as_deref(),
        Some("sk-project-key")
    );
    assert!(token(MEMBER, "agent", &private).is_err());
    assert!(token(VIEWER, "agent", &shared).is_err());
    assert!(token(VIEWER, "project", "p-shared").is_err());
    assert!(token(OTHER, "project", "p-shared").is_err());
}

/// A member's composer is offered the models the shared project's own
/// credentials run, read from the Home that holds the project, and none of the
/// owner's: the owner's key and the models the owner declared stay the
/// owner's (DR-0451 §2), while the member's turns spend the project's
/// (DR-0453 §5). Before this, the picker read only `/account/*`, which a
/// member is refused over the relay and which holds nothing of its own here,
/// so a member's composer offered no model at all (WS-1026).
#[tokio::test]
async fn a_members_composer_is_offered_the_projects_models_and_not_the_owners() {
    let (_root, wb) = open();
    shared_project_with_member_and_viewer(&wb);
    let app = gated(&wb);
    let owner = session(&wb, CLAIMANT);
    for (method, uri, body) in [
        (
            "POST",
            "/account/credentials",
            serde_json::json!({ "provider": "openai", "token": "sk-owner-key" }),
        ),
        (
            "PUT",
            "/account/settings/model_picker.endpoint_models",
            serde_json::json!({ "value": r#"{"openai-generic":["owner-model"]}"# }),
        ),
        (
            "POST",
            "/projects/p-shared/credentials",
            serde_json::json!({ "provider": "anthropic", "token": "sk-project-key" }),
        ),
    ] {
        let (status, response) = send(&app, method, uri, Some(&owner), Some(body)).await;
        assert!(status.is_success(), "{method} {uri}: {status} {response}");
    }

    let (status, member) = send(
        &app,
        "GET",
        "/projects/p-shared/models",
        Some(&session(&wb, MEMBER)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{member}");
    assert_eq!(
        member,
        serde_json::json!({
            "providers": ["anthropic"],
            "endpoint_models": {},
            "default_provider": "anthropic",
            "default_model": "claude-opus-5-5",
        }),
        "the project's key and the model an unpinned turn runs on it"
    );

    // The owner's turns there choose between its own key and the project's.
    let (status, owners) = send(&app, "GET", "/projects/p-shared/models", Some(&owner), None).await;
    assert_eq!(status, StatusCode::OK, "{owners}");
    assert_eq!(
        owners["providers"],
        serde_json::json!(["openai", "anthropic"])
    );

    // An account the project is not shared with learns nothing about it.
    let (status, _) = send(
        &app,
        "GET",
        "/projects/p-shared/models",
        Some(&session(&wb, OTHER)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A provider that ships no catalog runs the models declared for the key a
/// turn spends. For the project's own key those are its owner's, and a member
/// is offered them and its unpinned turns run the first, though it declares
/// nothing on someone else's computer (DR-0476 §1). Its own declarations, had
/// it any there, would not stand for the project's key.
#[tokio::test]
async fn a_members_composer_offers_the_models_the_owner_declared_for_the_projects_key() {
    let (_root, wb) = open();
    let (shared, _) = shared_project_with_member_and_viewer(&wb);
    let app = gated(&wb);
    let owner = session(&wb, CLAIMANT);
    let member = session(&wb, MEMBER);
    for (method, uri, bearer, body) in [
        (
            "PUT",
            "/account/settings/model_picker.endpoint_models",
            &owner,
            serde_json::json!({ "value": r#"{"openai-generic":["owner-model","owner-other"]}"# }),
        ),
        (
            "PUT",
            "/account/settings/model_picker.endpoint_models",
            &member,
            serde_json::json!({ "value": r#"{"openai-generic":["members-own-model"]}"# }),
        ),
        (
            "POST",
            "/projects/p-shared/credentials",
            &owner,
            serde_json::json!({
                "provider": "openai-generic",
                "token": "sk-project-key",
                "base_url": "https://models.example.test/v1",
            }),
        ),
    ] {
        let (status, response) = send(&app, method, uri, Some(bearer), Some(body)).await;
        assert!(status.is_success(), "{method} {uri}: {status} {response}");
    }
    for bearer in [&owner, &member] {
        let (status, access) =
            send(&app, "GET", "/projects/p-shared/models", Some(bearer), None).await;
        assert_eq!(status, StatusCode::OK, "{access}");
        assert_eq!(access["providers"], serde_json::json!(["openai-generic"]));
        assert_eq!(
            access["endpoint_models"],
            serde_json::json!({ "openai-generic": ["owner-model", "owner-other"] }),
            "the owner's declarations stand for the project's key"
        );
        assert_eq!(access["default_provider"], "openai-generic");
        assert_eq!(access["default_model"], "owner-model");
    }

    // A member's unpinned turn there runs what its picker names as default.
    let mut guard = wb.lock_unpoisoned();
    let chat = guard
        .create_chat_under_agent(&shared, "member edits")
        .unwrap_or_else(|_| panic!("an edit chat"))["id"]
        .as_str()
        .unwrap()
        .to_owned();
    guard.claim_chat_owner(&chat, MEMBER);
    let class = guard.model_execution_class();
    assert_eq!(
        guard
            .declared_default_model_for_chat(&chat, MEMBER, "openai-generic", class)
            .as_deref(),
        Some("owner-model")
    );
}

/// A member's turns never fall back to the owner's own account key: with no
/// key of the project's own, a member is offered nothing and its turns resolve
/// no provider credential, however many keys the owner keeps for itself
/// (DR-0476 §2). desk says so rather than listing nothing.
#[tokio::test]
async fn a_member_is_offered_nothing_when_the_project_holds_no_key() {
    let (_root, wb) = open();
    let (shared, _) = shared_project_with_member_and_viewer(&wb);
    let app = gated(&wb);
    let owner = session(&wb, CLAIMANT);
    let (status, response) = send(
        &app,
        "POST",
        "/account/credentials",
        Some(&owner),
        Some(serde_json::json!({ "provider": "anthropic", "token": "sk-owner-key" })),
    )
    .await;
    assert!(status.is_success(), "{status} {response}");
    let (status, access) = send(
        &app,
        "GET",
        "/projects/p-shared/models",
        Some(&session(&wb, MEMBER)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{access}");
    assert_eq!(
        access,
        serde_json::json!({
            "providers": [],
            "endpoint_models": {},
            "default_provider": null,
            "default_model": null,
        })
    );
    let mut guard = wb.lock_unpoisoned();
    let chat = guard
        .create_chat_under_agent(&shared, "member edits")
        .unwrap_or_else(|_| panic!("an edit chat"))["id"]
        .as_str()
        .unwrap()
        .to_owned();
    guard.claim_chat_owner(&chat, MEMBER);
    let class = guard.model_execution_class();
    assert!(guard
        .linked_providers_for_chat_in_class(&chat, MEMBER, class)
        .is_empty());
    assert!(guard
        .credential_capability_for_chat_in_class(&chat, "anthropic", MEMBER, class)
        .is_none());
}

/// The desktop window calls its control plane from another origin, so every
/// request with a session is preceded by a CORS preflight that carries none.
/// Driven through the composition the shell serves — the window's secret,
/// this gate, then the routes — because each layer alone was correct while
/// the stack refused every preflight to a signed-in account's project, and
/// the window could not start a chat (2026-10-07).
#[tokio::test]
async fn the_desktop_window_reaches_a_signed_in_accounts_project_across_origins() {
    use axum::http::header;
    const ORIGIN: &str = "tauri://localhost";
    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    project(&wb, "own-project", serde_json::json!({ "owner": CLAIMANT }));
    let claimant = session(&wb, CLAIMANT);
    let other = session(&wb, OTHER);
    let app = crate::local_operator::guard(
        crate::open_runtime::desktop_operator_plane(wb.clone()),
        Some(crate::local_operator::LocalOperatorSecret::parse(SECRET).unwrap()),
    );
    let call = |method: &str, uri: &str, bearer: Option<&str>| {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::ORIGIN, ORIGIN);
        if method == "OPTIONS" {
            request = request
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "authorization,content-type,idempotency-key,x-gaugedesk-operator",
                );
        } else {
            request = request.header(crate::local_operator::HEADER, SECRET);
        }
        if let Some(bearer) = bearer {
            request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        let request = request.body(Body::empty()).unwrap();
        let app = app.clone();
        async move { app.oneshot(request).await.unwrap() }
    };
    let allowed_origin = |response: &axum::response::Response| {
        response
            .headers()
            .get_all(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };

    // The preflight for starting a chat in the account's own project.
    let preflight = call(
        "OPTIONS",
        "/projects/own-project/placements/inst-placement-default/chats",
        None,
    )
    .await;
    assert!(
        preflight.status().is_success(),
        "a preflight is answered by CORS, not judged as the signed-out local account: {}",
        preflight.status()
    );
    assert_eq!(allowed_origin(&preflight), vec![ORIGIN.to_owned()]);

    // The request it was asking for reaches the route, readable by the window.
    let read = call("GET", "/projects/own-project/models", Some(&claimant)).await;
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(allowed_origin(&read), vec![ORIGIN.to_owned()]);

    // A refusal is still a refusal, and the window can read it as one rather
    // than as a network error.
    let refused = call("GET", "/projects/own-project/models", Some(&other)).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(allowed_origin(&refused), vec![ORIGIN.to_owned()]);
    let body = refused.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("not in scope for this project"));
}

#[path = "credential_scope_tests.rs"]
mod credential_scope_tests;
