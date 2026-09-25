//! DR-0225 and WHIP-5: a release-maintained project holds the source, and
//! Basics starts once in the learner's separate workspace.
use super::*;
use crate::{at_rest::LoopbackKeyWrap, LockUnpoisoned, SharedWorkbench};

fn open() -> (tempfile::TempDir, SharedWorkbench) {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::workbench_state::open_workbench_with_content_keywrap(root.path(), |_| {
        Ok(Box::new(LoopbackKeyWrap::new([37; 32])))
    })
    .unwrap();
    (root, wb)
}

fn owned() -> (tempfile::TempDir, SharedWorkbench) {
    let (root, wb) = open();
    crate::account_signin::store_session_for_test(&wb);
    crate::home_owner::claim_if_never_claimed(&wb).unwrap();
    (root, wb)
}

fn owner_context(wb: &SharedWorkbench) -> crate::identity::AuthenticatedActionContext {
    let token = crate::desktop_session::home_session(wb).expect("the owner's session");
    wb.lock_unpoisoned()
        .authenticate_action_context(&token)
        .unwrap()
}

#[test]
fn a_home_without_an_owner_has_no_tutorials_folder() {
    let (_root, wb) = open();
    let mut guard = wb.lock_unpoisoned();
    assert_eq!(
        guard.ensure_shipped_tutorials().unwrap(),
        ShippedTutorials::NoOwner
    );
    assert!(!guard.library.work_targets.contains_key(TUTORIALS_TARGET));
    assert!(!guard.targets.contains_key(TUTORIALS_TARGET));
}

#[test]
fn the_owner_gets_a_read_only_gaugewright_tutorials_project() {
    let (_root, wb) = owned();
    let mut guard = wb.lock_unpoisoned();
    let ShippedTutorials::Updated(head) = guard.ensure_shipped_tutorials().unwrap() else {
        panic!("the first ensure creates the folder");
    };
    let target_id = tutorial_target_id("account-root");
    let project_id = tutorial_project_id("account-root");
    let target = guard.library.work_targets[&target_id].clone();
    assert_eq!(
        target.authority, "account-root",
        "the owner's, not the Home's"
    );
    assert_eq!(target.parties, vec!["account-root".to_owned()]);
    assert_eq!(
        target.owner,
        WorkTargetOwner::Project {
            project_id: project_id.clone()
        },
        "it belongs to the learner's Tutorials project"
    );
    assert!(target.capabilities.read);
    assert!(
        !target.capabilities.propose && !target.capabilities.apply,
        "read-only"
    );
    assert_eq!(target.current_basis.as_deref(), Some(head.as_str()));
    assert_eq!(
        guard.targets[&target_id]
            .read_main_file("basics.whip")
            .unwrap()
            .as_deref(),
        Some(include_str!("tutorials/basics.whip"))
    );
    let project = &guard.library.projects[&project_id];
    assert_eq!(project.name, "Tutorials");
    assert!(is_tutorial_project(project));
    assert_eq!(project.extra["product"]["publisher"], "GaugeWright");
    assert!(
        !guard.library.work_targets.contains_key(TUTORIALS_TARGET),
        "no new Personal attachment"
    );
    let personal = crate::library_state::managed_project_target_id(DEFAULT_PROJECT);
    assert_eq!(
        guard.library.work_targets[&personal].authority,
        guard.home_id().as_str(),
        "Personal's own files are untouched"
    );

    let records = |g: &Workbench| {
        g.store_ref()
            .records(crate::library::LIBRARY_SCOPE, RELEASE_KIND)
            .unwrap()
            .len()
    };
    let before = records(&guard);
    assert_eq!(
        guard.ensure_shipped_tutorials().unwrap(),
        ShippedTutorials::Current(head)
    );
    assert_eq!(records(&guard), before, "a current folder writes nothing");
}

/// A release that ships a different set brings the folder to it, retiring what
/// it no longer ships, and records which version did.
#[test]
fn a_release_reconciles_the_folder_to_what_it_ships() {
    let (_root, wb) = owned();
    let mut guard = wb.lock_unpoisoned();
    guard.ensure_shipped_tutorials().unwrap();
    // As an older release left it: Basics at other text, plus one since retired.
    let target_id = tutorial_target_id("account-root");
    guard.targets[&target_id]
        .seed_main_exactly(
            &[
                ("basics.whip", "workflow Old() -> bool"),
                ("retired.whip", "x"),
            ],
            "whip",
        )
        .unwrap();
    let ShippedTutorials::Updated(head) = guard.ensure_shipped_tutorials().unwrap() else {
        panic!("a differing folder is brought to this release");
    };
    let target = &guard.targets[&target_id];
    assert_eq!(target.read_main_file("retired.whip").unwrap(), None);
    assert_eq!(
        target.read_main_file("basics.whip").unwrap().as_deref(),
        Some(include_str!("tutorials/basics.whip"))
    );
    let last: ShippedRelease = serde_json::from_str(
        guard
            .store_ref()
            .records(crate::library::LIBRARY_SCOPE, RELEASE_KIND)
            .unwrap()
            .last()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(last.cut, head);
    assert_eq!(last.version, env!("CARGO_PKG_VERSION"));
}

/// WHIP-5's start: no model, no caller stepping it, one run however often it is
/// asked for, and its tasks assigned to the owner in Tutorials.
#[test]
fn basics_starts_once_from_the_tutorials_folder() {
    let (_root, wb) = owned();
    let context = owner_context(&wb);
    let mut guard = wb.lock_unpoisoned();
    let first = guard
        .start_shipped_tutorial(&context, "basics")
        .expect("Basics starts");
    let again = guard
        .start_shipped_tutorial(&context, "basics")
        .expect("and is found again");
    assert_eq!(
        first.product_scope, again.product_scope,
        "a second ask is the same run"
    );
    assert_eq!(first.admission.instance_ref, again.admission.instance_ref);

    let step = guard
        .step_project_workflow_unattended(
            &first.product_scope,
            crate::project_workflow::ProjectWorkflowLimits::PRODUCT,
        )
        .unwrap();
    assert!(step.executed_effect.is_some(), "the first task is filed");
    let tasks = guard
        .read_project_tracker_tasks(&context, &tutorial_project_id("account-root"), "tutorials")
        .unwrap();
    let titles: Vec<_> = tasks
        .backlog
        .issues
        .iter()
        .map(|issue| issue.title.as_str())
        .collect();
    assert_eq!(titles, vec!["Create a chat in Personal"]);

    assert!(guard
        .start_shipped_tutorial(&context, "nonexistent")
        .is_err());
}

#[test]
fn a_home_without_an_owner_cannot_start_a_tutorial() {
    let (_root, wb) = open();
    let context = {
        let mut guard = wb.lock_unpoisoned();
        let token = guard
            .mint_account_session("someone", "passkey", 3600)
            .unwrap();
        guard.authenticate_action_context(&token).unwrap()
    };
    let refused = wb
        .lock_unpoisoned()
        .start_shipped_tutorial(&context, "basics")
        .unwrap_err();
    assert!(refused.contains("no owner"), "{refused}");
}

async fn post(
    app: &axum::Router,
    path: &str,
    bearer: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let mut request = axum::http::Request::builder().method("POST").uri(path);
    if let Some(token) = bearer {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    (
        status,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

async fn get(
    app: &axum::Router,
    path: &str,
    bearer: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let mut request = axum::http::Request::builder().uri(path);
    if let Some(token) = bearer {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// The route the welcome hands off through: only a signed-in person, and every
/// ask answers with the one run.
#[tokio::test]
async fn the_start_route_starts_basics_once_for_the_signed_in_owner() {
    let (_root, wb) = owned();
    let app = crate::open_control_plane(wb.clone());
    let (status, _) = post(&app, "/tutorials/basics/start", None).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    let token = crate::desktop_session::home_session(&wb).unwrap();
    let (status, first) = post(&app, "/tutorials/basics/start", Some(&token)).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{first}");
    let (status, again) = post(&app, "/tutorials/basics/start", Some(&token)).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{again}");
    assert_eq!(first["product_scope"], again["product_scope"]);
    let (status, _) = post(&app, "/tutorials/unknown/start", Some(&token)).await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn the_source_route_is_authenticated_and_reads_the_release_target() {
    let (_root, wb) = owned();
    wb.lock_unpoisoned().ensure_shipped_tutorials().unwrap();
    let app = crate::open_control_plane(wb.clone());
    assert_eq!(
        get(&app, "/tutorials/basics", None).await.0,
        axum::http::StatusCode::UNAUTHORIZED
    );
    let token = crate::desktop_session::home_session(&wb).unwrap();
    let (status, body) = get(&app, "/tutorials/basics", Some(&token)).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["source"], include_str!("tutorials/basics.whip"));
    assert_eq!(body["project"], tutorial_project_id("account-root"));
}

fn add_owner(wb: &SharedWorkbench, account: &str) {
    let record = crate::org::MembershipRecord {
        id: account.into(),
        op: crate::org::RecordOp::Upsert,
        org_id: crate::org::ORG_ID.into(),
        authority: account.into(),
        email: String::new(),
        role: "owner".into(),
        status: crate::org::MembershipStatus::Active,
        managed_by_scim: false,
        team: None,
    };
    wb.lock_unpoisoned()
        .store_mut()
        .append_record(
            crate::org::ORG_SCOPE,
            "membership",
            &serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
}

/// A governed Home gives each learner a separate product project, including
/// when its directory has more than one owner.
#[test]
fn a_governed_home_gives_the_folder_to_its_one_owner() {
    let (_root, wb) = open();
    add_owner(&wb, "tenant-owner");
    let mut guard = wb.lock_unpoisoned();
    assert!(matches!(
        guard.ensure_shipped_tutorials().unwrap(),
        ShippedTutorials::Updated(_)
    ));
    assert_eq!(
        guard.library.work_targets[&tutorial_target_id("tenant-owner")].authority,
        "tenant-owner"
    );
    drop(guard);

    let (_root, wb) = open();
    add_owner(&wb, "first-owner");
    add_owner(&wb, "second-owner");
    let mut guard = wb.lock_unpoisoned();
    assert!(matches!(
        guard.ensure_shipped_tutorials().unwrap(),
        ShippedTutorials::Updated(_)
    ));
    let first = tutorial_project_id("first-owner");
    let second = tutorial_project_id("second-owner");
    assert_ne!(first, second);
    assert!(guard.library.projects.contains_key(&first));
    assert!(guard.library.projects.contains_key(&second));
    assert_ne!(
        guard.library.project_collaboration_workspaces[&first].workspace_id,
        guard.library.project_collaboration_workspaces[&second].workspace_id
    );
    let visible = crate::library_routes::scope_workspace_value(
        &guard,
        crate::library_routes::workspace_value(&guard),
        &crate::workbench_auth::ProjectVisibility::All,
        Some("first-owner"),
    );
    let projects = visible["projects"].as_array().unwrap();
    assert!(projects.iter().any(|project| project["id"] == first));
    assert!(!projects.iter().any(|project| project["id"] == second));
}

#[test]
fn a_member_sees_only_their_tutorials_project_under_project_grants() {
    let (_root, wb) = open();
    add_owner(&wb, "tenant-owner");
    let member = crate::org::MembershipRecord {
        id: "learner".into(),
        op: RecordOp::Upsert,
        org_id: crate::org::ORG_ID.into(),
        authority: "learner".into(),
        email: String::new(),
        role: "member".into(),
        status: MembershipStatus::Active,
        managed_by_scim: false,
        team: None,
    };
    let mut guard = wb.lock_unpoisoned();
    guard
        .store_mut()
        .append_record(
            ORG_SCOPE,
            "membership",
            &serde_json::to_string(&member).unwrap(),
        )
        .unwrap();
    guard.ensure_shipped_tutorials().unwrap();
    let org = Org::rebuild(guard.store_ref()).unwrap();
    assert!(org.can_access_project("learner", &tutorial_project_id("learner")));
    assert!(!org.can_access_project("learner", &tutorial_project_id("tenant-owner")));
    assert_ne!(
        tutorial_target_id("learner"),
        tutorial_target_id("tenant-owner")
    );
}

#[test]
fn a_learner_cannot_rename_or_delete_the_release_project() {
    let (_root, wb) = owned();
    let mut guard = wb.lock_unpoisoned();
    guard.ensure_shipped_tutorials().unwrap();
    let id = tutorial_project_id("account-root");
    assert!(guard
        .update_project_record(&id, Some("Mine".into()), None, None, None)
        .is_none());
    assert!(!guard.delete_project_cascade(&id));
    assert_eq!(guard.library.projects[&id].name, "Tutorials");
}

#[test]
fn reconciliation_waits_while_the_tutorials_project_moves() {
    let (_root, wb) = owned();
    let mut guard = wb.lock_unpoisoned();
    guard.ensure_shipped_tutorials().unwrap();
    let project = tutorial_project_id("account-root");
    guard
        .store_mut()
        .append_record(
            &crate::federation::handoff_scope(&project),
            "event",
            &serde_json::to_string(&gaugedesk_core::handoff::HandoffEvent::HandoffOffered).unwrap(),
        )
        .unwrap();
    assert!(guard.project_moving(&project));
    assert!(guard
        .ensure_shipped_tutorials()
        .unwrap_err()
        .contains(crate::federation::PAUSED_FOR_MOVE));
}

#[test]
fn the_read_only_view_shows_installed_source_and_launch_state() {
    let (_root, wb) = owned();
    let context = owner_context(&wb);
    let mut guard = wb.lock_unpoisoned();
    guard.ensure_shipped_tutorials().unwrap();
    let ready = guard.shipped_tutorial_info(&context, "basics").unwrap();
    assert_eq!(ready["status"], "ready");
    assert_eq!(ready["source"], include_str!("tutorials/basics.whip"));
    assert_eq!(ready["publisher"], "GaugeWright");
    guard.start_shipped_tutorial(&context, "basics").unwrap();
    let started = guard.shipped_tutorial_info(&context, "basics").unwrap();
    assert_eq!(started["status"], "continue");
    assert_eq!(started["run_project"], tutorial_project_id("account-root"));
}

#[test]
fn an_older_personal_run_resumes_without_starting_a_second_basics() {
    use crate::project_workflow::{ProjectWorkflowLaunch, ProjectWorkflowLimits};
    let (_root, wb) = owned();
    let context = owner_context(&wb);
    let mut guard = wb.lock_unpoisoned();
    let workspace = guard
        .workspace_provider(TUTORIALS_TARGET)
        .init_at(&guard.targets_dir().join(TUTORIALS_TARGET))
        .unwrap();
    guard.targets.insert(TUTORIALS_TARGET.into(), workspace);
    let cut = guard.targets[TUTORIALS_TARGET]
        .seed_main_exactly(SHIPPED, "whip")
        .unwrap()
        .0;
    let mut record = crate::library_state::managed_target_record(
        TUTORIALS_TARGET.into(),
        "Tutorials".into(),
        WorkTargetOwner::Project {
            project_id: DEFAULT_PROJECT.into(),
        },
        guard.home_id(),
        cut.clone(),
    );
    record.authority = "account-root".into();
    record.parties = vec!["account-root".into()];
    record.capabilities = TargetCapabilities {
        read: true,
        propose: false,
        apply: false,
        publish: false,
        release: false,
    };
    guard.write_work_target_record(record);
    guard
        .declare_project_tracker(
            &context,
            DEFAULT_PROJECT,
            "tutorials",
            "shipped-tutorials",
            gaugedesk_core::abac::ResourceAttributes::default(),
        )
        .unwrap();
    let original = guard
        .launch_project_workflow(
            &context,
            &ProjectWorkflowLaunch {
                project: DEFAULT_PROJECT.into(),
                target: TUTORIALS_TARGET.into(),
                path: "basics.whip".into(),
                cut,
                request_id: tutorial_request_id("basics"),
                inputs: std::collections::BTreeMap::from([(
                    "learner".into(),
                    serde_json::json!({"authority":"account-root"}),
                )]),
            },
            ProjectWorkflowLimits::PRODUCT,
        )
        .unwrap();
    guard.ensure_shipped_tutorials().unwrap();
    let resumed = guard.start_shipped_tutorial(&context, "basics").unwrap();
    assert_eq!(resumed.project, DEFAULT_PROJECT);
    assert_eq!(resumed.product_scope, original.product_scope);
    let info = guard.shipped_tutorial_info(&context, "basics").unwrap();
    assert_eq!(info["run_project"], DEFAULT_PROJECT);
    assert!(!guard
        .project_workflow_launched(
            &tutorial_project_id("account-root"),
            "account-root",
            &tutorial_request_id("basics")
        )
        .unwrap());
}
