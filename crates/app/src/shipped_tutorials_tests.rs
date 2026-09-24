//! DR-0192 and WHIP-5: the owner's Tutorials folder holds exactly what the
//! release ships, and Basics starts from it once.
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
fn the_owner_gets_a_read_only_tutorials_folder_in_personal() {
    let (_root, wb) = owned();
    let mut guard = wb.lock_unpoisoned();
    let ShippedTutorials::Updated(head) = guard.ensure_shipped_tutorials().unwrap() else {
        panic!("the first ensure creates the folder");
    };
    let target = guard.library.work_targets[TUTORIALS_TARGET].clone();
    assert_eq!(
        target.authority, "account-root",
        "the owner's, not the Home's"
    );
    assert_eq!(target.parties, vec!["account-root".to_owned()]);
    assert_eq!(
        target.owner,
        WorkTargetOwner::Project {
            project_id: DEFAULT_PROJECT.into()
        },
        "it hangs off Personal"
    );
    assert!(target.capabilities.read);
    assert!(
        !target.capabilities.propose && !target.capabilities.apply,
        "read-only"
    );
    assert_eq!(target.current_basis.as_deref(), Some(head.as_str()));
    assert_eq!(
        guard.targets[TUTORIALS_TARGET]
            .read_main_file("basics.whip")
            .unwrap()
            .as_deref(),
        Some(include_str!("tutorials/basics.whip"))
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
    guard.targets[TUTORIALS_TARGET]
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
    let target = &guard.targets[TUTORIALS_TARGET];
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
/// asked for, and its tasks assigned to the owner in Personal.
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
        .read_project_tracker_tasks(&context, DEFAULT_PROJECT, "tutorials")
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

/// A Home governed by its own directory — a Cloud Home is provisioned with its
/// tenant's owner — gives the folder to that owner; two owners give it to
/// nobody rather than to a guess.
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
        guard.library.work_targets[TUTORIALS_TARGET].authority,
        "tenant-owner"
    );
    drop(guard);

    let (_root, wb) = open();
    add_owner(&wb, "first-owner");
    add_owner(&wb, "second-owner");
    assert_eq!(
        wb.lock_unpoisoned().ensure_shipped_tutorials().unwrap(),
        ShippedTutorials::NoOwner
    );
}
