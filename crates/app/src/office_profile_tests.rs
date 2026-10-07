//! WS-424 (HIPAA-1): the office-controlled profile binds the organization and
//! its local Project Host, admits only an administrator's enrollment, and has
//! no exit.
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Json, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::*;
use crate::org::{MembershipRecord, MembershipStatus, Org};
use crate::project_owner::ProjectOwner;
use crate::{LockUnpoisoned, SharedWorkbench};

fn open() -> (tempfile::TempDir, SharedWorkbench) {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    (root, wb)
}

fn member(wb: &mut Workbench, actor: &str, role: &str) {
    let record = MembershipRecord {
        id: actor.into(),
        op: RecordOp::Upsert,
        org_id: ORG_ID.into(),
        authority: actor.into(),
        email: format!("{actor}@example.test"),
        role: role.into(),
        status: MembershipStatus::Active,
        managed_by_scim: false,
        team: None,
    };
    wb.store_mut()
        .append_record(
            ORG_SCOPE,
            "membership",
            &serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
}

fn append(wb: &mut Workbench, record: &OfficeProfileRecord) {
    wb.store_mut()
        .append_record(
            ORG_SCOPE,
            OFFICE_PROFILE_KIND,
            &serde_json::to_string(record).unwrap(),
        )
        .unwrap();
}

fn binding(wb: &Workbench, home: &str) -> OfficeProfileRecord {
    OfficeProfileRecord {
        id: ORG_ID.into(),
        op: RecordOp::Upsert,
        organization: ORG_ID.into(),
        home_id: home.into(),
        enrolled_by: "dr-admin".into(),
        enrolled_at_ms: wb
            .store_ref()
            .records(ORG_SCOPE, "membership")
            .unwrap()
            .len() as u64,
    }
}

async fn body(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[test]
fn only_an_organization_administrator_enrolls_this_project_host() {
    let (_root, shared) = open();
    let mut wb = shared.lock_unpoisoned();
    member(&mut wb, "dr-admin", "admin");
    member(&mut wb, "front-desk", "member");
    member(&mut wb, "auditor", "auditor");
    let home = wb.home_id().as_str().to_owned();

    for actor in ["front-desk", "auditor", "stranger"] {
        let (status, _) = wb
            .plan_office_profile_enrollment(ORG_SCOPE, ORG_ID, &home, actor, 7)
            .unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN, "{actor}");
    }
    // A tenant change cannot enroll another organization's directory here.
    let (status, _) = wb
        .plan_office_profile_enrollment(
            "org::organization:other",
            "organization:other",
            &home,
            "dr-admin",
            7,
        )
        .unwrap_err();
    assert_eq!(status, StatusCode::CONFLICT);
    // A stale client that was shown another Project Host is refused.
    let (status, message) = wb
        .plan_office_profile_enrollment(ORG_SCOPE, ORG_ID, "home:elsewhere", "dr-admin", 7)
        .unwrap_err();
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(message.contains("another Project Host"));

    let record = wb
        .plan_office_profile_enrollment(ORG_SCOPE, ORG_ID, &home, "dr-admin", 7)
        .unwrap();
    assert_eq!(record.home_id, home);
    assert_eq!(record.enrolled_by, "dr-admin");
    append(&mut wb, &record);
    assert_eq!(wb.office_profile().unwrap(), Some(record));
    let (status, _) = wb
        .plan_office_profile_enrollment(ORG_SCOPE, ORG_ID, &home, "dr-admin", 8)
        .unwrap_err();
    assert_eq!(status, StatusCode::CONFLICT);
}

#[test]
fn a_hosted_home_cannot_hold_the_profile() {
    let (_root, shared) = open();
    let mut wb = shared.lock_unpoisoned();
    member(&mut wb, "dr-admin", "owner");
    wb.enable_hosted_home_mode();
    let home = wb.home_id().as_str().to_owned();
    assert!(wb.office_profile_enrollable(ORG_SCOPE).is_err());
    let (status, _) = wb
        .plan_office_profile_enrollment(ORG_SCOPE, ORG_ID, &home, "dr-admin", 7)
        .unwrap_err();
    assert_eq!(status, StatusCode::CONFLICT);
    // Even a binding that names this Home serves no office staff when the
    // store is opened as a hosted Home.
    let record = binding(&wb, &home);
    append(&mut wb, &record);
    assert_eq!(
        wb.office_profile_channel_refusal().unwrap().0,
        StatusCode::FORBIDDEN
    );
}

#[test]
fn no_later_record_clears_or_moves_the_binding() {
    let (_root, shared) = open();
    let mut wb = shared.lock_unpoisoned();
    let home = wb.home_id().as_str().to_owned();
    assert!(wb.office_profile().unwrap().is_none());
    let first = binding(&wb, &home);
    append(&mut wb, &first);
    // A stale client's tombstone, a replayed enrollment naming another host,
    // and a direct rebind are all folded away: the first binding stands.
    append(
        &mut wb,
        &OfficeProfileRecord {
            op: RecordOp::Tombstone,
            ..first.clone()
        },
    );
    let rebind = binding(&wb, "home:hosted");
    append(&mut wb, &rebind);
    assert_eq!(wb.office_profile().unwrap(), Some(first));
    assert!(wb.office_profile_channel_refusal().is_none());
    assert!(wb.office_profile_exit_refusal().is_some());
}

#[test]
fn the_binding_survives_restart_and_a_copy_on_another_host_is_refused() {
    let root = tempfile::tempdir().unwrap();
    {
        let wb = crate::open_workbench(root.path()).unwrap();
        wb.lock_unpoisoned()
            .enroll_office_profile_for_test("dr-admin");
    }
    let wb = crate::open_workbench(root.path()).unwrap();
    let guard = wb.lock_unpoisoned();
    assert!(guard.office_profile().unwrap().is_some());
    assert!(guard.office_profile_channel_refusal().is_none());

    // A restored or copied store whose binding names another Project Host is
    // not re-bound to this one, and still lets nothing leave.
    let (_other_root, other) = open();
    let mut other = other.lock_unpoisoned();
    let record = binding(&other, "home:the-office-desktop");
    append(&mut other, &record);
    let (status, message) = other.office_profile_channel_refusal().unwrap();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(message.contains("another Project Host"));
    assert!(other.office_profile_exit_refusal().is_some());
    drop(guard);
}

#[tokio::test]
async fn the_office_channel_refuses_an_unenrolled_home_before_the_handler_reads_a_body() {
    let (_root, wb) = open();
    {
        let mut guard = wb.lock_unpoisoned();
        member(&mut guard, "alice", "member");
    }
    let alice = wb
        .lock_unpoisoned()
        .mint_account_session("alice", "passkey", 60)
        .unwrap();
    let ran = Arc::new(AtomicBool::new(false));
    let seen = ran.clone();
    let app = Router::new()
        .route(
            "/projects/{project}/notes",
            post(move |_body: String| {
                let seen = seen.clone();
                async move {
                    seen.store(true, Ordering::SeqCst);
                    StatusCode::NO_CONTENT
                }
            }),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            wb.clone(),
            crate::office_home_admission::require_office_home_admission,
        ))
        .with_state(wb.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/projects/shared/notes")
                .header("authorization", format!("Bearer {alice}"))
                .body(Body::from("synthetic patient note"))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = body(response).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("not been enrolled"));
    assert!(!ran.load(Ordering::SeqCst));
}

#[test]
fn a_fork_inside_the_profile_is_the_organizations_and_reaches_its_forker() {
    let root = tempfile::tempdir().unwrap();
    let shared = crate::workbench_state::open_lean_workbench(root.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    member(&mut wb, "dr-lee", "member");
    wb.enroll_office_profile_for_test("dr-admin");
    crate::library_routes::create_named_project(&mut wb, "proj-clinic", "Clinic").unwrap();
    let fork = wb
        .fork_project("proj-clinic", None, "dr-lee", "op-1")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let record = wb.library.projects.get(&fork).unwrap().clone();
    assert_eq!(crate::project_owner::recorded_owner(&record), None);
    assert_eq!(record.extra["organization"], ORG_ID);
    assert_eq!(
        wb.project_owner(&fork),
        Some(ProjectOwner::Organization(ORG_ID.into()))
    );
    assert_eq!(&record.home_id, wb.home_id());
    let org = Org::rebuild(wb.store_ref()).unwrap();
    assert!(org.can_access_project("dr-lee", &fork));
    // A second account forking is the organization's too: switching account
    // never yields an account-owned project inside the profile.
    member(&mut wb, "dr-kim", "member");
    let other = wb
        .fork_project("proj-clinic", None, "dr-kim", "op-2")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        wb.project_owner(&other),
        Some(ProjectOwner::Organization(ORG_ID.into()))
    );
    let org = Org::rebuild(wb.store_ref()).unwrap();
    assert!(!org.can_access_project("dr-kim", &fork));
    assert!(org.can_access_project("dr-kim", &other));
}

#[tokio::test]
async fn no_project_moves_off_an_enrolled_project_host() {
    let (_root, wb) = open();
    {
        let mut guard = wb.lock_unpoisoned();
        crate::library_routes::create_named_project(&mut guard, "proj-clinic", "Clinic").unwrap();
        guard.enroll_office_profile_for_test("dr-admin");
    }
    let response = crate::federation::post_handoff_relocate(
        State(wb.clone()),
        HeaderMap::new(),
        Json(crate::federation::HandoffRelocateRequest {
            project: "proj-clinic".into(),
            peer: "authority:hosted".into(),
        }),
    )
    .await
    .into_response();
    let (status, body) = body(response).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("office-controlled profile"));

    let response = crate::federation::post_invite(
        State(wb.clone()),
        HeaderMap::new(),
        Json(crate::federation::InviteRequest {
            project: "proj-clinic".into(),
            disposition: crate::federation::InviteDisposition::Relocate,
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let mut guard = wb.lock_unpoisoned();
    let before = guard
        .library
        .projects
        .get("proj-clinic")
        .unwrap()
        .extra
        .clone();
    assert!(guard.movable_local_projects().is_empty());
    let refused = guard
        .transfer_local_projects(&BTreeSet::from(["proj-clinic".to_owned()]), "acct-someone")
        .unwrap_err();
    assert!(matches!(
        refused,
        crate::project_transfer::TransferRefused::OfficeProfile(_)
    ));
    assert_eq!(
        guard.library.projects.get("proj-clinic").unwrap().extra,
        before
    );
}
