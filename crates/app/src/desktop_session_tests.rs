//! DR-0188: the desktop's own UI gets a Home session for its signed-in owner,
//! and nobody else does.
use super::*;
use crate::{
    home_owner::claim_if_never_claimed,
    org::{MembershipRecord, MembershipStatus, RecordOp, ORG_ID, ORG_SCOPE},
};
use axum::{body::Body, http::Request, response::IntoResponse};
use tower::ServiceExt;

fn open() -> (tempfile::TempDir, SharedWorkbench) {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    (root, wb)
}

fn signed_in_owner() -> (tempfile::TempDir, SharedWorkbench) {
    let (root, wb) = open();
    crate::account_signin::store_session_for_test(&wb);
    claim_if_never_claimed(&wb).unwrap();
    (root, wb)
}

fn actor(wb: &SharedWorkbench, token: &str) -> Option<String> {
    wb.lock_unpoisoned()
        .authenticate_action_context(token)
        .map(|context| context.actor().as_str().to_owned())
}

#[test]
fn nobody_signed_in_gets_no_session() {
    let (_root, wb) = open();
    assert_eq!(home_session(&wb), None);
}

/// A signed-in account with no role in this computer's directory still works
/// here as itself (DR-0328); what it reaches is decided per project.
#[test]
fn a_signed_in_account_without_a_role_works_here_as_itself() {
    let (_root, wb) = open();
    let owner = MembershipRecord {
        id: "the-owner".into(),
        op: RecordOp::Upsert,
        org_id: ORG_ID.into(),
        authority: "the-owner".into(),
        email: String::new(),
        role: "owner".into(),
        status: MembershipStatus::Active,
        managed_by_scim: false,
        team: None,
    };
    wb.lock_unpoisoned()
        .store_mut()
        .append_record(
            ORG_SCOPE,
            "membership",
            &serde_json::to_string(&owner).unwrap(),
        )
        .unwrap();
    crate::account_signin::store_session_for_test(&wb);
    claim_if_never_claimed(&wb).unwrap();
    let token = home_session(&wb).expect("a session for the signed-in account");
    assert_eq!(actor(&wb, &token).as_deref(), Some("account-root"));
}

#[test]
fn the_owner_gets_one_home_session_attributed_to_them() {
    let (_root, wb) = signed_in_owner();
    let token = home_session(&wb).expect("the owner's UI gets a session");
    assert_eq!(actor(&wb, &token).as_deref(), Some("account-root"));
    assert_eq!(
        home_session(&wb).as_deref(),
        Some(token.as_str()),
        "the same session while the sign-in holds"
    );
    assert_ne!(
        Some(token.as_str()),
        crate::account_signin::hub_session_token(&wb).as_deref(),
        "never the Hub token"
    );
}

#[tokio::test]
async fn signing_out_revokes_the_session() {
    let (_root, wb) = signed_in_owner();
    let token = home_session(&wb).unwrap();
    crate::account_signin::post_signin_logout(axum::extract::State(wb.clone())).await;
    assert_eq!(actor(&wb, &token), None, "revoked at sign-out");
    assert_eq!(home_session(&wb), None);
}

#[test]
fn losing_standing_or_changing_account_revokes_the_session() {
    let (_root, wb) = signed_in_owner();
    let token = home_session(&wb).unwrap();
    crate::account_signin::store_session_as_for_test(&wb, "someone-else");
    let theirs = home_session(&wb).expect("another account works here as itself");
    assert_eq!(actor(&wb, &theirs).as_deref(), Some("someone-else"));
    assert_eq!(
        actor(&wb, &token),
        None,
        "and the owner's session is revoked"
    );

    crate::account_signin::store_session_for_test(&wb);
    let again = home_session(&wb).expect("the owner signs back in");
    let deprovisioned = MembershipRecord {
        id: "account-root".into(),
        op: RecordOp::Upsert,
        org_id: ORG_ID.into(),
        authority: "account-root".into(),
        email: String::new(),
        role: "owner".into(),
        status: MembershipStatus::Deprovisioned,
        managed_by_scim: false,
        team: None,
    };
    wb.lock_unpoisoned()
        .store_mut()
        .append_record(
            ORG_SCOPE,
            "membership",
            &serde_json::to_string(&deprovisioned).unwrap(),
        )
        .unwrap();
    // A role is not standing on a desktop, so losing one keeps the session.
    assert_eq!(home_session(&wb).as_deref(), Some(again.as_str()));
}

async fn workspace_projects(app: &axum::Router, bearer: Option<&str>) -> Vec<String> {
    let mut request = Request::builder().uri("/workspace");
    if let Some(token) = bearer {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let workspace: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    workspace["projects"]
        .as_array()
        .map(|projects| {
            projects
                .iter()
                .filter_map(|project| project["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

async fn get(app: &axum::Router, path: &str, bearer: Option<&str>) -> axum::http::StatusCode {
    let mut request = Request::builder().uri(path);
    if let Some(token) = bearer {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    app.clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

/// What the session is for: a native route that refused the desktop UI admits
/// its owner, and the legacy routes the UI already used keep working with it.
#[tokio::test]
async fn the_desktop_ui_reaches_native_and_legacy_routes_as_its_owner() {
    let (_root, wb) = signed_in_owner();
    let app = crate::open_control_plane(wb.clone());
    let trackers = format!("/projects/{}/trackers", crate::DEFAULT_PROJECT);
    assert_eq!(
        get(&app, &trackers, None).await,
        axum::http::StatusCode::UNAUTHORIZED,
        "without the session the native route has no actor"
    );
    let token = home_session(&wb).unwrap();
    assert_eq!(
        get(&app, &trackers, Some(&token)).await,
        axum::http::StatusCode::OK
    );
    // The task bar is a person's queue, so it too needs the session (WHIP-4).
    assert_eq!(
        get(&app, "/tasks", None).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get(&app, "/tasks", Some(&token)).await,
        axum::http::StatusCode::OK
    );
    let whips = format!("/projects/{}/whips", crate::DEFAULT_PROJECT);
    for legacy in [
        "/workspace",
        "/roster",
        "/fork-tree",
        "/chats",
        whips.as_str(),
    ] {
        let local = get(&app, legacy, None).await;
        assert!(
            local.is_success(),
            "{legacy} answers the local posture: {local}"
        );
        assert_eq!(
            get(&app, legacy, Some(&token)).await,
            local,
            "{legacy} answers the owner as it answered the local operator"
        );
    }
}

/// Selecting B changes the window, not the ownership or availability of A's
/// Home. The loopback operator shortcut must not serve A's work to B, even if
/// B sends no bearer, while the separately admitted relay can still serve A.
#[tokio::test]
async fn another_selected_account_reaches_none_of_the_first_accounts_projects() {
    let (_root, wb) = signed_in_owner();
    let owner_relay = relay_session(&wb, "account-root").unwrap();
    let app = crate::open_runtime::desktop_operator_plane(wb.clone());
    assert_eq!(
        get(&app, "/workspace", None).await,
        axum::http::StatusCode::OK
    );

    crate::account_signin::store_session_as_for_test(&wb, "someone-else");
    let theirs = home_session(&wb).expect("it works here as itself");
    // Its own window session, and the local channel alike, reach none of A's
    // projects (DR-0328 §2).
    for bearer in [Some(theirs.as_str()), None] {
        assert!(
            !workspace_projects(&app, bearer)
                .await
                .contains(&crate::DEFAULT_PROJECT.to_owned()),
            "A's Personal is not shown to {bearer:?}"
        );
    }
    assert_eq!(
        get(&app, "/account/hub-sessions", None).await,
        axum::http::StatusCode::OK,
        "the account selector remains reachable"
    );
    assert_eq!(
        actor(&wb, &relay_session(&wb, "account-root").unwrap()).as_deref(),
        Some("account-root"),
        "A's retained sign-in still serves A's admitted relay"
    );
    assert_eq!(actor(&wb, &owner_relay).as_deref(), Some("account-root"));

    crate::account_signin::store_session_for_test(&wb);
    assert_eq!(
        get(&app, "/workspace", None).await,
        axum::http::StatusCode::OK
    );
}

#[tokio::test]
async fn sign_out_shows_the_local_account_not_the_owners_projects() {
    let (_root, wb) = signed_in_owner();
    let app = crate::open_runtime::desktop_operator_plane(wb.clone());
    assert_eq!(
        get(&app, "/workspace", None).await,
        axum::http::StatusCode::OK
    );

    crate::account_signin::post_signin_logout(axum::extract::State(wb.clone())).await;
    assert!(
        !workspace_projects(&app, None)
            .await
            .contains(&crate::DEFAULT_PROJECT.to_owned()),
        "sign-out shows the local account's work, not the owner's"
    );
    let status = crate::account_signin::get_signin_status(axum::extract::State(wb.clone()))
        .await
        .into_response();
    let bytes = axum::body::to_bytes(status.into_body(), usize::MAX)
        .await
        .unwrap();
    let status: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status["local_choice_required"], true);

    let selected = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/account/hub-session/select-local")
                .header("idempotency-key", "select-local-after-signout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(selected.status(), axum::http::StatusCode::OK);
    assert_eq!(
        get(&app, "/workspace", None).await,
        axum::http::StatusCode::OK
    );
}

#[tokio::test]
async fn select_local_is_not_available_on_an_ordinary_home_listener() {
    let (_root, wb) = signed_in_owner();
    let app = crate::open_control_plane(wb);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/account/hub-session/select-local")
                .header("idempotency-key", "select-local-on-ordinary-home")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn native_home_broker_is_on_the_desktop_operator_plane() {
    let (_root, wb) = open();
    let app = crate::open_runtime::desktop_operator_plane(wb);
    assert_eq!(
        get(&app, "/account/hub-session/home/home:other/workspace", None).await,
        axum::http::StatusCode::UNAUTHORIZED,
        "the local broker asks for the selected sealed session before dialing"
    );
}

/// GaugeDesk 0.8.2 retained a sign-in for an account named by a 130-character
/// id but could never mint that account's keys — `<keys>/accounts/<hex>` was
/// past the file-name limit — and 0.8.4 mints them under a hashed folder name
/// (#1293). Neither the update nor the keys it then mints may drop the
/// retained sign-in: the window must open signed in (2026-10-07).
#[tokio::test(flavor = "multi_thread")]
async fn a_sign_in_retained_under_the_0_8_2_layout_opens_after_an_update() {
    let root = tempfile::tempdir().unwrap();
    // The length of an account named by its P-256 public key.
    let account = format!("04{}", "d9".repeat(64));
    {
        let wb = crate::open_workbench(root.path()).unwrap();
        crate::account_signin::store_session_as_for_test(&wb, &account);
        assert!(
            wb.lock_unpoisoned()
                .account_key_store()
                .held(&account, 0)
                .unwrap()
                .is_none(),
            "0.8.2 held no keys for this account"
        );
    }

    // The update: the new version's process opens the same root.
    let wb = crate::open_runtime::open_prepare(root.path()).unwrap();
    assert_eq!(
        crate::account_signin::signed_in_accounts(&wb),
        vec![account.clone()]
    );
    let token = home_session(&wb).expect("the retained sign-in opens after the update");
    assert_eq!(actor(&wb, &token).as_deref(), Some(account.as_str()));

    // Its first publish mints the account's keys, under the hashed name.
    wb.lock_unpoisoned()
        .account_key_store()
        .mint(&account, 0)
        .unwrap();
    let folders: Vec<String> = std::fs::read_dir(root.path().join("keys").join("accounts"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(folders.len(), 1);
    assert!(folders[0].starts_with("sha256-"), "{folders:?}");
    assert_eq!(
        home_session(&wb).as_deref(),
        Some(token.as_str()),
        "minting the account's keys leaves the sign-in open"
    );

    drop(wb);
    let wb = crate::open_workbench(root.path()).unwrap();
    assert!(crate::account_signin::hub_standing_for(&wb, &account).is_some());
    assert!(home_session(&wb).is_some(), "and so does the next restart");
}
