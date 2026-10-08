use super::*;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;

use gaugedesk_core::ids::HomeId;
use gaugedesk_core::signature::SigningKey;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32]).unwrap()
}

fn route(project: &str, endpoint: &str) -> OpaqueHomeRoute {
    OpaqueHomeRoute {
        project: project.into(),
        home_id: HomeId::new("home:owner"),
        endpoint: endpoint.into(),
        relay: None,
        author_authority: String::new(),
        author_root_pubkey: String::new(),
        author_signature: None,
        placement: None,
    }
}

fn entry(generation: u64, routes: Vec<OpaqueHomeRoute>) -> crate::directory_sync::FetchedRecord {
    let mut record = crate::directory_sync::FetchedRecord {
        entry: gaugedesk_directory_protocol::retraction_entry("owner-root".into(), generation),
        signature: None,
    };
    record.entry.retracted = false;
    record.entry.directory.home_routes = routes;
    record
}

fn pin(project_key: &SigningKey) -> SharedProjectPin {
    SharedProjectPin {
        id: "p-shared".into(),
        home_id: "home:owner".into(),
        project_key: project_key.public_key().as_str().into(),
        owner_root: "owner-root".into(),
    }
}

#[test]
fn only_a_route_the_pinned_key_placed_is_vouched_for_newest_first() {
    let (project, host, stranger) = (key(1), key(2), key(3));
    let placed = |endpoint: &str, by: &SigningKey| {
        gaugedesk_directory_protocol::sign_placement(route("p-shared", endpoint), by, &host)
            .unwrap()
    };
    let entries = vec![
        entry(1, vec![placed("https://old.example", &project)]),
        entry(
            4,
            vec![
                placed("https://forged.example", &stranger),
                route("p-shared", "https://unplaced.example"),
            ],
        ),
        entry(
            3,
            vec![
                placed("https://new.example", &project),
                placed("https://other.example", &project),
            ],
        ),
    ];
    let chosen = newest_placed(&entries, &pin(&project)).expect("a placed route");
    assert_eq!(
        chosen.endpoint, "https://new.example",
        "the newest route the pinned key placed; a forged or unplaced one is never taken"
    );
    let mut other = pin(&project);
    other.id = "p-elsewhere".into();
    assert!(
        newest_placed(&entries, &other).is_none(),
        "nothing for another project"
    );
}

#[test]
fn a_pin_is_kept_per_account_and_never_moves_to_another_key() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    let mut guard = wb.lock_unpoisoned();
    let pinned = pin(&key(1));
    guard.keep_shared_project_pin("acct-a", &pinned).unwrap();
    guard.keep_shared_project_pin("acct-a", &pinned).unwrap();
    assert_eq!(guard.shared_project_pins("acct-a"), vec![pinned.clone()]);
    assert!(
        guard.shared_project_pins("acct-b").is_empty(),
        "per account"
    );

    let swapped = pin(&key(9));
    assert_eq!(
        guard.keep_shared_project_pin("acct-a", &swapped),
        Err(PinRefusal::DifferentKey)
    );
    let incomplete = SharedProjectPin {
        project_key: String::new(),
        ..pinned.clone()
    };
    assert_eq!(
        guard.keep_shared_project_pin("acct-a", &incomplete),
        Err(PinRefusal::Incomplete)
    );
    assert_eq!(guard.shared_project_pins("acct-a"), vec![pinned]);
}

#[tokio::test]
async fn only_the_window_with_a_signed_in_account_keeps_a_pin() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    let token = wb
        .lock_unpoisoned()
        .mint_account_session("acct-dana", crate::desktop_session::METHOD, 3600)
        .unwrap();
    let body = serde_json::json!({
        "project": "p-shared",
        "home_id": "home:owner",
        "project_key": key(1).public_key().as_str(),
        "owner_root": "owner-root",
    });
    let attempts = std::sync::atomic::AtomicUsize::new(0);
    let post = |app: axum::Router, bearer: Option<String>| {
        let body = body.clone();
        let attempt = attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        async move {
            let mut request = Request::builder()
                .method("POST")
                .uri("/account/shared-projects")
                .header("idempotency-key", format!("pin-{attempt}"))
                .header("content-type", "application/json");
            if let Some(bearer) = bearer {
                request = request.header("authorization", format!("Bearer {bearer}"));
            }
            let response = app
                .oneshot(request.body(Body::from(body.to_string())).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let _ = response.into_body().collect().await;
            status
        }
    };
    let relay = crate::open_control_plane(wb.clone());
    assert_eq!(
        post(relay, Some(token.clone())).await,
        StatusCode::FORBIDDEN
    );
    let window = crate::open_runtime::desktop_operator_plane(wb.clone());
    assert_eq!(post(window.clone(), None).await, StatusCode::UNAUTHORIZED);
    assert!(wb
        .lock_unpoisoned()
        .shared_project_pins("acct-dana")
        .is_empty());
    assert_eq!(post(window, Some(token)).await, StatusCode::OK);
    assert_eq!(
        wb.lock_unpoisoned().shared_project_pins("acct-dana").len(),
        1
    );
}
