//! Two-instance federation roster enforcement over the real network (D-REMOTE).
//!
//! The production Engagement journey owns crossing/run evidence. This focused
//! integration keeps the independent peer-revocation tooth: two authorities pair
//! through the real rendezvous and cert-pinned TLS setup, then the shipped roster
//! operation revokes one peer durably and refuses its future project work.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use gaugewright_app::federation::Federation;
use gaugewright_app::open_control_plane;
use gaugewright_app::{SharedWorkbench, Workbench};
use gaugewright_core::ids::AuthorityId;
use gaugewright_store::Store;

fn instance(authority: &str, broker: &str) -> (Router, tempfile::TempDir, SharedWorkbench) {
    let root = tempfile::tempdir().unwrap();
    let fed =
        Federation::open(AuthorityId::new(authority), root.path(), broker.to_string()).unwrap();
    let wb = Workbench::new(Store::open_in_memory().unwrap())
        .with_authority(AuthorityId::new(authority))
        .with_root(root.path())
        .with_federation(fed);
    let shared = Arc::new(Mutex::new(wb));
    (open_control_plane(Arc::clone(&shared)), root, shared)
}

async fn post(app: &Router, uri: &str, body: Value) -> (StatusCode, Value) {
    static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header(
            "idempotency-key",
            format!(
                "federation-test-{}",
                NEXT_KEY.fetch_add(1, Ordering::Relaxed)
            ),
        )
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn get(app: &Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn delete(app: &Router, uri: &str) -> (StatusCode, Value) {
    static NEXT_KEY: AtomicU64 = AtomicU64::new(10_000);
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header(
            "idempotency-key",
            format!(
                "federation-delete-test-{}",
                NEXT_KEY.fetch_add(1, Ordering::Relaxed)
            ),
        )
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn start_broker() -> (
    String,
    Option<gaugewright_relay_transport::test_relay::TestRelay>,
) {
    if let Ok(endpoint) = std::env::var("GAUGEWRIGHT_LIVE_RELAY_ENDPOINT") {
        return (endpoint, None);
    }
    let relay = gaugewright_relay_transport::test_relay::TestRelay::bind()
        .await
        .unwrap();
    (relay.endpoint().to_owned(), Some(relay))
}

async fn pair(a: &Router, b: &Router) {
    let (_, a_ticket) = post(a, "/federation/pairing-ticket", json!({})).await;
    let (_, b_ticket) = post(b, "/federation/pairing-ticket", json!({})).await;
    let (sa, _) = post(b, "/federation/pair", a_ticket).await;
    let (sb, _) = post(a, "/federation/pair", b_ticket).await;
    assert_eq!(sa, StatusCode::OK);
    assert_eq!(sb, StatusCode::OK);
}

#[tokio::test]
async fn revoking_a_peer_over_http_blocks_future_work_and_keeps_the_audit_record() {
    let (broker, _relay) = start_broker().await;
    let (alice, _ra, _alice_wb) = instance("alice", &broker);
    let (bob, _rb, _bob_wb) = instance("bob", &broker);
    pair(&alice, &bob).await;

    let (status, body) = delete(&alice, "/federation/peers/bob").await;
    assert_eq!(status, StatusCode::OK, "revoke response: {body}");
    assert_eq!(body["authority"], "bob");
    assert_eq!(body["active"], false);

    let (_, peers) = get(&alice, "/federation/peers").await;
    assert_eq!(peers["peers"][0]["authority"], "bob");
    assert_eq!(peers["peers"][0]["active"], false);

    let (refused, refusal) = post(
        &alice,
        "/federation/run/place",
        json!({
            "peer": "bob",
            "project": "p1",
            "archetype": "analyst",
            "data_handle": "data-1",
            "prompt": "must not run"
        }),
    )
    .await;
    assert_eq!(refused, StatusCode::BAD_REQUEST, "refusal: {refusal}");

    let (missing, _) = delete(&alice, "/federation/peers/unknown").await;
    assert_eq!(missing, StatusCode::NOT_FOUND);
}
