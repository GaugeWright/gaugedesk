//! The account surface end to end (ACCT-1): the operator's device registry, settings,
//! and sealed linked-credentials over the mounted `control_plane`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use gaugedesk_app::account::{DeviceRecord, DeviceStatus, RecordOp};
use gaugedesk_app::open_control_plane;
use gaugedesk_app::Workbench;
use gaugedesk_store::Store;
use gaugedesk_workspace::Instance;

fn workbench() -> (tempfile::TempDir, Router) {
    let dir = tempfile::tempdir().unwrap();
    let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
    let store = Store::open_in_memory().unwrap();
    let wb = Workbench::with_target("inst-test", instance, store);
    (dir, open_control_plane(Arc::new(Mutex::new(wb))))
}

async fn send(app: &Router, method: &str, uri: &str, body: Option<&str>) -> (StatusCode, Value) {
    static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
    let mut builder = Request::builder().method(method).uri(uri);
    if method != "GET" && method != "HEAD" && method != "OPTIONS" {
        builder = builder.header(
            "idempotency-key",
            format!("account-test-{}", NEXT_KEY.fetch_add(1, Ordering::Relaxed)),
        );
    }
    let req = match body {
        Some(b) => builder
            .header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn device_registry_list_and_revoke_preserve_a_proof_bound_seed() {
    let dir = tempfile::tempdir().unwrap();
    let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
    let store = Store::open_in_memory().unwrap();
    let mut wb = Workbench::with_target("inst-test", instance, store);
    wb.upsert_account_device(&DeviceRecord {
        id: "phone".into(),
        op: RecordOp::Upsert,
        label: "My phone".into(),
        subkey_pubkey: "ab12".into(),
        status: DeviceStatus::Active,
        enrolled_at: 1,
    })
    .unwrap();
    let app = open_control_plane(Arc::new(Mutex::new(wb)));

    let (s, body) = send(&app, "GET", "/account/devices", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["devices"].as_array().unwrap().len(), 1);

    // Revoke keeps the record but flips status (INV-6).
    let (s, body) = send(&app, "POST", "/account/devices/phone/revoke", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["device"]["status"], "revoked");

    let (_s, body) = send(&app, "GET", "/account/devices", None).await;
    assert_eq!(body["devices"].as_array().unwrap().len(), 1);
    assert_eq!(body["devices"][0]["status"], "revoked");

    // Revoking an unknown device is a 404.
    let (s, _) = send(&app, "POST", "/account/devices/ghost/revoke", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn settings_round_trip() {
    let (_dir, app) = workbench();
    let (s, _) = send(
        &app,
        "PUT",
        "/account/settings/theme",
        Some(r#"{"value":"dark"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, body) = send(&app, "GET", "/account/settings", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["settings"]["theme"], "dark");
}

#[tokio::test]
async fn linked_credential_is_sealed_and_token_never_leaves() {
    let (_dir, app) = workbench();

    // Link an OpenAI account — the token goes in sealed.
    let (s, body) = send(
        &app,
        "POST",
        "/account/credentials",
        Some(r#"{"provider":"openai","token":"sk-super-secret"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["provider"], "openai");
    assert_eq!(body["linked"], true);

    // The list exposes the provider — never the token (sealed or otherwise).
    let (s, body) = send(&app, "GET", "/account/credentials", None).await;
    assert_eq!(s, StatusCode::OK);
    let raw = body.to_string();
    assert!(
        !raw.contains("sk-super-secret"),
        "token must never be returned over HTTP"
    );
    assert!(!raw.contains("token"), "no token field at all");
    assert_eq!(body["credentials"][0]["provider"], "openai");

    // Unlink.
    let (s, body) = send(&app, "DELETE", "/account/credentials/openai", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["linked"], false);
    let (_s, body) = send(&app, "GET", "/account/credentials", None).await;
    assert_eq!(body["credentials"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn managed_plan_and_usage_projection_round_trip() {
    let (_dir, app) = workbench();
    let (status, body) = send(
        &app,
        "POST",
        "/account/managed-inference",
        Some(r#"{"plan":"personal-managed","status":"active","included_tokens":250000}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["plan"]["status"], "active");

    let (status, body) = send(&app, "GET", "/account/managed-inference", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["plan"]["plan"], "personal-managed");
    assert_eq!(
        body["funding_ref"],
        "gaugedesk:managed-plan:v1:6163636f756e74:706572736f6e616c2d6d616e61676564"
    );
    assert_eq!(body["usage"]["runs"], 0);
    assert_eq!(body["usage"]["included_tokens"], 250000);
}
