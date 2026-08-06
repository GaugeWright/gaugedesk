//! Hermetic stand-in Hub for the desktop account-handoff e2e (LOGIN-5, ADR 0123).
//!
//! Plays the Hub's side of the **native device handoff** so the journey —
//! sign-in, device-bound refresh, revocation stopping refresh, sign-out — is
//! drivable with no IdP and no network. The real Hub handlers (exchange
//! recording the device, refresh refusing a revoked one) carry their own unit
//! tests in `auth_oidc`; this stub proves the desktop *client* half (the local
//! control plane's custody + the surfaces) end-to-end.
//!
//! Deterministic: every refresh advances `exp` by a strictly increasing
//! counter, so "refresh extended the session" is assertable across reads even
//! within one wall-clock second. `POST /test/revoke` flips the device to
//! revoked, after which any device-bound refresh is refused.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};

const PERSON: &str = "e2e-person@example.test";
const CODE: &str = "e2e-handoff-code";
const DEVICE: &str = "native-e2e-device";
/// Short enough that every status read on the desktop control plane falls
/// inside its proactive-refresh window (10 minutes).
const TOKEN_LIFE_SECS: i64 = 360;

#[derive(Default)]
struct Hub {
    revoked: AtomicBool,
    refreshes: AtomicI64,
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A JWT-shaped token (unsigned — the desktop control plane projects claims
/// from an already-server-verified token; it never verifies signatures).
fn mint(exp: i64) -> String {
    let b64 = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
    format!(
        "{}.{}.sig",
        b64(&json!({ "alg": "none" })),
        b64(&json!({ "sub": PERSON, "exp": exp }))
    )
}

async fn exchange(State(hub): State<Arc<Hub>>, Json(body): Json<Value>) -> impl IntoResponse {
    let code = body.get("code").and_then(Value::as_str).unwrap_or_default();
    let verifier = body
        .get("verifier")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if code != CODE || verifier.is_empty() {
        return (StatusCode::UNAUTHORIZED, "unknown handoff").into_response();
    }
    hub.revoked.store(false, Ordering::SeqCst);
    Json(json!({
        "id_token": mint(now_secs() + TOKEN_LIFE_SECS),
        "token_type": "Bearer",
        "device_id": DEVICE,
    }))
    .into_response()
}

async fn refresh(State(hub): State<Arc<Hub>>, headers: HeaderMap) -> impl IntoResponse {
    let authorized = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("Bearer "));
    if !authorized {
        return (StatusCode::UNAUTHORIZED, "authenticate to refresh").into_response();
    }
    let device_bound = headers.get("x-gw-device").is_some();
    if device_bound && hub.revoked.load(Ordering::SeqCst) {
        return (
            StatusCode::UNAUTHORIZED,
            "this device's account session was revoked",
        )
            .into_response();
    }
    let n = hub.refreshes.fetch_add(1, Ordering::SeqCst) + 1;
    Json(json!({
        "person": PERSON,
        "id_token": mint(now_secs() + TOKEN_LIFE_SECS + n),
        "token_type": "Bearer",
    }))
    .into_response()
}

async fn homes() -> impl IntoResponse {
    Json(json!({
        "homes": [{
            "id": "e2e-home",
            "kind": "registered",
            "endpoint": "https://home.e2e.test",
            "relay": null,
        }],
        "selected_home": null,
    }))
}

async fn home_routes() -> impl IntoResponse {
    Json(json!({
        "routes": [{
            "project": "e2e-project",
            "home_id": "e2e-home",
            "endpoint": "https://home.e2e.test",
        }],
    }))
}

async fn revoke(State(hub): State<Arc<Hub>>) -> impl IntoResponse {
    hub.revoked.store(true, Ordering::SeqCst);
    StatusCode::NO_CONTENT
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let addr =
        std::env::var("GAUGEWRIGHT_TEST_HUB_ADDR").unwrap_or_else(|_| "127.0.0.1:7910".to_string());
    let hub = Arc::new(Hub::default());
    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/auth/mobile/exchange", post(exchange))
        .route("/auth/mobile/refresh", post(refresh))
        .route("/account/homes", get(homes))
        .route("/account/home-routes", get(home_routes))
        .route("/test/revoke", post(revoke))
        .with_state(hub);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind test hub");
    eprintln!("[test-account-hub] listening on http://{addr}");
    axum::serve(listener, app).await.expect("serve test hub");
}
