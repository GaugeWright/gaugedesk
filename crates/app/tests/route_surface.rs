//! The router is part of the product, so it is tested like part of the product.
//!
//! Seven defects in the collection path shared one shape: working, tested code
//! that nothing could reach. A drain handler with no dispatch entry. A screening
//! pass called only from tests. A client sending five fields where the route
//! required six. Each had passing tests, because every one of those tests called
//! a function directly — past the router that had never learned about it.
//!
//! A test that invokes a handler proves the handler. It cannot prove that any
//! request in the world arrives there, and that is the property that kept
//! breaking. So this drives the **real** `open_control_plane` router over HTTP,
//! and asks two questions no unit test can:
//!
//! 1. **Does a request to this path reach a handler at all?** The discriminator
//!    is that axum's unmatched-route fallback answers 404 with an *empty* body
//!    while every handler here answers JSON. So a 404 is only acceptable when
//!    something spoke — "no such item" is a handler doing its job; silence is a
//!    route that does not exist.
//!
//! 2. **Does the handler accept the shape its callers send?** A serde rejection
//!    is reported as 422 with `Failed to deserialize`/`missing field`, which is
//!    exactly how the Drain button failed for its whole life. Any such body is a
//!    contract break between a caller and this route, never a legitimate answer.
//!
//! Deliberately *not* asserted: success. These routes touch a network, a
//! keyring, and a gate, and demanding 200 would mean mocking all of it — which
//! is how the original tests ended up proving something other than reachability.
//! A refusal from real code is a pass here; only silence and shape-drift fail.
//!
//! The second test is the structural half: a handler that exists but appears in
//! no router is an orphan, which is the defect *before* it becomes a 404.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use axum::Router;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

use gaugedesk_app::{open_control_plane, open_workbench};

const PROJECT: &str = "proj-default";
/// An id that matches nothing. A route that reaches its handler answers "no such
/// item" in JSON; a route that does not exist answers nothing at all.
const ABSENT_ITEM: &str = "sess_0000000000000000000000000000000000:1";

fn control_plane() -> (tempfile::TempDir, Router) {
    let dir = tempfile::tempdir().unwrap();
    let workbench = open_workbench(dir.path()).unwrap();
    let app = open_control_plane(Arc::clone(&workbench));
    (dir, app)
}

async fn send(app: &Router, method: &str, uri: &str, body: Option<String>) -> (u16, String) {
    static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
    let mut builder = axum::http::Request::builder().method(method).uri(uri);
    if method != "GET" {
        builder = builder.header(
            "idempotency-key",
            format!("route-surface-{}", NEXT_KEY.fetch_add(1, Ordering::Relaxed)),
        );
        builder = builder.header("content-type", "application/json");
    }
    let request: Request<Body> = builder
        .body(body.map(Body::from).unwrap_or_else(Body::empty))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// One production route, and a request shaped the way its callers shape it.
struct RouteCheck {
    method: &'static str,
    uri: String,
    body: Option<String>,
    /// Why this route is in the list, printed when it fails.
    because: &'static str,
}

fn collection_and_gate_surface() -> Vec<RouteCheck> {
    vec![
        RouteCheck {
            method: "GET",
            uri: "/workspace".into(),
            body: None,
            because: "the surface every other check navigates from",
        },
        RouteCheck {
            method: "GET",
            uri: format!("/projects/{PROJECT}/quarantine"),
            body: None,
            because: "the review surface's index (ADR 0110 §7)",
        },
        RouteCheck {
            method: "GET",
            uri: format!("/projects/{PROJECT}/quarantine/{ABSENT_ITEM}"),
            body: None,
            because: "reading one item is the reviewer's path, never an agent's",
        },
        RouteCheck {
            method: "POST",
            uri: format!("/projects/{PROJECT}/quarantine/{ABSENT_ITEM}/screen"),
            body: Some(json!({ "chat_id": "chat-absent" }).to_string()),
            because: "the gate's screening pass — unrouted until 2026-07-30, so \
                      no verdict from the product could ever settle",
        },
        RouteCheck {
            method: "POST",
            uri: format!("/projects/{PROJECT}/quarantine/{ABSENT_ITEM}/review"),
            body: Some(json!({ "verdict": "keep" }).to_string()),
            because: "a reviewer's verdict, carried to the gate that rules on it",
        },
        RouteCheck {
            method: "GET",
            uri: "/collection-recipients".into(),
            body: None,
            because: "the keyring index behind the deployment panel's selector",
        },
        RouteCheck {
            method: "POST",
            uri: "/collection-recipients".into(),
            body: Some(json!({ "recipient_id": "route-surface" }).to_string()),
            because: "load-or-create, so republishing cannot orphan sealed artifacts",
        },
        RouteCheck {
            method: "POST",
            uri: "/public-deployments/collect".into(),
            // The durable local binding resolves edge, deployment, project,
            // recipient, schema, and admission scope. The caller cannot redirect
            // inbound custody by resupplying any of those fields at drain time.
            body: Some(json!({ "binding_id": "route-surface" }).to_string()),
            because: "the drain the owner clicks to receive their collected material",
        },
        RouteCheck {
            method: "POST",
            uri: "/public-deployments/inspect".into(),
            body: Some(
                json!({
                    "deployment_id": "route-surface",
                    "edge_origin": "https://edge.invalid",
                })
                .to_string(),
            ),
            because: "the operation monitor behind a live deployment",
        },
    ]
}

#[tokio::test]
async fn every_declared_route_reaches_a_handler_that_accepts_its_callers_shape() {
    let (_dir, app) = control_plane();
    let mut broken = Vec::new();

    for check in collection_and_gate_surface() {
        let (status, body) = send(&app, check.method, &check.uri, check.body.clone()).await;
        let where_ = format!("{} {}", check.method, check.uri);

        // Axum's fallback answers an unmatched path with 404 and no body. A
        // handler that means "no such thing" answers JSON. The difference is the
        // whole point of this file.
        if status == 404 && body.trim().is_empty() {
            broken.push(format!("{where_} — no route ({})", check.because));
            continue;
        }
        if status == 405 {
            broken.push(format!(
                "{where_} — path exists but not for this method ({})",
                check.because,
            ));
            continue;
        }
        // A shape the route cannot parse is a broken contract with whoever sends
        // it, and it is invisible to any test that calls the handler directly.
        if body.contains("Failed to deserialize") || body.contains("missing field") {
            broken.push(format!("{where_} — {body} ({})", check.because));
        }
    }

    assert!(
        broken.is_empty(),
        "routes that no request can reach, or that refuse their callers' shape:\n  {}",
        broken.join("\n  "),
    );
}

/// Test-only paths compile only into debug builds (DR-0054 Phase A) — release
/// artifacts carry no such routes at all. Where the routes do exist (this test
/// binary is a debug build), the `GAUGEDESK_TEST_RESET` process guard stays
/// as defense in depth: without it the router must refuse them before reset,
/// conflict-injection, or raw account-device fixture state can change.
#[tokio::test]
async fn test_only_harness_routes_refuse_without_activation_guard() {
    assert!(
        gaugedesk_env::var_os("TEST_RESET").is_none(),
        "this disposition check must run without the BDD-only activation guard",
    );
    let (_dir, app) = control_plane();
    for (path, body) in [
        ("/test/reset", json!({})),
        ("/test/force-conflict", json!({ "on": true })),
        (
            "/account/devices",
            json!({
                "id": "test-fixture-device",
                "label": "Test fixture device",
                "subkey_pubkey": "test-fixture-public-subkey",
            }),
        ),
    ] {
        let (status, response) = send(&app, "POST", path, Some(body.to_string())).await;
        assert_eq!(status, 403, "{path} was not disabled: {response}");
        assert!(
            response.contains("disabled"),
            "{path} did not identify its activation guard refusal: {response}",
        );
    }
}

/// Library sync is intentionally part of the co-resident desktop surface: the
/// handler must be reachable there even when no facility has been activated.
/// A 409 is the real handler's fail-closed answer; 404/405 would mean the UI and
/// router have drifted apart again.
#[tokio::test]
async fn local_library_sync_routes_reach_the_desktop_handler() {
    let (_dir, app) = control_plane();
    for path in ["/account/library-sync", "/account/library-sync/pull"] {
        let (status, response) = send(&app, "POST", path, Some(json!({}).to_string())).await;
        assert_eq!(
            status, 409,
            "{path} did not reach its inactive-facility guard: {response}"
        );
        assert!(
            response.contains("library sync") && response.contains("not active"),
            "{path} did not return the library-sync authority refusal: {response}",
        );
    }
}

/// The "your sessions" surface (ACCT-1 / B8, ADR 0147) must be reachable through
/// the real router: listing answers 200 with a `sessions` array, and revoking an
/// absent grant reaches its handler's fail-closed 404 (a body, not silence).
#[tokio::test]
async fn hosted_account_sessions_list_and_revoke_reach_the_handler() {
    let (_dir, app) = control_plane();

    let (status, body) = send(&app, "GET", "/account/sessions", None).await;
    assert_eq!(
        status, 200,
        "session list did not reach its handler: {body}"
    );
    assert!(
        body.contains("\"sessions\""),
        "session list did not return the projection: {body}",
    );

    let (status, body) = send(
        &app,
        "POST",
        "/account/sessions/native-absent/revoke",
        Some(json!({}).to_string()),
    )
    .await;
    assert_eq!(
        status, 404,
        "session revoke did not reach its handler: {body}"
    );
    assert!(
        body.contains("no such session"),
        "session revoke did not return its fail-closed refusal: {body}",
    );
}

/// DR-0051 retires provisional federation drivers once the shipped Engagement
/// operations subsume them. They must remain absent instead of silently returning
/// as undocumented compatibility surface or browser-test shortcuts.
#[tokio::test]
async fn dormant_federation_facades_are_unreachable() {
    let (_dir, app) = control_plane();
    for (method, path, body) in [
        ("POST", "/federation/cross", Some(json!({}).to_string())),
        (
            "POST",
            "/federation/remote-run",
            Some(json!({}).to_string()),
        ),
        ("POST", "/federation/consent", Some(json!({}).to_string())),
        ("GET", "/federation/inbox", None),
        (
            "POST",
            "/federation/revoke-device",
            Some(json!({}).to_string()),
        ),
        (
            "POST",
            "/federation/recovery-code",
            Some(json!({}).to_string()),
        ),
        ("POST", "/federation/restore", Some(json!({}).to_string())),
        ("POST", "/federation/erase", Some(json!({}).to_string())),
        ("GET", "/federation/erase/queue", None),
        (
            "POST",
            "/federation/erase/term",
            Some(json!({}).to_string()),
        ),
    ] {
        let (status, response) = send(&app, method, path, body).await;
        assert_eq!(status, 404, "{method} {path} unexpectedly remained routed");
        assert!(
            response.trim().is_empty(),
            "{method} {path} reached a handler: {response}",
        );
    }
}

/// Attested boundary acceptance remains a deferred internal primitive until a
/// shipped attestation client can bind a server nonce into a real quote. The
/// former handler-only challenge route must not survive as compatibility API.
#[tokio::test]
async fn unconsumed_attestation_challenge_facade_is_unreachable() {
    let (_dir, app) = control_plane();
    let (status, response) = send(
        &app,
        "POST",
        "/boundaries/boundary-1/challenge",
        Some(json!({ "participant": "device-1" }).to_string()),
    )
    .await;
    assert_eq!(
        status, 404,
        "attestation challenge unexpectedly remained routed"
    );
    assert!(
        response.trim().is_empty(),
        "challenge reached a handler: {response}"
    );
}

/// The carrier-neutral reducer remains, but the former mock-carrier HTTP
/// service had no native client or APNs/FCM adapter. Release routers must not
/// expose that test driver while the real provider slice is deferred.
#[tokio::test]
async fn unconsumed_mobile_wake_facades_are_unreachable() {
    let (_dir, app) = control_plane();
    for (method, path, body) in [
        (
            "POST",
            "/account/mobile/installations",
            Some(json!({}).to_string()),
        ),
        (
            "DELETE",
            "/account/mobile/installations/device-1",
            Some(json!({}).to_string()),
        ),
        ("GET", "/account/mobile/wakes", None),
        ("POST", "/mobile/wakes", Some(json!({}).to_string())),
    ] {
        let (status, response) = send(&app, method, path, body).await;
        assert_eq!(status, 404, "{method} {path} unexpectedly remained routed");
        assert!(
            response.trim().is_empty(),
            "{method} {path} reached a handler: {response}",
        );
    }
}

/// A handler nothing routes to is the defect one step before it becomes a 404.
///
/// Both `screen_quarantined_item` and the edge's collection drain existed,
/// compiled, and were exercised by tests while being unreachable from any
/// request. This reads the source rather than the router because axum's `Router`
/// does not expose its table — a coarse check that catches the exact mistake is
/// worth more than an elegant one that cannot run.
#[test]
fn no_route_handler_is_left_unwired() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    // Everything that builds routes, whichever binary mounts it.
    let mut router_text = String::new();
    let mut handlers: Vec<(String, String)> = Vec::new();
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if text.contains(".route(") {
            router_text.push_str(&text);
        }
        if !name.ends_with("_routes.rs") {
            continue;
        }
        for line in text.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("pub async fn ") else {
                continue;
            };
            let Some(handler) = rest.split('(').next() else {
                continue;
            };
            // Handlers take axum extractors; helpers in the same file do not.
            let signature: String = text
                .split(&format!("pub async fn {handler}("))
                .nth(1)
                .unwrap_or_default()
                .chars()
                .take(400)
                .collect();
            if signature.contains("State(") || signature.contains("axum::extract::") {
                handlers.push((name.clone(), handler.to_owned()));
            }
        }
    }
    assert!(
        handlers.len() > 20,
        "the scan found only {} handlers, so it is matching nothing and proving nothing",
        handlers.len(),
    );

    let orphans: BTreeSet<String> = handlers
        .into_iter()
        .filter(|(_, handler)| {
            // Mentioned anywhere a route is built. Its own definition lives in a
            // file that may itself build routes, so the definition is excluded.
            !router_text
                .lines()
                .filter(|line| !line.trim().starts_with(&format!("pub async fn {handler}")))
                .any(|line| line.contains(handler.as_str()))
        })
        .map(|(file, handler)| format!("{file}::{handler}"))
        .collect();

    assert!(
        orphans.is_empty(),
        "handlers that no router mounts — reachable from tests, from nothing else:\n  {}",
        orphans.into_iter().collect::<Vec<_>>().join("\n  "),
    );
}
