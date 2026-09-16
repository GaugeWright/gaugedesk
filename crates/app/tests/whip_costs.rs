//! What a project's whips cost, over the real router (COST-3).
//!
//! Driven through `open_control_plane` rather than by calling the projection,
//! for the reason `route_surface.rs` gives at length: a test that invokes a
//! handler proves the handler and cannot prove that any request in the world
//! arrives there. Seven defects in the collection path were working, tested
//! code that nothing could reach.

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use gaugedesk_app::{open_control_plane, open_workbench};

const PROJECT: &str = "proj-default";

fn control_plane() -> (tempfile::TempDir, Router) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workbench = open_workbench(dir.path()).expect("workbench");
    let app = open_control_plane(Arc::clone(&workbench));
    (dir, app)
}

async fn get(app: &Router, uri: &str) -> (u16, Value) {
    let request: Request<Body> = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status().as_u16();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// A project that has run nothing costs a complete zero, and says so.
///
/// Zero rather than absent, because nothing having run is something the desk
/// knows rather than something it failed to read. The distinction is the one
/// the layer below is built around, and this is where a client meets it.
#[tokio::test]
async fn a_project_that_has_run_nothing_costs_a_recorded_zero() {
    let (_dir, app) = control_plane();
    let (status, body) = get(&app, &format!("/projects/{PROJECT}/whip-costs")).await;

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["schema"], "gaugedesk.project_whip_costs.v1");
    assert_eq!(body["project"], PROJECT);
    assert_eq!(body["complete"], true);
    assert_eq!(body["unread"], Value::Null);
    assert_eq!(body["total"]["amount_micros"], 0);
    assert_eq!(body["total"]["recorded_micros"], 0);
    assert_eq!(body["gaps"], serde_json::json!([]));
    assert!(
        body["whips"]
            .as_array()
            .is_some_and(|whips| !whips.is_empty()),
        "every project has a gate program before anything runs it: {body}"
    );
}

/// The card ships with no rates, and the document says so rather than implying
/// the project was free.
///
/// `rated_models: 0` is the honest reading of an empty card, and it is what a
/// surface needs to explain a null total that has no other gap to point at.
#[tokio::test]
async fn the_report_names_the_rate_card_it_was_priced_under() {
    let (_dir, app) = control_plane();
    let (_status, body) = get(&app, &format!("/projects/{PROJECT}/whip-costs")).await;

    assert_eq!(body["rate_card"]["currency"], "USD");
    assert!(
        body["rate_card"]["version"]
            .as_str()
            .is_some_and(|v| !v.is_empty()),
        "a figure can only be re-explained if it names the card it came from: {body}"
    );
    assert!(body["rate_card"]["rated_models"].as_u64().is_some());
}

/// An unknown project is a refusal, not an empty cost.
#[tokio::test]
async fn an_unknown_project_has_no_cost_rather_than_a_zero_one() {
    let (_dir, app) = control_plane();
    let (status, body) = get(&app, "/projects/proj-absent/whip-costs").await;

    assert_eq!(status, 404);
    assert_eq!(body["error"], "no such project");
}
