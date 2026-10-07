//! `POST /public-deployments/import` over the real router, against a hosted
//! origin that records every request it is sent (PANEL-7).
//!
//! A hosted deployment published before local bindings existed is refused an
//! update until its owner explicitly imports it onto a chosen Panel placement.
//! The import is a custody claim, not a deploy: it may only *read* the hosted
//! side — the deployment and its active release — and must leave the hosted
//! deployment, its release and its sessions exactly as it found them. The
//! conversion of the hosted config into the local operational record is unit
//! tested in `agent_release`; what this file holds is the HTTP seam: which
//! requests the route makes, that every one is a GET, and what it writes
//! locally on success and on each refusal.
//!
//! The edge is a loopback stub. It answers only the two GETs an import needs
//! and records — and refuses — anything else, so a mutation the route ever
//! attempted would appear in the log rather than succeed silently.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::Request;
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use gaugedesk_app::library::{PanelPublicProfile, PublicDeploymentBindingRecord, LIBRARY_SCOPE};
use gaugedesk_app::{open_control_plane, open_workbench, LockUnpoisoned, SharedWorkbench};

const PLACEMENT: &str = "inst-legacy-panel";
const DEPLOYMENT: &str = "legacy-intake";
const RELEASE: &str = "release-legacy-1";
const CREDENTIAL_CLASS: &str = "openai-api-key";

/// One request the hosted origin received: method, path, body length.
type Call = (String, String, usize);

struct HostedOrigin {
    panels: Vec<&'static str>,
    release_class: &'static str,
    calls: Vec<Call>,
}

fn hosted_config(panels: &[&str]) -> Value {
    json!({
        "deployment_id": DEPLOYMENT,
        "enabled": true,
        "allowed_origins": ["https://legacy.example"],
        "panel_ceiling": panels,
        "max_spend_cents": 4_200,
        "max_session_spend_cents": 420,
        "max_turn_spend_cents": 42,
        "reserve_cents_per_turn": 5,
        "per_visitor_turn_limit": 17,
        "max_concurrent_sessions": 7,
        "funding_ref": "funding:legacy",
        "credential_class": CREDENTIAL_CLASS,
        "credential_ref": "credential:public:legacy-intake:openai:key",
        "audience": { "anonymous_allowed": true },
        "pricing": {},
        "retention": {
            "idle_ttl_seconds": 1_800,
            "absolute_ttl_seconds": 43_200,
            "transcript_retained": true,
            "workspace_retained": false
        },
        "white_label": true
    })
}

fn hosted_origin(
    panels: Vec<&'static str>,
    release_class: &'static str,
) -> (String, Arc<Mutex<HostedOrigin>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(HostedOrigin {
        panels,
        release_class,
        calls: Vec::new(),
    }));
    let shared = Arc::clone(&state);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or_default().to_owned();
            let path = parts.next().unwrap_or_default().to_owned();
            let mut length = 0_usize;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                    break;
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or_default();
                }
            }
            let mut body = vec![0; length];
            let _ = reader.read_exact(&mut body);

            let (status, response) = {
                let mut state = shared.lock().unwrap();
                state.calls.push((method.clone(), path.clone(), length));
                let deployment_path = format!("/v1/deployments/{DEPLOYMENT}");
                let release_path = format!("/v1/releases/{RELEASE}");
                match (method.as_str(), path.as_str()) {
                    ("GET", p) if p == deployment_path => (
                        200,
                        json!({
                            "deployment": {
                                "config": hosted_config(&state.panels),
                                "active_release_id": RELEASE,
                                "lifecycle": "active",
                                "activation_revision": 3,
                                "spent_cents": 120,
                                "reserved_cents": 0,
                                "sessions": 2,
                                "settled_turns": 9
                            },
                            "audience": []
                        }),
                    ),
                    ("GET", p) if p == release_path => (
                        200,
                        json!({
                            "release_id": RELEASE,
                            "host_policy": { "credential_class": state.release_class }
                        }),
                    ),
                    // Anything else — above all any mutation — is refused, and
                    // has already been recorded for the assertions to find.
                    _ => (
                        405,
                        json!({ "error": "the hosted origin is read-only here" }),
                    ),
                }
            };
            let response = serde_json::to_vec(&response).unwrap();
            let _ = write!(
                stream,
                "HTTP/1.1 {status} Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                response.len()
            );
            let _ = stream.write_all(&response);
        }
    });
    (origin, state)
}

fn profile(components: &[&str]) -> PanelPublicProfile {
    let mut profile = PanelPublicProfile::default();
    profile.panels.components = components.iter().map(|name| (*name).to_owned()).collect();
    profile
}

/// A workbench whose one Panel placement froze `local_panels`, the router over
/// it, and a hosted origin serving a legacy deployment that names
/// `hosted_panels` under a release published as `release_class`.
fn setup(
    local_panels: &[&str],
    hosted_panels: Vec<&'static str>,
    release_class: &'static str,
) -> (
    tempfile::TempDir,
    SharedWorkbench,
    Router,
    String,
    Arc<Mutex<HostedOrigin>>,
) {
    let dir = tempfile::tempdir().unwrap();
    let workbench = open_workbench(dir.path()).unwrap();
    workbench
        .lock_unpoisoned()
        .seed_panel_placement(PLACEMENT, profile(local_panels))
        .expect("a fresh workbench can be seeded");
    let (edge, origin) = hosted_origin(hosted_panels, release_class);
    let app = open_control_plane(Arc::clone(&workbench));
    (dir, workbench, app, edge, origin)
}

async fn import(app: &Router, edge: &str) -> (u16, Value) {
    static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
    let body = json!({
        "placement_id": PLACEMENT,
        "deployment_id": DEPLOYMENT,
        "edge_origin": edge,
    });
    let request = Request::builder()
        .method("POST")
        .uri("/public-deployments/import")
        .header(
            "idempotency-key",
            format!("legacy-import-{}", NEXT_KEY.fetch_add(1, Ordering::Relaxed)),
        )
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn bindings(workbench: &SharedWorkbench) -> Vec<PublicDeploymentBindingRecord> {
    workbench
        .lock_unpoisoned()
        .store_ref()
        .records(LIBRARY_SCOPE, "public_deployment_binding")
        .unwrap()
        .into_iter()
        .map(|row| serde_json::from_str(&row).unwrap())
        .collect()
}

fn calls(origin: &Arc<Mutex<HostedOrigin>>) -> Vec<Call> {
    origin.lock().unwrap().calls.clone()
}

/// Every request the import made was a bodiless GET.
fn assert_read_only(calls: &[Call]) {
    for (method, path, length) in calls {
        assert_eq!(
            method, "GET",
            "a legacy import never mutates the hosted side; it sent {method} {path}",
        );
        assert_eq!(*length, 0, "a GET with a body: {method} {path}");
    }
}

#[tokio::test]
async fn an_import_reads_the_hosted_deployment_and_binds_it_without_mutating_it() {
    let (_dir, workbench, app, edge, origin) =
        setup(&["gw-chat"], vec!["gw-chat"], CREDENTIAL_CLASS);

    let (status, outcome) = import(&app, &edge).await;
    assert_eq!(status, 201, "the import is created: {outcome}");
    assert_eq!(outcome["deployment_id"], json!(DEPLOYMENT));
    assert_eq!(outcome["active_release_id"], json!(RELEASE));

    // Exactly the deployment and its active release, both read, nothing else.
    let calls = calls(&origin);
    assert_read_only(&calls);
    let paths: Vec<&str> = calls.iter().map(|(_, path, _)| path.as_str()).collect();
    assert_eq!(
        paths,
        [
            format!("/v1/deployments/{DEPLOYMENT}"),
            format!("/v1/releases/{RELEASE}"),
        ],
    );

    // The binding records the hosted deployment as it is — its own release and
    // its own operational record — not anything the local form would default.
    let bindings = bindings(&workbench);
    assert_eq!(bindings.len(), 1);
    let binding = &bindings[0];
    assert_eq!(binding.id, outcome["binding_id"].as_str().unwrap());
    assert_eq!(binding.project_id, outcome["project_id"].as_str().unwrap());
    assert_eq!(binding.placement_id, PLACEMENT);
    assert_eq!(binding.hosted_deployment_id, DEPLOYMENT);
    assert_eq!(binding.edge_origin, edge);
    assert_eq!(binding.active_release_id.as_deref(), Some(RELEASE));
    let operational = serde_json::to_value(&binding.operational).unwrap();
    assert_eq!(
        operational["allowed_origins"],
        json!(["https://legacy.example"])
    );
    assert_eq!(operational["funding_ref"], json!("funding:legacy"));
    assert_eq!(
        operational["credential_ref"],
        json!("credential:public:legacy-intake:openai:key"),
    );
    assert_eq!(operational["credential_class"], json!(CREDENTIAL_CLASS));
    assert_eq!(operational["per_visitor_turn_limit"], json!(17));
    assert_eq!(operational["max_concurrent_sessions"], json!(7));
    assert_eq!(operational["max_turn_spend_cents"], json!(42));
    assert_eq!(operational["white_label"], json!(true));
    assert_eq!(operational["retention_idle_ttl_seconds"], json!(1_800));
    assert_eq!(operational["retention_absolute_ttl_seconds"], json!(43_200));
}

#[tokio::test]
async fn a_second_import_of_a_bound_deployment_is_refused_before_it_reads_anything() {
    let (_dir, workbench, app, edge, origin) =
        setup(&["gw-chat"], vec!["gw-chat"], CREDENTIAL_CLASS);
    let (status, _) = import(&app, &edge).await;
    assert_eq!(status, 201);
    let before = calls(&origin).len();

    let (status, refusal) = import(&app, &edge).await;
    assert!(
        (400..500).contains(&status),
        "a re-import is refused, not repeated: {status} {refusal}",
    );
    assert!(
        refusal["error"]
            .as_str()
            .is_some_and(|error| error.contains("already has a local binding")),
        "the refusal says why: {refusal}",
    );
    assert_eq!(
        calls(&origin).len(),
        before,
        "the refusal is decided locally, before the hosted side is asked",
    );
    assert_eq!(bindings(&workbench).len(), 1, "no second binding");
}

#[tokio::test]
async fn a_hosted_panel_contract_the_placement_did_not_freeze_is_refused_and_binds_nothing() {
    let (_dir, workbench, app, edge, origin) =
        setup(&["gw-chat"], vec!["gw-chat", "gw-files"], CREDENTIAL_CLASS);

    let (status, refusal) = import(&app, &edge).await;
    assert!((400..500).contains(&status), "{status} {refusal}");
    assert!(
        refusal["error"]
            .as_str()
            .is_some_and(|error| error.contains("panels do not match")),
        "the refusal names the panel contract: {refusal}",
    );
    assert_read_only(&calls(&origin));
    assert!(bindings(&workbench).is_empty(), "nothing was bound");
}

#[tokio::test]
async fn a_hosted_config_outside_its_releases_credential_class_is_refused_and_binds_nothing() {
    let (_dir, workbench, app, edge, origin) =
        setup(&["gw-chat"], vec!["gw-chat"], "anthropic-api-key");

    let (status, refusal) = import(&app, &edge).await;
    assert!((400..500).contains(&status), "{status} {refusal}");
    assert!(
        refusal["error"]
            .as_str()
            .is_some_and(|error| error.contains("credential class")),
        "the refusal names the credential posture: {refusal}",
    );
    assert_read_only(&calls(&origin));
    assert!(bindings(&workbench).is_empty(), "nothing was bound");
}

#[tokio::test]
async fn a_placement_that_is_not_a_panel_cannot_import_and_the_origin_is_never_asked() {
    let (_dir, workbench, app, edge, origin) =
        setup(&["gw-chat"], vec!["gw-chat"], CREDENTIAL_CLASS);
    let body = json!({
        "placement_id": "inst-no-such-placement",
        "deployment_id": DEPLOYMENT,
        "edge_origin": edge,
    });
    let request = Request::builder()
        .method("POST")
        .uri("/public-deployments/import")
        .header("idempotency-key", "legacy-import-not-a-panel")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert!(response.status().is_client_error(), "{}", response.status());
    assert!(
        calls(&origin).is_empty(),
        "nothing was read for a non-Panel"
    );
    assert!(bindings(&workbench).is_empty());
}
