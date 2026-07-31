//! The drain chain into quarantine, end to end (ADR 0110; GATE-1/GATE-2).
//!
//! Every link in this path was already built and tested in isolation — drain,
//! open, custody, tray, mint, acknowledge. Isolation is exactly what let the
//! ECIES construction diverge for a whole slice without anything failing, so
//! what this test covers is the *joins*:
//!
//! - an artifact the session host's Durable Object actually emitted (the
//!   committed cross-language vector) is opened by the real
//!   `collect_into_project`, not by a hand-assembled call;
//! - it lands in quarantine, project-scoped, raising an attention count and
//!   belonging to no chat;
//! - the hosted copy is acknowledged only after the payload is durably here;
//! - and the payload sits outside every agent file store, which is the whole
//!   protection (ADR 0110 §1) and so is asserted against the live worktrees
//!   rather than assumed from the directory layout.
//!
//! The edge is a loopback stub. What it proves is the client half of the
//! contract — the request GaugeDesk sends and what it does with the reply; the
//! hosted half is covered by the edge-runtime's own tests.

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

use gaugewright_app::agent_release::CollectIntoProjectRequest;
use gaugewright_app::quarantine::{self, ItemStatus};
use gaugewright_app::{open_control_plane, open_workbench, LockUnpoisoned, SharedWorkbench};

const PROJECT: &str = "proj-default";
const PLACEMENT: &str = "inst-placement-default";
const DEPLOYMENT: &str = "dep-collect-1";
const RECIPIENT: &str = "theory-a";
/// The vector's `admission_scope`; a wrap is bound to it.
const ADMISSION_SCOPE: &str = "theory-a-test";
const SCHEMA_REF: &str = "survey.v1";
/// The session that emitted the committed vector, and the artifact id its
/// revision makes. Both are read off the vector rather than invented, so the
/// drain opens a real emission end to end.
const SESSION: &str = "session-collection";
const ARTIFACT: &str = "session-collection:1";

#[derive(serde::Deserialize)]
struct Vector {
    recipient_private_seed_hex: String,
    expected_plaintext: String,
    sealed: Value,
}

fn vector() -> Vector {
    serde_json::from_str(include_str!("collection-emitted-vector.json"))
        .expect("seal vector parses")
}

/// Put the vector's private half where this Home keeps recipient keys, so the
/// drain opens what the TypeScript sealer produced rather than something this
/// test sealed for itself.
fn install_recipient(root: &std::path::Path, seed_hex: &str) {
    let dir = root.join("keys").join("collection");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(format!("{}.recipient", hex::encode(RECIPIENT))),
        hex::decode(seed_hex).unwrap(),
    )
    .unwrap();
}

/// What the stub edge was asked to do, in order.
#[derive(Default)]
struct EdgeLog {
    calls: Vec<(String, String, String)>,
}

/// A loopback stand-in for the deployment object's drain surface. Serves the
/// sealed artifact once, then records what we acknowledge.
fn stub_edge(sealed: Value) -> (String, Arc<Mutex<EdgeLog>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let log = Arc::new(Mutex::new(EdgeLog::default()));
    let sink = Arc::clone(&log);
    std::thread::spawn(move || {
        let mut served = false;
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or_default().to_owned();
            let target = parts.next().unwrap_or_default().to_owned();
            let mut length = 0_usize;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header.trim().is_empty() {
                    break;
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0_u8; length];
            reader.read_exact(&mut body).unwrap();
            let body = String::from_utf8_lossy(&body).into_owned();
            sink.lock()
                .unwrap()
                .calls
                .push((method.clone(), target.clone(), body));

            let payload = if method == "POST" {
                json!({ "acknowledged": 1 }).to_string()
            } else if served {
                json!({ "deployment_id": DEPLOYMENT, "waiting": 0, "artifacts": [] }).to_string()
            } else {
                served = true;
                json!({
                    "deployment_id": DEPLOYMENT,
                    "waiting": 1,
                    "artifacts": [{
                        "session_id": SESSION,
                        "release_id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "schema_ref": SCHEMA_REF,
                        "recipient_ref": "recipient:collection:theory-a",
                        "revision": 1,
                        // What the emitting session declared, not a number this
                        // test chose: the opener refuses a length that does not
                        // describe the plaintext.
                        "byte_len": sealed["byte_len"].clone(),
                        "deposited_at_unix_ms": 1_700_000_000_000_u64,
                        "sealed": sealed,
                    }],
                })
                .to_string()
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                payload.len(),
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        }
    });
    (origin, log)
}

async fn send(app: &Router, method: &str, uri: &str, body: Option<&str>) -> (u16, Value) {
    static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
    let mut builder = Request::builder().method(method).uri(uri);
    if method != "GET" {
        builder = builder.header(
            "idempotency-key",
            format!("collect-{}", NEXT_KEY.fetch_add(1, Ordering::Relaxed)),
        );
    }
    let request = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn a_chat(app: &Router) -> String {
    let (_, workspace) = send(app, "GET", "/workspace", None).await;
    let target = workspace["projects"]
        .as_array()
        .expect("workspace lists projects")
        .iter()
        .find(|project| project["id"] == PROJECT)
        .expect("the default project is present")["placements"]
        .as_array()
        .expect("the project lists placements")
        .iter()
        .find(|placement| placement["placement_id"] == PLACEMENT)
        .expect("the default placement is present")["target_ids"][0]
        .as_str()
        .expect("the placement carries a target")
        .to_owned();
    let (status, body) = send(
        app,
        "POST",
        &format!("/projects/{PROJECT}/placements/{PLACEMENT}/chats"),
        Some(&json!({ "title": "survey results", "target_id": target }).to_string()),
    )
    .await;
    assert!((200..300).contains(&status), "chat not created: {body}");
    body["id"]
        .as_str()
        .or_else(|| body["chat"]["id"].as_str())
        .expect("created chat carries an id")
        .to_owned()
}

fn drain(workbench: &SharedWorkbench, edge: &str, project: &str) -> Value {
    let outcome = gaugewright_app::agent_release::collect_into_project(
        workbench,
        CollectIntoProjectRequest {
            deployment_id: DEPLOYMENT.to_owned(),
            edge_origin: edge.to_owned(),
            project_id: project.to_owned(),
            recipient_id: RECIPIENT.to_owned(),
            admission_scope: ADMISSION_SCOPE.to_owned(),
            schema_ref: SCHEMA_REF.to_owned(),
            after_unix_ms: None,
        },
    )
    .expect("the drain chain runs");
    serde_json::to_value(outcome).unwrap()
}

/// Run the project's gate so it files its review question and parks.
///
/// A reviewer answers a question the gate asked; before `GATE-3h` the route
/// decided on its own, so a test could review an item the gate had never seen.
/// It cannot now, and that is the point — this is the step that makes the answer
/// correlate to something.
fn park_for_review(workbench: &SharedWorkbench, chat: &str) {
    struct NoModel;
    impl gaugewright_whip_runtime::gate_runner::GateTransport for NoModel {
        fn fetch(
            &self,
            _: &gaugewright_whip_runtime::sansio_types::HttpRequest,
        ) -> Result<
            gaugewright_whip_runtime::sansio_types::HttpResponse,
            gaugewright_whip_runtime::sansio_types::TransportError,
        > {
            panic!("review-by-hand must not call a model");
        }
    }
    let parked = workbench
        .lock_unpoisoned()
        .run_project_gate(
            PROJECT,
            ARTIFACT,
            chat,
            &gaugewright_app::gate_service::unusable_coercion_config(),
            &NoModel,
        )
        .expect("the gate runs");
    assert!(parked.is_none(), "review-by-hand parks on a person");
}

fn setup() -> (
    tempfile::TempDir,
    SharedWorkbench,
    Router,
    String,
    Arc<Mutex<EdgeLog>>,
) {
    let vector = vector();
    let dir = tempfile::tempdir().unwrap();
    let workbench = open_workbench(dir.path()).unwrap();
    let root = workbench.lock_unpoisoned().root_path();
    install_recipient(&root, &vector.recipient_private_seed_hex);
    let (edge, log) = stub_edge(vector.sealed);
    let app = open_control_plane(Arc::clone(&workbench));
    (dir, workbench, app, edge, log)
}

#[tokio::test]
async fn a_drained_artifact_lands_in_quarantine_and_asks_for_attention() {
    let (_dir, workbench, _app, edge, log) = setup();
    let outcome = drain(&workbench, &edge, PROJECT);

    assert_eq!(outcome["landed"], json!([ARTIFACT]));
    assert_eq!(outcome["refused"], json!([]));
    assert_eq!(outcome["pending_attention"], json!(1));
    assert_eq!(outcome["acknowledged"], json!(1));

    let guard = workbench.lock_unpoisoned();
    let items = quarantine::list(guard.store_ref(), PROJECT).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].status,
        ItemStatus::Pending,
        "a drained collection waits for the gate; it belongs to no chat",
    );
    assert_eq!(items[0].schema_ref, SCHEMA_REF);
    assert_eq!(items[0].source_id, SESSION);

    // The bytes are the TypeScript sealer's, opened here.
    let plaintext = guard
        .quarantine_payloads()
        .read(PROJECT, ARTIFACT)
        .expect("plaintext is durably held");
    assert_eq!(
        String::from_utf8(plaintext).unwrap(),
        vector().expected_plaintext,
    );

    // Acknowledgement is the last step, never the first.
    let calls = &log.lock().unwrap().calls;
    assert_eq!(calls.len(), 2, "one drain, one acknowledgement");
    assert_eq!(calls[0].0, "GET");
    assert_eq!(calls[1].0, "POST");
    assert!(
        calls[1].2.contains(SESSION),
        "we acknowledge exactly what we kept: {}",
        calls[1].2,
    );
}

#[tokio::test]
async fn a_repeated_drain_neither_duplicates_nor_re_acknowledges() {
    let (_dir, workbench, _app, edge, _log) = setup();
    drain(&workbench, &edge, PROJECT);
    let second = drain(&workbench, &edge, PROJECT);
    assert_eq!(second["landed"], json!([]));
    assert_eq!(second["acknowledged"], json!(0));
    assert_eq!(
        quarantine::list(workbench.lock_unpoisoned().store_ref(), PROJECT)
            .unwrap()
            .len(),
        1,
    );
}

#[tokio::test]
async fn nothing_is_acknowledged_when_the_artifact_cannot_be_opened() {
    let vector = vector();
    let dir = tempfile::tempdir().unwrap();
    let workbench = open_workbench(dir.path()).unwrap();
    let root = workbench.lock_unpoisoned().root_path();
    install_recipient(&root, &vector.recipient_private_seed_hex);
    let (edge, log) = stub_edge(vector.sealed);

    // The wrong admission scope: the wrap is bound to it, so this is the shape a
    // misrouted or replayed artifact takes.
    let outcome = gaugewright_app::agent_release::collect_into_project(
        &workbench,
        CollectIntoProjectRequest {
            deployment_id: DEPLOYMENT.to_owned(),
            edge_origin: edge,
            project_id: PROJECT.to_owned(),
            recipient_id: RECIPIENT.to_owned(),
            admission_scope: "some-other-deployment".to_owned(),
            schema_ref: SCHEMA_REF.to_owned(),
            after_unix_ms: None,
        },
    )
    .expect("a refusal is reported, not raised");
    let outcome = serde_json::to_value(outcome).unwrap();

    assert_eq!(outcome["landed"], json!([]));
    assert_eq!(outcome["acknowledged"], json!(0));
    assert_eq!(outcome["refused"].as_array().unwrap().len(), 1);
    assert_eq!(outcome["refused"][0]["session_id"], json!(SESSION));
    assert!(
        quarantine::list(workbench.lock_unpoisoned().store_ref(), PROJECT)
            .unwrap()
            .is_empty(),
    );
    let calls = &log.lock().unwrap().calls;
    assert_eq!(
        calls.len(),
        1,
        "the hosted copy outlives a drain that could not keep it",
    );
}

// ---- the boundary (GATE-2) ------------------------------------------------

#[tokio::test]
async fn quarantine_is_unreachable_from_every_live_chat_worktree() {
    let (_dir, workbench, app, edge, _log) = setup();
    drain(&workbench, &edge, PROJECT);

    // Real chats, so the check runs against worktrees that actually exist
    // rather than against the directory layout we assume they follow.
    let first = a_chat(&app).await;
    let second = a_chat(&app).await;
    assert_ne!(first, second);

    let guard = workbench.lock_unpoisoned();
    assert!(
        guard.quarantine_isolation_violations().is_empty(),
        "an agent file store reaches quarantine: {:?}",
        guard.quarantine_isolation_violations(),
    );
}

#[tokio::test]
async fn the_drained_payload_sits_outside_every_worktree_on_disk() {
    let (_dir, workbench, app, edge, _log) = setup();
    drain(&workbench, &edge, PROJECT);
    a_chat(&app).await;

    let guard = workbench.lock_unpoisoned();
    let quarantine = guard.quarantine_payloads();
    assert!(
        quarantine.exists(PROJECT, ARTIFACT),
        "the payload is held here",
    );

    // The invariant is about paths, so assert on paths: no live worktree is an
    // ancestor of the quarantine root. A `read` that succeeds proves custody;
    // only this proves no agent can perform it.
    let root = quarantine.root().canonicalize().expect("quarantine exists");
    for engagement in guard.engagement_worktrees() {
        let worktree = engagement.canonicalize().unwrap_or(engagement.clone());
        assert!(
            !root.starts_with(&worktree),
            "quarantine {root:?} is inside agent worktree {worktree:?}",
        );
    }
}

// ---- the human gate, end to end (GATE-3) ----------------------------------

#[tokio::test]
async fn a_first_verdict_settles_an_item_nothing_has_screened() {
    // Every other review test calls `park_for_review` first, which arranges the
    // parked state by calling `run_project_gate` directly — a state the product
    // itself had no way to reach, because nothing routed to that method. So the
    // suite proved the second half of a sequence whose first half was
    // unreachable, and the real surface hit the gap: `deliver_verdict` finds no
    // parked request, returns `None`, and the item stays pending with nothing
    // said. This is the reviewer's *first* action on a freshly drained item,
    // which is what actually happens.
    let (_dir, workbench, app, edge, _log) = setup();
    drain(&workbench, &edge, PROJECT);
    let chat = a_chat(&app).await;

    let (status, body) = send(
        &app,
        "POST",
        &format!("/projects/{PROJECT}/quarantine/{ARTIFACT}/review"),
        Some(&json!({ "chat_id": chat, "verdict": "keep" }).to_string()),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let landed = body["workspace_path"]
        .as_str()
        .expect("a first verdict must settle the item, not silently park it");

    let guard = workbench.lock_unpoisoned();
    guard
        .engagement_worktrees()
        .into_iter()
        .find(|path| path.join(landed).exists())
        .unwrap_or_else(|| panic!("the approved item is workspace content at {landed}"));
    assert_eq!(
        quarantine::pending_count(guard.store_ref(), PROJECT).unwrap(),
        0,
        "nothing is left awaiting the gate",
    );
}

#[tokio::test]
async fn a_reviewer_can_approve_an_item_into_the_workspace() {
    let (_dir, workbench, app, edge, _log) = setup();
    drain(&workbench, &edge, PROJECT);
    let chat = a_chat(&app).await;

    // The reviewer reads the raw item first. A person reading untrusted text is
    // not an agent under injection; this is the control plane, not a file store.
    let (status, _) = send(
        &app,
        "GET",
        &format!("/projects/{PROJECT}/quarantine/{ARTIFACT}"),
        None,
    )
    .await;
    assert_eq!(status, 200);

    park_for_review(&workbench, &chat);
    let (status, body) = send(
        &app,
        "POST",
        &format!("/projects/{PROJECT}/quarantine/{ARTIFACT}/review"),
        Some(&json!({ "chat_id": chat, "verdict": "keep" }).to_string()),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let landed = body["workspace_path"]
        .as_str()
        .expect("it landed somewhere");

    let guard = workbench.lock_unpoisoned();
    let worktree = guard
        .engagement_worktrees()
        .into_iter()
        .find(|path| path.join(landed).exists())
        .expect("the approved item is in the chat's worktree");
    assert_eq!(
        std::fs::read_to_string(worktree.join(landed)).unwrap(),
        vector().expected_plaintext,
    );

    // Approved output is ordinary workspace content (ADR 0110 §4): no stamp, no
    // reduced ceiling, no special resource class. The chat that reviewed it is
    // an ordinary chat.
    assert!(
        gaugewright_app::resource_store::list(guard.store_ref(), &chat)
            .unwrap()
            .is_empty(),
        "an approved item is a workspace file, not a marked resource",
    );
    assert_eq!(
        quarantine::pending_count(guard.store_ref(), PROJECT).unwrap(),
        0,
    );
}

#[tokio::test]
async fn a_flagged_item_never_becomes_workspace_content() {
    let (_dir, workbench, app, edge, _log) = setup();
    drain(&workbench, &edge, PROJECT);
    let chat = a_chat(&app).await;

    park_for_review(&workbench, &chat);
    let (status, body) = send(
        &app,
        "POST",
        &format!("/projects/{PROJECT}/quarantine/{ARTIFACT}/review"),
        Some(&json!({ "chat_id": chat, "verdict": "flag" }).to_string()),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["workspace_path"].is_null(), "a flag writes nothing");

    let guard = workbench.lock_unpoisoned();
    for worktree in guard.engagement_worktrees() {
        assert!(
            !worktree
                .join(gaugewright_app::gate::approved_path(ARTIFACT))
                .exists(),
            "a flagged item must be readable by no agent",
        );
    }
    // The payload survives for a person to look at; a refusal escalates rather
    // than destroying the evidence.
    assert!(guard.quarantine_payloads().exists(PROJECT, ARTIFACT));
}

#[tokio::test]
async fn a_chat_outside_the_project_cannot_review_its_quarantine() {
    let (_dir, workbench, app, edge, _log) = setup();
    drain(&workbench, &edge, PROJECT);
    let chat = a_chat(&app).await;
    assert!(workbench
        .lock_unpoisoned()
        .review_quarantined_item(
            "some-other-project",
            ARTIFACT,
            &chat,
            gaugewright_app::gate::Verdict::Keep,
        )
        .is_err());
}

/// A stub edge that parks inside the drain `GET` until released.
///
/// Every other edge in this file answers instantly, which is why none of them
/// can see the defect below: the lock hold is real but too short to observe. A
/// production drain spends its time exactly here.
fn parked_stub_edge(
    sealed: Value,
    arrived: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut release = Some(release);
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let method = request_line
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned();
            let mut length = 0_usize;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header.trim().is_empty() {
                    break;
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0_u8; length];
            reader.read_exact(&mut body).unwrap();

            let payload = if method == "POST" {
                json!({ "acknowledged": 1 }).to_string()
            } else {
                // Park here — the drain is now mid-flight and the probe runs.
                if let Some(gate) = release.take() {
                    let _ = arrived.send(());
                    let _ = gate.recv();
                }
                json!({
                    "deployment_id": DEPLOYMENT,
                    "waiting": 1,
                    "artifacts": [{
                        "session_id": SESSION,
                        "release_id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "revision": 1,
                        "deposited_at_unix_ms": 1_750_000_000_000_u64,
                        "sealed": sealed,
                    }],
                })
                .to_string()
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                payload.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        }
    });
    origin
}

/// A drain in flight must not freeze the rest of the workbench.
///
/// This is the defect ADR 0115 §5 names, in the route that still had it after
/// the turn was fixed: `collect_into_project` ran under the global lock across a
/// network round trip to the edge plus one ECDH-and-AES open per artifact, so a
/// survey with a few hundred responses froze every read and every other chat.
///
/// The probe is `try_lock` against a deadline rather than a plain `lock`,
/// because the failing shape is a *hang* — a plain lock would block this test
/// forever instead of failing it.
#[test]
fn a_drain_in_flight_does_not_hold_the_workbench() {
    use std::time::{Duration, Instant};

    let vector = vector();
    let dir = tempfile::tempdir().unwrap();
    let workbench = open_workbench(dir.path()).unwrap();
    let root = workbench.lock_unpoisoned().root_path();
    install_recipient(&root, &vector.recipient_private_seed_hex);

    let (arrived_tx, arrived_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let edge = parked_stub_edge(vector.sealed, arrived_tx, release_rx);

    let drainer = {
        let workbench = Arc::clone(&workbench);
        std::thread::spawn(move || {
            gaugewright_app::agent_release::collect_into_project(
                &workbench,
                CollectIntoProjectRequest {
                    deployment_id: DEPLOYMENT.to_owned(),
                    edge_origin: edge,
                    project_id: PROJECT.to_owned(),
                    recipient_id: RECIPIENT.to_owned(),
                    admission_scope: ADMISSION_SCOPE.to_owned(),
                    schema_ref: SCHEMA_REF.to_owned(),
                    after_unix_ms: None,
                },
            )
        })
    };

    arrived_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the drain reaches the edge");

    // The probe: an ordinary reader must be able to take the workbench while
    // that round trip is outstanding.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut taken = false;
    while Instant::now() < deadline {
        if let Ok(guard) = workbench.try_lock() {
            let _ = guard.root_path();
            taken = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Release before asserting, or a failure leaves the drain thread parked and
    // this test hangs instead of reporting.
    let _ = release_tx.send(());
    let outcome = drainer.join().unwrap().expect("the drain still completes");

    assert!(
        taken,
        "the workbench stayed locked for the whole drain round trip"
    );
    let outcome = serde_json::to_value(outcome).unwrap();
    assert_eq!(
        outcome["landed"].as_array().unwrap().len(),
        1,
        "the artifact still lands: {outcome}"
    );
}

/// A scripted coercion provider, so the gate's model leg is deterministic.
struct Screener(&'static str);

impl gaugewright_whip_runtime::gate_runner::GateTransport for Screener {
    fn fetch(
        &self,
        _request: &gaugewright_whip_runtime::sansio_types::HttpRequest,
    ) -> Result<
        gaugewright_whip_runtime::sansio_types::HttpResponse,
        gaugewright_whip_runtime::sansio_types::TransportError,
    > {
        let disposition = self.0;
        Ok(gaugewright_whip_runtime::sansio_types::HttpResponse {
            status: 200,
            body: json!({
                "output": [{
                    "content": [{
                        "type": "output_text",
                        "text": json!({ "disposition": disposition }).to_string(),
                    }]
                }]
            }),
        })
    }
}

/// The project's own gate runs, and its verdict is what moves the bytes.
///
/// This is the join `GATE-3` never had: `gate::install` seeded a program, and
/// `run_gate` could execute one, but nothing in the product connected them — so
/// no gate had ever run outside a test harness. Here the program is read off the
/// project's own files target, admitted, and driven over a real drained
/// artifact.
#[tokio::test]
async fn a_projects_own_gate_screens_a_drained_item_into_the_workspace() {
    let (dir, workbench, app, edge, _log) = setup();
    drain(&workbench, &edge, PROJECT);
    let chat = a_chat(&app).await;

    // Switch this project to screening — review-by-hand parks on a person and
    // would settle nothing on one pass.
    let repo = dir
        .path()
        .join("targets")
        .join(gaugewright_app::library_state::managed_project_target_id(
            PROJECT,
        ))
        .join("repo");
    gaugewright_app::gate::install(&repo, gaugewright_app::gate::GateKind::CoerceScreen).unwrap();

    let coerce = gaugewright_whip_runtime::gate_runner::GateCoercionConfig {
        backend: gaugewright_whip_runtime::gate_runner::CoerceBackend::OpenAi,
        provider_id: "test".into(),
        base_url: "https://example.invalid/v1/responses".into(),
        api_key: "test".into(),
        model: "gpt-4.1-mini".into(),
        max_tokens: 64,
    };

    let landed = workbench
        .lock_unpoisoned()
        .run_project_gate(PROJECT, ARTIFACT, &chat, &coerce, &Screener("keep"))
        .expect("the project's gate runs")
        .expect("a kept item lands in the workspace");

    // The bytes are in the chat's worktree, and the record says so.
    let worktree = workbench
        .lock_unpoisoned()
        .engagement_worktrees()
        .into_iter()
        .find(|path| path.join(&landed).is_file())
        .expect("the approved item is on disk at the recorded path");
    assert!(worktree.join(&landed).is_file());

    let held = quarantine::list(workbench.lock_unpoisoned().store_ref(), PROJECT).unwrap();
    let item = held
        .iter()
        .find(|item| item.item_id == ARTIFACT)
        .expect("the item is still indexed");
    assert!(
        matches!(item.status, ItemStatus::Approved { .. }),
        "the gate's verdict settled the record: {:?}",
        item.status,
    );
}

/// A reviewer's answer settles an item *through* the gate, not around it.
///
/// This is the ADR 0110 §2 violation closed. The shipped path used to be an HTTP
/// route calling `apply_verdict` directly — a privileged runtime service reading
/// quarantine and writing the workspace, which §2 forbids in as many words.
/// Now the answer enters as a claim on the queue the gate parked against, the
/// gate's `settle` rule rules, and only then do bytes move.
///
/// The gate here is review-by-hand, the seeded default: its first pass parks on
/// a person and settles nothing, which is the behaviour under test.
#[tokio::test]
async fn a_reviewers_answer_settles_the_item_through_the_gate() {
    let (_dir, workbench, app, edge, _log) = setup();
    drain(&workbench, &edge, PROJECT);
    let chat = a_chat(&app).await;

    let coerce = gaugewright_whip_runtime::gate_runner::GateCoercionConfig {
        backend: gaugewright_whip_runtime::gate_runner::CoerceBackend::OpenAi,
        provider_id: "unused".into(),
        base_url: "https://example.invalid/v1/responses".into(),
        api_key: "unused".into(),
        model: "unused".into(),
        max_tokens: 16,
    };
    // A transport that must never be reached: review-by-hand asks a person and
    // calls no model, so a request here would mean the wrong gate ran.
    struct NoModel;
    impl gaugewright_whip_runtime::gate_runner::GateTransport for NoModel {
        fn fetch(
            &self,
            _: &gaugewright_whip_runtime::sansio_types::HttpRequest,
        ) -> Result<
            gaugewright_whip_runtime::sansio_types::HttpResponse,
            gaugewright_whip_runtime::sansio_types::TransportError,
        > {
            panic!("review-by-hand must not call a model");
        }
    }

    // Pass one: the gate files its question and parks. Nothing settles.
    let parked = workbench
        .lock_unpoisoned()
        .run_project_gate(PROJECT, ARTIFACT, &chat, &coerce, &NoModel)
        .expect("the gate runs");
    assert!(parked.is_none(), "review-by-hand parks on a person");

    // ADR 0117 §5: the review surface counts what awaits a *person*. A parked
    // item is exactly that, and it is one — not the whole quarantine.
    let state_root = workbench.lock_unpoisoned().root_path();
    let gate_state = gaugewright_app::gate_service::gate_state_dir(&state_root, PROJECT);
    assert_eq!(
        gaugewright_whip_runtime::gate_runner::reviews_awaiting_a_person(&gate_state)
            .expect("the gate's parked reviews are readable"),
        1,
        "a parked review is one item awaiting a person",
    );

    // And the top bar says so while it waits (ADR 0110 §7, GATE-6): one
    // `screen` task, project-scoped, naming the chat a reviewer opens to look.
    let (_, waiting_now) = send(&app, "GET", "/tasks", None).await;
    let screen: Vec<&Value> = waiting_now["tasks"]
        .as_array()
        .expect("the task queue is a list")
        .iter()
        .filter(|task| task["kind"] == "screen")
        .collect();
    assert_eq!(
        screen.len(),
        1,
        "one inbound pill per project, not per item"
    );
    assert_eq!(screen[0]["project"], PROJECT);
    assert_eq!(screen[0]["waiting"], 1);
    assert!(
        screen[0]["id"].as_str().is_some_and(|id| !id.is_empty()),
        "the pill opens a chat: {}",
        screen[0]["id"],
    );

    let held = quarantine::list(workbench.lock_unpoisoned().store_ref(), PROJECT).unwrap();
    assert!(
        held.iter()
            .any(|item| item.item_id == ARTIFACT && matches!(item.status, ItemStatus::Pending)),
        "a parked item is still awaiting the gate",
    );

    // Pass two: the person answers, and the gate is what rules.
    let landed = workbench
        .lock_unpoisoned()
        .review_through_gate(
            PROJECT,
            ARTIFACT,
            &chat,
            gaugewright_app::gate::Verdict::Keep,
            &coerce,
            &NoModel,
        )
        .expect("the verdict reaches the gate")
        .expect("the gate settles the item");

    let worktree = workbench
        .lock_unpoisoned()
        .engagement_worktrees()
        .into_iter()
        .find(|path| path.join(&landed).is_file())
        .expect("the approved item is on disk");
    assert!(worktree.join(&landed).is_file());

    // And the count falls back to zero. This is why the count reads the gate's
    // `Pending` facts rather than its open `review` issues: `settle` finishes
    // the *verdicts* issue the reviewer filed into and leaves the *review*
    // issue that asked the question open, so an open-issue count would still
    // report a question that has just been answered.
    assert_eq!(
        gaugewright_whip_runtime::gate_runner::reviews_awaiting_a_person(&gate_state)
            .expect("readable"),
        0,
        "an answered review no longer awaits a person",
    );

    // ...and the pill goes with it. A count that outlived its item would send a
    // person to an empty queue, which is the failure the top bar exists to avoid.
    let (_, after) = send(&app, "GET", "/tasks", None).await;
    assert!(
        !after["tasks"]
            .as_array()
            .expect("the task queue is a list")
            .iter()
            .any(|task| task["kind"] == "screen"),
        "no inbound pill once nothing awaits a person: {}",
        after["tasks"],
    );
}
