//! Two-instance project handoff / authority relocation over the real network
//! (`D-REMOTE` / `SERVE-1` / `FED-6`). Drives two mounted `control_plane` routers —
//! two distinct authorities — through pairing and then a cross-machine **relocation**
//! of a project's home, over the **real rendezvous broker** and **real cert-pinned
//! TLS** legs:
//!
//! 1. alice + bob pair (TOFU-pin each other's governance key + cert, spawn receivers);
//! 2. alice seeds a project log and `POST /federation/handoff/relocate`s it to bob;
//! 3. bob's handoff receiver verifies the offer against the pinned grant (C-1), imports
//!    the log, and commits — bob becomes the project's home;
//! 4. alice commits its side and becomes the operator.
//!
//! The relocation's one-home safety is the verified reducer (`gaugewright_core::handoff`);
//! only the transport — the signed offer + log over TLS through the blind broker — is
//! the integration under test. A relocation to an unpaired peer is refused before any
//! transport.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use gaugewright_app::account::{credentials_in_scope, project_scope};
use gaugewright_app::federation::Federation;
use gaugewright_app::open_control_plane;
use gaugewright_app::Workbench;
use gaugewright_core::ids::AuthorityId;
use gaugewright_store::Store;
use gaugewright_workspace::Instance;

/// Build a mounted control plane for `authority`; return it plus a handle to its
/// workbench so the test can seed/read the store directly.
fn instance(authority: &str, broker: &str) -> (Router, Arc<Mutex<Workbench>>, tempfile::TempDir) {
    let root = tempfile::tempdir().unwrap();
    let fed =
        Federation::open(AuthorityId::new(authority), root.path(), broker.to_string()).unwrap();
    let wb = Workbench::new(Store::open_in_memory().unwrap())
        .with_authority(AuthorityId::new(authority))
        .with_root(root.path())
        .with_federation(fed);
    let shared = Arc::new(Mutex::new(wb));
    (open_control_plane(shared.clone()), shared, root)
}

/// A federated control plane with a real local workspace, for crossings that
/// must drive an existing hub chat rather than the no-instance transport seam.
fn workspace_instance(
    authority: &str,
    broker: &str,
) -> (Router, Arc<Mutex<Workbench>>, tempfile::TempDir) {
    let root = tempfile::tempdir().unwrap();
    let workspace = Instance::init(root.path().join("repo"), root.path().join("wt")).unwrap();
    let fed =
        Federation::open(AuthorityId::new(authority), root.path(), broker.to_string()).unwrap();
    let wb = Workbench::with_target("inst-test", workspace, Store::open_in_memory().unwrap())
        .with_authority(AuthorityId::new(authority))
        .with_root(root.path())
        .with_federation(fed);
    let shared = Arc::new(Mutex::new(wb));
    (open_control_plane(shared.clone()), shared, root)
}

async fn post(app: &Router, uri: &str, body: Value) -> (StatusCode, Value) {
    static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header(
            "idempotency-key",
            format!("handoff-test-{}", NEXT_KEY.fetch_add(1, Ordering::Relaxed)),
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

#[tokio::test]
async fn raw_handoff_reducer_steps_are_not_public_routes() {
    let (app, _workbench, _root) = instance("alice", "wss://127.0.0.1:1");

    for path in [
        "/federation/handoff/offer",
        "/federation/handoff/sync",
        "/federation/handoff/commit",
    ] {
        let (status, body) = post(&app, path, json!({ "project": "project-1" })).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "retired route {path}: {body}"
        );
    }
}

async fn get_text(app: &Router, uri: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn start_broker() -> (String, gaugewright_relay_transport::test_relay::TestRelay) {
    let relay = gaugewright_relay_transport::test_relay::TestRelay::bind()
        .await
        .unwrap();
    (relay.endpoint().to_owned(), relay)
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
async fn a_project_home_relocates_to_a_paired_peer_with_its_log() {
    let (broker, _relay) = start_broker().await;
    let (alice, alice_wb, _ra) = instance("alice", &broker);
    let (bob, bob_wb, _rb) = instance("bob", &broker);

    pair(&alice, &bob).await;
    // Let bob's handoff receiver park on the broker for alice→bob.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Seed alice's project log across two of the project's owned scopes — the whole
    // relocatable history, not just one scope.
    {
        let mut g = alice_wb.lock().unwrap();
        g.store_mut()
            .append_record(
                "library",
                "project",
                r#"{"id":"engagement-1","op":"upsert","name":"Acme","is_default":false,"home_id":"home:alice","network_isolated":false}"#,
            )
            .unwrap();
        g.store_mut()
            .append_record("project_log::engagement-1", "event", r#"{"ev":"created"}"#)
            .unwrap();
        g.store_mut()
            .append_record(
                "project_log::engagement-1",
                "event",
                r#"{"ev":"named","name":"Acme"}"#,
            )
            .unwrap();
        g.rebuild_library();
        g.store_mut()
            .append_record(
                "project::engagement-1::notes",
                "note",
                r#"{"text":"kickoff"}"#,
            )
            .unwrap();
        let sealed = g
            .seal_project_secret("engagement-1", "project-provider-secret")
            .unwrap();
        g.upsert_project_credential("engagement-1", "openai".to_owned(), sealed, String::new())
            .unwrap();
    }

    // Before: alice is the home (origin); bob holds nothing for the project.
    let (_, a0) = get(&alice, "/federation/handoff/status?project=engagement-1").await;
    assert_eq!(a0["phase"], "draft");
    assert_eq!(a0["home_origin"], true);

    // alice relocates to bob. Without a standing pre-auth this lands PENDING — bob
    // must consent (INV-13). alice stays home (offered) until bob does.
    let (status, body) = post(
        &alice,
        "/federation/handoff/relocate",
        json!({ "project": "engagement-1", "peer": "bob" }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["phase"], "offered");
    assert_eq!(
        body["home_origin"], true,
        "alice stays home until bob consents"
    );

    // bob sees the pending incoming handoff.
    let (_, inc) = get(&bob, "/federation/handoff/incoming").await;
    let items = inc["incoming"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["project"], "engagement-1");
    assert_eq!(items[0]["source"], "alice");

    // bob consents → bob imports the log, commits, and becomes home.
    let (sa, ba) = post(
        &bob,
        "/federation/handoff/accept",
        json!({ "project": "engagement-1", "source": "alice" }),
    )
    .await;
    assert_eq!(sa, StatusCode::OK);
    assert_eq!(ba["phase"], "committed");
    assert_eq!(ba["home_target"], true, "bob committed and is home");

    // The whole log relocated: bob holds every owned scope alice shipped.
    {
        let g = bob_wb.lock().unwrap();
        let log = g
            .store_ref()
            .records("project_log::engagement-1", "event")
            .unwrap();
        assert_eq!(log.len(), 2, "bob imported the project_log scope");
        assert!(log[1].contains("Acme"), "the log content crossed verbatim");
        let notes = g
            .store_ref()
            .records("project::engagement-1::notes", "note")
            .unwrap();
        assert_eq!(
            notes.len(),
            1,
            "bob imported the project's notes sub-scope too"
        );
        assert!(notes[0].contains("kickoff"));
        let credential = credentials_in_scope(g.store_ref(), &project_scope("engagement-1"))
            .remove("openai")
            .unwrap();
        assert_eq!(
            g.unseal_project_secret("engagement-1", &credential.sealed_token)
                .as_deref(),
            Some("project-provider-secret"),
            "the target re-wraps the project key and can resolve the carried credential"
        );
    }

    // bob notified alice; alice commits its side (becomes operator) — poll for the
    // async reverse notification.
    assert!(
        poll_committed(&alice, "engagement-1").await,
        "alice committed its side on bob's consent notification (EXACTLY_ONE_HOME)"
    );
    assert_eq!(
        alice_wb
            .lock()
            .unwrap()
            .project_home_id("engagement-1")
            .unwrap()
            .as_str(),
        "home:bob"
    );
    assert_eq!(
        bob_wb
            .lock()
            .unwrap()
            .project_home_id("engagement-1")
            .unwrap()
            .as_str(),
        "home:bob"
    );
    {
        let g = alice_wb.lock().unwrap();
        let credential = credentials_in_scope(g.store_ref(), &project_scope("engagement-1"))
            .remove("openai")
            .unwrap();
        assert!(
            g.unseal_project_secret("engagement-1", &credential.sealed_token)
                .is_none(),
            "the former Home removes its wrapped project key after commit"
        );
    }
    // bob's incoming queue is now empty (the offer resolved).
    let (_, inc2) = get(&bob, "/federation/handoff/incoming").await;
    assert!(inc2["incoming"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn origin_cancel_removes_the_targets_pending_offer() {
    let (broker, _relay) = start_broker().await;
    let (alice, alice_wb, _ra) = instance("alice", &broker);
    let (bob, _bob_wb, _rb) = instance("bob", &broker);
    pair(&alice, &bob).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    {
        let mut guard = alice_wb.lock().unwrap();
        guard
            .store_mut()
            .append_record(
                "library",
                "project",
                r#"{"id":"cancel-me","op":"upsert","name":"Cancel me","is_default":false,"home_id":"home:alice","network_isolated":false}"#,
            )
            .unwrap();
        guard.rebuild_library();
    }

    let (offered, body) = post(
        &alice,
        "/federation/handoff/relocate",
        json!({ "project": "cancel-me", "peer": "bob" }),
    )
    .await;
    assert_eq!(offered, StatusCode::ACCEPTED);
    assert_eq!(body["phase"], "offered");
    let (_, incoming) = get(&bob, "/federation/handoff/incoming").await;
    assert_eq!(incoming["incoming"].as_array().unwrap().len(), 1);

    let (cancelled, body) = post(
        &alice,
        "/federation/handoff/abort",
        json!({ "project": "cancel-me" }),
    )
    .await;
    assert_eq!(cancelled, StatusCode::OK);
    assert_eq!(body["phase"], "aborted");
    assert_eq!(body["home_origin"], true);

    let (_, incoming) = get(&bob, "/federation/handoff/incoming").await;
    assert!(
        incoming["incoming"].as_array().unwrap().is_empty(),
        "origin cancellation resolves the target's held offer"
    );
    let (late_accept, _) = post(
        &bob,
        "/federation/handoff/accept",
        json!({ "project": "cancel-me", "source": "alice" }),
    )
    .await;
    assert_eq!(
        late_accept,
        StatusCode::NOT_FOUND,
        "a target cannot accept after the origin has cancelled"
    );
}

/// Poll an authority's handoff status until committed (the reverse Committed
/// notification is async), up to ~3s.
async fn poll_committed(app: &Router, project: &str) -> bool {
    for _ in 0..30 {
        let (_, s) = get(
            app,
            &format!("/federation/handoff/status?project={project}"),
        )
        .await;
        if s["phase"] == "committed" {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn a_pre_authorized_peer_relocates_and_registers_the_project() {
    let (broker, _relay) = start_broker().await;
    let (alice, alice_wb, _ra) = instance("alice", &broker);
    let (bob, bob_wb, _rb) = instance("bob", &broker);
    pair(&alice, &bob).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // alice has a project in her library (the library ProjectRecord).
    {
        let mut g = alice_wb.lock().unwrap();
        g.store_mut()
            .append_record(
                "library",
                "project",
                r#"{"id":"engagement-2","op":"upsert","name":"Acme Co","is_default":false,"home_id":"home:alice","network_isolated":false}"#,
            )
            .unwrap();
        g.rebuild_library();
    }

    // bob pre-authorizes alice: handoffs from alice auto-accept (friction reduction).
    let (sp, _) = post(
        &bob,
        "/federation/handoff/preauth",
        json!({ "peer": "alice" }),
    )
    .await;
    assert_eq!(sp, StatusCode::OK);

    // alice relocates → bob auto-accepts and commits immediately; alice commits too.
    let (status, body) = post(
        &alice,
        "/federation/handoff/relocate",
        json!({ "project": "engagement-2", "peer": "bob" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["phase"], "committed");
    assert_eq!(body["home_target"], true, "alice is the operator");
    assert_eq!(
        alice_wb
            .lock()
            .unwrap()
            .project_home_id("engagement-2")
            .unwrap()
            .as_str(),
        "home:bob"
    );

    let (_, b) = get(&bob, "/federation/handoff/status?project=engagement-2").await;
    assert_eq!(b["phase"], "committed");
    assert_eq!(b["home_target"], true, "bob auto-accepted and is home");
    assert_eq!(
        bob_wb
            .lock()
            .unwrap()
            .project_home_id("engagement-2")
            .unwrap()
            .as_str(),
        "home:bob"
    );

    // The library ProjectRecord registered: the relocated project appears in bob's
    // library (its workspace projection), with its name.
    let (_, ws) = get(&bob, "/workspace").await;
    assert!(
        ws.to_string().contains("Acme Co"),
        "the relocated project registered in bob's library"
    );

    // Auto-accepted, so nothing queued for consent.
    let (_, inc) = get(&bob, "/federation/handoff/incoming").await;
    assert!(inc["incoming"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn placement_policy_blocks_a_pre_authorized_handoff_before_auto_commit() {
    let (broker, _relay) = start_broker().await;
    let (alice, alice_wb, _ra) = instance("alice", &broker);
    let (bob, bob_wb, _rb) = instance("bob", &broker);
    pair(&alice, &bob).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    {
        let mut alice = alice_wb.lock().unwrap();
        alice
            .store_mut()
            .append_record(
                "library",
                "project",
                r#"{"id":"policy-blocked","op":"upsert","name":"Policy blocked","is_default":false,"home_id":"home:alice","network_isolated":false,"deployment_mode":{"operator":"local","attested":false}}"#,
            )
            .unwrap();
        alice.rebuild_library();
    }
    {
        let mut bob = bob_wb.lock().unwrap();
        bob.store_mut()
            .append_record(
                "org",
                "placement_policy",
                r#"{"id":"","op":"upsert","policy":{"require_attested":true,"allowed_operators":[]}}"#,
            )
            .unwrap();
    }

    let (preauth, _) = post(
        &bob,
        "/federation/handoff/preauth",
        json!({ "peer": "alice" }),
    )
    .await;
    assert_eq!(preauth, StatusCode::OK);

    let (status, body) = post(
        &alice,
        "/federation/handoff/relocate",
        json!({ "project": "policy-blocked", "peer": "bob" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "policy refusal: {body}");
    assert_eq!(
        alice_wb
            .lock()
            .unwrap()
            .project_home_id("policy-blocked")
            .unwrap()
            .as_str(),
        "home:alice",
        "the origin remains home after the target refuses"
    );
    assert!(
        bob_wb
            .lock()
            .unwrap()
            .project_home_id("policy-blocked")
            .is_none(),
        "preauthorization must not import a project that violates policy"
    );
}

#[tokio::test]
async fn relocation_carries_the_project_content_bytes_to_the_peer() {
    // The bytes behind the project's handles travel with the home (STATE_BEFORE_HOME):
    // alice's using-instance holds content; after relocation bob holds it on disk.
    let (broker, _relay) = start_broker().await;
    let (alice, alice_wb, _ra) = instance("alice", &broker);
    let (bob, bob_wb, rb) = instance("bob", &broker);
    pair(&alice, &bob).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // alice: a project with one placement and one managed target carrying real content
    // (a settled dossier on `main` plus in-flight work on an engagement branch).
    {
        let mut g = alice_wb.lock().unwrap();
        g.store_mut()
            .append_record(
                "library",
                "project",
                r#"{"id":"engagement-3","op":"upsert","name":"Acme Co","is_default":false,"home_id":"home:alice","network_isolated":false}"#,
            )
            .unwrap();
        g.store_mut()
            .append_record(
                "library",
                "instance",
                r#"{"id":"inst-acme","op":"upsert","kind":"using","agent_id":"analyst","project_id":"engagement-3"}"#,
            )
            .unwrap();
        g.store_mut()
            .append_record(
                "library",
                "work_target",
                r#"{"id":"target-acme","op":"upsert","name":"Acme files","owner":{"kind":"project","project_id":"engagement-3"},"kind":"managed","authority":"alice","parties":["alice"],"locator_handle":"managed:target-acme","adapter":"whipplescript","adapter_family":"whipplescript-v1","vcs_posture":"managed","current_basis":"cut-acme","path_scope":["."],"capabilities":{"read":true,"propose":true,"apply":true,"publish":false,"release":false},"status":"available"}"#,
            )
            .unwrap();
        g.store_mut()
            .append_record(
                "library",
                "placement_targets",
                r#"{"placement_id":"inst-acme","op":"upsert","target_ids":["target-acme"]}"#,
            )
            .unwrap();
        g.rebuild_library();

        // Lay the target store down on alice's disk and register it in the workbench.
        let dir = _ra.path().join("targets").join("target-acme");
        let target = gaugewright_workspace::Instance::init_at(&dir).unwrap();
        target
            .seed_main(&[("dossier.md", "acme financials")])
            .unwrap();
        let eng = target.create_engagement("chat-1").unwrap();
        std::fs::write(eng.path().join("draft.md"), "engagement notes").unwrap();
        eng.commit_turn("turn 1").unwrap();
        g.register_target("target-acme", Box::new(target));
    }

    // bob pre-authorizes alice, so the relocation auto-commits end-to-end.
    let (sp, _) = post(
        &bob,
        "/federation/handoff/preauth",
        json!({ "peer": "alice" }),
    )
    .await;
    assert_eq!(sp, StatusCode::OK);

    let (status, body) = post(
        &alice,
        "/federation/handoff/relocate",
        json!({ "project": "engagement-3", "peer": "bob" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["phase"], "committed");

    // bob is home and the project registered in its library.
    let (_, b) = get(&bob, "/federation/handoff/status?project=engagement-3").await;
    assert_eq!(b["phase"], "committed");
    let (_, ws) = get(&bob, "/workspace").await;
    assert!(
        ws.to_string().contains("Acme Co"),
        "project registered on bob"
    );

    // The content bytes materialized on bob: the target store's `main` content and
    // the engagement branch's in-flight work both resolve on bob's disk.
    // NOTE: these on-disk assertions (`targets/<id>/repo`, `worktrees/<chat>`) are
    // Provider-specific coverage of the WorkspaceProvider seam — the native
    // provider gets its own twin of this test rather than a change to this one.
    let repo = rb.path().join("targets").join("target-acme").join("repo");
    assert_eq!(
        std::fs::read_to_string(repo.join("dossier.md"))
            .ok()
            .as_deref(),
        Some("acme financials"),
        "main content (the bytes behind the relocated handles) landed on bob"
    );
    // The engagement worktree rehydrated with its work.
    let wt = rb
        .path()
        .join("targets")
        .join("target-acme")
        .join("worktrees")
        .join("chat-1");
    assert_eq!(
        std::fs::read_to_string(wt.join("draft.md")).ok().as_deref(),
        Some("engagement notes"),
        "engagement content materialized on bob"
    );
    // And bob's workbench can run against the relocated target (it is registered).
    {
        let g = bob_wb.lock().unwrap();
        assert!(
            g.has_target("target-acme"),
            "bob registered the relocated target"
        );
    }
}

#[tokio::test]
async fn batched_accept_admits_all_pending_handoffs_at_once() {
    let (broker, _relay) = start_broker().await;
    let (alice, alice_wb, _ra) = instance("alice", &broker);
    let (bob, _bob_wb, _rb) = instance("bob", &broker);
    pair(&alice, &bob).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // alice relocates two projects; without pre-auth both land pending on bob.
    {
        let mut guard = alice_wb.lock().unwrap();
        for project in ["proj-a", "proj-b"] {
            guard
                .store_mut()
                .append_record(
                    "library",
                    "project",
                    &json!({
                        "id": project,
                        "op": "upsert",
                        "name": project,
                        "is_default": false,
                        "home_id": "home:alice",
                        "network_isolated": false,
                    })
                    .to_string(),
                )
                .unwrap();
        }
        guard.rebuild_library();
    }
    for p in ["proj-a", "proj-b"] {
        let (st, _) = post(
            &alice,
            "/federation/handoff/relocate",
            json!({ "project": p, "peer": "bob" }),
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);
    }
    let (_, inc) = get(&bob, "/federation/handoff/incoming").await;
    assert_eq!(inc["incoming"].as_array().unwrap().len(), 2, "two pending");

    // bob accepts them all in one batched admission.
    let (sa, ba) = post(&bob, "/federation/handoff/accept-all", json!({})).await;
    assert_eq!(sa, StatusCode::OK);
    assert_eq!(ba["accepted"].as_array().unwrap().len(), 2);

    // both projects are now home on bob, the queue is empty, and alice committed both.
    for p in ["proj-a", "proj-b"] {
        let (_, b) = get(&bob, &format!("/federation/handoff/status?project={p}")).await;
        assert_eq!(b["phase"], "committed", "{p} committed on bob");
        assert!(
            poll_committed(&alice, p).await,
            "alice committed its side for {p}"
        );
    }
    let (_, inc2) = get(&bob, "/federation/handoff/incoming").await;
    assert!(inc2["incoming"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_combined_invite_pairs_and_hands_off_in_one_accept() {
    // FED-7 Slice 2 / ADR 0047: no prior pairing. Alice mints one invite; Bob's single
    // Accept pins Alice, arms a one-shot, and sends an acceptance back; Alice pins Bob
    // (mutual pairing) and relocates, which the one-shot auto-admits — Bob becomes home.
    let (broker, _relay) = start_broker().await;
    let (alice, alice_wb, _ra) = instance("alice", &broker);
    let (bob, bob_wb, _rb) = instance("bob", &broker);
    // Note: NO pair() — the invite bootstraps the pairing.

    // Alice has the project in her library.
    {
        let mut g = alice_wb.lock().unwrap();
        g.store_mut()
            .append_record(
                "library",
                "project",
                r#"{"id":"engagement-9","op":"upsert","name":"Acme Co","is_default":false,"home_id":"home:alice","network_isolated":false}"#,
            )
            .unwrap();
        g.rebuild_library();
    }

    // Alice mints a combined invite for the project.
    let (si, inv) = post(
        &alice,
        "/federation/invite",
        json!({ "project": "engagement-9" }),
    )
    .await;
    assert_eq!(si, StatusCode::OK);
    let invite_url = inv["invite_url"].as_str().expect("invite url").to_string();
    assert!(invite_url.starts_with("gaugewright://invite?d="));

    // Bob accepts the invite (one action): pins Alice, arms the one-shot, sends accept.
    let (sa, ba) = post(
        &bob,
        "/federation/invite/accept",
        json!({ "invite": invite_url }),
    )
    .await;
    assert_eq!(sa, StatusCode::OK, "accept ok: {ba}");
    assert_eq!(ba["ok"], true);
    assert_eq!(ba["origin"], "alice");

    // Bob becomes the project's home (the one-shot auto-admitted the relocation).
    assert!(
        poll_committed(&bob, "engagement-9").await,
        "bob committed and is home via the invite's one-shot admission"
    );
    let (_, bstatus) = get(&bob, "/federation/handoff/status?project=engagement-9").await;
    assert_eq!(bstatus["home_target"], true, "bob is home");

    // The relocated project registered in bob's library.
    let (_, ws) = get(&bob, "/workspace").await;
    assert!(
        ws.to_string().contains("Acme Co"),
        "project registered on bob"
    );

    // The target owns data and the origin owns archetypes. Drive the same
    // participant/data management routes the target's Engagement pane uses,
    // then read the folded projections back.
    let (_, participants) = get(
        &bob,
        "/federation/handoff/participants?project=engagement-9",
    )
    .await;
    let participant_rows = participants["participants"].as_array().unwrap();
    assert!(participant_rows
        .iter()
        .any(|p| { p["authority"] == "bob" && p["owns"] == "data" && p["revoked"] == false }));
    assert!(participant_rows.iter().any(|p| {
        p["authority"] == "alice" && p["owns"] == "archetypes" && p["revoked"] == false
    }));

    let (sc, _) = post(
        &bob,
        "/federation/handoff/connect-data",
        json!({
            "project": "engagement-9",
            "handle": "/tmp/invite-data",
            "label": "invite-data"
        }),
    )
    .await;
    assert_eq!(sc, StatusCode::OK);
    let (_, data) = get(&bob, "/federation/handoff/data?project=engagement-9").await;
    assert!(data["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| { item["handle"] == "/tmp/invite-data" && item["label"] == "invite-data" }));

    let (sr, _) = post(
        &bob,
        "/federation/handoff/revoke",
        json!({
            "project": "engagement-9",
            "authority": "alice",
            "owns": "archetypes"
        }),
    )
    .await;
    assert_eq!(sr, StatusCode::OK);
    let (_, participants_after) = get(
        &bob,
        "/federation/handoff/participants?project=engagement-9",
    )
    .await;
    assert!(participants_after["participants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| {
            p["authority"] == "alice" && p["owns"] == "archetypes" && p["revoked"] == true
        }));

    // Alice committed her side (becomes the operator).
    assert!(
        poll_committed(&alice, "engagement-9").await,
        "alice committed its side"
    );

    // The invite is single-use: replaying it finds no parked receiver (the invite was
    // consumed and resolved), so the accept times out cleanly rather than relocating
    // again — the project stays home on bob (EXACTLY_ONE_HOME). Single-use of the
    // admission itself is proven in `consent-guard.qnt`.
    let (sr, _replay) = post(
        &bob,
        "/federation/invite/accept",
        json!({ "invite": invite_url }),
    )
    .await;
    assert_eq!(
        sr,
        StatusCode::GATEWAY_TIMEOUT,
        "a consumed invite cannot be replayed"
    );
    let (_, after) = get(&bob, "/federation/handoff/status?project=engagement-9").await;
    assert_eq!(after["phase"], "committed", "bob is still the sole home");
    let _ = bob_wb;
}

#[tokio::test]
async fn a_relocated_workstream_chat_remains_a_valid_federated_run_target() {
    let (broker, _relay) = start_broker().await;
    let (alice, _alice_wb, _ra) = workspace_instance("alice", &broker);
    let (bob, _bob_wb, _rb) = workspace_instance("bob", &broker);

    let (sp, project) = post(&alice, "/projects", json!({ "name": "Relocated line" })).await;
    assert_eq!(sp, StatusCode::CREATED, "project: {project}");
    let project_id = project["id"].as_str().unwrap().to_owned();
    let target_id = project["target_id"].as_str().unwrap().to_owned();
    let (sa, archetype) = post(&alice, "/archetypes", json!({ "name": "Analyst" })).await;
    assert_eq!(sa, StatusCode::CREATED, "archetype: {archetype}");
    let archetype_id = archetype["id"].as_str().unwrap().to_owned();
    let (sb, placement) = post(
        &alice,
        &format!("/projects/{project_id}/placements"),
        json!({ "agent_id": archetype_id }),
    )
    .await;
    assert_eq!(sb, StatusCode::CREATED, "placement: {placement}");
    let placement_id = placement["instance_id"].as_str().unwrap().to_owned();
    let (sc, chat) = post(
        &alice,
        &format!("/projects/{project_id}/placements/{placement_id}/chats"),
        json!({ "title": "Relocated chat", "target_id": target_id }),
    )
    .await;
    assert_eq!(sc, StatusCode::CREATED, "chat: {chat}");
    let chat_id = chat["id"].as_str().unwrap().to_owned();
    let (sw, workstream) = post(
        &alice,
        &format!("/placements/{placement_id}/workstreams"),
        json!({ "name": "Relocated workstream", "target_id": target_id }),
    )
    .await;
    assert_eq!(sw, StatusCode::CREATED, "workstream: {workstream}");
    let workstream_id = workstream["id"].as_str().unwrap().to_owned();
    let (sj, joined) = post(
        &alice,
        &format!("/workstreams/{workstream_id}/join"),
        json!({ "chat": chat_id }),
    )
    .await;
    assert_eq!(sj, StatusCode::OK, "join: {joined}");

    let (_, invite) = post(
        &alice,
        "/federation/invite",
        json!({ "project": project_id }),
    )
    .await;
    let invite_url = invite["invite_url"].as_str().unwrap().to_owned();
    let (si, accepted) = post(
        &bob,
        "/federation/invite/accept",
        json!({ "invite": invite_url }),
    )
    .await;
    assert_eq!(si, StatusCode::OK, "accept: {accepted}");
    assert!(
        poll_committed(&bob, &project_id).await,
        "the invited project committed on bob"
    );

    let (sworkspace, workspace) = get(&bob, "/workspace").await;
    assert_eq!(
        sworkspace,
        StatusCode::OK,
        "the relocated custom archetype remains projectable: {workspace}"
    );
    assert!(
        workspace["archetypes"]
            .as_array()
            .is_some_and(|archetypes| archetypes.iter().any(|candidate| {
                candidate["id"] == archetype_id
                    && candidate["authoring_target_id"]
                        .as_str()
                        .is_some_and(|target| target == format!("target-archetype-{archetype_id}"))
            })),
        "the target received the custom archetype and its authoring target: {workspace}"
    );
    let (sabilities, abilities) = get(&bob, &format!("/placements/{placement_id}/abilities")).await;
    assert_eq!(
        sabilities,
        StatusCode::OK,
        "the relocated placement can load its authoring package: {abilities}"
    );
    let (snew_chat, new_chat) = post(
        &bob,
        &format!("/projects/{project_id}/placements/{placement_id}/chats"),
        json!({ "title": "Created after relocation", "target_id": target_id }),
    )
    .await;
    assert_eq!(
        snew_chat,
        StatusCode::CREATED,
        "the relocated placement remains runnable on its project target: {new_chat}"
    );

    tokio::time::sleep(Duration::from_millis(300)).await;
    let (sr, placed) = post(
        &alice,
        "/federation/run/place",
        json!({
            "peer": "bob",
            "project": project_id,
            "archetype": "analyst",
            "data_handle": "folder://relocated",
            "prompt": "drive the relocated chat",
            "target_chat": chat_id,
        }),
    )
    .await;
    assert_eq!(
        sr,
        StatusCode::ACCEPTED,
        "the relocated workstream member is admitted to the host queue: {placed}"
    );
    assert_eq!(placed["status"], "pending");
}

#[tokio::test]
async fn an_operator_run_is_gated_by_host_admission() {
    // FED-7 co-drive: the operator (alice) places a project-scoped run on the host (bob);
    // it lands in bob's admission queue until bob allows it, then executes (run-admission.qnt).
    std::env::set_var("GAUGEWRIGHT_FAKE_AGENT", "1"); // stub turn, no real model/runtime
    let (broker, _relay) = start_broker().await;
    let (alice, _wa, _ra) = instance("alice", &broker);
    let (bob, _wb, _rb) = instance("bob", &broker);
    pair(&alice, &bob).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    let place = |project: &str| {
        json!({ "peer": "bob", "project": project, "archetype": "analyst",
                "data_handle": "folder://acme", "prompt": "go" })
    };

    // 1) No standing allow → the run lands pending in bob's admission queue (fail-closed).
    let (s1, b1) = post(&alice, "/federation/run/place", place("engagement-cd")).await;
    assert_eq!(s1, StatusCode::ACCEPTED, "gated run is pending: {b1}");
    assert_eq!(b1["status"], "pending");

    // 2) Bob sees it in the queue: operator + project + archetype + data handle (INV-10).
    let (_, q) = get(&bob, "/federation/run/queue").await;
    let items = q["queue"].as_array().unwrap();
    assert_eq!(items.len(), 1, "one run queued");
    assert_eq!(items[0]["operator"], "alice");
    assert_eq!(items[0]["project"], "engagement-cd");
    assert_eq!(items[0]["archetype"], "analyst");

    // 3) Bob allows alice's runs on the project (Allow for project).
    let (sa, _) = post(
        &bob,
        "/federation/run/allow",
        json!({ "project": "engagement-cd", "operator": "alice" }),
    )
    .await;
    assert_eq!(sa, StatusCode::OK);

    // 4) Re-placing now auto-admits and executes on the host (observations admitted).
    let (s2, b2) = post(&alice, "/federation/run/place", place("engagement-cd")).await;
    assert_eq!(s2, StatusCode::OK, "allowed run executes: {b2}");
    assert_eq!(b2["status"], "admitted");
    assert!(
        b2["observations_admitted"].as_u64().unwrap() >= 1,
        "the run executed on the host"
    );

    // 5) A run on a different (un-allowed) project queues; bob denies it (fail-closed).
    let (_, b3) = post(&alice, "/federation/run/place", place("engagement-other")).await;
    let corr = b3["correlation"].as_str().unwrap().to_string();
    let (sd, _) = post(&bob, "/federation/run/deny", json!({ "correlation": corr })).await;
    assert_eq!(sd, StatusCode::OK);
    let (_, q2) = get(&bob, "/federation/run/queue").await;
    let projects: Vec<_> = q2["queue"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["project"].clone())
        .collect();
    assert!(
        !projects.contains(&json!("engagement-other")),
        "denied run left the queue"
    );
}

#[tokio::test]
async fn a_federated_run_drives_a_named_hub_workstream_chat_with_crossing_attribution() {
    std::env::set_var("GAUGEWRIGHT_FAKE_AGENT", "1");
    let (broker, _relay) = start_broker().await;
    let (alice, _wa, _ra) = instance("alice", &broker);
    let (bob, bob_wb, _rb) = workspace_instance("bob", &broker);

    // Build the hub-side project, chat, and active workstream before pairing.
    let (sp, project) = post(&bob, "/projects", json!({ "name": "Hub project" })).await;
    assert_eq!(sp, StatusCode::CREATED, "project: {project}");
    let project_id = project["id"].as_str().unwrap().to_owned();
    let target_id = project["target_id"].as_str().unwrap().to_owned();
    let (sa, archetype) = post(&bob, "/archetypes", json!({ "name": "Analyst" })).await;
    assert_eq!(sa, StatusCode::CREATED, "archetype: {archetype}");
    let archetype_id = archetype["id"].as_str().unwrap().to_owned();
    let (sb, placement) = post(
        &bob,
        &format!("/projects/{project_id}/placements"),
        json!({ "agent_id": archetype_id }),
    )
    .await;
    assert_eq!(sb, StatusCode::CREATED, "placement: {placement}");
    let placement_id = placement["instance_id"].as_str().unwrap().to_owned();
    let (sc, chat) = post(
        &bob,
        &format!("/projects/{project_id}/placements/{placement_id}/chats"),
        json!({ "title": "Shared analysis", "target_id": target_id }),
    )
    .await;
    assert_eq!(sc, StatusCode::CREATED, "chat: {chat}");
    let chat_id = chat["id"].as_str().unwrap().to_owned();
    let (sw, workstream) = post(
        &bob,
        &format!("/placements/{placement_id}/workstreams"),
        json!({ "name": "Analysis", "target_id": target_id }),
    )
    .await;
    assert_eq!(sw, StatusCode::CREATED, "workstream: {workstream}");
    let workstream_id = workstream["id"].as_str().unwrap().to_owned();
    let (sj, joined) = post(
        &bob,
        &format!("/workstreams/{workstream_id}/join"),
        json!({ "chat": chat_id }),
    )
    .await;
    assert_eq!(sj, StatusCode::OK, "join: {joined}");

    pair(&alice, &bob).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let (sa, _) = post(
        &bob,
        "/federation/run/allow",
        json!({ "project": project_id, "operator": "alice" }),
    )
    .await;
    assert_eq!(sa, StatusCode::OK);

    let (sr, run) = post(
        &alice,
        "/federation/run/place",
        json!({
            "peer": "bob",
            "project": project_id,
            "archetype": "analyst",
            "data_handle": "folder://hub",
            "prompt": "federated workstream contribution",
            "target_chat": chat_id,
        }),
    )
    .await;
    assert_eq!(sr, StatusCode::OK, "run: {run}");
    assert_eq!(run["status"], "admitted");

    // The named chat—not a throwaway remote-run scope—received and auto-synced
    // the work, and the contribution cites the verified crossing authority.
    let (sf, body) = get_text(&bob, &format!("/chats/{chat_id}/file?path=agent-note.txt")).await;
    assert_eq!(sf, StatusCode::OK, "target chat file: {body}");
    assert!(body.contains("federated workstream contribution"));
    let events = bob_wb
        .lock()
        .unwrap()
        .store_ref()
        .events(&workstream_id)
        .unwrap();
    assert!(
        events.iter().any(|(_, kind, payload)| {
            kind == "workstream"
                && payload.contains("ContributionAdmitted")
                && payload.contains("alice")
        }),
        "workstream contribution is attributed to alice: {events:?}",
    );

    std::env::remove_var("GAUGEWRIGHT_FAKE_AGENT");
}

#[tokio::test]
async fn allow_once_executes_one_queued_run_and_delivers_the_result() {
    // FED-7 co-drive "Allow once": the host admits *this one* queued run, executes it,
    // and delivers the result to the operator — without setting a standing allow.
    std::env::set_var("GAUGEWRIGHT_FAKE_AGENT", "1");
    let (broker, _relay) = start_broker().await;
    let (alice, _wa, _ra) = instance("alice", &broker);
    let (bob, _wb, _rb) = instance("bob", &broker);
    pair(&alice, &bob).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    let place = json!({ "peer": "bob", "project": "engagement-once", "archetype": "analyst",
                        "data_handle": "folder://acme", "prompt": "go" });

    // Operator places a run; no standing allow → pending.
    let (s1, b1) = post(&alice, "/federation/run/place", place.clone()).await;
    assert_eq!(s1, StatusCode::ACCEPTED);
    let corr = b1["correlation"].as_str().unwrap().to_string();

    // Host admits *this one* run (Allow once) → executes + delivers the result.
    let (sa, ba) = post(
        &bob,
        "/federation/run/admit-once",
        json!({ "correlation": corr }),
    )
    .await;
    assert_eq!(sa, StatusCode::OK, "admit-once ok: {ba}");

    // The operator polls its local result projection until the host's delivery lands.
    let mut done = false;
    for _ in 0..40 {
        let (_, r) = get(
            &alice,
            &format!("/federation/run/result?correlation={corr}"),
        )
        .await;
        if r["status"] == "done" {
            assert!(
                r["observations_admitted"].as_u64().unwrap() >= 1,
                "the run executed"
            );
            done = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(done, "the operator received the delivered run result");

    // Allow once did NOT set a standing allow: a second run queues again (single-run).
    let (s2, _) = post(&alice, "/federation/run/place", place).await;
    assert_eq!(
        s2,
        StatusCode::ACCEPTED,
        "still gated — Allow once was one-time"
    );
}

#[tokio::test]
async fn relocating_to_an_unpaired_peer_is_refused() {
    let (broker, _relay) = start_broker().await;
    let (alice, _wb, _ra) = instance("alice", &broker);
    // No pairing: alice has no grant/cert for "bob".
    let (status, _) = post(
        &alice,
        "/federation/handoff/relocate",
        json!({ "project": "p", "peer": "bob" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a relocation to an unpaired peer is refused before any transport"
    );
}
