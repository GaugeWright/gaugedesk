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
//! The relocation's one-home safety is the verified reducer (`gaugedesk_core::handoff`);
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

use gaugedesk_app::account::{credentials_in_scope, project_scope};
use gaugedesk_app::federation::Federation;
use gaugedesk_app::open_control_plane;
use gaugedesk_app::Workbench;
use gaugedesk_core::ids::AuthorityId;
use gaugedesk_store::Store;
use gaugedesk_workspace::Instance;

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

async fn start_broker() -> (String, gaugedesk_relay_transport::test_relay::TestRelay) {
    let relay = gaugedesk_relay_transport::test_relay::TestRelay::bind()
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

/// A bridge proves who a peer is; it deliberately grants no authority on an unrelated
/// project. Tests that exercise run admission without first relocating/joining declare the
/// exact participant fact that those product journeys would have written.
fn declare_operator(
    host: &Arc<Mutex<Workbench>>,
    project: &str,
    host_authority: &str,
    operator: &str,
) {
    let mut guard = host.lock().unwrap();
    let scope = format!("project::{project}::participants");
    for record in [
        json!({ "authority": host_authority, "role": "host", "owns": "data", "revoked": false }),
        json!({ "authority": operator, "role": "operator", "owns": "archetypes", "revoked": false }),
    ] {
        guard
            .store_mut()
            .append_record(&scope, "participant", &record.to_string())
            .unwrap();
    }
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

/// ADR 0155 §2, end to end: a serving Home re-sends a retraction whose delivery
/// was lost, for as long as the peer's grant lives.
///
/// Before that decision the retraction was **fire-once**. Both callers send it
/// while the record is still an upsert and tombstone locally straight after, and
/// the tombstone folded the record out of the very set the retractor iterates —
/// so a send that failed was not deferred but forgotten, and the operator kept a
/// live pointer at a Home that had stopped serving the project.
///
/// The retained departure is what gives the retraction somewhere to live between
/// failing and being re-sent.
#[tokio::test]
async fn a_lost_route_retraction_is_re_sent_while_the_grant_lives() {
    let (broker, relay) = start_broker().await;
    let (alice, alice_wb, _ra) = instance("alice", &broker);
    let (bob, bob_wb, _rb) = instance("bob", &broker);

    pair(&alice, &bob).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // alice serves a project bob operates on.
    {
        let mut g = alice_wb.lock().unwrap();
        let home = g.home_id().as_str().to_owned();
        g.store_mut()
            .append_record(
                "library",
                "project",
                &json!({ "id": "shared-1", "op": "upsert", "name": "Shared", "is_default": false,
                         "home_id": home, "network_isolated": false })
                .to_string(),
            )
            .unwrap();
        g.rebuild_library();
    }
    declare_operator(&alice_wb, "shared-1", "alice", "bob");

    let leg = |epoch: u64| gaugedesk_relay_transport::RelayRoute {
        endpoint: "wss://relay.example".to_owned(),
        handle: "h".repeat(43),
        epoch,
        proof: gaugedesk_relay_transport::RouteProof::new([2u8; 32]),
        previous_proof: None,
        home_fingerprint: [0xABu8; 32],
    };
    let held_by_bob = |project: &str| {
        let g = bob_wb.lock().unwrap();
        gaugedesk_app::account::Account::rebuild(g.store_ref())
            .unwrap()
            .home_routes
            .contains_key(project)
    };

    // alice authors and distributes the route; bob learns where the work lives.
    gaugedesk_app::home_reachability::republish(&alice_wb, &leg(1));
    let learned = tokio::time::timeout(Duration::from_secs(10), async {
        while !held_by_bob("shared-1") {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        learned.is_ok(),
        "bob must first hold the route this test retracts"
    );

    // alice stops serving it, and the retraction cannot cross.
    relay.disrupt_one_shot().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    {
        let mut g = alice_wb.lock().unwrap();
        let home = g.home_id().as_str().to_owned();
        g.store_mut()
            .append_record(
                "library",
                "project",
                &json!({ "id": "shared-1", "op": "tombstone", "name": "Shared", "is_default": false,
                         "home_id": home, "network_isolated": false })
                .to_string(),
            )
            .unwrap();
        g.rebuild_library();
    }
    gaugedesk_app::home_reachability::republish(&alice_wb, &leg(2));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        held_by_bob("shared-1"),
        "the retraction was genuinely lost — otherwise this test proves nothing"
    );

    // alice's own view has moved on: the route is departed, and retained.
    {
        let g = alice_wb.lock().unwrap();
        let account = gaugedesk_app::account::Account::rebuild(g.store_ref()).unwrap();
        assert!(!account.home_routes.contains_key("shared-1"));
        assert!(
            account.departed_home_routes.contains_key("shared-1"),
            "the departure is retained, which is what it can be re-sent from"
        );
    }

    // The next reachability reconcile re-sends it, and bob folds the stale
    // locator away rather than dialing a Home that stopped serving the project.
    relay.restore_one_shot().await;
    gaugedesk_app::home_reachability::republish(&alice_wb, &leg(3));
    let retracted = tokio::time::timeout(Duration::from_secs(10), async {
        while held_by_bob("shared-1") {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        retracted.is_ok(),
        "a retraction whose delivery failed must be re-sent while the grant lives"
    );
}

/// ADR 0156 §2–§3, end to end: the target commits, its `Committed` never arrives,
/// and the origin resolves the handoff by **asking** on reconnect.
///
/// This is the window FED-13 was opened for, and it needed a relay that can lose a
/// *single* message while everything else keeps working — taking the whole broker
/// away is a different failure, and one both sides can see.
#[tokio::test]
async fn a_lost_commit_notice_is_resolved_by_asking_the_peer_on_reconnect() {
    let (broker, relay) = start_broker().await;
    let (alice, alice_wb, _ra) = instance("alice", &broker);
    let (bob, bob_wb, _rb) = instance("bob", &broker);

    pair(&alice, &bob).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

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
        g.rebuild_library();
    }

    // The offer crosses and lands pending bob's consent; alice stays home.
    let (status, body) = post(
        &alice,
        "/federation/handoff/relocate",
        json!({ "project": "engagement-1", "peer": "bob" }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["phase"], "offered");

    // Lose exactly the reply. Peer messaging is severed; the fabric is untouched.
    relay.disrupt_one_shot().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (sa, ba) = post(
        &bob,
        "/federation/handoff/accept",
        json!({ "project": "engagement-1", "source": "alice" }),
    )
    .await;
    assert_eq!(sa, StatusCode::OK, "bob commits regardless: {ba}");
    assert_eq!(ba["home_target"], true, "bob is home");

    // The disagreement, made real: bob is home and alice does not know.
    let (_, mid) = get(&alice, "/federation/handoff/status?project=engagement-1").await;
    assert_eq!(
        mid["home_origin"], true,
        "alice still believes it is home — two Homes for one project: {mid}"
    );

    // Reconnect. Alice's receiver loop asks before it parks again.
    relay.restore_one_shot().await;
    let resolved = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let (_, s) = get(&alice, "/federation/handoff/status?project=engagement-1").await;
            if s["home_origin"] == false {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect(
        "alice must resolve the handoff by asking, not wait for a message that will never come",
    );

    assert_eq!(
        resolved["phase"], "committed",
        "alice commits its side from the answer: {resolved}"
    );
    assert_eq!(
        resolved["home_origin"], false,
        "and releases the project it had already given away: {resolved}"
    );
    assert!(
        bob_wb
            .lock()
            .unwrap()
            .project_home_id("engagement-1")
            .is_some(),
        "bob keeps it throughout — the resolution only ever moved alice toward releasing"
    );
}

/// ADR 0156 §1: a transport failure *after* the offer is on the wire does not say
/// whether the target got it — and the old path resolved that ambiguity by
/// assuming failure, then deleted the pending state that would have let anything
/// notice it had guessed wrong. Target home, origin home, no record of a question.
///
/// The offer now stays offered and is recorded as in doubt. `INV-13` keeps the
/// origin home either way, so waiting costs nothing that guessing would have
/// saved, and the evidence a reconcile needs survives.
#[tokio::test]
async fn an_offer_whose_reply_is_lost_stays_in_doubt_rather_than_rolling_back() {
    let (broker, relay) = start_broker().await;
    let (alice, alice_wb, _ra) = instance("alice", &broker);
    let (bob, _bob_wb, _rb) = instance("bob", &broker);

    pair(&alice, &bob).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

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
        g.rebuild_library();
    }

    // Take the rendezvous away. The offer cannot cross, and from alice's side this
    // is indistinguishable from an offer that crossed and whose reply was lost —
    // which is exactly why it may not be resolved by assumption.
    drop(relay);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (status, body) = post(
        &alice,
        "/federation/handoff/relocate",
        json!({ "project": "engagement-1", "peer": "bob" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "the send failed: {body}");
    assert_eq!(
        body["in_doubt"], true,
        "and the failure is reported as unresolved, not as a rollback: {body}"
    );

    // The load-bearing assertion. Before ADR 0156 this read `draft` — alice had
    // aborted, so a target that had in fact committed would have left two Homes
    // serving one project with nothing anywhere recording a question.
    let (_, after) = get(&alice, "/federation/handoff/status?project=engagement-1").await;
    assert_eq!(
        after["phase"], "offered",
        "the handoff stays offered, because whether it landed is still unknown: {after}"
    );
    assert_eq!(
        after["home_origin"], true,
        "and INV-13 keeps alice home meanwhile, so waiting costs nothing: {after}"
    );
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
    // A refusal, not a gateway failure: bob's placement policy *decided* against
    // this relocation and will decide the same way every time, so it must not be
    // reported as a broken upstream inviting a retry (`403`, not `502`).
    assert_eq!(status, StatusCode::FORBIDDEN, "policy refusal: {body}");
    // And bob's own sentence reaches the caller. Behind Cloudflare an origin 5xx
    // has its body replaced, so a refusal explained in a 502 explains nothing.
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("placement policy"),
        "the refusal must say why it refused: {body}",
    );
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
async fn a_relocation_that_cannot_reach_the_peer_is_still_a_gateway_failure() {
    // The counterpart to the refusal above, and the reason `403` is not simply
    // the new answer for "the relocation did not happen": when the leg to the
    // peer never comes up, nothing has *decided* anything. That is a genuine
    // transport fault, it may well succeed on the next attempt, and it keeps
    // `502` — the status a caller should retry.
    let (broker, _relay) = start_broker().await;
    // alice dials a broker nothing is listening on: bind one, take its address,
    // drop it. Pairing is local HTTP and does not need the broker, so alice ends
    // up properly paired with a peer it cannot reach.
    let dead_broker = {
        let relay = gaugedesk_relay_transport::test_relay::TestRelay::bind()
            .await
            .unwrap();
        relay.endpoint().to_owned()
    };
    let (alice, alice_wb, _ra) = instance("alice", &dead_broker);
    let (bob, _bob_wb, _rb) = instance("bob", &broker);
    pair(&alice, &bob).await;

    {
        let mut alice = alice_wb.lock().unwrap();
        alice
            .store_mut()
            .append_record(
                "library",
                "project",
                r#"{"id":"unreachable","op":"upsert","name":"Unreachable","is_default":false,"home_id":"home:alice","network_isolated":false}"#,
            )
            .unwrap();
        alice.rebuild_library();
    }

    let (status, body) = post(
        &alice,
        "/federation/handoff/relocate",
        json!({ "project": "unreachable", "peer": "bob" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "transport fault: {body}");
    assert_eq!(
        alice_wb
            .lock()
            .unwrap()
            .project_home_id("unreachable")
            .unwrap()
            .as_str(),
        "home:alice",
        "the origin rolls back and remains home when the offer never lands"
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
        let target = gaugedesk_workspace::Instance::init_at(&dir).unwrap();
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
async fn a_third_root_joins_an_existing_home_without_relocation_or_payload_copy() {
    let (broker, _relay) = start_broker().await;
    let (alice, _alice_wb, _ra) = instance("alice", &broker);
    let (bob, bob_wb, _rb) = instance("bob", &broker);
    let (carol, _carol_wb, _rc) = instance("carol", &broker);
    pair(&alice, &bob).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (created_status, created) = post(&bob, "/projects", json!({ "name": "N-party" })).await;
    assert_eq!(created_status, StatusCode::CREATED, "project: {created}");
    let project = created["id"].as_str().unwrap().to_owned();
    declare_operator(&bob_wb, &project, "bob", "alice");

    let (invite_status, invite) = post(
        &bob,
        "/federation/invite",
        json!({ "project": project, "disposition": "join" }),
    )
    .await;
    assert_eq!(invite_status, StatusCode::OK, "join invite: {invite}");
    assert_eq!(invite["disposition"], "join");
    let (accepted_status, accepted) = post(
        &carol,
        "/federation/invite/accept",
        json!({ "invite": invite["invite_url"] }),
    )
    .await;
    assert_eq!(accepted_status, StatusCode::OK, "join accept: {accepted}");
    assert_eq!(accepted["disposition"], "join");

    let (_, participants) = get(
        &bob,
        &format!("/federation/handoff/participants?project={project}"),
    )
    .await;
    let participants = participants["participants"].as_array().unwrap();
    assert!(participants.iter().any(|row| row["authority"] == "alice"));
    assert!(participants.iter().any(|row| row["authority"] == "carol"));
    assert!(participants.iter().any(|row| row["authority"] == "bob"));

    let (_, home) = get(
        &bob,
        &format!("/federation/handoff/status?project={project}"),
    )
    .await;
    assert_eq!(
        home["phase"], "draft",
        "join did not start a handoff: {home}"
    );
    assert_eq!(home["home_origin"], true, "the serving Home stayed on bob");
    let (_, carol_workspace) = get(&carol, "/workspace").await;
    assert!(
        !carol_workspace["projects"]
            .as_array()
            .is_some_and(|projects| projects.iter().any(|row| row["id"] == project)),
        "join copied the host project payload to carol: {carol_workspace}"
    );
}

#[tokio::test]
async fn a_relocated_workstream_chat_remains_a_valid_federated_run_target() {
    let (broker, _relay) = start_broker().await;
    let (alice, alice_wb, alice_root) = workspace_instance("alice", &broker);
    let (bob, _bob_wb, bob_root) = workspace_instance("bob", &broker);

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

    // Give the project a genuinely independent second managed target. A
    // second chat selects it so both partitions exist in the collaboration
    // workspace, while the workstream chat below remains scoped to only the
    // original target.
    let secondary_target_id = "target-relocation-secondary";
    {
        let secondary =
            Instance::init_at(alice_root.path().join("targets").join(secondary_target_id)).unwrap();
        secondary
            .seed_main(&[("secondary.txt", "secondary-only")])
            .unwrap();
        let basis = secondary
            .create_engagement("secondary-basis-probe")
            .unwrap()
            .boundary_cut()
            .unwrap()
            .to_string();
        secondary
            .remove_engagement("secondary-basis-probe")
            .unwrap();
        let mut guard = alice_wb.lock().unwrap();
        guard
            .store_mut()
            .append_record(
                "library",
                "work_target",
                &json!({
                    "id": secondary_target_id,
                    "op": "upsert",
                    "name": "Secondary files",
                    "owner": { "kind": "project", "project_id": project_id },
                    "kind": "managed",
                    "authority": "alice",
                    "parties": ["alice"],
                    "locator_handle": format!("managed:{secondary_target_id}"),
                    "adapter": "whipplescript",
                    "adapter_family": "whipplescript-v1",
                    "vcs_posture": "managed",
                    "current_basis": basis,
                    "path_scope": ["."],
                    "capabilities": {
                        "read": true,
                        "propose": true,
                        "apply": true,
                        "publish": false,
                        "release": false
                    },
                    "status": "available"
                })
                .to_string(),
            )
            .unwrap();
        guard
            .store_mut()
            .append_record(
                "library",
                "placement_targets",
                &json!({
                    "placement_id": placement_id,
                    "op": "upsert",
                    "target_ids": [target_id, secondary_target_id]
                })
                .to_string(),
            )
            .unwrap();
        guard.register_target(secondary_target_id, Box::new(secondary));
        guard.rebuild_library();
    }
    let (ss, secondary_chat) = post(
        &alice,
        &format!("/projects/{project_id}/placements/{placement_id}/chats"),
        json!({ "title": "Secondary-only chat", "target_id": secondary_target_id }),
    )
    .await;
    assert_eq!(ss, StatusCode::CREATED, "secondary chat: {secondary_chat}");
    let secondary_chat_id = secondary_chat["id"].as_str().unwrap().to_owned();

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
    let relocated_chat = workspace["recent"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["id"] == chat_id)
        .expect("relocated workstream chat is projected");
    let collaboration_workspace_id = relocated_chat["collaboration_workspace_id"]
        .as_str()
        .expect("work chat names its project collaboration workspace");
    let secondary_root = gaugedesk_app::library::target_id_path_v1(secondary_target_id).unwrap();
    let worktrees = bob_root
        .path()
        .join("collaboration-workspaces")
        .join(collaboration_workspace_id)
        .join("worktrees");
    assert!(
        !worktrees
            .join(&chat_id)
            .join("targets")
            .join(&secondary_root)
            .exists(),
        "relocation must not widen the workstream chat to an unrelated target partition"
    );
    assert_eq!(
        std::fs::read_to_string(
            worktrees
                .join(&secondary_chat_id)
                .join("targets")
                .join(&secondary_root)
                .join("secondary.txt")
        )
        .ok()
        .as_deref(),
        Some("secondary-only"),
        "the independently scoped chat retained its selected target partition"
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
async fn a_run_placement_refused_by_the_host_floor_is_forbidden_not_a_gateway_failure() {
    // The third federation route that flattened a decision into a 5xx. Bob's
    // placement floor declines the run (`ITGOV-3` (b) / ADR 0074): no attestation
    // quote crosses a run-place, so an attested-required policy refuses. That is
    // the host deciding — identically on every retry — and answers `403`.
    let (broker, _relay) = start_broker().await;
    let (alice, _wa, _ra) = instance("alice", &broker);
    let (bob, bob_wb, _rb) = instance("bob", &broker);
    pair(&alice, &bob).await;
    declare_operator(&bob_wb, "floor-blocked", "bob", "alice");
    tokio::time::sleep(Duration::from_millis(400)).await;

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
    // The floor narrows an *admitted* run, so bob must first grant the standing
    // allow the floor then overrides — grant admits, floor refuses (ADR 0074).
    let (allow, _) = post(
        &bob,
        "/federation/run/allow",
        json!({ "project": "floor-blocked", "operator": "alice" }),
    )
    .await;
    assert_eq!(allow, StatusCode::OK);

    let (status, body) = post(
        &alice,
        "/federation/run/place",
        json!({ "peer": "bob", "project": "floor-blocked", "archetype": "analyst",
                "data_handle": "folder://acme", "prompt": "go" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "floor refusal: {body}");
    assert_eq!(body["status"], "refused");
    // A floor refusal refuses rather than queues — it is not a consent prompt —
    // so there is nothing pending for bob to act on.
    let (_, queue) = get(&bob, "/federation/run/queue").await;
    assert!(
        queue["queue"].as_array().unwrap().is_empty(),
        "a floor refusal does not queue for admission: {queue}",
    );
}

#[tokio::test]
async fn an_operator_run_is_gated_by_host_admission() {
    // FED-7 co-drive: the operator (alice) places a project-scoped run on the host (bob);
    // it lands in bob's admission queue until bob allows it, then executes (run-admission.qnt).
    std::env::set_var("GAUGEDESK_FAKE_AGENT", "1"); // stub turn, no real model/runtime
    let (broker, _relay) = start_broker().await;
    let (alice, _wa, _ra) = instance("alice", &broker);
    let (bob, bob_wb, _rb) = instance("bob", &broker);
    pair(&alice, &bob).await;
    declare_operator(&bob_wb, "engagement-cd", "bob", "alice");
    declare_operator(&bob_wb, "engagement-other", "bob", "alice");
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
    std::env::set_var("GAUGEDESK_FAKE_AGENT", "1");
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
    declare_operator(&bob_wb, &project_id, "bob", "alice");
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
            kind == "workstream_contribution" && payload.contains("alice")
        }),
        "workstream contribution is attributed to alice: {events:?}",
    );

    std::env::remove_var("GAUGEDESK_FAKE_AGENT");
}

#[tokio::test]
async fn allow_once_executes_one_queued_run_and_delivers_the_result() {
    // FED-7 co-drive "Allow once": the host admits *this one* queued run, executes it,
    // and delivers the result to the operator — without setting a standing allow.
    std::env::set_var("GAUGEDESK_FAKE_AGENT", "1");
    let (broker, _relay) = start_broker().await;
    let (alice, _wa, _ra) = instance("alice", &broker);
    let (bob, bob_wb, _rb) = instance("bob", &broker);
    pair(&alice, &bob).await;
    declare_operator(&bob_wb, "engagement-once", "bob", "alice");
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

// --- Envelope supply at admission (ADR 0139 §5 layer 3, SUPPLY-1..3) --------

/// Grant alice a standing allow on `project` at bob, and place a run. Returns
/// the placement's `(status, body)`.
async fn allow_and_place(alice: &Router, bob: &Router, project: &str) -> (StatusCode, Value) {
    let (allow, _) = post(
        bob,
        "/federation/run/allow",
        json!({ "project": project, "operator": "alice" }),
    )
    .await;
    assert_eq!(allow, StatusCode::OK);
    post(
        alice,
        "/federation/run/place",
        json!({ "peer": "bob", "project": project, "archetype": "analyst",
                "data_handle": "folder://acme", "prompt": "go" }),
    )
    .await
}

/// Bob's governance root public key — the one an envelope of bob's must be
/// signed by (ADR 0139 §3).
fn root_signing_key(
    root: &tempfile::TempDir,
    authority: &str,
) -> gaugedesk_core::signature::SigningKey {
    use gaugedesk_app::key_store::{FileKeyStore, KeyStore};
    FileKeyStore::new(root.path().join("keys")).signing_key(&AuthorityId::new(authority))
}

/// Mint a genuinely signed `:v2` envelope for `authority`, signed by `root`.
///
/// The document has to be real: SUPPLY-4 verifies it against the authority's
/// governance root before composing, so a placeholder cannot reach the meet.
fn signed_envelope(
    authority: &str,
    root: &gaugedesk_core::signature::SigningKey,
) -> gaugedesk_app::envelope_supply::EnvelopeRecord {
    use whipplescript_kernel::gov::{external_signing_bytes_v2, SignedEnvelope};

    // A JSON body: `to_json` rebuilds the document from the canonical form, and a
    // DSL body does not survive that round trip.
    let config = r#"{"readers":{},"governed":[]}"#;
    let key_id = "gov-root";
    let epoch = 3u64;
    let preimage =
        external_signing_bytes_v2(config, authority, "p256-sha256", key_id, epoch, authority)
            .expect("preimage");
    let signature = hex::encode(root.sign(&preimage).as_bytes());
    let signed = SignedEnvelope::from_external_signature_v2(
        config,
        authority,
        "p256-sha256",
        key_id,
        &signature,
        epoch,
        authority,
    )
    .expect("signed envelope");

    gaugedesk_app::envelope_supply::EnvelopeRecord {
        authority: AuthorityId::new(authority),
        envelope_hash: signed.envelope_hash.clone(),
        epoch,
        signer: root.public_key(),
        signed_document: signed.to_json(),
    }
}

/// An envelope whose document is a placeholder — registered, identified, and
/// unverifiable. Used to show the meet refuses what supply alone would admit.
fn unsigned_envelope(
    authority: &str,
    signer: gaugedesk_core::ids::PublicKey,
) -> gaugedesk_app::envelope_supply::EnvelopeRecord {
    gaugedesk_app::envelope_supply::EnvelopeRecord {
        authority: AuthorityId::new(authority),
        envelope_hash: format!("hash-{authority}"),
        epoch: 3,
        signer,
        signed_document: String::new(),
    }
}

#[tokio::test]
async fn an_admitted_run_records_the_envelope_set_it_was_checked_under() {
    // ADR 0139's evidence consequence: "which policies was this checked under"
    // is answerable after the fact rather than reconstructed. With nobody
    // supplying policy the record is empty and the roster is not — and an empty
    // record beside a populated roster is exactly the statement that must not be
    // indistinguishable from a set that was never assembled (§2).
    std::env::set_var("GAUGEDESK_FAKE_AGENT", "1");
    let (broker, _relay) = start_broker().await;
    let (alice, _wa, _ra) = instance("alice", &broker);
    let (bob, bob_wb, _rb) = instance("bob", &broker);
    pair(&alice, &bob).await;
    declare_operator(&bob_wb, "supply-evidence", "bob", "alice");
    tokio::time::sleep(Duration::from_millis(400)).await;

    let (status, body) = allow_and_place(&alice, &bob, "supply-evidence").await;
    assert_eq!(status, StatusCode::OK, "allowed run executes: {body}");
    let correlation = body["correlation"]
        .as_str()
        .expect("correlation")
        .to_string();

    let guard = bob_wb.lock().unwrap();
    let supply = gaugedesk_app::envelope_supply::supply_for(guard.store_ref(), &correlation)
        .expect("an admitted run records its supply");
    assert_eq!(
        supply.roster.len(),
        1,
        "the host is a stakeholder in every run it admits: {supply:?}"
    );
    assert_eq!(supply.roster[0].authority.as_str(), "bob");
    assert!(!supply.roster[0].governed, "bob supplied no envelope");
    assert!(supply.record.is_empty(), "nothing was checked under policy");
    assert_eq!(supply.ungoverned().len(), 1);
}

#[tokio::test]
async fn a_root_signed_envelope_enters_the_composition_record() {
    // The positive path for SUPPLY-2/3: an envelope signed by the authority's
    // governance root is carried in the record, and its stakeholder flips to
    // governed in the roster. The two lists agree, which is what makes either
    // one readable.
    std::env::set_var("GAUGEDESK_FAKE_AGENT", "1");
    let (broker, _relay) = start_broker().await;
    let (alice, _wa, _ra) = instance("alice", &broker);
    let (bob, bob_wb, rb) = instance("bob", &broker);
    pair(&alice, &bob).await;
    declare_operator(&bob_wb, "supply-governed", "bob", "alice");
    tokio::time::sleep(Duration::from_millis(400)).await;

    {
        let mut guard = bob_wb.lock().unwrap();
        gaugedesk_app::envelope_supply::register_envelope(
            guard.store_mut(),
            "supply-governed",
            &signed_envelope("bob", &root_signing_key(&rb, "bob")),
        )
        .unwrap();
    }

    let (status, body) = allow_and_place(&alice, &bob, "supply-governed").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a root-signed envelope admits: {body}"
    );
    let correlation = body["correlation"]
        .as_str()
        .expect("correlation")
        .to_string();

    let guard = bob_wb.lock().unwrap();
    let supply = gaugedesk_app::envelope_supply::supply_for(guard.store_ref(), &correlation)
        .expect("supply recorded");
    assert_eq!(supply.record.len(), 1, "{supply:?}");
    assert_eq!(supply.record[0].authority.as_str(), "bob");
    // The hash is the real digest of the canonical envelope, not a fixture
    // string: SUPPLY-4 verifies the document, and `Composition::compose` refuses
    // a record citing a different envelope than the signature covers, so these
    // agreeing is the end-to-end property.
    assert_eq!(supply.record[0].envelope_hash.len(), 64);
    assert!(supply.record[0]
        .envelope_hash
        .chars()
        .all(|c| c.is_ascii_hexdigit()));
    assert_eq!(supply.record[0].epoch, 3);
    assert!(
        supply.roster[0].governed,
        "the roster agrees with the record"
    );
    assert!(supply.ungoverned().is_empty());
}

#[tokio::test]
async fn a_subkey_signed_envelope_refuses_the_run() {
    // ADR 0139 §3: a policy revision is not a crossing. A device subkey chains to
    // the root and signs every crossing, and must still not be able to author
    // policy — otherwise a stolen laptop is a policy author for its authority.
    std::env::set_var("GAUGEDESK_FAKE_AGENT", "1");
    let (broker, _relay) = start_broker().await;
    let (alice, _wa, _ra) = instance("alice", &broker);
    let (bob, bob_wb, _rb) = instance("bob", &broker);
    pair(&alice, &bob).await;
    declare_operator(&bob_wb, "supply-subkey", "bob", "alice");
    tokio::time::sleep(Duration::from_millis(400)).await;

    {
        let mut guard = bob_wb.lock().unwrap();
        // Any key that is not bob's governance root — a device subkey is one.
        let not_the_root = gaugedesk_core::signature::SigningKey::from_seed(&[7u8; 32])
            .expect("a valid P-256 scalar");
        gaugedesk_app::envelope_supply::register_envelope(
            guard.store_mut(),
            "supply-subkey",
            &signed_envelope("bob", &not_the_root),
        )
        .unwrap();
    }

    let (status, body) = allow_and_place(&alice, &bob, "supply-subkey").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["status"], "refused");
    assert!(
        body["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("governance root"),
        "the refusal names the tripped constraint: {body}"
    );
}

#[tokio::test]
async fn an_envelope_for_a_non_stakeholder_refuses_the_run() {
    // The direction ADR 0139 §2 fails closed on: an authority in the record but
    // not the roster means this side's derivation and its supply disagree about
    // who has a stake, and the one that can be influenced from outside is the
    // supply.
    std::env::set_var("GAUGEDESK_FAKE_AGENT", "1");
    let (broker, _relay) = start_broker().await;
    let (alice, _wa, _ra) = instance("alice", &broker);
    let (bob, bob_wb, _rb) = instance("bob", &broker);
    pair(&alice, &bob).await;
    declare_operator(&bob_wb, "supply-stranger", "bob", "alice");
    tokio::time::sleep(Duration::from_millis(400)).await;

    {
        let mut guard = bob_wb.lock().unwrap();
        gaugedesk_app::envelope_supply::register_envelope(
            guard.store_mut(),
            "supply-stranger",
            &unsigned_envelope("carol", gaugedesk_core::ids::PublicKey::new("04c0ffee")),
        )
        .unwrap();
    }

    let (status, body) = allow_and_place(&alice, &bob, "supply-stranger").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("not a derived stakeholder"),
        "the refusal names the tripped constraint: {body}"
    );
}

#[tokio::test]
async fn a_v1_signed_envelope_passes_supply_and_is_refused_by_the_meet() {
    // The layer-3 tooth. Supply checks that the SIGNER is the authority's
    // governance root (SUPPLY-3) and nothing more, so a `:v1` envelope signed by
    // the root passes it: the signer is right. Composition is what refuses it,
    // because `:v1` does not cover the epoch or the authority, and a set whose
    // constituents are not bound to a policy revision cannot carry the
    // non-retroactivity claim the composition record exists to make (DR-0063 §5).
    //
    // Without this the meet could stop refusing and every other test would still
    // pass — the subkey case never reaches it, being caught in `assemble` first.
    std::env::set_var("GAUGEDESK_FAKE_AGENT", "1");
    let (broker, _relay) = start_broker().await;
    let (alice, _wa, _ra) = instance("alice", &broker);
    let (bob, bob_wb, rb) = instance("bob", &broker);
    pair(&alice, &bob).await;
    declare_operator(&bob_wb, "supply-v1", "bob", "alice");
    tokio::time::sleep(Duration::from_millis(400)).await;

    {
        use whipplescript_kernel::gov::{external_signing_bytes, SignedEnvelope};
        let root = root_signing_key(&rb, "bob");
        let config = r#"{"readers":{},"governed":[]}"#;
        // `:v1` — the preimage covers neither the epoch nor the authority.
        let preimage =
            external_signing_bytes(config, "bob", "p256-sha256", "gov-root").expect("v1 preimage");
        let signature = hex::encode(root.sign(&preimage).as_bytes());
        let signed = SignedEnvelope::from_external_signature(
            config,
            "bob",
            "p256-sha256",
            "gov-root",
            &signature,
        )
        .expect("v1 signed envelope");

        let mut guard = bob_wb.lock().unwrap();
        gaugedesk_app::envelope_supply::register_envelope(
            guard.store_mut(),
            "supply-v1",
            &gaugedesk_app::envelope_supply::EnvelopeRecord {
                authority: AuthorityId::new("bob"),
                envelope_hash: signed.envelope_hash.clone(),
                epoch: 3,
                // The genuine root key, so supply's own check is satisfied.
                signer: root.public_key(),
                signed_document: signed.to_json(),
            },
        )
        .unwrap();
    }

    let (status, body) = allow_and_place(&alice, &bob, "supply-v1").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["status"], "refused");
    let reason = body["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("did not verify") || reason.contains("not composable"),
        "the refusal comes from the meet, not from supply: {body}"
    );
}
