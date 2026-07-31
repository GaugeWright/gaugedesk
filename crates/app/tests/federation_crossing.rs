//! Two-instance federation crossing over the real network (M4 / D-REMOTE /
//! `SERVE-1`). Drives two mounted `control_plane` routers — two distinct
//! authorities — through the whole pairing + crossing flow against a **real
//! rendezvous broker**, over **real cert-pinned TLS** legs:
//!
//! 1. each authority mints a pairing ticket (`POST /federation/pairing-ticket`);
//! 2. each accepts the other's ticket (`POST /federation/pair`), TOFU-pinning the
//!    peer's governance key + TLS-cert fingerprint and spawning a receiver;
//! 3. `GET /federation/peers` shows the pairing on both;
//! 4. one authority hand-drives a crossing (`POST /federation/cross`); the peer
//!    admits it through the verified, grant-pinned reducer and records the fact,
//!    visible at the peer's `GET /federation/inbox`.
//!
//! The crossing's security teeth (cert pin, grant source-key pin, signature) are
//! the verified ones; only the transport — TLS through the blind broker — is the
//! integration under test. A forged crossing (signed under the wrong key) is
//! denied even though it crosses the broker fine.

use std::collections::BTreeSet;
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
use gaugewright_app::{resource_store, LockUnpoisoned, SharedWorkbench, Workbench};
use gaugewright_core::abac::ResourceAttributes;
use gaugewright_core::boundary::Authority;
use gaugewright_core::ids::AuthorityId;
use gaugewright_core::resource::{ContentLocator, Resource, ResourceId, ResourceRecord};
use gaugewright_store::Store;
use gaugewright_workspace::Instance;

/// Build a mounted control plane for `authority`, federating through `broker`, with
/// its key/TLS material persisted under a fresh temp root.
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

/// A federated control plane with a real work target for lifecycle tests that
/// need to create and address a concrete chat resource.
fn workspace_instance(
    authority: &str,
    broker: &str,
) -> (Router, tempfile::TempDir, SharedWorkbench) {
    let root = tempfile::tempdir().unwrap();
    let target = Instance::init(root.path().join("repo"), root.path().join("wt")).unwrap();
    let fed =
        Federation::open(AuthorityId::new(authority), root.path(), broker.to_string()).unwrap();
    let wb = Workbench::with_target("inst-test", target, Store::open_in_memory().unwrap())
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

/// Start a hermetic WSS relay on an ephemeral port, or use the explicit live
/// endpoint. The guard keeps the local listener alive for the test.
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

/// Pair two instances both ways (each accepts the other's ticket). Returns nothing
/// — afterwards both hold the other's pinned grant + cert and a parked receiver.
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

#[tokio::test]
async fn two_authorities_pair_and_a_handle_crosses_and_admits_on_the_peer() {
    let (broker, _relay) = start_broker().await;
    let (alice, _ra, _alice_wb) = instance("alice", &broker);
    let (bob, _rb, _bob_wb) = instance("bob", &broker);

    pair(&alice, &bob).await;

    // Both see the pairing.
    let (_, peers_a) = get(&alice, "/federation/peers").await;
    let (_, peers_b) = get(&bob, "/federation/peers").await;
    assert_eq!(peers_a["peers"][0]["authority"], "bob");
    assert_eq!(peers_b["peers"][0]["authority"], "alice");

    // Give bob's receiver a moment to park on the broker for alice→bob.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // alice crosses a handle to bob.
    let (status, body) = post(
        &alice,
        "/federation/cross",
        json!({ "peer": "bob", "handle": "ctx-method-OBSERVATION-HANDLE", "correlation": "xc-1" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["admitted"], true,
        "the peer admitted the signed crossing"
    );

    // The fact lives in bob's inbox (admitted by bob), carrying only the handle.
    let (_, inbox) = get(&bob, "/federation/inbox").await;
    let facts = inbox["federated"].as_array().expect("federated array");
    assert_eq!(facts.len(), 1, "exactly one crossing admitted on the peer");
    assert_eq!(facts[0]["source"], "alice");
    assert_eq!(facts[0]["target"], "bob");
    assert_eq!(facts[0]["payload_handle"], "ctx-method-OBSERVATION-HANDLE");

    // alice, the source, recorded no inbound fact — only the target admits (INV-13).
    let (_, alice_inbox) = get(&alice, "/federation/inbox").await;
    assert_eq!(alice_inbox["federated"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn owner_places_a_remote_run_and_admits_the_peers_observations() {
    // The peer runs a real WhippleScript turn unless told to mock (FED-4); this
    // hermetic test uses the mock-LLM path (no model/OAuth), like the e2e suite.
    std::env::set_var("GAUGEWRIGHT_FAKE_AGENT", "1");
    let (broker, _relay) = start_broker().await;
    let (alice, _ra, _alice_wb) = instance("alice", &broker);
    let (bob, _rb, _bob_wb) = instance("bob", &broker);

    pair(&alice, &bob).await;
    // Let bob's runtime receiver park on the broker for alice→bob.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // alice places a run on bob; bob executes a turn and returns observations.
    let (status, body) = post(
        &alice,
        "/federation/remote-run",
        json!({ "peer": "bob", "run_scope": "run-remote-1", "prompt": "go" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["assistant_text"], "remote ran: go");
    let admitted = body["observations_admitted"].as_u64().unwrap_or(0);
    assert!(
        admitted >= 1,
        "the owner admitted the peer's federated observations (INV-4), got {admitted}"
    );

    // The run scope on the OWNER is running with the federated observations as
    // evidence — admitted by the owner, produced on the peer.
    let (_, run) = get(&alice, "/scopes/run-remote-1/run").await;
    assert_eq!(run["phase"], "Running");
}

#[tokio::test]
async fn shared_output_releases_only_after_the_remote_stakeholder_consents() {
    let (broker, _relay) = start_broker().await;
    let (alice, _ra, alice_wb) = workspace_instance("alice", &broker);
    let (bob, _rb, _bob_wb) = instance("bob", &broker);

    pair(&alice, &bob).await;
    // Let alice's consent receiver park on the broker for bob→alice.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let (created, response) = post(&alice, "/chats", json!({ "id": "shared" })).await;
    assert_eq!(
        created,
        StatusCode::CREATED,
        "create chat response: {response}"
    );

    // Alice hosts a concrete output owned by {alice, bob}; the product proposal
    // route derives both required consenters from that authoritative resource.
    {
        let mut guard = alice_wb.lock_unpoisoned();
        let id = ResourceId::new("out-1");
        let record = ResourceRecord {
            resource: Resource::derived(id.clone(), Authority::from("alice"), BTreeSet::new()),
            stakeholders: BTreeSet::from([Authority::from("alice"), Authority::from("bob")]),
            locator: ContentLocator::Workspace {
                path: "shared.txt".into(),
                commit: "fixture".into(),
            },
            tombstoned: false,
            attributes: ResourceAttributes::default(),
        };
        resource_store::put(guard.store_mut(), "shared", &record).unwrap();
    }
    let scope = resource_store::review_scope("shared", &ResourceId::new("out-1"));
    let (st, _) = post(&alice, "/chats/shared/resources/out-1/review", json!({})).await;
    assert_eq!(st, StatusCode::OK);

    // alice consents locally.
    let (_, after_alice) = post(
        &alice,
        "/chats/shared/resources/out-1/review/command",
        json!({ "action": "consent" }),
    )
    .await;
    assert_eq!(
        after_alice["phase"], "Proposed",
        "still missing bob's consent"
    );

    // alice cannot release alone — conjunctive consent blocks it (INV-16).
    let (blocked, _) = post(
        &alice,
        "/chats/shared/resources/out-1/review/command",
        json!({ "action": "release" }),
    )
    .await;
    assert_eq!(
        blocked,
        StatusCode::CONFLICT,
        "neither authority can release shared content alone"
    );

    // bob, the remote stakeholder, consents across the network.
    let (cs, consent_resp) = post(
        &bob,
        "/federation/consent",
        json!({ "owner": "alice", "review_scope": scope }),
    )
    .await;
    assert_eq!(cs, StatusCode::OK);
    assert_eq!(
        consent_resp["ok"], true,
        "owner authenticated the remote consent"
    );
    assert_eq!(
        consent_resp["review"]["phase"], "Cleared",
        "both have now consented"
    );

    // Now alice can release.
    let (released, rel) = post(
        &alice,
        "/chats/shared/resources/out-1/review/command",
        json!({ "action": "release" }),
    )
    .await;
    assert_eq!(released, StatusCode::OK);
    assert_eq!(rel["phase"], "Released");
}

#[tokio::test]
async fn a_revoked_device_subkey_can_no_longer_cross() {
    let (broker, _relay) = start_broker().await;
    let (alice, _ra, _alice_wb) = instance("alice", &broker);
    let (bob, _rb, _bob_wb) = instance("bob", &broker);

    pair(&alice, &bob).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Initially alice's device subkey can cross to bob.
    let (s1, b1) = post(
        &alice,
        "/federation/cross",
        json!({ "peer": "bob", "handle": "h1", "correlation": "xc-pre" }),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(
        b1["admitted"], true,
        "the device subkey crosses before revocation"
    );

    // alice revokes her current device subkey and pushes it to bob (Model A).
    let (sr, br) = post(
        &alice,
        "/federation/revoke-device",
        json!({ "peer": "bob" }),
    )
    .await;
    assert_eq!(sr, StatusCode::OK);
    assert_eq!(
        br["accepted"], true,
        "bob accepted the root-signed revocation"
    );
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Now the same (revoked) subkey is denied — before its delegation expires.
    let (s2, b2) = post(
        &alice,
        "/federation/cross",
        json!({ "peer": "bob", "handle": "h2", "correlation": "xc-post" }),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(
        b2["admitted"], false,
        "a crossing presenting the revoked device subkey is denied"
    );
}

#[tokio::test]
async fn a_recovery_code_restores_the_root_identity() {
    let (broker, _relay) = start_broker().await;
    let (alice, _ra, _alice_wb) = instance("alice", &broker);
    let (bob, _rb, _bob_wb) = instance("bob", &broker);

    // bob's recovery code + bob's original governance pubkey.
    let (_, bob_code) = post(&bob, "/federation/recovery-code", json!({})).await;
    let code = bob_code["recovery_code"].as_str().unwrap().to_string();
    let (_, bob_ticket) = post(&bob, "/federation/pairing-ticket", json!({})).await;
    let bob_pubkey = bob_ticket["governance_pubkey"]
        .as_str()
        .unwrap()
        .to_string();

    // alice's original key differs from bob's.
    let (_, alice_ticket) = post(&alice, "/federation/pairing-ticket", json!({})).await;
    assert_ne!(alice_ticket["governance_pubkey"], bob_pubkey);

    // Restore bob's recovery code into the alice instance: re-enrolling the seed
    // recovers the SAME identity it encoded (here, bob's) — proving restore changes
    // the stored root to the recovered key.
    let (sr, rr) = post(&alice, "/federation/restore", json!({ "code": code })).await;
    assert_eq!(sr, StatusCode::OK);
    assert_eq!(
        rr["governance_pubkey"], bob_pubkey,
        "restore recovered the exported key"
    );

    // The instance's governance key is now the recovered one (a fresh ticket shows it).
    let (_, alice_ticket2) = post(&alice, "/federation/pairing-ticket", json!({})).await;
    assert_eq!(alice_ticket2["governance_pubkey"], bob_pubkey);

    // A garbled code is refused (the checksum/format guard, fail-closed).
    let (bad, _) = post(
        &alice,
        "/federation/restore",
        json!({ "code": "NOPE-NOPE" }),
    )
    .await;
    assert_eq!(bad, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn crossing_to_an_unpaired_peer_is_refused() {
    let (broker, _relay) = start_broker().await;
    let (alice, _ra, _alice_wb) = instance("alice", &broker);
    // No pairing performed: alice has no grant/cert for "bob".
    let (status, _) = post(
        &alice,
        "/federation/cross",
        json!({ "peer": "bob", "handle": "h", "correlation": "xc-2" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a crossing to an unpaired peer is refused before any transport"
    );
}
