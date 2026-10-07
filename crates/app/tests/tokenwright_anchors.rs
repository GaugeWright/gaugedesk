//! The Home retaining a TokenWright box's audit anchors, end to end (WS-228).
//!
//! The box's design rests on one property: a compromised box can rewrite its
//! trail and re-sign a consistent head, but it cannot retract a head the Home
//! already recorded. This holds the Home's half of that across the things that
//! would break it — a restart between the report and the walk, a box that
//! re-signs every head of a rewritten history with its own key, and a walk
//! carried over the real relay with the certificate pinned.
//!
//! `tokenwright-audit-anchors.json` was produced by TokenWright's own
//! `Trail` and `sign_head`, not by this implementation, so agreement here is
//! agreement with the box: the canonical bytes, the entry hash, the genesis and
//! the signed payload. One honest entry carries a non-ASCII actor with a quote
//! and a newline, which is where two JSON serialisers first disagree.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use gaugedesk_relay_transport::test_relay::TestRelay;
use gaugedesk_relay_transport::{serve_home_forever, HomeRelayConfig, TlsIdentity};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use gaugedesk_app::account::{BoxMaterial, PairedBoxFacts, ACCOUNT_SCOPE};
use gaugedesk_app::tokenwright::route_bytes;
use gaugedesk_app::tokenwright_anchors::{
    audit_box_in, check_trail, AnchorError, AnchorRecord, ACK_KIND,
};
use gaugedesk_app::Workbench;
use gaugedesk_store::Store;
use gaugedesk_workspace::Instance;

const ROUTE: &str = "F8E0l3whZo41YL6B8yzSJAQdF8E0l3whZo41YL6B8yw";
const KEY: &str = "tw_secret";

fn vectors() -> Value {
    serde_json::from_str(include_str!("tokenwright-audit-anchors.json")).expect("vectors parse")
}

fn audit_key(vectors: &Value) -> [u8; 32] {
    hex::decode(vectors["audit_key"].as_str().expect("key"))
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

fn entries(vectors: &Value, which: &str) -> Vec<Value> {
    vectors[which]["entries"]
        .as_array()
        .expect("entries")
        .clone()
}

fn heads(vectors: &Value, which: &str) -> Vec<Vec<u8>> {
    vectors[which]["heads"]
        .as_array()
        .expect("heads")
        .iter()
        .map(|head| serde_json::to_vec(head).expect("encode"))
        .collect()
}

/// A Home on disk: the store and the key directory both under `dir`, so a
/// second call over the same `dir` is this Home after a restart.
fn home_at(dir: &std::path::Path, first_boot: bool) -> Workbench {
    let repo = dir.join("repo");
    let worktrees = dir.join("wt");
    let instance = if first_boot {
        Instance::init(&repo, &worktrees).expect("instance")
    } else {
        Instance::open(&repo, &worktrees)
    };
    let store = Store::open(dir.join("home.db").to_str().expect("path")).expect("store");
    Workbench::with_target("inst-test", instance, store)
}

fn pair(wb: &mut Workbench, fingerprint: &str, endpoint: &str) {
    wb.upsert_account_box_in(
        ACCOUNT_SCOPE,
        PairedBoxFacts {
            fingerprint: fingerprint.to_owned(),
            relay_endpoint: endpoint.to_owned(),
            paired_at: "2026-08-30T11:59:00Z".to_owned(),
            home_id: "home_a".to_owned(),
            key_id: "key_1".to_owned(),
        },
        &BoxMaterial {
            route: ROUTE.to_owned(),
            key: KEY.to_owned(),
        },
    )
    .expect("pair");
}

/// A box serving its management surface's two routes this walk needs — a
/// session, and the trail in pages of two so the walk has to follow
/// `next_from` — from whatever trail it currently holds.
async fn park_a_box(endpoint: &str, identity: &TlsIdentity, trail: Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("stub");
    let address = listener.local_addr().expect("stub addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let trail = Arc::clone(&trail);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16384];
                let read = stream.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                let start = request.lines().next().unwrap_or_default().to_owned();
                let authorized = request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case(&format!("authorization: Bearer {KEY}")));
                let (status, body) = if !authorized {
                    (401, serde_json::json!({"error": "bad_key"}))
                } else if start.starts_with("POST /environments/tokenwright/sessions ") {
                    (200, serde_json::json!({"session": {"id": "sess_key_1"}}))
                } else if start.starts_with("GET /environments/tokenwright/audit?") {
                    let query = start
                        .split_whitespace()
                        .nth(1)
                        .and_then(|target| target.split_once('?'))
                        .map(|(_, query)| query.to_owned())
                        .unwrap_or_default();
                    let params: BTreeMap<&str, &str> =
                        query.split('&').filter_map(|p| p.split_once('=')).collect();
                    if params.get("session") != Some(&"sess_key_1") {
                        (401, serde_json::json!({"error": "no_session"}))
                    } else {
                        let from: usize =
                            params.get("from").and_then(|f| f.parse().ok()).unwrap_or(1);
                        let trail = trail.lock().unwrap().clone();
                        let page: Vec<Value> =
                            trail.iter().skip(from - 1).take(2).cloned().collect();
                        let next = (from - 1 + page.len() < trail.len()).then(|| from + page.len());
                        (200, serde_json::json!({"entries": page, "next_from": next}))
                    }
                } else {
                    (404, serde_json::json!({"error": "not_found"}))
                };
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body,
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });

    let token = route_bytes(ROUTE).expect("route");
    let derived =
        gaugedesk_relay_transport::one_shot_websocket_route(endpoint, token).expect("route");
    let config = HomeRelayConfig {
        endpoint: endpoint.to_owned(),
        handle: derived.handle.clone(),
        proof: derived.proof.to_base64url(),
        previous_proof: None,
        route_epoch: derived.epoch,
    };
    let route = config.relay_route(identity).expect("route");
    let parked = identity.clone();
    tokio::spawn(async move {
        let _ = serve_home_forever(route, address, parked).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
}

#[tokio::test]
async fn a_full_rewrite_is_detected_after_the_home_restarts() {
    let vectors = vectors();
    let key = audit_key(&vectors);
    let relay = TestRelay::bind().await.expect("relay");
    let identity = TlsIdentity::generate().expect("identity");
    let fingerprint = hex::encode(identity.fingerprint());
    let presented = format!("sha256:{fingerprint}");
    let dir = tempfile::tempdir().expect("dir");

    // --- before the restart: the box reports every head, and each is acked.
    {
        let mut wb = home_at(dir.path(), true);
        pair(&mut wb, &fingerprint, relay.endpoint());
        for (index, head) in heads(&vectors, "honest").iter().enumerate() {
            let ack = wb
                .receive_tokenwright_head_in(ACCOUNT_SCOPE, &presented, &key, head)
                .expect("an honest head is retained");
            assert_eq!(ack.kind, ACK_KIND);
            assert_eq!(ack.box_fingerprint, presented);
            assert_eq!(ack.count, index as u64 + 1);
            assert_eq!(ack.retained, index + 1, "appended, never replaced");
        }
        // The same report twice is one anchor, acknowledged again.
        let again = wb
            .receive_tokenwright_head_in(
                ACCOUNT_SCOPE,
                &presented,
                &key,
                &heads(&vectors, "honest")[3],
            )
            .expect("a repeat is acknowledged");
        assert_eq!(again.retained, 4);
    }

    // --- the Home restarts. Nothing in memory survives; the store does.
    let shared = Arc::new(Mutex::new(home_at(dir.path(), false)));
    let retained = shared
        .lock()
        .unwrap()
        .tokenwright_anchors_in(ACCOUNT_SCOPE, &presented)
        .expect("anchors");
    assert_eq!(
        retained.iter().map(|a| a.count).collect::<Vec<_>>(),
        vec![1, 2, 3, 4],
        "every anchor survives the restart, in order"
    );

    // --- an honest box: its trail, walked over the pinned relay, holds.
    let served = Arc::new(Mutex::new(entries(&vectors, "honest")));
    park_a_box(relay.endpoint(), &identity, Arc::clone(&served)).await;
    let honest = audit_box_in(&shared, ACCOUNT_SCOPE, &presented)
        .await
        .expect("walk the honest trail");
    assert!(honest.holds(), "{honest:?}");
    assert_eq!(honest.entries, 4);
    assert_eq!(honest.anchored_count, 4);

    // --- the box rewrites its whole history and re-signs every head with its
    // own key. The new heads verify, and the Home keeps them too — beside the
    // old ones, which is the point.
    *served.lock().unwrap() = entries(&vectors, "rewritten");
    {
        let mut wb = shared.lock().unwrap();
        for head in heads(&vectors, "rewritten") {
            wb.receive_tokenwright_head_in(ACCOUNT_SCOPE, &presented, &key, &head)
                .expect("a validly signed head is retained");
        }
    }
    let rewritten = audit_box_in(&shared, ACCOUNT_SCOPE, &presented)
        .await
        .expect("walk the rewritten trail");
    assert!(
        rewritten.chain_verified,
        "a rewrite by the key holder is internally consistent — chaining alone cannot see it"
    );
    assert!(!rewritten.holds(), "retention must");
    let contradicted: Vec<u64> = rewritten.contradicted.iter().map(|a| a.count).collect();
    assert_eq!(
        contradicted,
        vec![1, 2, 3, 4],
        "every honest anchor contradicts the rewritten trail"
    );
}

#[test]
fn a_head_is_retained_only_for_a_paired_box_under_its_pinned_key() {
    let vectors = vectors();
    let key = audit_key(&vectors);
    let dir = tempfile::tempdir().expect("dir");
    let mut wb = home_at(dir.path(), true);
    let fingerprint = "ab".repeat(32);
    let presented = format!("sha256:{fingerprint}");
    let head = &heads(&vectors, "honest")[0];

    // Nobody paired this certificate.
    assert!(matches!(
        wb.receive_tokenwright_head_in(ACCOUNT_SCOPE, &presented, &key, head),
        Err(AnchorError::Unpaired)
    ));

    pair(&mut wb, &fingerprint, "wss://relay.example");

    // A signature that does not verify is refused and not retained.
    let mut forged: Value = serde_json::from_slice(head).unwrap();
    forged["count"] = Value::from(2);
    assert!(matches!(
        wb.receive_tokenwright_head_in(
            ACCOUNT_SCOPE,
            &presented,
            &key,
            &serde_json::to_vec(&forged).unwrap()
        ),
        Err(AnchorError::BadSignature)
    ));
    assert!(wb
        .tokenwright_anchors_in(ACCOUNT_SCOPE, &presented)
        .unwrap()
        .is_empty());

    // The first verified head pins the key; a different key afterwards is the
    // alarm, even with a signature that verifies under it.
    wb.receive_tokenwright_head_in(ACCOUNT_SCOPE, &presented, &key, head)
        .expect("retained");
    let other = [9u8; 32];
    assert!(matches!(
        wb.receive_tokenwright_head_in(ACCOUNT_SCOPE, &presented, &other, head),
        Err(AnchorError::KeyChanged)
    ));
    assert_eq!(
        wb.tokenwright_anchors_in(ACCOUNT_SCOPE, &presented)
            .unwrap()
            .len(),
        1
    );
}

fn anchors_for(vectors: &Value) -> Vec<AnchorRecord> {
    vectors["honest"]["heads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|head| AnchorRecord {
            id: String::new(),
            op: Default::default(),
            box_id: String::new(),
            audit_key: String::new(),
            count: head["count"].as_u64().unwrap(),
            head: head["head"].as_str().map(str::to_owned),
            at: head["at"].as_str().unwrap().to_owned(),
            signature: head["signature"].as_str().unwrap().to_owned(),
            received_at_ms: 0,
        })
        .collect()
}

#[test]
fn a_truncated_trail_contradicts_the_anchors_past_its_end() {
    let vectors = vectors();
    let mut trail = entries(&vectors, "honest");
    trail.truncate(2);
    let check = check_trail(&trail, &anchors_for(&vectors));
    assert!(check.chain_verified);
    assert_eq!(check.anchored_count, 2);
    assert_eq!(
        check
            .contradicted
            .iter()
            .map(|a| a.count)
            .collect::<Vec<_>>(),
        vec![3, 4]
    );
}

#[test]
fn an_edit_that_keeps_the_old_hashes_breaks_the_chain_and_the_anchors_after_it() {
    // The cheapest forgery: change an entry's content and leave every `hash`
    // field as it was. Reading the hash fields would accept it; recomputing
    // them does not.
    let vectors = vectors();
    let mut trail = entries(&vectors, "honest");
    trail[1]["outcome"] = Value::from("rejected");
    let check = check_trail(&trail, &anchors_for(&vectors));
    assert!(!check.chain_verified);
    assert_eq!(check.broken_at, Some(2));
    assert_eq!(check.anchored_count, 1);
    assert_eq!(
        check
            .contradicted
            .iter()
            .map(|a| a.count)
            .collect::<Vec<_>>(),
        vec![2, 3, 4]
    );
}

#[test]
fn the_boxes_own_hashes_are_reproduced() {
    // Including the entry whose actor is `opérateur "ü"\n`: the escapes JSON
    // requires and the UTF-8 it does not must both match Python's spelling.
    let vectors = vectors();
    for which in ["honest", "rewritten"] {
        let check = check_trail(&entries(&vectors, which), &[]);
        assert!(check.chain_verified, "{which}: {check:?}");
    }
}
