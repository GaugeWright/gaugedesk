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
    let (dir, router, _shared) = workbench_with_handle();
    (dir, router)
}

/// The same fixture, keeping the workbench itself.
///
/// Sealing is an *asymmetry* — the runtime can open what HTTP will not return —
/// and a test that only drives the router can see one half of it.
fn workbench_with_handle() -> (tempfile::TempDir, Router, Arc<Mutex<Workbench>>) {
    let dir = tempfile::tempdir().unwrap();
    let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
    let store = Store::open_in_memory().unwrap();
    let wb = Arc::new(Mutex::new(Workbench::with_target(
        "inst-test",
        instance,
        store,
    )));
    (dir, open_control_plane(Arc::clone(&wb)), wb)
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
async fn oauth_credential_stays_out_of_the_generic_credential_list() {
    let (_dir, app) = workbench();

    // An OAuth-linked provider (openai-codex) is projected by its own status
    // route and unlinked through its own flow. Listing it in the generic
    // key-credential list would show the same credential twice in every
    // surface that also renders the OAuth row.
    let (s, _) = send(
        &app,
        "POST",
        "/account/credentials",
        Some(r#"{"provider":"openai-codex","token":"oauth-bundle"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send(
        &app,
        "POST",
        "/account/credentials",
        Some(r#"{"provider":"anthropic","token":"sk-ant-test"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (s, body) = send(&app, "GET", "/account/credentials", None).await;
    assert_eq!(s, StatusCode::OK);
    let providers: Vec<&str> = body["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["provider"].as_str())
        .collect();
    assert_eq!(providers, ["anthropic"], "got {body}");
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

/// Unregistering the selected Home must not leave the selection naming it.
///
/// `PUT /account/homes/selected` refuses a Home that is not registered, so a
/// selection pointing at nothing is a state the account's own write path calls
/// invalid — but the unregister route could reach it, and every reader that
/// resolves the selected Home then failed on an account that still looked
/// registered. Nothing ordinary repaired it either: re-selecting needs a
/// registration, so the account was stuck until someone re-registered by hand.
#[tokio::test]
async fn unregistering_the_selected_home_clears_the_selection() {
    let (_dir, app) = workbench();
    let register = |id: &str| {
        format!(r#"{{"id":"{id}","kind":"registered","endpoint":"https://home.example.test"}}"#)
    };
    for id in ["home:one", "home:two"] {
        let (status, _) = send(&app, "POST", "/account/homes", Some(&register(id))).await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let (status, _) = send(
        &app,
        "PUT",
        "/account/homes/selected",
        Some(r#"{"home_id":"home:one"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Unregistering some *other* Home leaves the selection exactly alone.
    let (status, _) = send(&app, "DELETE", "/account/homes/home:two", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, body) = send(&app, "GET", "/account/homes", None).await;
    assert_eq!(body["selected_home"], "home:one");

    // Unregistering the selected one clears it rather than dangling.
    let (status, _) = send(&app, "DELETE", "/account/homes/home:one", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, body) = send(&app, "GET", "/account/homes", None).await;
    assert_eq!(body["homes"].as_array().unwrap().len(), 0);
    assert!(
        body["selected_home"].is_null(),
        "the selection outlived the Home it named: {body}",
    );
}

// --- paired TokenWright boxes ------------------------------------------------

const PIN: &str = "sha256:019f0246c6d3c7ee43c26869ba1a4c5821d115e5a6d7d0570da60bf4f544b75d";
const ROUTE: &str = "F8E0l3whZo41YL6B8yzSJAQdF8E0l3whZo41YL6B8yw";
const BOX_KEY: &str = "tw_box_key_do_not_leak";

fn pair_body(fingerprint: &str) -> String {
    format!(
        r#"{{"fingerprint":"{fingerprint}","route":"{ROUTE}","key":"{BOX_KEY}",
            "relay_endpoint":"wss://relay.example","paired_at":"2026-09-01T20:00:00Z",
            "home_id":"home_a","key_id":"key_c30f"}}"#
    )
}

#[tokio::test]
async fn a_paired_box_is_sealed_and_neither_capability_comes_back() {
    let (_dir, app) = workbench();

    let (s, body) = send(&app, "POST", "/account/boxes", Some(&pair_body(PIN))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["sealed"], true);

    // The list carries what is public — the endpoint and the pin — and neither
    // capability. A person's own browser is exactly where these must not be.
    let (s, body) = send(&app, "GET", "/account/boxes", None).await;
    assert_eq!(s, StatusCode::OK);
    let raw = body.to_string();
    assert!(!raw.contains(ROUTE), "the route must never be returned");
    assert!(!raw.contains(BOX_KEY), "the key must never be returned");
    assert!(!raw.contains("\"route\""), "no route field at all");
    assert!(!raw.contains("\"key\""), "no key field at all");
    assert_eq!(body["boxes"][0]["fingerprint"], PIN);
    assert_eq!(body["boxes"][0]["relay_endpoint"], "wss://relay.example");
    assert_eq!(body["boxes"][0]["key_id"], "key_c30f");
}

#[tokio::test]
async fn the_runtime_can_open_what_the_browser_cannot() {
    // The asymmetry is the whole point of sealing: the material exists and is
    // usable, just not over HTTP.
    let (_dir, app, shared) = workbench_with_handle();
    let (s, _) = send(&app, "POST", "/account/boxes", Some(&pair_body(PIN))).await;
    assert_eq!(s, StatusCode::OK);

    let wb = shared.lock().unwrap();
    let scope = wb.account_scope_for(None);
    let material = wb
        .resolve_account_box_in(&scope, PIN.trim_start_matches("sha256:"))
        .expect("the runtime must be able to unseal it");
    assert_eq!(material.route, ROUTE);
    assert_eq!(material.key, BOX_KEY);
}

#[tokio::test]
async fn a_box_is_keyed_by_its_certificate_however_the_pin_is_spelled() {
    // The box's documents say `sha256:<hex>`; the wasm tunnel wants bare hex.
    // Keying one box two ways would make a re-pair look like a second box that
    // also happens to shadow the first.
    let (_dir, app) = workbench();
    let bare = PIN.trim_start_matches("sha256:");
    let (s, _) = send(&app, "POST", "/account/boxes", Some(&pair_body(PIN))).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send(&app, "POST", "/account/boxes", Some(&pair_body(bare))).await;
    assert_eq!(s, StatusCode::OK);

    let (_s, body) = send(&app, "GET", "/account/boxes", None).await;
    assert_eq!(
        body["boxes"].as_array().unwrap().len(),
        1,
        "one box, however its pin was spelled"
    );
}

#[tokio::test]
async fn re_pairing_replaces_the_material_rather_than_keeping_both() {
    // A second claim mints a new key *and* moves the box to a new route, so the
    // previous material names an address nothing is listening on.
    let (_dir, app, shared) = workbench_with_handle();
    send(&app, "POST", "/account/boxes", Some(&pair_body(PIN))).await;
    let second = format!(
        r#"{{"fingerprint":"{PIN}","route":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "key":"tw_second_key","relay_endpoint":"wss://relay.example"}}"#
    );
    let (s, _) = send(&app, "POST", "/account/boxes", Some(&second)).await;
    assert_eq!(s, StatusCode::OK);

    let wb = shared.lock().unwrap();
    let scope = wb.account_scope_for(None);
    let material = wb
        .resolve_account_box_in(&scope, PIN.trim_start_matches("sha256:"))
        .expect("material");
    assert_eq!(material.key, "tw_second_key");
    assert_ne!(material.route, ROUTE, "the dead route must not survive");
}

#[tokio::test]
async fn half_a_box_is_refused() {
    // A box recorded with one capability lists and cannot be reached, which is
    // worse than one that never listed.
    let (_dir, app) = workbench();
    for body in [
        format!(r#"{{"fingerprint":"{PIN}","route":"","key":"k","relay_endpoint":"wss://r"}}"#),
        format!(
            r#"{{"fingerprint":"{PIN}","route":"{ROUTE}","key":"","relay_endpoint":"wss://r"}}"#
        ),
        format!(r#"{{"fingerprint":"{PIN}","route":"{ROUTE}","key":"k","relay_endpoint":""}}"#),
        format!(
            r#"{{"fingerprint":"not-a-digest","route":"{ROUTE}","key":"k","relay_endpoint":"wss://r"}}"#
        ),
    ] {
        let (s, _) = send(&app, "POST", "/account/boxes", Some(&body)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "refused: {body}");
    }
    let (_s, body) = send(&app, "GET", "/account/boxes", None).await;
    assert_eq!(body["boxes"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn forgetting_a_box_discards_the_material_too() {
    // Forgetting must not leave openable bytes behind: the record is what an
    // erase covers, and a tombstone that kept the seal would be a credential
    // the person believes they deleted.
    let (_dir, app, shared) = workbench_with_handle();
    send(&app, "POST", "/account/boxes", Some(&pair_body(PIN))).await;
    let bare = PIN.trim_start_matches("sha256:");

    let (s, body) = send(&app, "DELETE", &format!("/account/boxes/{bare}"), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["forgotten"], true);

    let (_s, body) = send(&app, "GET", "/account/boxes", None).await;
    assert_eq!(body["boxes"].as_array().unwrap().len(), 0);

    let wb = shared.lock().unwrap();
    let scope = wb.account_scope_for(None);
    assert!(
        wb.resolve_account_box_in(&scope, bare).is_none(),
        "a forgotten box must not still unseal"
    );
}

#[tokio::test]
async fn a_box_belongs_to_one_person_and_rides_their_erase() {
    // Two properties in one, because they are the same fact.
    //
    // INV-1: a person reads only their own boxes. And the mechanism that makes
    // that true — the record living in *that person's* account scope — is the
    // same mechanism that makes account erasure cover it, because the erase
    // destroys the scope's content key rather than a list of record kinds. A
    // box written anywhere else would be both readable by the wrong person and
    // left behind by their erase.
    let (_dir, app, shared) = workbench_with_handle();
    let (s, _) = send(&app, "POST", "/account/boxes", Some(&pair_body(PIN))).await;
    assert_eq!(s, StatusCode::OK);

    let wb = shared.lock().unwrap();
    let mine = wb.account_scope_for(None);
    let bare = PIN.trim_start_matches("sha256:");

    assert_eq!(wb.account_boxes_in(&mine).expect("mine").len(), 1);
    assert!(wb.resolve_account_box_in(&mine, bare).is_some());

    let someone_else = gaugedesk_app::account::account_scope("person_other");
    assert_ne!(
        someone_else, mine,
        "the fixture must not collapse the scopes"
    );
    assert!(
        wb.account_boxes_in(&someone_else)
            .expect("theirs")
            .is_empty(),
        "another person's scope must not see this box"
    );
    assert!(
        wb.resolve_account_box_in(&someone_else, bare).is_none(),
        "and must not be able to unseal it"
    );
}
