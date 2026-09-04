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
async fn default_model_follows_the_linked_credentials() {
    let (_dir, app) = workbench();

    // Nothing linked: no default to name. The picker asks for a model rather
    // than reporting the Codex fallback no credential could run.
    let (s, body) = send(&app, "GET", "/account/default-model", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["provider"], Value::Null);
    assert_eq!(body["model"], Value::Null);

    // One OpenAI-compatible endpoint linked: it is the default provider, but an
    // endpoint has no model until the operator declares one.
    let (s, _) = send(
        &app,
        "POST",
        "/account/credentials",
        Some(r#"{"provider":"openai-generic","token":"sk-local","base_url":"http://127.0.0.1:11434/v1"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_s, body) = send(&app, "GET", "/account/default-model", None).await;
    assert_eq!(body["provider"], "openai-generic");
    assert_eq!(body["model"], Value::Null);

    // The first declared model is what a no-pin turn runs, so it is what the
    // picker names.
    let (s, _) = send(
        &app,
        "PUT",
        "/account/settings/model_picker.endpoint_models",
        Some(r#"{"value":"{\"openai-generic\":[\"llama-3.3-70b\",\"qwen-3\"]}"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_s, body) = send(&app, "GET", "/account/default-model", None).await;
    assert_eq!(body["provider"], "openai-generic");
    assert_eq!(body["model"], "llama-3.3-70b");

    // A second keyed provider makes the choice real, so nothing is assumed.
    let (s, _) = send(
        &app,
        "POST",
        "/account/credentials",
        Some(r#"{"provider":"anthropic","token":"sk-ant-test"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_s, body) = send(&app, "GET", "/account/default-model", None).await;
    assert_eq!(body["provider"], Value::Null);
    assert_eq!(body["model"], Value::Null);
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

/// Seal a box the way the claim route does.
///
/// Through the workbench, not over HTTP, because **there is no HTTP route that
/// accepts these bytes** — that is the property. Claiming happens inside this
/// process (`crate::tokenwright`), so the capabilities are never something a
/// caller hands in.
fn seal_a_box(wb: &Arc<Mutex<Workbench>>, fingerprint: &str) -> String {
    let mut wb = wb.lock().unwrap();
    let scope = wb.account_scope_for(None);
    let bare = fingerprint
        .trim_start_matches("sha256:")
        .to_ascii_lowercase();
    wb.upsert_account_box_in(
        &scope,
        gaugedesk_app::account::PairedBoxFacts {
            fingerprint: bare.clone(),
            relay_endpoint: "ws://127.0.0.1:1".to_owned(),
            paired_at: "2026-09-01T20:00:00Z".to_owned(),
            home_id: "home_a".to_owned(),
            key_id: "key_c30f".to_owned(),
        },
        &gaugedesk_app::account::BoxMaterial {
            route: ROUTE.to_owned(),
            key: BOX_KEY.to_owned(),
        },
    )
    .expect("seal");
    bare
}

#[tokio::test]
async fn a_paired_box_is_listed_without_either_capability() {
    let (_dir, app, shared) = workbench_with_handle();
    seal_a_box(&shared, PIN);

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
    assert_eq!(body["boxes"][0]["relay_endpoint"], "ws://127.0.0.1:1");
    assert_eq!(body["boxes"][0]["key_id"], "key_c30f");
}

#[tokio::test]
async fn no_route_accepts_a_box_capability() {
    // The browser used to claim a box and hand the results up. It cannot now:
    // there is nowhere to hand them to, which is stronger than a route that
    // exists and is documented as unused.
    let (_dir, app, _shared) = workbench_with_handle();
    let body = format!(
        r#"{{"fingerprint":"{PIN}","route":"{ROUTE}","key":"{BOX_KEY}",
            "relay_endpoint":"wss://relay.example"}}"#
    );
    let (status, _) = send(&app, "POST", "/account/boxes", Some(&body)).await;
    assert_eq!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "POST /account/boxes must not exist",
    );
}

#[tokio::test]
async fn the_runtime_can_open_what_the_browser_cannot() {
    // The asymmetry is the whole point of sealing: the material exists and is
    // usable, just not over HTTP.
    let (_dir, _app, shared) = workbench_with_handle();
    let bare = seal_a_box(&shared, PIN);

    let wb = shared.lock().unwrap();
    let scope = wb.account_scope_for(None);
    let material = wb
        .resolve_account_box_in(&scope, &bare)
        .expect("the runtime must be able to unseal it");
    assert_eq!(material.route, ROUTE);
    assert_eq!(material.key, BOX_KEY);
}

#[tokio::test]
async fn re_pairing_replaces_the_material_rather_than_keeping_both() {
    // A second claim mints a new key *and* moves the box to a new route, so the
    // previous material names an address nothing is listening on.
    let (_dir, _app, shared) = workbench_with_handle();
    let bare = seal_a_box(&shared, PIN);
    {
        let mut wb = shared.lock().unwrap();
        let scope = wb.account_scope_for(None);
        wb.upsert_account_box_in(
            &scope,
            gaugedesk_app::account::PairedBoxFacts {
                fingerprint: bare.clone(),
                relay_endpoint: "ws://127.0.0.1:1".to_owned(),
                paired_at: String::new(),
                home_id: "home_a".to_owned(),
                key_id: "key_new".to_owned(),
            },
            &gaugedesk_app::account::BoxMaterial {
                route: "b".repeat(43),
                key: "tw_second_key".to_owned(),
            },
        )
        .expect("re-seal");
    }

    let wb = shared.lock().unwrap();
    let scope = wb.account_scope_for(None);
    let material = wb.resolve_account_box_in(&scope, &bare).expect("material");
    assert_eq!(material.key, "tw_second_key");
    assert_ne!(material.route, ROUTE, "the dead route must not survive");
    assert_eq!(wb.account_boxes_in(&scope).expect("boxes").len(), 1);
}

#[tokio::test]
async fn forgetting_a_box_discards_the_material_too() {
    // Forgetting must not leave openable bytes behind: a tombstone that kept
    // the seal would be a credential the person believes they deleted.
    let (_dir, app, shared) = workbench_with_handle();
    let bare = seal_a_box(&shared, PIN);

    let (s, body) = send(&app, "DELETE", &format!("/account/boxes/{bare}"), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["forgotten"], true);

    let (_s, body) = send(&app, "GET", "/account/boxes", None).await;
    assert_eq!(body["boxes"].as_array().unwrap().len(), 0);

    let wb = shared.lock().unwrap();
    let scope = wb.account_scope_for(None);
    assert!(
        wb.resolve_account_box_in(&scope, &bare).is_none(),
        "a forgotten box must not still unseal"
    );
}

#[tokio::test]
async fn a_claim_refuses_a_pairing_string_it_cannot_read() {
    // Before anything dials. "Could not reach the box" would send someone to
    // look at their network when they copied one line short.
    let (_dir, app, _shared) = workbench_with_handle();
    for pasted in ["", "ABCD-EFGH-JKMN-PQRS-TVWX", "tw1_short"] {
        let body = serde_json::json!({ "pairing_string": pasted }).to_string();
        let (status, _) = send(&app, "POST", "/account/boxes/claim", Some(&body)).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "must refuse {pasted:?} without dialling",
        );
    }
}

#[tokio::test]
async fn a_box_belongs_to_one_person_and_rides_their_erase() {
    // Two properties in one, because they are the same fact.
    //
    // INV-1: a person reads only their own boxes. And the mechanism that makes
    // that true — the record living in *that person's* account scope — is the
    // same mechanism that makes account erasure cover it, because the erase
    // destroys the scope's content key rather than a list of record kinds.
    let (_dir, _app, shared) = workbench_with_handle();
    let bare = seal_a_box(&shared, PIN);

    let wb = shared.lock().unwrap();
    let mine = wb.account_scope_for(None);
    assert_eq!(wb.account_boxes_in(&mine).expect("mine").len(), 1);
    assert!(wb.resolve_account_box_in(&mine, &bare).is_some());

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
        wb.resolve_account_box_in(&someone_else, &bare).is_none(),
        "and must not be able to unseal it"
    );
}

#[tokio::test]
async fn the_home_carries_only_the_declared_surface() {
    // A courier that carried whatever it was handed would be a way to reach a
    // box's model surface — inference under the Home's key, unaccounted — and
    // its pairing route, using a credential the caller never had.
    let (_dir, app, shared) = workbench_with_handle();
    let bare = seal_a_box(&shared, PIN);

    for (method, path) in [
        ("POST", "v1/chat/completions"),
        ("GET", "v1/models"),
        ("POST", "pair/claim"),
        // Refused by the router rather than the allowlist: the carried surface
        // is GET and POST only, so a DELETE never reaches the handler. Two
        // refusals for one rule is the point, not a redundancy.
        ("DELETE", "environments/tokenwright/documents/x"),
        ("GET", "environments/tokenwright/documents/a/b"),
    ] {
        let (status, _) = send(
            &app,
            method,
            &format!("/account/boxes/{bare}/surface/{path}"),
            if method == "GET" { None } else { Some("{}") },
        )
        .await;
        assert!(
            status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path} must not be carried, got {status}",
        );
    }
}

#[tokio::test]
async fn carrying_to_a_box_that_is_not_paired_is_not_a_bad_gateway() {
    // "No such box" and "the box did not answer" send a person to different
    // places, so they must not share a status.
    let (_dir, app, _shared) = workbench_with_handle();
    let (status, _) = send(
        &app,
        "GET",
        &format!(
            "/account/boxes/{}/surface/environments/tokenwright/audit",
            PIN.trim_start_matches("sha256:")
        ),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_box_that_cannot_be_reached_reports_the_box_not_this_home() {
    // The Home is fine; the box is not there. A 500 would say the fault is
    // here and send someone to read this Home's logs.
    let (_dir, app, shared) = workbench_with_handle();
    let bare = seal_a_box(&shared, PIN);
    let (status, _) = send(
        &app,
        "GET",
        &format!("/account/boxes/{bare}/surface/environments/tokenwright/audit"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}
