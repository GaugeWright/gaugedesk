//! SCIM 2.0 provisioning end to end (M3 B13 / `SCIM-1`/`-2`/`-4`). Issue a SCIM
//! token, provision a user (token-authenticated), reject a bad token, and
//! deprovision via DELETE — asserting the offboarding marks the member
//! deprovisioned and SCIM-managed.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use gaugedesk_app::org::{tenant_scope, MembershipRecord, MembershipStatus, RecordOp, ORG_ID};
use gaugedesk_app::Workbench;
use gaugedesk_ee::org_routes::enterprise_control_plane;
use gaugedesk_store::Store;
use gaugedesk_workspace::Instance;

mod support;
use support::{administration_command, administration_document};

fn workbench() -> (tempfile::TempDir, Router) {
    let dir = tempfile::tempdir().unwrap();
    let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
    let mut store = Store::open_in_memory().unwrap();
    for tenant in ["", "acme", "globex"] {
        store
            .append_record(
                &tenant_scope(tenant),
                "membership",
                &serde_json::to_string(&MembershipRecord {
                    id: "local-user".into(),
                    op: RecordOp::Upsert,
                    org_id: ORG_ID.into(),
                    authority: "local-user".into(),
                    email: "owner@example.test".into(),
                    role: "owner".into(),
                    status: MembershipStatus::Active,
                    managed_by_scim: false,
                    team: None,
                })
                .unwrap(),
            )
            .unwrap();
    }
    let wb = Workbench::with_target("inst-test", instance, store);
    (dir, enterprise_control_plane(Arc::new(Mutex::new(wb))))
}

async fn rotate_token(app: &Router, tenant: Option<&str>) -> (StatusCode, Value) {
    administration_command(
        app,
        tenant,
        None,
        "administration.identity",
        "scim-token.rotate",
        json!({}),
    )
    .await
}

async fn access_document(app: &Router) -> (StatusCode, Value) {
    let (status, response) =
        administration_document(app, None, None, "administration.access").await;
    (status, response["document"]["content"].clone())
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut b = Request::builder().method(method).uri(uri);
    static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
    if method != "GET" && method != "HEAD" && method != "OPTIONS" {
        b = b.header(
            "idempotency-key",
            format!("scim-test-{}", NEXT_KEY.fetch_add(1, Ordering::Relaxed)),
        );
    }
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let req = match body {
        Some(body) => b
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Like `send`, but also stamps the `X-Gaugewright-Tenant` header (DEPLOY-6).
async fn send_t(
    app: &Router,
    method: &str,
    uri: &str,
    tenant: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> (StatusCode, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-gaugewright-tenant", tenant);
    static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
    if method != "GET" && method != "HEAD" && method != "OPTIONS" {
        b = b.header(
            "idempotency-key",
            format!(
                "scim-tenant-test-{}",
                NEXT_KEY.fetch_add(1, Ordering::Relaxed)
            ),
        );
    }
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let req = match body {
        Some(j) => b
            .header("content-type", "application/json")
            .body(Body::from(j.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A bad-token SCIM POST that carries a chosen client IP (`CF-Connecting-IP`, the hosted
/// edge's key) and, optionally, a tenant header — so a test can vary the (spoofable) tenant
/// while holding the (IP) throttle key fixed, and vice versa.
async fn bad_scim_from(app: &Router, cf_ip: &str, tenant: Option<&str>) -> StatusCode {
    static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
    let mut b = Request::builder()
        .method("POST")
        .uri("/scim/v2/Users")
        .header("cf-connecting-ip", cf_ip)
        .header("authorization", "Bearer bad-token")
        .header("content-type", "application/json")
        .header(
            "idempotency-key",
            format!("scim-ip-test-{}", NEXT_KEY.fetch_add(1, Ordering::Relaxed)),
        );
    if let Some(t) = tenant {
        b = b.header("x-gaugewright-tenant", t);
    }
    let req = b.body(Body::from(r#"{"userName":"x@e.com"}"#)).unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn scim_throttles_after_repeated_bad_tokens() {
    // SECAUD-8 (CC6.6/CC6.7): a brute-force loop against the SCIM bearer is locked out
    // after the failure threshold (10/min) — the 11th attempt is 429, not another 401,
    // so guessing is slowed even if the edge rate-limit is absent. Keyed on the client IP
    // (CF-Connecting-IP), so a fixed attacker IP trips the lockout.
    let (_dir, app) = workbench();
    for _ in 0..10 {
        assert_eq!(
            bad_scim_from(&app, "203.0.113.7", None).await,
            StatusCode::UNAUTHORIZED,
            "a bad token is unauthorized"
        );
    }
    assert_eq!(
        bad_scim_from(&app, "203.0.113.7", None).await,
        StatusCode::TOO_MANY_REQUESTS,
        "locked out after the threshold"
    );
}

#[tokio::test]
async fn scim_lockout_keys_on_ip_not_the_spoofable_tenant_header() {
    // The security fix: the throttle key is the client IP, never the client-supplied
    // X-Gaugewright-Tenant header. So (a) rotating/omitting the tenant header on every
    // request does NOT mint a fresh bucket — a fixed IP still locks out — and (b) a
    // different IP is an independent bucket that the first IP's failures never touch.
    let (_dir, app) = workbench();

    // Ten failures from one IP, each carrying a *different* tenant header (the old bypass).
    for i in 0..10 {
        let tenant = format!("rotated-tenant-{i}");
        assert_eq!(
            bad_scim_from(&app, "198.51.100.9", Some(&tenant)).await,
            StatusCode::UNAUTHORIZED,
        );
    }
    // Rotating the tenant one more time does not escape the IP-keyed lockout.
    assert_eq!(
        bad_scim_from(&app, "198.51.100.9", Some("yet-another-tenant")).await,
        StatusCode::TOO_MANY_REQUESTS,
        "rotating the tenant header did not reset the IP's bucket",
    );
    // Omitting the tenant header entirely is still the same locked IP bucket.
    assert_eq!(
        bad_scim_from(&app, "198.51.100.9", None).await,
        StatusCode::TOO_MANY_REQUESTS,
        "omitting the tenant header did not reset the IP's bucket",
    );

    // A different client IP is untouched by the first IP's lockout — no cross-client DoS.
    assert_eq!(
        bad_scim_from(&app, "198.51.100.10", None).await,
        StatusCode::UNAUTHORIZED,
        "a different IP has an independent bucket",
    );
}

#[tokio::test]
async fn scim_tokens_are_tenant_isolated() {
    // DEPLOY-6 tail: a SCIM token issued for one tenant must NOT authenticate for another,
    // and provisioning lands in the issuing tenant's directory.
    let (_dir, app) = workbench();
    let token_a = rotate_token(&app, Some("acme")).await.1["result"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let token_g = rotate_token(&app, Some("globex")).await.1["result"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(token_a, token_g);

    // acme's token provisions under acme.
    let (s, _) = send_t(
        &app,
        "POST",
        "/scim/v2/Users",
        "acme",
        Some(&token_a),
        Some(r#"{"userName":"a@acme.com"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    // acme's token is REJECTED for globex — cross-tenant isolation (the key property).
    let (s, _) = send_t(
        &app,
        "POST",
        "/scim/v2/Users",
        "globex",
        Some(&token_a),
        Some(r#"{"userName":"x@globex.com"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // globex's own token works for globex.
    let (s, _) = send_t(
        &app,
        "POST",
        "/scim/v2/Users",
        "globex",
        Some(&token_g),
        Some(r#"{"userName":"g@globex.com"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
}

#[tokio::test]
async fn scim_provision_and_deprovision() {
    let (_dir, app) = workbench();

    // Administration issues a SCIM token after human review; plaintext returns once.
    let (s, body) = rotate_token(&app, None).await;
    assert_eq!(s, StatusCode::OK);
    let token = body["result"]["token"]
        .as_str()
        .expect("token issued")
        .to_string();
    assert!(!token.is_empty());

    // A bad token cannot provision.
    let (s, _) = send(
        &app,
        "POST",
        "/scim/v2/Users",
        Some(r#"{"userName":"alice@acme.com"}"#),
        Some("not-the-token"),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // No token cannot provision.
    let (s, _) = send(
        &app,
        "POST",
        "/scim/v2/Users",
        Some(r#"{"userName":"alice@acme.com"}"#),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // The real token provisions an active, SCIM-managed member.
    let (s, body) = send(
        &app,
        "POST",
        "/scim/v2/Users",
        Some(r#"{"userName":"alice@acme.com"}"#),
        Some(&token),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(body["userName"], "alice@acme.com");
    assert_eq!(body["active"], true);

    // It shows up in the directory, SCIM-managed and active.
    let (s, body) = access_document(&app).await;
    assert_eq!(s, StatusCode::OK);
    let members = body["members"].as_array().unwrap();
    let alice = members
        .iter()
        .find(|m| m["authority"] == "alice@acme.com")
        .expect("alice present");
    assert_eq!(alice["managed_by_scim"], true);
    assert_eq!(alice["status"], "active");

    // Offboarding via DELETE deprovisions (SCIM-2: access revoked).
    let (s, body) = send(
        &app,
        "DELETE",
        "/scim/v2/Users/alice@acme.com",
        None,
        Some(&token),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["active"], false);

    let (_s, body) = access_document(&app).await;
    let alice = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["authority"] == "alice@acme.com")
        .unwrap()
        .clone();
    assert_eq!(alice["status"], "deprovisioned");
}

#[tokio::test]
async fn scim_groups_map_to_roles() {
    let (_dir, app) = workbench();

    // ADR 0149 §1: SCIM may never confer a privileged role. Mapping a group into
    // `owner`/`admin` is refused at the config boundary (fail-closed).
    let (s, _) = administration_command(
        &app,
        None,
        None,
        "administration.identity",
        "group-mapping.set",
        json!({"group":"Leads","role":"admin","team":"eng"}),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "SCIM must not map a group into admin"
    );

    // Admin configures a group → non-privileged-role/team mapping (ungated single-user).
    let (s, _) = administration_command(
        &app,
        None,
        None,
        "administration.identity",
        "group-mapping.set",
        json!({"group":"Engineering","role":"viewer","team":"eng"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (_s, body) = rotate_token(&app, None).await;
    let token = body["result"]["token"].as_str().unwrap().to_string();

    // A user provisioned with that group takes the mapped role/team.
    let (s, _) = send(
        &app,
        "POST",
        "/scim/v2/Users",
        Some(r#"{"userName":"e@acme.com","groups":[{"value":"Engineering"}]}"#),
        Some(&token),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);

    let (_s, body) = access_document(&app).await;
    let m = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["authority"] == "e@acme.com")
        .unwrap()
        .clone();
    assert_eq!(m["role"], "viewer");
    assert_eq!(m["team"], "eng");

    // A user with an unmapped group falls back to the default member role.
    send(
        &app,
        "POST",
        "/scim/v2/Users",
        Some(r#"{"userName":"x@acme.com","groups":[{"value":"Unknown"}]}"#),
        Some(&token),
    )
    .await;
    let (_s, body) = access_document(&app).await;
    let x = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["authority"] == "x@acme.com")
        .unwrap()
        .clone();
    assert_eq!(x["role"], "member");
}

#[tokio::test]
async fn rotating_the_token_invalidates_the_old_one() {
    let (_dir, app) = workbench();
    let (_s, body) = rotate_token(&app, None).await;
    let first = body["result"]["token"].as_str().unwrap().to_string();
    let (_s, body) = rotate_token(&app, None).await;
    let second = body["result"]["token"].as_str().unwrap().to_string();
    assert_ne!(first, second);

    // The old token no longer authenticates; the new one does.
    let (s, _) = send(
        &app,
        "POST",
        "/scim/v2/Users",
        Some(r#"{"userName":"x@acme.com"}"#),
        Some(&first),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = send(
        &app,
        "POST",
        "/scim/v2/Users",
        Some(r#"{"userName":"x@acme.com"}"#),
        Some(&second),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
}

/// SCIM-1: the PATCH endpoint accepts the strict RFC 7644 PatchOp envelope that Okta / Entra
/// actually send to deprovision — `{"schemas":[…],"Operations":[{"op":"replace","path":"active","value":false}]}`
/// — end to end, deprovisioning the member (offboarding → access revoked, SCIM-2).
#[tokio::test]
async fn scim_patchop_envelope_deprovisions() {
    let (_dir, app) = workbench();
    let (_, body) = rotate_token(&app, None).await;
    let token = body["result"]["token"].as_str().unwrap().to_string();

    // Provision an active member.
    let (s, _) = send(
        &app,
        "POST",
        "/scim/v2/Users",
        Some(r#"{"userName":"bob@acme.com"}"#),
        Some(&token),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);

    // Deprovision via the real PatchOp envelope.
    let (s, body) = send(
        &app,
        "PATCH",
        "/scim/v2/Users/bob@acme.com",
        Some(
            r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}"#,
        ),
        Some(&token),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "PatchOp envelope accepted: {body}");
    assert_eq!(body["active"], false);

    // The directory reflects the deprovision (standing revoked).
    let (_, body) = access_document(&app).await;
    let bob = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["authority"] == "bob@acme.com")
        .unwrap()
        .clone();
    assert_eq!(bob["status"], "deprovisioned");

    // A PatchOp with no active-setting operation is a 400 (not a silent no-op).
    let (s, _) = send(
        &app,
        "PATCH",
        "/scim/v2/Users/bob@acme.com",
        Some(r#"{"Operations":[{"op":"replace","path":"displayName","value":"X"}]}"#),
        Some(&token),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "no active op ⇒ 400");
}
