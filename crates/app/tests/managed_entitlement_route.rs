//! The managed-inference entitlement mint endpoint over the real router
//! (SOC 2 finding F-5.3 / DR-0089).
//!
//! These drive `POST /account/tenants/{tenant}/managed-inference/entitlement`
//! through the mounted control plane and assert its refusals: a caller who does
//! not administer the tenant, a plan that is not active, a malformed publisher
//! key, and a Hub with no signing key configured (fail-closed). The signing and
//! verification of a well-formed entitlement is covered byte-for-byte by the
//! `managed_entitlement` module's own tests; here the concern is that the route
//! guards the way its handler intends before it ever reaches the signer.
//!
//! Every case runs with `GAUGEWRIGHT_MANAGED_ENTITLEMENT_SIGNING_KEY` unset, so
//! no test mutates process-global environment: the refusals are all decided
//! before the signing-configuration check, and the success path (which needs a
//! key) is proven at the module level instead.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use gaugedesk_app::account::ACCOUNT_SCOPE;
use gaugedesk_app::managed_inference::MANAGED_PLAN_KIND;
use gaugedesk_app::open_control_plane;
use gaugedesk_app::org::tenant_scope;
use gaugedesk_app::tenancy::TENANT_REF_KIND;
use gaugedesk_app::Workbench;
use gaugedesk_store::Store;
use gaugedesk_workspace::Instance;

const TENANT: &str = "acme";

/// A fixed, well-formed uncompressed-SEC1 P-256 publisher key (130 lowercase
/// hex, `0x04` prefix) that is a genuine point on the curve — generated once
/// with OpenSSL's `prime256v1` so the guards under test see a key the shape
/// check accepts, exercising authorization and plan state rather than encoding.
const PUBLISHER_KEY: &str =
    "047d635b1ba948fd02d7e02b1697893647cc39cf4178902e58e7a7507577ea367afec4bd02cec38a75daf17f5cff1b19b8714e7b89b2d5e5cda45c42bde45ed15b";

fn app_with(seed: impl FnOnce(&mut Store)) -> (tempfile::TempDir, Router) {
    let dir = tempfile::tempdir().unwrap();
    let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
    let mut store = Store::open_in_memory().unwrap();
    seed(&mut store);
    let wb = Workbench::with_target("inst-test", instance, store);
    (dir, open_control_plane(Arc::new(Mutex::new(wb))))
}

/// Put the current person into `tenant`'s switcher with `role`.
fn seed_membership(store: &mut Store, tenant: &str, role: &str) {
    let tenant_ref = json!({
        "id": tenant,
        "op": "upsert",
        "display_name": "Acme",
        "role": role,
        "personal": false,
    });
    store
        .append_record(ACCOUNT_SCOPE, TENANT_REF_KIND, &tenant_ref.to_string())
        .unwrap();
}

/// Give `tenant` a managed plan with `status` (`active` | `suspended` |
/// `lapsed`).
fn seed_plan(store: &mut Store, tenant: &str, status: &str) {
    let record = json!({
        "id": "managed-inference",
        "op": "upsert",
        "plan": "managed-monthly",
        "status": status,
        "included_tokens": 1000,
    });
    store
        .append_record(
            &tenant_scope(tenant),
            MANAGED_PLAN_KIND,
            &record.to_string(),
        )
        .unwrap();
}

async fn mint(app: &Router, tenant: &str, publisher_key: &str) -> (StatusCode, Value) {
    static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
    let body = json!({ "publisher_key": publisher_key }).to_string();
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "/account/tenants/{tenant}/managed-inference/entitlement"
        ))
        .header("content-type", "application/json")
        .header(
            "idempotency-key",
            format!(
                "entitlement-test-{}",
                NEXT_KEY.fetch_add(1, Ordering::Relaxed)
            ),
        )
        .body(Body::from(body))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn mint_refuses_a_caller_who_does_not_administer_the_tenant() {
    // No membership seeded at all.
    let (_dir, app) = app_with(|_store| {});
    let (status, _) = mint(&app, TENANT, PUBLISHER_KEY).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mint_refuses_a_member_who_is_not_an_owner_or_admin() {
    let (_dir, app) = app_with(|store| {
        seed_membership(store, TENANT, "member");
        seed_plan(store, TENANT, "active");
    });
    let (status, _) = mint(&app, TENANT, PUBLISHER_KEY).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mint_refuses_when_the_plan_is_suspended() {
    let (_dir, app) = app_with(|store| {
        seed_membership(store, TENANT, "owner");
        seed_plan(store, TENANT, "suspended");
    });
    let (status, _) = mint(&app, TENANT, PUBLISHER_KEY).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn mint_refuses_when_the_plan_is_lapsed() {
    let (_dir, app) = app_with(|store| {
        seed_membership(store, TENANT, "admin");
        seed_plan(store, TENANT, "lapsed");
    });
    let (status, _) = mint(&app, TENANT, PUBLISHER_KEY).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn mint_refuses_when_there_is_no_plan() {
    let (_dir, app) = app_with(|store| {
        seed_membership(store, TENANT, "owner");
    });
    let (status, _) = mint(&app, TENANT, PUBLISHER_KEY).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn mint_rejects_a_malformed_publisher_key() {
    let (_dir, app) = app_with(|store| {
        seed_membership(store, TENANT, "owner");
        seed_plan(store, TENANT, "active");
    });
    let (status, _) = mint(&app, TENANT, "not-a-key").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn mint_fails_closed_when_signing_is_not_configured() {
    // An owner with an active plan and a valid publisher key gets past every
    // guard and reaches the signing-configuration check, which fails closed
    // because the Hub holds no signing key in this environment.
    let (_dir, app) = app_with(|store| {
        seed_membership(store, TENANT, "owner");
        seed_plan(store, TENANT, "active");
    });
    let (status, _) = mint(&app, TENANT, PUBLISHER_KEY).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}
