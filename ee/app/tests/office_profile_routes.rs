//! Server-side refusal of hosted data routes for an organization enrolled in
//! the office-controlled healthcare profile (WS-426).
//!
//! The Hub mounts its hosted routes under the enterprise admission layer. This
//! test mounts stand-ins at the same paths under that same layer and drives
//! them the way a stale client would: authenticated, with or without the
//! organization header, sending the request the current client no longer
//! offers. The stand-in handler records that the request reached it; a refused
//! request must not reach it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{any, get};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use gaugedesk_app::account::ACCOUNT_SCOPE;
use gaugedesk_app::identity::LoopbackIdentityProvider;
use gaugedesk_app::office_hosted_routes::{enroll, HostedRouteFamily, INVENTORY};
use gaugedesk_app::org::{tenant_scope, MembershipRecord, MembershipStatus, RecordOp};
use gaugedesk_app::tenancy::{TenantRef, TENANT_REF_KIND};
use gaugedesk_app::{SharedWorkbench, Workbench};
use gaugedesk_core::abac::AuthorityAttributes;
use gaugedesk_core::ids::AuthorityId;
use gaugedesk_ee::org_routes::enterprise_auth;
use gaugedesk_store::Store;
use gaugedesk_workspace::Instance;

fn member(tenant: &str, authority: &str) -> MembershipRecord {
    MembershipRecord {
        id: authority.into(),
        op: RecordOp::Upsert,
        org_id: tenant.into(),
        authority: authority.into(),
        email: format!("{authority}@example.test"),
        role: "owner".into(),
        status: MembershipStatus::Active,
        managed_by_scim: false,
        team: None,
    }
}

fn seed_tenant(store: &mut Store, tenant: &str, authority: &str) {
    store
        .append_record(
            &tenant_scope(tenant),
            "membership",
            &serde_json::to_string(&member(tenant, authority)).unwrap(),
        )
        .unwrap();
}

/// A Hub-shaped router: stand-ins at every Hub-enforced hosted path, behind
/// the real enterprise admission layer. `office` decides whether the tenant
/// `clinic` is enrolled. The person's tenant index lives in the shared
/// desktop account scope, which is the scope this unhosted workbench resolves.
fn hub(office: bool) -> (tempfile::TempDir, Router, Arc<AtomicUsize>) {
    hub_for("clinic", office)
}

/// [`hub`] for an organization tenant named `tenant`.
fn hub_for(tenant: &str, office: bool) -> (tempfile::TempDir, Router, Arc<AtomicUsize>) {
    let dir = tempfile::tempdir().unwrap();
    let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
    let mut store = Store::open_in_memory().unwrap();
    seed_tenant(&mut store, tenant, "doc");
    let tenant_ref = TenantRef {
        id: tenant.into(),
        op: RecordOp::Upsert,
        display_name: "Clinic".into(),
        role: "owner".into(),
        personal: false,
    };
    store
        .append_record(
            ACCOUNT_SCOPE,
            TENANT_REF_KIND,
            &serde_json::to_string(&tenant_ref).unwrap(),
        )
        .unwrap();
    if office {
        enroll(&mut store, tenant, "clinic-home", "onboarding-operator", 1).unwrap();
    }
    let idp = LoopbackIdentityProvider::new().enroll(
        "doc-token",
        AuthorityId::new("doc"),
        AuthorityAttributes::default(),
    );
    let wb: SharedWorkbench = Arc::new(Mutex::new(
        Workbench::with_target("inst-test", instance, store).with_identity_provider(Arc::new(idp)),
    ));
    let count = Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    let reached = move || {
        let counter = counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            "reached"
        }
    };
    let app = Router::new()
        .route("/account/dictation/{action}", any(reached.clone()))
        .route("/product-analytics/events", any(reached.clone()))
        .route("/product-analytics/policy", get(reached.clone()))
        .route("/account/tenants/{tenant}/backups", any(reached.clone()))
        .route("/account/tenants/{tenant}/cloud-home", any(reached.clone()))
        .route(
            "/account/tenants/{tenant}/cloud-home/export",
            any(reached.clone()),
        )
        .route(
            "/gaugeapps/administration/model-providers/intake",
            any(reached.clone()),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            wb.clone(),
            enterprise_auth,
        ))
        .with_state(wb);
    (dir, app, count)
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    tenant: Option<&str>,
) -> (StatusCode, Value, String) {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    if let Some(tenant) = tenant {
        request = request.header("x-gaugewright-tenant", tenant);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from("{}")).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        text,
    )
}

const HOSTED: &[(&str, &str, HostedRouteFamily)] = &[
    (
        "POST",
        "/account/dictation/transcribe",
        HostedRouteFamily::Dictation,
    ),
    (
        "POST",
        "/account/dictation/entitlement",
        HostedRouteFamily::Dictation,
    ),
    (
        "POST",
        "/product-analytics/events",
        HostedRouteFamily::ProductAnalytics,
    ),
    (
        "GET",
        "/account/tenants/clinic/backups",
        HostedRouteFamily::HostedBackup,
    ),
    (
        "PUT",
        "/account/tenants/clinic/cloud-home",
        HostedRouteFamily::HostedHome,
    ),
    (
        "POST",
        "/account/tenants/clinic/cloud-home/export",
        HostedRouteFamily::HostedHome,
    ),
    (
        "POST",
        "/gaugeapps/administration/model-providers/intake",
        HostedRouteFamily::CredentialBroker,
    ),
];

#[tokio::test]
async fn an_enrolled_organizations_hosted_routes_refuse_a_stale_client() {
    let (_dir, app, reached) = hub(true);
    for (method, path, family) in HOSTED {
        // With the organization header, and without it: a client that never
        // learned about the profile sends none.
        for tenant in [Some("clinic"), None] {
            let before = reached.load(Ordering::SeqCst);
            let (status, body, text) = send(&app, method, path, Some("doc-token"), tenant).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{method} {path} {tenant:?}: {text}"
            );
            assert_eq!(body["refusal"], "office-profile", "{path}");
            assert_eq!(body["route_family"], family.as_str(), "{path}");
            assert_eq!(
                reached.load(Ordering::SeqCst),
                before,
                "{method} {path} reached its handler"
            );
        }
    }

    // The policy read that tells a client analytics is off still answers.
    let (status, _, text) = send(
        &app,
        "GET",
        "/product-analytics/policy",
        Some("doc-token"),
        Some("clinic"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
}

#[tokio::test]
async fn an_anonymous_caller_learns_nothing_about_the_profile() {
    let (_dir, app, _) = hub(true);
    let (status, body, text) =
        send(&app, "GET", "/account/tenants/clinic/backups", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{text}");
    assert!(body.get("refusal").is_none(), "{text}");
}

#[tokio::test]
async fn an_ordinary_organization_keeps_its_hosted_routes() {
    let (_dir, app, reached) = hub(false);
    for (method, path, _) in HOSTED {
        let (status, _, text) = send(&app, method, path, Some("doc-token"), Some("clinic")).await;
        assert_eq!(status, StatusCode::OK, "{method} {path}: {text}");
        assert_eq!(text, "reached");
    }
    assert_eq!(reached.load(Ordering::SeqCst), HOSTED.len());
}

#[test]
fn this_test_drives_every_hub_enforced_family() {
    use gaugedesk_app::office_hosted_routes::Enforcement;
    let driven: std::collections::BTreeSet<_> = HOSTED.iter().map(|(_, _, f)| *f).collect();
    for entry in INVENTORY {
        if matches!(entry.enforcement, Enforcement::HubAdmission(_)) {
            // Managed inference names a project; project admission refuses it
            // before this layer in the stand-in, so it is covered by the
            // classifier tests in gaugedesk-app instead.
            if entry.family == HostedRouteFamily::ManagedInference {
                continue;
            }
            assert!(
                driven.contains(&entry.family),
                "{:?} is not driven",
                entry.family
            );
        }
    }
}

/// A generated organization tenant is `organization:<hex>`, and the shipping
/// client sends it through `encodeURIComponent`. The router decodes it for the
/// handler, so the refusal must decode it too or the encoded form walks past.
#[tokio::test]
async fn an_encoded_organization_tenant_is_refused_like_the_plain_one() {
    let tenant = "organization:5f3a9c";
    let paths = [
        ("GET", "/account/tenants/organization%3A5f3a9c/backups"),
        ("PUT", "/account/tenants/organization%3A5f3a9c/cloud-home"),
        (
            "POST",
            "/account/tenants/organization%3a5f3a9c/cloud-home/export",
        ),
        ("GET", "/account/tenants/organization:5f3a9c/backups"),
    ];

    // Unenrolled, every form reaches its handler: the paths are real routes.
    let (_dir, app, reached) = hub_for(tenant, false);
    for (method, path) in paths {
        let (status, _, text) = send(&app, method, path, Some("doc-token"), Some(tenant)).await;
        assert_eq!(status, StatusCode::OK, "{method} {path}: {text}");
    }
    assert_eq!(reached.load(Ordering::SeqCst), paths.len());

    let (_dir, app, reached) = hub_for(tenant, true);
    for (method, path) in paths {
        for header in [Some(tenant), None] {
            let (status, body, text) = send(&app, method, path, Some("doc-token"), header).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{method} {path} {header:?}: {text}"
            );
            assert_eq!(body["refusal"], "office-profile", "{path}");
        }
    }
    assert_eq!(
        reached.load(Ordering::SeqCst),
        0,
        "a refused request reached its handler"
    );
}
