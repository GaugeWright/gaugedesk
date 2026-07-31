//! Live OIDC **admin-gate** end-to-end (M3 `ID-3`) — the full route-level proof the
//! shell + activation set up: with a verifier built from a *live* OP's JWKS
//! ([`build_oidc_idp`]) attached to the `Workbench`, and a provisioned directory, the
//! mounted `/admin/*` control plane **admits a genuine member's id-token** and refuses
//! an anonymous or bogus bearer (fail-closed, `INV-20`).
//!
//! `#[ignore]`d + env-driven (`OIDC_ISSUER` / `OIDC_AUDIENCE` / `OIDC_TOKEN`); the
//! `scripts/keycloak-oidc-check.sh` harness supplies a real id-token from the
//! self-hosted Keycloak, so this runs with no vendor signup.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

use gaugewright_app::org::{
    MembershipRecord, MembershipStatus, RecordOp, SsoConnectionRecord, SsoProtocol, ORG_ID,
    ORG_SCOPE,
};
use gaugewright_app::Workbench;
use gaugewright_ee::auth_oidc::build_oidc_idp;
use gaugewright_ee::org_routes::enterprise_control_plane;
use gaugewright_store::Store;

fn env_or_skip(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => {
            eprintln!("SKIP oidc_gate_live: ${key} unset (needs a live OP + id-token)");
            None
        }
    }
}

/// Send a request to the mounted control plane, optionally with a bearer; return the
/// status. Mirrors the `org_admin` harness, plus the `Authorization` header.
async fn status(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<&str>,
    bearer: Option<&str>,
) -> StatusCode {
    let mut builder = Request::builder().method(method).uri(uri);
    static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
    if method != "GET" && method != "HEAD" && method != "OPTIONS" {
        builder = builder.header(
            "idempotency-key",
            format!("oidc-test-{}", NEXT_KEY.fetch_add(1, Ordering::Relaxed)),
        );
    }
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let req = match body {
        Some(b) => builder
            .header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    app.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
#[ignore = "needs a live OP (issuer + a real id-token); driven by keycloak-oidc-check.sh"]
async fn admin_gate_admits_a_real_member_token_and_refuses_others() {
    let (Some(issuer), Some(audience), Some(token)) = (
        env_or_skip("OIDC_ISSUER"),
        env_or_skip("OIDC_AUDIENCE"),
        env_or_skip("OIDC_TOKEN"),
    ) else {
        return;
    };

    // Build the verifier from the live OP's JWKS and confirm the genuine token verifies
    // (its subject is who we provision as a member).
    let sso = SsoConnectionRecord {
        protocol: SsoProtocol::Oidc,
        issuer,
        audiences: vec![audience],
        ..Default::default()
    };
    let (idp, warm) = build_oidc_idp(Some(&sso)).expect("an OIDC connection yields a verifier");
    assert!(warm, "the live OP's JWKS must load (is the OP reachable?)");
    let subject = idp
        .authenticate(&token)
        .expect("the genuine id-token verifies")
        .as_str()
        .to_string();

    // Tenant/account provisioning establishes the first owner before the
    // Administration Environment can open; there is deliberately no bootstrap
    // `/admin/*` mutation bypass.
    let mut store = Store::open_in_memory().unwrap();
    store
        .append_record(
            ORG_SCOPE,
            "membership",
            &serde_json::to_string(&MembershipRecord {
                id: subject.clone(),
                op: RecordOp::Upsert,
                org_id: ORG_ID.into(),
                authority: subject.clone(),
                email: String::new(),
                role: "admin".into(),
                status: MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            })
            .unwrap(),
        )
        .unwrap();
    let wb = Workbench::new(store).with_identity_provider(idp);
    let app = enterprise_control_plane(Arc::new(Mutex::new(wb)));

    // The gate is now live (provisioned directory + attached verifier):
    assert_eq!(
        status(&app, "GET", "/admin/capabilities", None, Some(&token)).await,
        StatusCode::OK,
        "a real member's id-token is admitted",
    );
    assert_eq!(
        status(&app, "GET", "/admin/capabilities", None, None).await,
        StatusCode::UNAUTHORIZED,
        "an anonymous request is refused (fail-closed)",
    );
    assert_eq!(
        status(
            &app,
            "GET",
            "/admin/capabilities",
            None,
            Some("not.a.real.token"),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "a bogus bearer is refused",
    );
    println!("OIDC admin-gate VERIFIED ✔  member={subject}");
}

/// SECAUD-8: the OIDC callback is per-tenant rate-limited (defense-in-depth behind the edge
/// limit), mirroring the SCIM guard. A brute-force loop against the callback with a bogus
/// `state` (each a `400 unknown-or-expired state`) trips the lockout after 10 failures within
/// the window, and the 11th attempt is refused `429`. No live OP / SSO config needed — an
/// unknown `state` fails the CSRF take before any token exchange. Runs in-process (no #[ignore]).
#[tokio::test]
async fn oidc_callback_throttles_after_repeated_failures() {
    let wb = Workbench::new(Store::open_in_memory().unwrap());
    let app = enterprise_control_plane(Arc::new(Mutex::new(wb)));

    // 10 bogus-state callbacks: each is a fail-closed 400, and each records a failure.
    for i in 0..10 {
        let s = status(
            &app,
            "GET",
            &format!("/auth/callback?state=bogus-{i}&code=x"),
            None,
            None,
        )
        .await;
        assert_eq!(
            s,
            StatusCode::BAD_REQUEST,
            "attempt {i} is a fail-closed 400"
        );
    }

    // The 11th is locked out — the throttle, not the CSRF check, answers now.
    let s = status(
        &app,
        "GET",
        "/auth/callback?state=bogus-11&code=x",
        None,
        None,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::TOO_MANY_REQUESTS,
        "the tenant's SSO callback is throttled after 10 failures"
    );
}
