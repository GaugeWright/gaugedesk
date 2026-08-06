//! Organization admin surface, end to end (`ORG-1`, B10/B11). Drives the mounted
//! `control_plane`: set org settings, invite members, change a role, deactivate, and
//! assert the directory reads back — plus the structural guard that an org always
//! keeps a break-glass owner.

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
use support::{administration_command, administration_document, administration_domain_challenge};

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

async fn command(
    app: &Router,
    document: &str,
    command: &str,
    payload: Value,
) -> (StatusCode, Value) {
    administration_command(app, None, None, document, command, payload).await
}

async fn tenant_command(
    app: &Router,
    tenant: &str,
    document: &str,
    command: &str,
    payload: Value,
) -> (StatusCode, Value) {
    administration_command(app, Some(tenant), None, document, command, payload).await
}

async fn document(app: &Router, tenant: Option<&str>, id: &str) -> (StatusCode, Value) {
    let (status, response) = administration_document(app, tenant, None, id).await;
    (status, response["document"]["content"].clone())
}

async fn tenant_get(app: &Router, tenant: &str, uri: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("x-gaugewright-tenant", tenant)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn update_policy(
    app: &Router,
    security: Option<Value>,
    placement: Option<Value>,
) -> (StatusCode, Value) {
    let (status, document) =
        administration_document(app, None, None, "administration.policy").await;
    if status != StatusCode::OK {
        return (status, document);
    }
    let mut content = document["document"]["content"].clone();
    if !content["security"].is_object() {
        content["security"] = json!({});
    }
    if let Some(patch) = security.and_then(|value| value.as_object().cloned()) {
        let target = content["security"].as_object_mut().unwrap();
        for (key, value) in patch {
            target.insert(key, value);
        }
    }
    if let Some(placement) = placement {
        content["placement"] = placement;
    }
    command(app, "administration.policy", "policy.update", content).await
}

async fn send(app: &Router, method: &str, uri: &str, body: Option<&str>) -> (StatusCode, Value) {
    static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
    let mut builder = Request::builder().method(method).uri(uri);
    if method != "GET" && method != "HEAD" && method != "OPTIONS" {
        builder = builder.header(
            "idempotency-key",
            format!("org-test-{}", NEXT_KEY.fetch_add(1, Ordering::Relaxed)),
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
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn multi_tenant_admin_surfaces_are_scope_isolated() {
    // DEPLOY-6 end-to-end: two named tenants configure the same admin surfaces over the
    // same control plane and never see each other; the default (header-less) tenant is a
    // third, independent org.
    let (_dir, app) = workbench();
    assert_eq!(
        tenant_command(
            &app,
            "acme",
            "administration.organization",
            "organization.update",
            json!({"display_name":"Acme", "verified_domains":[], "kind":"client"})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        tenant_command(
            &app,
            "globex",
            "administration.organization",
            "organization.update",
            json!({"display_name":"Globex", "verified_domains":[], "kind":"client"})
        )
        .await
        .0,
        StatusCode::OK
    );
    // a member added under acme must not appear for globex (the isolation contract).
    tenant_command(
        &app,
        "acme",
        "administration.access",
        "member.invite",
        json!({"authority":"u1","email":"u1@acme.com","role":"member"}),
    )
    .await;

    let (_, a) = document(&app, Some("acme"), "administration.organization").await;
    assert_eq!(a["display_name"], "Acme");
    let (_, g) = document(&app, Some("globex"), "administration.organization").await;
    assert_eq!(g["display_name"], "Globex"); // not Acme — scope-isolated
    let (_, am) = document(&app, Some("acme"), "administration.access").await;
    let (_, gm) = document(&app, Some("globex"), "administration.access").await;
    assert!(am["members"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["authority"] == "u1"));
    assert!(
        !gm["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member["authority"] == "u1"),
        "globex has no acme member: {gm}",
    );
    tenant_command(
        &app,
        "acme",
        "administration.access",
        "member.invite",
        json!({"authority":"acme-audit-only","role":"member"}),
    )
    .await;
    let (status, acme_audit) = tenant_get(&app, "acme", "/admin/audit?format=json").await;
    assert_eq!(status, StatusCode::OK);
    let (status, globex_audit) = tenant_get(&app, "globex", "/admin/audit?format=json").await;
    assert_eq!(status, StatusCode::OK);
    assert!(acme_audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["target"] == "acme-audit-only"));
    assert!(!globex_audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["target"] == "acme-audit-only"));
    let (_, acme_audit_document) = document(&app, Some("acme"), "administration.audit").await;
    let (_, globex_audit_document) = document(&app, Some("globex"), "administration.audit").await;
    assert_eq!(acme_audit_document["integrity"]["ok"], true);
    assert_eq!(globex_audit_document["integrity"]["ok"], true);
    assert_ne!(
        acme_audit_document["integrity"]["entries"],
        globex_audit_document["integrity"]["entries"]
    );
    // the default tenant (no header) is independent — untouched by either named tenant.
    let (_, d) = document(&app, None, "administration.organization").await;
    assert!(d.is_null(), "default tenant unaffected: {d}");
}

#[tokio::test]
async fn org_settings_round_trip() {
    let (_dir, app) = workbench();
    let (status, _) = command(
        &app,
        "administration.organization",
        "organization.update",
        json!({"display_name":"Acme","verified_domains":[],"default_region":"eu","kind":"client"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = document(&app, None, "administration.organization").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["display_name"], "Acme");
    assert!(body["verified_domains"].as_array().unwrap().is_empty());
    assert_eq!(body["default_region"], "eu");
}

#[tokio::test]
async fn invite_list_and_change_role() {
    let (_dir, app) = workbench();

    let (status, _) = command(
        &app,
        "administration.access",
        "member.invite",
        json!({"authority":"alice-auth","email":"alice@acme.com","role":"member"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = document(&app, None, "administration.access").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["members"].as_array().unwrap().len(), 2);

    // Promote alice to admin.
    let (status, _) = command(
        &app,
        "administration.access",
        "member.role.set",
        json!({"id":"alice-auth","role":"admin"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = document(&app, None, "administration.access").await;
    assert_eq!(
        body["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|member| member["id"] == "alice-auth")
            .unwrap()["role"],
        "admin"
    );
}

#[tokio::test]
async fn unknown_role_is_rejected() {
    let (_dir, app) = workbench();
    let (status, _) = command(
        &app,
        "administration.access",
        "member.invite",
        json!({"authority":"x","role":"superuser"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn deactivate_marks_deprovisioned() {
    let (_dir, app) = workbench();
    command(
        &app,
        "administration.access",
        "member.invite",
        json!({"authority":"bob-auth","role":"member"}),
    )
    .await;

    let (status, _) = command(
        &app,
        "administration.access",
        "member.deactivate",
        json!({"id":"bob-auth"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = document(&app, None, "administration.access").await;
    assert_eq!(
        body["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|member| member["id"] == "bob-auth")
            .unwrap()["status"],
        "deprovisioned"
    );
}

#[tokio::test]
async fn cannot_deactivate_or_demote_the_last_owner() {
    let (_dir, app) = workbench();
    // Demote the only owner → refused.
    let (status, _) = command(
        &app,
        "administration.access",
        "member.role.set",
        json!({"id":"local-user","role":"admin"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Deactivate the only owner → refused.
    let (status, _) = command(
        &app,
        "administration.access",
        "member.deactivate",
        json!({"id":"local-user"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn billing_round_trips_and_is_not_authority() {
    let (_dir, app) = workbench();
    // Set a plan with seats; seats_used reflects active membership.
    let (status, _) = command(
        &app,
        "administration.billing",
        "billing.update",
        json!({"plan":"business","seats":10,"managed_inference":{"plan":"org-managed","status":"active","included_tokens":1000000}}),
    ).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = document(&app, None, "administration.billing").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["seats_used"], 1);
    assert_eq!(body["billing"]["managed_inference"]["status"], "active");
    assert_eq!(body["managed_usage"]["runs"], 0);
    assert_eq!(body["managed_usage"]["included_tokens"], 1_000_000);

    // BILL-3: lapse the plan to zero seats — it confers/revokes no authority.
    command(
        &app,
        "administration.billing",
        "billing.update",
        json!({"plan":"free","seats":0}),
    )
    .await;
    // The active owner's role/status is untouched by billing.
    let (_s, body) = document(&app, None, "administration.access").await;
    let owner = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["authority"] == "local-user")
        .unwrap()
        .clone();
    assert_eq!(owner["status"], "active");
    assert_eq!(owner["role"], "owner");
}

#[tokio::test]
async fn security_policy_round_trips() {
    let (_dir, app) = workbench();
    let (status, _) = update_policy(&app, Some(json!({"require_mfa":true,"session_lifetime_secs":3600,"idle_timeout_secs":900,"residency_region":"eu"})), None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = document(&app, None, "administration.policy").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["security"]["session_lifetime_secs"], 3600);
    assert_eq!(body["security"]["residency_region"], "eu");
}

#[tokio::test]
async fn audit_retention_min_guarantee_defaults_to_a_year_and_is_configurable() {
    // AUD-3: the minimum-retention guarantee is published on the audit timeline. The log is
    // append-only/forever (INV-6); this is the contractual floor, default one year.
    let (_dir, app) = workbench();
    let (status, body) = send(&app, "GET", "/admin/audit", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["retention_min_days"], 365,
        "default guarantee is one year"
    );

    // A buyer can configure a longer guarantee; it round-trips and the timeline publishes it.
    let (status, _) =
        update_policy(&app, Some(json!({"audit_retention_min_days":2555})), None).await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = send(&app, "GET", "/admin/audit", None).await;
    assert_eq!(body["retention_min_days"], 2555);
    let (_, sec) = document(&app, None, "administration.policy").await;
    assert_eq!(sec["security"]["audit_retention_min_days"], 2555);
}

#[tokio::test]
async fn org_kind_defaults_to_client_and_accepts_consultant() {
    let (_dir, app) = workbench();
    // Default kind is client (the existing single-org path is unchanged).
    let (status, _) = command(
        &app,
        "administration.organization",
        "organization.update",
        json!({"display_name":"Acme","verified_domains":[],"kind":"client"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = document(&app, None, "administration.organization").await;
    assert_eq!(body["kind"], "client");

    // A consultant org is the same primitive, different party (DEPLOY-6, ADR 0061).
    let (status, _) = command(
        &app,
        "administration.organization",
        "organization.update",
        json!({"display_name":"Expert LLC","verified_domains":[],"kind":"consultant"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = document(&app, None, "administration.organization").await;
    assert_eq!(body["kind"], "consultant");
}

#[tokio::test]
async fn placement_policy_round_trips() {
    let (_dir, app) = workbench();
    // Default (no record): the open policy — admits everything.
    let (status, body) = document(&app, None, "administration.policy").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["placement"]["require_attested"], false);

    // Tighten: require attested, restrict to counterparty-hosted.
    let (status, _) = update_policy(
        &app,
        None,
        Some(json!({"require_attested":true,"allowed_operators":["counterparty"]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = document(&app, None, "administration.policy").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["placement"]["require_attested"], true);
    assert_eq!(body["placement"]["allowed_operators"][0], "counterparty");
}

#[tokio::test]
async fn sso_connection_round_trips() {
    let (_dir, app) = workbench();
    let (status, _) = command(
        &app,
        "administration.identity",
        "sso.configure",
        json!({"protocol":"oidc","issuer":"https://idp.example.com","audiences":["client-1"],"enforce_sso":true}),
    ).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = document(&app, None, "administration.identity").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["sso"]["issuer"], "https://idp.example.com");
    assert_eq!(body["sso"]["audiences"][0], "client-1");
}

#[tokio::test]
async fn domain_capture_has_no_unauthenticated_public_mutation_route() {
    let (_dir, app) = workbench();
    let (status, _) = command(
        &app,
        "administration.organization",
        "organization.update",
        json!({"display_name":"Acme","verified_domains":["acme.com"],"kind":"client"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "an ordinary organization edit cannot self-assert a verified domain"
    );

    // JIT admission is part of the verified OIDC callback, not a caller-supplied
    // authority/email mutation. The former public façade is absent.
    let (status, _) = send(
        &app,
        "POST",
        "/admin/members/auto-join",
        Some(r#"{"authority":"alice-auth","email":"alice@acme.com"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, access) = document(&app, None, "administration.access").await;
    assert_eq!(access["members"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn audit_timeline_records_governance_actions() {
    let (_dir, app) = workbench();
    command(
        &app,
        "administration.access",
        "member.invite",
        json!({"authority":"alice","role":"member"}),
    )
    .await;
    command(
        &app,
        "administration.access",
        "member.role.set",
        json!({"id":"alice","role":"admin"}),
    )
    .await;

    // Proposal and apply audit rows coexist; domain effects remain queryable by
    // their semantic action.
    let (status, body) = send(&app, "GET", "/admin/audit", None).await;
    assert_eq!(status, StatusCode::OK);
    let entries = body["entries"].as_array().unwrap();
    assert!(entries
        .iter()
        .any(|e| e["action"] == "member.role" && e["target"] == "alice"));

    // Filter by action.
    let (status, body) = send(&app, "GET", "/admin/audit?action=member.role", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["entries"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn role_change_on_missing_member_is_404() {
    let (_dir, app) = workbench();
    let (status, _) = command(
        &app,
        "administration.access",
        "member.role.set",
        json!({"id":"ghost","role":"admin"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn configuring_oidc_sso_with_an_unreachable_issuer_surfaces_an_error_and_does_not_lock_out() {
    // Enterprise-mode activation (`ID-3`): reviewed sso.configure rebuilds wb.idp from the
    // connection. A bogus/unreachable issuer must NOT clobber the existing verifier
    // (here: none) — a bad runtime edit can't lock admins out — and the activation
    // error is surfaced so the operator sees it.
    let (_dir, app) = workbench();
    let (status, _) = command(
        &app,
        "administration.identity",
        "sso.configure",
        json!({"protocol":"oidc","issuer":"http://127.0.0.1:9/realms/x","audiences":["client-1"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the connection is still saved");
    let (_, body) = document(&app, None, "administration.identity").await;
    assert_eq!(body["sso"]["issuer"], "http://127.0.0.1:9/realms/x");

    // The verifier was left untouched (none) → admin stays ungated, not bricked: a
    // read without any bearer still succeeds.
    let (status, _) =
        administration_document(&app, None, None, "administration.organization").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admin is not locked out by a bad SSO edit"
    );
}

#[tokio::test]
async fn integration_details_expose_the_sp_side_values() {
    // ONB-1: the admin reads our SP/SCIM values to paste into their IdP.
    let (_dir, app) = workbench();
    let (status, body) = send(&app, "GET", "/admin/integration", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["oidc"]["redirect_uri"]
        .as_str()
        .unwrap()
        .ends_with("/auth/callback"));
    assert!(body["saml"]["metadata_url"]
        .as_str()
        .unwrap()
        .ends_with("/saml/metadata"));
    assert!(body["scim"]["base_url"]
        .as_str()
        .unwrap()
        .ends_with("/scim/v2"));
}

#[tokio::test]
async fn sso_test_connection_reports_unreachable_issuer() {
    // ONB-3: a real OIDC discovery probe; an unreachable issuer → ok:false (operational,
    // never stored). Port 9 (discard) → connection refused fast.
    let (_dir, app) = workbench();
    let (status, body) = send(
        &app,
        "POST",
        "/admin/sso/test",
        Some(r#"{"protocol":"oidc","issuer":"http://127.0.0.1:9/realms/x","audiences":["client-1"]}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], serde_json::json!(false));
    assert!(body["detail"].is_string());
}

#[tokio::test]
async fn domain_verify_token_returns_the_txt_record() {
    // ONB-5: the deterministic TXT record an admin publishes (domain lowercased).
    let (_dir, app) = workbench();
    let (status, body) = administration_domain_challenge(&app, None, None, "Acme.com").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["record_name"],
        serde_json::json!("_gaugewright-challenge.acme.com")
    );
    assert!(body["value"]
        .as_str()
        .unwrap()
        .starts_with("gaugewright-domain-verification="));
}
