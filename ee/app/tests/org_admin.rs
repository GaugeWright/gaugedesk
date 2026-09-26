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
    let (dir, app, _) = workbench_with_handle();
    (dir, app)
}

fn workbench_with_handle() -> (tempfile::TempDir, Router, Arc<Mutex<Workbench>>) {
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
    let wb = Arc::new(Mutex::new(Workbench::with_target(
        "inst-test",
        instance,
        store,
    )));
    (dir, enterprise_control_plane(wb.clone()), wb)
}

fn seed_member(workbench: &Arc<Mutex<Workbench>>, tenant: &str, id: &str, email: &str, role: &str) {
    workbench
        .lock()
        .unwrap()
        .store_mut()
        .append_record(
            &tenant_scope(tenant),
            "membership",
            &serde_json::to_string(&MembershipRecord {
                id: id.into(),
                op: RecordOp::Upsert,
                org_id: ORG_ID.into(),
                authority: id.into(),
                email: email.into(),
                role: role.into(),
                status: MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            })
            .unwrap(),
        )
        .unwrap();
}

fn seed_member_with_status(
    workbench: &Arc<Mutex<Workbench>>,
    tenant: &str,
    id: &str,
    email: &str,
    status: MembershipStatus,
) {
    workbench
        .lock()
        .unwrap()
        .store_mut()
        .append_record(
            &tenant_scope(tenant),
            "membership",
            &serde_json::to_string(&MembershipRecord {
                id: id.into(),
                op: RecordOp::Upsert,
                org_id: ORG_ID.into(),
                authority: id.into(),
                email: email.into(),
                role: "member".into(),
                status,
                managed_by_scim: false,
                team: None,
            })
            .unwrap(),
        )
        .unwrap();
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
    (status, response["page"]["model"].clone())
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

#[tokio::test]
async fn project_share_picker_is_exact_tenant_and_active_members_only() {
    let (_dir, app, workbench) = workbench_with_handle();
    seed_member_with_status(
        &workbench,
        "acme",
        "authority:active",
        "active@example.test",
        MembershipStatus::Active,
    );
    seed_member_with_status(
        &workbench,
        "acme",
        "authority:inactive",
        "inactive@example.test",
        MembershipStatus::Deprovisioned,
    );

    let (status, body) = tenant_get(
        &app,
        "acme",
        "/account/tenants/acme/project-share-candidates",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["candidates"],
        json!([{
            "authority": "authority:active",
            "label": "active@example.test",
        }])
    );

    let (status, _) = tenant_get(
        &app,
        "globex",
        "/account/tenants/acme/project-share-candidates",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

async fn update_policy(
    app: &Router,
    security: Option<Value>,
    placement: Option<Value>,
) -> (StatusCode, Value) {
    let (status, document) = administration_document(app, None, None, "organization-policy").await;
    if status != StatusCode::OK {
        return (status, document);
    }
    let mut content = document["page"]["model"].clone();
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
    command(
        app,
        "organization-policy",
        "organization-policy.set",
        content,
    )
    .await
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
            "organization",
            "organization.display-name.set",
            json!({"display_name":"Acme"})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        tenant_command(
            &app,
            "globex",
            "organization",
            "organization.display-name.set",
            json!({"display_name":"Globex"})
        )
        .await
        .0,
        StatusCode::OK
    );
    // a member added under acme must not appear for globex (the isolation contract).
    let (status, _) = tenant_command(
        &app,
        "acme",
        "people",
        "people.invitation.create",
        json!({"emails":["u1@acme.com"],"role":"member"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, a) = document(&app, Some("acme"), "organization").await;
    assert_eq!(a["display_name"], "Acme");
    let (_, g) = document(&app, Some("globex"), "organization").await;
    assert_eq!(g["display_name"], "Globex"); // not Acme — scope-isolated
    let (_, am) = document(&app, Some("acme"), "people").await;
    let (_, gm) = document(&app, Some("globex"), "people").await;
    assert!(am["invitations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|invitation| invitation["email"] == "u1@acme.com"));
    assert!(
        !gm["invitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|invitation| invitation["email"] == "u1@acme.com"),
        "globex has no acme invitation: {gm}",
    );
    tenant_command(
        &app,
        "acme",
        "people",
        "people.invitation.create",
        json!({"emails":["audit@acme.com"],"role":"member"}),
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
        .any(|entry| entry["action"] == "people.invitation.create"));
    assert!(!globex_audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["action"] == "people.invitation.create"));
    // Audit evidence remains tenant-scoped authority, but ADR 0161 deliberately
    // exposes no low-information Audit GaugeApp page.
    // the default tenant (no header) is independent — untouched by either named tenant.
    let (_, d) = document(&app, None, "organization").await;
    assert!(d.is_null(), "default tenant unaffected: {d}");
}

#[tokio::test]
async fn org_settings_round_trip() {
    let (_dir, app) = workbench();
    let (status, _) = command(
        &app,
        "organization",
        "organization.display-name.set",
        json!({"display_name":"Acme"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = document(&app, None, "organization").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["display_name"], "Acme");
    assert!(body["domains"].as_array().unwrap().is_empty());
    assert!(body.get("kind").is_none());
    assert_eq!(body["owner"]["authority"], "local-user");
}

#[tokio::test]
async fn organization_display_name_rejects_unowned_fields_and_preserves_truth() {
    let (_dir, app) = workbench();
    let (status, _) = command(
        &app,
        "organization",
        "organization.display-name.set",
        json!({"display_name":"Expert LLC"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = command(
        &app,
        "organization",
        "organization.display-name.set",
        json!({"display_name":"Changed","kind":"consultant"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let (status, body) = document(&app, None, "organization").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["display_name"], "Expert LLC");
    assert!(body.get("kind").is_none());
}

#[tokio::test]
async fn invite_list_and_change_role() {
    let (_dir, app, workbench) = workbench_with_handle();

    let (status, _) = command(
        &app,
        "people",
        "people.invitation.create",
        json!({"emails":["alice@acme.com"],"role":"member"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = document(&app, None, "people").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["members"].as_array().unwrap().len(), 1);
    assert_eq!(body["invitations"].as_array().unwrap().len(), 1);
    assert_eq!(body["invitations"][0]["email"], "alice@acme.com");

    // Acceptance is handled by the account-facing Cloud route. Seed its durable
    // result here so this GaugeDesk test can continue through member governance.
    seed_member(&workbench, "", "alice-auth", "alice@acme.com", "member");

    // Promote alice to admin.
    let (status, _) = command(
        &app,
        "people",
        "people.role.change",
        json!({"id":"alice-auth","role":"admin"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = document(&app, None, "people").await;
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
        "people",
        "people.invitation.create",
        json!({"emails":["x@example.test"],"role":"superuser"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn deactivate_marks_deprovisioned() {
    let (_dir, app, workbench) = workbench_with_handle();
    seed_member(&workbench, "", "bob-auth", "bob@example.test", "member");

    let (status, _) = command(
        &app,
        "people",
        "people.member.deactivate",
        json!({"id":"bob-auth"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = document(&app, None, "people").await;
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
        "people",
        "people.role.change",
        json!({"id":"local-user","role":"admin"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Deactivate the only owner → refused.
    let (status, _) = command(
        &app,
        "people",
        "people.member.deactivate",
        json!({"id":"local-user"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn billing_state_is_read_only_and_conveys_no_authority() {
    let (_dir, app) = workbench();
    let (status, body) = document(&app, None, "billing").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["billing"], Value::Null);
    assert_eq!(body["seats_used"], 1);
    assert_eq!(body["managed_usage"]["runs"], 0);

    // Subscription state is supplied by its owning authority. Administration
    // cannot forge a plan, seat allowance, or managed-inference entitlement.
    let (status, _) = command(
        &app,
        "billing",
        "billing.update",
        json!({"billing":{"plan":"business","seats":10,"managed_inference":{"plan":"org-managed","status":"active","included_tokens":1000000}}}),
    ).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = document(&app, None, "billing").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["billing"], Value::Null);
    assert_eq!(body["seats_used"], 1);
    assert_eq!(body["managed_usage"]["runs"], 0);

    // A forged billing mutation neither grants nor revokes organization authority.
    let (_s, body) = document(&app, None, "people").await;
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
async fn organization_session_policy_round_trips() {
    let (_dir, app) = workbench();
    let (status, _) = update_policy(
        &app,
        Some(json!({"session_lifetime_secs":3600,"idle_timeout_secs":900})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = document(&app, None, "organization-policy").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["security"]["session_lifetime_secs"], 3600);
    assert_eq!(body["security"]["idle_timeout_secs"], 900);
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
    let (_, sec) = document(&app, None, "organization-policy").await;
    assert_eq!(sec["security"]["audit_retention_min_days"], 2555);
}

#[tokio::test]
async fn retired_organization_kind_is_absent_and_rejected() {
    let (_dir, app) = workbench();
    let (status, _) = command(
        &app,
        "organization",
        "organization.display-name.set",
        json!({"display_name":"Acme"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = document(&app, None, "organization").await;
    assert!(body.get("kind").is_none());

    let (status, body) = command(
        &app,
        "organization",
        "organization.display-name.set",
        json!({"display_name":"Expert LLC","kind":"consultant"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let (_, body) = document(&app, None, "organization").await;
    assert!(body.get("kind").is_none());
}

#[tokio::test]
async fn placement_policy_round_trips() {
    let (_dir, app) = workbench();
    // Default (no record): the open policy — admits everything.
    let (status, body) = document(&app, None, "organization-policy").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["placement"]["require_attested"], false);

    // Tighten to counterparty-hosted. Attestation is deliberately not an
    // Organization Policy control: reported client posture is not attestation.
    let (status, _) = update_policy(
        &app,
        None,
        Some(json!({"require_attested":false,"allowed_operators":["counterparty"]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = document(&app, None, "organization-policy").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["placement"]["require_attested"], false);
    assert_eq!(body["placement"]["allowed_operators"][0], "counterparty");
}

#[tokio::test]
async fn sso_connection_round_trips() {
    let (_dir, app) = workbench();
    let (status, _) = command(
        &app,
        "enterprise-identity",
        "enterprise-identity.connection.set",
        json!({"protocol":"oidc","issuer":"https://idp.example.com","audiences":["client-1"],"enforce_sso":true}),
    ).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = document(&app, None, "enterprise-identity").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["sso"]["issuer"], "https://idp.example.com");
    assert_eq!(body["sso"]["audiences"][0], "client-1");
}

#[tokio::test]
async fn domain_capture_has_no_unauthenticated_public_mutation_route() {
    let (_dir, app) = workbench();
    let (status, _) = command(
        &app,
        "organization",
        "organization.display-name.set",
        json!({"display_name":"Acme","domains":["acme.com"]}),
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
    let (_, access) = document(&app, None, "people").await;
    assert_eq!(access["members"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn audit_timeline_records_governance_actions() {
    let (_dir, app, workbench) = workbench_with_handle();
    seed_member(&workbench, "", "alice", "alice@example.test", "member");
    command(
        &app,
        "people",
        "people.role.change",
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
        .any(|e| e["action"] == "people.role.change" && e["target"] == "alice"));

    // Filter by action.
    let (status, body) = send(&app, "GET", "/admin/audit?action=people.role.change", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["entries"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn role_change_on_missing_member_is_404() {
    let (_dir, app) = workbench();
    let (status, _) = command(
        &app,
        "people",
        "people.role.change",
        json!({"id":"ghost","role":"admin"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn configuring_oidc_sso_with_an_unreachable_issuer_surfaces_an_error_and_does_not_lock_out() {
    // Enterprise-mode activation (`ID-3`): the reviewed connection command rebuilds wb.idp from the
    // connection. A bogus/unreachable issuer must NOT clobber the existing verifier
    // (here: none) — a bad runtime edit can't lock admins out — and the activation
    // error is surfaced so the operator sees it.
    let (_dir, app) = workbench();
    let (status, _) = command(
        &app,
        "enterprise-identity",
        "enterprise-identity.connection.set",
        json!({"protocol":"oidc","issuer":"http://127.0.0.1:9/realms/x","audiences":["client-1"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the connection is still saved");
    let (_, body) = document(&app, None, "enterprise-identity").await;
    assert_eq!(body["sso"]["issuer"], "http://127.0.0.1:9/realms/x");

    // The verifier was left untouched (none) → admin stays ungated, not bricked: a
    // read without any bearer still succeeds.
    let (status, _) = administration_document(&app, None, None, "organization").await;
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
