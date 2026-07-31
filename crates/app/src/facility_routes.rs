//! The facility + tenant-switcher route surface (`ADR 0077` §7/§9): the operator's own
//! account-level facilities (attach / list / detach) and their tenant switcher, over the
//! reserved `account` scope. Like [`crate::account_routes`], these act on the operator's *own*
//! account, so they are **ungated on the loopback desktop** — the operator is the account owner.
//!
//! The hosted control-plane hub layers login (Google OIDC first), sessions, and the per-tenant
//! **role-gate** for *managing* tenant-level facilities on top of this surface; *using* a facility
//! is a separate resource grant (the manage-vs-use split, ADR 0077 §8). This module is only the
//! account-owner half — the reusable, testable base the hub wraps.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::facility::{FacilityKind, FacilityOwner, FacilityRecord, FacilityStatus};
use crate::{err_response, net_http, LockUnpoisoned, SharedWorkbench};

/// The account-owner facility + tenant routes (ungated on loopback; the hub adds auth on top).
pub fn routes() -> Router<SharedWorkbench> {
    Router::new()
        .route(
            "/account/facilities",
            get(get_facilities).post(post_facility),
        )
        .route("/account/facilities/:id", delete(delete_facility))
        // The tenant switcher (ADR 0077 §9): the person's tenants. Empty on the solo desktop
        // path (no personal tenant is provisioned there) — that is the org-free solo shape.
        .route("/account/tenants", get(get_tenants).post(post_tenant))
        // Invitation truth stays in each tenant directory. These account routes
        // expose/accept only the current person's metadata pointer.
        .route("/account/invitations", get(get_invitations))
        .route(
            "/account/invitations/:tenant/accept",
            post(post_accept_invitation),
        )
}

/// The caller's account-level facilities (scoped to the authenticated person on the hub).
pub async fn get_facilities(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    match wb.account_facilities_in(&scope) {
        Ok(facilities) => {
            let list: Vec<&FacilityRecord> = facilities.facilities.values().collect();
            (StatusCode::OK, Json(json!({ "facilities": list }))).into_response()
        }
        Err(e) => err_response(e),
    }
}

#[derive(Deserialize)]
pub struct AttachBody {
    id: String,
    #[serde(default)]
    kind: FacilityKind,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    config: serde_json::Value,
}

/// Attach (or update) one account-level facility. `owner` is always `person` here — these follow
/// the operator into every tenant; tenant-level facilities are attached through the hub.
pub async fn post_facility(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<AttachBody>,
) -> impl IntoResponse {
    if body.id.trim().is_empty() {
        return (StatusCode::UNPROCESSABLE_ENTITY, "facility id is required").into_response();
    }
    let record = FacilityRecord {
        id: body.id,
        op: crate::facility::RecordOp::Upsert,
        kind: body.kind,
        owner: FacilityOwner::Person,
        status: FacilityStatus::Active,
        display_name: body.display_name,
        config: body.config,
    };
    let mut wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    if let Err(e) = wb.upsert_account_facility_in(&scope, &record) {
        return err_response(e);
    }
    (StatusCode::OK, Json(json!({ "facility": record }))).into_response()
}

/// Detach (tombstone) one account-level facility — future-only revocation (`INV-18`).
pub async fn delete_facility(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    match wb.revoke_account_facility_in(&scope, &id) {
        Ok(Some(record)) => (StatusCode::OK, Json(json!({ "facility": record }))).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no such facility").into_response(),
        Err(e) => err_response(e),
    }
}

/// The caller's tenant switcher (scoped to the authenticated person on the hub).
pub async fn get_tenants(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    match wb.account_tenancy_in(&scope) {
        Ok(tenancy) => {
            let list: Vec<_> = tenancy.tenants.values().collect();
            (StatusCode::OK, Json(json!({ "tenants": list }))).into_response()
        }
        Err(e) => err_response(e),
    }
}

#[derive(Deserialize)]
pub struct CreateTenantBody {
    display_name: String,
}

/// Create a named organization for the authenticated account. The command writes only the new
/// tenant directory and this person's own switcher projection: it cannot invite a member, attach
/// a facility, or select a Home.
pub async fn post_tenant(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<CreateTenantBody>,
) -> impl IntoResponse {
    let display_name = body.display_name.trim();
    if display_name.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "organization name is required",
        )
            .into_response();
    }
    if display_name.chars().count() > 120 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "organization name must be at most 120 characters",
        )
            .into_response();
    }
    let mut wb = wb.lock_unpoisoned();
    let account_scope = wb.account_scope_for(net_http::bearer(&headers));
    let actor = wb.actor(net_http::bearer(&headers));
    if actor == "anonymous" {
        return (
            StatusCode::UNAUTHORIZED,
            "authenticate to create an organization",
        )
            .into_response();
    }
    match crate::tenancy::provision_organization(
        wb.store_mut(),
        &actor,
        &account_scope,
        display_name,
    ) {
        Ok(tenant) => (StatusCode::CREATED, Json(json!({ "tenant": tenant }))).into_response(),
        Err(e) => err_response(e),
    }
}

/// The current person's pending tenant invitations. This projection contains
/// workspace metadata only; membership records stay in their owning tenant.
pub async fn get_invitations(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let actor = wb.actor(net_http::bearer(&headers));
    if actor == "anonymous" {
        return (StatusCode::UNAUTHORIZED, "authenticate to view invitations").into_response();
    }
    match crate::tenancy::pending_tenant_invitations_in(wb.store_ref(), &actor) {
        Ok(invitations) => {
            (StatusCode::OK, Json(json!({ "invitations": invitations }))).into_response()
        }
        Err(e) => err_response(e),
    }
}

/// Accept exactly one invitation for the signed-in identity. The path contains
/// no role or other authority-bearing input; the tenancy command re-reads the
/// tenant directory and performs membership promotion plus switcher indexing in
/// one store transaction.
pub async fn post_accept_invitation(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Path(tenant): Path<String>,
) -> impl IntoResponse {
    if tenant.trim().is_empty() {
        return (StatusCode::NOT_FOUND, "invitation not found").into_response();
    }
    let mut wb = wb.lock_unpoisoned();
    let actor = wb.actor(net_http::bearer(&headers));
    if actor == "anonymous" {
        return (
            StatusCode::UNAUTHORIZED,
            "authenticate to accept an invitation",
        )
            .into_response();
    }
    match crate::tenancy::accept_tenant_invitation_in(wb.store_mut(), &actor, &tenant) {
        Ok(Some(tenant)) => (StatusCode::OK, Json(json!({ "tenant": tenant }))).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "invitation not found").into_response(),
        Err(e) => err_response(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Workbench;
    use axum::body::Body;
    use axum::http::Request;
    use axum::Router;
    use http_body_util::BodyExt;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    fn router_with(wb: SharedWorkbench) -> Router {
        routes().with_state(wb)
    }

    fn router() -> Router {
        let store = gaugewright_store::Store::open_in_memory().unwrap();
        let wb: SharedWorkbench = Arc::new(Mutex::new(Workbench::new(store)));
        router_with(wb)
    }

    async fn send(
        app: &Router,
        method: &str,
        uri: &str,
        body: Option<&str>,
    ) -> (StatusCode, String) {
        let mut rb = Request::builder().method(method).uri(uri);
        if body.is_some() {
            rb = rb.header("content-type", "application/json");
        }
        let req = rb
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn attach_lists_then_detach() {
        let app = router();
        // empty to start.
        let (s, b) = send(&app, "GET", "/account/facilities", None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(b.contains("\"facilities\":[]"), "empty list: {b}");

        // attach library sync.
        let (s, b) = send(
            &app,
            "POST",
            "/account/facilities",
            Some(r#"{"id":"lib","kind":"library_sync","display_name":"Library sync"}"#),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "attach: {b}");

        // it lists.
        let (_, b) = send(&app, "GET", "/account/facilities", None).await;
        assert!(b.contains("\"id\":\"lib\""), "lists the facility: {b}");
        assert!(b.contains("library_sync") && b.contains("\"owner\":\"person\""));

        // detach it.
        let (s, _) = send(&app, "DELETE", "/account/facilities/lib", None).await;
        assert_eq!(s, StatusCode::OK);
        let (_, b) = send(&app, "GET", "/account/facilities", None).await;
        assert!(b.contains("\"facilities\":[]"), "empty after detach: {b}");

        // detaching a missing one is a 404.
        let (s, _) = send(&app, "DELETE", "/account/facilities/lib", None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn attach_requires_an_id() {
        let app = router();
        let (s, _) = send(&app, "POST", "/account/facilities", Some(r#"{"id":"  "}"#)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn tenants_is_empty_on_the_solo_path() {
        // No personal tenant is provisioned on desktop (provisioning runs in the hub login flow),
        // so the switcher is empty — the org-free solo shape (ADR 0061).
        let app = router();
        let (s, b) = send(&app, "GET", "/account/tenants", None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(b.contains("\"tenants\":[]"), "empty switcher: {b}");
    }

    #[tokio::test]
    async fn creates_a_named_organization_for_the_account_owner() {
        let app = router();
        let (status, body) = send(
            &app,
            "POST",
            "/account/tenants",
            Some(r#"{"display_name":"Acme Studio"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "create: {body}");
        assert!(
            body.contains("\"display_name\":\"Acme Studio\""),
            "tenant: {body}"
        );
        assert!(
            body.contains("\"role\":\"owner\""),
            "owner membership: {body}"
        );

        let (status, body) = send(&app, "GET", "/account/tenants", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("\"display_name\":\"Acme Studio\""),
            "switcher: {body}"
        );
    }

    #[tokio::test]
    async fn organization_name_is_required() {
        let app = router();
        let (status, _) = send(
            &app,
            "POST",
            "/account/tenants",
            Some(r#"{"display_name":"  "}"#),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn invitation_routes_expose_metadata_then_accept_exact_person() {
        let mut store = gaugewright_store::Store::open_in_memory().unwrap();
        let actor = crate::LOCAL_AUTHORITY;
        let owner = "person:owner";
        let tenant = crate::tenancy::provision_organization(
            &mut store,
            owner,
            &crate::account::account_scope(owner),
            "Acme Studio",
        )
        .unwrap();
        let membership = crate::org::MembershipRecord {
            id: actor.into(),
            op: crate::org::RecordOp::Upsert,
            org_id: crate::org::ORG_ID.into(),
            authority: actor.into(),
            email: "private@example.test".into(),
            role: "member".into(),
            status: crate::org::MembershipStatus::Invited,
            managed_by_scim: false,
            team: None,
        };
        store
            .append_record(
                &crate::org::tenant_scope(&tenant.id),
                "membership",
                &serde_json::to_string(&membership).unwrap(),
            )
            .unwrap();
        let wb: SharedWorkbench = Arc::new(Mutex::new(Workbench::new(store)));
        let app = router_with(wb);

        let (status, body) = send(&app, "GET", "/account/invitations", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Acme Studio"));
        assert!(!body.contains("private@example.test"));

        let uri = format!("/account/invitations/{}/accept", tenant.id);
        let (status, body) = send(&app, "POST", &uri, None).await;
        assert_eq!(status, StatusCode::OK, "accept: {body}");
        assert!(body.contains("\"role\":\"member\""));

        let (status, body) = send(&app, "GET", "/account/invitations", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"invitations\":[]"));
    }
}
