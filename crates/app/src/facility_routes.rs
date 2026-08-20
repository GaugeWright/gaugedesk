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
        .route("/account/facilities/{id}", delete(delete_facility))
        // The tenant switcher (ADR 0077 §9): the person's tenants. Empty on the solo desktop
        // path (no personal tenant is provisioned there) — that is the org-free solo shape.
        .route("/account/tenants", get(get_tenants).post(post_tenant))
        // The counterpart to the create above. Without it an organization made
        // by mistake was permanent — see `delete_tenant`.
        .route("/account/tenants/{id}", delete(delete_tenant))
        // Invitation truth stays in each tenant directory. These account routes
        // expose/accept only the current person's metadata pointer.
        .route("/account/invitations", get(get_invitations))
        .route(
            "/account/invitations/{tenant}/accept",
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
    // A retry must not become a second organization. Every other account
    // mutation is keyed by a caller-supplied id and upserts, so a repeat is
    // harmless; this route mints a fresh random id, so a repeat is a *new*
    // organization the caller never asked for. A synthetic account accumulated
    // nineteen identical organizations this way, one per retry, and at the time
    // could shed none of them — `delete_tenant` now exists, but a duplicate
    // nobody notices is still a duplicate nobody deletes.
    //
    // The key is honoured only when the caller sends one. The browser console
    // sends none today, so requiring one would refuse every organization it
    // creates; an absent key keeps exactly the old behaviour.
    let idempotency_key = match headers
        .get("idempotency-key")
        .map(|value| value.to_str().unwrap_or_default().trim())
    {
        None => None,
        Some(key) if key.is_empty() || key.len() > 200 => {
            return (
                StatusCode::BAD_REQUEST,
                "Idempotency-Key must be 1..200 characters",
            )
                .into_response()
        }
        Some(key) => Some(key.to_owned()),
    };
    if let Some(key) = &idempotency_key {
        match crate::tenancy::organization_claimed_by(wb.store_ref(), &account_scope, key) {
            // `200`, not `201`: this call created nothing.
            Ok(Some(tenant)) => {
                return (StatusCode::OK, Json(json!({ "tenant": tenant }))).into_response()
            }
            Ok(None) => {}
            Err(e) => return err_response(e),
        }
    }
    match crate::tenancy::provision_organization(
        wb.store_mut(),
        &actor,
        &account_scope,
        display_name,
        idempotency_key.as_deref(),
    ) {
        Ok(tenant) => (StatusCode::CREATED, Json(json!({ "tenant": tenant }))).into_response(),
        Err(e) => err_response(e),
    }
}

/// Delete one organization the caller owns and is alone in.
///
/// Nothing removed an organization before this. `leave-organization` refuses a
/// sole active owner so an organization cannot be orphaned, which left the
/// person who created one as the only person who could neither leave it nor
/// remove it — a mistyped name was permanent. One account accumulated nineteen
/// identical organizations from a retry bug and could shed none of them.
///
/// It refuses while any other active member remains, so a delete can never
/// silently revoke someone else's access, and while any tenant-level facility is
/// still active, so a billable standing service is never orphaned past the
/// tenant that pays for it. The refusals are distinct statuses because each is a
/// different thing to do next: leave the others first, detach the facilities,
/// ask an owner, or you are not in this organization at all.
pub async fn delete_tenant(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    use crate::tenancy::DeleteOrganizationRefusal as Refusal;
    let mut wb = wb.lock_unpoisoned();
    let account_scope = wb.account_scope_for(net_http::bearer(&headers));
    let actor = wb.actor(net_http::bearer(&headers));
    if actor == "anonymous" {
        return (
            StatusCode::UNAUTHORIZED,
            "authenticate to delete an organization",
        )
            .into_response();
    }
    // Deleting also crypto-erases the tenant scope's content (SOC 2 finding 4.5 /
    // DR-0086): the command tombstones the org/membership/switcher records, then the
    // tenant scope's per-scope content DEK is destroyed so those now-encrypted-at-rest
    // records become permanently unrecoverable rather than merely tombstoned.
    match wb.delete_organization_in(&actor, &account_scope, &id) {
        Ok(Ok(_)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(Refusal::NoSuchOrganization)) => {
            (StatusCode::NOT_FOUND, "no such organization").into_response()
        }
        Ok(Err(Refusal::Personal)) => (
            StatusCode::CONFLICT,
            "Personal is your own space and cannot be deleted",
        )
            .into_response(),
        Ok(Err(Refusal::NotAnOwner)) => (
            StatusCode::FORBIDDEN,
            "only an active owner can delete an organization",
        )
            .into_response(),
        Ok(Err(Refusal::OtherMembersRemain(_))) => (
            StatusCode::CONFLICT,
            "every other member must leave before this organization can be deleted",
        )
            .into_response(),
        Ok(Err(Refusal::FacilitiesRemain(_))) => (
            StatusCode::CONFLICT,
            "detach this organization's facilities before deleting it",
        )
            .into_response(),
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
        let store = gaugedesk_store::Store::open_in_memory().unwrap();
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

    async fn create_tenant(app: &Router, name: &str, key: Option<&str>) -> (StatusCode, String) {
        let mut rb = Request::builder()
            .method("POST")
            .uri("/account/tenants")
            .header("content-type", "application/json");
        if let Some(key) = key {
            rb = rb.header("idempotency-key", key);
        }
        let req = rb
            .body(Body::from(format!(r#"{{"display_name":"{name}"}}"#)))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    fn urlencoding(id: &str) -> String {
        id.replace(':', "%3A")
    }

    fn tenant_id(body: &str) -> String {
        let value: serde_json::Value = serde_json::from_str(body).unwrap();
        value["tenant"]["id"].as_str().unwrap().to_owned()
    }

    /// A retried create must not become a second organization.
    ///
    /// This route mints a fresh random id, so unlike every other account
    /// mutation — all keyed by a caller-supplied id, so all upserts — a repeat
    /// here is a *new* organization the caller never asked for and cannot
    /// remove, because no route deletes one. A synthetic account accumulated
    /// nine identical organizations this way before anyone looked.
    #[tokio::test]
    async fn a_repeated_idempotency_key_returns_the_first_organization() {
        let app = router();
        let (status, first) = create_tenant(&app, "Acme", Some("key-one")).await;
        assert_eq!(status, StatusCode::CREATED, "{first}");

        // `200`, not `201`: the retry created nothing.
        let (status, again) = create_tenant(&app, "Acme", Some("key-one")).await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(tenant_id(&first), tenant_id(&again));

        // A different key is a different organization, even with the same name.
        let (status, other) = create_tenant(&app, "Acme", Some("key-two")).await;
        assert_eq!(status, StatusCode::CREATED, "{other}");
        assert_ne!(tenant_id(&first), tenant_id(&other));

        // No key at all keeps the old behaviour, which the browser relies on:
        // it sends none, and refusing it would refuse every organization the
        // console creates.
        let (status, keyless) = create_tenant(&app, "Acme", None).await;
        assert_eq!(status, StatusCode::CREATED, "{keyless}");
        assert_ne!(tenant_id(&first), tenant_id(&keyless));

        let (_, listed) = send(&app, "GET", "/account/tenants", None).await;
        let value: serde_json::Value = serde_json::from_str(&listed).unwrap();
        assert_eq!(
            value["tenants"].as_array().unwrap().len(),
            3,
            "four creates, three organizations: {listed}",
        );
    }

    /// The route half: an organization the caller made can be removed again, and
    /// the switcher stops listing it.
    #[tokio::test]
    async fn an_organization_can_be_deleted_by_the_owner_who_is_alone_in_it() {
        let app = router();
        let (status, created) = create_tenant(&app, "Acme", None).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = tenant_id(&created);

        let uri = format!("/account/tenants/{}", urlencoding(&id));
        let (status, body) = send(&app, "DELETE", &uri, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "delete: {body}");

        let (_, listed) = send(&app, "GET", "/account/tenants", None).await;
        assert!(
            !listed.contains(&id),
            "the switcher still lists it: {listed}"
        );

        // Deleting it again reads as absent, not as a second success.
        let (status, _) = send(&app, "DELETE", &uri, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn deleting_an_organization_the_caller_is_not_in_is_a_404() {
        let app = router();
        let (status, _) = send(
            &app,
            "DELETE",
            "/account/tenants/organization%3Asomeone-else",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn an_unusable_idempotency_key_is_refused_rather_than_ignored() {
        let app = router();
        let (status, _) = create_tenant(&app, "Acme", Some("   ")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = create_tenant(&app, "Acme", Some(&"k".repeat(201))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
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
        let mut store = gaugedesk_store::Store::open_in_memory().unwrap();
        let actor = crate::LOCAL_AUTHORITY;
        let owner = "person:owner";
        let tenant = crate::tenancy::provision_organization(
            &mut store,
            owner,
            &crate::account::account_scope(owner),
            "Acme Studio",
            None,
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
