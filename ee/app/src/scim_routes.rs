//! SCIM 2.0 provisioning (M3 B13 / `SCIM-1`,`-2`,`-4`). The IdP drives membership
//! through a standard SCIM Users endpoint, authenticated by a **SCIM bearer token**
//! (issued/rotated by an admin, stored by hash only — `SEC-5`). Creating a user
//! provisions an active member; deactivating/deleting **deprovisions** them, which —
//! because [`Org::role_of`](gaugedesk_app::org::Org::role_of) only returns an *active*
//! member's role — immediately revokes their standing (the offboarding → access-
//! revoked chain, `SCIM-2`/`INV-18`).
//!
//! Users create / (PatchOp) replace-active / delete, plus token issue/rotate. The PATCH
//! endpoint accepts the strict RFC 7644 §3.5.2 SCIM **PatchOp envelope** (what Okta / Entra
//! send to deprovision) via [`parse_scim_patch`] as well as the legacy simplified body.
//! Groups (`SCIM-3`) and `GET /Users` filtering remain follow-ons; members provisioned here
//! are marked `managed_by_scim` so the console shows them read-only (B11).

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use gaugedesk_core::rbac::Capability;

use gaugedesk_app::org::{
    sha256_hex, MembershipRecord, MembershipStatus, Org, RecordOp, ScimTokenRecord, ORG_ID,
};
use gaugedesk_app::{LockUnpoisoned, SharedWorkbench, Workbench};

use crate::org_routes::{bearer, deny, write_membership};

fn default_true() -> bool {
    true
}

/// A fresh 256-bit bearer token, hex-encoded.
fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("CSPRNG");
    hex::encode(bytes)
}

/// Whether the request carries the org's current SCIM bearer token.
fn scim_authed(wb: &Workbench, headers: &HeaderMap) -> bool {
    // DEPLOY-6: validate the SCIM bearer against THIS tenant's stored token (the edge
    // resolves the tenant from the host → X-Gaugewright-Tenant), so one tenant's token
    // never authenticates against another's directory.
    match bearer(headers) {
        Some(token) => Org::rebuild_in(wb.store_ref(), &crate::org_routes::req_scope(headers))
            .map(|o| o.scim_token_valid(token))
            .unwrap_or(false),
        None => false,
    }
}

/// **SECAUD-8** (CC6.6/CC6.7): throttle then authenticate a SCIM request. A per-tenant
/// failed-attempt lockout (`429` when locked) wraps the bearer check (`401` on a bad
/// token); a success clears the tenant's failure count. Defense-in-depth behind the
/// edge rate-limit — a brute-force loop against one tenant's token is slowed without
/// locking out another tenant.
fn scim_guard(wb: &Workbench, headers: &HeaderMap) -> Result<(), (StatusCode, &'static str)> {
    let key = crate::org_routes::req_scope(headers);
    let throttle = wb.scim_throttle();
    let now = throttle.now_ms();
    if !throttle.allowed(&key, now) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed SCIM auth attempts; retry later",
        ));
    }
    if scim_authed(wb, headers) {
        throttle.record_success(&key);
        Ok(())
    } else {
        throttle.record_failure(&key, now);
        Err((StatusCode::UNAUTHORIZED, "invalid SCIM token"))
    }
}

/// Render a membership as a minimal SCIM User resource.
fn scim_user(rec: &MembershipRecord) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": rec.id,
        "userName": rec.email,
        "active": rec.status == MembershipStatus::Active,
    })
}

// ---- token issue / rotate (admin, B13) -----------------------------------

/// Issue (or rotate) the SCIM bearer token. Admin-gated (`ConfigureProvisioning`).
/// Returns the plaintext **once**; only its hash is stored, and rotating overwrites
/// the hash so any prior token stops authenticating (`SCIM-4`).
pub async fn post_scim_token(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, Some(Capability::ConfigureProvisioning)) {
        return resp;
    }
    let token = generate_token();
    let rec = ScimTokenRecord {
        id: ORG_ID.to_string(),
        op: RecordOp::Upsert,
        token_sha256: sha256_hex(&token),
    };
    let _ = wb.store_mut().append_record(
        &crate::org_routes::req_scope(&headers),
        "scim_token",
        &serde_json::to_string(&rec).unwrap(),
    );
    wb.notify_library_changed("scim_token", ORG_ID, "upsert");
    (StatusCode::OK, Json(json!({ "token": token }))).into_response()
}

// ---- SCIM Users (token-authenticated) ------------------------------------

/// A SCIM group reference (`{"value": "...", "display": "..."}`); we read whichever
/// name is present to match a configured group→role mapping.
#[derive(Deserialize)]
pub struct ScimGroupRef {
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    display: Option<String>,
}

#[derive(Deserialize)]
pub struct ScimUserBody {
    #[serde(rename = "userName")]
    user_name: String,
    #[serde(default = "default_true")]
    active: bool,
    /// The user's IdP groups, mapped to a role/team via `SCIM-3`.
    #[serde(default)]
    groups: Vec<ScimGroupRef>,
}

/// Provision a user: an active SCIM user becomes an active `member` (managed by the
/// IdP). The `userName` (email) is the stable id; if the user's groups match a
/// configured group→role mapping (`SCIM-3`), the member takes that role/team.
pub async fn post_scim_user(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<ScimUserBody>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Err((code, msg)) = scim_guard(&wb, &headers) {
        return (code, msg).into_response();
    }
    if body.user_name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "userName is required").into_response();
    }
    let mut rec = membership_from(&body.user_name, body.active);
    // SCIM-3: map the user's groups to a role/team if a mapping matches.
    let group_names: Vec<String> = body
        .groups
        .iter()
        .filter_map(|g| g.value.clone().or_else(|| g.display.clone()))
        .collect();
    let store_scope = crate::org_routes::req_scope(&headers);
    if let Ok(org) = Org::rebuild_in(wb.store_ref(), &store_scope) {
        if let Some((role, team)) = org.role_for_groups(&group_names) {
            rec.role = role;
            rec.team = team;
        }
    }
    write_membership(&mut wb, &store_scope, &rec);
    gaugedesk_app::audit::record_in(&mut wb, &store_scope, "scim", "scim.provision", &rec.id);
    (StatusCode::CREATED, Json(scim_user(&rec))).into_response()
}

/// Extract the target `active` state from a SCIM PATCH body (`SCIM-1`). Accepts the strict
/// RFC 7644 §3.5.2 **PatchOp envelope** —
/// `{"schemas":[…],"Operations":[{"op":"replace","path":"active","value":false}]}` — which is
/// what Okta / Entra actually send to deprovision; `path` may be omitted with
/// `value:{"active":false}`, `op` is case-insensitive, and `value` may be a JSON bool or the
/// string `"true"`/`"false"` (IdPs differ). For back-compat it also accepts the simplified
/// `{"active":false}` shape. Returns the resolved flag (last matching op wins) or an error
/// describing why no active-setting operation was found — pure, so it is unit-tested apart
/// from the route.
pub fn parse_scim_patch(body: &serde_json::Value) -> Result<bool, &'static str> {
    fn as_bool(v: &serde_json::Value) -> Option<bool> {
        v.as_bool().or_else(|| match v.as_str() {
            Some(s) if s.eq_ignore_ascii_case("true") => Some(true),
            Some(s) if s.eq_ignore_ascii_case("false") => Some(false),
            _ => None,
        })
    }
    if let Some(ops) = body.get("Operations").and_then(|o| o.as_array()) {
        let mut resolved = None;
        for op in ops {
            let verb = op.get("op").and_then(|o| o.as_str()).unwrap_or("");
            if !verb.eq_ignore_ascii_case("replace") && !verb.eq_ignore_ascii_case("add") {
                continue; // a `remove` (or unknown) op does not set `active` here
            }
            let path = op.get("path").and_then(|p| p.as_str()).unwrap_or("");
            let value = op.get("value");
            if path.eq_ignore_ascii_case("active") {
                if let Some(b) = value.and_then(as_bool) {
                    resolved = Some(b);
                }
            } else if path.is_empty() {
                // No path ⇒ the value is an attribute object, e.g. {"active": false}.
                if let Some(b) = value.and_then(|v| v.get("active")).and_then(as_bool) {
                    resolved = Some(b);
                }
            }
        }
        return resolved.ok_or("no active-setting replace/add operation in the PatchOp");
    }
    if let Some(b) = body.get("active").and_then(as_bool) {
        return Ok(b); // legacy simplified shape
    }
    Err("unrecognized SCIM PATCH body (expected a PatchOp envelope or {active})")
}

/// Replace a user's active flag — `active:false` deprovisions (revokes standing). Accepts the
/// strict SCIM PatchOp envelope (and the legacy simplified body), parsed by
/// [`parse_scim_patch`].
pub async fn patch_scim_user(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Err((code, msg)) = scim_guard(&wb, &headers) {
        return (code, msg).into_response();
    }
    let active = match parse_scim_patch(&body) {
        Ok(active) => active,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    set_active(
        &mut wb,
        &crate::org_routes::req_scope(&headers),
        &id,
        active,
    )
}

/// Delete a user — deprovisions them (offboarding → access-revoked, `SCIM-2`).
pub async fn delete_scim_user(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Err((code, msg)) = scim_guard(&wb, &headers) {
        return (code, msg).into_response();
    }
    set_active(&mut wb, &crate::org_routes::req_scope(&headers), &id, false)
}

fn membership_from(user_name: &str, active: bool) -> MembershipRecord {
    MembershipRecord {
        id: user_name.to_string(),
        op: RecordOp::Upsert,
        org_id: ORG_ID.to_string(),
        authority: user_name.to_string(),
        email: user_name.to_string(),
        role: "member".to_string(),
        status: if active {
            MembershipStatus::Active
        } else {
            MembershipStatus::Deprovisioned
        },
        managed_by_scim: true,
        team: None,
    }
}

/// Set a SCIM-managed member's active flag (deprovision when `false`). 404 if the
/// member is unknown.
fn set_active(wb: &mut Workbench, scope: &str, id: &str, active: bool) -> axum::response::Response {
    let org = match Org::rebuild_in(wb.store_ref(), scope) {
        Ok(org) => org,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
    };
    let Some(existing) = org.members.get(id) else {
        return (StatusCode::NOT_FOUND, "no such user").into_response();
    };
    let mut rec = existing.clone();
    rec.op = RecordOp::Upsert;
    rec.status = if active {
        MembershipStatus::Active
    } else {
        MembershipStatus::Deprovisioned
    };
    rec.managed_by_scim = true;
    write_membership(wb, scope, &rec);
    let action = if active {
        "scim.provision"
    } else {
        "scim.deprovision"
    };
    gaugedesk_app::audit::record_in(wb, scope, "scim", action, &rec.id);
    (StatusCode::OK, Json(scim_user(&rec))).into_response()
}

#[cfg(test)]
mod tests {
    use super::parse_scim_patch;
    use serde_json::json;

    #[test]
    fn strict_patchop_replace_active_by_path() {
        // What Okta / Entra send to deprovision.
        let body = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{ "op": "replace", "path": "active", "value": false }],
        });
        assert_eq!(parse_scim_patch(&body), Ok(false));
    }

    #[test]
    fn strict_patchop_replace_via_value_object_and_no_path() {
        let body = json!({
            "Operations": [{ "op": "replace", "value": { "active": true } }],
        });
        assert_eq!(parse_scim_patch(&body), Ok(true));
    }

    #[test]
    fn op_and_value_are_lenient() {
        // op is case-insensitive; value may be the string "False" (some IdPs stringify).
        let body =
            json!({ "Operations": [{ "op": "Replace", "path": "active", "value": "False" }] });
        assert_eq!(parse_scim_patch(&body), Ok(false));
    }

    #[test]
    fn last_active_operation_wins() {
        let body = json!({ "Operations": [
            { "op": "replace", "path": "active", "value": true },
            { "op": "replace", "path": "active", "value": false },
        ] });
        assert_eq!(parse_scim_patch(&body), Ok(false));
    }

    #[test]
    fn legacy_simplified_body_still_accepted() {
        assert_eq!(parse_scim_patch(&json!({ "active": false })), Ok(false));
    }

    #[test]
    fn a_patchop_with_no_active_operation_is_rejected() {
        // e.g. a displayName change we don't model — not a deprovision.
        let body =
            json!({ "Operations": [{ "op": "replace", "path": "displayName", "value": "X" }] });
        assert!(parse_scim_patch(&body).is_err());
        assert!(parse_scim_patch(&json!({ "foo": 1 })).is_err());
    }
}
