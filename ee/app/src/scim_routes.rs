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

use gaugedesk_core::ids::ScopeId;
use gaugedesk_core::rbac::Capability;
use gaugedesk_store::CommandRecordFact;

use gaugedesk_app::membership_fence::{
    committed_activation_fact, committed_denial_fact, denial_operation, membership_transitions,
    MembershipTransition, StandingFenceOutcome,
};
use gaugedesk_app::org::{
    sha256_hex, MembershipRecord, MembershipStatus, Org, RecordOp, ScimSyncError,
    ScimSyncOperation, ScimSyncRecord, ScimSyncStatus, ScimTokenRecord, ORG_ID, SCIM_SYNC_KIND,
};
use gaugedesk_app::{LockUnpoisoned, SharedWorkbench, Workbench};

use crate::org_routes::{bearer, deny, write_membership};

#[derive(Clone)]
enum ScimMembershipPlan {
    Create {
        subject: String,
        active: bool,
        groups: Vec<String>,
    },
    SetActive {
        subject: String,
        active: bool,
    },
}

impl ScimMembershipPlan {
    fn subject(&self) -> &str {
        match self {
            Self::Create { subject, .. } | Self::SetActive { subject, .. } => subject,
        }
    }

    fn active(&self) -> bool {
        match self {
            Self::Create { active, .. } | Self::SetActive { active, .. } => *active,
        }
    }

    fn operation(&self) -> ScimSyncOperation {
        scim_operation(self.active())
    }

    fn success_status(&self) -> StatusCode {
        match self {
            Self::Create { .. } => StatusCode::CREATED,
            Self::SetActive { .. } => StatusCode::OK,
        }
    }

    fn plan(
        &self,
        wb: &Workbench,
        scope: &str,
    ) -> Result<(MembershipRecord, Option<MembershipRecord>), ScimPlanFailure> {
        let org = Org::rebuild_in(wb.store_ref(), scope).map_err(|_| ScimPlanFailure {
            code: StatusCode::SERVICE_UNAVAILABLE,
            message: "membership state unavailable",
            error: ScimSyncError::Storage,
        })?;
        let rec = match self {
            Self::Create {
                subject,
                active,
                groups,
            } => {
                let mut rec = membership_from(subject, *active);
                if let Some((role, team)) = org.role_for_groups(groups) {
                    rec.role = role;
                    rec.team = team;
                }
                rec
            }
            Self::SetActive { subject, active } => {
                let Some(existing) = org.members.get(subject) else {
                    return Err(ScimPlanFailure {
                        code: StatusCode::NOT_FOUND,
                        message: "no such user",
                        error: ScimSyncError::UnknownUser,
                    });
                };
                let mut rec = existing.clone();
                rec.op = RecordOp::Upsert;
                rec.status = if *active {
                    MembershipStatus::Active
                } else {
                    MembershipStatus::Deprovisioned
                };
                rec.managed_by_scim = true;
                rec
            }
        };
        if rec.status == MembershipStatus::Active && !org.seat_available_for(&rec.id) {
            return Err(ScimPlanFailure {
                code: StatusCode::CONFLICT,
                message: "purchased seat capacity is full",
                error: ScimSyncError::SeatCapacity,
            });
        }
        let before = org.members.get(&rec.id).cloned();
        Ok((rec, before))
    }
}

struct ScimPlanFailure {
    code: StatusCode,
    message: &'static str,
    error: ScimSyncError,
}

enum PreparedStanding {
    Denial { operation: String },
    Activation { observed: serde_json::Value },
}

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

/// **SECAUD-8** (CC6.6/CC6.7): throttle then authenticate a SCIM request. A per-**client-IP**
/// failed-attempt lockout (`429` when locked) wraps the bearer check (`401` on a bad token); a
/// success clears that IP's failure count. Defense-in-depth behind the edge rate-limit — a
/// brute-force loop from one client IP is slowed without another client (or another tenant)
/// being lockable by it.
///
/// The key is the real client IP (`peer` resolves it via CF-Connecting-IP / socket peer),
/// **never** the client-supplied tenant header — that let an attacker rotate the header for a
/// fresh bucket per request, or spoof a victim's tenant to lock the victim out. `None` = the
/// client cannot be identified (no edge, no peer); the in-process backstop is skipped rather
/// than keyed on one shared bucket, and the edge stays the primary control.
fn scim_guard(
    wb: &Workbench,
    headers: &HeaderMap,
    peer: Option<std::net::IpAddr>,
) -> Result<(), (StatusCode, &'static str)> {
    let throttle = wb.scim_throttle();
    let Some(key) =
        crate::org_routes::throttle_scope(headers, peer, crate::org_routes::web_account_mode())
    else {
        // Unidentifiable client: authenticate without the lockout (the edge is the control).
        return if scim_authed(wb, headers) {
            Ok(())
        } else {
            Err((StatusCode::UNAUTHORIZED, "invalid SCIM token"))
        };
    };
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

const MAX_SCIM_SUBJECT_BYTES: usize = 320;

fn scim_subject(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= MAX_SCIM_SUBJECT_BYTES).then(|| value.to_owned())
}

fn scim_operation(active: bool) -> ScimSyncOperation {
    if active {
        ScimSyncOperation::Provision
    } else {
        ScimSyncOperation::Deprovision
    }
}

/// Record only authenticated, bounded SCIM operating evidence. Invalid bearer
/// attempts are deliberately absent: they neither identify a real IdP action
/// nor get to fill a customer's Administration surface with attacker traffic.
fn record_scim_sync(
    wb: &mut Workbench,
    scope: &str,
    operation: ScimSyncOperation,
    subject: Option<String>,
    error: Option<ScimSyncError>,
) {
    let status = if error.is_some() {
        ScimSyncStatus::Failed
    } else {
        ScimSyncStatus::Succeeded
    };
    let record = ScimSyncRecord {
        operation,
        subject: subject.clone(),
        status,
        error,
        observed_at_ms: gaugedesk_app::account::session_now_ms(),
    };
    let _ = wb.store_mut().append_record(
        scope,
        SCIM_SYNC_KIND,
        &serde_json::to_string(&record).expect("SCIM sync record serializes"),
    );
    wb.notify_library_changed(
        SCIM_SYNC_KIND,
        subject.as_deref().unwrap_or("request"),
        "upsert",
    );
}

/// Stage the exact SCIM membership command around the installed Cosmos fence.
/// The only remote calls run after the Workbench guard has been dropped.
async fn commit_scim_membership(
    wb: SharedWorkbench,
    headers: HeaderMap,
    scope: String,
    plan: ScimMembershipPlan,
) -> axum::response::Response {
    let (rec, scope_head, hook, key) = {
        let mut guard = wb.lock_unpoisoned();
        if !scim_authed(&guard, &headers) {
            return (StatusCode::UNAUTHORIZED, "invalid SCIM token").into_response();
        }
        let (rec, before) = match plan.plan(&guard, &scope) {
            Ok(planned) => planned,
            Err(failure) => {
                record_scim_sync(
                    &mut guard,
                    &scope,
                    plan.operation(),
                    Some(plan.subject().to_owned()),
                    Some(failure.error),
                );
                return (failure.code, failure.message).into_response();
            }
        };
        let Some(hook) = guard.member_standing_fence() else {
            if write_membership(&mut guard, &scope, &rec).is_err() {
                record_scim_sync(
                    &mut guard,
                    &scope,
                    plan.operation(),
                    Some(plan.subject().to_owned()),
                    Some(ScimSyncError::Storage),
                );
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "membership write unavailable",
                )
                    .into_response();
            }
            gaugedesk_app::audit::record_in(
                &mut guard,
                &scope,
                "scim",
                if plan.active() {
                    "scim.provision"
                } else {
                    "scim.deprovision"
                },
                &rec.id,
            );
            record_scim_sync(
                &mut guard,
                &scope,
                plan.operation(),
                Some(plan.subject().to_owned()),
                None,
            );
            return (plan.success_status(), Json(scim_user(&rec))).into_response();
        };
        let head = match guard.store_ref().record_scope_head(&scope) {
            Ok(head) => head,
            Err(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "membership state unavailable",
                )
                    .into_response()
            }
        };
        // A retry of an uncertain pre-Store denial must reuse its operation.
        // The prior member projection changes after a committed membership
        // mutation, so a later distinct transition gets a new command key.
        let key_basis = json!({"scope": scope, "before": before, "after": rec});
        let key = sha256_hex(&key_basis.to_string());
        (rec, head, hook, key)
    };

    let owner = ScopeId::from(scope.as_str());
    let membership_fact = CommandRecordFact {
        scope_id: scope.clone(),
        kind: "membership".into(),
        payload: serde_json::to_string(&rec).expect("SCIM membership serializes"),
    };
    let transition = {
        let guard = wb.lock_unpoisoned();
        match membership_transitions(
            guard.store_ref(),
            &owner,
            std::slice::from_ref(&membership_fact),
        ) {
            Ok(mut transitions) if transitions.len() == 1 => transitions.pop().unwrap(),
            _ => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "membership standing unavailable",
                )
                    .into_response()
            }
        }
    };
    let member = match &transition {
        MembershipTransition::Deny { member, .. }
        | MembershipTransition::Activate { member, .. } => member.clone(),
    };
    let command_scope = format!("gaugevault:membership:{scope}");
    let snapshot = membership_fact.payload.clone();
    let operation = denial_operation(&command_scope, &key, &snapshot);
    let remote_hook = hook.clone();
    let remote_owner = owner.clone();
    let remote_member = member.clone();
    let prepared = tokio::task::spawn_blocking(move || match transition {
        MembershipTransition::Deny { .. } => {
            match remote_hook
                .0
                .begin_denial(&remote_owner, &remote_member, &operation)
            {
                Ok(StandingFenceOutcome::Committed) => Ok(PreparedStanding::Denial { operation }),
                _ => Err(()),
            }
        }
        MembershipTransition::Activate { .. } => remote_hook
            .0
            .observe_activation(&remote_owner, &remote_member)
            .map(|observed| PreparedStanding::Activation { observed })
            .map_err(|_| ()),
    })
    .await;
    let Ok(Ok(prepared)) = prepared else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "membership standing unavailable",
        )
            .into_response();
    };

    {
        let mut guard = wb.lock_unpoisoned();
        if !scim_authed(&guard, &headers) {
            return (StatusCode::UNAUTHORIZED, "invalid SCIM token").into_response();
        }
        let replanned = match plan.plan(&guard, &scope) {
            Ok((rec, _)) => rec,
            Err(_) => {
                return (StatusCode::CONFLICT, "membership changed during request").into_response()
            }
        };
        if serde_json::to_string(&replanned).ok().as_deref() != Some(snapshot.as_str()) {
            return (StatusCode::CONFLICT, "membership changed during request").into_response();
        }
        let receipt = match &prepared {
            PreparedStanding::Denial { .. } => {
                committed_denial_fact(&command_scope, &key, &snapshot, &owner, &member)
            }
            PreparedStanding::Activation { observed } => committed_activation_fact(
                &command_scope,
                &key,
                &snapshot,
                &owner,
                &member,
                observed.clone(),
            ),
        };
        if guard
            .store_mut()
            .admit_record_facts_at_scope_head(
                &command_scope,
                &key,
                &snapshot,
                &[membership_fact, receipt],
                &scope,
                scope_head,
            )
            .is_err()
        {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "membership write unavailable",
            )
                .into_response();
        }
        guard.notify_library_changed("membership", &rec.id, "upsert");
        gaugedesk_app::audit::record_in(
            &mut guard,
            &scope,
            "scim",
            if plan.active() {
                "scim.provision"
            } else {
                "scim.deprovision"
            },
            &rec.id,
        );
    }

    let remote_hook = hook.clone();
    let remote_owner = owner.clone();
    let remote_member = member.clone();
    let finished = tokio::task::spawn_blocking(move || match prepared {
        PreparedStanding::Denial { operation } => {
            remote_hook
                .0
                .complete_denial(&remote_owner, &remote_member, &operation)
        }
        PreparedStanding::Activation { observed } => {
            remote_hook
                .0
                .admit_if_unchanged(&remote_owner, &remote_member, &observed)
        }
    })
    .await;
    let mut guard = wb.lock_unpoisoned();
    let success = matches!(finished, Ok(Ok(StandingFenceOutcome::Committed)));
    record_scim_sync(
        &mut guard,
        &scope,
        plan.operation(),
        Some(plan.subject().to_owned()),
        (!success).then_some(ScimSyncError::Storage),
    );
    if success {
        (plan.success_status(), Json(scim_user(&rec))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "membership standing unavailable",
        )
            .into_response()
    }
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
    crate::org_routes::PeerIp(peer): crate::org_routes::PeerIp,
    headers: HeaderMap,
    Json(body): Json<ScimUserBody>,
) -> impl IntoResponse {
    let store_scope = crate::org_routes::req_scope(&headers);
    let subject = {
        let mut guard = wb.lock_unpoisoned();
        if let Err((code, msg)) = scim_guard(&guard, &headers, peer) {
            return (code, msg).into_response();
        }
        let Some(subject) = scim_subject(&body.user_name) else {
            record_scim_sync(
                &mut guard,
                &store_scope,
                scim_operation(body.active),
                None,
                Some(ScimSyncError::InvalidUserName),
            );
            return (
                StatusCode::BAD_REQUEST,
                "userName is required and must be bounded",
            )
                .into_response();
        };
        subject
    };
    let groups = body
        .groups
        .into_iter()
        .filter_map(|g| g.value.or(g.display))
        .collect();
    commit_scim_membership(
        wb,
        headers,
        store_scope,
        ScimMembershipPlan::Create {
            subject,
            active: body.active,
            groups,
        },
    )
    .await
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
    crate::org_routes::PeerIp(peer): crate::org_routes::PeerIp,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let scope = crate::org_routes::req_scope(&headers);
    let (subject, active) = {
        let mut guard = wb.lock_unpoisoned();
        if let Err((code, msg)) = scim_guard(&guard, &headers, peer) {
            return (code, msg).into_response();
        }
        let Some(subject) = scim_subject(&id) else {
            record_scim_sync(
                &mut guard,
                &scope,
                ScimSyncOperation::Provision,
                None,
                Some(ScimSyncError::InvalidUserName),
            );
            return (
                StatusCode::BAD_REQUEST,
                "user id is required and must be bounded",
            )
                .into_response();
        };
        let active = match parse_scim_patch(&body) {
            Ok(active) => active,
            Err(msg) => {
                record_scim_sync(
                    &mut guard,
                    &scope,
                    ScimSyncOperation::Update,
                    Some(subject),
                    Some(ScimSyncError::UnsupportedChange),
                );
                return (StatusCode::BAD_REQUEST, msg).into_response();
            }
        };
        (subject, active)
    };
    commit_scim_membership(
        wb,
        headers,
        scope,
        ScimMembershipPlan::SetActive { subject, active },
    )
    .await
}

/// Delete a user — deprovisions them (offboarding → access-revoked, `SCIM-2`).
pub async fn delete_scim_user(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    crate::org_routes::PeerIp(peer): crate::org_routes::PeerIp,
    headers: HeaderMap,
) -> impl IntoResponse {
    let scope = crate::org_routes::req_scope(&headers);
    let subject = {
        let mut guard = wb.lock_unpoisoned();
        if let Err((code, msg)) = scim_guard(&guard, &headers, peer) {
            return (code, msg).into_response();
        }
        let Some(subject) = scim_subject(&id) else {
            record_scim_sync(
                &mut guard,
                &scope,
                ScimSyncOperation::Deprovision,
                None,
                Some(ScimSyncError::InvalidUserName),
            );
            return (
                StatusCode::BAD_REQUEST,
                "user id is required and must be bounded",
            )
                .into_response();
        };
        subject
    };
    commit_scim_membership(
        wb,
        headers,
        scope,
        ScimMembershipPlan::SetActive {
            subject,
            active: false,
        },
    )
    .await
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
