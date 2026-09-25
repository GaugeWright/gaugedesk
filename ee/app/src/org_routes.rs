//! Enterprise governance projections and external protocol routes (`ORG-1`,
//! B10/B11). Administration reads fold the tenant's records on demand (`INV-5`).
//! Durable human management writes are deliberately absent from `/admin/*`: they
//! enter through [`crate::gaugeapp_routes`], which binds the authenticated actor,
//! exact tenant scope, capability, document base, idempotency key, and review.
//! SCIM remains a separate external-actor protocol. Verified-domain JIT admission
//! happens inside the authenticated OIDC callback and has no public mutation route.
//!
//! All projections are capability-gated. The structural break-glass invariant still
//! requires at least one active owner (`ID-5`).

use axum::routing::{get, patch, post};
use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use gaugedesk_core::abac::Policy;
use gaugedesk_core::rbac::Capability;

use gaugedesk_app::org::{
    is_privileged_role, is_valid_role, tenant_scope, ArchetypeApprovalPolicyRecord,
    GroupMappingRecord, MemberGrantRecord, MembershipRecord, MembershipStatus, Org, OrgRecord,
    PolicyRecord, RecordOp, SecurityPolicyRecord, SoftwarePolicyRecord, SsoBrowserTestRecord,
    SsoConnectionRecord, SsoProtocol, ORG_ID, SSO_BROWSER_TEST_KIND,
};
use gaugedesk_app::{LockUnpoisoned, SharedWorkbench, Workbench};

/// The ee enterprise composition (SPLIT-1): the open route surface plus this
/// module's governance routes, wrapped in the same ENTSEC-1 auth route-layer /
/// CORS / HSTS ordering the hosted cross-band composition
/// (`gaugewright-cloud-server`) uses — minus the settlement, attestation, and
/// embed planes, which live in their own `cloud/` crates. Enterprise
/// integration tests compose against this.
///
/// Composition setup also runs enterprise-mode activation
/// ([`crate::auth_oidc::activate_configured_idp`]): the persisted Org SSO
/// connection attaches the OIDC verifier before any request is served — the
/// same pre-request timing the pre-split workbench-open activation had.
pub fn enterprise_control_plane(wb: SharedWorkbench) -> Router {
    {
        let mut guard = wb.lock_unpoisoned();
        // Also back-links legacy consumer sign-ins (GAUGEAPP-9) when Google is configured.
        crate::auth_oidc::activate_configured_idp(&mut guard);
    }
    // ENTSEC-1: the middleware needs its own handle to the workbench (the router
    // moves `wb` into `.with_state`).
    let auth_wb = wb.clone();
    let federation_on = {
        let g = wb.lock_unpoisoned();
        g.is_federation_enabled()
    };
    Router::new()
        .merge(gaugedesk_app::local_routes::routes(federation_on))
        .merge(gaugedesk_app::home_routes::routes())
        .merge(routes())
        // A shared authenticated process may expose person-scoped account
        // records and runtime credentials, but not sovereign library sync: that
        // operation signs/opens with the co-resident desktop's root key.
        .merge(gaugedesk_app::account_routes::hub_routes())
        .merge(gaugedesk_app::account_routes::runtime_credential_routes())
        // Native Desk reaches the independently deployed person account plane
        // through its co-resident sealed-session proxy. Hosted Cloud mounts the
        // real Account Settings handlers instead and never installs this route
        // set or marker.
        .merge(gaugedesk_app::account_signin::gaugeapp_proxy_routes())
        .merge(gaugedesk_app::facility_routes::routes())
        .merge(gaugedesk_app::mobile_machine_session::routes())
        // Materialize non-environment mutation idempotency inside the
        // enterprise identity boundary. An anonymous mutation must fail as
        // unauthenticated before request-shape or idempotency diagnostics reveal
        // anything about an admitted route.
        .layer(axum::middleware::from_fn_with_state(
            wb.clone(),
            gaugedesk_app::command_idempotency::guard,
        ))
        .route_layer(axum::middleware::from_fn_with_state(
            auth_wb,
            enterprise_auth,
        ))
        .layer(Extension(gaugedesk_app::account_signin::NativeAccountPlane))
        .layer(gaugedesk_app::net_http::cors_layer())
        .with_state(wb.clone())
        .layer(axum::middleware::from_fn(
            gaugedesk_app::net_http::security_headers,
        ))
}

/// Enterprise governance route surface: SSO/OIDC/SAML, SCIM,
/// RBAC, org policy, audit, security, and billing-seat administration. Always
/// the real routes — the `ee/` crate boundary is a capability boundary (ADR 0121), so
/// the old `featured_routes()` feature on/off wrapper collapsed with the
/// extraction. Mints one composition-scoped
/// [`AuthShellState`](crate::auth_oidc::AuthShellState) (the OIDC
/// pending-login store) and hands it to the `/auth/*` handlers as an
/// `Extension`, so the pending-login lifetime spans requests.
pub fn routes() -> Router<SharedWorkbench> {
    routes_with_auth_state(auth_shell_state())
}

/// One hosted composition owns one authentication shell. Cloud passes this
/// same handle to the login routes and Account Settings GaugeApp so transient
/// passkey ceremonies cannot split across two process-local stores.
pub fn auth_shell_state() -> crate::auth_oidc::AuthShellState {
    // The enterprise composition registers its login fold (ADR 0122 §3):
    // exact subject-to-account resolution plus the organization's explicit
    // invited-only, verified-domain JIT, or SCIM admission policy. The shell
    // verifies the assertion and mints a session only after this returns.
    crate::auth_oidc::AuthShellState::new()
        .with_login_fold(crate::login_fold::hub_login_fold())
        .with_enterprise_connection_test_fold(std::sync::Arc::new(fold_enterprise_connection_test))
}

/// Admit successful OIDC browser-test evidence without turning the verified
/// subject into a login or membership. The pending state proves who initiated
/// the test; this fold rechecks that actor's live capability and the exact
/// connection revision after the provider round trip.
fn fold_enterprise_connection_test(
    wb: &mut Workbench,
    pending: &crate::auth_oidc::PendingEnterpriseConnectionTest,
    verified: &crate::auth_oidc::VerifiedOidcIdentity,
) -> Result<(), String> {
    record_enterprise_connection_test(
        wb,
        pending,
        SsoProtocol::Oidc,
        &verified.authority,
        &verified.attributes,
    )
}

pub(crate) fn record_enterprise_connection_test(
    wb: &mut Workbench,
    pending: &crate::auth_oidc::PendingEnterpriseConnectionTest,
    protocol: SsoProtocol,
    authority: &gaugedesk_core::ids::AuthorityId,
    attributes: &gaugedesk_core::abac::AuthorityAttributes,
) -> Result<(), String> {
    let org = Org::rebuild_in(wb.store_ref(), &pending.store_scope)
        .map_err(|_| "organization directory unavailable".to_owned())?;
    let connection = org
        .sso
        .as_ref()
        .ok_or_else(|| "corporate sign-in is no longer configured".to_owned())?;
    if connection.id != pending.connection_id
        || connection.current_revision() != pending.connection_revision
        || connection.protocol != protocol
    {
        return Err("corporate sign-in changed during the browser test".to_owned());
    }
    let role = org
        .role_of(&pending.actor)
        .ok_or_else(|| "the initiating administrator is no longer active".to_owned())?;
    if !gaugedesk_core::rbac::role_can(&role, Capability::ConfigureSso) {
        return Err("the initiating administrator can no longer configure sign-in".to_owned());
    }
    let record = SsoBrowserTestRecord {
        id: pending.id.clone(),
        connection_id: pending.connection_id.clone(),
        connection_revision: pending.connection_revision.clone(),
        protocol,
        subject: authority.as_str().to_owned(),
        mapped_roles: attributes
            .roles
            .iter()
            .map(|role| role.as_str().to_owned())
            .collect(),
        mapped_region: attributes
            .region
            .as_ref()
            .map(|region| region.as_str().to_owned()),
        mapped_tenant: attributes
            .affiliation
            .as_ref()
            .map(|tenant| tenant.as_str().to_owned()),
        initiated_by: pending.actor.clone(),
        tested_at_ms: gaugedesk_app::account::session_now_ms(),
    };
    wb.store_mut()
        .append_record(
            &pending.store_scope,
            SSO_BROWSER_TEST_KIND,
            &serde_json::to_string(&record).map_err(|_| "test evidence did not serialize")?,
        )
        .map_err(|_| "test evidence could not be recorded".to_owned())?;
    gaugedesk_app::audit::record_in(
        wb,
        &pending.store_scope,
        &pending.actor,
        "enterprise-identity.connection.browser-tested",
        &pending.connection_id,
    );
    wb.notify_library_changed(SSO_BROWSER_TEST_KIND, &record.id, "append");
    Ok(())
}

pub fn routes_with_auth_state(
    enterprise_auth_state: crate::auth_oidc::AuthShellState,
) -> Router<SharedWorkbench> {
    let saml_state = crate::identity_saml::SamlBrowserState::default();
    let saml_login_state = saml_state.clone();
    let enterprise_auth_state =
        enterprise_auth_state.with_enterprise_saml_start(std::sync::Arc::new(move |request| {
            let base = request.public_base.clone();
            let sp = sp_entity_id(&base);
            let acs = format!("{base}/auth/saml/acs");
            saml_login_state
                .begin_login(request, &sp, &acs)
                .map(|launch| launch.launch_url)
                .map_err(|error| match error {
                    crate::identity_saml::SamlBrowserError::Metadata(error) => {
                        error.message().to_owned()
                    }
                    crate::identity_saml::SamlBrowserError::NotSaml => {
                        "the selected connection is not SAML".to_owned()
                    }
                    crate::identity_saml::SamlBrowserError::Request => {
                        "could not build the SAML sign-in request".to_owned()
                    }
                })
        }));
    Router::new()
        .merge(
            crate::gaugeapp_routes::routes()
                .layer(Extension(enterprise_auth_state.clone()))
                .layer(Extension(saml_state.clone())),
        )
        // Capability-gated entry to the Administration Environment (`ADMIN-ENV-2`).
        // This read is available to every authenticated active member; an incapable
        // role receives an empty list rather than access to another Admin surface.
        .route("/admin/capabilities", get(get_capabilities))
        // SP integration details (M3 ONB-1): the values an admin pastes into their IdP
        // (`/admin/integration`, console-gated) + the public SP metadata descriptor.
        .route("/admin/integration", get(get_integration))
        .route("/saml/metadata", get(get_saml_metadata))
        // SSO test-connection (M3 ONB-3): live OIDC discovery + JWKS reachability check.
        .route("/admin/sso/test", post(post_sso_test))
        // Per-actor audit timeline (M3 B14 / AUD-1, AUD-2): filterable + CSV export.
        .route("/admin/audit", get(get_audit_log))
        // Client/session compatibility floor (`ITGOV-4`). This exact route is
        // an authenticated recovery surface when the caller itself is blocked.
        .route("/admin/software-policy", get(get_software_policy))
        // Enrolled members must evaluate the tenant placement floor before pairing.
        // This is not an Administration projection: it is a client enforcement input.
        .route("/admin/placement-policy", get(get_placement_policy))
        // Member-readable picker projection for ordinary Project settings. The
        // Home, not this directory, owns the resulting project invitation.
        .route(
            "/account/tenants/{tenant}/project-share-candidates",
            get(get_project_share_candidates),
        )
        // The consumer login shell is core (ADR 0122); this composition mounts
        // it with the enterprise login fold registered above.
        .merge(crate::auth_oidc::auth_routes(enterprise_auth_state.clone()))
        .merge(
            crate::identity_saml::browser_routes()
                .layer(Extension(enterprise_auth_state))
                .layer(Extension(saml_state)),
        )
        // SCIM provisioning is an external protocol actor. Administration issues
        // its token and group mappings only through the shared Environment command path.
        .route("/scim/v2/Users", post(crate::scim_routes::post_scim_user))
        .route(
            "/scim/v2/Users/{id}",
            patch(crate::scim_routes::patch_scim_user).delete(crate::scim_routes::delete_scim_user),
        )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ProjectShareCandidate {
    authority: String,
    label: String,
}

fn project_share_candidates(org: &Org, actor: &str) -> Vec<ProjectShareCandidate> {
    let mut candidates: Vec<_> = org
        .members
        .values()
        .filter(|member| {
            member.status == MembershipStatus::Active
                && member.authority != actor
                && !member.authority.trim().is_empty()
        })
        .map(|member| ProjectShareCandidate {
            authority: member.authority.clone(),
            label: if member.email.trim().is_empty() {
                member.authority.clone()
            } else {
                member.email.clone()
            },
        })
        .collect();
    candidates.sort_by(|left, right| {
        left.label
            .to_lowercase()
            .cmp(&right.label.to_lowercase())
            .then_with(|| left.authority.cmp(&right.authority))
    });
    candidates
}

async fn get_project_share_candidates(
    State(wb): State<SharedWorkbench>,
    Path(tenant): Path<String>,
    Extension(actor): Extension<gaugedesk_app::identity::AuthenticatedActor>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if tenant_scope(&tenant) != req_scope(&headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "tenant mismatch" })),
        )
            .into_response();
    }
    match Org::rebuild_in(wb.store_ref(), &req_scope(&headers)) {
        Ok(org) => (
            StatusCode::OK,
            Json(json!({
                "candidates": project_share_candidates(&org, actor.0.as_str())
            })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "tenant directory unavailable" })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod project_share_directory_tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use gaugedesk_app::identity::LoopbackIdentityProvider;
    use gaugedesk_app::open_workbench;
    use gaugedesk_app::org::{MembershipRecord, MembershipStatus, Org, RecordOp};
    use gaugedesk_app::tenancy::provision_personal_tenant;
    use gaugedesk_app::LockUnpoisoned;
    use gaugedesk_core::abac::AuthorityAttributes;
    use gaugedesk_core::ids::AuthorityId;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::{
        enterprise_auth, get_project_share_candidates, project_share_candidates,
        ProjectShareCandidate,
    };

    fn member(authority: &str, email: &str, status: MembershipStatus) -> MembershipRecord {
        MembershipRecord {
            id: authority.into(),
            op: RecordOp::Upsert,
            org_id: "organization:example".into(),
            authority: authority.into(),
            email: email.into(),
            role: "member".into(),
            status,
            managed_by_scim: false,
            team: None,
        }
    }

    #[test]
    fn picker_projects_only_other_active_account_identities() {
        let org = Org {
            members: BTreeMap::from([
                (
                    "owner".into(),
                    member(
                        "authority:owner",
                        "owner@example.test",
                        MembershipStatus::Active,
                    ),
                ),
                (
                    "active".into(),
                    member(
                        "authority:active",
                        "active@example.test",
                        MembershipStatus::Active,
                    ),
                ),
                (
                    "inactive".into(),
                    member(
                        "authority:inactive",
                        "inactive@example.test",
                        MembershipStatus::Deprovisioned,
                    ),
                ),
            ]),
            ..Org::default()
        };
        assert_eq!(
            project_share_candidates(&org, "authority:owner"),
            vec![ProjectShareCandidate {
                authority: "authority:active".into(),
                label: "active@example.test".into(),
            },]
        );
    }

    #[tokio::test]
    async fn ordinary_active_members_can_read_the_picker_but_outsiders_cannot() {
        let root = tempfile::tempdir().unwrap();
        let workbench = open_workbench(root.path()).unwrap();
        let tenant = {
            let mut guard = workbench.lock_unpoisoned();
            guard.set_identity_provider(Some(Arc::new(
                LoopbackIdentityProvider::new()
                    .enroll(
                        "owner-login",
                        AuthorityId::new("authority:owner"),
                        AuthorityAttributes::default(),
                    )
                    .enroll(
                        "member-login",
                        AuthorityId::new("authority:member"),
                        AuthorityAttributes::default(),
                    )
                    .enroll(
                        "outsider-login",
                        AuthorityId::new("authority:outsider"),
                        AuthorityAttributes::default(),
                    ),
            )));
            let tenant = provision_personal_tenant(
                guard.store_mut(),
                "authority:owner",
                "Example Organization",
            )
            .unwrap();
            let member = member(
                "authority:member",
                "member@example.test",
                MembershipStatus::Active,
            );
            guard
                .store_mut()
                .append_record(
                    &gaugedesk_app::org::tenant_scope(&tenant),
                    "membership",
                    &serde_json::to_string(&MembershipRecord {
                        org_id: tenant.clone(),
                        ..member
                    })
                    .unwrap(),
                )
                .unwrap();
            tenant
        };
        let app = Router::new()
            .route(
                "/account/tenants/{tenant}/project-share-candidates",
                get(get_project_share_candidates),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                workbench.clone(),
                enterprise_auth,
            ))
            .with_state(workbench);
        let path = format!("/account/tenants/{tenant}/project-share-candidates");

        let response = app
            .clone()
            .oneshot(
                Request::get(&path)
                    .header("authorization", "Bearer member-login")
                    .header("x-gaugewright-tenant", &tenant)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["candidates"].as_array().unwrap().len(), 1);
        assert_eq!(value["candidates"][0]["authority"], "authority:owner");

        let forbidden = app
            .oneshot(
                Request::get(&path)
                    .header("authorization", "Bearer outsider-login")
                    .header("x-gaugewright-tenant", &tenant)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    }
}

// ---- helpers -------------------------------------------------------------

fn op_str(op: RecordOp) -> &'static str {
    match op {
        RecordOp::Upsert => "upsert",
        RecordOp::Tombstone => "tombstone",
    }
}

async fn get_capabilities(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let result = wb
        .lock_unpoisoned()
        .admin_capabilities(bearer(&headers), &req_scope(&headers));
    match result {
        Ok(capabilities) => {
            let capabilities = capabilities
                .into_iter()
                .map(Capability::as_str)
                .collect::<Vec<_>>();
            let mut agent_tools = Vec::new();
            if !capabilities.is_empty() {
                agent_tools.extend([
                    "admin.files.list",
                    "admin.files.read",
                    "admin.changes.propose",
                    "question.ask",
                ]);
                if capabilities
                    .iter()
                    .any(|capability| *capability != Capability::ManageBilling.as_str())
                {
                    agent_tools.insert(2, "admin.homes.query");
                }
            }
            (
                StatusCode::OK,
                Json(json!({
                    "capabilities": capabilities,
                    "agent": {
                        "message_attachments": false,
                        "additional_tools": false,
                        "tools": agent_tools
                    }
                })),
            )
                .into_response()
        }
        Err((status, message)) => (status, Json(json!({ "error": message }))).into_response(),
    }
}

/// The bearer credential from the `Authorization: Bearer <token>` header — the
/// open neutral parser, re-exported for this module's handlers and tests.
pub use gaugedesk_app::net_http::bearer;

/// The open admin-gate and tenant-scope substrate ([`gaugedesk_app::workbench_auth`]),
/// re-exported so the ee route surface and its sibling modules keep one import home.
/// The settlement plane (`gaugewright-cloud-settlement`) consumes the same seams
/// directly from the open crate.
pub use gaugedesk_app::workbench_auth::{
    deny, req_scope, throttle_scope, web_account_mode, PeerIp,
};

/// ENTSEC-1: paths that bypass the enterprise data-route auth gate — the pre-auth and
/// own-auth flows. `/health` (readiness), `/auth/*` (the OIDC login/callback that *mints* the
/// bearer), `/scim/*` (its own SCIM bearer token), `/saml/*` (IdP metadata/ACS), `/federation/*`
/// (cross-machine signed-envelope auth, not org-member bearers), and `/test/*` (env-gated reset).
/// The public embed/audience plane is merged AFTER this layer, so it is never wrapped and keeps
/// its own audience auth.
fn entsec_exempt(path: &str) -> bool {
    path == "/health"
        // What revision this Hub is serving. The four static surfaces publish the
        // same document at the same path with no credential, and a monitor
        // compares them; gating this one would mean the surface thirteen canary
        // suites address is the only one that cannot be asked. It carries a build
        // revision and nothing else -- no account, tenant or member state.
        || path == "/gaugewright-release.json"
        // Stripe authenticates delivery with its signed webhook header. The route must
        // reach that verifier without a browser/member bearer; it grants no account access.
        || path == "/stripe/webhook"
        || path == "/stripe/connect/webhook"
        || path.starts_with("/auth/")
        || path.starts_with("/scim/")
        || path.starts_with("/saml/")
        || path.starts_with("/federation/")
        // Ordinary Home invitation acceptance authenticates the account itself,
        // then atomically creates membership. It cannot require that membership
        // in this outer layer before its own authority-bound capability check.
        || path == "/home/invitations/accept"
        // Tenant invitations are account-owned metadata pointers. Their own
        // handlers authenticate the current person then atomically activate an
        // exact matching membership; requiring active membership here would make
        // an invitation impossible to accept.
        || path == "/account/invitations"
        || path.starts_with("/account/invitations/")
        // A commercial proposal link carries its own one-use recipient proof.
        // Preview grants only that proposal's commercial terms; acceptance
        // additionally verifies the addressed GaugeDesk account when present.
        // Requiring provider-tenant membership in this outer layer would hand
        // the acceptance boundary back to the provider or make it unreachable.
        || path == "/commercial/proposals/preview"
        || path == "/commercial/proposals/accept"
        // ADR 0109 pre-auth controller ceremony. Each route owns a one-use
        // invitation/challenge/credential proof and grants no account/admin API.
        || path == "/mobile/enrollment/claim"
        || path == "/mobile/enrollment/prove"
        || path == "/mobile/enrollment/status"
        || path == "/mobile/sessions/challenge"
        || path == "/mobile/sessions"
        || path.starts_with("/test/")
}

/// Exact Administration GaugeApp routes that rebuild the recovery-restricted
/// session before projecting or mutating anything. Keep this allowlist closed:
/// a future route under the same prefix must choose recovery deliberately.
fn administration_sso_recovery_path(path: &str) -> bool {
    matches!(
        path,
        "/gaugeapps/administration/sessions"
            | "/gaugeapps/administration/updates"
            | "/gaugeapps/administration/commands"
            | "/gaugeapps/administration/enterprise-identity/credential"
            | "/gaugeapps/administration/proposals"
            | "/gaugeapps/administration/agent/messages"
            | "/gaugeapps/administration/agent/events"
            | "/gaugeapps/administration/agent/stop"
            | "/gaugeapps/administration/agent/erase"
    ) || path.starts_with("/gaugeapps/administration/pages/")
        || (path.starts_with("/gaugeapps/administration/proposals/") && path.ends_with("/review"))
}

/// Person-owned account routes authenticate the GaugeDesk account but do not
/// require membership in whichever organization happens to be selected. The
/// project-share directory is the exception: it reads an exact tenant's member
/// roster and therefore stays on the ordinary organization gate. Tenant-bound
/// account commands (for example managed funding) perform their explicit role
/// check inside the handler against the person's admitted tenant index.
fn person_account_path(path: &str) -> bool {
    path.starts_with("/account/")
        && !path.ends_with("/project-share-candidates")
        && !path.starts_with("/account/hub-session")
}

/// ENTSEC-1 middleware ([ADR 0065]): in **enterprise mode** (an `IdentityProvider` is attached
/// and the directory is provisioned) every consultant route requires an authenticated active
/// member; **solo / loopback passes through** (the control-plane API is the local operator's own
/// channel). Exempt paths keep their own auth / pre-auth flow. Fail-closed (`INV-20`).
pub async fn enterprise_auth(
    axum::extract::State(wb): axum::extract::State<SharedWorkbench>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // CORS preflight carries no credentials — let it through (the CORS layer answers it).
    if req.method() == axum::http::Method::OPTIONS || entsec_exempt(req.uri().path()) {
        return next.run(req).await;
    }
    let request_path = req.uri().path();
    if !request_path.starts_with("/admin/")
        && !request_path.starts_with("/account/")
        && !request_path.starts_with("/auth/")
        && !request_path.starts_with("/mobile/")
    {
        if let Some(session) = gaugedesk_app::mobile_machine_session::session_token(req.headers()) {
            let grant = {
                let mut guard = wb.lock_unpoisoned();
                gaugedesk_app::mobile_machine_session::authorize_session(&mut guard, session)
            };
            if let Some(grant) = grant {
                req.extensions_mut()
                    .insert(gaugedesk_app::identity::AuthenticatedActor(
                        gaugedesk_core::ids::AuthorityId::new(grant.device.as_str()),
                    ));
                return next.run(req).await;
            }
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Machine controller session is expired or revoked" })),
            )
                .into_response();
        }
    }
    let bearer = bearer(req.headers()).map(str::to_owned);
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let client = gaugedesk_app::client_admission::ClientBuild::from_headers(req.headers());
    let org_scope = req_scope(req.headers());
    // Every active member must retain this authenticated recovery path so the
    // desktop updater can discover the policy that blocked its current build.
    // Tenant membership admission above is the complete authority check.
    let enforce_software = path != "/admin/software-policy";
    // Creating an organization belongs to the same sealed Hub account as the
    // picker membership projection, even when this desktop selected a Home.
    let native_account_path = path.starts_with("/gaugeapps/account-settings/")
        || (path == "/account/tenants" && method == axum::http::Method::POST)
        || matches!(
            path.as_str(),
            "/auth/account/authorization/start"
                | "/auth/account/authorization/finish"
                | "/auth/account/consumer-oidc/link/start"
                | "/auth/account/consumer-oidc/avatar/start"
        );
    if req
        .extensions()
        .get::<gaugedesk_app::account_signin::NativeAccountPlane>()
        .is_some()
        && native_account_path
        && bearer.is_none()
    {
        let Some(actor) = gaugedesk_app::account_signin::hub_session_actor(&wb) else {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "sign in to access Account Settings" })),
            )
                .into_response();
        };
        req.extensions_mut()
            .insert(gaugedesk_app::identity::AuthenticatedActor(
                gaugedesk_core::ids::AuthorityId::new(actor),
            ));
        return next.run(req).await;
    }
    if person_account_path(&path) {
        let actor = wb.lock_unpoisoned().actor(bearer.as_deref());
        if actor == "anonymous" {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "authenticate to access your account" })),
            )
                .into_response();
        }
        req.extensions_mut()
            .insert(gaugedesk_app::identity::AuthenticatedActor(
                gaugedesk_core::ids::AuthorityId::new(&actor),
            ));
        return next.run(req).await;
    }
    {
        let mut guard = wb.lock_unpoisoned();
        // ENTSEC-1 + ENTSEC-2 + SECAUD-7: one fold-once admission — authenticate the bearer,
        // confirm active membership, and (if the path is project-scoped) enforce the grant
        // (owner/admin bypass), all against a single consistent directory read. Returns the
        // resolved actor so the audit record below reuses it (no re-authenticate). Folding the
        // org twice opened a TOCTOU window between membership and scope (CC6.1).
        let project = guard.scope_project_of_path(&path);
        let actor = match guard.admit_data_request_with_client(
            bearer.as_deref(),
            project.as_deref(),
            &org_scope,
            client,
            enforce_software,
        ) {
            Ok(actor) => actor,
            Err((code, msg)) => {
                // Enforced-SSO break glass is intentionally smaller than
                // ordinary Home admission: only the Administration GaugeApp can
                // reach its own recovery projection. That adapter independently
                // restricts the session to Enterprise Identity + disable SSO.
                if administration_sso_recovery_path(&path) {
                    match guard.admit_sso_recovery(bearer.as_deref(), &org_scope) {
                        Ok(actor) => actor,
                        Err(_) => {
                            return (code, Json(json!({ "error": msg }))).into_response();
                        }
                    }
                } else {
                    return (code, Json(json!({ "error": msg }))).into_response();
                }
            }
        };
        // ENTSEC-4 (ADR 0065): audit data-route *actions* (mutating methods) to the org trail —
        // the "what did this consultant do" record (references only, `INV-10`). `/admin/*` audits
        // itself semantically, so it is not double-logged here. Solo (no IdP) writes nothing.
        // SECAUD-4 (CC7.2): when sensitive-read auditing is enabled, GET reads of *project-scoped*
        // data (transcripts/files/diffs/resource content — i.e. `project` resolved Some) are
        // recorded too, so "who read this client's data" is answerable; off by default (reads are
        // high-volume), so the nav/listing GETs (project None) are never logged.
        let is_admin = path.starts_with("/admin/");
        let mutating = method != axum::http::Method::GET;
        let sensitive_read = !mutating && project.is_some() && guard.audits_reads();
        if guard.has_idp() && !is_admin && (mutating || sensitive_read) {
            gaugedesk_app::audit::record_in(
                &mut guard,
                &org_scope,
                &actor,
                &format!("{method} {path}"),
                &path,
            );
        }
        req.extensions_mut()
            .insert(gaugedesk_app::identity::AuthenticatedActor(actor.into()));
    }
    next.run(req).await
}

fn write_org(wb: &mut Workbench, scope: &str, r: &OrgRecord) {
    let op = op_str(r.op);
    let _ = wb
        .store_mut()
        .append_record(scope, "org", &serde_json::to_string(r).unwrap());
    wb.notify_library_changed("org", &r.id, op);
}

pub(crate) fn write_membership(wb: &mut Workbench, scope: &str, r: &MembershipRecord) {
    let op = op_str(r.op);
    let _ = wb
        .store_mut()
        .append_record(scope, "membership", &serde_json::to_string(r).unwrap());
    wb.notify_library_changed("membership", &r.id, op);
}

fn write_policy(wb: &mut Workbench, scope: &str, r: &PolicyRecord) {
    let op = op_str(r.op);
    let _ = wb
        .store_mut()
        .append_record(scope, "policy", &serde_json::to_string(r).unwrap());
    wb.notify_library_changed("policy", &r.id, op);
}

fn unprocessable(msg: &str) -> axum::response::Response {
    (StatusCode::UNPROCESSABLE_ENTITY, msg.to_string()).into_response()
}

// ---- org settings (B10) --------------------------------------------------

pub async fn get_org(State(wb): State<SharedWorkbench>, headers: HeaderMap) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, None) {
        return resp;
    }
    match Org::rebuild_in(wb.store_ref(), &req_scope(&headers)) {
        Ok(org) => (StatusCode::OK, Json(json!({ "org": org.org }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
    }
}

// `post_org` stood here as the `/admin/org` façade. The route is retired — see
// `retired_legacy_management_facades_are_unreachable` — and the handler was left
// behind unmounted, carrying the same all-optional body that let an incomplete
// payload blank the org. GaugeApp now exposes narrow named operations such as
// `organization.display-name.set`, which preserves every field it does not own.

// ---- members (B11) -------------------------------------------------------

pub async fn get_members(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, None) {
        return resp;
    }
    match Org::rebuild_in(wb.store_ref(), &req_scope(&headers)) {
        Ok(org) => {
            let members: Vec<&MembershipRecord> = org.members.values().collect();
            (StatusCode::OK, Json(json!({ "members": members }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
    }
}

/// `GET /admin/sessions` (`ITGOV-2`) — the live **IT session roster**: which members are
/// currently active (authority, age, idle), recorded by the data-route admission. Console-read
/// gated; never exposes a bearer. Empty until members make authenticated data requests.
pub async fn get_sessions(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, None) {
        return resp;
    }
    (
        StatusCode::OK,
        Json(json!({ "sessions": wb.session_roster() })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct InviteBody {
    /// Stable member id; defaults to the authority string.
    #[serde(default)]
    id: Option<String>,
    authority: String,
    #[serde(default)]
    email: String,
    role: String,
    #[serde(default)]
    status: Option<MembershipStatus>,
    #[serde(default)]
    managed_by_scim: bool,
    #[serde(default)]
    team: Option<String>,
}

pub async fn post_member(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<InviteBody>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, Some(Capability::ManageMembers)) {
        return resp;
    }
    if !is_valid_role(&body.role) {
        return unprocessable(&format!("unknown role {:?}", body.role));
    }
    // ADR 0149 §1: inviting a member directly into a privileged role (`owner`/`admin`)
    // is a role grant, which requires the owner-only `GrantPrivilegedRoles` capability
    // in addition to `ManageMembers`. An admin (which lacks it) cannot seed a privileged
    // principal; fail-closed.
    if is_privileged_role(&body.role) {
        if let Some(resp) = deny(&wb, &headers, Some(Capability::GrantPrivilegedRoles)) {
            return resp;
        }
    }
    if body.authority.trim().is_empty() {
        return unprocessable("authority is required");
    }
    let record = MembershipRecord {
        id: body.id.unwrap_or_else(|| body.authority.clone()),
        op: RecordOp::Upsert,
        org_id: ORG_ID.to_string(),
        authority: body.authority,
        email: body.email,
        role: body.role,
        // Default a freshly-added member to Invited (operational, not yet truth);
        // an explicit status (e.g. SCIM creating an Active member) overrides.
        status: body.status.unwrap_or(MembershipStatus::Invited),
        managed_by_scim: body.managed_by_scim,
        team: body.team,
    };
    let scope = req_scope(&headers);
    if record.status == MembershipStatus::Active {
        let org = match Org::rebuild_in(wb.store_ref(), &scope) {
            Ok(org) => org,
            Err(error) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{error:?}")).into_response()
            }
        };
        if !org.seat_available_for(&record.id) {
            return (StatusCode::CONFLICT, "purchased seat capacity is full").into_response();
        }
    }
    write_membership(&mut wb, &scope, &record);
    let actor = wb.actor(bearer(&headers));
    gaugedesk_app::audit::record(&mut wb, &actor, "member.invite", &record.id);
    (StatusCode::OK, Json(json!({ "member": record }))).into_response()
}

#[derive(Deserialize)]
pub struct RoleBody {
    role: String,
}

pub async fn post_member_role(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RoleBody>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, Some(Capability::ManageMembers)) {
        return resp;
    }
    if !is_valid_role(&body.role) {
        return unprocessable(&format!("unknown role {:?}", body.role));
    }
    let org = match Org::rebuild_in(wb.store_ref(), &req_scope(&headers)) {
        Ok(org) => org,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
    };
    let Some(existing) = org.members.get(&id) else {
        return (StatusCode::NOT_FOUND, "no such member").into_response();
    };
    // ADR 0149 §1: elevating a principal *to* a privileged role (`owner`/`admin`) — the
    // target role, regardless of the member's current one — requires the owner-only
    // `GrantPrivilegedRoles` capability, over and above `ManageMembers`. This is the
    // separation-of-duties gate that stops an admin from elevating anyone, including
    // itself, to `owner`/`admin` (self- and lateral-escalation). Fail-closed.
    if is_privileged_role(&body.role) {
        if let Some(resp) = deny(&wb, &headers, Some(Capability::GrantPrivilegedRoles)) {
            return resp;
        }
    }
    if !wb.team_scope_ok_in(
        bearer(&headers),
        existing.team.as_deref(),
        &req_scope(&headers),
    ) {
        return (StatusCode::FORBIDDEN, "outside your team scope").into_response();
    }
    // An org must always retain a break-glass owner: refuse demoting the last active
    // one (ID-5 / INV-1).
    if existing.role == "owner"
        && existing.status == MembershipStatus::Active
        && body.role != "owner"
        && org.active_count_with_role("owner") <= 1
    {
        return (StatusCode::CONFLICT, "cannot demote the last owner").into_response();
    }
    let mut record = existing.clone();
    record.op = RecordOp::Upsert;
    record.role = body.role;
    write_membership(&mut wb, &req_scope(&headers), &record);
    let actor = wb.actor(bearer(&headers));
    gaugedesk_app::audit::record(&mut wb, &actor, "member.role", &record.id);
    (StatusCode::OK, Json(json!({ "member": record }))).into_response()
}

pub async fn post_member_deactivate(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, Some(Capability::ManageMembers)) {
        return resp;
    }
    let org = match Org::rebuild_in(wb.store_ref(), &req_scope(&headers)) {
        Ok(org) => org,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
    };
    let Some(existing) = org.members.get(&id) else {
        return (StatusCode::NOT_FOUND, "no such member").into_response();
    };
    if !wb.team_scope_ok_in(
        bearer(&headers),
        existing.team.as_deref(),
        &req_scope(&headers),
    ) {
        return (StatusCode::FORBIDDEN, "outside your team scope").into_response();
    }
    if existing.role == "owner"
        && existing.status == MembershipStatus::Active
        && org.active_count_with_role("owner") <= 1
    {
        return (StatusCode::CONFLICT, "cannot deactivate the last owner").into_response();
    }
    // Deprovision in place (keep the record so the audit shows the offboarding,
    // INV-18); not a tombstone.
    let mut record = existing.clone();
    record.op = RecordOp::Upsert;
    record.status = MembershipStatus::Deprovisioned;
    write_membership(&mut wb, &req_scope(&headers), &record);
    let actor = wb.actor(bearer(&headers));
    gaugedesk_app::audit::record(&mut wb, &actor, "member.deactivate", &record.id);
    (StatusCode::OK, Json(json!({ "member": record }))).into_response()
}

// ---- member → project scope grants (ENTSEC-2 / ADR 0065) -----------------

fn write_grant(wb: &mut Workbench, scope: &str, r: &MemberGrantRecord) {
    let op = op_str(r.op);
    let _ = wb
        .store_mut()
        .append_record(scope, "member_grant", &serde_json::to_string(r).unwrap());
    wb.notify_library_changed("member_grant", &r.id, op);
}

#[derive(Deserialize)]
pub struct GrantBody {
    authority: String,
    project_id: String,
}

/// `GET /admin/grants` (`ENTSEC-2`) — the member→project scope grants. Console-read gated.
pub async fn get_grants(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, None) {
        return resp;
    }
    match Org::rebuild_in(wb.store_ref(), &req_scope(&headers)) {
        Ok(org) => {
            let grants: Vec<&MemberGrantRecord> = org.grants.values().collect();
            (StatusCode::OK, Json(json!({ "grants": grants }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
    }
}

/// `POST /admin/grants` (`ENTSEC-2`, [ADR 0065]) — grant a member access to a project's data.
/// `ManageMembers`-gated (a directory-administration action). Owner/admin already see every
/// project; this is how a scoped member (a consultant) is given their engagement's project.
pub async fn post_grant(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<GrantBody>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, Some(Capability::ManageMembers)) {
        return resp;
    }
    if body.authority.trim().is_empty() || body.project_id.trim().is_empty() {
        return unprocessable("authority and project_id are required");
    }
    let record = MemberGrantRecord {
        id: MemberGrantRecord::make_id(&body.authority, &body.project_id),
        op: RecordOp::Upsert,
        authority: body.authority,
        project_id: body.project_id,
    };
    write_grant(&mut wb, &req_scope(&headers), &record);
    let actor = wb.actor(bearer(&headers));
    gaugedesk_app::audit::record(&mut wb, &actor, "grant.add", &record.id);
    (StatusCode::OK, Json(json!({ "grant": record }))).into_response()
}

/// `DELETE /admin/grants` (`ENTSEC-2`) — revoke a member's access to a project (tombstone;
/// future-only revocation, `INV-18`). `ManageMembers`-gated. Body carries the `(authority,
/// project_id)` pair (the grant has no standalone id a client would already hold).
pub async fn delete_grant(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<GrantBody>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, Some(Capability::ManageMembers)) {
        return resp;
    }
    let record = MemberGrantRecord {
        id: MemberGrantRecord::make_id(&body.authority, &body.project_id),
        op: RecordOp::Tombstone,
        authority: body.authority,
        project_id: body.project_id,
    };
    write_grant(&mut wb, &req_scope(&headers), &record);
    let actor = wb.actor(bearer(&headers));
    gaugedesk_app::audit::record(&mut wb, &actor, "grant.revoke", &record.id);
    (StatusCode::OK, Json(json!({ "grant": record }))).into_response()
}

// ---- SCIM group → role/team mappings (B13 / SCIM-3) ----------------------

#[derive(Deserialize)]
pub struct GroupMappingBody {
    pub(crate) group: String,
    pub(crate) role: String,
    #[serde(default)]
    pub(crate) team: Option<String>,
}

/// Configure an IdP-group → workspace-role (and optional team) mapping (`SCIM-3`).
/// Admin-gated (`ConfigureProvisioning`). The SCIM Users endpoint applies it when a
/// provisioned user carries the group.
pub async fn post_group_mapping(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<GroupMappingBody>,
) -> impl IntoResponse {
    if !is_valid_role(&body.role) {
        return unprocessable(&format!("unknown role {:?}", body.role));
    }
    // ADR 0149 §1: SCIM may never confer a privileged role. Refuse mapping a group into
    // `owner`/`admin` at the config boundary (fail-closed); `role_for_groups` also drops
    // any such mapping at read time as defense-in-depth.
    if is_privileged_role(&body.role) {
        return unprocessable(&format!(
            "cannot map a group into the privileged role {:?}; owner/admin are owner-granted only",
            body.role
        ));
    }
    let mut wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, Some(Capability::ConfigureProvisioning)) {
        return resp;
    }
    let record = GroupMappingRecord {
        id: body.group.clone(),
        op: RecordOp::Upsert,
        group: body.group,
        role: body.role,
        team: body.team,
    };
    let _ = wb.store_mut().append_record(
        &req_scope(&headers),
        "group_mapping",
        &serde_json::to_string(&record).unwrap(),
    );
    wb.notify_library_changed("group_mapping", &record.id, "upsert");
    (StatusCode::OK, Json(json!({ "mapping": record }))).into_response()
}

// ---- audit timeline (B14 / AUD-1, AUD-2) ---------------------------------

#[derive(Deserialize)]
pub struct AuditQuery {
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    action: Option<String>,
    /// `csv` exports CSV; otherwise JSON (the default).
    #[serde(default)]
    format: Option<String>,
}

/// The per-actor audit timeline (`AUD-1`), filterable by `?actor=`/`?action=`, and
/// exportable as `?format=csv` (`AUD-2`). Gated by `ViewAudit`. Returns references
/// only, never payloads (`INV-10`).
pub async fn get_audit_log(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, Some(Capability::ViewAudit)) {
        return resp;
    }
    let store_scope = req_scope(&headers);
    let entries: Vec<gaugedesk_app::audit::AuditEntry> =
        gaugedesk_app::audit::list_in(wb.store_ref(), &store_scope)
            .into_iter()
            .filter(|e| q.actor.as_ref().is_none_or(|a| &e.actor == a))
            .filter(|e| q.action.as_ref().is_none_or(|a| &e.action == a))
            .collect();
    if q.format.as_deref() == Some("csv") {
        (
            StatusCode::OK,
            [("content-type", "text/csv")],
            gaugedesk_app::audit::to_csv(&entries),
        )
            .into_response()
    } else {
        // AUD-3: publish the minimum-retention guarantee alongside the timeline. The log is
        // append-only/forever (`INV-6`); this is the contractual floor surfaced to the buyer.
        let retention_min_days = Org::rebuild_in(wb.store_ref(), &store_scope)
            .map(|o| o.audit_retention_min_days())
            .unwrap_or(gaugedesk_app::org::DEFAULT_AUDIT_RETENTION_MIN_DAYS);
        (
            StatusCode::OK,
            Json(json!({ "entries": entries, "retention_min_days": retention_min_days })),
        )
            .into_response()
    }
}

/// Verify the audit log's hash-chain integrity (`SECAUD-2`, SOC 2 CC7.2/CC7.3): a
/// public, queryable tamper-evidence check. Walks the chain and reports `ok`, the
/// entry count, the current head hash (anchor/sign it externally to also catch tail
/// truncation), and the first broken link if any. Gated by `ViewAudit`. References
/// only, never payloads (`INV-10`).
pub async fn get_audit_verify(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, Some(Capability::ViewAudit)) {
        return resp;
    }
    // SECAUD-2: pass the workbench's own governance public key as the trusted verifier
    // of the signed checkpoint — never the key embedded in the checkpoint record.
    let pubkey = wb.governance_public_key();
    (
        StatusCode::OK,
        Json(gaugedesk_app::audit::verify_in(
            wb.store_ref(),
            &req_scope(&headers),
            Some(&pubkey),
        )),
    )
        .into_response()
}

// ---- domain-capture auto-join (B10 / ID-6) -------------------------------

#[derive(Deserialize)]
pub struct AutoJoinBody {
    authority: String,
    email: String,
}

/// Domain-capture auto-join (`ID-6`): a user whose email is on a **verified domain**
/// (B10) joins the org as an active `member`. The verified domain *is* the
/// authorization basis (no admin capability required); in production the
/// authenticated email comes from the IdP. A non-verified domain is refused (`403`),
/// fail-closed. Idempotent: re-joining upserts the same active membership.
pub async fn post_auto_join(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<AutoJoinBody>,
) -> impl IntoResponse {
    if body.authority.trim().is_empty() {
        return unprocessable("authority is required");
    }
    let mut wb = wb.lock_unpoisoned();
    let org = match Org::rebuild_in(wb.store_ref(), &req_scope(&headers)) {
        Ok(org) => org,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
    };
    if !org.domain_is_verified(&body.email) {
        return (
            StatusCode::FORBIDDEN,
            "email domain is not verified for auto-join",
        )
            .into_response();
    }
    let record = MembershipRecord {
        id: body.authority.clone(),
        op: RecordOp::Upsert,
        org_id: ORG_ID.to_string(),
        authority: body.authority,
        email: body.email,
        role: "member".to_string(),
        status: MembershipStatus::Active,
        managed_by_scim: false,
        team: None,
    };
    if !org.seat_available_for(&record.id) {
        return (StatusCode::CONFLICT, "purchased seat capacity is full").into_response();
    }
    write_membership(&mut wb, &req_scope(&headers), &record);
    (StatusCode::OK, Json(json!({ "member": record }))).into_response()
}

// ---- org policy (B15 / RBAC-6) -------------------------------------------

pub async fn get_policy(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, None) {
        return resp;
    }
    match Org::rebuild_in(wb.store_ref(), &req_scope(&headers)) {
        Ok(org) => (StatusCode::OK, Json(json!({ "policy": org.policy() }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
    }
}

pub async fn post_policy(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(policy): Json<Policy>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, Some(Capability::ConfigureSecurity)) {
        return resp;
    }
    let record = PolicyRecord {
        id: ORG_ID.to_string(),
        op: RecordOp::Upsert,
        policy,
    };
    write_policy(&mut wb, &req_scope(&headers), &record);
    let actor = wb.actor(bearer(&headers));
    gaugedesk_app::audit::record(&mut wb, &actor, "policy.update", "policy");
    (StatusCode::OK, Json(json!({ "policy": record.policy }))).into_response()
}

// ---- placement policy (DEPLOY-2) -----------------------------------------

fn write_placement_policy(
    wb: &mut Workbench,
    scope: &str,
    r: &gaugedesk_app::org::PlacementPolicyRecord,
) {
    let op = op_str(r.op);
    let _ = wb.store_mut().append_record(
        scope,
        "placement_policy",
        &serde_json::to_string(r).unwrap(),
    );
    wb.notify_library_changed("placement_policy", &r.id, op);
}

pub async fn get_placement_policy(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    // The composed enterprise layer has already admitted an active tenant
    // member. This read is intentionally not console-only: the enrolled client
    // must fetch the tenant floor before it accepts a pairing (DEPLOY-4).
    match Org::rebuild_in(wb.store_ref(), &req_scope(&headers)) {
        Ok(org) => (
            StatusCode::OK,
            Json(json!({ "placement_policy": org.effective_placement_policy() })),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
    }
}

pub async fn post_placement_policy(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(policy): Json<gaugedesk_core::boundary_lifecycle::PlacementPolicy>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, Some(Capability::ConfigureSecurity)) {
        return resp;
    }
    let record = gaugedesk_app::org::PlacementPolicyRecord {
        id: ORG_ID.to_string(),
        op: RecordOp::Upsert,
        policy,
    };
    write_placement_policy(&mut wb, &req_scope(&headers), &record);
    let actor = wb.actor(bearer(&headers));
    gaugedesk_app::audit::record(
        &mut wb,
        &actor,
        "placement_policy.update",
        "placement_policy",
    );
    (
        StatusCode::OK,
        Json(json!({ "placement_policy": record.policy })),
    )
        .into_response()
}

// ---- client software admission (ITGOV-4 / ADR 0095) ---------------------

fn write_software_policy(wb: &mut Workbench, scope: &str, r: &SoftwarePolicyRecord) {
    let op = op_str(r.op);
    let _ =
        wb.store_mut()
            .append_record(scope, "software_policy", &serde_json::to_string(r).unwrap());
    wb.notify_library_changed("software_policy", &r.id, op);
}

pub async fn get_software_policy(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    // The composed enterprise layer has already admitted an active member and
    // deliberately skipped compatibility blocking for this recovery route. Do
    // not reclassify the read as console-only here: ordinary members need it to
    // discover the release channel that repairs their blocked client.
    match Org::rebuild_in(wb.store_ref(), &req_scope(&headers)) {
        Ok(org) => (
            StatusCode::OK,
            Json(json!({ "software_policy": org.software_policy.unwrap_or_default() })),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
    }
}

pub async fn post_software_policy(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(mut policy): Json<gaugedesk_app::client_admission::SoftwarePolicy>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, Some(Capability::ConfigureSecurity)) {
        return resp;
    }
    policy.minimum_version = policy.minimum_version.trim().to_string();
    policy.allowed_channels = policy
        .allowed_channels
        .into_iter()
        .map(|channel| channel.trim().to_ascii_lowercase())
        .filter(|channel| !channel.is_empty())
        .collect();
    policy.allowed_channels.sort();
    policy.allowed_channels.dedup();
    if policy.grace_until_unix_ms == Some(0) {
        policy.grace_until_unix_ms = None;
    }
    if let Err(message) = policy.validate() {
        return unprocessable(&message);
    }
    let record = SoftwarePolicyRecord {
        id: ORG_ID.to_string(),
        op: RecordOp::Upsert,
        policy,
    };
    write_software_policy(&mut wb, &req_scope(&headers), &record);
    let actor = wb.actor(bearer(&headers));
    gaugedesk_app::audit::record(&mut wb, &actor, "software_policy.update", "software_policy");
    (
        StatusCode::OK,
        Json(json!({ "software_policy": record.policy })),
    )
        .into_response()
}

// ---- billing & seats (B16 / BILL-1, BILL-3) ------------------------------

pub async fn get_billing(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, Some(Capability::ManageBilling)) {
        return resp;
    }
    match Org::rebuild_in(wb.store_ref(), &req_scope(&headers)) {
        Ok(org) => {
            let scope = req_scope(&headers);
            let included = org
                .billing
                .as_ref()
                .and_then(|billing| billing.managed_inference.as_ref())
                .map_or(0, |plan| plan.included_tokens);
            match gaugedesk_app::managed_inference::fold_usage(wb.store_ref(), &scope, included) {
                Ok(usage) => (
                    StatusCode::OK,
                    Json(json!({
                        "billing": org.billing,
                        "seats_used": org.seats_used(),
                        "managed_usage": usage,
                    })),
                )
                    .into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
    }
}

// `post_billing` stood here as the `/admin/billing` façade. It and the later
// GaugeApp `billing.update` command are retired: plan, seat, and managed-inference
// state arrives from the subscription authority and is read-only here. The only
// organization-owned Billing edit is the separately scoped billing contact.

// ---- security policy (B15 / SEC-1/2/3) -----------------------------------

fn write_security(wb: &mut Workbench, scope: &str, r: &SecurityPolicyRecord) {
    let op = op_str(r.op);
    let _ = wb
        .store_mut()
        .append_record(scope, "security", &serde_json::to_string(r).unwrap());
    wb.notify_library_changed("security", &r.id, op);
}

pub async fn get_security(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, None) {
        return resp;
    }
    match Org::rebuild_in(wb.store_ref(), &req_scope(&headers)) {
        Ok(org) => (StatusCode::OK, Json(json!({ "security": org.security }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
    }
}

pub async fn post_security(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(mut record): Json<SecurityPolicyRecord>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, Some(Capability::ConfigureSecurity)) {
        return resp;
    }
    record.id = ORG_ID.to_string();
    record.op = RecordOp::Upsert;
    write_security(&mut wb, &req_scope(&headers), &record);
    let actor = wb.actor(bearer(&headers));
    gaugedesk_app::audit::record(&mut wb, &actor, "security.update", "security");
    (StatusCode::OK, Json(json!({ "security": record }))).into_response()
}

// ---- archetype-approval policy (ADR 0063) --------------------------------
// The org default a project inherits: when set, an added archetype's placement is
// **pending** until the owner accepts; unset = frictionless (active at once).

fn write_archetype_approval(wb: &mut Workbench, scope: &str, r: &ArchetypeApprovalPolicyRecord) {
    let op = op_str(r.op);
    let _ = wb.store_mut().append_record(
        scope,
        "archetype_approval",
        &serde_json::to_string(r).unwrap(),
    );
    wb.notify_library_changed("archetype_approval", &r.id, op);
}

pub async fn get_archetype_approval(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, None) {
        return resp;
    }
    match Org::rebuild_in(wb.store_ref(), &req_scope(&headers)) {
        Ok(org) => (
            StatusCode::OK,
            Json(json!({ "require_approval": org.effective_require_archetype_approval() })),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
    }
}

pub async fn post_archetype_approval(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(mut record): Json<ArchetypeApprovalPolicyRecord>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, Some(Capability::ConfigureSecurity)) {
        return resp;
    }
    record.id = ORG_ID.to_string();
    record.op = RecordOp::Upsert;
    write_archetype_approval(&mut wb, &req_scope(&headers), &record);
    let actor = wb.actor(bearer(&headers));
    gaugedesk_app::audit::record(
        &mut wb,
        &actor,
        "archetype_approval.update",
        "archetype_approval",
    );
    (
        StatusCode::OK,
        Json(json!({ "require_approval": record.require_approval })),
    )
        .into_response()
}

// ---- SSO connection (B12 / ID-5) -----------------------------------------

fn write_sso(wb: &mut Workbench, scope: &str, r: &SsoConnectionRecord) {
    let op = op_str(r.op);
    let _ = wb
        .store_mut()
        .append_record(scope, "sso", &serde_json::to_string(r).unwrap());
    wb.notify_library_changed("sso", &r.id, op);
}

fn public_sso(
    record: Option<&SsoConnectionRecord>,
    client_secret_configured: bool,
) -> serde_json::Value {
    record.map_or(serde_json::Value::Null, |record| {
        json!({
            "id": record.id,
            "revision": record.current_revision(),
            "protocol": record.protocol,
            "issuer": record.issuer,
            "audiences": record.audiences,
            "metadata": record.metadata,
            "enforce_sso": record.enforce_sso,
            "claim_mapping": record.claim_mapping,
            "client_secret_configured": client_secret_configured,
        })
    })
}

pub async fn get_sso(State(wb): State<SharedWorkbench>, headers: HeaderMap) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, None) {
        return resp;
    }
    match Org::rebuild_in(wb.store_ref(), &req_scope(&headers)) {
        Ok(org) => (
            StatusCode::OK,
            Json(json!({
                "sso": public_sso(org.sso.as_ref(), org.current_sso_credential().is_some())
            })),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
    }
}

pub async fn post_sso(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(mut record): Json<SsoConnectionRecord>,
) -> impl IntoResponse {
    let client_secret_configured;
    {
        let mut wbg = wb.lock_unpoisoned();
        if let Some(resp) = deny(&wbg, &headers, Some(Capability::ConfigureSso)) {
            return resp;
        }
        record.id = ORG_ID.to_string();
        record.op = RecordOp::Upsert;
        match record.protocol {
            gaugedesk_app::org::SsoProtocol::Oidc => {
                record.saml_sp_entity_id.clear();
                record.saml_acs_url.clear();
            }
            gaugedesk_app::org::SsoProtocol::Saml => {
                let base = public_base(&headers);
                record.saml_sp_entity_id = sp_entity_id(&base);
                record.saml_acs_url = format!("{base}/auth/saml/acs");
            }
        }
        let current_org = match Org::rebuild_in(wbg.store_ref(), &req_scope(&headers)) {
            Ok(org) => org,
            Err(error) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{error:?}")).into_response()
            }
        };
        let current = current_org.sso.as_ref();
        let retains_credential = current.is_some_and(|current| {
            current.protocol == record.protocol
                && current.issuer == record.issuer
                && current.audiences == record.audiences
        });
        record.credential_revision = current.as_ref().and_then(|current| {
            retains_credential
                .then(|| current.credential_revision.clone())
                .flatten()
        });
        client_secret_configured =
            retains_credential && current_org.current_sso_credential().is_some();
        record.seal_revision();
        write_sso(&mut wbg, &req_scope(&headers), &record);
        let actor = wbg.actor(bearer(&headers));
        gaugedesk_app::audit::record(&mut wbg, &actor, "sso.configure", "sso");
    }
    // Activate OIDC verification from the just-saved connection (`ID-3`) without a
    // restart, so the bearer `/auth/callback` returns is honored on `/admin/*`. The
    // initial JWKS load touches the network → off the async runtime. A connection only
    // takes effect once its issuer is reachable (warm): a cold one (unreachable / bad
    // issuer) is "saved, not activated" and the existing verifier is left **untouched**
    // — so a bad runtime edit can't lock admins out. (Startup differs: it attaches a
    // cold verifier to fail closed + self-heal, since no operator is in the loop.)
    let activation = crate::auth_oidc::activate_updated_idp(&wb, record.clone()).await;
    (
        StatusCode::OK,
        Json(json!({
            "sso": public_sso(Some(&record), client_secret_configured),
            "oidc_active": activation.oidc_active,
            "activation_error": activation.activation_error,
        })),
    )
        .into_response()
}

// ---- SP integration details (ONB-1) --------------------------------------

/// The control plane's public base URL — what the admin's IdP must reach. An explicit
/// `GAUGEDESK_PUBLIC_URL` wins (the deployment's canonical externally-visible URL);
/// otherwise it is derived from the request (`X-Forwarded-Proto` +
/// `X-Forwarded-Host`/`Host`), so a default loopback run works unconfigured.
fn public_base(headers: &HeaderMap) -> String {
    crate::auth_oidc::request_public_base(headers)
}

pub(crate) fn enterprise_integration(headers: &HeaderMap) -> serde_json::Value {
    let base = public_base(headers);
    let sp = sp_entity_id(&base);
    json!({
        "base_url": base,
        "oidc": {
            "redirect_uri": format!("{base}/auth/callback"),
            "login_url": format!("{base}/auth/login"),
        },
        "saml": {
            "sp_entity_id": sp,
            "acs_url": format!("{base}/auth/saml/acs"),
            "metadata_url": format!("{base}/saml/metadata"),
        },
        "scim": {
            "base_url": format!("{base}/scim/v2"),
        },
    })
}

fn sp_entity_id(base: &str) -> String {
    gaugedesk_env::var("SP_ENTITY_ID")
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("{base}/saml/metadata"))
}

/// `GET /admin/integration` (`ONB-1`) — the **SP-side values** an IT admin pastes into
/// their IdP to connect us: the OIDC redirect URI + login URL, the SAML SP entity id /
/// ACS / metadata URL, and the SCIM base URL. Console-read gated. The admin no longer
/// has to reverse-engineer our endpoints (the biggest onboarding friction, ADR 0058).
pub async fn get_integration(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if let Some(resp) = deny(&wb, &headers, None) {
        return resp;
    }
    (StatusCode::OK, Json(enterprise_integration(&headers))).into_response()
}

/// `GET /saml/metadata` (`ONB-1`) — the SP metadata descriptor an IdP consumes to
/// pre-register us (entity id + the HTTP-POST ACS location + WantAssertionsSigned).
/// Public (SP metadata carries no secret); served as `application/samlmetadata+xml`.
pub async fn get_saml_metadata(headers: HeaderMap) -> impl IntoResponse {
    let base = public_base(&headers);
    let sp = sp_entity_id(&base);
    let acs = format!("{base}/auth/saml/acs");
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{sp}">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}" index="0" isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>"#
    );
    (
        StatusCode::OK,
        [("content-type", "application/samlmetadata+xml")],
        xml,
    )
        .into_response()
}

// ---- SSO test-connection (ONB-3) -----------------------------------------

/// `POST /admin/sso/test` (`ONB-3`) — a real connectivity test of an OIDC SSO
/// connection (the one in the body, so the wizard can test before saving): runs the
/// live discovery + JWKS load via [`crate::auth_oidc::build_oidc_idp`] and reports
/// whether the issuer is reachable and its signing keys load. The result is
/// **operational evidence, never an admitted "connected" fact** (`INV-2`) — nothing is
/// stored. `ConfigureSso`-gated; the network fetch runs off the async runtime.
pub async fn post_sso_test(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(record): Json<SsoConnectionRecord>,
) -> impl IntoResponse {
    {
        let wb = wb.lock_unpoisoned();
        if let Some(resp) = deny(&wb, &headers, Some(Capability::ConfigureSso)) {
            return resp;
        }
    }
    if record.protocol != gaugedesk_app::org::SsoProtocol::Oidc {
        return (
            StatusCode::OK,
            Json(json!({
                "ok": false,
                "detail": "live test is supported for OIDC; SAML connects via SP metadata + the ACS flow",
            })),
        )
            .into_response();
    }
    let built =
        tokio::task::spawn_blocking(move || crate::auth_oidc::build_oidc_idp(Some(&record))).await;
    let (ok, detail) = match built {
        Ok(Some((_idp, true))) => (
            true,
            "issuer reachable and signing keys loaded — the connection can verify tokens",
        ),
        Ok(Some((_idp, false))) => (
            false,
            "issuer or JWKS endpoint unreachable — check the issuer URL is correct and public",
        ),
        Ok(None) => (
            false,
            "incomplete OIDC connection — an issuer and at least one audience (client id) are required",
        ),
        Err(_) => (false, "the test task failed unexpectedly"),
    };
    (StatusCode::OK, Json(json!({ "ok": ok, "detail": detail }))).into_response()
}

// ---- DNS-TXT domain verification (ONB-5) ---------------------------------

/// The deterministic per-(org, domain) challenge token an admin publishes as a TXT
/// record to prove control of the domain. Deterministic so no pending state need be
/// stored; unguessable enough that the real gate is DNS control (the point of the proof).
fn domain_challenge_token(domain: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(
        format!(
            "gaugewright-domain-verification:{ORG_ID}:{}",
            domain.trim().to_lowercase()
        )
        .as_bytes(),
    );
    hex::encode(h.finalize())
}

/// The full TXT value to publish (`gaugewright-domain-verification=<token>`).
pub(crate) fn expected_txt(domain: &str) -> String {
    format!(
        "gaugewright-domain-verification={}",
        domain_challenge_token(domain)
    )
}

/// Whether any of the DNS TXT `values` (DoH may quote them) matches the challenge.
fn txt_matches(values: &[String], domain: &str) -> bool {
    let want = expected_txt(domain);
    values
        .iter()
        .any(|v| v.trim().trim_matches('"').trim() == want)
}

/// Look up the TXT records at `name` via DNS-over-HTTPS (reusing the shared HTTP
/// client — no resolver dependency). Returns the record strings (empty on any error).
fn doh_txt(name: &str) -> Vec<String> {
    use crate::identity_oidc::HttpGet;
    let http = gaugedesk_app::net_http::HttpClient::new();
    let url = format!("https://dns.google/resolve?name={name}&type=TXT");
    let Ok(body) = http.get(&url) else {
        return vec![];
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
        return vec![];
    };
    v.get("Answer")
        .and_then(|a| a.as_array())
        .map(|ans| {
            ans.iter()
                .filter_map(|r| r.get("data").and_then(|d| d.as_str()))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Recheck the hosted DNS proof off the async runtime immediately before an
/// admitted domain-verification command applies.
pub(crate) async fn domain_proof_matches(domain: &str) -> bool {
    let domain = domain.trim().to_ascii_lowercase();
    let name = format!("_gaugewright-challenge.{domain}");
    let values = tokio::task::spawn_blocking(move || doh_txt(&name))
        .await
        .unwrap_or_default();
    txt_matches(&values, &domain)
}

#[derive(Deserialize)]
pub struct DomainBody {
    domain: String,
}

/// `POST /admin/domains/verify-token` (`ONB-5`) — the TXT record the admin must publish
/// to prove control of a domain (the hosted-mode basis for auto-join/JIT). `EditOrgSettings`-gated.
pub async fn post_domain_verify_token(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<DomainBody>,
) -> impl IntoResponse {
    {
        let wb = wb.lock_unpoisoned();
        if let Some(resp) = deny(&wb, &headers, Some(Capability::EditOrgSettings)) {
            return resp;
        }
    }
    let domain = body.domain.trim().to_lowercase();
    if domain.is_empty() {
        return unprocessable("domain is required");
    }
    (
        StatusCode::OK,
        Json(json!({
            "domain": domain,
            "record_name": format!("_gaugewright-challenge.{domain}"),
            "record_type": "TXT",
            "value": expected_txt(&domain),
        })),
    )
        .into_response()
}

/// `POST /admin/domains/verify` (`ONB-5`) — look up the TXT challenge over DoH; on a
/// match, **admit** the domain into the org's verified set (the verifying event, B10),
/// which then powers domain-capture auto-join (`ID-6`) and JIT (`ONB-2`). On no match,
/// returns the expected record so the admin can fix it. `EditOrgSettings`-gated; the
/// DNS lookup runs off the async runtime.
pub async fn post_domain_verify(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<DomainBody>,
) -> impl IntoResponse {
    {
        let wb = wb.lock_unpoisoned();
        if let Some(resp) = deny(&wb, &headers, Some(Capability::EditOrgSettings)) {
            return resp;
        }
    }
    let domain = body.domain.trim().to_lowercase();
    if domain.is_empty() {
        return unprocessable("domain is required");
    }
    let name = format!("_gaugewright-challenge.{domain}");
    let values = tokio::task::spawn_blocking(move || doh_txt(&name))
        .await
        .unwrap_or_default();
    if !txt_matches(&values, &domain) {
        return (
            StatusCode::OK,
            Json(json!({
                "verified": false,
                "expected": { "record_name": format!("_gaugewright-challenge.{domain}"), "value": expected_txt(&domain) },
                "seen": values,
            })),
        )
            .into_response();
    }
    // Admit the domain into the org's verified set (preserving the rest of the record).
    let mut wbg = wb.lock_unpoisoned();
    let mut record = match Org::rebuild(wbg.store_ref()) {
        Ok(o) => o.org.unwrap_or_default(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
    };
    record.id = ORG_ID.to_string();
    record.op = RecordOp::Upsert;
    if !record
        .verified_domains
        .iter()
        .any(|d| d.eq_ignore_ascii_case(&domain))
    {
        record.verified_domains.push(domain.clone());
    }
    write_org(&mut wbg, &req_scope(&headers), &record);
    let actor = wbg.actor(bearer(&headers));
    gaugedesk_app::audit::record(&mut wbg, &actor, "domain.verified", &domain);
    (
        StatusCode::OK,
        Json(json!({ "verified": true, "domain": domain })),
    )
        .into_response()
}

#[cfg(test)]
mod onb5_tests {
    use super::{expected_txt, txt_matches};

    #[test]
    fn txt_matches_the_expected_challenge_and_is_domain_specific() {
        let want = expected_txt("acme.com");
        // DoH returns TXT values quoted; bare and quoted both match, case-insensitive domain.
        assert!(txt_matches(&[format!("\"{want}\"")], "acme.com"));
        assert!(txt_matches(std::slice::from_ref(&want), "Acme.com"));
        // wrong / missing → no match (fail-closed).
        assert!(!txt_matches(
            &["gaugewright-domain-verification=nope".into()],
            "acme.com"
        ));
        assert!(!txt_matches(&[], "acme.com"));
        // the token is domain-bound — acme's value does not verify evil.com.
        assert_ne!(expected_txt("acme.com"), expected_txt("evil.com"));
    }
}

#[cfg(test)]
mod public_origin_tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::public_base;

    #[test]
    fn trusted_forwarded_origin_wins_over_the_loopback_upstream() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("127.0.0.1:5293"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("desk.gw.localhost:7563"),
        );
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(public_base(&headers), "https://desk.gw.localhost:7563");
    }
}

#[cfg(test)]
mod enterprise_connection_test_tests {
    use gaugedesk_app::auth_oidc::{PendingEnterpriseConnectionTest, VerifiedOidcIdentity};
    use gaugedesk_app::org::{
        MembershipRecord, MembershipStatus, Org, SsoConnectionRecord, SsoProtocol, ORG_ID,
        ORG_SCOPE,
    };
    use gaugedesk_app::Workbench;
    use gaugedesk_core::abac::{AuthorityAttributes, Role};
    use gaugedesk_core::ids::AuthorityId;
    use gaugedesk_store::Store;
    use gaugedesk_workspace::Instance;

    use super::{fold_enterprise_connection_test, write_membership, write_sso, RecordOp};

    fn fixture() -> (tempfile::TempDir, Workbench, SsoConnectionRecord) {
        let dir = tempfile::tempdir().unwrap();
        let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let mut workbench =
            Workbench::with_target("inst-test", instance, Store::open_in_memory().unwrap());
        write_membership(
            &mut workbench,
            ORG_SCOPE,
            &MembershipRecord {
                id: "owner".into(),
                op: RecordOp::Upsert,
                org_id: ORG_ID.into(),
                authority: "authority:owner".into(),
                email: "owner@example.test".into(),
                role: "owner".into(),
                status: MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            },
        );
        let mut connection = SsoConnectionRecord {
            id: ORG_ID.into(),
            protocol: SsoProtocol::Oidc,
            issuer: "https://idp.example.test".into(),
            audiences: vec!["gaugedesk".into()],
            ..Default::default()
        };
        connection.seal_revision();
        write_sso(&mut workbench, ORG_SCOPE, &connection);
        (dir, workbench, connection)
    }

    #[test]
    fn browser_test_records_evidence_without_creating_membership() {
        let (_dir, mut workbench, connection) = fixture();
        let pending = PendingEnterpriseConnectionTest {
            id: "ssotest-1".into(),
            store_scope: ORG_SCOPE.into(),
            actor: "authority:owner".into(),
            connection_id: ORG_ID.into(),
            connection_revision: connection.current_revision(),
        };
        let mut attributes = AuthorityAttributes::default();
        attributes.roles.insert(Role::new("engineering"));
        let verified = VerifiedOidcIdentity {
            authority: AuthorityId::new("corporate-subject"),
            id_token: "not-persisted".into(),
            refresh_token: Some("not-persisted".into()),
            attributes,
        };

        fold_enterprise_connection_test(&mut workbench, &pending, &verified).unwrap();
        let org = Org::rebuild(workbench.store_ref()).unwrap();
        let evidence = org.current_sso_browser_test().unwrap();
        assert_eq!(evidence.subject, "corporate-subject");
        assert_eq!(evidence.mapped_roles, vec!["engineering"]);
        assert_eq!(
            org.members.len(),
            1,
            "the test never provisions its subject"
        );
        let stored = workbench
            .store_ref()
            .records(ORG_SCOPE, gaugedesk_app::org::SSO_BROWSER_TEST_KIND)
            .unwrap()
            .join("\n");
        assert!(
            !stored.contains("not-persisted"),
            "no external token is stored"
        );
    }

    #[test]
    fn browser_test_refuses_a_changed_connection_revision() {
        let (_dir, mut workbench, connection) = fixture();
        let pending = PendingEnterpriseConnectionTest {
            id: "ssotest-stale".into(),
            store_scope: ORG_SCOPE.into(),
            actor: "authority:owner".into(),
            connection_id: ORG_ID.into(),
            connection_revision: connection.current_revision(),
        };
        let mut changed = connection;
        changed.audiences = vec!["replacement".into()];
        changed.seal_revision();
        write_sso(&mut workbench, ORG_SCOPE, &changed);
        let verified = VerifiedOidcIdentity {
            authority: AuthorityId::new("corporate-subject"),
            id_token: String::new(),
            refresh_token: None,
            attributes: AuthorityAttributes::default(),
        };

        assert!(fold_enterprise_connection_test(&mut workbench, &pending, &verified).is_err());
        assert!(Org::rebuild(workbench.store_ref())
            .unwrap()
            .sso_browser_tests
            .is_empty());
    }

    #[test]
    fn saml_browser_result_uses_the_same_revision_and_non_membership_contract() {
        let (_dir, mut workbench, mut connection) = fixture();
        connection.protocol = SsoProtocol::Saml;
        connection.issuer = "https://saml-idp.example.test".into();
        connection.audiences.clear();
        connection.seal_revision();
        write_sso(&mut workbench, ORG_SCOPE, &connection);
        let pending = PendingEnterpriseConnectionTest {
            id: "ssotest-saml".into(),
            store_scope: ORG_SCOPE.into(),
            actor: "authority:owner".into(),
            connection_id: ORG_ID.into(),
            connection_revision: connection.current_revision(),
        };
        let attributes = AuthorityAttributes::default();

        super::record_enterprise_connection_test(
            &mut workbench,
            &pending,
            SsoProtocol::Saml,
            &AuthorityId::new("signed-name-id"),
            &attributes,
        )
        .unwrap();
        let org = Org::rebuild(workbench.store_ref()).unwrap();
        assert_eq!(
            org.current_sso_browser_test().unwrap().subject,
            "signed-name-id"
        );
        assert_eq!(org.members.len(), 1);
    }
}

#[cfg(test)]
mod authenticated_actor_tests {
    use std::sync::{Arc, Mutex};

    use axum::body::Body;
    use axum::extract::Extension;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use axum::http::StatusCode;
    use gaugedesk_app::account_auth::{
        append_facts as append_account_auth_facts, AccountAuthFact, RecoveryBatchRecord,
        RecoveryBatchStatus, RecoveryCodeRecord, WebAuthnMethodRecord,
    };
    use gaugedesk_app::identity::{AuthenticatedActor, LoopbackIdentityProvider};
    use gaugedesk_app::org::{
        MembershipRecord, MembershipStatus, SsoConnectionRecord, SsoProtocol, ORG_ID, ORG_SCOPE,
    };
    use gaugedesk_app::Workbench;
    use gaugedesk_core::abac::AuthorityAttributes;
    use gaugedesk_core::ids::AuthorityId;
    use gaugedesk_store::Store;
    use gaugedesk_workspace::Instance;

    use super::{
        administration_sso_recovery_path, enterprise_auth, entsec_exempt, person_account_path,
        write_membership, RecordOp,
    };

    async fn who_am_i(Extension(actor): Extension<AuthenticatedActor>) -> String {
        actor.0.as_str().to_owned()
    }

    #[tokio::test]
    async fn authenticated_member_is_carried_to_the_data_handler() {
        let dir = tempfile::tempdir().unwrap();
        let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let idp = LoopbackIdentityProvider::new().enroll(
            "alice-token",
            AuthorityId::new("authority:alice"),
            AuthorityAttributes::default(),
        );
        let mut workbench =
            Workbench::with_target("inst-test", instance, Store::open_in_memory().unwrap())
                .with_identity_provider(Arc::new(idp));
        write_membership(
            &mut workbench,
            ORG_SCOPE,
            &MembershipRecord {
                id: "alice".to_owned(),
                op: RecordOp::Upsert,
                org_id: "org".to_owned(),
                authority: "authority:alice".to_owned(),
                email: "alice@example.test".to_owned(),
                role: "owner".to_owned(),
                status: MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            },
        );
        let shared = Arc::new(Mutex::new(workbench));
        let app = Router::new()
            .route("/whoami", get(who_am_i))
            .route_layer(axum::middleware::from_fn_with_state(
                shared.clone(),
                enterprise_auth,
            ))
            .with_state(shared);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/whoami")
                    .header("authorization", "Bearer alice-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_success());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"authority:alice");
    }

    #[tokio::test]
    async fn enforced_sso_exposes_only_the_gaugeapp_recovery_entry_to_a_passkey_owner() {
        let dir = tempfile::tempdir().unwrap();
        let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let mut workbench =
            Workbench::with_target("inst-recovery", instance, Store::open_in_memory().unwrap())
                .with_identity_provider(Arc::new(LoopbackIdentityProvider::new()));
        write_membership(
            &mut workbench,
            ORG_SCOPE,
            &MembershipRecord {
                id: "owner".to_owned(),
                op: RecordOp::Upsert,
                org_id: ORG_ID.to_owned(),
                authority: "person-root".to_owned(),
                email: "owner@example.test".to_owned(),
                role: "owner".to_owned(),
                status: MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            },
        );
        let mut connection = SsoConnectionRecord {
            id: ORG_ID.to_owned(),
            op: RecordOp::Upsert,
            protocol: SsoProtocol::Oidc,
            issuer: "https://idp.example.test".to_owned(),
            audiences: vec!["gaugedesk".to_owned()],
            enforce_sso: true,
            ..Default::default()
        };
        connection.seal_revision();
        workbench
            .store_mut()
            .append_record(
                ORG_SCOPE,
                "sso",
                &serde_json::to_string(&connection).unwrap(),
            )
            .unwrap();
        let credential = WebAuthnMethodRecord::new(
            "person-root",
            "owner-passkey",
            "public verifier",
            "Security key",
            1,
        )
        .unwrap();
        let recovery =
            RecoveryCodeRecord::prepare("person-root", "owner-recovery", "salt", "one-use-code")
                .unwrap();
        append_account_auth_facts(
            workbench.store_mut(),
            &[
                AccountAuthFact::WebAuthn(credential),
                AccountAuthFact::RecoveryBatch(RecoveryBatchRecord {
                    id: "owner-recovery".to_owned(),
                    op: RecordOp::Upsert,
                    account_id: "person-root".to_owned(),
                    created_at: 1,
                    status: RecoveryBatchStatus::Active,
                }),
                AccountAuthFact::RecoveryCode(recovery),
            ],
        )
        .unwrap();
        let passkey = workbench
            .mint_account_session("person-root", "passkey", 3600)
            .unwrap();
        let shared = Arc::new(Mutex::new(workbench));
        let app = Router::new()
            .route("/whoami", get(who_am_i))
            .route("/gaugeapps/administration/sessions", get(who_am_i))
            .route_layer(axum::middleware::from_fn_with_state(
                shared.clone(),
                enterprise_auth,
            ))
            .with_state(shared);

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/whoami")
                    .header("authorization", format!("Bearer {passkey}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);

        let admitted = app
            .oneshot(
                Request::builder()
                    .uri("/gaugeapps/administration/sessions")
                    .header("authorization", format!("Bearer {passkey}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(admitted.status(), StatusCode::OK);
        let body = admitted.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"person-root");
    }

    #[test]
    fn stripe_callbacks_bypass_member_auth_only_at_exact_verifier_paths() {
        assert!(entsec_exempt("/stripe/webhook"));
        assert!(entsec_exempt("/stripe/connect/webhook"));
        for path in [
            "/stripe",
            "/stripe/connect",
            "/stripe/connect/webhook-extra",
            "/stripe/connect/webhook/anything",
            "/stripe/accounts",
        ] {
            assert!(!entsec_exempt(path), "{path}");
        }
    }

    #[test]
    fn pending_tenant_invitation_routes_bypass_membership_gate_only_for_acceptance() {
        assert!(entsec_exempt("/account/invitations"));
        assert!(entsec_exempt(
            "/account/invitations/organization%3Aacme/accept"
        ));
        // A public operational probe, like `/health`: the identity of the running
        // build, carrying no account state. Deployed gated, it answered
        // "authenticate to access your account" and could not do the one job it
        // has.
        assert!(entsec_exempt("/gaugewright-release.json"));
        // Exempting the exact path must not exempt anything near it.
        assert!(!entsec_exempt("/gaugewright-release.json.map"));
        assert!(!entsec_exempt("/account/tenants"));
        assert!(!entsec_exempt("/account/invitations-extra"));
    }

    #[test]
    fn person_account_routes_do_not_inherit_the_selected_organization_gate() {
        for path in [
            "/account/settings",
            "/account/homes",
            "/account/model-access",
            "/account/sessions",
        ] {
            assert!(person_account_path(path), "{path}");
        }
        for path in [
            "/account/project-share-candidates",
            "/account/home/project-share-candidates",
            "/account/hub-session",
            "/account/hub-session/redeem",
            "/accounts/settings",
        ] {
            assert!(!person_account_path(path), "{path}");
        }
    }

    #[test]
    fn sso_recovery_allowlist_names_only_routes_that_rebuild_the_restricted_session() {
        for path in [
            "/gaugeapps/administration/sessions",
            "/gaugeapps/administration/pages/enterprise-identity",
            "/gaugeapps/administration/updates",
            "/gaugeapps/administration/commands",
            "/gaugeapps/administration/proposals",
            "/gaugeapps/administration/proposals/change-1/review",
            "/gaugeapps/administration/agent/messages",
            "/gaugeapps/administration/agent/events",
            "/gaugeapps/administration/agent/stop",
            "/gaugeapps/administration/agent/erase",
        ] {
            assert!(administration_sso_recovery_path(path), "{path}");
        }
        for path in [
            "/gaugeapps/administration",
            "/gaugeapps/administration/recovery",
            "/gaugeapps/administration/organization/domain-verification",
            "/gaugeapps/administration/proposals/change-1",
            "/admin/software-policy",
        ] {
            assert!(!administration_sso_recovery_path(path), "{path}");
        }
    }
}
