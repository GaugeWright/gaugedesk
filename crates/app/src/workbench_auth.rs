//! Workbench-local authorization and actor resolution helpers — the shared
//! admission substrate the route compositions use: the Administration
//! surface (`gaugedesk-ee`) and the private settlement plane
//! (`gaugewright-cloud-settlement`) both gate their routes through these seams.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;

use crate::{identity, net_http, org, resource_store, throttle, Workbench};

/// Whether this deployment is the hosted **web account** (`ADR 0077`) — the control-plane hub at
/// `auth.gaugewright.com`. Set by `GAUGEDESK_WEB_ACCOUNT=1`. In this mode the account/data routes
/// require a valid session (no bootstrap-passthrough); the desktop/enterprise paths are unchanged.
/// (The `gaugedesk-ee` login shell reads the same env for its own provisioning hook.)
pub fn web_account_mode() -> bool {
    gaugedesk_env::var("WEB_ACCOUNT")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Which projects a request's caller may **see** in the nav/list projections (`ENTSEC-2`).
/// This is the projection-visibility complement to the per-route [`Workbench::authorize_scope`]
/// gate: the gate refuses *access* to another project's data; this stops another project even
/// *appearing* in the nav for a scoped member (no information leak of project/chat existence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectVisibility {
    /// See everything — solo/loopback (no IdP), bootstrap (unprovisioned directory), or an
    /// `owner`/`admin` who bypasses scoping. The default, so the single-user shape is untouched.
    All,
    /// A scoped member sees **only** these explicitly-granted project ids (fail-closed: an
    /// empty set means no client projects are visible).
    Only(BTreeSet<String>),
}

impl ProjectVisibility {
    /// Whether `project_id` is visible under this policy.
    pub fn allows(&self, project_id: &str) -> bool {
        match self {
            ProjectVisibility::All => true,
            ProjectVisibility::Only(set) => set.contains(project_id),
        }
    }
}

/// Gate an admin request by capability (`RBAC-5`); returns the error response to
/// short-circuit with, or `None` to proceed. `cap = None` is a read (any console
/// access). Ungated in single-user mode (no IdP) — see [`Workbench::authorize`].
/// `pub` so the extracted enterprise band (`gaugedesk-ee`) and settlement plane
/// (`gaugewright-cloud-settlement`) reuse the RBAC gate across the crate boundary.
pub fn deny(
    wb: &Workbench,
    headers: &HeaderMap,
    cap: Option<gaugedesk_core::rbac::Capability>,
) -> Option<axum::response::Response> {
    let scope = req_scope(headers);
    wb.authorize_in(net_http::bearer(headers), cap, &scope)
        .err()
        .map(|(code, msg)| (code, msg).into_response())
}

/// The org store scope for a request's tenant (`DEPLOY-6`). Resolves the tenant from the
/// `X-Gaugewright-Tenant` header (the hosted multi-tenant edge sets it from the host /
/// subdomain); absent ⇒ the **default tenant** (solo / singleton), i.e. `ORG_SCOPE` — so a
/// single-tenant deployment is unaffected. Reads + writes for a request all use this scope,
/// keeping tenants isolated (`INV-1`/`INV-22`). `pub` so the extracted enterprise band and
/// settlement plane resolve the same tenant scope across the crate boundary.
pub fn req_scope(headers: &HeaderMap) -> String {
    let tenant = headers
        .get("x-gaugewright-tenant")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    org::tenant_scope(tenant)
}

impl Workbench {
    /// Resolve the provider-neutral Hub account session first, then optional
    /// OIDC. Both yield the same durable account/authority type; neither
    /// credential becomes the identity.
    pub fn authenticate_bearer(&self, token: &str) -> Option<gaugedesk_core::ids::AuthorityId> {
        self.account_sessions
            .resolve_now(token)
            .map(gaugedesk_core::ids::AuthorityId::new)
            .or_else(|| self.idp.as_ref().and_then(|idp| idp.authenticate(token)))
    }

    pub fn account_sessions(&self) -> Arc<crate::account_session::AccountSessionStore> {
        Arc::clone(&self.account_sessions)
    }

    /// Mint a durable, opaque account session for `account_id` (`ADR 0147` §1). Mints
    /// the bearer entropy into the in-memory hot cache and writes the digest-keyed
    /// index record into the shared `account-auth` scope so the session survives a
    /// restart and can be revoked server-side. `method` is `"oidc"` or `"passkey"` —
    /// the session surface reports it. Returns the raw token to set as the cookie; the
    /// caller keys the per-session refresh grant by [`account_session::session_id`].
    /// `lifetime_secs` bounds the opaque token's cache liveness — the OIDC browser
    /// path passes the platform absolute-lifetime (the refresh grant enforces the
    /// idle bound), the passkey ceremony passes its own session TTL. Best-effort
    /// durability: a store-write failure leaves a working cache session that simply
    /// does not survive a restart.
    pub fn mint_account_session(
        &mut self,
        account_id: &str,
        method: &str,
        lifetime_secs: u64,
    ) -> Option<String> {
        let now_ms = crate::account::session_now_ms();
        let now_secs = now_ms / 1000;
        let cache = Arc::clone(&self.account_sessions);
        let token = cache.issue_with_method(account_id, method, now_secs, lifetime_secs)?;
        let session_id = crate::account_session::session_id(&token);
        if let Ok(record) = crate::account_auth::AccountSessionRecord::new(
            &session_id,
            account_id,
            method,
            now_ms,
            lifetime_secs,
        ) {
            let _ = crate::account_auth::append_facts(
                self.store_mut(),
                &[crate::account_auth::AccountAuthFact::Session(record)],
            );
        }
        Some(token)
    }

    /// Revoke the opaque session `token` names (`ADR 0147` §3): evict it from the hot
    /// cache and tombstone its durable index record (future-only, `INV-18`), so the
    /// token stops resolving now and after a restart. Returns whether a live cache
    /// entry was removed. The caller separately tombstones the per-session refresh
    /// grant keyed by the same session id.
    pub fn revoke_account_session(&mut self, token: &str) -> bool {
        let session_id = crate::account_session::session_id(token);
        let removed = Arc::clone(&self.account_sessions).revoke(token);
        let tombstone = crate::account_auth::AccountSessionRecord {
            id: session_id,
            op: crate::account_auth::RecordOp::Tombstone,
            account_id: String::new(),
            method: String::new(),
            issued_at_ms: 0,
            last_seen_ms: 0,
            lifetime_secs: 0,
        };
        let _ = crate::account_auth::append_facts(
            self.store_mut(),
            &[crate::account_auth::AccountAuthFact::Session(tombstone)],
        );
        removed
    }

    /// Re-seat live opaque sessions into the hot cache from the durable index on
    /// startup (`ADR 0147` §1) — the substrate that makes a hosted session survive a
    /// restart. A session whose absolute lifetime has elapsed is left out.
    pub(crate) fn restore_account_sessions(&mut self) {
        let Ok(auth) = crate::account_auth::AccountAuth::rebuild(self.store_ref()) else {
            return;
        };
        let now_ms = crate::account::session_now_ms();
        for record in auth.sessions.values() {
            let lifetime_ms = record.lifetime_secs.saturating_mul(1000);
            let expires_ms = record.issued_at_ms.saturating_add(lifetime_ms);
            if expires_ms <= now_ms {
                continue;
            }
            self.account_sessions.insert_loaded(
                &record.id,
                &record.account_id,
                &record.method,
                expires_ms / 1000,
            );
        }
    }

    fn identity_claims(
        &self,
        bearer: Option<&str>,
        authority: &gaugedesk_core::ids::AuthorityId,
    ) -> gaugedesk_core::abac::AuthorityAttributes {
        if bearer.is_some_and(|token| self.account_sessions.resolve_now(token).is_some()) {
            return gaugedesk_core::abac::AuthorityAttributes::default();
        }
        self.idp
            .as_ref()
            .map(|idp| idp.claims(authority))
            .unwrap_or_default()
    }

    /// The SCIM failed-attempt throttle (`SECAUD-8`).
    pub fn scim_throttle(&self) -> &Arc<throttle::Throttle> {
        &self.scim_throttle
    }

    /// The OIDC-callback failed-attempt throttle (`SECAUD-8`) — the per-tenant brute-force
    /// guard on the SSO callback, mirroring [`scim_throttle`](Self::scim_throttle).
    pub fn oidc_throttle(&self) -> &Arc<throttle::Throttle> {
        &self.oidc_throttle
    }

    /// The live IT **session roster** (`ITGOV-2`): the active member sessions the data-route
    /// admission has recorded — the authority (never the bearer), its age and idle. What the
    /// IT console lists so an admin can see who is currently active. Empty in solo mode.
    pub fn session_roster(&self) -> Vec<crate::session_activity::SessionInfo> {
        let now = self.session_activity.now_ms();
        self.session_activity.roster(now)
    }

    /// Wire an [`identity::IdentityProvider`] (enterprise mode, `RBAC-5`): the
    /// adapter that authenticates a request's bearer credential. Without one the
    /// workbench stays single-user/local and the admin routes are ungated. Builder.
    pub fn with_identity_provider(
        mut self,
        idp: Arc<dyn identity::IdentityProvider + Send + Sync>,
    ) -> Self {
        self.idp = Some(idp);
        self
    }

    /// Attach / clear the identity provider at runtime — the `&mut` counterpart of
    /// [`with_identity_provider`](Self::with_identity_provider). `POST /admin/sso`
    /// uses this to (de)activate OIDC verification from the stored connection without
    /// a restart (`ID-3` enterprise-mode activation — the ee band's
    /// `auth_oidc::build_oidc_idp`, `gaugedesk-ee`).
    pub fn set_identity_provider(
        &mut self,
        idp: Option<Arc<dyn identity::IdentityProvider + Send + Sync>>,
    ) {
        self.idp = idp;
    }

    /// Whether an identity provider is attached (enterprise mode active). `false` is
    /// the single-user local shape (admin ungated).
    pub fn has_idp(&self) -> bool {
        self.idp.is_some()
    }

    /// Discover the current actor's administration capabilities in one tenant
    /// scope (`ADMIN-ENV-2`). This is presentation admission only; every route
    /// still gates its own action independently through [`Self::authorize`].
    ///
    /// Unlike the historical client-side `?cp=` heuristic, this derives from the
    /// active membership and the same fixed capability matrix as route admission.
    /// An unprovisioned directory has no Administration environment. In a local
    /// enterprise composition without an IdP, the workbench authority must itself
    /// be an active member; hosted deployments still fail closed without an IdP.
    pub fn admin_capabilities(
        &self,
        bearer: Option<&str>,
        org_scope: &str,
    ) -> Result<Vec<gaugedesk_core::rbac::Capability>, (StatusCode, &'static str)> {
        let org = org::Org::rebuild_in(self.store_ref(), org_scope)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "directory unavailable"))?;
        let provisioned = org
            .members
            .values()
            .any(|member| member.status == org::MembershipStatus::Active);
        if !provisioned {
            return Ok(Vec::new());
        }

        let authority = if self.idp.is_some() || web_account_mode() {
            bearer
                .and_then(|token| self.authenticate_bearer(token))
                .ok_or((StatusCode::UNAUTHORIZED, "authenticate to administer"))?
                .as_str()
                .to_string()
        } else {
            if self.hosted_home_mode() {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Home identity provider unavailable",
                ));
            }
            self.authority().as_str().to_string()
        };

        let Some(role) = org.role_of(&authority) else {
            return Ok(Vec::new());
        };
        Ok(gaugedesk_core::rbac::Capability::ALL
            .into_iter()
            .filter(|&capability| gaugedesk_core::rbac::role_can(&role, capability))
            .collect())
    }

    /// Authorize an `/admin/*` request (`RBAC-5`). The gate:
    ///
    /// - **No IdP** (single-user local) ⇒ always `Ok` — the existing open behavior;
    ///   M3 adds the org layer without changing the single-user shape (ADR 0020).
    /// - **IdP, empty directory** ⇒ `Ok` (bootstrap): the directory must be seedable
    ///   (by SCIM / the initial owner) before there is anyone to authorize against.
    /// - **IdP, populated directory** ⇒ authenticate the bearer to an authority, read
    ///   its **active**-member role from the directory, and require it (fail-closed,
    ///   `INV-20`): a missing/invalid token is `401`; an authenticated actor without
    ///   the capability (or any console access, for a read) is `403`. `cap = None`
    ///   means "a read" — require any console access ([`rbac::can_access_console`]).
    pub fn authorize(
        &self,
        bearer: Option<&str>,
        cap: Option<gaugedesk_core::rbac::Capability>,
    ) -> Result<(), (StatusCode, &'static str)> {
        self.authorize_in(bearer, cap, org::ORG_SCOPE)
    }

    /// **RBAC-5 / DEPLOY-6**: [`authorize`](Self::authorize) against a specific tenant
    /// scope. The admin gate must fold the *same* tenant directory the handler reads and
    /// writes (resolved from `X-Gaugewright-Tenant` via [`req_scope`]); otherwise a
    /// default-scope owner — or, under bootstrap-passthrough, an unseeded default scope —
    /// would authorize actions against another tenant's data the gate never inspects
    /// (cross-tenant authz bypass). [`authorize`] delegates here with the default
    /// [`ORG_SCOPE`](org::ORG_SCOPE), so header-absent (desktop / single-tenant) callers
    /// are byte-for-byte unchanged (`tenant_scope("") == ORG_SCOPE`).
    pub fn authorize_in(
        &self,
        bearer: Option<&str>,
        cap: Option<gaugedesk_core::rbac::Capability>,
        org_scope: &str,
    ) -> Result<(), (StatusCode, &'static str)> {
        if self.idp.is_none() && !web_account_mode() {
            if self.hosted_home_mode() {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Home identity provider unavailable",
                ));
            }
            return Ok(()); // single-user local: ungated
        }
        let org = org::Org::rebuild_in(self.store_ref(), org_scope)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "directory unavailable"))?;
        let provisioned = org
            .members
            .values()
            .any(|m| m.status == org::MembershipStatus::Active);
        if !provisioned && !self.hosted_home_mode() {
            return Ok(()); // bootstrap: directory not yet provisioned
        }
        let Some(authority) = bearer.and_then(|t| self.authenticate_bearer(t)) else {
            return Err((StatusCode::UNAUTHORIZED, "authenticate to administer"));
        };
        let Some(role) = org.role_of(authority.as_str()) else {
            return Err((StatusCode::FORBIDDEN, "not an active member"));
        };
        match cap {
            None if gaugedesk_core::rbac::can_access_console(&role) => Ok(()),
            None => Err((StatusCode::FORBIDDEN, "role has no console access")),
            Some(c) if gaugedesk_core::rbac::role_can(&role, c) => Ok(()),
            Some(_) => Err((StatusCode::FORBIDDEN, "role lacks capability")),
        }
    }

    /// **ENTSEC-1**: authenticate a request to a *data* route (chats / resources / projections /
    /// runs / workspace …) in enterprise mode. The gate, mirroring [`authorize`](Self::authorize)
    /// but requiring only **active membership** (any role — these are not console actions; per-
    /// scope RBAC is `ENTSEC-2`):
    ///
    /// - **No IdP** (single-user local / loopback) ⇒ `Ok` — the zero-friction solo shape is
    ///   untouched (ADR 0020 / [ADR 0065]); the loopback channel is the local operator's own.
    /// - **IdP, empty directory** ⇒ `Ok` (bootstrap — there is no one to authenticate against
    ///   until SCIM / the initial owner provisions).
    /// - **IdP, provisioned** ⇒ the bearer must authenticate to an **active member**; a
    ///   missing/invalid token is `401`, a non-member is `403`, fail-closed (`INV-20`). So in a
    ///   deployed (enterprise) workspace the data routes are no longer the open loopback API.
    pub fn authenticate_request(
        &self,
        bearer: Option<&str>,
    ) -> Result<(), (StatusCode, &'static str)> {
        self.admit_data_request(bearer, None).map(|_| ())
    }

    /// **ENTSEC-2** ([ADR 0065]): authorize a request to a *project-scoped* data route. Layered
    /// on top of [`authenticate_request`](Self::authenticate_request)'s membership check — the
    /// actor is already an active member here; this narrows to the projects they may touch:
    ///
    /// - **No IdP** / **not provisioned** ⇒ `Ok` (solo / bootstrap, unchanged).
    /// - **owner / admin** ⇒ `Ok` — the client org's own people see every project (role bypass).
    /// - **any other member** ⇒ `Ok` only if explicitly **granted** `project_id`
    ///   ([`Org::can_access_project`](org::Org::can_access_project)); else `403`, fail-closed
    ///   (`INV-20`). A token that no longer authenticates is `401`.
    pub fn authorize_scope(
        &self,
        bearer: Option<&str>,
        project_id: &str,
    ) -> Result<(), (StatusCode, &'static str)> {
        self.admit_data_request(bearer, Some(project_id))
            .map(|_| ())
    }

    /// **SECAUD-7** (SOC 2 CC6.1): the single fold-once admission for an enterprise data
    /// route — fold the org **exactly once** and authenticate the bearer **exactly once**,
    /// then run membership and (if the path is project-scoped) project-scope against that
    /// one consistent read, returning the resolved **actor** label for the audit trail.
    ///
    /// Folding the directory twice (membership, then scope) opened a TOCTOU window: a
    /// concurrent deprovision / grant-revoke between the two reads could admit on the first
    /// and mis-decide on the second. One fold closes it. Solo (no IdP) ⇒ the local authority;
    /// bootstrap (not provisioned) ⇒ the best-effort actor; otherwise an active member, with
    /// `owner`/`admin` seeing every project and any other member needing an explicit grant
    /// (`INV-20`, fail-closed). `pub` so the extracted enterprise band's ENTSEC-1
    /// data-route middleware (`gaugedesk-ee`) admits through the same fold-once seam.
    pub fn admit_data_request(
        &self,
        bearer: Option<&str>,
        project: Option<&str>,
    ) -> Result<String, (StatusCode, &'static str)> {
        self.admit_data_request_with_client(
            bearer,
            project,
            org::ORG_SCOPE,
            crate::client_admission::ClientBuild::default(),
            false,
        )
    }

    /// Enterprise admission with `ITGOV-4` client compatibility evidence. The
    /// `org_scope` is the same tenant scope the route handlers use. `enforce_software`
    /// is false only for authenticated recovery surfaces such as the software-policy
    /// document itself; the session is still recorded with its real status.
    pub fn admit_data_request_with_client(
        &self,
        bearer: Option<&str>,
        project: Option<&str>,
        org_scope: &str,
        client: crate::client_admission::ClientBuild,
        enforce_software: bool,
    ) -> Result<String, (StatusCode, &'static str)> {
        if self.idp.is_none() && !web_account_mode() {
            if self.hosted_home_mode() {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Home identity provider unavailable",
                ));
            }
            // single-user local / loopback: the operator's own channel.
            return Ok(self.authority().as_str().to_string());
        }
        let org = org::Org::rebuild_in(self.store_ref(), org_scope)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "directory unavailable"))?;
        let authority = bearer.and_then(|t| self.authenticate_bearer(t));
        // Hosted web account (ADR 0077): an opaque GaugeDesk session or legacy verified id-token
        // (header or shared `.gaugewright.com` cookie) is the authorization. Every request must
        // carry one; there is **no bootstrap-passthrough** here, because the "directory" is per-person
        // tenants, not the default org scope (so the `provisioned` check below is always false and
        // would otherwise leave `/account/*` open to anonymous callers). Fail-closed (`INV-20`).
        // The authenticated authority IS the person; per-person account-scope isolation is layered
        // by the routes on top of this gate.
        if web_account_mode() && !self.hosted_home_mode() {
            return authority.map(|a| a.as_str().to_string()).ok_or((
                StatusCode::UNAUTHORIZED,
                "authenticate to access your account",
            ));
        }
        let provisioned = org
            .members
            .values()
            .any(|m| m.status == org::MembershipStatus::Active);
        if !provisioned && self.hosted_home_mode() {
            return Err((StatusCode::FORBIDDEN, "Home has no active owner"));
        }
        if !provisioned {
            // bootstrap: directory not yet provisioned — actor resolved best-effort.
            return Ok(authority
                .map(|a| a.as_str().to_string())
                .unwrap_or_else(|| "anonymous".to_string()));
        }
        let Some(authority) = authority else {
            return Err((
                StatusCode::UNAUTHORIZED,
                "authenticate to access this workspace",
            ));
        };
        if org.role_of(authority.as_str()).is_none() {
            return Err((StatusCode::FORBIDDEN, "not an active member"));
        }
        // SEC-2: enforce the org session lifetime / idle-timeout policy, keyed by a hash of
        // the bearer (never the raw token). A no-op when both bounds are unset, so a workspace
        // with no session policy is unaffected. A violation forces re-authentication (401).
        // SEC-2 + ITGOV-2/ITGOV-3(d): record the session's activity on every authenticated
        // data request — this populates the IT session roster (`GET /admin/sessions`) *and*
        // enforces the org lifetime/idle bounds. Unset bounds (`0`) record without refusing,
        // so the roster is populated even with no timeout policy; a violated bound is a `401`.
        let (lifetime_ms, idle_ms) = org.session_bounds_ms();
        let key = org::sha256_hex(bearer.unwrap_or_default());
        let now = self.session_activity.now_ms();
        let now_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        let software = crate::client_admission::evaluate_client(
            org.software_policy.as_ref(),
            &client,
            now_unix_ms,
        );
        if let Err(expiry) = self.session_activity.check_and_touch_client(
            &key,
            authority.as_str(),
            now,
            lifetime_ms,
            idle_ms,
            client,
            software.clone(),
        ) {
            return Err((StatusCode::UNAUTHORIZED, expiry.reason()));
        }
        if enforce_software
            && software.status == crate::client_admission::ClientAdmissionStatus::Blocked
        {
            return Err((
                StatusCode::UPGRADE_REQUIRED,
                "GaugeDesk client does not satisfy organization software policy",
            ));
        }
        if let Some(project) = project {
            if !org.can_access_project(authority.as_str(), project) {
                return Err((StatusCode::FORBIDDEN, "not in scope for this project"));
            }
        }
        Ok(authority.as_str().to_string())
    }

    /// Authenticate a bearer to its durable authority without granting Home
    /// membership. Invitation acceptance uses this narrower seam: it must know
    /// who is accepting before it can atomically activate that exact member.
    pub fn authenticate_identity(
        &self,
        bearer: Option<&str>,
    ) -> Result<gaugedesk_core::ids::AuthorityId, (StatusCode, &'static str)> {
        if self.idp.is_none() && !web_account_mode() {
            if self.hosted_home_mode() {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Home identity provider unavailable",
                ));
            }
            return Ok(self.authority().clone());
        }
        bearer
            .and_then(|token| self.authenticate_bearer(token))
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "authenticate to accept this invitation",
            ))
    }

    /// **ENTSEC-2** ([ADR 0065]): the set of projects a request's caller may **see** in the
    /// nav / list projections — the visibility complement to [`authorize_scope`](Self::authorize_scope).
    /// Mirrors [`admit_data_request`](Self::admit_data_request)'s membership logic: solo (no IdP),
    /// bootstrap (unprovisioned), and `owner`/`admin` are unrestricted ([`ProjectVisibility::All`]);
    /// any other active member is restricted to their explicitly-granted projects. An
    /// unauthenticated / non-member caller in enterprise mode (which the ENTSEC-1 data-route gate
    /// would already have refused with `401`/`403`) resolves fail-closed to an empty set, so a
    /// projection can never leak project existence to someone the gate would reject.
    pub fn project_visibility(&self, bearer: Option<&str>) -> ProjectVisibility {
        self.project_visibility_in(bearer, org::ORG_SCOPE)
    }

    /// [`project_visibility`](Self::project_visibility) against a specific tenant scope
    /// (`DEPLOY-6`): the visibility set must be read from the same tenant directory the
    /// projection lists. Delegated to by [`project_visibility`] with the default
    /// [`ORG_SCOPE`](org::ORG_SCOPE).
    pub fn project_visibility_in(
        &self,
        bearer: Option<&str>,
        org_scope: &str,
    ) -> ProjectVisibility {
        if self.idp.is_none() && !web_account_mode() {
            if self.hosted_home_mode() {
                return ProjectVisibility::Only(BTreeSet::new());
            }
            return ProjectVisibility::All; // solo / loopback: the operator's own channel
        }
        let Ok(org) = org::Org::rebuild_in(self.store_ref(), org_scope) else {
            return ProjectVisibility::Only(BTreeSet::new()); // directory unreadable: leak nothing
        };
        let provisioned = org
            .members
            .values()
            .any(|m| m.status == org::MembershipStatus::Active);
        if !provisioned && self.hosted_home_mode() {
            return ProjectVisibility::Only(BTreeSet::new());
        }
        if !provisioned {
            return ProjectVisibility::All; // bootstrap: nothing to scope against yet
        }
        let Some(authority) = bearer.and_then(|t| self.authenticate_bearer(t)) else {
            return ProjectVisibility::Only(BTreeSet::new()); // unauthenticated: leak nothing
        };
        match org.role_of(authority.as_str()) {
            Some(role)
                if role == gaugedesk_core::abac::Role::owner()
                    || role == gaugedesk_core::abac::Role::admin() =>
            {
                ProjectVisibility::All // the client org's own people see every project
            }
            Some(_) => ProjectVisibility::Only(org.granted_project_ids(authority.as_str())),
            None => ProjectVisibility::Only(BTreeSet::new()), // not a member: leak nothing
        }
    }

    /// Whether a **chat** is visible to a caller under `vis` (`ENTSEC-2`): its project must be
    /// visible. A chat with no resolvable project (an edit/authoring chat — not a client
    /// member's surface) is visible only under [`ProjectVisibility::All`].
    pub fn chat_visible(&self, chat_id: &str, vis: &ProjectVisibility) -> bool {
        match vis {
            ProjectVisibility::All => true,
            ProjectVisibility::Only(_) => self
                .library
                .project_of_chat(chat_id)
                .map(|p| vis.allows(p))
                .unwrap_or(false),
        }
    }

    /// **ENTSEC-2**: resolve the **project** a request path is scoped to, if any — the chat /
    /// placement / project the URL addresses. `None` for the non-project-scoped routes (the
    /// workspace nav, archetype editing, `POST /projects` / `POST /chats`, `/admin/*`), which the
    /// per-project gate does not apply to (membership alone governs them). Chat & scope ids
    /// resolve through the library (`chat → instance → project`); a `/projects/{id}` or
    /// `/placements/{id}` path carries / resolves the id directly. An unknown id resolving to
    /// `None` is safe: the handler itself 404s, leaking nothing. `pub` so the extracted
    /// enterprise band's ENTSEC-1 middleware (`gaugedesk-ee`) resolves the same scope.
    pub fn scope_project_of_path(&self, path: &str) -> Option<String> {
        let mut segs = path.trim_start_matches('/').split('/');
        match segs.next()? {
            "chats" | "scopes" => self
                .library
                .project_of_chat(segs.next()?)
                .map(str::to_string),
            "placements" => self
                .library
                .project_of_instance(segs.next()?)
                .map(str::to_string),
            "workstreams" => self
                .library_workstream(segs.next()?)
                .and_then(|workstream| {
                    self.placement_project_id(&workstream.instance_id)
                        .map(str::to_string)
                }),
            "projects" => {
                let id = segs.next()?;
                (!id.is_empty()).then(|| id.to_string())
            }
            _ => None,
        }
    }

    /// Whether the bearer may administer a member in `target_team` (`RBAC-4`).
    /// Single-user (no IdP) ⇒ always (ungated). Enterprise: an `owner` is org-wide; an
    /// `admin` with no team is org-wide; an `admin` scoped to a team may administer
    /// only that team — so a team-scoped admin cannot touch another team (fail-closed).
    /// Called *after* the capability gate, which already established the actor is an
    /// owner/admin.
    pub fn team_scope_ok(&self, bearer: Option<&str>, target_team: Option<&str>) -> bool {
        self.team_scope_ok_in(bearer, target_team, org::ORG_SCOPE)
    }

    /// [`team_scope_ok`](Self::team_scope_ok) against a specific tenant scope (`DEPLOY-6`):
    /// the team check must fold the same tenant directory the handler acts on. Delegated to
    /// by [`team_scope_ok`] with the default [`ORG_SCOPE`](org::ORG_SCOPE).
    pub fn team_scope_ok_in(
        &self,
        bearer: Option<&str>,
        target_team: Option<&str>,
        org_scope: &str,
    ) -> bool {
        if self.idp.is_none() && !web_account_mode() {
            return true; // single-user local: ungated
        }
        let Some(authority) = bearer.and_then(|t| self.authenticate_bearer(t)) else {
            return false;
        };
        let Ok(org) = org::Org::rebuild_in(self.store_ref(), org_scope) else {
            return false;
        };
        match org.role_of(authority.as_str()) {
            Some(r) if r == gaugedesk_core::abac::Role::owner() => true,
            Some(r) if r == gaugedesk_core::abac::Role::admin() => {
                match org.team_of(authority.as_str()) {
                    None => true, // org-wide admin
                    Some(actor_team) => target_team == Some(actor_team.as_str()),
                }
            }
            _ => false,
        }
    }

    /// The label for the authority acting on a request (`AUD-1`): in enterprise mode
    /// the bearer's authenticated authority (or `"anonymous"` if it does not
    /// authenticate); in single-user local mode this control plane's own authority.
    /// Used to attribute audit entries to their actor (`INV-21`).
    pub fn actor(&self, bearer: Option<&str>) -> String {
        if self.idp.is_some() || web_account_mode() {
            bearer
                .and_then(|token| self.authenticate_bearer(token))
                .map(|authority| authority.as_str().to_string())
                .unwrap_or_else(|| "anonymous".to_string())
        } else {
            self.authority().as_str().to_string()
        }
    }

    /// The **account store scope** for a request (`ADR 0077`): in the hosted hub
    /// ([`web_account_mode`]) the caller's own `account::<person>` scope (resolved from the session
    /// bearer via [`actor`](Self::actor)), so authenticated people are isolated (`INV-1`);
    /// otherwise the shared [`crate::account::ACCOUNT_SCOPE`] (desktop / single-user, unchanged).
    /// The web-account gate ([`admit_data_request`](Self::admit_data_request)) guarantees a valid
    /// session before the account routes run, so the resolved actor here is the authenticated
    /// person. The account routes pass this to the `*_in(scope)` account methods.
    pub fn account_scope_for(&self, bearer: Option<&str>) -> String {
        if self.hosted_home_mode || web_account_mode() {
            crate::account::account_scope(&self.actor(bearer))
        } else {
            crate::account::ACCOUNT_SCOPE.to_string()
        }
    }

    /// Account scope for an actor that has already crossed the request/runtime
    /// authentication boundary. Hosted Home turns use this after binding the
    /// authenticated actor into the turn; desktop keeps the collapsed account
    /// scope. This avoids re-parsing a bearer after admission.
    pub(crate) fn account_scope_for_actor(&self, actor: &str) -> String {
        if self.hosted_home_mode || web_account_mode() {
            crate::account::account_scope(actor)
        } else {
            crate::account::ACCOUNT_SCOPE.to_string()
        }
    }

    /// Gate an export by the org's resource-floor policy (`RBAC-6`; the export half
    /// of `RBAC-5`). Single-user (no IdP) ⇒ open. Enterprise + provisioned ⇒ the
    /// actor authenticates and the org [`Policy`](gaugedesk_core::abac::Policy) must
    /// permit `Export` for its role — restrict-only, so e.g. a `viewer` is denied
    /// (`viewer ⇒ no export`), fail-closed (`INV-20`). Resource-attribute-specific
    /// rules (pii/region) are enforced by the resource-export protection path; this
    /// is the role-level gate the org policy adds on top.
    pub fn authorize_export(&self, bearer: Option<&str>) -> Result<(), (StatusCode, &'static str)> {
        self.authorize_export_in(bearer, org::ORG_SCOPE)
    }

    /// [`authorize_export`](Self::authorize_export) against a specific tenant scope
    /// (`DEPLOY-6`): the role gate must fold the same tenant directory the export runs
    /// against. Delegated to by [`authorize_export`] with the default
    /// [`ORG_SCOPE`](org::ORG_SCOPE).
    pub fn authorize_export_in(
        &self,
        bearer: Option<&str>,
        org_scope: &str,
    ) -> Result<(), (StatusCode, &'static str)> {
        if self.idp.is_none() && !web_account_mode() {
            return Ok(()); // single-user local: ungated
        }
        let org = org::Org::rebuild_in(self.store_ref(), org_scope)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "directory unavailable"))?;
        let provisioned = org
            .members
            .values()
            .any(|m| m.status == org::MembershipStatus::Active);
        if !provisioned {
            return Ok(());
        }
        let Some(authority) = bearer.and_then(|t| self.authenticate_bearer(t)) else {
            return Err((StatusCode::UNAUTHORIZED, "authenticate to export"));
        };
        let Some(role) = org.role_of(authority.as_str()) else {
            return Err((StatusCode::FORBIDDEN, "not an active member"));
        };
        let actor = gaugedesk_core::abac::AuthorityAttributes {
            roles: std::iter::once(role).collect(),
            ..Default::default()
        };
        let decision = gaugedesk_core::abac::Decision {
            actor,
            resource: gaugedesk_core::abac::ResourceAttributes::default(),
            action: gaugedesk_core::abac::Action::Export,
            context: gaugedesk_core::abac::Context {
                ceiling_attested: false,
            },
        };
        if gaugedesk_core::abac::permitted_with_policy(true, &org.policy(), &decision) {
            Ok(())
        } else {
            Err((StatusCode::FORBIDDEN, "role is not permitted to export"))
        }
    }

    /// **SECAUD-5 / CORE-6**: enforce the **resource-attribute** ABAC floor on a specific
    /// resource's export — the live-route half of [ADR 0032] step 4. Composes the actor's
    /// IdP claims with the resource's persisted classification/region (captured at ingest)
    /// and the org [`Policy`](gaugedesk_core::abac::Policy): restrict-only, so e.g. a `Pii`
    /// resource at an **unattested** ceiling is denied egress even when the role-level gate
    /// and the consent floor would allow it. Solo (no IdP) / not-provisioned ⇒ open
    /// (unchanged); unlabeled (`Regulated`/default) resources are unconstrained by the
    /// example policy, so existing exports are unaffected. Fail-closed (`INV-20`).
    pub fn authorize_resource_export(
        &self,
        bearer: Option<&str>,
        engagement: &str,
        res_id: &gaugedesk_core::resource::ResourceId,
    ) -> Result<(), (StatusCode, &'static str)> {
        self.authorize_resource_export_in(bearer, engagement, res_id, org::ORG_SCOPE)
    }

    /// [`authorize_resource_export`](Self::authorize_resource_export) against a specific
    /// tenant scope (`DEPLOY-6`): the directory role composed with the resource attributes
    /// must be read from the same tenant directory the export runs against. Delegated to by
    /// [`authorize_resource_export`] with the default [`ORG_SCOPE`](org::ORG_SCOPE).
    pub fn authorize_resource_export_in(
        &self,
        bearer: Option<&str>,
        engagement: &str,
        res_id: &gaugedesk_core::resource::ResourceId,
        org_scope: &str,
    ) -> Result<(), (StatusCode, &'static str)> {
        if self.idp.is_none() && !web_account_mode() {
            return Ok(()); // single-user local / loopback: ungated
        }
        let org = org::Org::rebuild_in(self.store_ref(), org_scope)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "directory unavailable"))?;
        let provisioned = org
            .members
            .values()
            .any(|m| m.status == org::MembershipStatus::Active);
        if !provisioned {
            return Ok(());
        }
        let Some(authority) = bearer.and_then(|t| self.authenticate_bearer(t)) else {
            return Err((StatusCode::UNAUTHORIZED, "authenticate to export"));
        };
        let actor =
            org.with_directory_role(self.identity_claims(bearer, &authority), authority.as_str());
        // A local/unattested egress edge: a `Pii` resource requires an attested ceiling,
        // so it is denied here (an attested boundary integration would pass `true`).
        let context = gaugedesk_core::abac::Context {
            ceiling_attested: false,
        };
        match resource_store::abac_permits(
            self.store_ref(),
            engagement,
            res_id,
            &actor,
            gaugedesk_core::abac::Action::Export,
            context,
            &org.policy(),
            true,
        ) {
            Ok(true) => Ok(()),
            Ok(false) => Err((
                StatusCode::FORBIDDEN,
                "resource policy forbids export (data classification / residency)",
            )),
            Err(_) => Err((
                StatusCode::FORBIDDEN,
                "resource export policy could not be evaluated",
            )),
        }
    }

    /// **CORE-6** ([ADR 0032] step 4): enforce the **resource-attribute** ABAC floor when a
    /// resource's access is *granted* — the access counterpart of
    /// [`authorize_resource_export`](Self::authorize_resource_export). Composes the approving
    /// actor's IdP claims with the resource's persisted classification/region and the org
    /// [`Policy`](gaugedesk_core::abac::Policy): restrict-only, so e.g. a `Pii` resource at an
    /// **unattested** ceiling is denied a grant even when the consent reducer would allow it.
    /// Solo (no IdP) / not-provisioned ⇒ open (unchanged); unlabeled resources are
    /// unconstrained. Fail-closed (`INV-20`).
    pub fn authorize_resource_access(
        &self,
        bearer: Option<&str>,
        engagement: &str,
        res_id: &gaugedesk_core::resource::ResourceId,
    ) -> Result<(), (StatusCode, &'static str)> {
        self.authorize_resource_access_in(bearer, engagement, res_id, org::ORG_SCOPE)
    }

    /// [`authorize_resource_access`](Self::authorize_resource_access) against a specific
    /// tenant scope (`DEPLOY-6`): the directory role composed with the resource attributes
    /// must be read from the same tenant directory the grant runs against. Delegated to by
    /// [`authorize_resource_access`] with the default [`ORG_SCOPE`](org::ORG_SCOPE).
    pub fn authorize_resource_access_in(
        &self,
        bearer: Option<&str>,
        engagement: &str,
        res_id: &gaugedesk_core::resource::ResourceId,
        org_scope: &str,
    ) -> Result<(), (StatusCode, &'static str)> {
        if self.idp.is_none() && !web_account_mode() {
            return Ok(()); // single-user local / loopback: ungated
        }
        let org = org::Org::rebuild_in(self.store_ref(), org_scope)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "directory unavailable"))?;
        let provisioned = org
            .members
            .values()
            .any(|m| m.status == org::MembershipStatus::Active);
        if !provisioned {
            return Ok(());
        }
        let Some(authority) = bearer.and_then(|t| self.authenticate_bearer(t)) else {
            return Err((StatusCode::UNAUTHORIZED, "authenticate to grant access"));
        };
        let actor =
            org.with_directory_role(self.identity_claims(bearer, &authority), authority.as_str());
        let context = gaugedesk_core::abac::Context {
            ceiling_attested: false,
        };
        match resource_store::abac_permits(
            self.store_ref(),
            engagement,
            res_id,
            &actor,
            gaugedesk_core::abac::Action::Access,
            context,
            &org.policy(),
            true,
        ) {
            Ok(true) => Ok(()),
            Ok(false) => Err((
                StatusCode::FORBIDDEN,
                "resource policy forbids access (data classification / residency)",
            )),
            Err(_) => Err((
                StatusCode::FORBIDDEN,
                "resource access policy could not be evaluated",
            )),
        }
    }
}

#[cfg(test)]
mod provider_neutral_identity_tests {
    use super::*;
    use crate::app_support::LockUnpoisoned;
    use gaugedesk_core::abac::{AuthorityAttributes, Role};
    use std::collections::BTreeSet;

    #[test]
    fn account_session_never_inherits_claims_from_a_colliding_idp_authority() {
        let account_id = gaugedesk_core::ids::AuthorityId::new("person-root");
        let idp = crate::identity::LoopbackIdentityProvider::new().enroll(
            "oidc-token",
            account_id.clone(),
            AuthorityAttributes {
                roles: BTreeSet::from([Role::admin()]),
                ..AuthorityAttributes::default()
            },
        );
        let wb = Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap())
            .with_identity_provider(Arc::new(idp));
        let account_token = wb
            .account_sessions()
            .issue("person-root", crate::account_session::unix_now(), 60)
            .unwrap();

        assert!(wb
            .identity_claims(Some(&account_token), &account_id)
            .roles
            .is_empty());
        assert!(wb
            .identity_claims(Some("oidc-token"), &account_id)
            .roles
            .contains(&Role::admin()));
    }

    #[test]
    fn a_durable_opaque_session_survives_a_restart_and_revoke_is_future_only() {
        let root = tempfile::tempdir().unwrap();
        // First process: mint an OIDC-derived opaque session.
        let token = {
            let wb = crate::open_workbench(root.path()).unwrap();
            let mut g = wb.lock_unpoisoned();
            let token = g
                .mint_account_session("person-root", "oidc", 24 * 60 * 60)
                .unwrap();
            assert_eq!(
                g.account_sessions().resolve_now(&token).as_deref(),
                Some("person-root")
            );
            // The session surface reads the true minting method from the record.
            assert_eq!(
                g.account_sessions().resolve_session(&token).unwrap().1,
                "oidc"
            );
            token
        };
        // A fresh process re-seats the session from the durable index (ADR 0147 §1).
        {
            let wb = crate::open_workbench(root.path()).unwrap();
            let g = wb.lock_unpoisoned();
            assert_eq!(
                g.account_sessions().resolve_now(&token).as_deref(),
                Some("person-root"),
                "an opaque session survives a restart"
            );
            assert_eq!(
                g.account_sessions().resolve_session(&token).unwrap().1,
                "oidc"
            );
        }
        // Revoke it, then confirm it stays revoked across another restart (INV-18).
        {
            let wb = crate::open_workbench(root.path()).unwrap();
            let mut g = wb.lock_unpoisoned();
            assert!(g.revoke_account_session(&token));
            assert!(g.account_sessions().resolve_now(&token).is_none());
        }
        {
            let wb = crate::open_workbench(root.path()).unwrap();
            let g = wb.lock_unpoisoned();
            assert!(
                g.account_sessions().resolve_now(&token).is_none(),
                "a revoked session does not resurrect on restart"
            );
        }
    }

    #[test]
    fn revoking_one_session_leaves_a_concurrent_session_live() {
        let mut wb = Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap());
        let first = wb
            .mint_account_session("person-root", "oidc", 3600)
            .unwrap();
        let second = wb
            .mint_account_session("person-root", "passkey", 3600)
            .unwrap();
        assert_ne!(first, second, "each login mints its own opaque session");

        // Logout/revoke ends only the caller's own session (ADR 0147 §3).
        assert!(wb.revoke_account_session(&first));
        assert!(wb.account_sessions().resolve_now(&first).is_none());
        assert_eq!(
            wb.account_sessions().resolve_now(&second).as_deref(),
            Some("person-root"),
            "a concurrent session of the same person stays live"
        );
        assert_eq!(
            wb.account_sessions().resolve_session(&second).unwrap().1,
            "passkey"
        );
    }
}
