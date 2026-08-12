//! Organization + membership directory — the M3 enterprise substrate (`ORG-1`).
//!
//! The org-facing layer (SSO / SCIM / RBAC / audit / admin console) operates on an
//! **organization**: one company's people, the [[authority]] they sign in as, and
//! the fixed workspace-administration roles. See
//! [`specs/primitives/organization.md`](../../../specs/primitives/organization.md).
//!
//! Like the [`crate::library`], these are durable **records** folded latest-wins by
//! id (`data.md`, `INV-5`/`INV-6`) — an `Upsert` sets, a `Tombstone` removes — held
//! in a reserved `org` scope. This module is the pure data model + projection (no
//! `Workbench`/route deps); the CRUD routes and their workspace-change notifications
//! live in the ee band's `org_routes` (`gaugedesk-ee`, `ee/app` — SPLIT-1).
//! Adds no protection invariant (ADR 0020): the org
//! lives inside one authority's domain.
//!
//! [[authority]]: gaugedesk_core::ids::AuthorityId

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use gaugedesk_core::abac::{Policy, Role};
use gaugedesk_core::boundary_lifecycle::PlacementPolicy;
use gaugedesk_store::{AdmitError, Store};

// Reuse the library's latest-wins / tombstone record op — same record discipline.
pub use crate::library::RecordOp;

/// The reserved store scope holding the org record + every membership record.
pub const ORG_SCOPE: &str = "org";

/// The org is a singleton per deployment (M3 is one org per running instance, not
/// multi-tenant): its record id is fixed.
pub const ORG_ID: &str = "org";

/// The fixed workspace-administration roles (ADR 0043 §2). Custom roles + a
/// policy-authoring surface stay upmarket; M3 ships exactly these.
pub const FIXED_ROLES: [&str; 5] = ["owner", "admin", "member", "viewer", "billing"];

/// Whether `role` is one of the fixed workspace-admin roles. Assigning an unknown
/// role is rejected at the boundary (fail-closed, `INV-20`).
pub fn is_valid_role(role: &str) -> bool {
    FIXED_ROLES.contains(&role)
}

/// A member's lifecycle status. `Invited`/sync-pending is operational evidence;
/// `Active` is product truth; `Deprovisioned` retracts standing (offboarding is a
/// security control, `INV-18`).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum MembershipStatus {
    #[default]
    Invited,
    Active,
    Deprovisioned,
}

/// Which **party** a tenant is (`DEPLOY-6`, [ADR 0061](../../../specs/decisions/0061-tenant-and-home-governance.md)).
/// The org is a *party-neutral* tenant: a **client** org buys + hosts data; a **consultant**
/// org sells methods + gets paid. The same primitive, different role — the role selects which
/// levers apply (a client org sets a placement policy, a consultant org owes the seat fee /
/// `SETTLE-3`). Defaults to `Client` so the existing single-org path is unchanged.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OrgKind {
    #[default]
    Client,
    Consultant,
}

/// The org's profile (B10): display name, verified email domains (the basis for
/// domain-capture auto-join, `ID-6`), the default data-residency region new projects inherit
/// (the ADR 0032 `region` attribute), and the tenant **kind** (party-neutral, ADR 0061).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OrgRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub verified_domains: Vec<String>,
    #[serde(default)]
    pub default_region: Option<String>,
    /// The tenant party (`DEPLOY-6`): `client` (default) or `consultant`.
    #[serde(default)]
    pub kind: OrgKind,
}

/// One person in the directory (B11): the [[authority]] they authenticate to, their
/// email, their role, status, and whether the IdP (SCIM) owns their lifecycle.
///
/// [[authority]]: gaugedesk_core::ids::AuthorityId
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MembershipRecord {
    /// Stable member id (the authority string for a directly-known member, or a
    /// minted invite id for one not yet authenticated).
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    #[serde(default)]
    pub org_id: String,
    /// The `AuthorityId` string this member authenticates to (the join key to the
    /// `IdentityProvider`-resolved actor).
    pub authority: String,
    #[serde(default)]
    pub email: String,
    /// One of [`FIXED_ROLES`].
    pub role: String,
    #[serde(default)]
    pub status: MembershipStatus,
    /// `true` ⇒ lifecycle is owned by the IdP via SCIM (shown read-only in-console).
    #[serde(default)]
    pub managed_by_scim: bool,
    /// The team this member belongs to (`RBAC-4`). `None` = org-wide. A team-scoped
    /// `admin` may administer only members in the same team (`owner` is unscoped).
    #[serde(default)]
    pub team: Option<String>,
}

/// The SSO protocol a connection speaks (B12).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum SsoProtocol {
    #[default]
    Oidc,
    Saml,
}

/// Which id-token claims carry the ABAC attributes the verifier maps (B12 / `ID-3`):
/// the admin-configurable home for what was previously only a `GAUGEDESK_OIDC_*_CLAIM`
/// env knob. Every field is optional — unset means "fall back to the env knob, else do
/// not map that attribute" (fail-closed: no attribute is safer than a wrong one). The
/// subject defaults to `sub` (the OIDC stable identifier) when unset.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SsoClaimMapping {
    /// The claim naming the durable subject → authority. `None` ⇒ `sub`.
    #[serde(default)]
    pub subject_claim: Option<String>,
    /// The claim carrying roles (a JSON array or space-delimited string). `None` ⇒ none.
    #[serde(default)]
    pub roles_claim: Option<String>,
    /// The claim carrying the data-residency region. `None` ⇒ none.
    #[serde(default)]
    pub region_claim: Option<String>,
    /// The claim carrying the tenant / affiliation. `None` ⇒ none.
    #[serde(default)]
    pub tenant_claim: Option<String>,
}

/// The org's SSO connection (B12): which IdP, over which protocol, and whether SSO
/// is **enforced** (`ID-5`). `connected` is the admitted fact — a test-connection
/// result is operational evidence, never product truth (`INV-2`), so it is not
/// stored here. Singleton per org.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SsoConnectionRecord {
    // The route overrides this with the singleton id; defaulted so a POST body need
    // not carry it.
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    #[serde(default)]
    pub protocol: SsoProtocol,
    /// OIDC issuer URL / SAML IdP entityID.
    #[serde(default)]
    pub issuer: String,
    /// OIDC client id(s) the id-token `aud` must match.
    #[serde(default)]
    pub audiences: Vec<String>,
    /// OIDC discovery URL or raw SAML metadata (the connection material).
    #[serde(default)]
    pub metadata: String,
    /// Require all members to authenticate via the IdP (`ID-5`). Fail-safe: it never
    /// removes the last break-glass `owner` — that guard is structural (enforced by
    /// the member routes), independent of this flag.
    #[serde(default)]
    pub enforce_sso: bool,
    /// How id-token claims map onto ABAC attributes (`ID-3`). `#[serde(default)]` keeps
    /// old log records (written before this field) parseable (`INV-6`).
    #[serde(default)]
    pub claim_mapping: SsoClaimMapping,
}

/// The org's resource-floor ABAC policy (B15, `RBAC-6`): the per-org [`Policy`] the
/// export/access gate reads. Still **fixed roles, not a DSL** (ADR 0043 §3) — the
/// authorable surface is the role set; the policy carries their restrict-only rules
/// (e.g. `viewer ⇒ no export`). Singleton per org.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PolicyRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub policy: Policy,
}

/// The org's **placement policy** (`DEPLOY-2`, [ADR 0059](../../../specs/decisions/0059-deployment-topology-headless-control-plane-policy-gated-pairing.md)/[ADR 0061](../../../specs/decisions/0061-tenant-and-home-governance.md)):
/// which `(operator, attested)` deployment modes are admissible for engagements touching this
/// org's data. Restrict-only (`PlacementPolicy::admits`); the engagement pairing consults it
/// at the client's `accept` (`DEPLOY-3`). Singleton per org; absent ⇒ the open policy.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PlacementPolicyRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    #[serde(default)]
    pub policy: PlacementPolicy,
}

/// The org's enterprise client compatibility floor (`ITGOV-4`, ADR 0095).
/// This is session admission policy, not endpoint attestation. The reported build
/// is evaluated by the Home on every enterprise request.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SoftwarePolicyRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    #[serde(flatten)]
    pub policy: crate::client_admission::SoftwarePolicy,
}

/// The org's SCIM provisioning token (B13). Only the **hash** is stored — the
/// plaintext is shown once at issuance and never persisted (`SEC-5`: no secret at
/// rest in plaintext). Rotating issues a new token and overwrites the hash, so the
/// prior token stops authenticating. Singleton per org.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ScimTokenRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    /// Hex-encoded SHA-256 of the bearer token.
    pub token_sha256: String,
}

/// The org's security policy (B15 / `SEC-1`/`-2`/`-3`): MFA enforcement, session
/// lifetime / idle timeout, and the default residency region. These controls
/// *compose with* — never widen — the protection floor (`ABAC_MONOTONE`). The MFA
/// factor and session tokens are enforced by the IdP (under enforce-SSO) / the
/// session layer; this record is the org-level declaration they honor. Singleton.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SecurityPolicyRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    /// Require multi-factor auth for all members (`SEC-1`).
    #[serde(default)]
    pub require_mfa: bool,
    /// Absolute session lifetime in seconds (`SEC-2`); `0` = unset.
    #[serde(default)]
    pub session_lifetime_secs: u64,
    /// Idle timeout in seconds (`SEC-2`); `0` = unset.
    #[serde(default)]
    pub idle_timeout_secs: u64,
    /// Default data-residency region for new projects (`SEC-3`; the ADR 0032 `region`).
    #[serde(default)]
    pub residency_region: Option<String>,
    /// The **minimum audit-retention guarantee** in days surfaced to the buyer (`AUD-3`).
    /// The audit timeline is the append-only event log (`INV-6`), so we retain *forever* by
    /// construction — this is a **promise floor** (the contractual minimum), never a delete
    /// policy. `0` ⇒ the published [`DEFAULT_AUDIT_RETENTION_MIN_DAYS`].
    #[serde(default)]
    pub audit_retention_min_days: u64,
    /// Whether this org **accepts auto-upgrades** of archetypes its placements use (`UX-9`,
    /// [ADR 0063]). Default `false` — manual: an archetype owner's auto-upgrade preference
    /// only takes effect where the hosting org allows it, else it falls back to manual (the
    /// host admits changes to its own placements, `INV-13`).
    #[serde(default)]
    pub allow_auto_upgrade: bool,
}

/// The default published minimum audit-retention guarantee (`AUD-3`): one year. We keep the
/// log forever (`INV-6`); this is the floor a buyer is guaranteed unless they configure a
/// longer one.
pub const DEFAULT_AUDIT_RETENTION_MIN_DAYS: u64 = 365;

/// The org-level **archetype-approval policy** ([ADR 0063](../../../specs/decisions/0063-archetype-approval-two-acts.md)).
/// When `require_approval` is set, adding an archetype to a project lands its [[placement]]
/// **pending** until the project/placement owner accepts; when unset (the default) the
/// placement is active at once (trust-by-default). This is the org default projects inherit.
/// Singleton.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ArchetypeApprovalPolicyRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    /// Require owner approval before an added archetype's placement becomes active.
    #[serde(default)]
    pub require_approval: bool,
}

/// The org's billing/seat state (B16 / `BILL-1`). **Operational, never authority**
/// (`BILL-3`/`INV-18`): a paid seat is not a grant and a lapsed plan rewrites no
/// history; seat state may *gate future* seat assignment only. Nothing in the
/// authority/role path reads this record. Singleton.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct BillingRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    /// Plan/tier label (e.g. `team`, `business`).
    #[serde(default)]
    pub plan: String,
    /// Purchased seat entitlement.
    #[serde(default)]
    pub seats: u64,
    /// Optional organization-funded managed-inference subscription (LLM-3).
    /// Operational only: suspension gates future model calls and never rewrites
    /// historical usage or authority.
    #[serde(default)]
    pub managed_inference: Option<crate::managed_inference::ManagedInferencePlan>,
}

/// A mapping from an IdP **group** to a workspace role (and optional team) (B13 /
/// `SCIM-3`). When SCIM provisions a user carrying this group, the member takes the
/// mapped role/team instead of the default `member`. Keyed by group name.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct GroupMappingRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub group: String,
    pub role: String,
    #[serde(default)]
    pub team: Option<String>,
}

/// An explicit **member → project grant** (`ENTSEC-2`, [ADR 0065](../../../specs/decisions/0065-enterprise-trust-is-a-thin-client-workspace-not-the-tee.md)) —
/// the scoping primitive of the governed thin-client workspace. An external consultant (any
/// non-`owner`/`admin` member) may touch a project's data **only** if granted it here:
/// least-privilege, fail-closed (`INV-20`). The client org's own `owner`/`admin` bypass (they
/// see every project). Keyed `"{authority}:{project_id}"` so a grant is revocable per
/// `(member, project)` by tombstone (future-only revocation, `INV-18`). In practice it is
/// derived from the engagement relationship (a consultant is granted the project they were
/// engaged on) — a thin explicit record rather than a new relationship model (the first cut,
/// ADR 0065).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct MemberGrantRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    /// The member authority this grant is for (joins to the IdP-resolved actor).
    pub authority: String,
    /// The project id the member may access.
    pub project_id: String,
}

impl MemberGrantRecord {
    /// The deterministic id binding a `(member, project)` pair — so re-granting upserts and
    /// revoking tombstones the same record.
    pub fn make_id(authority: &str, project_id: &str) -> String {
        format!("{authority}:{project_id}")
    }
}

/// The folded org directory projection (derived, rebuildable — `INV-5`).
#[derive(Default, Clone, Debug)]
pub struct Org {
    pub org: Option<OrgRecord>,
    pub members: BTreeMap<String, MembershipRecord>,
    /// Explicit member→project scope grants (`ENTSEC-2`), folded latest-wins by id.
    pub grants: BTreeMap<String, MemberGrantRecord>,
    pub group_mappings: BTreeMap<String, GroupMappingRecord>,
    pub policy: Option<Policy>,
    pub placement_policy: Option<PlacementPolicy>,
    pub software_policy: Option<crate::client_admission::SoftwarePolicy>,
    pub sso: Option<SsoConnectionRecord>,
    pub scim_token_sha256: Option<String>,
    pub security: Option<SecurityPolicyRecord>,
    pub billing: Option<BillingRecord>,
    pub archetype_approval: Option<ArchetypeApprovalPolicyRecord>,
}

/// The store scope holding tenant `tenant`'s org records (`DEPLOY-6` tenancy-as-scope).
/// The deployment's **default tenant** (solo / the singleton, `tenant == ""` or `ORG_ID`)
/// uses the fixed [`ORG_SCOPE`] — so the single-user path is unchanged; a **named** tenant
/// (hosted multi-tenant) gets its own isolated scope `org::<tenant>`. Isolation is by scope,
/// so one tenant's directory can never fold into another's (`INV-1`/`INV-22`).
pub fn tenant_scope(tenant: &str) -> String {
    if tenant.is_empty() || tenant == ORG_ID {
        ORG_SCOPE.to_string()
    } else {
        format!("{ORG_SCOPE}::{tenant}")
    }
}

impl Org {
    /// Rebuild the **default tenant**'s directory (the solo / singleton path) — folds the
    /// fixed [`ORG_SCOPE`]. Equivalent to [`rebuild_in`](Self::rebuild_in) at that scope.
    pub fn rebuild(store: &Store) -> Result<Org, AdmitError> {
        Self::rebuild_in(store, ORG_SCOPE)
    }

    /// Rebuild a tenant's directory by folding **its** scope's records in position order
    /// (latest-wins). For the default tenant pass [`ORG_SCOPE`]; for a named tenant pass
    /// [`tenant_scope`]`(id)`. Tenancy-as-scope (`DEPLOY-6`): the fold is scope-isolated.
    pub fn rebuild_in(store: &Store, scope: &str) -> Result<Org, AdmitError> {
        let mut org = Org::default();
        for row in store.records(scope, "org")? {
            let r: OrgRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => org.org = None,
                RecordOp::Upsert => org.org = Some(r),
            }
        }
        for row in store.records(scope, "membership")? {
            let r: MembershipRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => {
                    org.members.remove(&r.id);
                }
                RecordOp::Upsert => {
                    org.members.insert(r.id.clone(), r);
                }
            }
        }
        for row in store.records(scope, "policy")? {
            let r: PolicyRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => org.policy = None,
                RecordOp::Upsert => org.policy = Some(r.policy),
            }
        }
        for row in store.records(scope, "placement_policy")? {
            let r: PlacementPolicyRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => org.placement_policy = None,
                RecordOp::Upsert => org.placement_policy = Some(r.policy),
            }
        }
        for row in store.records(scope, "software_policy")? {
            let r: SoftwarePolicyRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => org.software_policy = None,
                RecordOp::Upsert => org.software_policy = Some(r.policy),
            }
        }
        for row in store.records(scope, "sso")? {
            let r: SsoConnectionRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => org.sso = None,
                RecordOp::Upsert => org.sso = Some(r),
            }
        }
        for row in store.records(scope, "scim_token")? {
            let r: ScimTokenRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => org.scim_token_sha256 = None,
                RecordOp::Upsert => org.scim_token_sha256 = Some(r.token_sha256),
            }
        }
        for row in store.records(scope, "security")? {
            let r: SecurityPolicyRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => org.security = None,
                RecordOp::Upsert => org.security = Some(r),
            }
        }
        for row in store.records(scope, "billing")? {
            let r: BillingRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => org.billing = None,
                RecordOp::Upsert => org.billing = Some(r),
            }
        }
        for row in store.records(scope, "archetype_approval")? {
            let r: ArchetypeApprovalPolicyRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => org.archetype_approval = None,
                RecordOp::Upsert => org.archetype_approval = Some(r),
            }
        }
        for row in store.records(scope, "member_grant")? {
            let r: MemberGrantRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => {
                    org.grants.remove(&r.id);
                }
                RecordOp::Upsert => {
                    org.grants.insert(r.id.clone(), r);
                }
            }
        }
        for row in store.records(scope, "group_mapping")? {
            let r: GroupMappingRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => {
                    org.group_mappings.remove(&r.id);
                }
                RecordOp::Upsert => {
                    org.group_mappings.insert(r.id.clone(), r);
                }
            }
        }
        Ok(org)
    }

    /// The (role, team) a member carrying any of `groups` should take, from the
    /// configured group→role mappings (`SCIM-3`). The first matching mapping wins
    /// (stable BTreeMap order); `None` if no group matches (the caller defaults to
    /// `member`).
    pub fn role_for_groups(&self, groups: &[String]) -> Option<(String, Option<String>)> {
        groups
            .iter()
            .find_map(|g| self.group_mappings.get(g))
            .map(|m| (m.role.clone(), m.team.clone()))
    }

    /// The effective placement policy (`DEPLOY-2`): the configured one, or the **open**
    /// policy (admits everything) when none is set — the tenant-of-one / no-policy default.
    pub fn effective_placement_policy(&self) -> PlacementPolicy {
        self.placement_policy.clone().unwrap_or_default()
    }

    /// The effective archetype-approval requirement (ADR 0063): the org default a project
    /// inherits. `false` (frictionless, trust-by-default) when no policy is configured.
    pub fn effective_require_archetype_approval(&self) -> bool {
        self.archetype_approval
            .as_ref()
            .map(|r| r.require_approval)
            .unwrap_or(false)
    }

    /// The org session-timeout policy as `(absolute_lifetime_ms, idle_timeout_ms)` (`SEC-2`);
    /// `0` for either means that bound is unset (not enforced). `(0, 0)` when no security
    /// policy is configured — the enforcement is then a no-op.
    pub fn session_bounds_ms(&self) -> (u64, u64) {
        self.security
            .as_ref()
            .map(|s| {
                (
                    s.session_lifetime_secs.saturating_mul(1000),
                    s.idle_timeout_secs.saturating_mul(1000),
                )
            })
            .unwrap_or((0, 0))
    }

    /// The effective **minimum audit-retention guarantee** in days (`AUD-3`): the configured
    /// floor, or [`DEFAULT_AUDIT_RETENTION_MIN_DAYS`] (one year) when unset. A promise floor —
    /// the log is kept forever (`INV-6`); this is what the buyer is guaranteed at minimum.
    pub fn audit_retention_min_days(&self) -> u64 {
        match self.security.as_ref().map(|s| s.audit_retention_min_days) {
            Some(d) if d > 0 => d,
            _ => DEFAULT_AUDIT_RETENTION_MIN_DAYS,
        }
    }

    /// Whether this org accepts auto-upgrades of archetypes its placements use (`UX-9`,
    /// [ADR 0063]). Default `false` (manual) when unset — the host must opt in.
    pub fn allow_auto_upgrade(&self) -> bool {
        self.security
            .as_ref()
            .map(|s| s.allow_auto_upgrade)
            .unwrap_or(false)
    }

    /// Seats currently in use — the count of **active** members. The billing surface
    /// shows this against the purchased entitlement (`BILL-1`); it is derived, never a
    /// grant (`BILL-3`).
    pub fn seats_used(&self) -> usize {
        self.members
            .values()
            .filter(|m| m.status == MembershipStatus::Active)
            .count()
    }

    /// Whether `token` is the org's current SCIM bearer (`B13`): SHA-256 of the
    /// presented token matches the stored hash. No token issued ⇒ never authenticates
    /// (fail-closed). Constant work; the hash compare is over fixed-width hex.
    pub fn scim_token_valid(&self, token: &str) -> bool {
        let Some(stored) = &self.scim_token_sha256 else {
            return false;
        };
        &sha256_hex(token) == stored
    }

    /// Whether SSO is enforced (`ID-5`) — `false` until a connection sets the flag.
    pub fn sso_enforced(&self) -> bool {
        self.sso.as_ref().is_some_and(|s| s.enforce_sso)
    }

    /// Whether `email`'s domain is one of the org's **verified domains** (B10) — the
    /// basis for domain-capture auto-join (`ID-6`). Case-insensitive; an address with
    /// no `@`, or an org with no verified domains, is never captured (fail-closed).
    pub fn domain_is_verified(&self, email: &str) -> bool {
        let Some((_, domain)) = email.rsplit_once('@') else {
            return false;
        };
        if domain.is_empty() {
            return false;
        }
        self.org.as_ref().is_some_and(|o| {
            o.verified_domains
                .iter()
                .any(|d| d.eq_ignore_ascii_case(domain))
        })
    }

    /// The org's resource-floor policy — the stored one, or the worked enterprise
    /// default (`viewer ⇒ no export`, pii rules) if none has been set yet. The export
    /// gate evaluates against this (`RBAC-6`).
    pub fn policy(&self) -> Policy {
        self.policy
            .clone()
            .unwrap_or_else(Policy::enterprise_example)
    }

    /// The membership whose authority matches, if any.
    pub fn member_by_authority(&self, authority: &str) -> Option<&MembershipRecord> {
        self.members.values().find(|m| m.authority == authority)
    }

    /// The role attribute for an authenticated authority, read from the directory —
    /// the member's role **iff `Active`**, else `None`. Invited/deprovisioned carry
    /// no role (fail-closed, `INV-20`): an inactive member has no standing. This is
    /// what RBAC joins onto the `IdentityProvider`-authenticated actor (`RBAC-5`).
    pub fn role_of(&self, authority: &str) -> Option<Role> {
        self.members
            .values()
            .find(|m| m.authority == authority && m.status == MembershipStatus::Active)
            .map(|m| Role::new(m.role.as_str()))
    }

    /// The attributes to evaluate an authenticated authority at: what the IdP
    /// asserted, with the directory's role joined on when the IdP asserted none.
    ///
    /// This is the join [`role_of`](Self::role_of) exists for (`RBAC-5`), performed
    /// where the attributes are actually materialized. Authentication and
    /// authorization are different records: an OIDC provider populates roles only
    /// when a `roles_claim` is configured *and* the token carries it, and a Google
    /// id-token carries none — so an actor arrived role-less and every
    /// role-derived attribute evaluated as if the person held no standing, while
    /// the directory recorded them an active owner. In production that denied an
    /// agent turn over the person's own project.
    ///
    /// Only fills when the IdP asserted nothing, so a provider that does map roles
    /// stays authoritative and an org that configured `roles_claim` is unaffected.
    /// An inactive or absent member still contributes nothing — `role_of` is
    /// already fail-closed on `Active`.
    pub fn with_directory_role(
        &self,
        mut attributes: gaugedesk_core::abac::AuthorityAttributes,
        authority: &str,
    ) -> gaugedesk_core::abac::AuthorityAttributes {
        if attributes.roles.is_empty() {
            if let Some(role) = self.role_of(authority) {
                attributes.roles.insert(role);
            }
        }
        attributes
    }

    /// The project ids a member has been explicitly granted (`ENTSEC-2`). Owner/admin are not
    /// represented here — they bypass scoping; this is the explicit set for everyone else.
    pub fn granted_project_ids(&self, authority: &str) -> std::collections::BTreeSet<String> {
        self.grants
            .values()
            .filter(|g| g.authority == authority)
            .map(|g| g.project_id.clone())
            .collect()
    }

    /// Whether `authority` may access `project_id`'s data (`ENTSEC-2`, [ADR 0065]). The client
    /// org's own `owner`/`admin` bypass (they see every project); every other **active** member
    /// is scoped to the projects explicitly granted to them; an inactive / unknown authority has
    /// no standing (fail-closed, `INV-20`).
    pub fn can_access_project(&self, authority: &str, project_id: &str) -> bool {
        match self.role_of(authority) {
            None => false,
            Some(role) if role == Role::owner() || role == Role::admin() => true,
            Some(_) => self
                .grants
                .values()
                .any(|g| g.authority == authority && g.project_id == project_id),
        }
    }

    /// The team of the member with this authority, if any (`RBAC-4`).
    pub fn team_of(&self, authority: &str) -> Option<String> {
        self.member_by_authority(authority)
            .and_then(|m| m.team.clone())
    }

    /// The number of `active` members carrying `role` — the break-glass guard for
    /// `ID-5` reads this to refuse deactivating/demoting the last `owner`.
    pub fn active_count_with_role(&self, role: &str) -> usize {
        self.members
            .values()
            .filter(|m| m.status == MembershipStatus::Active && m.role == role)
            .count()
    }
}

/// Hex-encoded SHA-256 of `s` — used to store/verify the SCIM token by hash only
/// (`SEC-5`: the plaintext token is never persisted).
pub fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn store_with(records: &[(&str, &str)]) -> Store {
        let mut s = Store::open_in_memory().unwrap();
        for (kind, payload) in records {
            s.append_record(ORG_SCOPE, kind, payload).unwrap();
        }
        s
    }

    fn membership(id: &str, authority: &str, role: &str, status: MembershipStatus) -> String {
        serde_json::to_string(&MembershipRecord {
            id: id.into(),
            op: RecordOp::Upsert,
            org_id: ORG_ID.into(),
            authority: authority.into(),
            email: format!("{id}@example.com"),
            role: role.into(),
            status,
            managed_by_scim: false,
            team: None,
        })
        .unwrap()
    }

    /// The production case: an OIDC actor arrives with no roles, because a
    /// provider only maps them when a `roles_claim` is configured and a Google
    /// id-token carries none. The directory records the same authority an active
    /// owner, and that is the record authorization is supposed to read (RBAC-5).
    #[test]
    fn the_directory_supplies_the_role_an_idp_did_not_assert() {
        use gaugedesk_core::abac::AuthorityAttributes;

        let store = store_with(&[(
            "membership",
            &membership("m1", "auth-owner", "owner", MembershipStatus::Active),
        )]);
        let org = Org::rebuild(&store).expect("org");

        let joined = org.with_directory_role(AuthorityAttributes::default(), "auth-owner");
        assert_eq!(joined.roles, BTreeSet::from([Role::owner()]));

        // An IdP that does assert roles stays authoritative — the directory does
        // not override a provider an org deliberately configured.
        let asserted = AuthorityAttributes {
            roles: BTreeSet::from([Role::viewer()]),
            ..AuthorityAttributes::default()
        };
        assert_eq!(
            org.with_directory_role(asserted, "auth-owner").roles,
            BTreeSet::from([Role::viewer()]),
        );

        // An authority the directory does not know gains nothing.
        assert!(org
            .with_directory_role(AuthorityAttributes::default(), "auth-stranger")
            .roles
            .is_empty());
    }

    /// An inactive member has no standing, so the join must not manufacture one.
    #[test]
    fn an_inactive_member_contributes_no_role() {
        use gaugedesk_core::abac::AuthorityAttributes;

        for status in [MembershipStatus::Invited, MembershipStatus::Deprovisioned] {
            let store = store_with(&[(
                "membership",
                &membership("m1", "auth-pending", "owner", status),
            )]);
            let org = Org::rebuild(&store).expect("org");
            assert!(
                org.with_directory_role(AuthorityAttributes::default(), "auth-pending")
                    .roles
                    .is_empty(),
                "{status:?} must carry no role",
            );
        }
    }

    #[test]
    fn rebuild_folds_org_and_members_latest_wins() {
        let store = store_with(&[
            (
                "org",
                &serde_json::to_string(&OrgRecord {
                    id: ORG_ID.into(),
                    display_name: "Old Co".into(),
                    ..Default::default()
                })
                .unwrap(),
            ),
            (
                "org",
                &serde_json::to_string(&OrgRecord {
                    id: ORG_ID.into(),
                    display_name: "Acme".into(),
                    verified_domains: vec!["acme.com".into()],
                    default_region: Some("eu".into()),
                    ..Default::default()
                })
                .unwrap(),
            ),
            (
                "membership",
                &membership("alice", "alice", "owner", MembershipStatus::Active),
            ),
        ]);
        let org = Org::rebuild(&store).unwrap();
        assert_eq!(org.org.as_ref().unwrap().display_name, "Acme");
        assert_eq!(org.org.as_ref().unwrap().verified_domains, vec!["acme.com"]);
        assert_eq!(org.members.len(), 1);
    }

    #[test]
    fn tenancy_is_scope_isolated() {
        // DEPLOY-6: two tenants in one store, each in its own scope, never fold into each
        // other — and the default tenant (solo / singleton) stays on the fixed ORG_SCOPE.
        assert_eq!(tenant_scope(""), ORG_SCOPE); // solo collapse: default tenant
        assert_eq!(tenant_scope(ORG_ID), ORG_SCOPE);
        assert_ne!(tenant_scope("acme"), ORG_SCOPE); // a named tenant is isolated

        let org_rec = |name: &str| {
            serde_json::to_string(&OrgRecord {
                id: ORG_ID.into(),
                display_name: name.into(),
                ..Default::default()
            })
            .unwrap()
        };
        let mut s = Store::open_in_memory().unwrap();
        s.append_record(&tenant_scope(""), "org", &org_rec("Default Co"))
            .unwrap();
        s.append_record(&tenant_scope("acme"), "org", &org_rec("Acme"))
            .unwrap();

        // each tenant folds only its own scope.
        assert_eq!(
            Org::rebuild(&s).unwrap().org.unwrap().display_name,
            "Default Co"
        );
        assert_eq!(
            Org::rebuild_in(&s, &tenant_scope("acme"))
                .unwrap()
                .org
                .unwrap()
                .display_name,
            "Acme"
        );
        // an unknown tenant folds to empty — no cross-tenant leakage (fail-closed).
        assert!(Org::rebuild_in(&s, &tenant_scope("globex"))
            .unwrap()
            .org
            .is_none());
    }

    #[test]
    fn role_of_reads_active_member_role() {
        let store = store_with(&[(
            "membership",
            &membership("alice", "alice-auth", "admin", MembershipStatus::Active),
        )]);
        let org = Org::rebuild(&store).unwrap();
        assert_eq!(org.role_of("alice-auth"), Some(Role::admin()));
    }

    #[test]
    fn inactive_member_has_no_role() {
        // Fail-closed (INV-20): invited / deprovisioned members carry no standing.
        let store = store_with(&[
            (
                "membership",
                &membership("bob", "bob-auth", "admin", MembershipStatus::Invited),
            ),
            (
                "membership",
                &membership(
                    "carol",
                    "carol-auth",
                    "owner",
                    MembershipStatus::Deprovisioned,
                ),
            ),
        ]);
        let org = Org::rebuild(&store).unwrap();
        assert_eq!(org.role_of("bob-auth"), None);
        assert_eq!(org.role_of("carol-auth"), None);
    }

    #[test]
    fn unknown_authority_has_no_role() {
        let org = Org::default();
        assert_eq!(org.role_of("nobody"), None);
    }

    #[test]
    fn active_count_with_role_counts_only_active() {
        let store = store_with(&[
            (
                "membership",
                &membership("a", "a", "owner", MembershipStatus::Active),
            ),
            (
                "membership",
                &membership("b", "b", "owner", MembershipStatus::Active),
            ),
            (
                "membership",
                &membership("c", "c", "owner", MembershipStatus::Invited),
            ),
        ]);
        let org = Org::rebuild(&store).unwrap();
        assert_eq!(org.active_count_with_role("owner"), 2);
    }

    #[test]
    fn tombstone_removes_a_member() {
        let mut tomb: MembershipRecord = serde_json::from_str(&membership(
            "alice",
            "alice",
            "owner",
            MembershipStatus::Active,
        ))
        .unwrap();
        tomb.op = RecordOp::Tombstone;
        let store = store_with(&[
            (
                "membership",
                &membership("alice", "alice", "owner", MembershipStatus::Active),
            ),
            ("membership", &serde_json::to_string(&tomb).unwrap()),
        ]);
        let org = Org::rebuild(&store).unwrap();
        assert!(org.members.is_empty());
    }

    #[test]
    fn policy_folds_and_defaults_to_enterprise_example() {
        // No stored policy → the worked enterprise default (viewer ⇒ no export).
        let empty = Org::default();
        assert_eq!(
            empty.policy(),
            gaugedesk_core::abac::Policy::enterprise_example()
        );

        // A stored policy round-trips and overrides the default.
        let custom = gaugedesk_core::abac::Policy::default(); // no rules
        let rec = PolicyRecord {
            id: ORG_ID.into(),
            op: RecordOp::Upsert,
            policy: custom.clone(),
        };
        let store = store_with(&[("policy", &serde_json::to_string(&rec).unwrap())]);
        let org = Org::rebuild(&store).unwrap();
        assert_eq!(org.policy(), custom);
    }

    #[test]
    fn sso_folds_and_reports_enforcement() {
        assert!(!Org::default().sso_enforced());
        let rec = SsoConnectionRecord {
            id: ORG_ID.into(),
            op: RecordOp::Upsert,
            protocol: SsoProtocol::Oidc,
            issuer: "https://idp".into(),
            audiences: vec!["client".into()],
            metadata: String::new(),
            enforce_sso: true,
            ..Default::default()
        };
        let store = store_with(&[("sso", &serde_json::to_string(&rec).unwrap())]);
        let org = Org::rebuild(&store).unwrap();
        assert!(org.sso_enforced());
        assert_eq!(org.sso.unwrap().issuer, "https://idp");
    }

    #[test]
    fn domain_capture_matches_verified_domains() {
        let rec = OrgRecord {
            id: ORG_ID.into(),
            op: RecordOp::Upsert,
            display_name: "Acme".into(),
            verified_domains: vec!["acme.com".into()],
            default_region: None,
            kind: Default::default(),
        };
        let store = store_with(&[("org", &serde_json::to_string(&rec).unwrap())]);
        let org = Org::rebuild(&store).unwrap();
        assert!(org.domain_is_verified("alice@acme.com"));
        assert!(org.domain_is_verified("bob@ACME.COM")); // case-insensitive
        assert!(!org.domain_is_verified("eve@evil.com"));
        assert!(!org.domain_is_verified("no-at-sign")); // fail-closed
        assert!(!org.domain_is_verified("trailing@")); // empty domain
        assert!(!Org::default().domain_is_verified("x@acme.com")); // no org record
    }

    #[test]
    fn member_project_grants_scope_access_and_owner_admin_bypass() {
        // ENTSEC-2 (ADR 0065): owner/admin see every project; a plain member only the projects
        // explicitly granted; an inactive / unknown authority nothing (fail-closed).
        let grant = |authority: &str, project: &str, op: RecordOp| {
            serde_json::to_string(&MemberGrantRecord {
                id: MemberGrantRecord::make_id(authority, project),
                op,
                authority: authority.into(),
                project_id: project.into(),
            })
            .unwrap()
        };
        let store = store_with(&[
            (
                "membership",
                &membership("own", "owner-auth", "owner", MembershipStatus::Active),
            ),
            (
                "membership",
                &membership("adm", "admin-auth", "admin", MembershipStatus::Active),
            ),
            (
                "membership",
                &membership("con", "consultant-auth", "member", MembershipStatus::Active),
            ),
            (
                "membership",
                &membership("inv", "invited-auth", "member", MembershipStatus::Invited),
            ),
            (
                "member_grant",
                &grant("consultant-auth", "proj-acme", RecordOp::Upsert),
            ),
            (
                "member_grant",
                &grant("invited-auth", "proj-acme", RecordOp::Upsert),
            ),
        ]);
        let org = Org::rebuild(&store).unwrap();

        // owner/admin bypass — every project, even ones with no grant.
        assert!(org.can_access_project("owner-auth", "proj-acme"));
        assert!(org.can_access_project("owner-auth", "proj-globex"));
        assert!(org.can_access_project("admin-auth", "proj-globex"));

        // a scoped member: only the granted project.
        assert!(org.can_access_project("consultant-auth", "proj-acme"));
        assert!(!org.can_access_project("consultant-auth", "proj-globex"));
        assert_eq!(
            org.granted_project_ids("consultant-auth"),
            std::collections::BTreeSet::from(["proj-acme".to_string()])
        );

        // an inactive member has no standing even with a grant on the books (role_of is None).
        assert!(!org.can_access_project("invited-auth", "proj-acme"));
        // an unknown authority: nothing.
        assert!(!org.can_access_project("nobody", "proj-acme"));
    }

    #[test]
    fn grant_tombstone_revokes_access() {
        // INV-18 future-only revocation: a tombstoned grant removes access.
        let grant = |op: RecordOp| {
            serde_json::to_string(&MemberGrantRecord {
                id: MemberGrantRecord::make_id("consultant-auth", "proj-acme"),
                op,
                authority: "consultant-auth".into(),
                project_id: "proj-acme".into(),
            })
            .unwrap()
        };
        let store = store_with(&[
            (
                "membership",
                &membership("con", "consultant-auth", "member", MembershipStatus::Active),
            ),
            ("member_grant", &grant(RecordOp::Upsert)),
            ("member_grant", &grant(RecordOp::Tombstone)),
        ]);
        let org = Org::rebuild(&store).unwrap();
        assert!(org.grants.is_empty());
        assert!(!org.can_access_project("consultant-auth", "proj-acme"));
    }

    #[test]
    fn fixed_roles_validate() {
        assert!(is_valid_role("owner") && is_valid_role("billing"));
        assert!(!is_valid_role("superuser") && !is_valid_role(""));
    }
}
