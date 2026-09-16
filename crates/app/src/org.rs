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

/// The fixed workspace-administration roles (ADR 0043 §2, separated by ADR 0149).
/// Custom roles + a policy-authoring surface (and a finer `security-admin` tier,
/// ADR 0149 §5) stay upmarket; M3 ships exactly these. `auditor` is the read-only
/// separation-of-duties reader (ADR 0149 §3).
pub const FIXED_ROLES: [&str; 6] = ["owner", "admin", "auditor", "member", "viewer", "billing"];

/// The **privileged** roles (ADR 0149 §1): granting one requires the owner-only
/// `GrantPrivilegedRoles` capability, and SCIM group→role mapping refuses to map a
/// group into either. Everything else is a non-privileged role `ManageMembers` covers.
pub const PRIVILEGED_ROLES: [&str; 2] = ["owner", "admin"];

/// Whether `role` is one of the fixed workspace-admin roles. Assigning an unknown
/// role is rejected at the boundary (fail-closed, `INV-20`).
pub fn is_valid_role(role: &str) -> bool {
    FIXED_ROLES.contains(&role)
}

/// Whether `role` is a **privileged** role (`owner`/`admin`) — assignable only through
/// the owner-only `GrantPrivilegedRoles` capability, and never via SCIM (ADR 0149 §1).
pub fn is_privileged_role(role: &str) -> bool {
    PRIVILEGED_ROLES.contains(&role)
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
/// domain-capture auto-join, `ID-6`), the domains still awaiting their DNS
/// proof, the default data-residency region new projects inherit (the ADR 0032
/// `region` attribute), and the tenant **kind** (party-neutral, ADR 0061).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OrgRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub verified_domains: Vec<String>,
    /// Domains an administrator has claimed but not yet proved. A pending entry
    /// is a durable place to publish the DNS challenge against and nothing
    /// more: it admits no sign-in and carries no authority until
    /// `organization.domain.verify` proves the TXT record and promotes it into
    /// `verified_domains`. Holding the claim server-side is the whole point —
    /// before it existed the domain lived only in the open form, so a reload
    /// lost it and the page could never show what was still outstanding.
    #[serde(default)]
    pub pending_domains: Vec<String>,
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

/// The durable lifecycle of an email-addressed organization invitation.
///
/// This is deliberately separate from [`MembershipRecord`]: an email address is
/// not an authenticated GaugeDesk authority, and an invitation grants no
/// standing before the recipient either presents its one-time proof while
/// signed in or returns a provider-verified matching subject through the
/// organization's explicit invited-only SSO admission mode.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum OrganizationInvitationStatus {
    #[default]
    Pending,
    Accepted,
    Declined,
    Cancelled,
}

/// A hash-only, email-addressed invitation into one organization.
///
/// The plaintext proof is response-only at creation/resend and may be delivered
/// by an administrator or an outbound-mail adapter. The append-only directory
/// retains only its SHA-256 digest, so page models, transcripts, receipts, and
/// backups cannot disclose a usable invitation.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OrganizationInvitationRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    #[serde(default)]
    pub org_id: String,
    pub email: String,
    pub role: String,
    #[serde(default)]
    pub team: Option<String>,
    pub proof_sha256: String,
    #[serde(default)]
    pub status: OrganizationInvitationStatus,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    #[serde(default)]
    pub responded_by: Option<String>,
    #[serde(default)]
    pub responded_at_ms: Option<u64>,
}

/// Record kind for [`OrganizationInvitationRecord`] facts.
pub const ORGANIZATION_INVITATION_KIND: &str = "organization_invitation";

impl OrganizationInvitationRecord {
    /// Whether this exact plaintext proof may still authorize a recipient
    /// response. Expiry is server-observed and an already-consumed/cancelled
    /// record always fails closed.
    pub fn accepts_proof(&self, proof: &str, now_ms: u64) -> bool {
        self.status == OrganizationInvitationStatus::Pending
            && self.expires_at_ms > now_ms
            && !proof.trim().is_empty()
            && self.proof_sha256 == sha256_hex(proof.trim())
    }
}

/// The SSO protocol a connection speaks (B12).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum SsoProtocol {
    #[default]
    Oidc,
    Saml,
}

/// The separately custodied credential for one organization SSO connection.
///
/// Configuration proposals never carry this record. The public connection
/// names only its opaque `credential_revision`; the plaintext is sealed under
/// the organization content key before this record enters the event store.
/// This is a singleton today because an organization has one SSO connection.
pub const SSO_CREDENTIAL_KIND: &str = "sso_credential";

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SsoCredentialRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub connection_id: String,
    pub protocol: SsoProtocol,
    /// Random opaque revision. It is deliberately not a digest of the
    /// credential, because client secrets can have low entropy.
    pub credential_revision: String,
    /// Ciphertext produced by the organization content vault. It is never
    /// returned through an HTTP projection.
    pub sealed_secret: String,
}

/// How a verified corporate subject may become an organization member
/// (`AUTH-7`, ADR 0146 §4). This is separate from the identity-provider
/// connection: changing who may enter must not invalidate a working protocol
/// configuration or its browser-test evidence.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum SsoAdmissionMode {
    InvitedOnly,
    VerifiedDomainJit,
    Scim,
}

/// Explicit organization admission policy. Absence means unconfigured, not an
/// implicit JIT default; an administrator must choose one of the three accepted
/// modes before SSO enforcement can be enabled.
pub const SSO_ADMISSION_KIND: &str = "sso_admission";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SsoAdmissionRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub mode: SsoAdmissionMode,
}

/// Which verified OIDC claims or signed SAML attributes carry identity and ABAC
/// values (B12 / `ID-3`):
/// the admin-configurable home for what was previously only a `GAUGEDESK_OIDC_*_CLAIM`
/// env knob. Every field is optional — unset means "fall back to the env knob, else do
/// not map that attribute" (fail-closed: no attribute is safer than a wrong one). The
/// subject defaults to `sub` (the OIDC stable identifier) when unset.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SsoClaimMapping {
    /// The OIDC claim naming the durable subject → authority. `None` ⇒
    /// `sub`; SAML always uses signed NameID.
    #[serde(default)]
    pub subject_claim: Option<String>,
    /// The verified email claim / signed SAML attribute used for admission.
    /// OIDC defaults to `email`; SAML defaults to an email-shaped NameID.
    /// An organization whose SAML NameID is opaque names its email attribute
    /// here rather than relying on an implementation-specific guess.
    #[serde(default)]
    pub email_claim: Option<String>,
    /// The claim / SAML attribute carrying roles. `None` ⇒ none.
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
    /// Digest of the exact connection configuration. The server replaces this
    /// on every admitted edit; browser-test evidence binds to this value rather
    /// than to a timeless `connected` flag.
    #[serde(default)]
    pub revision: String,
    /// Opaque revision of the separately sealed credential, when this OIDC
    /// client is confidential. Its presence is safe to project only as a
    /// boolean; the value remains server-side connection material.
    #[serde(default)]
    pub credential_revision: Option<String>,
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
    /// Exact SAML service-provider entity id bound when the connection is
    /// admitted. Empty only on legacy records created before revisioned SAML
    /// browser ceremonies existed.
    #[serde(default)]
    pub saml_sp_entity_id: String,
    /// Exact SAML assertion-consumer URL paired with `saml_sp_entity_id`.
    #[serde(default)]
    pub saml_acs_url: String,
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

impl SsoConnectionRecord {
    /// Compute the revision over the connection material, excluding the digest
    /// itself. This also gives pre-revision records a deterministic current
    /// revision without requiring an in-place migration.
    pub fn computed_revision(&self) -> String {
        let mut canonical = self.clone();
        canonical.revision.clear();
        // Enforcement is organization entry policy, not IdP protocol material.
        // Toggling it must not manufacture a new connection revision and
        // immediately invalidate the browser test that made enforcement safe.
        canonical.enforce_sso = false;
        sha256_hex(
            &serde_json::to_string(&canonical)
                .expect("SSO connection configuration serializes for revisioning"),
        )
    }

    /// Replace any caller-supplied or stale revision with the server-derived
    /// digest of this exact configuration.
    pub fn seal_revision(&mut self) {
        self.revision = self.computed_revision();
    }

    /// The exact revision represented by this record, including old records
    /// written before the explicit field existed.
    pub fn current_revision(&self) -> String {
        let computed = self.computed_revision();
        if self.revision == computed {
            self.revision.clone()
        } else {
            computed
        }
    }

    /// Exact non-secret binding placed inside the sealed credential envelope.
    /// `None` means this connection is public-client / metadata-only and has no
    /// credential to resolve.
    pub fn credential_binding(&self) -> Option<String> {
        let revision = self.credential_revision.as_deref()?;
        let protocol = match self.protocol {
            SsoProtocol::Oidc => "oidc",
            SsoProtocol::Saml => "saml",
        };
        Some(format!("sso:{}:{protocol}:{revision}", self.id))
    }
}

/// Durable evidence that one real browser authentication completed against an
/// exact enterprise-connection revision. It is not a login, membership, or
/// timeless `connected` flag; changing the connection makes this evidence
/// inapplicable without rewriting its history.
pub const SSO_BROWSER_TEST_KIND: &str = "sso_browser_test";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SsoBrowserTestRecord {
    pub id: String,
    pub connection_id: String,
    pub connection_revision: String,
    pub protocol: SsoProtocol,
    pub subject: String,
    #[serde(default)]
    pub mapped_roles: Vec<String>,
    #[serde(default)]
    pub mapped_region: Option<String>,
    #[serde(default)]
    pub mapped_tenant: Option<String>,
    pub initiated_by: String,
    pub tested_at_ms: u64,
}

/// Server-derived prerequisites for the admitted `Require SSO for members`
/// transition (`AUTH-8`, ADR 0146 §7). These facts are projected for a useful
/// setup UI, but only [`ready`](Self::ready) decides the mutation.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SsoEnforcementReadiness {
    pub connection_configured: bool,
    pub domain_verified: bool,
    pub browser_test_current: bool,
    pub admission_configured: bool,
    pub owner_subject_linked: bool,
    pub owner_recovery_ready: bool,
    /// A second active owner is a warning, not an initial hard gate.
    pub second_owner_present: bool,
}

impl SsoEnforcementReadiness {
    pub fn ready(&self) -> bool {
        self.connection_configured
            && self.domain_verified
            && self.browser_test_current
            && self.admission_configured
            && self.owner_subject_linked
            && self.owner_recovery_ready
    }
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

/// Safe operational evidence from an authenticated SCIM request. The record
/// deliberately retains only the operation, optional SCIM resource id, a
/// closed outcome/reason, and server time. Arbitrary provider payloads and
/// bearer material never enter the organization log.
pub const SCIM_SYNC_KIND: &str = "scim_sync";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ScimSyncOperation {
    Provision,
    Update,
    Deprovision,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ScimSyncStatus {
    Succeeded,
    Failed,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ScimSyncError {
    InvalidUserName,
    UnsupportedChange,
    UnknownUser,
    SeatCapacity,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ScimSyncRecord {
    pub operation: ScimSyncOperation,
    #[serde(default)]
    pub subject: Option<String>,
    pub status: ScimSyncStatus,
    #[serde(default)]
    pub error: Option<ScimSyncError>,
    pub observed_at_ms: u64,
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

/// A future-only revocation of one authenticated client's access to this exact
/// organization. The id is the public, domain-separated organization-session id —
/// never a bearer or a directly reusable credential. This record deliberately does
/// not revoke the person's Trusted Device or their access to another organization.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OrganizationSessionRevocationRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
}

/// The default published minimum audit-retention guarantee (`AUD-3`): one year. We keep the
/// log forever (`INV-6`); this is the floor a buyer is guaranteed unless they configure a
/// longer one.
pub const DEFAULT_AUDIT_RETENTION_MIN_DAYS: u64 = 365;
pub const BILLING_CONTACT_KIND: &str = "billing_contact";

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
/// history; seat state may *refuse future* activation only. It never grants a
/// role or project authority and never revokes an existing member. Singleton.
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

/// The minimum organization-owned recipient metadata GaugeWright needs for
/// billing notices. Payment instruments, postal addresses, tax identity, and
/// invoice documents remain with the payment processor. This is deliberately
/// separate from [`BillingRecord`]: reconciled subscription updates replace
/// that operational record and must never erase an independently edited
/// contact. Singleton.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct BillingContactRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub name: String,
    pub email: String,
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
    /// Exact store scope this projection was rebuilt from. Enterprise
    /// connection ids are scoped to an organization, so globally stored
    /// account-subject links and account-session methods must include this
    /// namespace rather than treating every tenant's singleton `org` id as the
    /// same provider connection.
    pub scope: String,
    pub org: Option<OrgRecord>,
    pub members: BTreeMap<String, MembershipRecord>,
    /// Email-addressed invitations that have not yet become memberships.
    pub invitations: BTreeMap<String, OrganizationInvitationRecord>,
    /// Explicit member→project scope grants (`ENTSEC-2`), folded latest-wins by id.
    pub grants: BTreeMap<String, MemberGrantRecord>,
    pub group_mappings: BTreeMap<String, GroupMappingRecord>,
    pub policy: Option<Policy>,
    pub placement_policy: Option<PlacementPolicy>,
    pub software_policy: Option<crate::client_admission::SoftwarePolicy>,
    pub sso: Option<SsoConnectionRecord>,
    /// Separately sealed credential material. It never participates in a
    /// public projection; consumers must resolve it against the current SSO
    /// connection's exact id, protocol, and credential revision.
    pub sso_credential: Option<SsoCredentialRecord>,
    /// Explicit admission mode for corporate subjects. `None` is intentionally
    /// unconfigured and cannot satisfy the enforce-SSO reducer.
    pub sso_admission: Option<SsoAdmissionRecord>,
    /// Ordered real-browser sign-in evidence. Consumers select evidence whose
    /// connection id, protocol, and revision still match the current record.
    pub sso_browser_tests: Vec<SsoBrowserTestRecord>,
    pub scim_token_sha256: Option<String>,
    /// Ordered authenticated SCIM request outcomes. Consumers project only the
    /// last successful sync and unresolved recent failures.
    pub scim_sync: Vec<ScimSyncRecord>,
    pub security: Option<SecurityPolicyRecord>,
    pub billing: Option<BillingRecord>,
    pub billing_contact: Option<BillingContactRecord>,
    pub archetype_approval: Option<ArchetypeApprovalPolicyRecord>,
    /// Organization-only session revocations keyed by stable session id.
    pub session_revocations: BTreeMap<String, OrganizationSessionRevocationRecord>,
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
    /// Return only credential ciphertext belonging to the exact current
    /// connection revision. A stale, cross-protocol, or caller-injected record
    /// is unusable rather than a fallback credential.
    pub fn current_sso_credential(&self) -> Option<&SsoCredentialRecord> {
        let connection = self.sso.as_ref()?;
        let revision = connection.credential_revision.as_deref()?;
        self.sso_credential.as_ref().filter(|credential| {
            credential.op == RecordOp::Upsert
                && credential.connection_id == connection.id
                && credential.protocol == connection.protocol
                && credential.credential_revision == revision
                && !credential.sealed_secret.is_empty()
        })
    }

    /// Rebuild the **default tenant**'s directory (the solo / singleton path) — folds the
    /// fixed [`ORG_SCOPE`]. Equivalent to [`rebuild_in`](Self::rebuild_in) at that scope.
    pub fn rebuild(store: &Store) -> Result<Org, AdmitError> {
        Self::rebuild_in(store, ORG_SCOPE)
    }

    /// Rebuild a tenant's directory by folding **its** scope's records in position order
    /// (latest-wins). For the default tenant pass [`ORG_SCOPE`]; for a named tenant pass
    /// [`tenant_scope`]`(id)`. Tenancy-as-scope (`DEPLOY-6`): the fold is scope-isolated.
    pub fn rebuild_in(store: &Store, scope: &str) -> Result<Org, AdmitError> {
        let mut org = Org {
            scope: scope.to_owned(),
            ..Org::default()
        };
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
        for row in store.records(scope, ORGANIZATION_INVITATION_KIND)? {
            let r: OrganizationInvitationRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => {
                    org.invitations.remove(&r.id);
                }
                RecordOp::Upsert => {
                    org.invitations.insert(r.id.clone(), r);
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
        for row in store.records(scope, SSO_CREDENTIAL_KIND)? {
            let r: SsoCredentialRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => org.sso_credential = None,
                RecordOp::Upsert => org.sso_credential = Some(r),
            }
        }
        for row in store.records(scope, SSO_ADMISSION_KIND)? {
            let r: SsoAdmissionRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => org.sso_admission = None,
                RecordOp::Upsert => org.sso_admission = Some(r),
            }
        }
        for row in store.records(scope, SSO_BROWSER_TEST_KIND)? {
            let r: SsoBrowserTestRecord = serde_json::from_str(&row)?;
            org.sso_browser_tests.push(r);
        }
        for row in store.records(scope, "scim_token")? {
            let r: ScimTokenRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => org.scim_token_sha256 = None,
                RecordOp::Upsert => org.scim_token_sha256 = Some(r.token_sha256),
            }
        }
        for row in store.records(scope, SCIM_SYNC_KIND)? {
            let r: ScimSyncRecord = serde_json::from_str(&row)?;
            org.scim_sync.push(r);
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
        for row in store.records(scope, BILLING_CONTACT_KIND)? {
            let r: BillingContactRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => org.billing_contact = None,
                RecordOp::Upsert => org.billing_contact = Some(r),
            }
        }
        for row in store.records(scope, "archetype_approval")? {
            let r: ArchetypeApprovalPolicyRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => org.archetype_approval = None,
                RecordOp::Upsert => org.archetype_approval = Some(r),
            }
        }
        for row in store.records(scope, "organization_session_revocation")? {
            let r: OrganizationSessionRevocationRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => {
                    org.session_revocations.remove(&r.id);
                }
                RecordOp::Upsert => {
                    org.session_revocations.insert(r.id.clone(), r);
                }
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

    /// Most recent successful real-browser test for the exact live connection
    /// revision. Old evidence remains in the append-only log but cannot satisfy
    /// a changed connection.
    pub fn current_sso_browser_test(&self) -> Option<&SsoBrowserTestRecord> {
        let connection = self.sso.as_ref()?;
        let revision = connection.current_revision();
        self.sso_browser_tests.iter().rev().find(|test| {
            test.connection_id == connection.id
                && test.connection_revision == revision
                && test.protocol == connection.protocol
        })
    }

    /// Derive the complete lockout-safety basis from current organization and
    /// account-auth facts. No client-supplied readiness flag participates.
    pub fn sso_enforcement_readiness(
        &self,
        account_auth: &crate::account_auth::AccountAuth,
    ) -> SsoEnforcementReadiness {
        let active_owners = self
            .members
            .values()
            .filter(|member| member.status == MembershipStatus::Active && member.role == "owner")
            .map(|member| member.authority.as_str())
            .collect::<Vec<_>>();
        let connection = self.sso.as_ref();
        let owner_subject_linked = active_owners
            .iter()
            .any(|account_id| self.corporate_subject_linked_for(account_auth, account_id));
        let owner_recovery_ready = active_owners.iter().any(|account_id| {
            account_auth.active_webauthn_count(account_id) > 0
                && account_auth.unused_recovery_code_count(account_id) > 0
        });
        let admission_configured =
            self.sso_admission
                .as_ref()
                .is_some_and(|admission| match admission.mode {
                    SsoAdmissionMode::InvitedOnly => true,
                    SsoAdmissionMode::VerifiedDomainJit => self
                        .org
                        .as_ref()
                        .is_some_and(|record| !record.verified_domains.is_empty()),
                    SsoAdmissionMode::Scim => self.scim_token_sha256.is_some(),
                });
        SsoEnforcementReadiness {
            connection_configured: connection.is_some(),
            domain_verified: self
                .org
                .as_ref()
                .is_some_and(|record| !record.verified_domains.is_empty()),
            browser_test_current: self.current_sso_browser_test().is_some(),
            admission_configured,
            owner_subject_linked,
            owner_recovery_ready,
            second_owner_present: active_owners.len() > 1,
        }
    }

    /// Whether `account_id` holds an active subject link for the exact current
    /// corporate connection. Old-provider and revoked links never count.
    pub fn corporate_subject_linked_for(
        &self,
        account_auth: &crate::account_auth::AccountAuth,
        account_id: &str,
    ) -> bool {
        let Some(connection) = self.sso.as_ref() else {
            return false;
        };
        let expected_kind = match connection.protocol {
            SsoProtocol::Oidc => crate::account_auth::ExternalSubjectKind::EnterpriseOidc,
            SsoProtocol::Saml => crate::account_auth::ExternalSubjectKind::EnterpriseSaml,
        };
        account_auth.external_subjects.values().any(|subject| {
            subject.status == crate::account_auth::AuthMethodStatus::Active
                && subject.account_id == account_id
                && subject.connection_id == self.enterprise_connection_key(&connection.id)
                && subject.issuer == connection.issuer
                && subject.kind == expected_kind
        })
    }

    /// Globally unambiguous key for an organization-scoped enterprise
    /// connection. The connection record is singleton-within-scope and is
    /// commonly named `org`; the account-auth ledger is global, so the scope is
    /// part of every subject-link and session-method identity.
    pub fn enterprise_connection_key(&self, connection_id: &str) -> String {
        let scope = if self.scope.is_empty() {
            ORG_SCOPE
        } else {
            &self.scope
        };
        format!("{scope}:{connection_id}")
    }

    /// The (role, team) a member carrying any of `groups` should take, from the
    /// configured group→role mappings (`SCIM-3`). The first matching mapping wins
    /// (stable BTreeMap order); `None` if no group matches (the caller defaults to
    /// `member`).
    ///
    /// A mapping into a **privileged** role (`owner`/`admin`) is refused fail-closed
    /// (ADR 0149 §1): those roles are owner-granted only and can never be conferred by
    /// SCIM. Such a mapping is dropped as if it did not match, so the caller falls back
    /// to the non-privileged default rather than silently elevating a provisioned user.
    /// (Creation of a privileged mapping is also rejected at the config boundary; this
    /// is the defense-in-depth guarantee even if one is somehow present.)
    pub fn role_for_groups(&self, groups: &[String]) -> Option<(String, Option<String>)> {
        groups
            .iter()
            .find_map(|g| self.group_mappings.get(g))
            .filter(|m| !is_privileged_role(&m.role))
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

    /// Whether this exact organization session has been durably revoked. A new
    /// authentication receives a different session id and is not caught by the old
    /// tombstone; the same credential cannot regain access after a process restart.
    pub fn organization_session_revoked(&self, session_id: &str) -> bool {
        self.session_revocations.contains_key(session_id)
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

    /// Whether activating `member_id` would fit the purchased capacity. An
    /// organization without a billing record keeps the legacy unmetered
    /// behavior. A record with zero seats deliberately freezes new activation,
    /// while already-active members remain active (`BILL-3`).
    pub fn seat_available_for(&self, member_id: &str) -> bool {
        if self
            .members
            .get(member_id)
            .is_some_and(|member| member.status == MembershipStatus::Active)
        {
            return true;
        }
        self.billing.as_ref().is_none_or(|billing| {
            u64::try_from(self.seats_used()).is_ok_and(|used| used < billing.seats)
        })
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

    /// Whether an opaque account session was minted by this exact current
    /// enterprise connection. Consumer OIDC and passkey sessions deliberately
    /// do not satisfy organization SSO enforcement.
    pub fn enterprise_session_method_matches(&self, method: &str) -> bool {
        let Some(connection) = self.sso.as_ref() else {
            return false;
        };
        let family = match connection.protocol {
            SsoProtocol::Oidc => "enterprise-oidc",
            SsoProtocol::Saml => "enterprise-saml",
        };
        method
            == format!(
                "{family}:{}",
                self.enterprise_connection_key(&connection.id)
            )
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

    #[test]
    fn organization_invitation_folds_hash_only_and_consumes_once() {
        let proof = "plain-proof-never-stored";
        let pending = OrganizationInvitationRecord {
            id: "oinv-one".into(),
            op: RecordOp::Upsert,
            org_id: ORG_ID.into(),
            email: "person@example.test".into(),
            role: "member".into(),
            team: None,
            proof_sha256: sha256_hex(proof),
            status: OrganizationInvitationStatus::Pending,
            issued_at_ms: 10,
            expires_at_ms: 100,
            responded_by: None,
            responded_at_ms: None,
        };
        let payload = serde_json::to_string(&pending).unwrap();
        assert!(!payload.contains(proof));
        let mut store = store_with(&[(ORGANIZATION_INVITATION_KIND, &payload)]);
        let folded = Org::rebuild(&store).unwrap();
        assert!(folded.invitations["oinv-one"].accepts_proof(proof, 99));
        assert!(!folded.invitations["oinv-one"].accepts_proof("wrong", 99));
        assert!(!folded.invitations["oinv-one"].accepts_proof(proof, 100));

        let mut accepted = pending;
        accepted.status = OrganizationInvitationStatus::Accepted;
        accepted.responded_by = Some("person:recipient".into());
        accepted.responded_at_ms = Some(50);
        store
            .append_record(
                ORG_SCOPE,
                ORGANIZATION_INVITATION_KIND,
                &serde_json::to_string(&accepted).unwrap(),
            )
            .unwrap();
        let folded = Org::rebuild(&store).unwrap();
        assert!(!folded.invitations["oinv-one"].accepts_proof(proof, 51));
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
    fn enterprise_connection_keys_include_the_organization_scope() {
        let store = Store::open_in_memory().unwrap();
        let default = Org::rebuild(&store).unwrap();
        let alpha = Org::rebuild_in(&store, &tenant_scope("organization:alpha")).unwrap();
        let beta = Org::rebuild_in(&store, &tenant_scope("organization:beta")).unwrap();

        assert_eq!(default.enterprise_connection_key(ORG_ID), "org:org");
        assert_eq!(
            alpha.enterprise_connection_key(ORG_ID),
            "org::organization:alpha:org"
        );
        assert_ne!(
            alpha.enterprise_connection_key(ORG_ID),
            beta.enterprise_connection_key(ORG_ID)
        );
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
    fn sso_revision_is_server_derived_and_changes_with_configuration() {
        let mut record = SsoConnectionRecord {
            id: ORG_ID.into(),
            op: RecordOp::Upsert,
            protocol: SsoProtocol::Oidc,
            issuer: "https://idp.example.test".into(),
            audiences: vec!["client".into()],
            revision: "caller-value".into(),
            ..Default::default()
        };
        let expected = record.computed_revision();
        assert_eq!(record.current_revision(), expected);
        record.seal_revision();
        assert_eq!(record.revision, expected);
        record.enforce_sso = true;
        assert_eq!(
            record.current_revision(),
            expected,
            "entry enforcement is not connection material"
        );
        record.audiences.push("second-client".into());
        assert_ne!(record.current_revision(), expected);
        let before_credential = record.current_revision();
        record.credential_revision = Some("opaque-credential-revision".into());
        assert_ne!(record.current_revision(), before_credential);
    }

    #[test]
    fn sso_credential_folds_only_for_the_exact_current_connection() {
        let mut connection = SsoConnectionRecord {
            id: ORG_ID.into(),
            op: RecordOp::Upsert,
            protocol: SsoProtocol::Oidc,
            issuer: "https://idp.example.test".into(),
            audiences: vec!["gaugedesk".into()],
            credential_revision: Some("secret-rev-1".into()),
            ..Default::default()
        };
        connection.seal_revision();
        let credential = SsoCredentialRecord {
            id: ORG_ID.into(),
            op: RecordOp::Upsert,
            connection_id: ORG_ID.into(),
            protocol: SsoProtocol::Oidc,
            credential_revision: "secret-rev-1".into(),
            sealed_secret: "ciphertext".into(),
        };
        let store = store_with(&[
            ("sso", &serde_json::to_string(&connection).unwrap()),
            (
                SSO_CREDENTIAL_KIND,
                &serde_json::to_string(&credential).unwrap(),
            ),
        ]);
        let org = Org::rebuild(&store).unwrap();
        assert_eq!(
            org.current_sso_credential()
                .map(|record| record.credential_revision.as_str()),
            Some("secret-rev-1")
        );

        let mut stale = credential;
        stale.credential_revision = "secret-rev-0".into();
        let store = store_with(&[
            ("sso", &serde_json::to_string(&connection).unwrap()),
            (SSO_CREDENTIAL_KIND, &serde_json::to_string(&stale).unwrap()),
        ]);
        assert!(Org::rebuild(&store)
            .unwrap()
            .current_sso_credential()
            .is_none());
    }

    #[test]
    fn domain_capture_matches_verified_domains() {
        let rec = OrgRecord {
            id: ORG_ID.into(),
            op: RecordOp::Upsert,
            display_name: "Acme".into(),
            verified_domains: vec!["acme.com".into()],
            pending_domains: Vec::new(),
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
    fn purchased_capacity_only_gates_future_activation() {
        let billing = serde_json::to_string(&BillingRecord {
            id: "organization-billing".into(),
            op: RecordOp::Upsert,
            plan: "cloud".into(),
            seats: 2,
            managed_inference: None,
        })
        .unwrap();
        let store = store_with(&[
            (
                "membership",
                &membership("one", "one", "owner", MembershipStatus::Active),
            ),
            (
                "membership",
                &membership("two", "two", "member", MembershipStatus::Active),
            ),
            (
                "membership",
                &membership(
                    "waiting",
                    "waiting",
                    "member",
                    MembershipStatus::Deprovisioned,
                ),
            ),
            ("billing", &billing),
        ]);
        let org = Org::rebuild(&store).unwrap();
        assert!(
            org.seat_available_for("one"),
            "billing never revokes standing"
        );
        assert!(
            !org.seat_available_for("waiting"),
            "a third activation is refused"
        );
    }

    #[test]
    fn billing_contact_is_independent_of_subscription_reconciliation() {
        let contact = BillingContactRecord {
            id: "tenant-billing-contact".into(),
            op: RecordOp::Upsert,
            name: "Ada Lovelace".into(),
            email: "billing@example.test".into(),
        };
        let first_billing = BillingRecord {
            id: "organization-billing".into(),
            op: RecordOp::Upsert,
            plan: "business".into(),
            seats: 2,
            managed_inference: None,
        };
        let replacement_billing = BillingRecord {
            seats: 5,
            ..first_billing.clone()
        };
        let contact_json = serde_json::to_string(&contact).unwrap();
        let first_billing_json = serde_json::to_string(&first_billing).unwrap();
        let replacement_billing_json = serde_json::to_string(&replacement_billing).unwrap();
        let store = store_with(&[
            (BILLING_CONTACT_KIND, &contact_json),
            ("billing", &first_billing_json),
            ("billing", &replacement_billing_json),
        ]);

        let org = Org::rebuild(&store).unwrap();
        assert_eq!(org.billing_contact, Some(contact));
        assert_eq!(org.billing.unwrap().seats, 5);
    }

    #[test]
    fn fixed_roles_validate() {
        assert!(is_valid_role("owner") && is_valid_role("billing"));
        // ADR 0149 §3: the read-only auditor is a fixed role.
        assert!(is_valid_role("auditor"));
        assert!(!is_valid_role("superuser") && !is_valid_role(""));
    }

    #[test]
    fn privileged_roles_are_owner_and_admin_only() {
        // ADR 0149 §1: only owner/admin are privileged (owner-granted only).
        assert!(is_privileged_role("owner") && is_privileged_role("admin"));
        for r in ["auditor", "member", "viewer", "billing", "", "superuser"] {
            assert!(!is_privileged_role(r), "{r:?} must not be privileged");
        }
    }

    fn group_mapping(group: &str, role: &str) -> String {
        serde_json::to_string(&GroupMappingRecord {
            id: group.into(),
            op: RecordOp::Upsert,
            group: group.into(),
            role: role.into(),
            team: None,
        })
        .unwrap()
    }

    #[test]
    fn scim_group_mapping_refuses_privileged_roles() {
        // ADR 0149 §1: SCIM may never confer owner/admin. Even if a privileged mapping
        // is somehow present, `role_for_groups` drops it (fail-closed to the default),
        // while a non-privileged mapping resolves normally.
        let store = store_with(&[
            ("group_mapping", &group_mapping("eng-leads", "admin")),
            ("group_mapping", &group_mapping("owners", "owner")),
            ("group_mapping", &group_mapping("eng", "member")),
            ("group_mapping", &group_mapping("finance", "billing")),
        ]);
        let org = Org::rebuild(&store).unwrap();

        assert_eq!(org.role_for_groups(&["eng-leads".into()]), None);
        assert_eq!(org.role_for_groups(&["owners".into()]), None);
        assert_eq!(
            org.role_for_groups(&["eng".into()]),
            Some(("member".into(), None))
        );
        assert_eq!(
            org.role_for_groups(&["finance".into()]),
            Some(("billing".into(), None))
        );
    }

    #[test]
    fn browser_test_evidence_applies_only_to_the_exact_connection_revision() {
        let mut connection = SsoConnectionRecord {
            id: ORG_ID.into(),
            protocol: SsoProtocol::Oidc,
            issuer: "https://idp.example.test".into(),
            audiences: vec!["gaugedesk".into()],
            ..Default::default()
        };
        connection.seal_revision();
        let test = SsoBrowserTestRecord {
            id: "ssotest-1".into(),
            connection_id: connection.id.clone(),
            connection_revision: connection.current_revision(),
            protocol: SsoProtocol::Oidc,
            subject: "corporate-subject".into(),
            mapped_roles: vec!["engineering".into()],
            mapped_region: None,
            mapped_tenant: None,
            initiated_by: "owner".into(),
            tested_at_ms: 42,
        };
        let connection_json = serde_json::to_string(&connection).unwrap();
        let test_json = serde_json::to_string(&test).unwrap();
        let store = store_with(&[
            ("sso", &connection_json),
            (SSO_BROWSER_TEST_KIND, &test_json),
        ]);
        let org = Org::rebuild(&store).unwrap();
        assert_eq!(org.current_sso_browser_test(), Some(&test));

        let mut changed = connection;
        changed.audiences = vec!["replacement-client".into()];
        changed.seal_revision();
        let changed_json = serde_json::to_string(&changed).unwrap();
        let store = store_with(&[
            ("sso", &connection_json),
            (SSO_BROWSER_TEST_KIND, &test_json),
            ("sso", &changed_json),
        ]);
        let org = Org::rebuild(&store).unwrap();
        assert!(org.current_sso_browser_test().is_none());
        assert_eq!(org.sso_browser_tests, vec![test], "history remains");
    }

    #[test]
    fn sso_admission_is_explicit_and_folds_latest_wins() {
        let invited = SsoAdmissionRecord {
            id: ORG_ID.into(),
            op: RecordOp::Upsert,
            mode: SsoAdmissionMode::InvitedOnly,
        };
        let scim = SsoAdmissionRecord {
            mode: SsoAdmissionMode::Scim,
            ..invited.clone()
        };
        let store = store_with(&[
            (
                SSO_ADMISSION_KIND,
                &serde_json::to_string(&invited).unwrap(),
            ),
            (SSO_ADMISSION_KIND, &serde_json::to_string(&scim).unwrap()),
        ]);
        assert_eq!(Org::rebuild(&store).unwrap().sso_admission, Some(scim));
        assert!(Org::default().sso_admission.is_none());
    }

    #[test]
    fn sso_enforcement_requires_every_lockout_safety_fact_but_not_a_second_owner() {
        use crate::account_auth::{
            AuthMethodStatus, ExternalSubjectKind, ExternalSubjectRecord, RecoveryBatchRecord,
            RecoveryBatchStatus, RecoveryCodeRecord, WebAuthnMethodRecord,
        };

        let mut connection = SsoConnectionRecord {
            id: ORG_ID.into(),
            protocol: SsoProtocol::Oidc,
            issuer: "https://idp.example.test".into(),
            audiences: vec!["gaugedesk".into()],
            ..Default::default()
        };
        connection.seal_revision();
        let mut org = Org {
            org: Some(OrgRecord {
                id: ORG_ID.into(),
                op: RecordOp::Upsert,
                display_name: "Acme".into(),
                verified_domains: vec!["acme.example".into()],
                pending_domains: Vec::new(),
                default_region: None,
                kind: Default::default(),
            }),
            sso: Some(connection.clone()),
            sso_admission: Some(SsoAdmissionRecord {
                id: ORG_ID.into(),
                op: RecordOp::Upsert,
                mode: SsoAdmissionMode::InvitedOnly,
            }),
            ..Default::default()
        };
        org.members.insert(
            "owner".into(),
            MembershipRecord {
                id: "owner".into(),
                op: RecordOp::Upsert,
                org_id: ORG_ID.into(),
                authority: "account-owner".into(),
                email: "owner@acme.example".into(),
                role: "owner".into(),
                status: MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            },
        );
        org.sso_browser_tests.push(SsoBrowserTestRecord {
            id: "test".into(),
            connection_id: connection.id.clone(),
            connection_revision: connection.current_revision(),
            protocol: connection.protocol,
            subject: "corporate-owner".into(),
            mapped_roles: vec![],
            mapped_region: None,
            mapped_tenant: None,
            initiated_by: "account-owner".into(),
            tested_at_ms: 1,
        });

        let mut auth = crate::account_auth::AccountAuth::default();
        let subject = ExternalSubjectRecord::new(
            "account-owner",
            &org.enterprise_connection_key(ORG_ID),
            &connection.issuer,
            "corporate-owner",
            ExternalSubjectKind::EnterpriseOidc,
            2,
        )
        .unwrap();
        auth.external_subjects.insert(subject.id.clone(), subject);
        auth.webauthn_methods.insert(
            "credential".into(),
            WebAuthnMethodRecord {
                id: "credential".into(),
                op: RecordOp::Upsert,
                account_id: "account-owner".into(),
                verifier_json: "public-verifier".into(),
                label: "Security key".into(),
                created_at: 1,
                status: AuthMethodStatus::Active,
            },
        );
        auth.recovery_batches.insert(
            "batch".into(),
            RecoveryBatchRecord {
                id: "batch".into(),
                op: RecordOp::Upsert,
                account_id: "account-owner".into(),
                created_at: 1,
                status: RecoveryBatchStatus::Active,
            },
        );
        auth.recovery_codes.insert(
            "code".into(),
            RecoveryCodeRecord {
                id: "code".into(),
                op: RecordOp::Upsert,
                account_id: "account-owner".into(),
                batch_id: "batch".into(),
                salt: "salt".into(),
                code_hash: "hash".into(),
                consumed_at: None,
            },
        );

        let readiness = org.sso_enforcement_readiness(&auth);
        assert!(readiness.ready());
        assert!(!readiness.second_owner_present, "second owner is a warning");

        org.sso_admission.as_mut().unwrap().mode = SsoAdmissionMode::Scim;
        let readiness = org.sso_enforcement_readiness(&auth);
        assert!(!readiness.admission_configured);
        assert!(!readiness.ready(), "SCIM needs an issued credential");
    }
}
