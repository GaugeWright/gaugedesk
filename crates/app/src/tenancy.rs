//! Tenancy — the **person → tenants** tier above the [`crate::org`] directory (`ADR 0077` §9).
//!
//! The person (`user::<root>`, the account root in [`crate::account`]) sits **above** tenants;
//! tenants hang below it. A person's **personal tenant** is their default **tenant-of-one** —
//! modeled uniformly as a *real* tenant (an auto-provisioned [`crate::org::OrgRecord`] with
//! **no SSO connection** — "idp=None" — and a single `owner`/`active`
//! [`crate::org::MembershipRecord`]), so personal and org are the *same* primitive throughout,
//! but it is **not surfaced to a solo user as "your org."** See
//! [`specs/decisions/0077-web-account-person-tenants-facilities.md`](../../../specs/decisions/0077-web-account-person-tenants-facilities.md).
//!
//! This tier is a **hub concern**, not the desktop path: provisioning runs in the control-plane
//! hub's login flow (when a web account is created), **never** on desktop first-launch — the solo
//! shape stays org-free and friction-free (`ADR 0061`: org-ness stays off the core path). The
//! person's tenant list — the Console **switcher** — is an index of [`TenantRef`] records folded
//! from the reserved [`crate::account::ACCOUNT_SCOPE`] (the person's own scope). Adds no protection
//! invariant (ADR 0020); isolation stays by scope (`INV-1`).

use std::collections::BTreeMap;

use gaugedesk_store::{AdmitError, Store};

use crate::account::ACCOUNT_SCOPE;
use crate::org::{
    tenant_scope, MembershipRecord, MembershipStatus, Org, OrgRecord, RecordOp, ORG_ID,
};

use serde::{Deserialize, Serialize};

/// The record kind, in the person's [`ACCOUNT_SCOPE`], indexing the tenants they belong to.
pub const TENANT_REF_KIND: &str = "tenant_ref";

/// The **personal tenant** id for a person rooted at `root` — deterministic, so provisioning is
/// idempotent and the id is stable across the person's devices. Namespaced `personal:` so it can
/// never collide with a named org tenant.
pub fn personal_tenant_id(root: &str) -> String {
    format!("personal:{root}")
}

/// One entry in the person's tenant index (the switcher, `ADR 0077` §9): a tenant they belong to
/// and the role they hold there. Durable, folded latest-wins by id (`INV-5`/`INV-6`); a tombstone
/// drops the tenant from the switcher (leaving a tenant is future-only, `INV-18`).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TenantRef {
    /// The tenant id — the discriminator of its [`tenant_scope`]. For the personal tenant this is
    /// [`personal_tenant_id`].
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    /// Display label for the switcher.
    #[serde(default)]
    pub display_name: String,
    /// The person's role in this tenant (one of [`crate::org::FIXED_ROLES`]); `owner` for the
    /// personal tenant.
    #[serde(default)]
    pub role: String,
    /// `true` for the auto-provisioned personal tenant-of-one — the Console shows it as the
    /// person's own space, not surfaced as "your org."
    #[serde(default)]
    pub personal: bool,
}

/// A metadata-only pointer to one tenant invitation for the signed-in person.
///
/// This is a derived account-shell projection: the invitation itself remains the
/// [`MembershipRecord`] in the tenant's directory. In particular, no email,
/// invitation token, member id, project, or Home address is copied into the
/// person's account scope.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct PendingTenantInvitation {
    pub tenant_id: String,
    pub display_name: String,
    pub role: String,
}

/// The folded person→tenants index (the switcher), derived from [`ACCOUNT_SCOPE`] — rebuildable
/// (`INV-5`).
#[derive(Default, Clone, Debug)]
pub struct Tenancy {
    /// The tenants this person belongs to, folded latest-wins by id.
    pub tenants: BTreeMap<String, TenantRef>,
}

impl Tenancy {
    /// Rebuild the tenant index from the default [`ACCOUNT_SCOPE`] (solo / desktop).
    pub fn rebuild(store: &Store) -> Result<Tenancy, AdmitError> {
        Self::rebuild_in(store, ACCOUNT_SCOPE)
    }

    /// Rebuild **one person's** tenant index by folding their account `scope` (the hosted hub keys
    /// this per person via [`crate::account::account_scope`], so switchers are isolated, `INV-1`).
    pub fn rebuild_in(store: &Store, scope: &str) -> Result<Tenancy, AdmitError> {
        let mut out = Tenancy::default();
        for row in store.records(scope, TENANT_REF_KIND)? {
            let r: TenantRef = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => {
                    out.tenants.remove(&r.id);
                }
                RecordOp::Upsert => {
                    out.tenants.insert(r.id.clone(), r);
                }
            }
        }
        Ok(out)
    }

    /// Whether the person belongs to tenant `id`.
    pub fn contains(&self, id: &str) -> bool {
        self.tenants.contains_key(id)
    }

    /// The person's tenants in stable id order (what the switcher renders).
    pub fn list(&self) -> impl Iterator<Item = &TenantRef> {
        self.tenants.values()
    }

    /// The person's personal tenant-of-one, if provisioned.
    pub fn personal(&self) -> Option<&TenantRef> {
        self.tenants.values().find(|t| t.personal)
    }
}

/// Derive the signed-in person's outstanding tenant invitations. Only named
/// tenant scopes are considered: the singleton local `org` scope is not a
/// hosted workspace and must never appear in the account shell.
pub fn pending_tenant_invitations_in(
    store: &Store,
    authority: &str,
) -> Result<Vec<PendingTenantInvitation>, AdmitError> {
    let mut invitations = Vec::new();
    for scope in store.scope_ids()? {
        let Some(tenant_id) = scope.strip_prefix("org::") else {
            continue;
        };
        // Keep the inverse mapping exact even if a malformed scope somehow
        // reaches the store; no alternate string representation selects a tenant.
        if tenant_scope(tenant_id) != scope {
            continue;
        }
        let org = Org::rebuild_in(store, &scope)?;
        let invitation_role = org
            .member_by_authority(authority)
            .filter(|member| member.status == MembershipStatus::Invited)
            .map(|member| member.role.clone());
        let Some(org_record) = org.org else {
            continue;
        };
        if let Some(role) = invitation_role {
            invitations.push(PendingTenantInvitation {
                tenant_id: tenant_id.to_owned(),
                display_name: org_record.display_name,
                role,
            });
        }
    }
    Ok(invitations)
}

/// Accept the current person's invitation to exactly `tenant_id`.
///
/// The browser supplies only the tenant id. This command re-reads the tenant
/// directory, verifies the matching authority, then atomically promotes the
/// invited membership and writes the ordinary switcher entry. It is idempotent
/// for an already-active member, including repair of a missing switcher entry.
/// `Ok(None)` deliberately reveals no distinction between a missing tenant and
/// a tenant to which this person was not invited.
pub fn accept_tenant_invitation_in(
    store: &mut Store,
    authority: &str,
    tenant_id: &str,
) -> Result<Option<TenantRef>, AdmitError> {
    let scope = tenant_scope(tenant_id);
    // The Hub has no invitation flow for its singleton desktop directory.
    if scope == crate::org::ORG_SCOPE {
        return Ok(None);
    }
    let org = Org::rebuild_in(store, &scope)?;
    let Some(member) = org.member_by_authority(authority).cloned() else {
        return Ok(None);
    };
    let Some(org_record) = org.org else {
        return Ok(None);
    };
    if member.status == MembershipStatus::Deprovisioned {
        return Ok(None);
    }

    let tenant = TenantRef {
        id: tenant_id.to_owned(),
        op: RecordOp::Upsert,
        display_name: org_record.display_name,
        role: member.role.clone(),
        personal: false,
    };
    let account_scope = crate::account::account_scope(authority);
    let indexed = Tenancy::rebuild_in(store, &account_scope)?
        .tenants
        .get(tenant_id)
        .is_some_and(|existing| {
            existing.display_name == tenant.display_name
                && existing.role == tenant.role
                && !existing.personal
        });

    let mut payloads: Vec<(&str, &str, String)> = Vec::new();
    if member.status == MembershipStatus::Invited {
        let mut active = member;
        active.status = MembershipStatus::Active;
        payloads.push((&scope, "membership", serde_json::to_string(&active)?));
    }
    if !indexed {
        payloads.push((
            &account_scope,
            TENANT_REF_KIND,
            serde_json::to_string(&tenant)?,
        ));
    }
    if !payloads.is_empty() {
        let records: Vec<(&str, &str, &str)> = payloads
            .iter()
            .map(|(scope, kind, payload)| (*scope, *kind, payload.as_str()))
            .collect();
        store.append_records_atomically(&records)?;
    }
    Ok(Some(tenant))
}

/// Auto-provision the person's **personal tenant-of-one** (`ADR 0077` §9), idempotently, and index
/// it in the switcher. Called by the hub when a web account is created — **never** on the desktop
/// solo path.
///
/// Writes, only where missing (self-healing, so a re-run after a partial write completes it):
/// - into [`tenant_scope`]`(personal_tenant_id(root))`: an [`OrgRecord`] (the tenant, no SSO
///   connection ⇒ "idp=None") and a single `owner`/`active` [`MembershipRecord`] for `root`;
/// - into the person's [`ACCOUNT_SCOPE`]: a [`TenantRef`] indexing it in the switcher, flagged
///   `personal`.
///
/// Returns the personal tenant id. A second call is a no-op (both the org record and the index
/// entry already exist).
pub fn provision_personal_tenant(
    store: &mut Store,
    root: &str,
    display: &str,
) -> Result<String, AdmitError> {
    let tid = personal_tenant_id(root);
    let scope = tenant_scope(&tid);
    // The switcher index lives in the **person's own** account scope (ADR 0077), so each person's
    // tenant list is isolated on the hosted hub (`INV-1`).
    let acct_scope = crate::account::account_scope(root);

    // Authoritative existence check: does the personal tenant's own directory hold its org record?
    let org_exists = Org::rebuild_in(store, &scope)?.org.is_some();
    let indexed = Tenancy::rebuild_in(store, &acct_scope)?.contains(&tid);
    if org_exists && indexed {
        return Ok(tid); // already provisioned — no writes.
    }

    if !org_exists {
        // The tenant record: a real tenant with no SSO connection (idp=None), party-neutral default.
        let org = OrgRecord {
            id: ORG_ID.into(),
            op: RecordOp::Upsert,
            display_name: display.to_string(),
            ..Default::default()
        };
        store.append_record(&scope, "org", &serde_json::to_string(&org)?)?;

        // The single owner membership — the person is `owner`/`active` of their own tenant.
        let owner = MembershipRecord {
            id: root.to_string(),
            op: RecordOp::Upsert,
            org_id: tid.clone(),
            authority: root.to_string(),
            email: String::new(),
            role: "owner".to_string(),
            status: MembershipStatus::Active,
            managed_by_scim: false,
            team: None,
        };
        store.append_record(&scope, "membership", &serde_json::to_string(&owner)?)?;
    }

    if !indexed {
        let tref = TenantRef {
            id: tid.clone(),
            op: RecordOp::Upsert,
            display_name: display.to_string(),
            role: "owner".to_string(),
            personal: true,
        };
        store.append_record(&acct_scope, TENANT_REF_KIND, &serde_json::to_string(&tref)?)?;
    }

    Ok(tid)
}

/// The record kind, in the person's [`ACCOUNT_SCOPE`], binding one caller-supplied
/// idempotency key to the organization that key created.
pub const TENANT_CLAIM_KIND: &str = "tenant_claim";

/// One key → organization binding, so a retried create returns the organization
/// the first attempt made instead of making a second one.
///
/// It lives in the person's own account scope, and is therefore keyed by the
/// *person*, not by the credential they presented. That distinction is the whole
/// point: a bearer rotates — a hosted session mints a fresh id token on every
/// refresh — so anything keyed by the credential treats one person's retry as a
/// different caller and dedupes nothing.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TenantClaimRecord {
    /// The caller's idempotency key.
    pub id: String,
    pub op: RecordOp,
    pub tenant_id: String,
}

/// The organization a previous create with this key made, if the person still
/// belongs to it.
///
/// A claim whose tenant has since left the switcher — the person left the
/// organization — is treated as absent rather than replayed: returning a tenant
/// they no longer belong to would be a worse answer than making a new one.
pub fn organization_claimed_by(
    store: &Store,
    account_scope: &str,
    key: &str,
) -> Result<Option<TenantRef>, AdmitError> {
    let mut claims: BTreeMap<String, TenantClaimRecord> = BTreeMap::new();
    for row in store.records(account_scope, TENANT_CLAIM_KIND)? {
        let record: TenantClaimRecord = serde_json::from_str(&row)?;
        match record.op {
            RecordOp::Tombstone => {
                claims.remove(&record.id);
            }
            RecordOp::Upsert => {
                claims.insert(record.id.clone(), record);
            }
        }
    }
    let Some(claim) = claims.get(key) else {
        return Ok(None);
    };
    Ok(Tenancy::rebuild_in(store, account_scope)?
        .tenants
        .get(&claim.tenant_id)
        .cloned())
}

/// Provision one named organization for `root` and index its single owner membership in that
/// person's switcher. The tenant id is server-generated so a caller can name an organization
/// without choosing, probing, or colliding with another tenant's isolation scope.
///
/// `claim` is the caller's idempotency key, when they supplied one. It is recorded
/// alongside the organization so a retry can find it — see
/// [`organization_claimed_by`], which callers consult *before* reaching here. The
/// key is deliberately not folded into the id: deriving the id from a
/// caller-chosen string would make it guessable by anyone who could guess the
/// key, and unguessability is what the random id is for.
///
/// All four records land in one transaction. Before, a failure between them could
/// leave an organization with no membership, or a membership no switcher listed.
pub fn provision_organization(
    store: &mut Store,
    root: &str,
    account_scope: &str,
    display: &str,
    claim: Option<&str>,
) -> Result<TenantRef, AdmitError> {
    let id = format!(
        "organization:{}",
        hex::encode(crate::session::random_bytes::<16>())
    );
    let scope = tenant_scope(&id);
    let display_name = display.trim().to_string();

    let org = OrgRecord {
        id: ORG_ID.into(),
        op: RecordOp::Upsert,
        display_name: display_name.clone(),
        ..Default::default()
    };
    let owner = MembershipRecord {
        id: root.to_string(),
        op: RecordOp::Upsert,
        org_id: id.clone(),
        authority: root.to_string(),
        email: String::new(),
        role: "owner".to_string(),
        status: MembershipStatus::Active,
        managed_by_scim: false,
        team: None,
    };
    let tenant = TenantRef {
        id: id.clone(),
        op: RecordOp::Upsert,
        display_name,
        role: "owner".to_string(),
        personal: false,
    };

    let org_json = serde_json::to_string(&org)?;
    let owner_json = serde_json::to_string(&owner)?;
    let tenant_json = serde_json::to_string(&tenant)?;
    let claim_json = claim
        .map(|key| {
            serde_json::to_string(&TenantClaimRecord {
                id: key.to_owned(),
                op: RecordOp::Upsert,
                tenant_id: id.clone(),
            })
        })
        .transpose()?;

    let mut records: Vec<(&str, &str, &str)> = vec![
        (scope.as_str(), "org", org_json.as_str()),
        (scope.as_str(), "membership", owner_json.as_str()),
        (account_scope, TENANT_REF_KIND, tenant_json.as_str()),
    ];
    if let Some(claim_json) = &claim_json {
        records.push((account_scope, TENANT_CLAIM_KIND, claim_json.as_str()));
    }
    store.append_records_atomically(&records)?;
    Ok(tenant)
}

/// Why a delete was refused. Each arm is a different thing for a person to do
/// next, which is why the caller gets these rather than one "no".
#[derive(Debug, PartialEq, Eq)]
pub enum DeleteOrganizationRefusal {
    /// The person does not belong to a tenant by that id. Deliberately does not
    /// distinguish "no such organization" from "not yours", matching
    /// [`accept_tenant_invitation_in`].
    NoSuchOrganization,
    /// The personal tenant-of-one is the person's own space, not an organization
    /// they created, and deleting it would leave the account with no context.
    Personal,
    /// Only an active owner may delete.
    NotAnOwner,
    /// Someone else is still an active member. Deleting would revoke their access
    /// without their knowing, so they leave (or are deactivated) first.
    OtherMembersRemain(usize),
    /// A tenant-level facility is still active in this tenant. Every one of them
    /// bills to the tenant (`FacilityRecord::is_tenant_billable`) and its
    /// lifecycle controls are reached *through* the tenant, so deleting first
    /// would leave a live, billing service nobody can retire. Detach them first.
    FacilitiesRemain(usize),
}

/// Delete one organization the caller owns and is alone in.
///
/// The counterpart to [`provision_organization`]. Without it an organization
/// created by mistake was permanent: nothing removed one, and
/// `leave-organization` refuses a sole active owner precisely so an organization
/// cannot be orphaned — which left the person who made it the one person who
/// could neither leave nor remove it. One synthetic account accumulated nineteen.
///
/// Deliberately narrow. It refuses while any other active member remains, so a
/// delete can never silently revoke someone else's access: the others leave, and
/// the last owner deletes. That composes with the existing flow instead of
/// competing with it, and leaves the harder "delete an organization people are
/// working in" — notice, export, grace — to a design that can afford it.
///
/// It refuses on the same grounds while any tenant-level facility is still
/// active. Those are the tenant's billable standing services, and their
/// retention/deletion lifecycle is reached through the tenant, so removing the
/// tenant around them would leave a live facility still charging with nobody
/// left who can retire it. The facilities are detached first, exactly as the
/// other members leave first.
///
/// Writes in one transaction: the directory record is tombstoned, so the
/// organization stops resolving and no invitation into it can be accepted; the
/// caller's membership is deprovisioned; and the switcher entry is tombstoned.
/// Future-only revocation throughout (`INV-18`) — nothing is erased, so the
/// audit trail stays intact.
pub fn delete_organization_in(
    store: &mut Store,
    authority: &str,
    account_scope: &str,
    tenant_id: &str,
) -> Result<Result<TenantRef, DeleteOrganizationRefusal>, AdmitError> {
    let tenancy = Tenancy::rebuild_in(store, account_scope)?;
    let Some(tenant) = tenancy.tenants.get(tenant_id).cloned() else {
        return Ok(Err(DeleteOrganizationRefusal::NoSuchOrganization));
    };
    if tenant.personal {
        return Ok(Err(DeleteOrganizationRefusal::Personal));
    }
    let scope = tenant_scope(tenant_id);
    // The singleton local directory is not a hosted organization and has no
    // switcher entry to remove.
    if scope == crate::org::ORG_SCOPE {
        return Ok(Err(DeleteOrganizationRefusal::NoSuchOrganization));
    }
    let org = Org::rebuild_in(store, &scope)?;
    let Some(member) = org.member_by_authority(authority).cloned() else {
        return Ok(Err(DeleteOrganizationRefusal::NoSuchOrganization));
    };
    if member.status != MembershipStatus::Active || member.role != "owner" {
        return Ok(Err(DeleteOrganizationRefusal::NotAnOwner));
    }
    let others = org
        .members
        .values()
        .filter(|m| m.status == MembershipStatus::Active && m.authority != authority)
        .count();
    if others > 0 {
        return Ok(Err(DeleteOrganizationRefusal::OtherMembersRemain(others)));
    }
    // Facilities live in this same tenant scope and bill to the tenant. An
    // active one is a standing service, so it is retired through its own
    // lifecycle before the tenant that pays for it disappears.
    let facilities = crate::facility::Facilities::rebuild_in(store, &scope)?
        .active()
        .count();
    if facilities > 0 {
        return Ok(Err(DeleteOrganizationRefusal::FacilitiesRemain(facilities)));
    }

    let mut retired = member;
    retired.status = MembershipStatus::Deprovisioned;
    let directory = OrgRecord {
        id: ORG_ID.into(),
        op: RecordOp::Tombstone,
        ..Default::default()
    };
    let dropped = TenantRef {
        id: tenant_id.to_owned(),
        op: RecordOp::Tombstone,
        ..tenant.clone()
    };

    let directory_json = serde_json::to_string(&directory)?;
    let retired_json = serde_json::to_string(&retired)?;
    let dropped_json = serde_json::to_string(&dropped)?;
    store.append_records_atomically(&[
        (scope.as_str(), "org", directory_json.as_str()),
        (scope.as_str(), "membership", retired_json.as_str()),
        (account_scope, TENANT_REF_KIND, dropped_json.as_str()),
    ])?;
    Ok(Ok(tenant))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "pubkey-abc";

    /// Deleting must remove the organization from the directory as well as from
    /// the switcher. Dropping only the switcher entry would leave an
    /// organization that still resolves, so an invitation into it could still be
    /// accepted by someone who held the id.
    #[test]
    fn deleting_retires_the_directory_the_membership_and_the_switcher_entry() {
        let mut s = Store::open_in_memory().unwrap();
        let account_scope = crate::account::account_scope(ROOT);
        let tenant =
            provision_organization(&mut s, ROOT, &account_scope, "Acme Studio", None).unwrap();

        let deleted = delete_organization_in(&mut s, ROOT, &account_scope, &tenant.id).unwrap();
        assert_eq!(deleted.unwrap().id, tenant.id);

        assert!(!Tenancy::rebuild_in(&s, &account_scope)
            .unwrap()
            .contains(&tenant.id));
        let org = Org::rebuild_in(&s, &tenant_scope(&tenant.id)).unwrap();
        assert!(org.org.is_none(), "the directory record still resolves");
        assert_eq!(
            org.member_by_authority(ROOT).unwrap().status,
            MembershipStatus::Deprovisioned,
        );
        // And an invitation into it can no longer be accepted.
        assert!(accept_tenant_invitation_in(&mut s, ROOT, &tenant.id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn deleting_is_refused_for_an_organization_someone_else_is_still_in() {
        let mut s = Store::open_in_memory().unwrap();
        let account_scope = crate::account::account_scope(ROOT);
        let tenant =
            provision_organization(&mut s, ROOT, &account_scope, "Acme Studio", None).unwrap();
        let colleague = MembershipRecord {
            id: "person:other".into(),
            op: RecordOp::Upsert,
            org_id: tenant.id.clone(),
            authority: "person:other".into(),
            email: String::new(),
            role: "member".into(),
            status: MembershipStatus::Active,
            managed_by_scim: false,
            team: None,
        };
        s.append_record(
            &tenant_scope(&tenant.id),
            "membership",
            &serde_json::to_string(&colleague).unwrap(),
        )
        .unwrap();

        assert_eq!(
            delete_organization_in(&mut s, ROOT, &account_scope, &tenant.id)
                .unwrap()
                .unwrap_err(),
            DeleteOrganizationRefusal::OtherMembersRemain(1),
        );
        assert!(Tenancy::rebuild_in(&s, &account_scope)
            .unwrap()
            .contains(&tenant.id));

        // Once they are gone the last owner can delete — the two flows compose.
        let mut departed = colleague;
        departed.status = MembershipStatus::Deprovisioned;
        s.append_record(
            &tenant_scope(&tenant.id),
            "membership",
            &serde_json::to_string(&departed).unwrap(),
        )
        .unwrap();
        assert!(
            delete_organization_in(&mut s, ROOT, &account_scope, &tenant.id)
                .unwrap()
                .is_ok()
        );
    }

    /// A tenant-level facility bills to the tenant and is retired through its own
    /// lifecycle. Deleting the tenant around one would leave a live, charging
    /// service with nobody left who can reach its controls, so the delete refuses
    /// until it is detached — the same shape as waiting for the other members.
    #[test]
    fn deleting_is_refused_while_a_billable_facility_is_still_attached() {
        use crate::facility::{
            FacilityKind, FacilityOwner, FacilityRecord, FacilityStatus, FACILITY_KIND,
        };

        let mut s = Store::open_in_memory().unwrap();
        let account_scope = crate::account::account_scope(ROOT);
        let tenant =
            provision_organization(&mut s, ROOT, &account_scope, "Acme Studio", None).unwrap();
        let mut facility = FacilityRecord {
            id: "hosted-home".into(),
            op: RecordOp::Upsert,
            kind: FacilityKind::HostedHomeNode,
            owner: FacilityOwner::Tenant,
            status: FacilityStatus::Active,
            display_name: "Hosted Home".into(),
            config: serde_json::Value::Null,
        };
        assert!(facility.is_tenant_billable());
        s.append_record(
            &tenant_scope(&tenant.id),
            FACILITY_KIND,
            &serde_json::to_string(&facility).unwrap(),
        )
        .unwrap();

        assert_eq!(
            delete_organization_in(&mut s, ROOT, &account_scope, &tenant.id)
                .unwrap()
                .unwrap_err(),
            DeleteOrganizationRefusal::FacilitiesRemain(1),
        );
        assert!(Tenancy::rebuild_in(&s, &account_scope)
            .unwrap()
            .contains(&tenant.id));

        // Detaching it clears the refusal: future-only revocation, so the
        // facility's own record stays in the log.
        facility.op = RecordOp::Tombstone;
        s.append_record(
            &tenant_scope(&tenant.id),
            FACILITY_KIND,
            &serde_json::to_string(&facility).unwrap(),
        )
        .unwrap();
        assert!(
            delete_organization_in(&mut s, ROOT, &account_scope, &tenant.id)
                .unwrap()
                .is_ok()
        );
    }

    #[test]
    fn the_personal_tenant_and_other_peoples_organizations_are_refused() {
        let mut s = Store::open_in_memory().unwrap();
        let account_scope = crate::account::account_scope(ROOT);
        let personal = provision_personal_tenant(&mut s, ROOT, "Personal").unwrap();
        assert_eq!(
            delete_organization_in(&mut s, ROOT, &account_scope, &personal)
                .unwrap()
                .unwrap_err(),
            DeleteOrganizationRefusal::Personal,
        );

        // A tenant this person does not belong to is indistinguishable from one
        // that does not exist, the same posture invitation acceptance takes.
        assert_eq!(
            delete_organization_in(&mut s, ROOT, &account_scope, "organization:someone-else")
                .unwrap()
                .unwrap_err(),
            DeleteOrganizationRefusal::NoSuchOrganization,
        );

        // A member who is not an owner is refused, and the organization stands.
        let tenant =
            provision_organization(&mut s, ROOT, &account_scope, "Acme Studio", None).unwrap();
        let other_scope = crate::account::account_scope("person:member");
        let member = MembershipRecord {
            id: "person:member".into(),
            op: RecordOp::Upsert,
            org_id: tenant.id.clone(),
            authority: "person:member".into(),
            email: String::new(),
            role: "member".into(),
            status: MembershipStatus::Active,
            managed_by_scim: false,
            team: None,
        };
        s.append_record(
            &tenant_scope(&tenant.id),
            "membership",
            &serde_json::to_string(&member).unwrap(),
        )
        .unwrap();
        s.append_record(
            &other_scope,
            TENANT_REF_KIND,
            &serde_json::to_string(&TenantRef {
                id: tenant.id.clone(),
                op: RecordOp::Upsert,
                display_name: "Acme Studio".into(),
                role: "member".into(),
                personal: false,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            delete_organization_in(&mut s, "person:member", &other_scope, &tenant.id)
                .unwrap()
                .unwrap_err(),
            DeleteOrganizationRefusal::NotAnOwner,
        );
        assert!(Org::rebuild_in(&s, &tenant_scope(&tenant.id))
            .unwrap()
            .org
            .is_some());
    }

    /// A key whose organization is gone must not replay it: the claim outlives
    /// the tenant, and returning a deleted organization would be worse than
    /// making a new one.
    #[test]
    fn a_claim_whose_organization_was_deleted_does_not_replay() {
        let mut s = Store::open_in_memory().unwrap();
        let account_scope = crate::account::account_scope(ROOT);
        let tenant =
            provision_organization(&mut s, ROOT, &account_scope, "Acme", Some("key-one")).unwrap();
        assert_eq!(
            organization_claimed_by(&s, &account_scope, "key-one")
                .unwrap()
                .map(|t| t.id),
            Some(tenant.id.clone()),
        );
        delete_organization_in(&mut s, ROOT, &account_scope, &tenant.id)
            .unwrap()
            .unwrap();
        assert!(organization_claimed_by(&s, &account_scope, "key-one")
            .unwrap()
            .is_none());
    }

    #[test]
    fn personal_tenant_id_is_deterministic_and_namespaced() {
        assert_eq!(personal_tenant_id(ROOT), "personal:pubkey-abc");
        assert_eq!(personal_tenant_id(ROOT), personal_tenant_id(ROOT));
        // never collides with a named org tenant scope.
        assert_ne!(
            tenant_scope(&personal_tenant_id(ROOT)),
            tenant_scope("acme")
        );
    }

    #[test]
    fn provision_creates_tenant_owner_and_switcher_entry() {
        let mut s = Store::open_in_memory().unwrap();
        let tid = provision_personal_tenant(&mut s, ROOT, "Personal").unwrap();

        // the personal tenant's own directory: an org record + a single owner/active membership.
        let org = Org::rebuild_in(&s, &tenant_scope(&tid)).unwrap();
        assert_eq!(org.org.as_ref().unwrap().display_name, "Personal");
        assert_eq!(org.role_of(ROOT), Some(gaugedesk_core::abac::Role::owner()));
        assert!(org.can_access_project(ROOT, "any-project")); // owner bypass

        // the switcher: one personal tenant.
        let tenancy = Tenancy::rebuild_in(&s, &crate::account::account_scope(ROOT)).unwrap();
        assert!(tenancy.contains(&tid));
        assert_eq!(tenancy.list().count(), 1);
        let p = tenancy.personal().unwrap();
        assert_eq!(p.id, tid);
        assert_eq!(p.role, "owner");
        assert!(p.personal);
    }

    #[test]
    fn provision_is_idempotent() {
        let mut s = Store::open_in_memory().unwrap();
        let tid1 = provision_personal_tenant(&mut s, ROOT, "Personal").unwrap();
        // a second call writes nothing new.
        let before = s.records(&tenant_scope(&tid1), "org").unwrap().len();
        let tid2 = provision_personal_tenant(&mut s, ROOT, "Personal").unwrap();
        let after = s.records(&tenant_scope(&tid1), "org").unwrap().len();
        assert_eq!(tid1, tid2);
        assert_eq!(before, after, "no duplicate org record on re-provision");
        assert_eq!(
            Tenancy::rebuild_in(&s, &crate::account::account_scope(ROOT))
                .unwrap()
                .list()
                .count(),
            1
        );
    }

    #[test]
    fn organization_provisioning_creates_an_isolated_owner_workspace() {
        let mut s = Store::open_in_memory().unwrap();
        let account_scope = crate::account::account_scope(ROOT);
        let created =
            provision_organization(&mut s, ROOT, &account_scope, "Acme Studio", None).unwrap();
        assert!(created.id.starts_with("organization:"));
        assert_eq!(created.display_name, "Acme Studio");
        assert_eq!(created.role, "owner");
        assert!(!created.personal);

        let org = Org::rebuild_in(&s, &tenant_scope(&created.id)).unwrap();
        assert_eq!(org.org.as_ref().unwrap().display_name, "Acme Studio");
        assert_eq!(org.role_of(ROOT), Some(gaugedesk_core::abac::Role::owner()));

        let tenancy = Tenancy::rebuild_in(&s, &crate::account::account_scope(ROOT)).unwrap();
        assert_eq!(tenancy.list().count(), 1);
        assert!(tenancy.contains(&created.id));
    }

    #[test]
    fn provision_self_heals_a_missing_index_entry() {
        // If the tenant was written but the switcher entry was lost (partial write), a re-run
        // completes it rather than duplicating the tenant.
        let mut s = Store::open_in_memory().unwrap();
        let tid = personal_tenant_id(ROOT);
        let org = OrgRecord {
            id: ORG_ID.into(),
            op: RecordOp::Upsert,
            display_name: "Personal".into(),
            ..Default::default()
        };
        s.append_record(
            &tenant_scope(&tid),
            "org",
            &serde_json::to_string(&org).unwrap(),
        )
        .unwrap();
        // index is empty at this point.
        assert!(
            !Tenancy::rebuild_in(&s, &crate::account::account_scope(ROOT))
                .unwrap()
                .contains(&tid)
        );

        provision_personal_tenant(&mut s, ROOT, "Personal").unwrap();
        // the org record was not rewritten (still one), and the index is now healed.
        assert_eq!(s.records(&tenant_scope(&tid), "org").unwrap().len(), 1);
        assert!(
            Tenancy::rebuild_in(&s, &crate::account::account_scope(ROOT))
                .unwrap()
                .contains(&tid)
        );
    }

    #[test]
    fn distinct_persons_get_distinct_isolated_tenants() {
        let mut s = Store::open_in_memory().unwrap();
        let a = provision_personal_tenant(&mut s, "root-a", "A").unwrap();
        let b = provision_personal_tenant(&mut s, "root-b", "B").unwrap();
        assert_ne!(a, b);
        // each tenant's directory holds only its own owner (scope isolation, INV-1).
        assert_eq!(
            Org::rebuild_in(&s, &tenant_scope(&a))
                .unwrap()
                .role_of("root-a"),
            Some(gaugedesk_core::abac::Role::owner())
        );
        assert_eq!(
            Org::rebuild_in(&s, &tenant_scope(&a))
                .unwrap()
                .role_of("root-b"),
            None
        );
    }

    #[test]
    fn tenant_invitation_is_metadata_only_and_acceptance_is_atomic_and_idempotent() {
        let mut s = Store::open_in_memory().unwrap();
        let owner_scope = crate::account::account_scope(ROOT);
        let tenant =
            provision_organization(&mut s, ROOT, &owner_scope, "Acme Studio", None).unwrap();
        let invited = MembershipRecord {
            id: "invitee-record".into(),
            op: RecordOp::Upsert,
            org_id: ORG_ID.into(),
            authority: "person:invitee".into(),
            email: "private@example.test".into(),
            role: "member".into(),
            status: MembershipStatus::Invited,
            managed_by_scim: false,
            team: None,
        };
        let tenant_scope = tenant_scope(&tenant.id);
        s.append_record(
            &tenant_scope,
            "membership",
            &serde_json::to_string(&invited).unwrap(),
        )
        .unwrap();

        // The shell sees only the tenant pointer and role; neither email nor
        // directory record id are duplicated into account state.
        assert_eq!(
            pending_tenant_invitations_in(&s, "person:invitee").unwrap(),
            vec![PendingTenantInvitation {
                tenant_id: tenant.id.clone(),
                display_name: "Acme Studio".into(),
                role: "member".into(),
            }]
        );
        assert!(pending_tenant_invitations_in(&s, "person:other")
            .unwrap()
            .is_empty());

        let accepted = accept_tenant_invitation_in(&mut s, "person:invitee", &tenant.id)
            .unwrap()
            .unwrap();
        assert_eq!(accepted.role, "member");
        assert!(
            Tenancy::rebuild_in(&s, &crate::account::account_scope("person:invitee"))
                .unwrap()
                .contains(&tenant.id)
        );
        assert_eq!(
            Org::rebuild_in(&s, &tenant_scope)
                .unwrap()
                .role_of("person:invitee"),
            Some(gaugedesk_core::abac::Role::member())
        );
        assert!(pending_tenant_invitations_in(&s, "person:invitee")
            .unwrap()
            .is_empty());

        // A retry adds no second promotion record and returns the same safe pointer.
        let before = s.records(&tenant_scope, "membership").unwrap().len();
        assert_eq!(
            accept_tenant_invitation_in(&mut s, "person:invitee", &tenant.id)
                .unwrap()
                .unwrap()
                .id,
            tenant.id
        );
        assert_eq!(
            s.records(&tenant_scope, "membership").unwrap().len(),
            before
        );

        // Guessing a tenant id never reveals or changes its directory.
        assert!(
            accept_tenant_invitation_in(&mut s, "person:other", &tenant.id)
                .unwrap()
                .is_none()
        );
    }
}
