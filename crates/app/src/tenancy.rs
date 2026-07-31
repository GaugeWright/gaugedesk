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

use gaugewright_store::{AdmitError, Store};

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

/// Provision one named organization for `root` and index its single owner membership in that
/// person's switcher. The tenant id is server-generated so a caller can name an organization
/// without choosing, probing, or colliding with another tenant's isolation scope.
pub fn provision_organization(
    store: &mut Store,
    root: &str,
    account_scope: &str,
    display: &str,
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
    store.append_record(&scope, "org", &serde_json::to_string(&org)?)?;

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
    store.append_record(&scope, "membership", &serde_json::to_string(&owner)?)?;

    let tenant = TenantRef {
        id,
        op: RecordOp::Upsert,
        display_name,
        role: "owner".to_string(),
        personal: false,
    };
    store.append_record(
        account_scope,
        TENANT_REF_KIND,
        &serde_json::to_string(&tenant)?,
    )?;
    Ok(tenant)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "pubkey-abc";

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
        assert_eq!(
            org.role_of(ROOT),
            Some(gaugewright_core::abac::Role::owner())
        );
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
        let created = provision_organization(&mut s, ROOT, &account_scope, "Acme Studio").unwrap();
        assert!(created.id.starts_with("organization:"));
        assert_eq!(created.display_name, "Acme Studio");
        assert_eq!(created.role, "owner");
        assert!(!created.personal);

        let org = Org::rebuild_in(&s, &tenant_scope(&created.id)).unwrap();
        assert_eq!(org.org.as_ref().unwrap().display_name, "Acme Studio");
        assert_eq!(
            org.role_of(ROOT),
            Some(gaugewright_core::abac::Role::owner())
        );

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
            Some(gaugewright_core::abac::Role::owner())
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
        let tenant = provision_organization(&mut s, ROOT, &owner_scope, "Acme Studio").unwrap();
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
            Some(gaugewright_core::abac::Role::member())
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
