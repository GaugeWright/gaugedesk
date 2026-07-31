//! Facility — the attachable/revocable unit of hosted functionality (`ADR 0077`).
//!
//! A **facility** is what a web user adds to a tenant (or, for account-level ones, to
//! the person) that contributes a Console **surface** and/or a **connection to a home
//! node** and/or quiet **config**: cloud backup, a hosted home node, a registered host,
//! library sync. It is the unit the hosted-account Console is built from — the Console is
//! *core (account + tenant switcher) + the surfaces its facilities contribute*, with no
//! hardcoded section list. See
//! [`specs/primitives/facility.md`](../../../specs/primitives/facility.md).
//!
//! Like the [`crate::org`] directory and the [`crate::library`], these are durable
//! **records** folded latest-wins by id (`data.md`, `INV-5`/`INV-6`) — an `Upsert` sets,
//! a `Tombstone` removes — held as record kind [`FACILITY_KIND`] in the **owner's** scope:
//! a *tenant-level* facility in that tenant's [`crate::org::tenant_scope`], an
//! *account-level* one in the reserved [`crate::account::ACCOUNT_SCOPE`], so a facility is
//! scope-isolated to its owner (`INV-1`). This module is the pure data model + projection
//! (no `Workbench`/route deps); the attach/configure/revoke CRUD routes and their
//! role-gating (`rbac.rs`) live with the control-plane hub.
//!
//! Adds no protection invariant (ADR 0020): a facility organizes *access to* hosted
//! capability. **Attach is not access** — reaching the work is always the home admitting
//! you (`INV-13`), never the facility handing you a key (`INV-10`); the hub stays blind
//! (`INV-14`). The person's **devices** and **linked model key** are the account-level
//! facilities already modeled in [`crate::account`]; this module holds the *other*
//! attachable hosted units, which need their own record.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use gaugewright_store::{AdmitError, Store};

// Reuse the library's latest-wins / tombstone record op — same record discipline.
pub use crate::library::RecordOp;

/// The record kind, within the owner's scope, holding every facility record.
pub const FACILITY_KIND: &str = "facility";

/// The kind of hosted functionality a facility provides. A closed set for now (each kind
/// mints its own Console section, ADR 0077 §7); grouping/extension is deferred until forced.
/// Devices and the linked model key are **not** here — they are the account-level facilities
/// already modeled in [`crate::account`].
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum FacilityKind {
    /// The `ADR 0054` blind-directory / sealed account-state sync (devices, settings, the
    /// sealed linked model key) across the person's machines. Account-level; the first
    /// live facility. Default so a bare record parses to the simplest kind.
    #[default]
    LibrarySync,
    /// Durable backup of a tenant's work to a hosted store.
    CloudBackup,
    /// A hosted home node in the tenant — a cloud runtime the thin client is admitted to
    /// (the target runtime is WhippleScript-on-DO reached via a `ControlPlane` adapter,
    /// `ADR 0076`).
    HostedHomeNode,
    /// A registered host the tenant owns that runs a home node (the tenant's own box).
    RegisteredHost,
}

/// Who a facility attaches to (ADR 0077 §7/§9).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum FacilityOwner {
    /// Tenant-level: **billed to the tenant** and lives in the tenant's org scope.
    #[default]
    Tenant,
    /// Account-level: attaches to the person and **follows them into every tenant**; lives
    /// in the reserved account scope.
    Person,
}

/// A facility's lifecycle status. Only [`Active`](FacilityStatus::Active) opens a connection
/// / contributes a live surface; every other lifecycle state opens no facility
/// connection (fail-closed, `INV-20`).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum FacilityStatus {
    /// The tenant has admitted the commercial/configuration fact but the
    /// isolated Home root is not ready yet. Retries resume the same facility.
    Provisioning,
    #[default]
    Active,
    /// Standing paused going forward (billing gate); re-activating restores it. Forward-only
    /// (`INV-18`): suspension never reaches back into already-admitted work.
    Suspended,
    /// Service is stopped and preserved only through its declared grace/
    /// retention deadline. Reads/exports remain possible; new hosted acts do not.
    Retention,
    /// Terminal lifecycle fact retained for administration/audit after the
    /// Home's storage domain has been erased.
    Deleted,
    /// Legacy spelling for a detached non-Cloud facility.
    Revoked,
}

/// One facility: its kind, owner, status, display name, and kind-specific config.
///
/// Append-only, folded latest-wins by [`id`](FacilityRecord::id). The stable id lets a
/// re-attach upsert and a revoke tombstone the same record (future-only revocation,
/// `INV-18`). `config` is opaque kind-specific JSON (a backup schedule, a home-node
/// address) — the pure model does not interpret it.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct FacilityRecord {
    /// Stable facility id (unique within the owner's scope).
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    #[serde(default)]
    pub kind: FacilityKind,
    #[serde(default)]
    pub owner: FacilityOwner,
    #[serde(default)]
    pub status: FacilityStatus,
    /// Human label for the Console surface this facility mints.
    #[serde(default)]
    pub display_name: String,
    /// Kind-specific configuration (the connection/config the facility carries). `Null`
    /// when the kind needs none. `#[serde(default)]` keeps records written before a field
    /// was added parseable (`INV-6`).
    #[serde(default)]
    pub config: serde_json::Value,
}

impl FacilityRecord {
    /// Whether this facility currently opens a connection / contributes a live surface —
    /// **only** an [`Active`](FacilityStatus::Active) one. A suspended/revoked facility is
    /// usable by nobody (fail-closed): attach-is-not-access still holds either way
    /// (`INV-13`), but a paused facility offers not even the connection.
    pub fn is_usable(&self) -> bool {
        self.status == FacilityStatus::Active
    }

    /// Whether this facility bills to a tenant (ADR 0048): every **tenant-level** facility
    /// does; account-level ones follow the person and are not tenant-billed. Billing is
    /// **not authority** (`INV-18`) — this only informs the billing surface, never access.
    pub fn is_tenant_billable(&self) -> bool {
        self.owner == FacilityOwner::Tenant
    }
}

/// The folded facilities projection for one owner scope (derived, rebuildable — `INV-5`).
#[derive(Default, Clone, Debug)]
pub struct Facilities {
    /// Facilities held in this scope, folded latest-wins by id.
    pub facilities: BTreeMap<String, FacilityRecord>,
}

impl Facilities {
    /// Rebuild the **person's** account-level facilities — folds the reserved
    /// [`crate::account::ACCOUNT_SCOPE`]. These follow the person into every tenant.
    pub fn rebuild_account(store: &Store) -> Result<Facilities, AdmitError> {
        Self::rebuild_in(store, crate::account::ACCOUNT_SCOPE)
    }

    /// Rebuild a **tenant's** facilities — folds [`crate::org::tenant_scope`]`(tenant)`. For
    /// the default tenant (solo / singleton) pass `""` or the org id.
    pub fn rebuild_tenant(store: &Store, tenant: &str) -> Result<Facilities, AdmitError> {
        Self::rebuild_in(store, &crate::org::tenant_scope(tenant))
    }

    /// Rebuild the facilities held in `scope` by folding its [`FACILITY_KIND`] records in
    /// position order (latest-wins). Scope-isolated (`INV-1`): one owner's facilities never
    /// fold into another's.
    pub fn rebuild_in(store: &Store, scope: &str) -> Result<Facilities, AdmitError> {
        let mut out = Facilities::default();
        for row in store.records(scope, FACILITY_KIND)? {
            let r: FacilityRecord = serde_json::from_str(&row)?;
            match r.op {
                RecordOp::Tombstone => {
                    out.facilities.remove(&r.id);
                }
                RecordOp::Upsert => {
                    out.facilities.insert(r.id.clone(), r);
                }
            }
        }
        Ok(out)
    }

    /// The facility with this id, if any.
    pub fn get(&self, id: &str) -> Option<&FacilityRecord> {
        self.facilities.get(id)
    }

    /// The **active** facilities — the ones that open a connection / contribute a live
    /// surface. What the Console renders and what a usability check joins onto.
    pub fn active(&self) -> impl Iterator<Item = &FacilityRecord> {
        self.facilities.values().filter(|f| f.is_usable())
    }

    /// Whether an **active** facility of `kind` is held here — e.g. "is library sync on for
    /// this person". A suspended/revoked one does not count (fail-closed).
    pub fn has_active(&self, kind: FacilityKind) -> bool {
        self.facilities
            .values()
            .any(|f| f.kind == kind && f.is_usable())
    }

    /// Whether the facility `id` may be **used** right now — present and active. Absent /
    /// suspended / revoked ⇒ `false` (fail-closed, `INV-20`). This gates *using* what a
    /// facility provides; *managing* it is a separate tenant-admin capability enforced at
    /// the routes (`rbac.rs`).
    pub fn is_usable(&self, id: &str) -> bool {
        self.facilities.get(id).is_some_and(|f| f.is_usable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facility(
        id: &str,
        kind: FacilityKind,
        owner: FacilityOwner,
        status: FacilityStatus,
    ) -> String {
        serde_json::to_string(&FacilityRecord {
            id: id.into(),
            op: RecordOp::Upsert,
            kind,
            owner,
            status,
            display_name: format!("{id} facility"),
            config: serde_json::Value::Null,
        })
        .unwrap()
    }

    fn store_with(scope: &str, records: &[String]) -> Store {
        let mut s = Store::open_in_memory().unwrap();
        for payload in records {
            s.append_record(scope, FACILITY_KIND, payload).unwrap();
        }
        s
    }

    #[test]
    fn rebuild_folds_facilities_latest_wins() {
        use crate::account::ACCOUNT_SCOPE;
        // Two upserts of the same id → latest wins (display_name changes).
        let mut renamed: FacilityRecord = serde_json::from_str(&facility(
            "lib",
            FacilityKind::LibrarySync,
            FacilityOwner::Person,
            FacilityStatus::Active,
        ))
        .unwrap();
        renamed.display_name = "Library sync (renamed)".into();
        let store = store_with(
            ACCOUNT_SCOPE,
            &[
                facility(
                    "lib",
                    FacilityKind::LibrarySync,
                    FacilityOwner::Person,
                    FacilityStatus::Active,
                ),
                serde_json::to_string(&renamed).unwrap(),
            ],
        );
        let f = Facilities::rebuild_account(&store).unwrap();
        assert_eq!(f.facilities.len(), 1);
        assert_eq!(f.get("lib").unwrap().display_name, "Library sync (renamed)");
    }

    #[test]
    fn tombstone_removes_a_facility() {
        use crate::account::ACCOUNT_SCOPE;
        let mut tomb: FacilityRecord = serde_json::from_str(&facility(
            "lib",
            FacilityKind::LibrarySync,
            FacilityOwner::Person,
            FacilityStatus::Active,
        ))
        .unwrap();
        tomb.op = RecordOp::Tombstone;
        let store = store_with(
            ACCOUNT_SCOPE,
            &[
                facility(
                    "lib",
                    FacilityKind::LibrarySync,
                    FacilityOwner::Person,
                    FacilityStatus::Active,
                ),
                serde_json::to_string(&tomb).unwrap(),
            ],
        );
        let f = Facilities::rebuild_account(&store).unwrap();
        assert!(f.facilities.is_empty());
        assert!(!f.is_usable("lib"));
    }

    #[test]
    fn only_active_facilities_are_usable() {
        // Fail-closed (INV-20): suspended / revoked open no connection; absent is not usable.
        use crate::account::ACCOUNT_SCOPE;
        let store = store_with(
            ACCOUNT_SCOPE,
            &[
                facility(
                    "on",
                    FacilityKind::LibrarySync,
                    FacilityOwner::Person,
                    FacilityStatus::Active,
                ),
                facility(
                    "paused",
                    FacilityKind::CloudBackup,
                    FacilityOwner::Person,
                    FacilityStatus::Suspended,
                ),
                facility(
                    "gone",
                    FacilityKind::CloudBackup,
                    FacilityOwner::Person,
                    FacilityStatus::Revoked,
                ),
            ],
        );
        let f = Facilities::rebuild_account(&store).unwrap();
        assert!(f.is_usable("on"));
        assert!(!f.is_usable("paused"));
        assert!(!f.is_usable("gone"));
        assert!(!f.is_usable("missing"));
        assert_eq!(f.active().count(), 1);
        assert!(f.has_active(FacilityKind::LibrarySync));
        assert!(!f.has_active(FacilityKind::CloudBackup)); // both non-active
    }

    #[test]
    fn tenant_and_account_facilities_are_scope_isolated() {
        // INV-1: a person's account-level facilities and a tenant's facilities live in
        // different scopes and never fold into each other.
        let mut s = Store::open_in_memory().unwrap();
        s.append_record(
            crate::account::ACCOUNT_SCOPE,
            FACILITY_KIND,
            &facility(
                "lib",
                FacilityKind::LibrarySync,
                FacilityOwner::Person,
                FacilityStatus::Active,
            ),
        )
        .unwrap();
        s.append_record(
            &crate::org::tenant_scope("acme"),
            FACILITY_KIND,
            &facility(
                "backup",
                FacilityKind::CloudBackup,
                FacilityOwner::Tenant,
                FacilityStatus::Active,
            ),
        )
        .unwrap();

        let acct = Facilities::rebuild_account(&s).unwrap();
        assert!(acct.get("lib").is_some());
        assert!(acct.get("backup").is_none()); // the tenant's facility does not leak in

        let acme = Facilities::rebuild_tenant(&s, "acme").unwrap();
        assert!(acme.get("backup").is_some());
        assert!(acme.get("lib").is_none());
        // an unknown tenant folds to empty (fail-closed).
        assert!(Facilities::rebuild_tenant(&s, "globex")
            .unwrap()
            .facilities
            .is_empty());
    }

    #[test]
    fn tenant_facilities_bill_account_facilities_do_not() {
        let tenant: FacilityRecord = serde_json::from_str(&facility(
            "backup",
            FacilityKind::CloudBackup,
            FacilityOwner::Tenant,
            FacilityStatus::Active,
        ))
        .unwrap();
        let person: FacilityRecord = serde_json::from_str(&facility(
            "lib",
            FacilityKind::LibrarySync,
            FacilityOwner::Person,
            FacilityStatus::Active,
        ))
        .unwrap();
        assert!(tenant.is_tenant_billable());
        assert!(!person.is_tenant_billable());
    }
}
