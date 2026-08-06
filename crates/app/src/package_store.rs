//! Durable M2 distribution records (`primitives/data.md` "minimum records"): the
//! **package**, **agent-version**, and **deployment-entitlement** records.
//!
//! These are declarative manifests — the source of truth for *what* a package/
//! version/entitlement is — held as append-only records folded latest-wins by id
//! (the [`crate::resource_store`]/[`crate::library`] idiom). They carry **handles
//! and metadata, never payload** (`INV-10`); and they do **not** duplicate lifecycle
//! phase (`data.md`): distribution/entitlement *status* is folded from the
//! [`gaugedesk_core::package_distribution`] / [`gaugedesk_core::deployment_entitlement`]
//! reducers, not stored here. A record may be tombstoned (future-only).

use std::collections::BTreeMap;

use gaugedesk_core::resource::ResourceId;
use gaugedesk_store::{AdmitError, Store};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// A durable record kind, folded latest-wins by `id`.
pub trait Record: Serialize + DeserializeOwned + Clone {
    /// The store record-kind discriminator (distinct from any lifecycle `KIND`).
    const KIND: &'static str;
    fn id(&self) -> &str;
    fn tombstoned(&self) -> bool;
    fn set_tombstoned(&mut self);
}

/// The shareable-object manifest (`primitives/package.md`): a frozen agent version
/// packaged for transfer. Method handles convey no payload access (`INV-10`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PackageRecord {
    pub id: String,
    /// The frozen [[agent-version]] this package references.
    pub version: String,
    pub source_authority: String,
    pub agent_ref: String,
    pub method_handles: Vec<ResourceId>,
    /// The declared minimum boundary ceiling required to run safely.
    pub protection_posture: String,
    /// Permission for the manifest + handles to cross to the target authority.
    pub source_basis: bool,
    #[serde(default)]
    pub tombstoned: bool,
}

/// A frozen [[agent-version]] snapshot's durable record.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VersionRecord {
    pub id: String,
    pub agent_ref: String,
    pub method_handles: Vec<ResourceId>,
    pub config: String,
    pub protection_posture: String,
    #[serde(default)]
    pub provenance: Vec<String>,
    #[serde(default)]
    pub content_hashes: Vec<String>,
    #[serde(default)]
    pub tombstoned: bool,
}

/// A governed deployment entitlement's durable record (status is folded from the
/// [`gaugedesk_core::deployment_entitlement`] reducer, not stored here).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EntitlementRecord {
    pub id: String,
    pub installed_package: String,
    pub target_context: String,
    pub entitlement_authority: String,
    #[serde(default)]
    pub terms: String,
    /// Correlation handles for billing/support/audit receipts (evidence, not authority).
    #[serde(default)]
    pub correlation: Vec<String>,
    #[serde(default)]
    pub tombstoned: bool,
}

macro_rules! impl_record {
    ($t:ty, $kind:literal) => {
        impl Record for $t {
            const KIND: &'static str = $kind;
            fn id(&self) -> &str {
                &self.id
            }
            fn tombstoned(&self) -> bool {
                self.tombstoned
            }
            fn set_tombstoned(&mut self) {
                self.tombstoned = true;
            }
        }
    };
}
impl_record!(PackageRecord, "package_record");
impl_record!(VersionRecord, "version_record");
impl_record!(EntitlementRecord, "entitlement_record");

/// Persist a record (a new latest-wins revision for its id).
pub fn put<R: Record>(store: &mut Store, scope: &str, rec: &R) -> Result<(), AdmitError> {
    store.append_record(scope, R::KIND, &serde_json::to_string(rec)?)?;
    Ok(())
}

/// Every record of this kind in a scope at its current revision (latest-wins by id;
/// tombstoned records are included — the manifest/history persists).
pub fn list<R: Record>(store: &Store, scope: &str) -> Result<Vec<R>, AdmitError> {
    let mut latest: BTreeMap<String, R> = BTreeMap::new();
    for row in store.records(scope, R::KIND)? {
        let rec: R = serde_json::from_str(&row)?;
        latest.insert(rec.id().to_string(), rec);
    }
    Ok(latest.into_values().collect())
}

/// The current revision of one record by id.
pub fn get<R: Record>(store: &Store, scope: &str, id: &str) -> Result<Option<R>, AdmitError> {
    Ok(list::<R>(store, scope)?.into_iter().find(|r| r.id() == id))
}

/// Tombstone a record (future-only): append a tombstoned revision. Returns `false`
/// if no such record exists.
pub fn tombstone<R: Record>(store: &mut Store, scope: &str, id: &str) -> Result<bool, AdmitError> {
    match get::<R>(store, scope, id)? {
        Some(mut rec) => {
            rec.set_tombstoned();
            put(store, scope, &rec)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(id: &str, version: &str) -> PackageRecord {
        PackageRecord {
            id: id.into(),
            version: version.into(),
            source_authority: "source".into(),
            agent_ref: "agent-default".into(),
            method_handles: vec![ResourceId::new("ctx-method")],
            protection_posture: "local".into(),
            source_basis: true,
            tombstoned: false,
        }
    }

    #[test]
    fn package_records_round_trip_latest_wins_and_tombstone() {
        let mut store = Store::open_in_memory().unwrap();
        let scope = "library";
        put(&mut store, scope, &pkg("p1", "v1")).unwrap();
        put(&mut store, scope, &pkg("p2", "v1")).unwrap();
        put(&mut store, scope, &pkg("p1", "v2")).unwrap(); // re-publish at v2 supersedes

        assert_eq!(list::<PackageRecord>(&store, scope).unwrap().len(), 2);
        assert_eq!(
            get::<PackageRecord>(&store, scope, "p1")
                .unwrap()
                .unwrap()
                .version,
            "v2"
        );

        // tombstone is future-only — the record still lists, marked tombstoned (INV-18).
        assert!(tombstone::<PackageRecord>(&mut store, scope, "p1").unwrap());
        assert!(
            get::<PackageRecord>(&store, scope, "p1")
                .unwrap()
                .unwrap()
                .tombstoned
        );
        assert_eq!(list::<PackageRecord>(&store, scope).unwrap().len(), 2);
        assert!(!tombstone::<PackageRecord>(&mut store, scope, "nope").unwrap());
    }

    #[test]
    fn record_kinds_are_independent_streams() {
        let mut store = Store::open_in_memory().unwrap();
        let scope = "library";
        put(&mut store, scope, &pkg("p1", "v1")).unwrap();
        put(
            &mut store,
            scope,
            &VersionRecord {
                id: "v1".into(),
                agent_ref: "agent-default".into(),
                method_handles: vec![],
                config: "{}".into(),
                protection_posture: "local".into(),
                provenance: vec![],
                content_hashes: vec!["abc".into()],
                tombstoned: false,
            },
        )
        .unwrap();
        put(
            &mut store,
            scope,
            &EntitlementRecord {
                id: "e1".into(),
                installed_package: "p1".into(),
                target_context: "ctx".into(),
                entitlement_authority: "target".into(),
                terms: "monthly".into(),
                correlation: vec![],
                tombstoned: false,
            },
        )
        .unwrap();
        // each kind folds independently
        assert_eq!(list::<PackageRecord>(&store, scope).unwrap().len(), 1);
        assert_eq!(list::<VersionRecord>(&store, scope).unwrap().len(), 1);
        assert_eq!(list::<EntitlementRecord>(&store, scope).unwrap().len(), 1);
        assert_eq!(
            get::<VersionRecord>(&store, scope, "v1")
                .unwrap()
                .unwrap()
                .content_hashes,
            ["abc"]
        );
    }
}
