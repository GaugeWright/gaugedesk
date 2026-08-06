//! The M2 publish → install → entitle flow (PK-2), wiring the verified reducers
//! AV-1 → PD-1 → DE-1 in the **loopback two-authority** shape: source and target
//! are distinct actors over per-instance scopes in one store (the M2 analog of M1's
//! single-user collapse). The keystone property: **install alone grants no run
//! authority** — a governed run is ready only when the install is `Installed` *and*
//! a deployment entitlement is `Active` (ADR 0011/0016/0021).

use gaugedesk_core::agent_version::{VersionCommand, VersionState};
use gaugedesk_core::deployment_entitlement::{
    EntitlementCommand, EntitlementPhase, EntitlementState,
};
use gaugedesk_core::key_release::{EntitlementIneligibility, EntitlementVerdict};
use gaugedesk_core::package_distribution::{DistCommand, DistPhase, DistState};
use gaugedesk_store::{AdmitError, Store};

use crate::library::LIBRARY_SCOPE;
use crate::package_store::{self, PackageRecord, VersionRecord};
use crate::Workbench;

/// One package-distribution lifecycle instance per package (source publishes, target
/// installs — correlated by package id, the loopback two-authority collapse).
pub fn dist_scope(package_id: &str) -> String {
    format!("dist::{package_id}")
}
/// One agent-version lifecycle instance per version.
pub fn version_scope(version_id: &str) -> String {
    format!("version::{version_id}")
}
/// One deployment-entitlement instance per (package, governed context).
pub fn entitle_scope(package_id: &str, context: &str) -> String {
    format!("entitle::{package_id}::{context}")
}

/// Source: freeze an agent version (AV-1) and persist its durable record.
pub fn freeze_version(
    store: &mut Store,
    source_scope: &str,
    rec: &VersionRecord,
) -> Result<(), AdmitError> {
    let vs = version_scope(&rec.id);
    store.admit::<VersionState>(&vs, VersionCommand::CreateDraft)?;
    store.admit::<VersionState>(&vs, VersionCommand::FreezeVersion)?;
    package_store::put(store, source_scope, rec)?;
    Ok(())
}

/// Source: publish a package (PD-1) referencing a frozen version; record the package
/// reference on the version (AV-1) and persist the package manifest.
pub fn publish(
    store: &mut Store,
    source_scope: &str,
    rec: &PackageRecord,
) -> Result<(), AdmitError> {
    store.admit::<VersionState>(
        &version_scope(&rec.version),
        VersionCommand::RecordPackageReference,
    )?;
    store.admit::<DistState>(&dist_scope(&rec.id), DistCommand::PublishPackage)?;
    package_store::put(store, source_scope, rec)?;
    Ok(())
}

/// Target: install a published package (PD-1 request → target-admit → install).
pub fn install(store: &mut Store, package_id: &str) -> Result<DistPhase, AdmitError> {
    let ds = dist_scope(package_id);
    store.admit::<DistState>(&ds, DistCommand::RequestInstall)?;
    store.admit::<DistState>(&ds, DistCommand::TargetAdmitInstall)?;
    Ok(store
        .admit::<DistState>(&ds, DistCommand::InstallPackage)?
        .phase)
}

/// Target authority: activate a deployment entitlement for a governed context (DE-1).
pub fn entitle(store: &mut Store, package_id: &str, context: &str) -> Result<(), AdmitError> {
    let es = entitle_scope(package_id, context);
    store.admit::<EntitlementState>(&es, EntitlementCommand::AdmitPackageInstall)?;
    store.admit::<EntitlementState>(&es, EntitlementCommand::RequestEntitlement)?;
    store.admit::<EntitlementState>(&es, EntitlementCommand::ActivateEntitlement)?;
    Ok(())
}

/// Suspend a governed context's entitlement (DE-1) — blocks future governed runs.
pub fn suspend(store: &mut Store, package_id: &str, context: &str) -> Result<(), AdmitError> {
    store.admit::<EntitlementState>(
        &entitle_scope(package_id, context),
        EntitlementCommand::SuspendEntitlement,
    )?;
    Ok(())
}

/// Source: withdraw a package version (PD-1) — future-only; blocks new installs/runs
/// while preserving prior install evidence.
pub fn withdraw(store: &mut Store, package_id: &str) -> Result<(), AdmitError> {
    store.admit::<DistState>(&dist_scope(package_id), DistCommand::WithdrawPackage)?;
    Ok(())
}

/// The package's current distribution status (folded from PD-1) as a display string —
/// the catalog availability field (`published`/`installed`/`withdrawn`/…).
pub fn dist_status(store: &Store, package_id: &str) -> Result<String, AdmitError> {
    Ok(format!(
        "{:?}",
        store.fold::<DistState>(&dist_scope(package_id))?.phase
    ))
}

/// Whether the package is currently installed (PD-1 `Installed`, not withdrawn).
pub fn is_installed(store: &Store, package_id: &str) -> Result<bool, AdmitError> {
    Ok(store.fold::<DistState>(&dist_scope(package_id))?.phase == DistPhase::Installed)
}

/// Whether a governed deployment entitlement is active for the context (DE-1 `Active`).
/// Gates on the **real** active predicate ([`EntitlementState::active_entitlement`]),
/// not `phase == Active`: the lifecycle permits `phase == Active` to coexist with a
/// withdrawn/inactive entitlement, so trusting the phase would over-grant eligibility.
pub fn is_entitled(store: &Store, package_id: &str, context: &str) -> Result<bool, AdmitError> {
    Ok(store
        .fold::<EntitlementState>(&entitle_scope(package_id, context))?
        .active_entitlement())
}

/// Governed run readiness: **installed AND entitled**. Install alone is never enough
/// (INV-10/11/12); entitlement narrows future-run eligibility (ADR 0021).
pub fn run_ready(store: &Store, package_id: &str, context: &str) -> Result<bool, AdmitError> {
    Ok(is_installed(store, package_id)? && is_entitled(store, package_id, context)?)
}

impl Workbench {
    /// Package catalog projection joined with live distribution status.
    pub fn package_catalog(&self) -> Result<Vec<(PackageRecord, String)>, AdmitError> {
        let store = self.store_ref();
        let records = package_store::list::<PackageRecord>(store, LIBRARY_SCOPE)?;
        Ok(records
            .into_iter()
            .map(|record| {
                let status = dist_status(store, &record.id).unwrap_or_else(|_| "Draft".into());
                (record, status)
            })
            .collect())
    }

    /// Withdraw a package from future installs/runs.
    pub fn withdraw_package(&mut self, id: &str) -> Result<(), AdmitError> {
        withdraw(self.store_mut(), id).map(|_| ())
    }

    /// Freeze an agent version and publish its package record.
    pub fn publish_package(
        &mut self,
        version: &VersionRecord,
        package: &PackageRecord,
    ) -> Result<(), AdmitError> {
        freeze_version(self.store_mut(), LIBRARY_SCOPE, version)?;
        publish(self.store_mut(), LIBRARY_SCOPE, package)
    }

    /// Install a published package.
    pub fn install_package(&mut self, id: &str) -> Result<DistPhase, AdmitError> {
        install(self.store_mut(), id)
    }

    /// Entitle a context to run an installed package.
    pub fn entitle_package(&mut self, id: &str, context: &str) -> Result<(), AdmitError> {
        entitle(self.store_mut(), id, context)
    }

    /// Whether a package is installed, entitled, and run-ready for a context.
    pub fn package_readiness(&self, id: &str, context: &str) -> (bool, bool, bool) {
        let store = self.store_ref();
        let installed = is_installed(store, id).unwrap_or(false);
        let entitled = is_entitled(store, id, context).unwrap_or(false);
        (installed, entitled, installed && entitled)
    }
}

// --- Attested-run entitlement, keyed by engagement (ADR 0048) ---------------------
//
// The attested sealed run is the commercial wedge (ADR 0048): a host earns the keys
// that unseal a run's inputs only by attesting AND presenting a valid entitlement.
// The engagement *is* the governed deployment context for an attested run, so these
// reuse the verified DE-1 reducer keyed by the engagement rather than a package —
// the consultant's purchase provisions an entitlement into the engagement's scope.

/// One attested-run deployment-entitlement instance per engagement (ADR 0048).
pub fn attested_run_scope(engagement: &str) -> String {
    format!("attest-run::{engagement}")
}

/// The record kind under which an attested-run grant's **TTL** is stored alongside
/// its DE-1 entitlement (ADR 0048: "valid, *unexpired*"). The DE-1 reducer is pure and
/// holds no clock (`INV-9`); the grant's expiry is shell data, materialized here and
/// compared to the wall clock by [`attested_run_verdict`].
const ATTESTED_GRANT_KIND: &str = "attested-run-grant";

/// The TTL side of an attested-run entitlement grant: the wall-clock instant after
/// which the grant is no longer fresh (`None` = no expiry). Latest-wins per scope.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct AttestedRunGrant {
    /// Unix-epoch millis after which the grant is `Expired`; `None` ⇒ never expires.
    expires_at_ms: Option<u64>,
}

/// Activate an engagement's attested-run entitlement (DE-1 admit-install → request →
/// activate) with an optional TTL (ADR 0048). `expires_at_ms` is the wall-clock
/// instant after which the grant reads `Expired`; `None` is a non-expiring grant. This
/// is what the consultant's purchase provisions into the engagement.
pub fn entitle_attested_run_until(
    store: &mut Store,
    engagement: &str,
    expires_at_ms: Option<u64>,
) -> Result<(), AdmitError> {
    let es = attested_run_scope(engagement);
    store.admit::<EntitlementState>(&es, EntitlementCommand::AdmitPackageInstall)?;
    store.admit::<EntitlementState>(&es, EntitlementCommand::RequestEntitlement)?;
    store.admit::<EntitlementState>(&es, EntitlementCommand::ActivateEntitlement)?;
    let payload = serde_json::to_string(&AttestedRunGrant { expires_at_ms })?;
    store.append_record(&es, ATTESTED_GRANT_KIND, &payload)?;
    Ok(())
}

/// Activate a non-expiring attested-run entitlement (the no-TTL convenience).
pub fn entitle_attested_run(store: &mut Store, engagement: &str) -> Result<(), AdmitError> {
    entitle_attested_run_until(store, engagement, None)
}

/// Suspend an engagement's attested-run entitlement — future-only block (`INV-18`):
/// past releases stand; new attested runs are gated off until resumed.
pub fn suspend_attested_run(store: &mut Store, engagement: &str) -> Result<(), AdmitError> {
    store.admit::<EntitlementState>(
        &attested_run_scope(engagement),
        EntitlementCommand::SuspendEntitlement,
    )?;
    Ok(())
}

/// The latest TTL grant recorded for the engagement's attested-run entitlement, if any.
fn latest_attested_grant(
    store: &Store,
    engagement: &str,
) -> Result<Option<AttestedRunGrant>, AdmitError> {
    let mut latest = None;
    // records() is position-ordered (oldest→newest), so a later grant wins.
    for row in store.records(&attested_run_scope(engagement), ATTESTED_GRANT_KIND)? {
        latest = Some(serde_json::from_str(&row)?);
    }
    Ok(latest)
}

/// The attestation-gate verdict for an engagement's attested-run entitlement **as of
/// `now_ms`** (ADR 0048): fold the DE-1 phase, then — for an active entitlement — check
/// the grant's TTL against `now_ms`. Fail-closed (`INV-20`): anything but a fresh,
/// active entitlement denies the sealed-key release. The clock enters as data so the
/// gate stays deterministic and unit-testable (`INV-9`).
pub fn attested_run_verdict_at(
    store: &Store,
    engagement: &str,
    now_ms: u64,
) -> Result<EntitlementVerdict, AdmitError> {
    let s = store.fold::<EntitlementState>(&attested_run_scope(engagement))?;
    // Gate on the **real** active predicate, not `phase == Active` alone: the
    // lifecycle permits `phase == Active` to coexist with a withdrawn/inactive
    // entitlement (`WithdrawPackageInstall` clears `entitlement_active` without
    // moving `phase`), so trusting the phase here would release a sealed key for an
    // inactive entitlement. `phase` is consulted only to explain *why* an inactive
    // entitlement is ineligible (blocked vs no-entitlement).
    Ok(if s.active_entitlement() {
        // Active, but is it still fresh? "valid, *unexpired*".
        match latest_attested_grant(store, engagement)? {
            Some(AttestedRunGrant {
                expires_at_ms: Some(exp),
            }) if now_ms >= exp => EntitlementVerdict::Ineligible {
                reason: EntitlementIneligibility::Expired,
            },
            _ => EntitlementVerdict::Active,
        }
    } else {
        match s.phase {
            // Suspended/closed: the relationship exists but future use is blocked.
            EntitlementPhase::Suspended | EntitlementPhase::Closed => {
                EntitlementVerdict::Ineligible {
                    reason: EntitlementIneligibility::Blocked,
                }
            }
            // None/Requested/Denied — and the withdrawn-while-Active landmine: no
            // active entitlement to bill against.
            _ => EntitlementVerdict::Ineligible {
                reason: EntitlementIneligibility::NoActiveEntitlement,
            },
        }
    })
}

/// The attestation-gate verdict **now** — the shell convenience that reads the wall
/// clock and delegates to [`attested_run_verdict_at`]. Reading the clock here (not in
/// the pure gate) keeps non-determinism at the boundary (`INV-9`).
pub fn attested_run_verdict(
    store: &Store,
    engagement: &str,
) -> Result<EntitlementVerdict, AdmitError> {
    attested_run_verdict_at(store, engagement, now_ms())
}

/// Wall-clock Unix-epoch millis (shell-only; the pure gate never reads it).
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::resource::ResourceId;

    fn version_rec(id: &str) -> VersionRecord {
        VersionRecord {
            id: id.into(),
            agent_ref: "agent-default".into(),
            method_handles: vec![ResourceId::new("ctx-method")],
            config: "{}".into(),
            protection_posture: "local".into(),
            provenance: vec![],
            content_hashes: vec![],
            tombstoned: false,
        }
    }
    fn package_rec(id: &str, version: &str) -> PackageRecord {
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

    // --- attested-run entitlement TTL → Expired verdict (ADR 0048) ---

    /// A non-expiring grant stays `Active` regardless of the clock.
    #[test]
    fn attested_run_without_ttl_is_active_at_any_time() {
        let mut store = Store::open_in_memory().unwrap();
        entitle_attested_run(&mut store, "eng-1").unwrap();
        assert_eq!(
            attested_run_verdict_at(&store, "eng-1", u64::MAX).unwrap(),
            EntitlementVerdict::Active
        );
    }

    /// A TTL grant is `Active` before its expiry and `Expired` at/after it — the
    /// "valid, *unexpired*" half of the gate, with the clock injected as data.
    #[test]
    fn attested_run_ttl_expires_at_the_deadline() {
        let mut store = Store::open_in_memory().unwrap();
        entitle_attested_run_until(&mut store, "eng-1", Some(1_000)).unwrap();

        // Before the deadline: fresh.
        assert_eq!(
            attested_run_verdict_at(&store, "eng-1", 999).unwrap(),
            EntitlementVerdict::Active,
            "active before expiry"
        );
        // At and after the deadline: expired (fail-closed).
        assert_eq!(
            attested_run_verdict_at(&store, "eng-1", 1_000).unwrap(),
            EntitlementVerdict::Ineligible {
                reason: EntitlementIneligibility::Expired
            },
            "expired at the deadline"
        );
        assert_eq!(
            attested_run_verdict_at(&store, "eng-1", 5_000).unwrap(),
            EntitlementVerdict::Ineligible {
                reason: EntitlementIneligibility::Expired
            },
            "stays expired after"
        );
    }

    /// Suspension dominates the TTL: a suspended entitlement is `Blocked` even before
    /// its grant would have expired (future-only block, `INV-18`).
    #[test]
    fn suspended_attested_run_is_blocked_even_before_expiry() {
        let mut store = Store::open_in_memory().unwrap();
        entitle_attested_run_until(&mut store, "eng-1", Some(10_000)).unwrap();
        suspend_attested_run(&mut store, "eng-1").unwrap();
        assert_eq!(
            attested_run_verdict_at(&store, "eng-1", 1).unwrap(),
            EntitlementVerdict::Ineligible {
                reason: EntitlementIneligibility::Blocked
            }
        );
    }

    /// No entitlement at all is `NoActiveEntitlement`, regardless of the clock.
    #[test]
    fn unentitled_engagement_has_no_active_entitlement() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(
            attested_run_verdict_at(&store, "eng-unknown", 0).unwrap(),
            EntitlementVerdict::Ineligible {
                reason: EntitlementIneligibility::NoActiveEntitlement
            }
        );
    }

    #[test]
    fn install_grants_no_run_authority_until_entitled() {
        let mut store = Store::open_in_memory().unwrap();
        let src = "source-lib";
        // source: freeze v1, publish p1 referencing it.
        freeze_version(&mut store, src, &version_rec("v1")).unwrap();
        publish(&mut store, src, &package_rec("p1", "v1")).unwrap();
        // both durable records exist.
        assert_eq!(
            package_store::list::<PackageRecord>(&store, src)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            package_store::list::<VersionRecord>(&store, src)
                .unwrap()
                .len(),
            1
        );

        // target: install. The package is installed…
        assert_eq!(install(&mut store, "p1").unwrap(), DistPhase::Installed);
        assert!(is_installed(&store, "p1").unwrap());
        // …but a governed run is NOT ready — install grants no run authority.
        assert!(
            !run_ready(&store, "p1", "ctx").unwrap(),
            "install alone must not be runnable"
        );

        // target authority: entitle the context → now ready.
        entitle(&mut store, "p1", "ctx").unwrap();
        assert!(
            run_ready(&store, "p1", "ctx").unwrap(),
            "installed + entitled ⇒ runnable"
        );

        // suspending the entitlement blocks future governed runs again.
        suspend(&mut store, "p1", "ctx").unwrap();
        assert!(
            !run_ready(&store, "p1", "ctx").unwrap(),
            "suspended ⇒ not runnable"
        );
        assert!(
            is_installed(&store, "p1").unwrap(),
            "…but the install record persists"
        );
    }

    #[test]
    fn cannot_install_an_unpublished_package() {
        let mut store = Store::open_in_memory().unwrap();
        // no publish → request-install is rejected by PD-1.
        assert!(install(&mut store, "ghost").is_err());
    }
}
