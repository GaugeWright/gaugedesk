//! Measurement store — the reproducible-build seam (D-ATTEST / ADR 0040, ATTEST-10).
//!
//! Attestation only protects a method secret if the [`CodeMeasurement`] a host
//! attests to can be tied back to a *known, reproducible build*: a verdict of
//! "this host runs digest `abc…`" is worthless unless we already know that
//! `abc…` is the SHA-256 of an image we built from audited source. The
//! measurement store is that map — from a logical [`BuildId`] (an image ref +
//! version a reproducible build publishes) to the [`MeasurementRecord`] pinning
//! the measurement that build produces.
//!
//! Two reads sit on top of it:
//! - [`MeasurementStore::lookup`] — resolve one build to its pinned measurement.
//! - [`MeasurementStore::allow_list`] — the set of trusted measurements, which is
//!   exactly the allow-list a [`LoopbackVerifier`](crate::attestation_verifier)
//!   (and, later, a real TEE verifier) consults before a quote may verify
//!   (ATTEST-3) and before any sealed key is released to it (ATTEST-5).
//!
//! This is the buildable-now, in-memory loopback shape: the store is populated by
//! the operator registering the measurements they trust. The real impl attaches
//! behind the same surface — it ingests the SHA-256 measurements a reproducible
//! build CI/CD pipeline produces and publishes (ATTEST-15, needs-infra) — with no
//! change to callers, exactly like the federation relay and the quote verifier.

use std::collections::BTreeMap;

use gaugedesk_core::attestation::CodeMeasurement;
use gaugedesk_store::{AdmitError, Store};

use crate::boundary_keeper::LoopbackKeyReleaseService;
use crate::Workbench;

/// The well-known scope holding the **durable** operator measurement registry — the
/// append-only record of which reproducible builds the operator trusts (ADR 0049). The
/// in-memory [`MeasurementStore`] is rebuilt from it at startup so registrations
/// survive a restart (the loopback store was per-process and lost them).
pub const REGISTRY_SCOPE: &str = "measurements";
/// The record kind under which a [`MeasurementRecord`] is persisted in the registry.
const MEASUREMENT_KIND: &str = "measurement-record";

/// The logical identity of a reproducible build: the image reference and the
/// version a build of it publishes. Two builds of the *same* source at the *same*
/// version reproduce the same [`CodeMeasurement`]; a [`BuildId`] is how the
/// operator names which build they mean when registering or looking up a trusted
/// measurement.
///
/// A typed identity, never a bare `String` pair in the domain (`principles.md`
/// "Contracts at the boundary"); builds compare and key by value.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct BuildId {
    /// The image reference the build publishes under (e.g. a registry path).
    pub image_ref: String,
    /// The build version / tag (e.g. a release version or git describe).
    pub version: String,
}

impl BuildId {
    /// Name a build by its image reference and version.
    pub fn new(image_ref: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            image_ref: image_ref.into(),
            version: version.into(),
        }
    }
}

/// A pinned reproducible-build measurement: the [`CodeMeasurement`] a build of
/// [`build`](MeasurementRecord::build) produces. Registering one declares "a host
/// attesting to this measurement is running exactly this build" — the fact the
/// verifier's allow-list is derived from.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MeasurementRecord {
    /// The build this measurement was produced by.
    pub build: BuildId,
    /// The image digest a reproducible build of `build` produces.
    pub measurement: CodeMeasurement,
}

impl MeasurementRecord {
    /// Pin `measurement` as the digest of `build`.
    pub fn new(build: BuildId, measurement: CodeMeasurement) -> Self {
        Self { build, measurement }
    }
}

/// An in-memory store of trusted reproducible-build measurements, keyed by
/// [`BuildId`] (latest registration wins for a given build — a re-publish of the
/// same version supersedes the prior pin).
///
/// The loopback-first impl of the ATTEST-10 seam: the operator registers the
/// builds they trust; the verifier reads back the [`allow_list`](Self::allow_list).
/// The real impl ingests measurements from a reproducible-build pipeline behind the
/// same surface (ATTEST-15).
#[derive(Clone, Debug, Default)]
pub struct MeasurementStore {
    records: BTreeMap<BuildId, CodeMeasurement>,
}

impl MeasurementStore {
    /// An empty store, trusting no measurement.
    pub fn new() -> Self {
        Self::default()
    }

    /// A store trusting exactly the given records — the convenient shape for tests
    /// and for seeding from a known build manifest.
    pub fn with_records(records: impl IntoIterator<Item = MeasurementRecord>) -> Self {
        let mut store = Self::new();
        for record in records {
            store.register(record);
        }
        store
    }

    /// Register (or update, latest-wins) the trusted measurement for a build.
    pub fn register(&mut self, record: MeasurementRecord) {
        self.records.insert(record.build, record.measurement);
    }

    /// The pinned measurement for `build`, if one is registered.
    pub fn lookup(&self, build: &BuildId) -> Option<&CodeMeasurement> {
        self.records.get(build)
    }

    /// Whether any registered build pins `measurement` — the predicate the boundary
    /// gate uses to confirm an attested digest is a known reproducible build.
    pub fn is_trusted(&self, measurement: &CodeMeasurement) -> bool {
        self.records.values().any(|m| m == measurement)
    }

    /// The reproducible-build allow-list: every trusted measurement, deduplicated.
    /// This is exactly what a verifier is constructed to trust (ATTEST-3): two
    /// builds may reproduce the same digest, so the list carries each measurement
    /// once.
    pub fn allow_list(&self) -> Vec<CodeMeasurement> {
        let mut out: Vec<CodeMeasurement> = Vec::new();
        for m in self.records.values() {
            if !out.contains(m) {
                out.push(m.clone());
            }
        }
        out
    }

    /// How many builds are registered.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the store trusts no build (an empty allow-list).
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Every registered build→measurement record — the operator-facing registry view
    /// (`GET /measurements`), build-ordered. Unlike [`allow_list`](Self::allow_list)
    /// it keeps the build mapping (it does not dedup by measurement).
    pub fn records(&self) -> Vec<MeasurementRecord> {
        self.records
            .iter()
            .map(|(build, m)| MeasurementRecord::new(build.clone(), m.clone()))
            .collect()
    }

    /// The builds whose registered measurement equals `measurement` — **verify-before-
    /// trust** (ADR 0044): a consultant/client recomputes the digest from the open
    /// reproducible build and confirms it maps to a known, trusted build. Empty ⇒ the
    /// digest is not trusted.
    pub fn builds_for_measurement(&self, measurement: &CodeMeasurement) -> Vec<BuildId> {
        self.records
            .iter()
            .filter(|(_, m)| *m == measurement)
            .map(|(build, _)| build.clone())
            .collect()
    }
}

/// Persist a registration to the durable registry (ADR 0049) — append-only, latest-wins
/// by build on restore. Call alongside [`MeasurementStore::register`] so the in-memory
/// allow-list and the durable record stay in step.
pub fn persist(store: &mut Store, record: &MeasurementRecord) -> Result<(), AdmitError> {
    let payload = serde_json::to_string(record)?;
    store.append_record(REGISTRY_SCOPE, MEASUREMENT_KIND, &payload)?;
    Ok(())
}

/// The durable registry's current records, folded latest-wins by [`BuildId`] (a
/// re-publish of a version supersedes the prior pin). Used to rebuild the in-memory
/// [`MeasurementStore`] at startup.
pub fn restore_records(store: &Store) -> Result<Vec<MeasurementRecord>, AdmitError> {
    let mut latest: BTreeMap<BuildId, MeasurementRecord> = BTreeMap::new();
    for row in store.records(REGISTRY_SCOPE, MEASUREMENT_KIND)? {
        let rec: MeasurementRecord = serde_json::from_str(&row)?;
        // records() is position-ordered (oldest→newest), so a later registration wins.
        latest.insert(rec.build.clone(), rec);
    }
    Ok(latest.into_values().collect())
}

impl Workbench {
    /// The reproducible-build measurement store (ATTEST-10) — what an attested
    /// host's quote is checked against. Mutable so the operator (or a startup seed)
    /// can register the builds they trust.
    pub fn measurements(&mut self) -> &mut MeasurementStore {
        &mut self.measurements
    }

    /// The trusted-measurement registry, read-only — for the operator registry views
    /// (`GET /measurements`, verify-before-trust).
    pub fn measurements_ref(&self) -> &MeasurementStore {
        &self.measurements
    }

    /// The sealed-key release service (ATTEST-5/-6) — the keys an attested host may
    /// unseal. Mutable so the operator can seal the keys a placement releases.
    pub fn sealed_keys(&mut self) -> &mut LoopbackKeyReleaseService {
        &mut self.sealed_keys
    }

    /// Register a trusted reproducible-build measurement (ADR 0049, ATTEST-10): persist
    /// it to the durable registry **and** add it to the in-memory allow-list, so the
    /// verifier trusts it immediately and a restart restores it.
    pub fn register_measurement(&mut self, record: MeasurementRecord) -> Result<(), AdmitError> {
        persist(self.store_mut(), &record)?;
        self.measurements.register(record);
        Ok(())
    }

    /// Rebuild the in-memory measurement allow-list from the durable registry — run at
    /// startup so operator registrations survive a restart (the loopback store was
    /// per-process). Mirrors `Workbench::restore_workstream_homing`.
    pub fn restore_measurements(&mut self) {
        if let Ok(records) = restore_records(self.store_ref()) {
            for record in records {
                self.measurements.register(record);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation_verifier::{LoopbackVerifier, QuoteVerifier};
    use gaugedesk_core::attestation::{AttestationQuote, QuoteVerificationResult};

    fn measurement_a() -> CodeMeasurement {
        CodeMeasurement::new("a".repeat(64))
    }

    fn measurement_b() -> CodeMeasurement {
        CodeMeasurement::new("b".repeat(64))
    }

    fn build_a() -> BuildId {
        BuildId::new("registry/gaugewright-host", "1.0.0")
    }

    fn build_b() -> BuildId {
        BuildId::new("registry/gaugewright-host", "2.0.0")
    }

    #[test]
    fn lookup_resolves_a_registered_build_to_its_measurement() {
        let store =
            MeasurementStore::with_records([MeasurementRecord::new(build_a(), measurement_a())]);
        assert_eq!(store.lookup(&build_a()), Some(&measurement_a()));
        assert_eq!(store.lookup(&build_b()), None);
    }

    #[test]
    fn empty_store_trusts_nothing() {
        let store = MeasurementStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(!store.is_trusted(&measurement_a()));
        assert!(store.allow_list().is_empty());
    }

    #[test]
    fn registering_a_build_makes_its_measurement_trusted() {
        let mut store = MeasurementStore::new();
        store.register(MeasurementRecord::new(build_a(), measurement_a()));
        assert!(store.is_trusted(&measurement_a()));
        assert!(!store.is_trusted(&measurement_b()));
        assert_eq!(store.allow_list(), vec![measurement_a()]);
    }

    /// Re-registering the same build (a re-publish of that version) supersedes the
    /// prior pin latest-wins, without adding a second entry.
    #[test]
    fn re_registering_a_build_supersedes_latest_wins() {
        let mut store = MeasurementStore::new();
        store.register(MeasurementRecord::new(build_a(), measurement_a()));
        store.register(MeasurementRecord::new(build_a(), measurement_b()));
        assert_eq!(store.len(), 1);
        assert_eq!(store.lookup(&build_a()), Some(&measurement_b()));
        assert!(!store.is_trusted(&measurement_a()));
        assert!(store.is_trusted(&measurement_b()));
    }

    /// Two distinct builds that reproduce the *same* digest appear once in the
    /// allow-list — it is the deduplicated set of trusted measurements.
    #[test]
    fn allow_list_deduplicates_shared_measurements() {
        let store = MeasurementStore::with_records([
            MeasurementRecord::new(build_a(), measurement_a()),
            MeasurementRecord::new(build_b(), measurement_a()),
        ]);
        assert_eq!(store.len(), 2);
        assert_eq!(store.allow_list(), vec![measurement_a()]);
    }

    /// The store's allow-list is exactly what a verifier is built to trust: a quote
    /// for a registered build verifies; one for an unregistered build does not
    /// (ATTEST-3 ⇄ ATTEST-10). This is the seam the boundary gate rides.
    #[test]
    fn allow_list_drives_the_verifier_trust_decision() {
        let store =
            MeasurementStore::with_records([MeasurementRecord::new(build_a(), measurement_a())]);
        let verifier = LoopbackVerifier::new(store.allow_list());

        let trusted_quote = AttestationQuote::new(measurement_a(), "nonce-1", vec![1, 2, 3]);
        assert_eq!(
            verifier.verify(&trusted_quote, "nonce-1"),
            QuoteVerificationResult::Verified {
                measurement: measurement_a()
            }
        );

        let unknown_quote = AttestationQuote::new(measurement_b(), "nonce-1", vec![1, 2, 3]);
        assert!(!verifier.verify(&unknown_quote, "nonce-1").is_verified());
    }

    /// The record round-trips through serde (it rides API projections + any later
    /// durable manifest, like the other app records).
    #[test]
    fn measurement_record_serde_round_trips() {
        let record = MeasurementRecord::new(build_a(), measurement_a());
        let json = serde_json::to_string(&record).unwrap();
        let back: MeasurementRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    /// `records()` keeps the build mapping (unlike the deduped allow-list), and
    /// `builds_for_measurement` is the verify-before-trust lookup.
    #[test]
    fn records_and_verify_before_trust_lookup() {
        let store = MeasurementStore::with_records([
            MeasurementRecord::new(build_a(), measurement_a()),
            MeasurementRecord::new(build_b(), measurement_a()), // same digest, two builds
        ]);
        assert_eq!(store.records().len(), 2, "both builds kept (not deduped)");
        // A trusted digest maps back to the builds that reproduce it.
        let mut builds = store.builds_for_measurement(&measurement_a());
        builds.sort();
        assert_eq!(builds, vec![build_a(), build_b()]);
        // An unknown digest maps to no build → untrusted.
        assert!(store.builds_for_measurement(&measurement_b()).is_empty());
    }

    /// The durable registry round-trips: persisted registrations restore (latest-wins
    /// by build), so registrations survive a process restart.
    #[test]
    fn registry_persist_then_restore_round_trips() {
        let mut store = Store::open_in_memory().unwrap();
        persist(
            &mut store,
            &MeasurementRecord::new(build_a(), measurement_a()),
        )
        .unwrap();
        persist(
            &mut store,
            &MeasurementRecord::new(build_b(), measurement_b()),
        )
        .unwrap();
        // Re-publish build_a at a new digest — latest wins.
        persist(
            &mut store,
            &MeasurementRecord::new(build_a(), measurement_b()),
        )
        .unwrap();

        // Rebuild a fresh in-memory store from the durable records, as startup does.
        let restored = MeasurementStore::with_records(restore_records(&store).unwrap());
        assert_eq!(restored.len(), 2, "two distinct builds");
        assert_eq!(
            restored.lookup(&build_a()),
            Some(&measurement_b()),
            "latest wins"
        );
        assert_eq!(restored.lookup(&build_b()), Some(&measurement_b()));
        // measurement_a was superseded for build_a → no longer trusted.
        assert!(!restored.is_trusted(&measurement_a()));
        assert!(restored.is_trusted(&measurement_b()));
    }
}
