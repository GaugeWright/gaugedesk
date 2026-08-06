//! Boundary keeper — the app-layer gate that turns an *attested* acceptance into
//! a trustworthy boundary admission + a sealed-key release (D-ATTEST / ADR 0040,
//! ATTEST-5).
//!
//! Attestation is a **boundary modifier**, not a separate runtime: the reducer's
//! decision logic is unchanged (`boundary_lifecycle`), but the ceiling
//! (`method_secret() == attested`) is only *honest* if the host actually proved
//! what code it runs before any sealed key reached it. That proof lives here, in
//! the app, behind two seams:
//!
//! - The [`QuoteVerifier`](crate::attestation_verifier) (ATTEST-3) turns the raw
//!   [`AttestationQuote`] a host presents into a
//!   [`QuoteVerificationResult`](gaugedesk_core::attestation::QuoteVerificationResult).
//!   The keeper pairs quote + verdict into the
//!   [`AttestationEvidence`](gaugedesk_core::attestation::AttestationEvidence) that
//!   rides in `BoundaryEvent::Accepted` (ATTEST-2) — so an attested acceptance is
//!   admitted *only* with evidence the verifier vouched for.
//! - The [`SealedKeyReleaseService`] (the KMS seam) releases the keys that unseal
//!   the workload's inputs — and only to a host whose carried evidence is
//!   trustworthy *for the very measurement the key is sealed to* (ATTEST-4/-6).
//!
//! [`accept_boundary_attested`] is the gate that composes them: verify the quote,
//! drive the boundary `Accept` with the resulting evidence, then release the
//! sealed keys gated on that same evidence. A rejected quote never admits the
//! acceptance and never releases a key — the ceiling never over-promises.
//!
//! This is the buildable-now loopback shape: [`LoopbackKeyReleaseService`] is an
//! in-memory key store with no real KMS. A real KMS (Azure Key Vault / AWS KMS /
//! GCP KMS) that binds sealing to attestation attaches behind
//! [`SealedKeyReleaseService`] with no change to the gate (ATTEST-15, needs-infra),
//! exactly like the federation relay and the quote verifier.

use std::collections::BTreeMap;

use gaugedesk_core::attestation::{AttestationEvidence, AttestationQuote, CodeMeasurement};
use gaugedesk_core::boundary_lifecycle::{
    self, pairing_admitted, BoundaryCommand, BoundaryEvent, BoundaryState, PlacementPolicy,
};
use gaugedesk_core::key_release::{
    EntitlementProof, EntitlementVerdict, KeyReleaseDecision, KeyReleaseRequest, SealedKeyRecord,
};
use gaugedesk_core::Lifecycle;
use gaugedesk_store::{AdmitError, Store};

use crate::attestation_verifier::QuoteVerifier;

/// The sealed-key release seam (ATTEST-5): release the key sealed under an id, to
/// a request that carries the attestation evidence a host presented. The decision
/// is the pure [`KeyReleaseRequest::decide`] over the matching [`SealedKeyRecord`];
/// the *service* owns where sealed records live (an in-memory map in the loopback
/// impl, a real KMS behind the same surface later).
pub trait SealedKeyReleaseService {
    /// Decide whether to release the key named by `request.sealed_key_id` to the
    /// evidence the request carries. An unknown id is denied
    /// ([`KeyReleaseDenial::UnknownSealedKey`](gaugedesk_core::key_release::KeyReleaseDenial)),
    /// never released.
    fn release(&self, request: &KeyReleaseRequest) -> KeyReleaseDecision;

    /// The ids of every sealed key bound to `measurement` — exactly the keys an
    /// attested host proving that measurement is entitled to unseal. The
    /// resource-store release flow (ATTEST-6) enumerates these to release and grant
    /// every key the attested boundary unlocks, not just one named key. Ordered for
    /// determinism.
    fn sealed_key_ids_for_measurement(&self, measurement: &CodeMeasurement) -> Vec<String>;
}

/// The buildable-now loopback key-release service: an in-memory set of
/// [`SealedKeyRecord`]s, keyed by id. Release is the pure decision the core
/// defines — trustworthy evidence for the *exact* measurement a key is sealed to,
/// or a structured denial. No real KMS, no I/O.
///
/// The real KMS attaches behind [`SealedKeyReleaseService`] with no change to the
/// gate: it replaces the in-memory map with attestation-bound key sealing.
#[derive(Clone, Debug, Default)]
pub struct LoopbackKeyReleaseService {
    sealed: BTreeMap<String, SealedKeyRecord>,
}

impl LoopbackKeyReleaseService {
    /// An empty service holding no sealed keys.
    pub fn new() -> Self {
        Self::default()
    }

    /// A service holding exactly the given sealed records — the convenient shape
    /// for tests and for seeding from a sealing manifest.
    pub fn with_keys(records: impl IntoIterator<Item = SealedKeyRecord>) -> Self {
        let mut service = Self::new();
        for record in records {
            service.seal(record);
        }
        service
    }

    /// Seal `record` into the service (latest-wins for a given id).
    pub fn seal(&mut self, record: SealedKeyRecord) {
        self.sealed.insert(record.id.clone(), record);
    }

    /// The sealed record for `id`, if one is held.
    pub fn get(&self, id: &str) -> Option<&SealedKeyRecord> {
        self.sealed.get(id)
    }
}

impl SealedKeyReleaseService for LoopbackKeyReleaseService {
    fn release(&self, request: &KeyReleaseRequest) -> KeyReleaseDecision {
        match self.sealed.get(&request.sealed_key_id) {
            Some(record) => request.decide(record),
            None => KeyReleaseDecision::Denied {
                reason: gaugedesk_core::key_release::KeyReleaseDenial::UnknownSealedKey,
            },
        }
    }

    fn sealed_key_ids_for_measurement(&self, measurement: &CodeMeasurement) -> Vec<String> {
        // `sealed` is a BTreeMap, so iteration is id-ordered — deterministic.
        self.sealed
            .values()
            .filter(|record| &record.measurement == measurement)
            .map(|record| record.id.clone())
            .collect()
    }
}

/// The **Azure Key Vault Secure Key Release** seam (ADR 0049): the network call that
/// unwraps a key bound to an attestation policy. The live impl presents the host's
/// attestation (a Microsoft Azure Attestation token derived from `evidence`) to an
/// AKV Managed HSM whose SKR policy is keyed on the launch measurement, and AKV
/// returns the unwrapped key **only** if the policy is satisfied. Tests use an
/// in-process fake. This is the only genuinely hardware/cloud-bound step; everything
/// around it — the gate, the entitlement check — is exercised without it.
pub trait SecureKeyRelease {
    /// Unwrap the key bound to `key_policy_id`, presenting `evidence`. `Ok(bytes)` iff
    /// the SKR policy released it; `Err` iff the policy rejected the attestation or the
    /// call failed (mapped to a fail-closed [`KeyReleaseDenial::ReleaseUnavailable`]).
    fn unwrap_key(
        &self,
        key_policy_id: &str,
        evidence: &AttestationEvidence,
    ) -> Result<Vec<u8>, SkrError>;
}

/// Why an SKR unwrap did not produce a key (kept opaque — the verdict the gate
/// surfaces is always [`KeyReleaseDenial::ReleaseUnavailable`], never the detail).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkrError {
    /// The SKR policy rejected the presented attestation (wrong measurement/claims).
    PolicyRejected,
    /// The call to the KMS failed (network, auth, configuration).
    CallFailed,
}

/// The binding of one sealed key id to the AKV key it unwraps: the measurement the
/// key is released to (the gate checks it) and the AKV SKR key/policy id (what the
/// network call names). The real key bytes live in AKV, never here (ADR 0049).
#[derive(Clone, Debug)]
pub struct KmsKeyBinding {
    /// The launch measurement the key is released to.
    pub measurement: CodeMeasurement,
    /// The AKV Managed HSM key (with its SKR policy) that holds the wrapped key.
    pub key_policy_id: String,
}

/// A KMS-backed [`SealedKeyReleaseService`] (ADR 0049). The **gate decision stays the
/// pure [`KeyReleaseRequest::decide`]** — id match, trustworthy attestation, sealed-to
/// measurement, *and* the ADR-0048 entitlement check — run here against a key-less
/// placeholder record. Only when the gate authorizes does this call Azure SKR for the
/// real bytes; a gate denial never touches the network, and an SKR failure is a
/// fail-closed `ReleaseUnavailable`. So the meter and the security floor are enforced
/// identically to the loopback path; only *where the bytes come from* differs.
#[derive(Clone, Debug)]
pub struct KmsKeyReleaseService<C: SecureKeyRelease> {
    /// sealed_key_id → its AKV binding.
    bindings: BTreeMap<String, KmsKeyBinding>,
    /// The Secure Key Release client (live AKV, or a fake in tests).
    client: C,
}

impl<C: SecureKeyRelease> KmsKeyReleaseService<C> {
    /// Construct from the per-key AKV bindings and the SKR client.
    pub fn new(bindings: impl IntoIterator<Item = (String, KmsKeyBinding)>, client: C) -> Self {
        Self {
            bindings: bindings.into_iter().collect(),
            client,
        }
    }
}

impl<C: SecureKeyRelease> SealedKeyReleaseService for KmsKeyReleaseService<C> {
    fn release(&self, request: &KeyReleaseRequest) -> KeyReleaseDecision {
        use gaugedesk_core::key_release::KeyReleaseDenial;
        let Some(binding) = self.bindings.get(&request.sealed_key_id) else {
            return KeyReleaseDecision::Denied {
                reason: KeyReleaseDenial::UnknownSealedKey,
            };
        };
        // Run the SAME pure gate the loopback path runs — over a key-less placeholder
        // sealed to this binding's measurement. It enforces id + trustworthy + sealed-to
        // measurement + the ADR-0048 entitlement check; the placeholder's empty bytes
        // are never surfaced (a denial returns here; an authorization fetches the real
        // bytes from AKV below).
        let placeholder = SealedKeyRecord::new(
            request.sealed_key_id.clone(),
            binding.measurement.clone(),
            Vec::new(),
        );
        match request.decide(&placeholder) {
            denied @ KeyReleaseDecision::Denied { .. } => denied,
            KeyReleaseDecision::Released { .. } => {
                // Gate authorized → only now does the network call happen.
                match self
                    .client
                    .unwrap_key(&binding.key_policy_id, &request.evidence)
                {
                    Ok(key_bytes) => KeyReleaseDecision::Released { key_bytes },
                    Err(_) => KeyReleaseDecision::Denied {
                        reason: KeyReleaseDenial::ReleaseUnavailable,
                    },
                }
            }
        }
    }

    fn sealed_key_ids_for_measurement(&self, measurement: &CodeMeasurement) -> Vec<String> {
        // BTreeMap iteration is id-ordered — deterministic.
        self.bindings
            .iter()
            .filter(|(_, b)| &b.measurement == measurement)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

/// The outcome of an attested acceptance gate: the boundary state after the
/// acceptance was admitted, and — when a sealed key was requested — the
/// release decision. The decision is `Some` iff a `sealed_key_id` was named.
#[derive(Clone, Debug)]
pub struct AttestedAcceptance {
    /// The boundary state after the (admitted) acceptance.
    pub state: BoundaryState,
    /// The key-release decision, if release of a sealed key was requested.
    pub release: Option<KeyReleaseDecision>,
}

/// Why the attested-acceptance gate refused before any boundary event was
/// admitted or any key released.
#[derive(Debug)]
pub enum AcceptError {
    /// The presented quote did not verify (the verifier rejected it). The
    /// acceptance is never admitted — an attested boundary admits only verified
    /// evidence (ATTEST-2), so the ceiling never over-promises.
    QuoteRejected(gaugedesk_core::attestation::QuoteRejection),
    /// The boundary reducer rejected the acceptance command (not a declared
    /// boundary, not a participant, or the placement is not attested).
    Boundary(gaugedesk_core::Rejection),
    /// The store failed to admit the event.
    Store(AdmitError),
}

/// The attested-acceptance gate (ATTEST-5): admit a participant's acceptance of an
/// *attested* boundary only with evidence a [`QuoteVerifier`] vouched for, then —
/// if `sealed_key_id` is named — release the keys sealed to the attested
/// measurement.
///
/// The flow, in order, so a bad quote stops before it can do harm:
/// 1. **Verify** the presented `quote` against `expected_nonce` via `verifier`. A
///    rejection returns [`AcceptError::QuoteRejected`] — nothing is admitted.
/// 2. **Pair** quote + verdict into
///    [`AttestationEvidence`](gaugedesk_core::attestation::AttestationEvidence) and drive
///    `BoundaryCommand::Accept` against the boundary `scope`. The reducer enforces
///    `ATTESTED_ACCEPT_REQUIRES_EVIDENCE` (ATTEST-2); a non-participant or
///    unattested placement is rejected here.
/// 3. **Release** the sealed key (if requested) gated on that *same* evidence **and**
///    the `entitlement` verdict — the pure [`KeyReleaseRequest::decide`] releases only
///    to trustworthy evidence for the sealed-to measurement *and* a valid, unexpired
///    entitlement for the engagement (ADR 0048). The verdict is the shell's, evaluated
///    by [`package_flow::attested_run_verdict`](crate::package_flow::attested_run_verdict);
///    the gate trusts it.
///
/// Because the released evidence is the verifier's verdict, a key can be released
/// only to a host that genuinely attested a trusted, sealed-to measurement — the
/// host-blind ceiling the placement claims (`Placement::method_secret`) is now
/// backed by the gate, not merely declared — and only while the engagement is
/// entitled (ADR 0048: attestation is the meter).
/// The **policy axis** of policy-gated pairing (`DEPLOY-3`, [ADR 0059]/[ADR 0061]): read the
/// boundary's declared placement from `scope` and decide whether the org placement `policy`
/// admits it, composed with the measurement verdict via
/// [`pairing_admitted`](gaugedesk_core::boundary_lifecycle::pairing_admitted). The client's
/// `accept` route calls this **before** admitting an engagement — refusing a non-compliant
/// deployment mode regardless of whether the quote verifies. Fail-closed (`INV-20`): an
/// unreadable, malformed, or not-yet-declared boundary is **not** admitted.
///
/// [ADR 0059]: ../../specs/decisions/0059-deployment-topology-headless-control-plane-policy-gated-pairing.md
/// [ADR 0061]: ../../specs/decisions/0061-tenant-and-home-governance.md
pub fn pairing_policy_admits(
    store: &Store,
    scope: &str,
    policy: &PlacementPolicy,
    measurement_verified: bool,
) -> bool {
    let Ok(rows) = store.records(scope, <BoundaryState as Lifecycle>::KIND) else {
        return false;
    };
    let mut state = BoundaryState::default();
    for row in rows {
        let Ok(ev) = serde_json::from_str::<BoundaryEvent>(&row) else {
            return false;
        };
        state = boundary_lifecycle::evolve(&state, ev);
    }
    let Some(declared) = state.placement else {
        return false;
    };
    pairing_admitted(policy, &declared, measurement_verified)
}

#[allow(clippy::too_many_arguments)] // the attested-acceptance gate genuinely needs all of: store, scope, participant, quote, expected measurement, verifier, key-release service, entitlement verdict, and sealed-key sink.
pub fn accept_boundary_attested(
    store: &mut Store,
    scope: &str,
    participant: &str,
    quote: AttestationQuote,
    expected_nonce: &str,
    verifier: &dyn QuoteVerifier,
    keys: &dyn SealedKeyReleaseService,
    entitlement: EntitlementVerdict,
    sealed_key_id: Option<&str>,
) -> Result<AttestedAcceptance, AcceptError> {
    use gaugedesk_core::attestation::{AttestationEvidence, QuoteVerificationResult};

    // 1. Verify the presented quote. A rejected quote never reaches the boundary.
    let result = verifier.verify(&quote, expected_nonce);
    if let QuoteVerificationResult::Rejected { reason } = result {
        return Err(AcceptError::QuoteRejected(reason));
    }
    let evidence = AttestationEvidence::new(quote, result);

    // 2. Drive the acceptance with the verified evidence. The reducer is the
    //    authority on whether this is a valid attested acceptance (ATTEST-2).
    let state = store
        .admit::<BoundaryState>(
            scope,
            BoundaryCommand::Accept {
                participant: participant.to_string(),
                evidence: Some(evidence.clone()),
            },
        )
        .map_err(|e| match e {
            AdmitError::Rejected(r) => AcceptError::Boundary(r),
            other => AcceptError::Store(other),
        })?;

    // 3. Release the sealed key (if requested) gated on the same evidence AND the
    //    engagement's entitlement verdict (ADR 0048). A request whose evidence is not
    //    trustworthy for the sealed-to measurement — or whose engagement is not
    //    entitled — is denied by the pure decision; the acceptance still stands, but
    //    no key flows.
    let release = sealed_key_id.map(|id| {
        keys.release(&KeyReleaseRequest::new(
            id,
            evidence.clone(),
            EntitlementProof::new(scope, entitlement),
        ))
    });

    Ok(AttestedAcceptance { state, release })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation_verifier::LoopbackVerifier;
    use gaugedesk_core::attestation::{CodeMeasurement, QuoteRejection};
    use gaugedesk_core::boundary_lifecycle::{Operator, Placement};
    use gaugedesk_core::key_release::{EntitlementIneligibility, KeyReleaseDenial};
    use std::collections::BTreeSet;

    const NONCE: &str = "challenge-1";

    fn measurement() -> CodeMeasurement {
        CodeMeasurement::new("a".repeat(64))
    }

    fn other_measurement() -> CodeMeasurement {
        CodeMeasurement::new("b".repeat(64))
    }

    fn quote_for(m: CodeMeasurement, nonce: &str) -> AttestationQuote {
        AttestationQuote::new(m, nonce, vec![1, 2, 3, 4])
    }

    fn parts() -> BTreeSet<String> {
        BTreeSet::from(["A".to_string(), "B".to_string()])
    }

    /// A store with an *attested* boundary declared and proposed, ready for an
    /// acceptance — the precondition the gate runs against.
    fn attested_boundary(scope: &str) -> Store {
        let mut store = Store::open_in_memory().unwrap();
        store
            .admit::<BoundaryState>(scope, BoundaryCommand::Propose(parts()))
            .unwrap();
        store
            .admit::<BoundaryState>(
                scope,
                BoundaryCommand::DeclareCeiling(Placement {
                    operator: Operator::Counterparty,
                    attested: true,
                }),
            )
            .unwrap();
        store
    }

    fn verifier() -> LoopbackVerifier {
        LoopbackVerifier::trusting(measurement())
    }

    #[test]
    fn pairing_policy_axis_composes_policy_and_measurement() {
        // The declared boundary is counterparty-hosted + attested.
        let store = attested_boundary("bnd");

        // Open policy admits, gated only by the measurement verdict.
        let open = PlacementPolicy::open();
        assert!(pairing_policy_admits(&store, "bnd", &open, true));
        assert!(!pairing_policy_admits(&store, "bnd", &open, false)); // attested ⇒ must verify

        // require_attested is satisfied (the boundary is attested) — admitted when verified.
        let strict = PlacementPolicy {
            require_attested: true,
            ..Default::default()
        };
        assert!(pairing_policy_admits(&store, "bnd", &strict, true));
        assert!(!pairing_policy_admits(&store, "bnd", &strict, false));

        // A policy that only allows Local refuses the counterparty placement (policy axis),
        // regardless of a verified measurement.
        let local_only = PlacementPolicy {
            allowed_operators: BTreeSet::from([Operator::Local]),
            ..Default::default()
        };
        assert!(!pairing_policy_admits(&store, "bnd", &local_only, true));

        // Fail-closed: an undeclared boundary is never admitted.
        let empty = Store::open_in_memory().unwrap();
        assert!(!pairing_policy_admits(&empty, "bnd", &open, true));
    }

    fn key_service() -> LoopbackKeyReleaseService {
        LoopbackKeyReleaseService::with_keys([SealedKeyRecord::new(
            "sealed-1",
            measurement(),
            vec![9, 8, 7],
        )])
    }

    /// The happy path: a fresh quote for a trusted measurement verifies, the
    /// acceptance is admitted with the evidence, and the sealed key — sealed to that
    /// very measurement — is released.
    #[test]
    fn verified_quote_admits_acceptance_and_releases_sealed_key() {
        let scope = "boundary-1";
        let mut store = attested_boundary(scope);
        let out = accept_boundary_attested(
            &mut store,
            scope,
            "A",
            quote_for(measurement(), NONCE),
            NONCE,
            &verifier(),
            &key_service(),
            EntitlementVerdict::Active,
            Some("sealed-1"),
        )
        .expect("verified quote accepts");

        assert!(out.state.accepted.contains("A"));
        assert!(out.state.attestation_evidence.contains_key("A"));
        let release = out.release.expect("release was requested");
        assert!(release.is_released());
        assert_eq!(release.released_key(), Some([9, 8, 7].as_slice()));
    }

    /// A quote echoing a stale nonce is a possible replay: rejected by the verifier,
    /// the acceptance is never admitted and no key is released — the boundary state
    /// is untouched.
    #[test]
    fn stale_nonce_quote_rejects_and_admits_nothing() {
        let scope = "boundary-2";
        let mut store = attested_boundary(scope);
        let err = accept_boundary_attested(
            &mut store,
            scope,
            "A",
            quote_for(measurement(), "stale-nonce"),
            NONCE,
            &verifier(),
            &key_service(),
            EntitlementVerdict::Active,
            Some("sealed-1"),
        )
        .expect_err("stale nonce rejects");
        assert!(matches!(
            err,
            AcceptError::QuoteRejected(QuoteRejection::StaleNonce)
        ));

        // Nothing was admitted: the participant never accepted.
        let state = store.fold::<BoundaryState>(scope).unwrap();
        assert!(!state.accepted.contains("A"));
        assert!(state.attestation_evidence.is_empty());
    }

    /// A quote for an untrusted measurement is rejected before any boundary event —
    /// a host running unknown code never gets its acceptance admitted, let alone a key.
    #[test]
    fn untrusted_measurement_rejects_and_admits_nothing() {
        let scope = "boundary-3";
        let mut store = attested_boundary(scope);
        let err = accept_boundary_attested(
            &mut store,
            scope,
            "A",
            quote_for(other_measurement(), NONCE),
            NONCE,
            &verifier(),
            &key_service(),
            EntitlementVerdict::Active,
            Some("sealed-1"),
        )
        .expect_err("unknown measurement rejects");
        assert!(matches!(
            err,
            AcceptError::QuoteRejected(QuoteRejection::UnknownMeasurement)
        ));
        assert!(store
            .fold::<BoundaryState>(scope)
            .unwrap()
            .accepted
            .is_empty());
    }

    /// A correctly-attested host whose measurement does not match the *sealed* key is
    /// admitted to the boundary (its quote is trustworthy) but denied the key — a
    /// trusted host still cannot take another measurement's sealed key.
    #[test]
    fn trusted_but_non_matching_measurement_accepts_but_is_denied_the_key() {
        let scope = "boundary-4";
        let mut store = attested_boundary(scope);
        // Verifier trusts the *other* measurement; key is sealed to `measurement()`.
        let verifier = LoopbackVerifier::trusting(other_measurement());
        let out = accept_boundary_attested(
            &mut store,
            scope,
            "A",
            quote_for(other_measurement(), NONCE),
            NONCE,
            &verifier,
            &key_service(),
            EntitlementVerdict::Active,
            Some("sealed-1"),
        )
        .expect("trustworthy quote accepts");
        assert!(out.state.accepted.contains("A"));
        assert_eq!(
            out.release,
            Some(KeyReleaseDecision::Denied {
                reason: KeyReleaseDenial::MeasurementMismatch
            })
        );
    }

    /// A request for a sealed key the service does not hold is denied as unknown —
    /// never released, even to a perfectly trustworthy host.
    #[test]
    fn unknown_sealed_key_is_denied() {
        let scope = "boundary-5";
        let mut store = attested_boundary(scope);
        let out = accept_boundary_attested(
            &mut store,
            scope,
            "A",
            quote_for(measurement(), NONCE),
            NONCE,
            &verifier(),
            &key_service(),
            EntitlementVerdict::Active,
            Some("no-such-key"),
        )
        .expect("verified quote accepts");
        assert!(out.state.accepted.contains("A"));
        assert_eq!(
            out.release,
            Some(KeyReleaseDecision::Denied {
                reason: KeyReleaseDenial::UnknownSealedKey
            })
        );
    }

    /// Accepting without requesting a sealed key admits the acceptance and releases
    /// nothing — the gate also serves pure attested admission.
    #[test]
    fn acceptance_without_key_request_releases_nothing() {
        let scope = "boundary-6";
        let mut store = attested_boundary(scope);
        let out = accept_boundary_attested(
            &mut store,
            scope,
            "A",
            quote_for(measurement(), NONCE),
            NONCE,
            &verifier(),
            &key_service(),
            EntitlementVerdict::Active,
            None,
        )
        .expect("verified quote accepts");
        assert!(out.state.accepted.contains("A"));
        assert!(out.release.is_none());
    }

    /// A ghost participant is rejected by the reducer even with a verified quote —
    /// the boundary keeper does not bypass `NO_GHOST_ACCEPT`.
    #[test]
    fn ghost_participant_is_rejected_by_the_boundary_reducer() {
        let scope = "boundary-7";
        let mut store = attested_boundary(scope);
        let err = accept_boundary_attested(
            &mut store,
            scope,
            "ghost",
            quote_for(measurement(), NONCE),
            NONCE,
            &verifier(),
            &key_service(),
            EntitlementVerdict::Active,
            Some("sealed-1"),
        )
        .expect_err("ghost cannot accept");
        assert!(matches!(err, AcceptError::Boundary(_)));
        assert!(store
            .fold::<BoundaryState>(scope)
            .unwrap()
            .accepted
            .is_empty());
    }

    /// Two trustworthy attested acceptances drive the boundary to active and the
    /// honest host-blind ceiling holds — the end-to-end attested admission the
    /// ATTEST-5 gate enables.
    #[test]
    fn both_attested_acceptances_activate_a_host_blind_boundary() {
        let scope = "boundary-8";
        let mut store = attested_boundary(scope);
        for p in ["A", "B"] {
            accept_boundary_attested(
                &mut store,
                scope,
                p,
                quote_for(measurement(), NONCE),
                NONCE,
                &verifier(),
                &key_service(),
                EntitlementVerdict::Active,
                None,
            )
            .expect("verified quote accepts");
        }
        let state = store.fold::<BoundaryState>(scope).unwrap();
        assert!(state.active());
        assert!(state.placement.unwrap().method_secret());
    }

    /// ADR 0048: a fully trustworthy attested acceptance still releases **no key**
    /// when the engagement presents no active entitlement — the commercial gate is the
    /// same checkpoint as the seal. The acceptance is admitted (attestation is sound);
    /// only the key is gated, with a structured `Unentitled` denial.
    #[test]
    fn unentitled_engagement_is_admitted_but_denied_the_key() {
        let scope = "boundary-9";
        let mut store = attested_boundary(scope);
        let out = accept_boundary_attested(
            &mut store,
            scope,
            "A",
            quote_for(measurement(), NONCE),
            NONCE,
            &verifier(),
            &key_service(),
            EntitlementVerdict::Ineligible {
                reason: EntitlementIneligibility::NoActiveEntitlement,
            },
            Some("sealed-1"),
        )
        .expect("trustworthy quote accepts");
        assert!(out.state.accepted.contains("A"));
        assert_eq!(
            out.release,
            Some(KeyReleaseDecision::Denied {
                reason: KeyReleaseDenial::Unentitled {
                    reason: EntitlementIneligibility::NoActiveEntitlement
                }
            })
        );
    }

    /// The loopback service is the pure-decision seam: a held sealed key releases to
    /// trustworthy evidence, and `get` exposes the sealed record.
    #[test]
    fn loopback_service_releases_via_the_pure_decision() {
        let service = key_service();
        assert!(service.get("sealed-1").is_some());
        assert!(service.get("missing").is_none());

        let evidence = gaugedesk_core::attestation::AttestationEvidence::new(
            quote_for(measurement(), NONCE),
            gaugedesk_core::attestation::QuoteVerificationResult::Verified {
                measurement: measurement(),
            },
        );
        let decision = service.release(&KeyReleaseRequest::new(
            "sealed-1",
            evidence,
            EntitlementProof::active("engagement-1"),
        ));
        assert!(decision.is_released());
    }

    /// The KMS-backed service (ADR 0049): the gate (incl. the ADR-0048 entitlement
    /// check) stays the pure decision, and Azure SKR is called only after it
    /// authorizes — a denial never touches the network.
    mod kms {
        use super::*;
        use gaugedesk_core::attestation::{AttestationEvidence, QuoteVerificationResult};
        use std::cell::Cell;
        use std::rc::Rc;

        /// A fake Secure Key Release client: a fixed outcome + a shared call counter so
        /// a test can assert the network was (not) reached.
        struct FakeSkr {
            outcome: Result<Vec<u8>, SkrError>,
            calls: Rc<Cell<u32>>,
        }
        impl SecureKeyRelease for FakeSkr {
            fn unwrap_key(
                &self,
                _key_policy_id: &str,
                _evidence: &AttestationEvidence,
            ) -> Result<Vec<u8>, SkrError> {
                self.calls.set(self.calls.get() + 1);
                self.outcome.clone()
            }
        }

        fn trustworthy() -> AttestationEvidence {
            AttestationEvidence::new(
                quote_for(measurement(), NONCE),
                QuoteVerificationResult::Verified {
                    measurement: measurement(),
                },
            )
        }
        fn binding() -> (String, KmsKeyBinding) {
            (
                "sealed-1".to_string(),
                KmsKeyBinding {
                    measurement: measurement(),
                    key_policy_id: "akv://example-mhsm/keys/seal-1".to_string(),
                },
            )
        }
        fn service(
            outcome: Result<Vec<u8>, SkrError>,
        ) -> (KmsKeyReleaseService<FakeSkr>, Rc<Cell<u32>>) {
            let calls = Rc::new(Cell::new(0));
            let svc = KmsKeyReleaseService::new(
                [binding()],
                FakeSkr {
                    outcome,
                    calls: calls.clone(),
                },
            );
            (svc, calls)
        }
        fn request(evidence: AttestationEvidence, ent: EntitlementProof) -> KeyReleaseRequest {
            KeyReleaseRequest::new("sealed-1", evidence, ent)
        }

        /// Gate passes (trustworthy + sealed-to measurement + entitled) → AKV is called
        /// and its unwrapped bytes are released. The key never lived in-process.
        #[test]
        fn gate_pass_releases_the_akv_unwrapped_key() {
            let (svc, calls) = service(Ok(vec![7, 7, 7]));
            let d = svc.release(&request(trustworthy(), EntitlementProof::active("eng")));
            assert_eq!(d.released_key(), Some([7, 7, 7].as_slice()));
            assert_eq!(
                calls.get(),
                1,
                "AKV is called exactly once on a gated release"
            );
        }

        /// No entitlement → `Unentitled`, and **AKV is never called** (the meter gates
        /// before the network).
        #[test]
        fn unentitled_denies_without_calling_the_kms() {
            let (svc, calls) = service(Ok(vec![7]));
            let d = svc.release(&request(
                trustworthy(),
                EntitlementProof::ineligible("eng", EntitlementIneligibility::NoActiveEntitlement),
            ));
            assert_eq!(
                d,
                KeyReleaseDecision::Denied {
                    reason: KeyReleaseDenial::Unentitled {
                        reason: EntitlementIneligibility::NoActiveEntitlement
                    }
                }
            );
            assert_eq!(calls.get(), 0, "a gate denial must not reach the KMS");
        }

        /// Untrustworthy attestation → `UntrustedAttestation`, AKV never called.
        #[test]
        fn untrusted_attestation_denies_without_calling_the_kms() {
            let untrusted = AttestationEvidence::new(
                quote_for(measurement(), NONCE),
                QuoteVerificationResult::Rejected {
                    reason: QuoteRejection::StaleNonce,
                },
            );
            let (svc, calls) = service(Ok(vec![7]));
            let d = svc.release(&request(untrusted, EntitlementProof::active("eng")));
            assert_eq!(
                d,
                KeyReleaseDecision::Denied {
                    reason: KeyReleaseDenial::UntrustedAttestation
                }
            );
            assert_eq!(calls.get(), 0);
        }

        /// Gate authorizes but AKV SKR rejects/fails → fail-closed `ReleaseUnavailable`,
        /// no bytes flow.
        #[test]
        fn skr_failure_is_release_unavailable() {
            let (svc, calls) = service(Err(SkrError::PolicyRejected));
            let d = svc.release(&request(trustworthy(), EntitlementProof::active("eng")));
            assert_eq!(
                d,
                KeyReleaseDecision::Denied {
                    reason: KeyReleaseDenial::ReleaseUnavailable
                }
            );
            assert_eq!(calls.get(), 1, "the gate passed, so AKV was attempted");
        }

        /// An unknown sealed-key id is denied as unknown, AKV never called.
        #[test]
        fn unknown_key_id_denies_without_calling_the_kms() {
            let (svc, calls) = service(Ok(vec![7]));
            let d = svc.release(&KeyReleaseRequest::new(
                "no-such-key",
                trustworthy(),
                EntitlementProof::active("eng"),
            ));
            assert_eq!(
                d,
                KeyReleaseDecision::Denied {
                    reason: KeyReleaseDenial::UnknownSealedKey
                }
            );
            assert_eq!(calls.get(), 0);
        }

        /// The measurement→key enumeration mirrors the loopback service's.
        #[test]
        fn enumerates_keys_for_a_measurement() {
            let (svc, _) = service(Ok(vec![7]));
            assert_eq!(
                svc.sealed_key_ids_for_measurement(&measurement()),
                vec!["sealed-1".to_string()]
            );
            assert!(svc
                .sealed_key_ids_for_measurement(&other_measurement())
                .is_empty());
        }
    }
}
