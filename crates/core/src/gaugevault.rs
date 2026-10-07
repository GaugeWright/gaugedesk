//! GaugeVault credential standing (VAULT-2; GaugeWright DR-0150).
//!
//! This pure reducer orders candidates, activation, revocation and erasure for
//! one opaque owner scope. It holds a distinct object name and exact backing
//! reference per candidate, never material.
//! The admitting shell authenticates capabilities and Key Vault observations.
//! The dispatch ledger orders one-use final effects against rotation and
//! revocation. The shell still must verify grants, the independent recovery
//! fence and the exact request; this state alone must never authorize use.

use std::collections::{BTreeMap, BTreeSet};

use crate::ids::{
    AuthorityId, ObservationId, ScopeId, VaultBackingVersionId, VaultCandidateId,
    VaultCredentialId, VaultDispatchId, VaultIntakeMarkerId, VaultOperationId, VaultStorageNameId,
    VaultSubjectId, VaultTargetId, VaultTenantPrefixId,
};
use crate::{Lifecycle, Rejection};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Binding {
    pub authority: AuthorityId,
    pub owner_scope: ScopeId,
    /// The Store stream for this one credential; the shell must admit the
    /// event under this exact scope, distinct from another credential's log.
    pub credential_scope: ScopeId,
    pub credential: VaultCredentialId,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    #[default]
    Absent,
    Pending,
    Active,
    Revoked,
    ErasureFenced,
    Erased,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Candidate {
    AwaitingStore {
        deadline: u64,
    },
    Stored {
        reference: VaultBackingVersionId,
        deadline: u64,
    },
    Active {
        reference: VaultBackingVersionId,
    },
    Retired {
        reference: VaultBackingVersionId,
    },
    /// Includes an unknown write: the intake service must reconcile the
    /// candidate before reporting cleanup, never assume no Azure object exists.
    CleanupRequired {
        reference: Option<VaultBackingVersionId>,
    },
    Cleaned {
        evidence: ObservationId,
        /// Retained so cleanup and restore still know which exact object was used.
        reference: Option<VaultBackingVersionId>,
    },
}

impl Candidate {
    fn reference(&self) -> Option<&VaultBackingVersionId> {
        match self {
            Self::Stored { reference, .. }
            | Self::Active { reference }
            | Self::Retired { reference } => Some(reference),
            Self::CleanupRequired {
                reference: Some(reference),
            }
            | Self::Cleaned {
                reference: Some(reference),
                ..
            } => Some(reference),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UseMode {
    AuthenticateEffect,
    DeliverMaterial,
}

/// Secret-free identity of the exact final effect. The admitting shell checks
/// its canonical request, target, subject and operation against a current grant.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Effect {
    pub subject: VaultSubjectId,
    pub operation: VaultOperationId,
    pub target: VaultTargetId,
    pub mode: UseMode,
    pub request_evidence: ObservationId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchPhase {
    Dispatched,
    Unknown,
    Settled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    EffectObserved,
    NoEffectObserved,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DispatchRecord {
    pub effect: Effect,
    pub reference: VaultBackingVersionId,
    pub grant_evidence: ObservationId,
    pub fence_evidence: ObservationId,
    pub phase: DispatchPhase,
    pub outcome: Option<Outcome>,
    pub outcome_evidence: Option<ObservationId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct State {
    pub binding: Option<Binding>,
    pub revision: u64,
    pub last_at: u64,
    pub status: Status,
    /// The shell proves this opaque namespace belongs to the authenticated
    /// Personal or organization account; the prefix is not Azure isolation.
    pub tenant_prefix: Option<VaultTenantPrefixId>,
    /// Bound before `set` and retained through cleanup and recovery.
    pub candidate_storage_names: BTreeMap<VaultCandidateId, VaultStorageNameId>,
    pub candidates: BTreeMap<VaultCandidateId, Candidate>,
    /// Retained through cleanup so an ambiguous write always reconciles under
    /// the marker durably bound to its original candidate before the PUT.
    pub intake_markers: BTreeMap<VaultCandidateId, VaultIntakeMarkerId>,
    pub current: Option<VaultCandidateId>,
    /// Retained after cleanup so a provider version cannot be rebound to a
    /// different candidate through replay or a later intake.
    pub used_references: BTreeSet<VaultBackingVersionId>,
    /// Retained across rotation and closure. The hosted recovery fence must
    /// also preserve this history when an old product snapshot is restored.
    pub dispatches: BTreeMap<VaultDispatchId, DispatchRecord>,
}

/// Whitelisted metadata for a credential's Administration status. The caller
/// must first prove current access to the owner account; this projection does
/// not authorize an account read or a credential use. It deliberately omits
/// backing references, storage names, intake markers and effect evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct AdministrationStatus {
    pub status: Status,
    pub revision: u64,
    pub last_at: u64,
    pub pending_intakes: usize,
    pub cleanup_required: usize,
    pub unsettled_uses: usize,
    pub unknown_outcomes: usize,
}

impl State {
    /// Metadata standing only. A use also needs current grant, dispatch and
    /// recovery-fence checks at the final boundary.
    pub fn active_reference(&self) -> Option<&VaultBackingVersionId> {
        if self.status != Status::Active {
            return None;
        }
        match self.candidates.get(self.current.as_ref()?)? {
            Candidate::Active { reference } => Some(reference),
            _ => None,
        }
    }

    /// A secret-free status for an already-authorized Administration read.
    /// These counts describe this credential's ordered product state, not the
    /// health or freshness of Key Vault, grants or the independent fence.
    pub fn administration_status(&self) -> AdministrationStatus {
        AdministrationStatus {
            status: self.status,
            revision: self.revision,
            last_at: self.last_at,
            pending_intakes: self
                .candidates
                .values()
                .filter(|candidate| {
                    matches!(
                        candidate,
                        Candidate::AwaitingStore { .. } | Candidate::Stored { .. }
                    )
                })
                .count(),
            cleanup_required: self
                .candidates
                .values()
                .filter(|candidate| matches!(candidate, Candidate::CleanupRequired { .. }))
                .count(),
            unsettled_uses: self
                .dispatches
                .values()
                .filter(|dispatch| dispatch.phase != DispatchPhase::Settled)
                .count(),
            unknown_outcomes: self
                .dispatches
                .values()
                .filter(|dispatch| dispatch.phase == DispatchPhase::Unknown)
                .count(),
        }
    }
}

/// Supplied by an authenticating shell, never accepted from a browser field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Capability {
    Manage,
    IntakeReceipt,
    ConfirmCleanup,
    OwnerClosure,
    ObserveDeadline,
    /// Only the shell that rechecks grant, exact request and recovery fence.
    AdmitFinalUse,
    /// Only the custodian that authenticates final-use outcome observations.
    ConfirmFinalUse,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Command {
    pub binding: Binding,
    pub capability: Capability,
    pub expected_revision: u64,
    pub now: u64,
    pub operation: Operation,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Operation {
    Create {
        tenant_prefix: VaultTenantPrefixId,
    },
    BeginCandidate {
        id: VaultCandidateId,
        marker: VaultIntakeMarkerId,
        storage_name: VaultStorageNameId,
        deadline: u64,
    },
    RecordStored {
        id: VaultCandidateId,
        reference: VaultBackingVersionId,
    },
    Activate {
        id: VaultCandidateId,
    },
    CancelCandidate {
        id: VaultCandidateId,
    },
    ExpireCandidate {
        id: VaultCandidateId,
    },
    RecordCleaned {
        id: VaultCandidateId,
        evidence: ObservationId,
    },
    Revoke,
    FenceErasure,
    ConfirmErasure {
        evidence: ObservationId,
    },
    Dispatch {
        id: VaultDispatchId,
        effect: Effect,
        /// The version selected when the exact effect was admitted. A rotation
        /// between work admission and final dispatch must re-admit the request.
        expected_reference: VaultBackingVersionId,
        grant_evidence: ObservationId,
        fence_evidence: ObservationId,
    },
    OutcomeUnknown {
        id: VaultDispatchId,
        evidence: ObservationId,
    },
    SettleDispatch {
        id: VaultDispatchId,
        outcome: Outcome,
        evidence: ObservationId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Event {
    pub binding: Binding,
    pub at: u64,
    pub change: Change,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Change {
    Created {
        tenant_prefix: VaultTenantPrefixId,
    },
    CandidateBegun {
        id: VaultCandidateId,
        marker: VaultIntakeMarkerId,
        storage_name: VaultStorageNameId,
        deadline: u64,
    },
    CandidateStored {
        id: VaultCandidateId,
        reference: VaultBackingVersionId,
    },
    CandidateCleanupRequired {
        id: VaultCandidateId,
        reference: Option<VaultBackingVersionId>,
    },
    CandidateActivated {
        id: VaultCandidateId,
    },
    CandidateCleaned {
        id: VaultCandidateId,
        evidence: ObservationId,
    },
    Revoked,
    ErasureFenced,
    Erased {
        evidence: ObservationId,
    },
    Dispatched {
        id: VaultDispatchId,
        effect: Effect,
        reference: VaultBackingVersionId,
        grant_evidence: ObservationId,
        fence_evidence: ObservationId,
    },
    DispatchOutcomeUnknown {
        id: VaultDispatchId,
        evidence: ObservationId,
    },
    DispatchSettled {
        id: VaultDispatchId,
        outcome: Outcome,
        evidence: ObservationId,
    },
}

fn refuse(reason: &'static str) -> Result<Vec<Event>, Rejection> {
    Err(Rejection { reason })
}

fn canonical_intake_marker(marker: &VaultIntakeMarkerId) -> bool {
    let bytes = marker.as_str().as_bytes();
    bytes.len() == 32
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn canonical_hex_128(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn candidate_name_matches_prefix(name: &VaultStorageNameId, prefix: &VaultTenantPrefixId) -> bool {
    name.as_str()
        .strip_prefix("gv-")
        .and_then(|rest| rest.strip_prefix(prefix.as_str()))
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(canonical_hex_128)
}

pub fn decide(state: &State, command: Command) -> Result<Vec<Event>, Rejection> {
    if state.revision != command.expected_revision {
        return refuse("GaugeVault: stale revision");
    }
    if command.now == 0 || command.now < state.last_at {
        return refuse("GaugeVault: invalid or stale observation time");
    }
    if state
        .binding
        .as_ref()
        .is_some_and(|binding| binding != &command.binding)
    {
        return refuse("GaugeVault: wrong authority, owner or credential");
    }
    let change = match command.operation {
        Operation::Create { tenant_prefix }
            if command.capability == Capability::Manage
                && state.status == Status::Absent
                && canonical_hex_128(tenant_prefix.as_str()) =>
        {
            Change::Created { tenant_prefix }
        }
        Operation::BeginCandidate {
            id,
            marker,
            storage_name,
            deadline,
        } if command.capability == Capability::Manage
            && matches!(state.status, Status::Pending | Status::Active)
            && deadline > command.now
            && !state.candidates.contains_key(&id)
            && canonical_intake_marker(&marker)
            && !state.intake_markers.values().any(|used| used == &marker)
            && state
                .tenant_prefix
                .as_ref()
                .is_some_and(|prefix| candidate_name_matches_prefix(&storage_name, prefix))
            && !state
                .candidate_storage_names
                .values()
                .any(|used| used == &storage_name) =>
        {
            Change::CandidateBegun {
                id,
                marker,
                storage_name,
                deadline,
            }
        }
        Operation::RecordStored { id, reference }
            if command.capability == Capability::IntakeReceipt
                && matches!(
                    state.candidates.get(&id),
                    Some(
                        Candidate::AwaitingStore { .. }
                            | Candidate::CleanupRequired { reference: None }
                    )
                )
                && state.status != Status::Erased
                && !state.used_references.contains(&reference) =>
        {
            match state.candidates.get(&id) {
                Some(Candidate::AwaitingStore { deadline })
                    if command.now < *deadline
                        && matches!(state.status, Status::Pending | Status::Active) =>
                {
                    Change::CandidateStored { id, reference }
                }
                _ => Change::CandidateCleanupRequired {
                    id,
                    reference: Some(reference),
                },
            }
        }
        Operation::Activate { id }
            if command.capability == Capability::Manage
                && matches!(state.status, Status::Pending | Status::Active)
                && matches!(
                    state.candidates.get(&id),
                    Some(Candidate::Stored { deadline, .. }) if command.now < *deadline
                ) =>
        {
            Change::CandidateActivated { id }
        }
        Operation::CancelCandidate { id }
            if command.capability == Capability::Manage
                && matches!(
                    state.candidates.get(&id),
                    Some(Candidate::AwaitingStore { .. } | Candidate::Stored { .. })
                ) =>
        {
            Change::CandidateCleanupRequired {
                reference: state
                    .candidates
                    .get(&id)
                    .and_then(Candidate::reference)
                    .cloned(),
                id,
            }
        }
        Operation::ExpireCandidate { id }
            if command.capability == Capability::ObserveDeadline
                && matches!(
                    state.candidates.get(&id),
                    Some(Candidate::AwaitingStore { deadline } | Candidate::Stored { deadline, .. })
                        if command.now >= *deadline
                ) =>
        {
            Change::CandidateCleanupRequired {
                reference: state
                    .candidates
                    .get(&id)
                    .and_then(Candidate::reference)
                    .cloned(),
                id,
            }
        }
        Operation::RecordCleaned { id, evidence }
            if command.capability == Capability::ConfirmCleanup
                && matches!(
                    state.candidates.get(&id),
                    Some(Candidate::CleanupRequired { .. } | Candidate::Retired { .. })
                ) =>
        {
            Change::CandidateCleaned { id, evidence }
        }
        Operation::Revoke
            if command.capability == Capability::Manage
                && matches!(state.status, Status::Pending | Status::Active) =>
        {
            Change::Revoked
        }
        Operation::FenceErasure
            if matches!(
                command.capability,
                Capability::Manage | Capability::OwnerClosure
            ) && matches!(
                state.status,
                Status::Pending | Status::Active | Status::Revoked
            ) =>
        {
            Change::ErasureFenced
        }
        Operation::ConfirmErasure { evidence }
            if command.capability == Capability::ConfirmCleanup
                && state.status == Status::ErasureFenced
                && state
                    .candidates
                    .values()
                    .all(|candidate| matches!(candidate, Candidate::Cleaned { .. })) =>
        {
            Change::Erased { evidence }
        }
        Operation::Dispatch {
            id,
            effect,
            expected_reference,
            grant_evidence,
            fence_evidence,
        } if command.capability == Capability::AdmitFinalUse
            && state.status == Status::Active
            && !state.dispatches.contains_key(&id)
            && state.active_reference() == Some(&expected_reference) =>
        {
            Change::Dispatched {
                id,
                effect,
                reference: expected_reference,
                grant_evidence,
                fence_evidence,
            }
        }
        Operation::OutcomeUnknown { id, evidence }
            if command.capability == Capability::ConfirmFinalUse
                && matches!(
                    state.dispatches.get(&id),
                    Some(DispatchRecord {
                        phase: DispatchPhase::Dispatched,
                        ..
                    })
                ) =>
        {
            Change::DispatchOutcomeUnknown { id, evidence }
        }
        Operation::SettleDispatch {
            id,
            outcome,
            evidence,
        } if command.capability == Capability::ConfirmFinalUse
            && matches!(
                state.dispatches.get(&id),
                Some(DispatchRecord {
                    phase: DispatchPhase::Dispatched | DispatchPhase::Unknown,
                    ..
                })
            ) =>
        {
            Change::DispatchSettled {
                id,
                outcome,
                evidence,
            }
        }
        _ => return refuse("GaugeVault: operation lacks standing or capability"),
    };
    Ok(vec![Event {
        binding: command.binding,
        at: command.now,
        change,
    }])
}

pub fn evolve(state: &State, event: Event) -> State {
    let mut next = state.clone();
    if let Some(binding) = &next.binding {
        assert_eq!(
            binding, &event.binding,
            "GaugeVault event changed its owner"
        );
    }
    next.binding = Some(event.binding);
    next.revision += 1;
    next.last_at = event.at;
    match event.change {
        Change::Created { tenant_prefix } => {
            next.tenant_prefix = Some(tenant_prefix);
            next.status = Status::Pending;
        }
        Change::CandidateBegun {
            id,
            marker,
            storage_name,
            deadline,
        } => {
            next.intake_markers.insert(id.clone(), marker);
            next.candidate_storage_names
                .insert(id.clone(), storage_name);
            next.candidates
                .insert(id, Candidate::AwaitingStore { deadline });
        }
        Change::CandidateStored { id, reference } => {
            let deadline = match next.candidates.get(&id) {
                Some(Candidate::AwaitingStore { deadline }) => *deadline,
                _ => unreachable!("only admitted candidate events are folded"),
            };
            next.used_references.insert(reference.clone());
            next.candidates.insert(
                id,
                Candidate::Stored {
                    reference,
                    deadline,
                },
            );
        }
        Change::CandidateCleanupRequired { id, reference } => {
            if let Some(reference) = &reference {
                next.used_references.insert(reference.clone());
            }
            next.candidates
                .insert(id, Candidate::CleanupRequired { reference });
        }
        Change::CandidateActivated { id } => {
            if let Some(old) = next.current.take() {
                let reference = next.candidates[&old]
                    .reference()
                    .expect("active candidate has an exact reference")
                    .clone();
                next.candidates
                    .insert(old, Candidate::Retired { reference });
            }
            let reference = next.candidates[&id]
                .reference()
                .expect("stored candidate has an exact reference")
                .clone();
            next.candidates
                .insert(id.clone(), Candidate::Active { reference });
            next.current = Some(id);
            next.status = Status::Active;
        }
        Change::CandidateCleaned { id, evidence } => {
            let reference = next
                .candidates
                .get(&id)
                .and_then(Candidate::reference)
                .cloned();
            next.candidates.insert(
                id,
                Candidate::Cleaned {
                    evidence,
                    reference,
                },
            );
        }
        Change::Revoked => {
            next.status = Status::Revoked;
            if let Some(current) = next.current.take() {
                let reference = next.candidates[&current]
                    .reference()
                    .expect("active candidate has an exact reference")
                    .clone();
                next.candidates
                    .insert(current, Candidate::Retired { reference });
            }
        }
        Change::ErasureFenced => {
            next.status = Status::ErasureFenced;
            next.current = None;
            for candidate in next.candidates.values_mut() {
                if !matches!(candidate, Candidate::Cleaned { .. }) {
                    let reference = candidate.reference().cloned();
                    *candidate = Candidate::CleanupRequired { reference };
                }
            }
        }
        Change::Erased { .. } => next.status = Status::Erased,
        Change::Dispatched {
            id,
            effect,
            reference,
            grant_evidence,
            fence_evidence,
        } => {
            next.dispatches.insert(
                id,
                DispatchRecord {
                    effect,
                    reference,
                    grant_evidence,
                    fence_evidence,
                    phase: DispatchPhase::Dispatched,
                    outcome: None,
                    outcome_evidence: None,
                },
            );
        }
        Change::DispatchOutcomeUnknown { id, evidence } => {
            let dispatch = next.dispatches.get_mut(&id).expect("admitted dispatch");
            dispatch.phase = DispatchPhase::Unknown;
            dispatch.outcome_evidence = Some(evidence);
        }
        Change::DispatchSettled {
            id,
            outcome,
            evidence,
        } => {
            let dispatch = next.dispatches.get_mut(&id).expect("admitted dispatch");
            dispatch.phase = DispatchPhase::Settled;
            dispatch.outcome = Some(outcome);
            dispatch.outcome_evidence = Some(evidence);
        }
    }
    next
}

impl Lifecycle for State {
    type State = State;
    type Command = Command;
    type Event = Event;
    const KIND: &'static str = "gaugevault_credential";

    fn decide(state: &State, command: Command) -> Result<Vec<Event>, Rejection> {
        decide(state, command)
    }

    fn evolve(state: &State, event: Event) -> State {
        evolve(state, event)
    }

    /// Checkpointed (SCALE-1). Raise the version with any change to `evolve`
    /// or to the state's shape.
    fn snapshot_codec() -> Option<crate::SnapshotCodec<Self::State>> {
        Some(crate::SnapshotCodec::serde("gaugevault_credential", 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(number: u8) -> VaultIntakeMarkerId {
        VaultIntakeMarkerId::from(format!("{number:032x}"))
    }

    fn name(number: u8) -> VaultStorageNameId {
        VaultStorageNameId::from(format!("gv-{}-{number:032x}", "1".repeat(32)))
    }

    fn binding() -> Binding {
        Binding {
            authority: AuthorityId::from("hub"),
            owner_scope: ScopeId::from("scope:hub:owner"),
            credential_scope: ScopeId::from("scope:hub:owner:vault:credential-1"),
            credential: VaultCredentialId::from("credential-1"),
        }
    }

    fn apply(state: &mut State, capability: Capability, now: u64, operation: Operation) {
        let command = Command {
            binding: binding(),
            capability,
            expected_revision: state.revision,
            now,
            operation,
        };
        for event in decide(state, command).unwrap() {
            *state = evolve(state, event);
        }
    }

    fn active() -> State {
        let mut state = State::default();
        apply(
            &mut state,
            Capability::Manage,
            1,
            Operation::Create {
                tenant_prefix: VaultTenantPrefixId::from("1".repeat(32)),
            },
        );
        apply(
            &mut state,
            Capability::Manage,
            2,
            Operation::BeginCandidate {
                id: VaultCandidateId::from("candidate-1"),
                marker: marker(1),
                storage_name: name(1),
                deadline: 20,
            },
        );
        apply(
            &mut state,
            Capability::IntakeReceipt,
            3,
            Operation::RecordStored {
                id: VaultCandidateId::from("candidate-1"),
                reference: VaultBackingVersionId::from("exact-version-1"),
            },
        );
        apply(
            &mut state,
            Capability::Manage,
            4,
            Operation::Activate {
                id: VaultCandidateId::from("candidate-1"),
            },
        );
        state
    }

    #[test]
    fn administration_status_reports_obligations_without_exposing_custody_metadata() {
        let mut state = active();
        apply(
            &mut state,
            Capability::Manage,
            5,
            Operation::BeginCandidate {
                id: VaultCandidateId::from("pending-candidate"),
                marker: marker(2),
                storage_name: name(2),
                deadline: 20,
            },
        );
        apply(
            &mut state,
            Capability::Manage,
            6,
            Operation::BeginCandidate {
                id: VaultCandidateId::from("cleanup-candidate"),
                marker: marker(3),
                storage_name: name(3),
                deadline: 20,
            },
        );
        apply(
            &mut state,
            Capability::Manage,
            7,
            Operation::CancelCandidate {
                id: VaultCandidateId::from("cleanup-candidate"),
            },
        );
        apply(
            &mut state,
            Capability::AdmitFinalUse,
            8,
            dispatch("dispatch-1", UseMode::AuthenticateEffect, "exact-version-1"),
        );
        apply(
            &mut state,
            Capability::ConfirmFinalUse,
            9,
            Operation::OutcomeUnknown {
                id: VaultDispatchId::from("dispatch-1"),
                evidence: ObservationId::from("unknown-outcome-evidence"),
            },
        );

        let status = state.administration_status();
        assert_eq!(status.status, Status::Active);
        assert_eq!(status.revision, state.revision);
        assert_eq!(status.last_at, 9);
        assert_eq!(status.pending_intakes, 1);
        assert_eq!(status.cleanup_required, 1);
        assert_eq!(status.unsettled_uses, 1);
        assert_eq!(status.unknown_outcomes, 1);

        let mut encoded = Vec::new();
        ciborium::into_writer(&status, &mut encoded).unwrap();
        let value: ciborium::Value = ciborium::from_reader(encoded.as_slice()).unwrap();
        let ciborium::Value::Map(entries) = value else {
            panic!("administration status must serialize as a map");
        };
        let fields: BTreeSet<_> = entries
            .iter()
            .map(|(key, _)| key.as_text().unwrap())
            .collect();
        assert_eq!(
            fields,
            BTreeSet::from([
                "status",
                "revision",
                "last_at",
                "pending_intakes",
                "cleanup_required",
                "unsettled_uses",
                "unknown_outcomes",
            ])
        );
        for private in [
            binding().owner_scope.as_str(),
            "exact-version-1",
            name(1).as_str(),
            marker(1).as_str(),
            "request-1",
            "grant-1",
            "fence-1",
            "unknown-outcome-evidence",
        ] {
            assert!(
                !encoded
                    .windows(private.len())
                    .any(|window| window == private.as_bytes()),
                "projected {private}"
            );
        }

        apply(&mut state, Capability::Manage, 10, Operation::Revoke);
        apply(
            &mut state,
            Capability::ConfirmFinalUse,
            11,
            Operation::SettleDispatch {
                id: VaultDispatchId::from("dispatch-1"),
                outcome: Outcome::NoEffectObserved,
                evidence: ObservationId::from("settled-outcome-evidence"),
            },
        );
        let closed = state.administration_status();
        assert_eq!(closed.status, Status::Revoked);
        assert_eq!(closed.unsettled_uses, 0);
        assert_eq!(closed.unknown_outcomes, 0);
        assert_eq!(closed.cleanup_required, 1);
    }

    #[test]
    fn stored_candidate_is_not_active_and_rotation_selects_exact_version() {
        let mut state = active();
        assert_eq!(
            state.active_reference().unwrap().as_str(),
            "exact-version-1"
        );
        apply(
            &mut state,
            Capability::Manage,
            5,
            Operation::BeginCandidate {
                id: VaultCandidateId::from("candidate-2"),
                marker: marker(2),
                storage_name: name(2),
                deadline: 30,
            },
        );
        apply(
            &mut state,
            Capability::IntakeReceipt,
            6,
            Operation::RecordStored {
                id: VaultCandidateId::from("candidate-2"),
                reference: VaultBackingVersionId::from("exact-version-2"),
            },
        );
        assert_eq!(
            state.active_reference().unwrap().as_str(),
            "exact-version-1"
        );
        apply(
            &mut state,
            Capability::Manage,
            7,
            Operation::Activate {
                id: VaultCandidateId::from("candidate-2"),
            },
        );
        assert_eq!(
            state.active_reference().unwrap().as_str(),
            "exact-version-2"
        );
        assert_ne!(
            state.candidate_storage_names[&VaultCandidateId::from("candidate-1")],
            state.candidate_storage_names[&VaultCandidateId::from("candidate-2")]
        );
        assert!(matches!(
            state.candidates[&VaultCandidateId::from("candidate-1")],
            Candidate::Retired { .. }
        ));
    }

    #[test]
    fn intake_marker_survives_event_replay_and_candidate_cleanup() {
        let mut state = State::default();
        apply(
            &mut state,
            Capability::Manage,
            1,
            Operation::Create {
                tenant_prefix: VaultTenantPrefixId::from("1".repeat(32)),
            },
        );
        let event = decide(
            &state,
            Command {
                binding: binding(),
                capability: Capability::Manage,
                expected_revision: state.revision,
                now: 2,
                operation: Operation::BeginCandidate {
                    id: VaultCandidateId::from("candidate-1"),
                    marker: marker(1),
                    storage_name: name(1),
                    deadline: 20,
                },
            },
        )
        .unwrap()
        .remove(0);
        let mut serialized = Vec::new();
        ciborium::into_writer(&event, &mut serialized).unwrap();
        let replayed = ciborium::from_reader(serialized.as_slice()).unwrap();
        state = evolve(&state, replayed);
        assert_eq!(
            state.intake_markers[&VaultCandidateId::from("candidate-1")],
            marker(1)
        );
        assert_eq!(
            state.candidate_storage_names[&VaultCandidateId::from("candidate-1")],
            name(1)
        );
        apply(
            &mut state,
            Capability::Manage,
            3,
            Operation::CancelCandidate {
                id: VaultCandidateId::from("candidate-1"),
            },
        );
        apply(
            &mut state,
            Capability::ConfirmCleanup,
            4,
            Operation::RecordCleaned {
                id: VaultCandidateId::from("candidate-1"),
                evidence: ObservationId::from("no-backed-version"),
            },
        );
        assert_eq!(
            state.intake_markers[&VaultCandidateId::from("candidate-1")],
            marker(1)
        );
        assert_eq!(
            state.candidate_storage_names[&VaultCandidateId::from("candidate-1")],
            name(1)
        );
        for reused in [marker(1), VaultIntakeMarkerId::from("invalid-marker")] {
            assert!(decide(
                &state,
                Command {
                    binding: binding(),
                    capability: Capability::Manage,
                    expected_revision: state.revision,
                    now: 5,
                    operation: Operation::BeginCandidate {
                        id: VaultCandidateId::from("candidate-2"),
                        marker: reused,
                        storage_name: name(2),
                        deadline: 20,
                    },
                },
            )
            .is_err());
        }
        for invalid_name in [
            name(1),
            VaultStorageNameId::from(format!("gv-{}-{:032x}", "2".repeat(32), 2)),
        ] {
            assert!(decide(
                &state,
                Command {
                    binding: binding(),
                    capability: Capability::Manage,
                    expected_revision: state.revision,
                    now: 5,
                    operation: Operation::BeginCandidate {
                        id: VaultCandidateId::from("candidate-2"),
                        marker: marker(2),
                        storage_name: invalid_name,
                        deadline: 20,
                    },
                },
            )
            .is_err());
        }
    }

    #[test]
    fn revocation_and_erasure_are_terminal_for_resolution() {
        let mut state = active();
        let before_revoke = state.clone();
        apply(&mut state, Capability::Manage, 5, Operation::Revoke);
        assert!(state.active_reference().is_none());
        let stale = Command {
            binding: binding(),
            capability: Capability::Manage,
            expected_revision: before_revoke.revision,
            now: 6,
            operation: Operation::BeginCandidate {
                id: VaultCandidateId::from("candidate-2"),
                marker: marker(2),
                storage_name: name(2),
                deadline: 30,
            },
        };
        assert!(decide(&state, stale).is_err());
        apply(
            &mut state,
            Capability::OwnerClosure,
            7,
            Operation::FenceErasure,
        );
        assert!(state.active_reference().is_none());
        assert!(decide(
            &state,
            Command {
                binding: binding(),
                capability: Capability::ConfirmCleanup,
                expected_revision: state.revision,
                now: 8,
                operation: Operation::ConfirmErasure {
                    evidence: ObservationId::from("evidence")
                }
            }
        )
        .is_err());
    }

    #[test]
    fn late_write_requires_cleanup_and_never_activates() {
        let mut state = State::default();
        apply(
            &mut state,
            Capability::Manage,
            1,
            Operation::Create {
                tenant_prefix: VaultTenantPrefixId::from("1".repeat(32)),
            },
        );
        apply(
            &mut state,
            Capability::Manage,
            2,
            Operation::BeginCandidate {
                id: VaultCandidateId::from("candidate-1"),
                marker: marker(1),
                storage_name: name(1),
                deadline: 5,
            },
        );
        apply(
            &mut state,
            Capability::IntakeReceipt,
            6,
            Operation::RecordStored {
                id: VaultCandidateId::from("candidate-1"),
                reference: VaultBackingVersionId::from("late-version"),
            },
        );
        assert!(matches!(
            state.candidates[&VaultCandidateId::from("candidate-1")],
            Candidate::CleanupRequired { .. }
        ));
        assert!(state.active_reference().is_none());
        assert!(decide(
            &state,
            Command {
                binding: binding(),
                capability: Capability::Manage,
                expected_revision: state.revision,
                now: 7,
                operation: Operation::Activate {
                    id: VaultCandidateId::from("candidate-1")
                }
            }
        )
        .is_err());
    }

    #[test]
    fn canceled_intake_can_record_late_backing_version_for_cleanup() {
        let mut state = State::default();
        apply(
            &mut state,
            Capability::Manage,
            1,
            Operation::Create {
                tenant_prefix: VaultTenantPrefixId::from("1".repeat(32)),
            },
        );
        apply(
            &mut state,
            Capability::Manage,
            2,
            Operation::BeginCandidate {
                id: VaultCandidateId::from("candidate-1"),
                marker: marker(1),
                storage_name: name(1),
                deadline: 10,
            },
        );
        apply(
            &mut state,
            Capability::Manage,
            3,
            Operation::CancelCandidate {
                id: VaultCandidateId::from("candidate-1"),
            },
        );
        apply(
            &mut state,
            Capability::IntakeReceipt,
            4,
            Operation::RecordStored {
                id: VaultCandidateId::from("candidate-1"),
                reference: VaultBackingVersionId::from("late-version"),
            },
        );
        assert!(matches!(
            state.candidates[&VaultCandidateId::from("candidate-1")],
            Candidate::CleanupRequired { reference: Some(_) }
        ));
        assert!(state.active_reference().is_none());
    }

    #[test]
    fn wrong_scope_and_untrusted_cleanup_cannot_change_standing() {
        let mut state = active();
        assert!(decide(
            &state,
            Command {
                binding: binding(),
                capability: Capability::Manage,
                expected_revision: state.revision,
                now: 3,
                operation: Operation::Revoke,
            }
        )
        .is_err());
        let mut other = binding();
        other.owner_scope = ScopeId::from("scope:hub:other-owner");
        assert!(decide(
            &state,
            Command {
                binding: other,
                capability: Capability::Manage,
                expected_revision: state.revision,
                now: 5,
                operation: Operation::Revoke,
            }
        )
        .is_err());
        apply(
            &mut state,
            Capability::OwnerClosure,
            6,
            Operation::FenceErasure,
        );
        let candidate = VaultCandidateId::from("candidate-1");
        assert!(matches!(
            state.candidates[&candidate],
            Candidate::CleanupRequired { .. }
        ));
        assert!(decide(
            &state,
            Command {
                binding: binding(),
                capability: Capability::Manage,
                expected_revision: state.revision,
                now: 7,
                operation: Operation::RecordCleaned {
                    id: candidate.clone(),
                    evidence: ObservationId::from("cleanup-1"),
                },
            }
        )
        .is_err());
        apply(
            &mut state,
            Capability::ConfirmCleanup,
            8,
            Operation::RecordCleaned {
                id: candidate,
                evidence: ObservationId::from("cleanup-1"),
            },
        );
        apply(
            &mut state,
            Capability::ConfirmCleanup,
            9,
            Operation::ConfirmErasure {
                evidence: ObservationId::from("erasure-1"),
            },
        );
        assert_eq!(state.status, Status::Erased);
        assert!(state.active_reference().is_none());
    }

    #[test]
    fn cleaned_reference_cannot_be_rebound_to_another_candidate() {
        let mut state = active();
        apply(
            &mut state,
            Capability::Manage,
            5,
            Operation::BeginCandidate {
                id: VaultCandidateId::from("candidate-2"),
                marker: marker(2),
                storage_name: name(2),
                deadline: 10,
            },
        );
        apply(
            &mut state,
            Capability::IntakeReceipt,
            6,
            Operation::RecordStored {
                id: VaultCandidateId::from("candidate-2"),
                reference: VaultBackingVersionId::from("exact-version-2"),
            },
        );
        apply(
            &mut state,
            Capability::ObserveDeadline,
            10,
            Operation::ExpireCandidate {
                id: VaultCandidateId::from("candidate-2"),
            },
        );
        apply(
            &mut state,
            Capability::ConfirmCleanup,
            11,
            Operation::RecordCleaned {
                id: VaultCandidateId::from("candidate-2"),
                evidence: ObservationId::from("cleanup-2"),
            },
        );
        assert_eq!(
            state.candidates[&VaultCandidateId::from("candidate-2")]
                .reference()
                .unwrap()
                .as_str(),
            "exact-version-2"
        );
        apply(
            &mut state,
            Capability::Manage,
            12,
            Operation::BeginCandidate {
                id: VaultCandidateId::from("candidate-3"),
                marker: marker(3),
                storage_name: name(3),
                deadline: 20,
            },
        );
        assert!(decide(
            &state,
            Command {
                binding: binding(),
                capability: Capability::IntakeReceipt,
                expected_revision: state.revision,
                now: 13,
                operation: Operation::RecordStored {
                    id: VaultCandidateId::from("candidate-3"),
                    reference: VaultBackingVersionId::from("exact-version-2"),
                },
            }
        )
        .is_err());
    }

    fn effect(mode: UseMode) -> Effect {
        Effect {
            subject: VaultSubjectId::from("subject-1"),
            operation: VaultOperationId::from("operation-1"),
            target: VaultTargetId::from("target-1"),
            mode,
            request_evidence: ObservationId::from("request-1"),
        }
    }

    fn dispatch(id: &str, mode: UseMode, expected_reference: &str) -> Operation {
        Operation::Dispatch {
            id: VaultDispatchId::from(id),
            effect: effect(mode),
            expected_reference: VaultBackingVersionId::from(expected_reference),
            grant_evidence: ObservationId::from("grant-1"),
            fence_evidence: ObservationId::from("fence-1"),
        }
    }

    #[test]
    fn dispatch_is_single_use_and_binds_the_exact_active_version() {
        let mut state = active();
        let untrusted = Command {
            binding: binding(),
            capability: Capability::Manage,
            expected_revision: state.revision,
            now: 5,
            operation: dispatch("dispatch-1", UseMode::AuthenticateEffect, "exact-version-1"),
        };
        assert!(decide(&state, untrusted).is_err());
        apply(
            &mut state,
            Capability::AdmitFinalUse,
            5,
            dispatch("dispatch-1", UseMode::AuthenticateEffect, "exact-version-1"),
        );
        let recorded = &state.dispatches[&VaultDispatchId::from("dispatch-1")];
        assert_eq!(recorded.reference.as_str(), "exact-version-1");
        assert_eq!(recorded.phase, DispatchPhase::Dispatched);
        assert_eq!(recorded.effect.mode, UseMode::AuthenticateEffect);
        assert!(decide(
            &state,
            Command {
                binding: binding(),
                capability: Capability::AdmitFinalUse,
                expected_revision: state.revision,
                now: 6,
                operation: dispatch("dispatch-1", UseMode::DeliverMaterial, "exact-version-1"),
            }
        )
        .is_err());
    }

    #[test]
    fn rotation_and_revocation_order_dispatch_without_erasing_settlement() {
        let mut state = active();
        apply(
            &mut state,
            Capability::AdmitFinalUse,
            5,
            dispatch(
                "dispatch-old",
                UseMode::AuthenticateEffect,
                "exact-version-1",
            ),
        );
        apply(
            &mut state,
            Capability::Manage,
            6,
            Operation::BeginCandidate {
                id: VaultCandidateId::from("candidate-2"),
                marker: marker(2),
                storage_name: name(2),
                deadline: 20,
            },
        );
        apply(
            &mut state,
            Capability::IntakeReceipt,
            7,
            Operation::RecordStored {
                id: VaultCandidateId::from("candidate-2"),
                reference: VaultBackingVersionId::from("exact-version-2"),
            },
        );
        apply(
            &mut state,
            Capability::Manage,
            8,
            Operation::Activate {
                id: VaultCandidateId::from("candidate-2"),
            },
        );
        assert!(decide(
            &state,
            Command {
                binding: binding(),
                capability: Capability::AdmitFinalUse,
                expected_revision: state.revision,
                now: 9,
                operation: dispatch(
                    "dispatch-stale",
                    UseMode::AuthenticateEffect,
                    "exact-version-1",
                ),
            }
        )
        .is_err());
        apply(
            &mut state,
            Capability::AdmitFinalUse,
            9,
            dispatch("dispatch-new", UseMode::DeliverMaterial, "exact-version-2"),
        );
        assert_eq!(
            state.dispatches[&VaultDispatchId::from("dispatch-old")]
                .reference
                .as_str(),
            "exact-version-1"
        );
        assert_eq!(
            state.dispatches[&VaultDispatchId::from("dispatch-new")]
                .reference
                .as_str(),
            "exact-version-2"
        );
        apply(&mut state, Capability::Manage, 10, Operation::Revoke);
        assert!(decide(
            &state,
            Command {
                binding: binding(),
                capability: Capability::AdmitFinalUse,
                expected_revision: state.revision,
                now: 11,
                operation: dispatch(
                    "dispatch-late",
                    UseMode::AuthenticateEffect,
                    "exact-version-2",
                ),
            }
        )
        .is_err());
        apply(
            &mut state,
            Capability::ConfirmFinalUse,
            12,
            Operation::OutcomeUnknown {
                id: VaultDispatchId::from("dispatch-old"),
                evidence: ObservationId::from("unknown-1"),
            },
        );
        apply(
            &mut state,
            Capability::ConfirmFinalUse,
            13,
            Operation::SettleDispatch {
                id: VaultDispatchId::from("dispatch-old"),
                outcome: Outcome::EffectObserved,
                evidence: ObservationId::from("settlement-1"),
            },
        );
        assert_eq!(
            state.dispatches[&VaultDispatchId::from("dispatch-old")].phase,
            DispatchPhase::Settled
        );
        assert!(decide(
            &state,
            Command {
                binding: binding(),
                capability: Capability::ConfirmFinalUse,
                expected_revision: state.revision,
                now: 14,
                operation: Operation::SettleDispatch {
                    id: VaultDispatchId::from("dispatch-old"),
                    outcome: Outcome::NoEffectObserved,
                    evidence: ObservationId::from("settlement-2"),
                },
            }
        )
        .is_err());
    }

    #[test]
    fn serialized_state_preserves_terminal_fences_and_consumed_dispatches() {
        let mut state = active();
        apply(
            &mut state,
            Capability::AdmitFinalUse,
            5,
            dispatch("dispatch-1", UseMode::AuthenticateEffect, "exact-version-1"),
        );
        apply(&mut state, Capability::Manage, 6, Operation::Revoke);
        apply(&mut state, Capability::Manage, 7, Operation::FenceErasure);

        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&state, &mut encoded).unwrap();
        let restored: State = ciborium::de::from_reader(encoded.as_slice()).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.status, Status::ErasureFenced);
        assert!(restored
            .dispatches
            .contains_key(&VaultDispatchId::from("dispatch-1")));
        assert!(restored
            .used_references
            .contains(&VaultBackingVersionId::from("exact-version-1")));
    }
}
