//! GaugeVault credential standing (VAULT-2; GaugeWright DR-0150).
//!
//! This pure reducer orders candidates, activation, revocation and erasure for
//! one opaque owner scope. It holds exact backing references, never material.
//! The admitting shell authenticates capabilities and Key Vault observations.
//! Grants, single-use dispatch, independent recovery fences and provider I/O
//! remain separate required work: this state alone must never authorize use.

use std::collections::{BTreeMap, BTreeSet};

use crate::ids::{
    AuthorityId, ObservationId, ScopeId, SecretHandleId, VaultBackingVersionId, VaultCandidateId,
    VaultCredentialId,
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
            } => Some(reference),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub binding: Option<Binding>,
    pub revision: u64,
    pub last_at: u64,
    pub status: Status,
    pub storage_name: Option<SecretHandleId>,
    pub candidates: BTreeMap<VaultCandidateId, Candidate>,
    pub current: Option<VaultCandidateId>,
    /// Retained after cleanup so a provider version cannot be rebound to a
    /// different candidate through replay or a later intake.
    pub used_references: BTreeSet<VaultBackingVersionId>,
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
}

/// Supplied by an authenticating shell, never accepted from a browser field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    Manage,
    IntakeReceipt,
    ConfirmCleanup,
    OwnerClosure,
    ObserveDeadline,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    pub binding: Binding,
    pub capability: Capability,
    pub expected_revision: u64,
    pub now: u64,
    pub operation: Operation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    Create {
        storage_name: SecretHandleId,
    },
    BeginCandidate {
        id: VaultCandidateId,
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
        storage_name: SecretHandleId,
    },
    CandidateBegun {
        id: VaultCandidateId,
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
}

fn refuse(reason: &'static str) -> Result<Vec<Event>, Rejection> {
    Err(Rejection { reason })
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
        Operation::Create { storage_name }
            if command.capability == Capability::Manage && state.status == Status::Absent =>
        {
            Change::Created { storage_name }
        }
        Operation::BeginCandidate { id, deadline }
            if command.capability == Capability::Manage
                && matches!(state.status, Status::Pending | Status::Active)
                && deadline > command.now
                && !state.candidates.contains_key(&id) =>
        {
            Change::CandidateBegun { id, deadline }
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
        Change::Created { storage_name } => {
            next.storage_name = Some(storage_name);
            next.status = Status::Pending;
        }
        Change::CandidateBegun { id, deadline } => {
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
            next.candidates.insert(id, Candidate::Cleaned { evidence });
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
                storage_name: SecretHandleId::from("opaque-name"),
            },
        );
        apply(
            &mut state,
            Capability::Manage,
            2,
            Operation::BeginCandidate {
                id: VaultCandidateId::from("candidate-1"),
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
        assert!(matches!(
            state.candidates[&VaultCandidateId::from("candidate-1")],
            Candidate::Retired { .. }
        ));
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
                storage_name: SecretHandleId::from("opaque-name"),
            },
        );
        apply(
            &mut state,
            Capability::Manage,
            2,
            Operation::BeginCandidate {
                id: VaultCandidateId::from("candidate-1"),
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
                storage_name: SecretHandleId::from("opaque-name"),
            },
        );
        apply(
            &mut state,
            Capability::Manage,
            2,
            Operation::BeginCandidate {
                id: VaultCandidateId::from("candidate-1"),
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
        apply(
            &mut state,
            Capability::Manage,
            12,
            Operation::BeginCandidate {
                id: VaultCandidateId::from("candidate-3"),
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
}
