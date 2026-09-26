//! Durable, secret-free final-use outcome admission for GaugeVault (VAULT-2).
//!
//! A trusted custodian reports a definite or unknown result for one already
//! committed dispatch. A retry observes current standing without appending a
//! second outcome or authorizing another effect. The hosted protocol still
//! must authenticate the custodian and substantiate its outcome evidence.

use gaugedesk_core::gaugevault::{
    self, Binding, Capability, Command, DispatchPhase, DispatchRecord, Effect, Operation, Outcome,
};
use gaugedesk_core::ids::{ObservationId, VaultBackingVersionId, VaultDispatchId};
use gaugedesk_core::Rejection;
use gaugedesk_store::{AdmitError, Store};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum OutcomeObservation {
    Unknown,
    Definite(Outcome),
}

/// `now` is a trusted observation time and is excluded from the stable
/// idempotency identity. The effect and backing version bind this report to
/// the dispatch the custodian received, not a caller-supplied replacement.
pub struct DispatchOutcomeRequest {
    pub binding: Binding,
    pub dispatch: VaultDispatchId,
    pub effect: Effect,
    pub expected_reference: VaultBackingVersionId,
    pub observation: OutcomeObservation,
    pub evidence: ObservationId,
    pub request_key: String,
    pub now: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutcomeAdmission {
    pub phase: DispatchPhase,
    pub outcome: Option<Outcome>,
    pub replayed: bool,
}

#[derive(serde::Serialize)]
struct StableIntent<'a> {
    v: u8,
    binding: &'a Binding,
    dispatch: &'a VaultDispatchId,
    effect: &'a Effect,
    expected_reference: &'a VaultBackingVersionId,
    observation: OutcomeObservation,
    evidence: &'a ObservationId,
}

/// Order a custodian's outcome in the same credential stream as its dispatch.
/// `authenticate` must validate the caller and its evidence for this exact
/// record. It runs on exact replay too, even after rotation or revocation;
/// unlike a new use, settling an earlier dispatch requires no current grant.
/// The callback runs inside the Store transaction and must be pure.
pub fn admit_outcome(
    store: &mut Store,
    request: &DispatchOutcomeRequest,
    authenticate: impl FnOnce(&DispatchRecord) -> Result<(), Rejection>,
) -> Result<OutcomeAdmission, AdmitError> {
    if request.request_key.trim().is_empty()
        || request.binding.credential_scope.as_str().trim().is_empty()
        || request.dispatch.as_str().trim().is_empty()
        || request.expected_reference.as_str().trim().is_empty()
        || request.evidence.as_str().trim().is_empty()
        || request.now == 0
    {
        return Err(AdmitError::Rejected(Rejection {
            reason: "GaugeVault: invalid final-use outcome",
        }));
    }
    let intent = StableIntent {
        v: 1,
        binding: &request.binding,
        dispatch: &request.dispatch,
        effect: &request.effect,
        expected_reference: &request.expected_reference,
        observation: request.observation,
        evidence: &request.evidence,
    };
    let key = format!(
        "gaugevault:outcome:{}:{}",
        request.dispatch.as_str(),
        request.request_key
    );
    let admission = store.admit_request::<gaugevault::State, _>(
        request.binding.credential_scope.as_str(),
        &key,
        &intent,
        |state| {
            if state.binding.as_ref() != Some(&request.binding) {
                return Err(Rejection {
                    reason: "GaugeVault: wrong outcome binding",
                });
            }
            let Some(record) = state.dispatches.get(&request.dispatch) else {
                return Err(Rejection {
                    reason: "GaugeVault: dispatch missing for outcome",
                });
            };
            if record.effect != request.effect || record.reference != request.expected_reference {
                return Err(Rejection {
                    reason: "GaugeVault: outcome differs from dispatch",
                });
            }
            authenticate(record)
        },
        |state| {
            let operation = match request.observation {
                OutcomeObservation::Unknown => Operation::OutcomeUnknown {
                    id: request.dispatch.clone(),
                    evidence: request.evidence.clone(),
                },
                OutcomeObservation::Definite(outcome) => Operation::SettleDispatch {
                    id: request.dispatch.clone(),
                    outcome,
                    evidence: request.evidence.clone(),
                },
            };
            Ok(Command {
                binding: request.binding.clone(),
                capability: Capability::ConfirmFinalUse,
                expected_revision: state.revision,
                now: request.now,
                operation,
            })
        },
    )?;
    let record = admission
        .state
        .dispatches
        .get(&request.dispatch)
        .ok_or_else(|| AdmitError::Codec("GaugeVault outcome receipt has no dispatch".into()))?;
    Ok(OutcomeAdmission {
        phase: record.phase,
        outcome: record.outcome,
        replayed: admission.replayed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gaugevault_dispatch::{admit_dispatch, BeginDispatchRequest, DispatchEvidence};
    use gaugedesk_core::gaugevault::{Status, UseMode};
    use gaugedesk_core::ids::{
        AuthorityId, ScopeId, SecretHandleId, VaultCandidateId, VaultCredentialId,
        VaultIntakeMarkerId, VaultOperationId, VaultSubjectId, VaultTargetId,
    };

    fn binding() -> Binding {
        Binding {
            authority: AuthorityId::from("synthetic-home"),
            owner_scope: ScopeId::from("synthetic-owner"),
            credential_scope: ScopeId::from("synthetic-owner:vault:one"),
            credential: VaultCredentialId::from("credential-one"),
        }
    }

    fn effect() -> Effect {
        Effect {
            subject: VaultSubjectId::from("subject-one"),
            operation: VaultOperationId::from("authenticate-request"),
            target: VaultTargetId::from("target-one"),
            mode: UseMode::AuthenticateEffect,
            request_evidence: ObservationId::from("exact-request"),
        }
    }

    fn reference() -> VaultBackingVersionId {
        VaultBackingVersionId::from("exact-version-one")
    }

    fn request(observation: OutcomeObservation, key: &str, now: u64) -> DispatchOutcomeRequest {
        DispatchOutcomeRequest {
            binding: binding(),
            dispatch: VaultDispatchId::from("dispatch-one"),
            effect: effect(),
            expected_reference: reference(),
            observation,
            evidence: ObservationId::from(match observation {
                OutcomeObservation::Unknown => "custodian-outcome-unknown",
                OutcomeObservation::Definite(_) => "custodian-outcome-definite",
            }),
            request_key: key.into(),
            now,
        }
    }

    fn append(store: &mut Store, now: u64, capability: Capability, operation: Operation) {
        let scope = binding().credential_scope;
        let revision = store
            .fold::<gaugevault::State>(scope.as_str())
            .unwrap()
            .revision;
        store
            .admit::<gaugevault::State>(
                scope.as_str(),
                Command {
                    binding: binding(),
                    capability,
                    expected_revision: revision,
                    now,
                    operation,
                },
            )
            .unwrap();
    }

    fn active_store(path: &str) -> Store {
        let mut store = Store::open(path).unwrap();
        append(
            &mut store,
            1,
            Capability::Manage,
            Operation::Create {
                storage_name: SecretHandleId::from("opaque-storage-name"),
            },
        );
        append(
            &mut store,
            2,
            Capability::Manage,
            Operation::BeginCandidate {
                id: VaultCandidateId::from("candidate-one"),
                marker: VaultIntakeMarkerId::from("abcdef0123456789abcdef0123456789"),
                deadline: 100,
            },
        );
        append(
            &mut store,
            3,
            Capability::IntakeReceipt,
            Operation::RecordStored {
                id: VaultCandidateId::from("candidate-one"),
                reference: reference(),
            },
        );
        append(
            &mut store,
            4,
            Capability::Manage,
            Operation::Activate {
                id: VaultCandidateId::from("candidate-one"),
            },
        );
        let dispatched = admit_dispatch(
            &mut store,
            &BeginDispatchRequest {
                binding: binding(),
                dispatch: VaultDispatchId::from("dispatch-one"),
                effect: effect(),
                expected_reference: reference(),
                request_key: "dispatch-request-one".into(),
                now: 5,
            },
            |_| {
                Ok(DispatchEvidence {
                    grant: ObservationId::from("synthetic-current-grant"),
                    fence: ObservationId::from("synthetic-current-fence"),
                })
            },
        )
        .unwrap();
        assert!(matches!(
            dispatched,
            crate::gaugevault_dispatch::DispatchAdmission::NewlyCommitted { .. }
        ));
        store
    }

    #[test]
    fn unknown_then_definite_outcome_survives_revoke_restart_and_exact_retries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.db");
        let mut store = active_store(path.to_str().unwrap());
        append(&mut store, 6, Capability::Manage, Operation::Revoke);
        let first = admit_outcome(
            &mut store,
            &request(OutcomeObservation::Unknown, "unknown", 7),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(first.phase, DispatchPhase::Unknown);
        assert!(!first.replayed);
        drop(store);

        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        let retry = admit_outcome(
            &mut store,
            &request(OutcomeObservation::Unknown, "unknown", 8),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(retry.phase, DispatchPhase::Unknown);
        assert!(retry.replayed);
        let settled = admit_outcome(
            &mut store,
            &request(
                OutcomeObservation::Definite(Outcome::NoEffectObserved),
                "definite",
                9,
            ),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(settled.phase, DispatchPhase::Settled);
        assert_eq!(settled.outcome, Some(Outcome::NoEffectObserved));
        assert!(!settled.replayed);

        let old_retry = admit_outcome(
            &mut store,
            &request(OutcomeObservation::Unknown, "unknown", 10),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(old_retry.phase, DispatchPhase::Settled);
        assert!(old_retry.replayed);
        let exact_retry = admit_outcome(
            &mut store,
            &request(
                OutcomeObservation::Definite(Outcome::NoEffectObserved),
                "definite",
                11,
            ),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(
            exact_retry,
            OutcomeAdmission {
                replayed: true,
                ..settled
            }
        );
        assert!(matches!(
            admit_outcome(
                &mut store,
                &request(
                    OutcomeObservation::Definite(Outcome::EffectObserved),
                    "second-definite",
                    12,
                ),
                |_| Ok(()),
            ),
            Err(AdmitError::Rejected(_))
        ));
        let state = store
            .fold::<gaugevault::State>(binding().credential_scope.as_str())
            .unwrap();
        assert_eq!(state.status, Status::Revoked);
        assert_eq!(state.revision, 8);
        assert_eq!(state.dispatches.len(), 1);
        assert_eq!(
            state.dispatches[&VaultDispatchId::from("dispatch-one")].outcome,
            Some(Outcome::NoEffectObserved)
        );
    }

    #[test]
    fn wrong_dispatch_or_untrusted_custodian_cannot_record_an_outcome() {
        let mut store = active_store(":memory:");
        let mut wrong = request(OutcomeObservation::Unknown, "wrong", 6);
        wrong.expected_reference = VaultBackingVersionId::from("another-version");
        assert!(matches!(
            admit_outcome(&mut store, &wrong, |_| panic!(
                "must refuse before authentication"
            )),
            Err(AdmitError::Rejected(_))
        ));
        assert!(matches!(
            admit_outcome(
                &mut store,
                &request(OutcomeObservation::Unknown, "denied", 6),
                |_| {
                    Err(Rejection {
                        reason: "untrusted custodian",
                    })
                }
            ),
            Err(AdmitError::Rejected(_))
        ));
        assert!(matches!(
            admit_outcome(
                &mut store,
                &request(OutcomeObservation::Unknown, "denied", 7),
                |_| { Ok(()) }
            ),
            Ok(OutcomeAdmission {
                replayed: false,
                ..
            })
        ));
        assert!(matches!(
            admit_outcome(
                &mut store,
                &request(OutcomeObservation::Unknown, "denied", 8),
                |_| {
                    Err(Rejection {
                        reason: "untrusted custodian",
                    })
                }
            ),
            Err(AdmitError::Rejected(_))
        ));
        let mut changed = request(
            OutcomeObservation::Definite(Outcome::EffectObserved),
            "denied",
            9,
        );
        changed.evidence = ObservationId::from("different-evidence");
        assert!(matches!(
            admit_outcome(&mut store, &changed, |_| Ok(())),
            Err(AdmitError::Rejected(_))
        ));
        let state = store
            .fold::<gaugevault::State>(binding().credential_scope.as_str())
            .unwrap();
        assert_eq!(state.revision, 6);
        assert_eq!(
            state.dispatches[&VaultDispatchId::from("dispatch-one")].phase,
            DispatchPhase::Unknown
        );
    }
}
