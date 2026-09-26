//! Secret-free GaugeVault final-use admission (VAULT-2).
//!
//! This internal seam commits one dispatch before the trusted custodian may
//! perform an effect. A replay returns reconciliation-only standing and can
//! never authorize a second effect. The hosted shell still has to authenticate
//! the caller, check the exact grant and request, and consult an independently
//! surviving recovery fence on every attempt. This module is not a final-use
//! route or a recovery-fence implementation.

use std::cell::RefCell;

use gaugedesk_core::gaugevault::{
    self, Binding, Capability, Command, DispatchPhase, Effect, Operation, Status,
};
use gaugedesk_core::ids::{ObservationId, VaultBackingVersionId, VaultDispatchId};
use gaugedesk_core::Rejection;
use gaugedesk_store::{AdmitError, Store};

/// The shell derives these observations after checking the current grant and
/// independent recovery fence. They are audit evidence, never bearer grants.
pub struct DispatchEvidence {
    pub grant: ObservationId,
    pub fence: ObservationId,
}

/// Secret-free caller intent. `now` is a trusted observation time, excluded
/// from the stable idempotency identity so an exact retry can arrive later.
pub struct BeginDispatchRequest {
    pub binding: Binding,
    pub dispatch: VaultDispatchId,
    pub effect: Effect,
    pub expected_reference: VaultBackingVersionId,
    pub request_key: String,
    pub now: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispatchAdmission {
    /// Only this result may be delivered to the trusted custodian for one use.
    NewlyCommitted { reference: VaultBackingVersionId },
    /// A retry must reconcile the original outcome without another effect.
    ReconcileOnly {
        reference: VaultBackingVersionId,
        phase: DispatchPhase,
    },
}

#[derive(serde::Serialize)]
struct StableIntent<'a> {
    v: u8,
    binding: &'a Binding,
    dispatch: &'a VaultDispatchId,
    effect: &'a Effect,
    expected_reference: &'a VaultBackingVersionId,
}

/// Atomically order an exact final-use dispatch with rotation and revocation
/// in this credential's Store stream. `authorize` runs even on a receipt replay
/// and must validate fresh grant and recovery-fence evidence for the exact
/// effect. Both callbacks run in the Store transaction and must be pure: the
/// shell obtains external evidence before admission and performs no provider
/// effect from either callback. A hosted recovery-fence protocol is still
/// required before this can authorize production use.
pub fn admit_dispatch(
    store: &mut Store,
    request: &BeginDispatchRequest,
    authorize: impl FnOnce(&gaugevault::State) -> Result<DispatchEvidence, Rejection>,
) -> Result<DispatchAdmission, AdmitError> {
    if request.request_key.trim().is_empty()
        || request.binding.credential_scope.as_str().trim().is_empty()
        || request.dispatch.as_str().trim().is_empty()
        || request.effect.subject.as_str().trim().is_empty()
        || request.effect.operation.as_str().trim().is_empty()
        || request.effect.target.as_str().trim().is_empty()
        || request.effect.request_evidence.as_str().trim().is_empty()
        || request.expected_reference.as_str().trim().is_empty()
        || request.now == 0
    {
        return Err(AdmitError::Rejected(Rejection {
            reason: "GaugeVault: invalid final-use request",
        }));
    }
    let intent = StableIntent {
        v: 1,
        binding: &request.binding,
        dispatch: &request.dispatch,
        effect: &request.effect,
        expected_reference: &request.expected_reference,
    };
    let evidence = RefCell::new(None);
    let admission = store.admit_request::<gaugevault::State, _>(
        request.binding.credential_scope.as_str(),
        &request.request_key,
        &intent,
        |state| {
            if state.binding.as_ref() != Some(&request.binding)
                || state.status != Status::Active
                || state.active_reference() != Some(&request.expected_reference)
            {
                return Err(Rejection {
                    reason: "GaugeVault: final-use standing changed",
                });
            }
            let checked = authorize(state)?;
            if checked.grant.as_str().trim().is_empty() || checked.fence.as_str().trim().is_empty()
            {
                return Err(Rejection {
                    reason: "GaugeVault: missing final-use evidence",
                });
            }
            *evidence.borrow_mut() = Some(checked);
            Ok(())
        },
        |state| {
            let checked = evidence.borrow_mut().take().ok_or(Rejection {
                reason: "GaugeVault: final-use authorization missing",
            })?;
            Ok(Command {
                binding: request.binding.clone(),
                capability: Capability::AdmitFinalUse,
                expected_revision: state.revision,
                now: request.now,
                operation: Operation::Dispatch {
                    id: request.dispatch.clone(),
                    effect: request.effect.clone(),
                    expected_reference: request.expected_reference.clone(),
                    grant_evidence: checked.grant,
                    fence_evidence: checked.fence,
                },
            })
        },
    )?;
    let record = admission
        .state
        .dispatches
        .get(&request.dispatch)
        .ok_or_else(|| AdmitError::Codec("GaugeVault dispatch receipt has no record".into()))?;
    if record.reference != request.expected_reference || record.effect != request.effect {
        return Err(AdmitError::Codec(
            "GaugeVault dispatch receipt differs from request".into(),
        ));
    }
    Ok(if admission.replayed {
        DispatchAdmission::ReconcileOnly {
            reference: record.reference.clone(),
            phase: record.phase,
        }
    } else {
        DispatchAdmission::NewlyCommitted {
            reference: record.reference.clone(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::gaugevault::UseMode;
    use gaugedesk_core::ids::{
        AuthorityId, ScopeId, SecretHandleId, VaultCandidateId, VaultCredentialId,
        VaultIntakeMarkerId, VaultOperationId, VaultSubjectId, VaultTargetId,
    };

    fn binding() -> Binding {
        Binding {
            authority: AuthorityId::from("hosted-home"),
            owner_scope: ScopeId::from("owner:synthetic"),
            credential_scope: ScopeId::from("owner:synthetic:vault:one"),
            credential: VaultCredentialId::from("credential-one"),
        }
    }

    fn request(now: u64) -> BeginDispatchRequest {
        BeginDispatchRequest {
            binding: binding(),
            dispatch: VaultDispatchId::from("dispatch-one"),
            effect: Effect {
                subject: VaultSubjectId::from("worker-one"),
                operation: VaultOperationId::from("authenticate"),
                target: VaultTargetId::from("synthetic-target"),
                mode: UseMode::AuthenticateEffect,
                request_evidence: ObservationId::from("canonical-request-one"),
            },
            expected_reference: VaultBackingVersionId::from("exact-version-one"),
            request_key: "dispatch-request-one".into(),
            now,
        }
    }

    fn evidence() -> DispatchEvidence {
        DispatchEvidence {
            grant: ObservationId::from("current-grant-one"),
            fence: ObservationId::from("current-fence-one"),
        }
    }

    fn admit_operation(store: &mut Store, revision: u64, now: u64, operation: Operation) {
        store
            .admit::<gaugevault::State>(
                binding().credential_scope.as_str(),
                Command {
                    binding: binding(),
                    capability: match operation {
                        Operation::RecordStored { .. } => Capability::IntakeReceipt,
                        _ => Capability::Manage,
                    },
                    expected_revision: revision,
                    now,
                    operation,
                },
            )
            .unwrap();
    }

    fn active_store(path: &str) -> Store {
        let mut store = Store::open(path).unwrap();
        admit_operation(
            &mut store,
            0,
            1,
            Operation::Create {
                storage_name: SecretHandleId::from("opaque-storage-name"),
            },
        );
        admit_operation(
            &mut store,
            1,
            2,
            Operation::BeginCandidate {
                id: VaultCandidateId::from("candidate-one"),
                marker: VaultIntakeMarkerId::from("0123456789abcdef0123456789abcdef"),
                deadline: 100,
            },
        );
        admit_operation(
            &mut store,
            2,
            3,
            Operation::RecordStored {
                id: VaultCandidateId::from("candidate-one"),
                reference: VaultBackingVersionId::from("exact-version-one"),
            },
        );
        admit_operation(
            &mut store,
            3,
            4,
            Operation::Activate {
                id: VaultCandidateId::from("candidate-one"),
            },
        );
        store
    }

    #[test]
    fn one_dispatch_survives_restart_and_replay_cannot_authorize_another_effect() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.db");
        let scope = binding().credential_scope.to_string();
        let mut store = active_store(path.to_str().unwrap());
        let first = admit_dispatch(&mut store, &request(5), |_| Ok(evidence())).unwrap();
        assert_eq!(
            first,
            DispatchAdmission::NewlyCommitted {
                reference: VaultBackingVersionId::from("exact-version-one")
            }
        );
        drop(store);

        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        let replay = admit_dispatch(&mut store, &request(6), |_| Ok(evidence())).unwrap();
        assert_eq!(
            replay,
            DispatchAdmission::ReconcileOnly {
                reference: VaultBackingVersionId::from("exact-version-one"),
                phase: DispatchPhase::Dispatched,
            }
        );
        let state = store.fold::<gaugevault::State>(&scope).unwrap();
        assert_eq!(state.dispatches.len(), 1);
        assert_eq!(state.revision, 5);
        let record = &state.dispatches[&VaultDispatchId::from("dispatch-one")];
        assert_eq!(record.effect, request(7).effect);
        assert_eq!(record.grant_evidence.as_str(), "current-grant-one");
        assert_eq!(record.fence_evidence.as_str(), "current-fence-one");

        let changed = BeginDispatchRequest {
            effect: Effect {
                target: VaultTargetId::from("another-target"),
                ..request(8).effect
            },
            ..request(8)
        };
        assert!(matches!(
            admit_dispatch(&mut store, &changed, |_| Ok(evidence())),
            Err(AdmitError::Rejected(_))
        ));
        assert!(matches!(
            admit_dispatch(&mut store, &request(9), |_| {
                Err(Rejection {
                    reason: "grant withdrawn",
                })
            }),
            Err(AdmitError::Rejected(_))
        ));
        admit_operation(&mut store, 5, 10, Operation::Revoke);
        assert!(matches!(
            admit_dispatch(&mut store, &request(11), |_| Ok(evidence())),
            Err(AdmitError::Rejected(_))
        ));
        let state = store.fold::<gaugevault::State>(&scope).unwrap();
        assert_eq!(state.dispatches.len(), 1);
        assert_eq!(state.revision, 6);
        assert_eq!(state.status, Status::Revoked);
    }

    #[test]
    fn no_dispatch_before_activation_or_for_the_wrong_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.db");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        admit_operation(
            &mut store,
            0,
            1,
            Operation::Create {
                storage_name: SecretHandleId::from("opaque-storage-name"),
            },
        );
        assert!(matches!(
            admit_dispatch(&mut store, &request(2), |_| Ok(evidence())),
            Err(AdmitError::Rejected(_))
        ));
        assert!(store
            .fold::<gaugevault::State>(binding().credential_scope.as_str())
            .unwrap()
            .dispatches
            .is_empty());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("active-authority.db");
        let mut store = active_store(path.to_str().unwrap());
        let wrong = BeginDispatchRequest {
            expected_reference: VaultBackingVersionId::from("different-version"),
            ..request(5)
        };
        assert!(matches!(
            admit_dispatch(&mut store, &wrong, |_| Ok(evidence())),
            Err(AdmitError::Rejected(_))
        ));
        assert!(matches!(
            admit_dispatch(&mut store, &request(5), |_| {
                Ok(DispatchEvidence {
                    grant: ObservationId::from("current-grant-one"),
                    fence: ObservationId::from(""),
                })
            }),
            Err(AdmitError::Rejected(_))
        ));
        let state = store
            .fold::<gaugevault::State>(binding().credential_scope.as_str())
            .unwrap();
        assert!(state.dispatches.is_empty());
    }

    #[test]
    fn rotation_refuses_an_admitted_request_for_the_earlier_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.db");
        let mut store = active_store(path.to_str().unwrap());
        admit_operation(
            &mut store,
            4,
            5,
            Operation::BeginCandidate {
                id: VaultCandidateId::from("candidate-two"),
                marker: VaultIntakeMarkerId::from("fedcba9876543210fedcba9876543210"),
                deadline: 100,
            },
        );
        admit_operation(
            &mut store,
            5,
            6,
            Operation::RecordStored {
                id: VaultCandidateId::from("candidate-two"),
                reference: VaultBackingVersionId::from("exact-version-two"),
            },
        );
        admit_operation(
            &mut store,
            6,
            7,
            Operation::Activate {
                id: VaultCandidateId::from("candidate-two"),
            },
        );
        assert!(matches!(
            admit_dispatch(&mut store, &request(8), |_| Ok(evidence())),
            Err(AdmitError::Rejected(_))
        ));
        let current = BeginDispatchRequest {
            expected_reference: VaultBackingVersionId::from("exact-version-two"),
            ..request(9)
        };
        assert_eq!(
            admit_dispatch(&mut store, &current, |_| Ok(evidence())).unwrap(),
            DispatchAdmission::NewlyCommitted {
                reference: VaultBackingVersionId::from("exact-version-two"),
            }
        );
        let state = store
            .fold::<gaugevault::State>(binding().credential_scope.as_str())
            .unwrap();
        assert_eq!(state.dispatches.len(), 1);
        assert_eq!(state.revision, 8);
    }
}
