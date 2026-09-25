//! Durable, secret-free beginning of GaugeVault intake (VAULT-2 / DR-0227).
//!
//! This is an internal admission seam, not an HTTP route. Its caller must
//! authenticate the manager, derive the binding and request key from the
//! selected owner, and provide the current authorization check. The candidate
//! and its random Azure metadata marker commit in one Store transaction before
//! any Key Vault `set`. A replay can only reconcile the original attempt; it
//! must never issue another `set` under the same marker.

use gaugedesk_core::gaugevault::{self, Binding, Capability, Command, Operation};
use gaugedesk_core::ids::{VaultCandidateId, VaultIntakeMarkerId, VaultSubjectId};
use gaugedesk_core::Rejection;
use gaugedesk_store::{AdmitError, Store};
use ring::rand::{SecureRandom, SystemRandom};

/// All fields are secret-free. `now` comes from the trusted clock; it is not
/// part of the stable caller intent, so an exact retry may arrive later.
pub struct BeginCandidateRequest {
    pub binding: Binding,
    pub actor: VaultSubjectId,
    pub candidate: VaultCandidateId,
    pub request_key: String,
    pub lifetime_secs: u64,
    pub now: u64,
}

/// Only `NewlyCommitted` may proceed to the *first* backing write. An unknown
/// outcome or a replay must query version metadata and settle that candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeginCandidateAdmission {
    NewlyCommitted { marker: VaultIntakeMarkerId },
    ReconcileOnly { marker: VaultIntakeMarkerId },
}

#[derive(serde::Serialize)]
struct StableIntent<'a> {
    v: u8,
    binding: &'a Binding,
    actor: &'a VaultSubjectId,
    candidate: &'a VaultCandidateId,
    lifetime_secs: u64,
}

/// Admit a candidate under the credential's exact Store scope. `authorize`
/// runs even on a receipt replay; the hosted shell must use it to check the
/// manager's *current* owner and grant standing. `max_lifetime_secs` is a
/// trusted deployment limit, not a browser field.
pub fn admit_candidate_begin(
    store: &mut Store,
    request: &BeginCandidateRequest,
    max_lifetime_secs: u64,
    authorize: impl FnOnce(&gaugevault::State) -> Result<(), Rejection>,
) -> Result<BeginCandidateAdmission, AdmitError> {
    if request.request_key.trim().is_empty()
        || request.actor.as_str().trim().is_empty()
        || request.candidate.as_str().trim().is_empty()
        || request.binding.credential_scope.as_str().trim().is_empty()
        || request.now == 0
    {
        return Err(AdmitError::Rejected(Rejection {
            reason: "GaugeVault: invalid intake begin request",
        }));
    }
    let intent = StableIntent {
        v: 1,
        binding: &request.binding,
        actor: &request.actor,
        candidate: &request.candidate,
        lifetime_secs: request.lifetime_secs,
    };
    let admission = store.admit_request::<gaugevault::State, _>(
        request.binding.credential_scope.as_str(),
        &request.request_key,
        &intent,
        |state| {
            if state.binding.as_ref() != Some(&request.binding) {
                return Err(Rejection {
                    reason: "GaugeVault: wrong credential binding",
                });
            }
            authorize(state)
        },
        |state| {
            if request.lifetime_secs == 0 || request.lifetime_secs > max_lifetime_secs {
                return Err(Rejection {
                    reason: "GaugeVault: invalid intake lifetime",
                });
            }
            let deadline = request
                .now
                .checked_add(request.lifetime_secs)
                .ok_or(Rejection {
                    reason: "GaugeVault: invalid intake deadline",
                })?;
            let mut bytes = [0u8; 16];
            SystemRandom::new()
                .fill(&mut bytes)
                .map_err(|_| Rejection {
                    reason: "GaugeVault: marker randomness unavailable",
                })?;
            Ok(Command {
                binding: request.binding.clone(),
                capability: Capability::Manage,
                expected_revision: state.revision,
                now: request.now,
                operation: Operation::BeginCandidate {
                    id: request.candidate.clone(),
                    marker: VaultIntakeMarkerId::from(hex::encode(bytes)),
                    deadline,
                },
            })
        },
    )?;
    let marker = admission
        .state
        .intake_markers
        .get(&request.candidate)
        .cloned()
        .ok_or_else(|| AdmitError::Codec("GaugeVault intake receipt has no marker".into()))?;
    Ok(if admission.replayed {
        BeginCandidateAdmission::ReconcileOnly { marker }
    } else {
        BeginCandidateAdmission::NewlyCommitted { marker }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::gaugevault::Status;
    use gaugedesk_core::ids::{AuthorityId, ScopeId, SecretHandleId, VaultCredentialId};

    fn binding() -> Binding {
        Binding {
            authority: AuthorityId::from("hosted-home"),
            owner_scope: ScopeId::from("owner:test"),
            credential_scope: ScopeId::from("owner:test:vault:one"),
            credential: VaultCredentialId::from("credential-one"),
        }
    }

    fn request(now: u64) -> BeginCandidateRequest {
        BeginCandidateRequest {
            binding: binding(),
            actor: VaultSubjectId::from("manager-one"),
            candidate: VaultCandidateId::from("candidate-one"),
            request_key: "request-one".into(),
            lifetime_secs: 300,
            now,
        }
    }

    #[test]
    fn committed_marker_survives_restart_and_retry_is_reconcile_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.db");
        let scope = binding().credential_scope.to_string();
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        store
            .admit::<gaugevault::State>(
                &scope,
                Command {
                    binding: binding(),
                    capability: Capability::Manage,
                    expected_revision: 0,
                    now: 1,
                    operation: Operation::Create {
                        storage_name: SecretHandleId::from("opaque-azure-name"),
                    },
                },
            )
            .unwrap();
        assert!(matches!(
            admit_candidate_begin(&mut store, &request(2), 600, |_| {
                Err(Rejection {
                    reason: "manager grant absent",
                })
            }),
            Err(AdmitError::Rejected(_))
        ));
        let denied_state = store.fold::<gaugevault::State>(&scope).unwrap();
        assert_eq!(denied_state.revision, 1);
        assert!(denied_state.intake_markers.is_empty());
        let first = admit_candidate_begin(&mut store, &request(2), 600, |_| Ok(())).unwrap();
        let BeginCandidateAdmission::NewlyCommitted { marker } = first else {
            panic!("first admit did not open one backing write");
        };
        assert_eq!(marker.as_str().len(), 32);
        assert!(marker.as_str().bytes().all(|byte| byte.is_ascii_hexdigit()));
        drop(store);

        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        // A later deployment may tighten the intake lifetime. The exact old
        // receipt still reconciles; the new limit applies only to new admits.
        let replay = admit_candidate_begin(&mut store, &request(20), 60, |_| Ok(())).unwrap();
        assert_eq!(
            replay,
            BeginCandidateAdmission::ReconcileOnly {
                marker: marker.clone()
            }
        );
        let state = store.fold::<gaugevault::State>(&scope).unwrap();
        assert_eq!(state.revision, 2);
        assert_eq!(state.status, Status::Pending);
        assert_eq!(
            state.intake_markers[&VaultCandidateId::from("candidate-one")],
            marker
        );

        let changed = BeginCandidateRequest {
            candidate: VaultCandidateId::from("candidate-two"),
            ..request(21)
        };
        assert!(matches!(
            admit_candidate_begin(&mut store, &changed, 600, |_| Ok(())),
            Err(AdmitError::Rejected(_))
        ));
        assert!(matches!(
            admit_candidate_begin(&mut store, &request(22), 600, |_| {
                Err(Rejection {
                    reason: "manager grant was revoked",
                })
            }),
            Err(AdmitError::Rejected(_))
        ));
    }
}
