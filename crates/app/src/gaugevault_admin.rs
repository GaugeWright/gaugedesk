//! Secret-free GaugeVault credential administration (VAULT-2).
//!
//! An internal seam for the selected account's Administration: list, inspect,
//! revoke and request erasure of credentials by their opaque reference. It is
//! not an HTTP route. Every call resolves the owner from the authenticated
//! person and the tenant they selected, never from a caller-supplied binding,
//! so a reference copied from another account answers exactly as an absent one
//! and confers no read or management (`INV-10`). Responses carry only the
//! reducer's whitelisted [`AdministrationStatus`]: no storage name, tenant
//! prefix, intake marker, backing version reference or effect evidence, and no
//! material exists anywhere in this path to leak.
//!
//! Grant shapes for who may administer an account's credentials are not yet
//! settled by the lifecycle, so the hosted shell supplies them through the
//! `authorize` callbacks; current account standing is checked here regardless.

use std::num::NonZeroUsize;

use gaugedesk_core::gaugevault::{self, AdministrationStatus, Capability, Command, Operation};
use gaugedesk_core::ids::{ScopeId, VaultCredentialId, VaultSubjectId};
use gaugedesk_core::{Lifecycle, Rejection};
use gaugedesk_store::{AdmitError, Store};

use crate::gaugevault_namespace::selected_owner_scope;

const DISCOVERY_PAGE: NonZeroUsize = match NonZeroUsize::new(64) {
    Some(page) => page,
    None => unreachable!(),
};

/// The signed-in person and the tenant they selected. Both come from the
/// authenticated session; neither is a browser-chosen owner scope.
#[derive(Clone, Copy, Debug)]
pub struct Caller<'a> {
    pub authenticated_person: &'a str,
    pub selected_tenant_id: &'a str,
}

/// One credential as Administration may show it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct CredentialAdministration {
    pub credential: VaultCredentialId,
    #[serde(flatten)]
    pub status: AdministrationStatus,
}

fn absent() -> AdmitError {
    AdmitError::Rejected(Rejection {
        reason: "GaugeVault: no such credential for the selected account",
    })
}

fn summary(state: &gaugevault::State) -> Option<CredentialAdministration> {
    Some(CredentialAdministration {
        credential: state.binding.as_ref()?.credential.clone(),
        status: state.administration_status(),
    })
}

/// Every credential stream bound to exactly `owner`. Discovery is by the
/// owner's scope prefix, but membership is decided by the folded binding, so a
/// stream whose name merely begins like this owner's is never claimed.
fn owned_credentials(
    store: &Store,
    owner: &ScopeId,
) -> Result<Vec<(String, gaugevault::State)>, AdmitError> {
    let prefix = format!("{}:", owner.as_str());
    let mut after = prefix.clone();
    let mut owned = Vec::new();
    loop {
        let page = store.scope_ids_with_kind(
            <gaugevault::State as Lifecycle>::KIND,
            Some(&after),
            DISCOVERY_PAGE,
        )?;
        let full = page.len() == DISCOVERY_PAGE.get();
        for scope in page {
            if !scope.starts_with(&prefix) {
                return Ok(owned);
            }
            let state = store.fold::<gaugevault::State>(&scope)?;
            if state.binding.as_ref().is_some_and(|binding| {
                &binding.owner_scope == owner && binding.credential_scope.as_str() == scope
            }) {
                owned.push((scope.clone(), state));
            }
            after = scope;
        }
        if !full {
            return Ok(owned);
        }
    }
}

/// The one stream under `owner` that holds `credential`. An ambiguous
/// reference refuses rather than choosing between two streams.
fn resolve(
    store: &Store,
    owner: &ScopeId,
    credential: &VaultCredentialId,
) -> Result<(String, gaugevault::State), AdmitError> {
    if credential.as_str().trim().is_empty() {
        return Err(absent());
    }
    let mut matches = owned_credentials(store, owner)?
        .into_iter()
        .filter(|(_, state)| {
            state
                .binding
                .as_ref()
                .is_some_and(|binding| &binding.credential == credential)
        });
    let found = matches.next().ok_or_else(absent)?;
    if matches.next().is_some() {
        return Err(AdmitError::Rejected(Rejection {
            reason: "GaugeVault: credential reference is ambiguous",
        }));
    }
    Ok(found)
}

/// List the selected account's credentials. `authorize` checks the caller's
/// Administration read grant for that owner.
pub fn list_credentials(
    store: &Store,
    caller: Caller<'_>,
    authorize: impl FnOnce(&ScopeId) -> Result<(), Rejection>,
) -> Result<Vec<CredentialAdministration>, AdmitError> {
    let owner = selected_owner_scope(
        store,
        caller.authenticated_person,
        caller.selected_tenant_id,
    )?;
    authorize(&owner).map_err(AdmitError::Rejected)?;
    Ok(owned_credentials(store, &owner)?
        .iter()
        .filter_map(|(_, state)| summary(state))
        .collect())
}

/// Inspect one credential of the selected account by its opaque reference.
pub fn inspect_credential(
    store: &Store,
    caller: Caller<'_>,
    credential: &VaultCredentialId,
    authorize: impl FnOnce(&ScopeId) -> Result<(), Rejection>,
) -> Result<CredentialAdministration, AdmitError> {
    let owner = selected_owner_scope(
        store,
        caller.authenticated_person,
        caller.selected_tenant_id,
    )?;
    authorize(&owner).map_err(AdmitError::Rejected)?;
    let (_, state) = resolve(store, &owner, credential)?;
    summary(&state).ok_or_else(absent)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Terminal: stops new use whatever the backing store later shows.
    Revoke,
    /// Fences future resolution and opens backing cleanup. It does not claim
    /// physical destruction; the trusted cleanup path confirms erasure.
    RequestErasure,
}

/// `now` comes from the trusted clock and is excluded from the retry identity.
pub struct ActionRequest<'a> {
    pub caller: Caller<'a>,
    pub credential: VaultCredentialId,
    pub actor: VaultSubjectId,
    pub action: Action,
    pub request_key: String,
    pub now: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ActionOutcome {
    #[serde(flatten)]
    pub credential: CredentialAdministration,
    /// The request key was already committed; nothing new was admitted.
    pub replayed: bool,
}

#[derive(serde::Serialize)]
struct StableIntent<'a> {
    v: u8,
    owner_scope: &'a ScopeId,
    credential: &'a VaultCredentialId,
    actor: &'a VaultSubjectId,
    action: Action,
}

/// Admit a revocation or erasure request in the credential's own ordered
/// stream. `authorize` runs inside the Store transaction, on the first call
/// and on every receipt replay, and must check the actor's current management
/// grant for this credential.
pub fn admit_action(
    store: &mut Store,
    request: &ActionRequest<'_>,
    authorize: impl FnOnce(&gaugevault::State) -> Result<(), Rejection>,
) -> Result<ActionOutcome, AdmitError> {
    if request.request_key.trim().is_empty()
        || request.actor.as_str().trim().is_empty()
        || request.now == 0
    {
        return Err(AdmitError::Rejected(Rejection {
            reason: "GaugeVault: invalid administration request",
        }));
    }
    let owner = selected_owner_scope(
        store,
        request.caller.authenticated_person,
        request.caller.selected_tenant_id,
    )?;
    let (scope, resolved) = resolve(store, &owner, &request.credential)?;
    let binding = resolved.binding.clone().ok_or_else(absent)?;
    let intent = StableIntent {
        v: 1,
        owner_scope: &owner,
        credential: &request.credential,
        actor: &request.actor,
        action: request.action,
    };
    let admission = store.admit_request::<gaugevault::State, _>(
        &scope,
        &request.request_key,
        &intent,
        |state| {
            if state.binding.as_ref() != Some(&binding) {
                return Err(Rejection {
                    reason: "GaugeVault: wrong credential binding",
                });
            }
            authorize(state)
        },
        |state| {
            Ok(Command {
                binding: binding.clone(),
                capability: Capability::Manage,
                expected_revision: state.revision,
                now: request.now,
                operation: match request.action {
                    Action::Revoke => Operation::Revoke,
                    Action::RequestErasure => Operation::FenceErasure,
                },
            })
        },
    )?;
    Ok(ActionOutcome {
        credential: summary(&admission.state).ok_or_else(absent)?,
        replayed: admission.replayed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::gaugevault::{Binding, Status};
    use gaugedesk_core::ids::{
        AuthorityId, VaultBackingVersionId, VaultCandidateId, VaultTenantPrefixId,
    };

    use crate::account::account_scope;
    use crate::gaugevault_intake::{admit_candidate_begin, BeginCandidateRequest};
    use crate::gaugevault_namespace::{
        admit_credential_create, provision_namespace, CreateCredentialRequest,
    };
    use crate::org::{MembershipStatus, Org};
    use crate::tenancy::{provision_organization, provision_personal_tenant};

    const ALICE: &str = "person:alice";
    const BOB: &str = "person:bob";

    fn binding(owner: &ScopeId, credential: &str) -> Binding {
        Binding {
            authority: AuthorityId::from("hosted-home"),
            owner_scope: owner.clone(),
            credential_scope: ScopeId::from(format!("{}:vault:{credential}", owner.as_str())),
            credential: VaultCredentialId::from(credential),
        }
    }

    fn create(store: &mut Store, owner: &ScopeId, credential: &str) -> Binding {
        let binding = binding(owner, credential);
        admit_credential_create(
            store,
            &CreateCredentialRequest {
                selected_owner_scope: owner.clone(),
                binding: binding.clone(),
                actor: VaultSubjectId::from("manager"),
                request_key: format!("create:{credential}"),
                now: 1,
            },
            |_| Ok(()),
        )
        .unwrap();
        binding
    }

    /// Alice's Personal tenant holding one active and one pending credential,
    /// and Bob's Personal tenant holding one of his own.
    struct World {
        alice_tenant: String,
        bob_tenant: String,
        alice_owner: ScopeId,
        active: Binding,
        secrets: Vec<String>,
    }

    fn world() -> (Store, World) {
        let mut store = Store::open(":memory:").unwrap();
        let alice_tenant = provision_personal_tenant(&mut store, ALICE, "Alice").unwrap();
        let bob_tenant = provision_personal_tenant(&mut store, BOB, "Bob").unwrap();
        let alice_owner = selected_owner_scope(&store, ALICE, &alice_tenant).unwrap();
        let bob_owner = selected_owner_scope(&store, BOB, &bob_tenant).unwrap();
        let alice_prefix = provision_namespace(&mut store, &alice_owner, |_| Ok(())).unwrap();
        provision_namespace(&mut store, &bob_owner, |_| Ok(())).unwrap();
        let active = create(&mut store, &alice_owner, "deploy-key");
        create(&mut store, &alice_owner, "pending-key");
        create(&mut store, &bob_owner, "bob-key");

        let begun = admit_candidate_begin(
            &mut store,
            &BeginCandidateRequest {
                binding: active.clone(),
                actor: VaultSubjectId::from("manager"),
                candidate: VaultCandidateId::from("candidate-one"),
                request_key: "begin-one".into(),
                lifetime_secs: 300,
                now: 2,
            },
            600,
            |_| Ok(()),
        )
        .unwrap();
        let (marker, storage_name) = match begun {
            crate::gaugevault_intake::BeginCandidateAdmission::NewlyCommitted {
                marker,
                storage_name,
            } => (marker, storage_name),
            other => panic!("unexpected {other:?}"),
        };
        let reference = VaultBackingVersionId::from(format!(
            "https://vault.example/secrets/{}/0123456789abcdef",
            storage_name.as_str()
        ));
        let scope = active.credential_scope.as_str();
        for (capability, operation) in [
            (
                Capability::IntakeReceipt,
                Operation::RecordStored {
                    id: VaultCandidateId::from("candidate-one"),
                    reference: reference.clone(),
                },
            ),
            (
                Capability::Manage,
                Operation::Activate {
                    id: VaultCandidateId::from("candidate-one"),
                },
            ),
        ] {
            let revision = store.fold::<gaugevault::State>(scope).unwrap().revision;
            store
                .admit::<gaugevault::State>(
                    scope,
                    Command {
                        binding: active.clone(),
                        capability,
                        expected_revision: revision,
                        now: 3,
                        operation,
                    },
                )
                .unwrap();
        }
        let secrets = vec![
            alice_prefix.as_str().to_owned(),
            marker.as_str().to_owned(),
            storage_name.as_str().to_owned(),
            reference.as_str().to_owned(),
            active.credential_scope.as_str().to_owned(),
            active.authority.as_str().to_owned(),
        ];
        (
            store,
            World {
                alice_tenant,
                bob_tenant,
                alice_owner,
                active,
                secrets,
            },
        )
    }

    fn alice(world: &World) -> Caller<'_> {
        Caller {
            authenticated_person: ALICE,
            selected_tenant_id: &world.alice_tenant,
        }
    }

    fn bob(world: &World) -> Caller<'_> {
        Caller {
            authenticated_person: BOB,
            selected_tenant_id: &world.bob_tenant,
        }
    }

    fn reason(error: AdmitError) -> &'static str {
        match error {
            AdmitError::Rejected(rejection) => rejection.reason,
            other => panic!("unexpected {other:?}"),
        }
    }

    fn assert_secret_free(world: &World, value: &impl serde::Serialize) {
        let json = serde_json::to_string(value).unwrap();
        for secret in &world.secrets {
            assert!(!json.contains(secret.as_str()), "{json} leaked {secret}");
        }
        for key in [
            "reference",
            "storage",
            "marker",
            "prefix",
            "evidence",
            "binding",
        ] {
            assert!(!json.contains(key), "{json} carries {key}");
        }
    }

    fn request<'a>(
        caller: Caller<'a>,
        credential: &str,
        action: Action,
        key: &str,
    ) -> ActionRequest<'a> {
        ActionRequest {
            caller,
            credential: VaultCredentialId::from(credential),
            actor: VaultSubjectId::from("manager"),
            action,
            request_key: key.into(),
            now: 10,
        }
    }

    #[test]
    fn lists_and_inspects_only_the_selected_account_without_backing_detail() {
        let (store, world) = world();
        let listed = list_credentials(&store, alice(&world), |_| Ok(())).unwrap();
        let names: Vec<_> = listed.iter().map(|c| c.credential.as_str()).collect();
        assert_eq!(names, ["deploy-key", "pending-key"]);
        assert_eq!(listed[0].status.status, Status::Active);
        assert_eq!(listed[1].status.status, Status::Pending);
        assert_secret_free(&world, &listed);

        let inspected = inspect_credential(
            &store,
            alice(&world),
            &VaultCredentialId::from("deploy-key"),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(inspected, listed[0]);
        assert_secret_free(&world, &inspected);

        let bobs = list_credentials(&store, bob(&world), |_| Ok(())).unwrap();
        assert_eq!(bobs.len(), 1);
        assert_eq!(bobs[0].credential.as_str(), "bob-key");

        assert!(matches!(
            list_credentials(&store, alice(&world), |_| Err(Rejection {
                reason: "no administration grant",
            })),
            Err(AdmitError::Rejected(_))
        ));
    }

    #[test]
    fn a_copied_or_cross_account_reference_answers_as_absent_and_changes_nothing() {
        let (mut store, world) = world();
        let before = store
            .fold::<gaugevault::State>(world.active.credential_scope.as_str())
            .unwrap();
        let missing = inspect_credential(
            &store,
            bob(&world),
            &VaultCredentialId::from("no-such-key"),
            |_| Ok(()),
        )
        .map(drop)
        .map_err(reason);
        let copied = inspect_credential(
            &store,
            bob(&world),
            &VaultCredentialId::from("deploy-key"),
            |_| Ok(()),
        )
        .map(drop)
        .map_err(reason);
        // No oracle: another account's credential reads exactly as absent.
        assert_eq!(missing, copied);

        let bob_caller = bob(&world);
        for action in [Action::Revoke, Action::RequestErasure] {
            let error = admit_action(
                &mut store,
                &request(bob_caller, "deploy-key", action, "copied"),
                |_| Ok(()),
            )
            .map(drop)
            .map_err(reason);
            assert_eq!(error, missing);
        }

        // Bob naming Alice's tenant is not standing in it.
        let impersonating = Caller {
            authenticated_person: BOB,
            selected_tenant_id: &world.alice_tenant.clone(),
        };
        assert!(matches!(
            admit_action(
                &mut store,
                &request(impersonating, "deploy-key", Action::Revoke, "impersonate"),
                |_| Ok(()),
            ),
            Err(AdmitError::Rejected(_))
        ));
        assert!(matches!(
            list_credentials(&store, impersonating, |_| Ok(())),
            Err(AdmitError::Rejected(_))
        ));

        let after = store
            .fold::<gaugevault::State>(world.active.credential_scope.as_str())
            .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn a_stream_that_only_looks_like_the_owners_is_not_listed() {
        let (mut store, world) = world();
        // A foreign owner's credential written under a scope name that begins
        // with Alice's owner scope must not be claimed by Alice.
        let foreign_owner = ScopeId::from("org::someone-else");
        let planted_scope = format!("{}:vault:planted", world.alice_owner.as_str());
        let foreign = Binding {
            credential_scope: ScopeId::from(planted_scope.as_str()),
            ..binding(&foreign_owner, "planted")
        };
        store
            .admit::<gaugevault::State>(
                &planted_scope,
                Command {
                    binding: foreign,
                    capability: Capability::Manage,
                    expected_revision: 0,
                    now: 1,
                    operation: Operation::Create {
                        tenant_prefix: VaultTenantPrefixId::from("2".repeat(32)),
                    },
                },
            )
            .unwrap();
        let listed = list_credentials(&store, alice(&world), |_| Ok(())).unwrap();
        assert!(listed.iter().all(|c| c.credential.as_str() != "planted"));
        assert!(inspect_credential(
            &store,
            alice(&world),
            &VaultCredentialId::from("planted"),
            |_| Ok(()),
        )
        .is_err());
    }

    #[test]
    fn revocation_and_erasure_are_ordered_replayable_and_rechecked() {
        let (mut store, world) = world();
        let caller = alice(&world);
        assert!(matches!(
            admit_action(
                &mut store,
                &request(caller, "deploy-key", Action::Revoke, "revoke-one"),
                |_| Err(Rejection {
                    reason: "no management grant",
                }),
            ),
            Err(AdmitError::Rejected(_))
        ));
        let revoked = admit_action(
            &mut store,
            &request(caller, "deploy-key", Action::Revoke, "revoke-one"),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(revoked.credential.status.status, Status::Revoked);
        assert!(!revoked.replayed);
        assert_secret_free(&world, &revoked);
        let state = store
            .fold::<gaugevault::State>(world.active.credential_scope.as_str())
            .unwrap();
        assert!(state.active_reference().is_none());

        let replay = admit_action(
            &mut store,
            &request(caller, "deploy-key", Action::Revoke, "revoke-one"),
            |_| Ok(()),
        )
        .unwrap();
        assert!(replay.replayed);
        assert_eq!(
            replay.credential.status.revision,
            revoked.credential.status.revision
        );
        // A replay still rechecks the caller's current grant.
        assert!(matches!(
            admit_action(
                &mut store,
                &request(caller, "deploy-key", Action::Revoke, "revoke-one"),
                |_| Err(Rejection {
                    reason: "grant removed",
                }),
            ),
            Err(AdmitError::Rejected(_))
        ));
        // Revocation is terminal: a fresh revoke has no standing.
        assert!(matches!(
            admit_action(
                &mut store,
                &request(caller, "deploy-key", Action::Revoke, "revoke-two"),
                |_| Ok(()),
            ),
            Err(AdmitError::Rejected(_))
        ));

        let erased = admit_action(
            &mut store,
            &request(caller, "deploy-key", Action::RequestErasure, "erase-one"),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(erased.credential.status.status, Status::ErasureFenced);
        // The active candidate now owes backing cleanup; nothing claims it gone.
        assert_eq!(erased.credential.status.cleanup_required, 1);
        assert_secret_free(&world, &erased);

        let pending = admit_action(
            &mut store,
            &request(
                caller,
                "pending-key",
                Action::RequestErasure,
                "erase-pending",
            ),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(pending.credential.status.status, Status::ErasureFenced);
    }

    #[test]
    fn a_removed_organization_member_loses_administration() {
        let mut store = Store::open(":memory:").unwrap();
        let account = account_scope(ALICE);
        let tenant = provision_organization(&mut store, ALICE, &account, "Acme", None).unwrap();
        let owner = selected_owner_scope(&store, ALICE, &tenant.id).unwrap();
        provision_namespace(&mut store, &owner, |_| Ok(())).unwrap();
        create(&mut store, &owner, "org-key");
        let caller = Caller {
            authenticated_person: ALICE,
            selected_tenant_id: &tenant.id,
        };
        assert_eq!(
            list_credentials(&store, caller, |_| Ok(())).unwrap().len(),
            1
        );

        let mut former = Org::rebuild_in(&store, owner.as_str())
            .unwrap()
            .member_by_authority(ALICE)
            .unwrap()
            .clone();
        former.status = MembershipStatus::Deprovisioned;
        store
            .append_record(
                owner.as_str(),
                "membership",
                &serde_json::to_string(&former).unwrap(),
            )
            .unwrap();
        assert!(list_credentials(&store, caller, |_| Ok(())).is_err());
        assert!(admit_action(
            &mut store,
            &request(caller, "org-key", Action::Revoke, "revoke"),
            |_| Ok(()),
        )
        .is_err());
        let state = store
            .fold::<gaugevault::State>(binding(&owner, "org-key").credential_scope.as_str())
            .unwrap();
        assert_eq!(state.status, Status::Pending);
    }

    #[test]
    fn invalid_requests_refuse_before_any_lookup() {
        let (mut store, world) = world();
        let caller = alice(&world);
        for bad in [
            ActionRequest {
                request_key: " ".into(),
                ..request(caller, "deploy-key", Action::Revoke, "x")
            },
            ActionRequest {
                actor: VaultSubjectId::from(""),
                ..request(caller, "deploy-key", Action::Revoke, "x")
            },
            ActionRequest {
                now: 0,
                ..request(caller, "deploy-key", Action::Revoke, "x")
            },
            request(caller, "", Action::Revoke, "x"),
        ] {
            assert!(matches!(
                admit_action(&mut store, &bad, |_| Ok(())),
                Err(AdmitError::Rejected(_))
            ));
        }
    }
}
