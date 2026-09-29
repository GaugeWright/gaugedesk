//! Internal, secret-free account namespace and credential creation admission.
//!
//! The hosted shell must derive `owner_scope` from the authenticated Personal
//! or organization tenant and check its current standing in each callback.
//! Neither function is an HTTP route or a substitute for the recovery fence.

use gaugedesk_core::gaugevault::{self, Binding, Capability, Operation};
use gaugedesk_core::gaugevault_namespace::{self, Command as NamespaceCommand};
use gaugedesk_core::ids::{ScopeId, VaultSubjectId, VaultTenantPrefixId};
use gaugedesk_core::Rejection;
use gaugedesk_store::{AdmitError, Store};
use ring::rand::{SecureRandom, SystemRandom};

use crate::account::account_scope;
use crate::org::{tenant_scope, MembershipStatus, Org, ORG_SCOPE};
use crate::tenancy::{personal_tenant_id, Tenancy};

const NAMESPACE_KEY: &str = "gaugevault:namespace:v1";

fn is_named_tenant_scope(scope: &ScopeId) -> bool {
    scope.as_str().strip_prefix("org::").is_some_and(|tenant| {
        !tenant.is_empty() && tenant.trim() == tenant && tenant_scope(tenant) == scope.as_str()
    })
}

fn no_current_owner() -> AdmitError {
    AdmitError::Rejected(Rejection {
        reason: "GaugeVault: selected account has no current standing",
    })
}

/// Resolve a tenant chosen by a signed-in person to the exact owner scope.
/// The person's account index only names choices; the tenant's current
/// directory supplies membership. Neither membership nor this scope alone
/// grants credential management or final use.
pub fn selected_owner_scope(
    store: &Store,
    authenticated_person: &str,
    selected_tenant_id: &str,
) -> Result<ScopeId, AdmitError> {
    if authenticated_person.trim().is_empty() || selected_tenant_id.trim().is_empty() {
        return Err(no_current_owner());
    }
    let account = account_scope(authenticated_person);
    let tenancy = Tenancy::rebuild_in(store, &account)?;
    let selected = tenancy
        .tenants
        .get(selected_tenant_id)
        .ok_or_else(no_current_owner)?;
    let personal = selected_tenant_id.starts_with("personal:");
    if selected.personal != personal
        || (personal && selected_tenant_id != personal_tenant_id(authenticated_person))
    {
        return Err(no_current_owner());
    }
    let scope = tenant_scope(selected_tenant_id);
    if scope == ORG_SCOPE {
        return Err(no_current_owner());
    }
    let org = Org::rebuild_in(store, &scope)?;
    let member = org
        .member_by_authority(authenticated_person)
        .ok_or_else(no_current_owner)?;
    if org.org.is_none()
        || member.status != MembershipStatus::Active
        || (personal && member.role != "owner")
    {
        return Err(no_current_owner());
    }
    Ok(ScopeId::from(scope))
}

#[derive(serde::Serialize)]
struct NamespaceIntent<'a> {
    v: u8,
    owner_scope: &'a ScopeId,
}

/// Commit one random prefix in the authenticated owner's tenant scope. The
/// authorization callback runs again on every replay and must check current
/// account standing. A receipt replay never generates another prefix.
pub fn provision_namespace(
    store: &mut Store,
    owner_scope: &ScopeId,
    authorize: impl FnOnce(&gaugevault_namespace::State) -> Result<(), Rejection>,
) -> Result<VaultTenantPrefixId, AdmitError> {
    if !is_named_tenant_scope(owner_scope) {
        return Err(AdmitError::Rejected(Rejection {
            reason: "GaugeVault: named account owner scope required",
        }));
    }
    let intent = NamespaceIntent { v: 1, owner_scope };
    let admission = store.admit_request::<gaugevault_namespace::State, _>(
        owner_scope.as_str(),
        NAMESPACE_KEY,
        &intent,
        |state| {
            if state
                .owner_scope
                .as_ref()
                .is_some_and(|prior| prior != owner_scope)
            {
                return Err(Rejection {
                    reason: "GaugeVault: wrong namespace owner",
                });
            }
            authorize(state)
        },
        |_| {
            let mut bytes = [0u8; 16];
            SystemRandom::new()
                .fill(&mut bytes)
                .map_err(|_| Rejection {
                    reason: "GaugeVault: namespace randomness unavailable",
                })?;
            Ok(NamespaceCommand {
                owner_scope: owner_scope.clone(),
                prefix: VaultTenantPrefixId::from(hex::encode(bytes)),
            })
        },
    )?;
    if admission.state.owner_scope.as_ref() != Some(owner_scope) {
        return Err(AdmitError::Codec(
            "GaugeVault namespace receipt has wrong owner".into(),
        ));
    }
    admission
        .state
        .prefix
        .ok_or_else(|| AdmitError::Codec("GaugeVault namespace receipt has no prefix".into()))
}

/// The trusted caller has selected an account and a credential scope. The
/// selected owner is separate from `binding` so a copied binding cannot switch
/// accounts. `now` comes from a trusted clock and is excluded from retry intent.
pub struct CreateCredentialRequest {
    pub selected_owner_scope: ScopeId,
    pub binding: Binding,
    pub actor: VaultSubjectId,
    pub request_key: String,
    pub now: u64,
}

#[derive(serde::Serialize)]
struct CreateIntent<'a> {
    v: u8,
    binding: &'a Binding,
    actor: &'a VaultSubjectId,
    prefix: &'a VaultTenantPrefixId,
}

/// Create a credential only under the prefix already committed for the
/// authenticated owner. The hosted shell must authenticate the actor and
/// authorize management on both the first call and every receipt replay.
pub fn admit_credential_create(
    store: &mut Store,
    request: &CreateCredentialRequest,
    authorize: impl FnOnce(&gaugevault::State) -> Result<(), Rejection>,
) -> Result<VaultTenantPrefixId, AdmitError> {
    if !is_named_tenant_scope(&request.selected_owner_scope)
        || request.binding.owner_scope != request.selected_owner_scope
        || !request
            .binding
            .credential_scope
            .as_str()
            .starts_with(&format!("{}:", request.selected_owner_scope.as_str()))
        || request.binding.credential_scope.as_str().len()
            <= request.selected_owner_scope.as_str().len() + 1
        || request.actor.as_str().trim().is_empty()
        || request.request_key.trim().is_empty()
        || request.now == 0
    {
        return Err(AdmitError::Rejected(Rejection {
            reason: "GaugeVault: invalid credential owner binding",
        }));
    }
    let namespace =
        store.fold::<gaugevault_namespace::State>(request.selected_owner_scope.as_str())?;
    if namespace.owner_scope.as_ref() != Some(&request.selected_owner_scope) {
        return Err(AdmitError::Rejected(Rejection {
            reason: "GaugeVault: owner namespace unavailable",
        }));
    }
    let prefix = namespace.prefix.ok_or_else(|| {
        AdmitError::Rejected(Rejection {
            reason: "GaugeVault: owner namespace unavailable",
        })
    })?;
    let intent = CreateIntent {
        v: 1,
        binding: &request.binding,
        actor: &request.actor,
        prefix: &prefix,
    };
    let admission = store.admit_request::<gaugevault::State, _>(
        request.binding.credential_scope.as_str(),
        &request.request_key,
        &intent,
        |state| {
            if state
                .binding
                .as_ref()
                .is_some_and(|prior| prior != &request.binding)
            {
                return Err(Rejection {
                    reason: "GaugeVault: wrong credential binding",
                });
            }
            authorize(state)
        },
        |state| {
            Ok(gaugevault::Command {
                binding: request.binding.clone(),
                capability: Capability::Manage,
                expected_revision: state.revision,
                now: request.now,
                operation: Operation::Create {
                    tenant_prefix: prefix.clone(),
                },
            })
        },
    )?;
    if admission.state.binding.as_ref() != Some(&request.binding)
        || admission.state.tenant_prefix.as_ref() != Some(&prefix)
    {
        return Err(AdmitError::Codec(
            "GaugeVault credential receipt has wrong namespace".into(),
        ));
    }
    Ok(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::ids::{AuthorityId, VaultCredentialId};

    use crate::tenancy::{provision_organization, provision_personal_tenant};

    fn owner(value: &str) -> ScopeId {
        ScopeId::from(value)
    }

    fn create_request(owner_scope: ScopeId, credential: &str) -> CreateCredentialRequest {
        CreateCredentialRequest {
            selected_owner_scope: owner_scope.clone(),
            binding: Binding {
                authority: AuthorityId::from("hosted-home"),
                credential_scope: ScopeId::from(format!(
                    "{}:vault:{}",
                    owner_scope.as_str(),
                    credential
                )),
                owner_scope,
                credential: VaultCredentialId::from(credential),
            },
            actor: VaultSubjectId::from("manager"),
            request_key: format!("gaugevault:create:{credential}"),
            now: 1,
        }
    }

    #[test]
    fn one_prefix_is_committed_per_account_and_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.db");
        let personal = owner("org::personal:person-one");
        let organization = owner("org::organization-one");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        let personal_prefix = provision_namespace(&mut store, &personal, |_| Ok(())).unwrap();
        let org_prefix = provision_namespace(&mut store, &organization, |_| Ok(())).unwrap();
        assert_ne!(personal_prefix, org_prefix);
        assert_eq!(personal_prefix.as_str().len(), 32);
        let first = create_request(personal.clone(), "first");
        assert_eq!(
            admit_credential_create(&mut store, &first, |_| Ok(())).unwrap(),
            personal_prefix
        );
        let organization_credential = create_request(organization.clone(), "first");
        assert_eq!(
            admit_credential_create(&mut store, &organization_credential, |_| Ok(())).unwrap(),
            org_prefix
        );
        drop(store);

        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        assert_eq!(
            provision_namespace(&mut store, &personal, |_| Ok(())).unwrap(),
            personal_prefix
        );
        assert!(matches!(
            provision_namespace(&mut store, &personal, |_| Err(Rejection {
                reason: "account no longer authorized",
            })),
            Err(AdmitError::Rejected(_))
        ));
        assert_eq!(
            admit_credential_create(&mut store, &first, |_| Ok(())).unwrap(),
            personal_prefix
        );
        assert!(matches!(
            admit_credential_create(&mut store, &first, |_| Err(Rejection {
                reason: "manager grant removed",
            })),
            Err(AdmitError::Rejected(_))
        ));
        let second = create_request(personal.clone(), "second");
        assert_eq!(
            admit_credential_create(&mut store, &second, |_| Ok(())).unwrap(),
            personal_prefix
        );
        for request in [&first, &second] {
            let state = store
                .fold::<gaugevault::State>(request.binding.credential_scope.as_str())
                .unwrap();
            assert_eq!(state.tenant_prefix.as_ref(), Some(&personal_prefix));
            assert_eq!(state.revision, 1);
        }
    }

    #[test]
    fn copied_binding_and_missing_namespace_cannot_create() {
        let mut store = Store::open(":memory:").unwrap();
        let personal = owner("org::personal:person-one");
        let organization = owner("org::organization-one");
        let request = create_request(personal.clone(), "first");
        assert!(matches!(
            admit_credential_create(&mut store, &request, |_| Ok(())),
            Err(AdmitError::Rejected(_))
        ));
        provision_namespace(&mut store, &personal, |_| Ok(())).unwrap();
        provision_namespace(&mut store, &organization, |_| Ok(())).unwrap();
        let mut copied = create_request(personal.clone(), "other");
        copied.selected_owner_scope = organization;
        assert!(matches!(
            admit_credential_create(&mut store, &copied, |_| Ok(())),
            Err(AdmitError::Rejected(_))
        ));
        assert!(matches!(
            admit_credential_create(&mut store, &request, |_| Err(Rejection {
                reason: "manager grant absent",
            })),
            Err(AdmitError::Rejected(_))
        ));
        assert!(store
            .fold::<gaugevault::State>(request.binding.credential_scope.as_str())
            .unwrap()
            .binding
            .is_none());
    }

    #[test]
    fn namespace_and_credential_create_refuse_person_index_and_foreign_streams() {
        let mut store = Store::open(":memory:").unwrap();
        for invalid in ["account::person-one", "org", "org::", "org:: ", "org::org"] {
            assert!(matches!(
                provision_namespace(&mut store, &owner(invalid), |_| Ok(())),
                Err(AdmitError::Rejected(_))
            ));
        }

        let personal = owner("org::personal:person-one");
        provision_namespace(&mut store, &personal, |_| Ok(())).unwrap();

        let mut wrong_index = create_request(personal.clone(), "one");
        wrong_index.selected_owner_scope = owner("account::person-one");
        wrong_index.binding.owner_scope = wrong_index.selected_owner_scope.clone();
        assert!(matches!(
            admit_credential_create(&mut store, &wrong_index, |_| Ok(())),
            Err(AdmitError::Rejected(_))
        ));

        let mut foreign_stream = create_request(personal.clone(), "one");
        foreign_stream.binding.credential_scope = owner("org::personal:person-one-other:vault:one");
        assert!(matches!(
            admit_credential_create(&mut store, &foreign_stream, |_| Ok(())),
            Err(AdmitError::Rejected(_))
        ));
        assert!(store
            .fold::<gaugevault::State>(foreign_stream.binding.credential_scope.as_str())
            .unwrap()
            .binding
            .is_none());
    }

    #[test]
    fn personal_owner_is_the_current_tenant_not_a_copied_person_index() {
        let mut store = Store::open(":memory:").unwrap();
        let alice = "person:alice";
        let bob = "person:bob";
        let alice_tenant = provision_personal_tenant(&mut store, alice, "Alice").unwrap();
        let bob_tenant = provision_personal_tenant(&mut store, bob, "Bob").unwrap();

        let alice_owner = selected_owner_scope(&store, alice, &alice_tenant).unwrap();
        let bob_owner = selected_owner_scope(&store, bob, &bob_tenant).unwrap();
        assert_eq!(alice_owner.as_str(), tenant_scope(&alice_tenant));
        assert_ne!(alice_owner, bob_owner);
        assert!(matches!(
            selected_owner_scope(&store, bob, &alice_tenant),
            Err(AdmitError::Rejected(_))
        ));
        assert!(matches!(
            selected_owner_scope(&store, alice, "missing-tenant"),
            Err(AdmitError::Rejected(_))
        ));

        let prefix = provision_namespace(&mut store, &alice_owner, |_| Ok(())).unwrap();
        let alice_credential = create_request(alice_owner.clone(), "first");
        assert_eq!(
            admit_credential_create(&mut store, &alice_credential, |_| Ok(())).unwrap(),
            prefix
        );
        let mut copied = create_request(alice_owner, "copied");
        copied.selected_owner_scope = bob_owner;
        assert!(matches!(
            admit_credential_create(&mut store, &copied, |_| Ok(())),
            Err(AdmitError::Rejected(_))
        ));
    }

    #[test]
    fn organization_selection_rechecks_current_directory_membership() {
        let mut store = Store::open(":memory:").unwrap();
        let alice = "person:alice";
        let account = account_scope(alice);
        let tenant = provision_organization(&mut store, alice, &account, "Acme", None).unwrap();
        let scope = selected_owner_scope(&store, alice, &tenant.id).unwrap();
        assert_eq!(scope.as_str(), tenant_scope(&tenant.id));
        assert!(matches!(
            selected_owner_scope(&store, "person:outsider", &tenant.id),
            Err(AdmitError::Rejected(_))
        ));

        let mut former_member = Org::rebuild_in(&store, scope.as_str())
            .unwrap()
            .member_by_authority(alice)
            .unwrap()
            .clone();
        former_member.status = MembershipStatus::Deprovisioned;
        store
            .append_record(
                scope.as_str(),
                "membership",
                &serde_json::to_string(&former_member).unwrap(),
            )
            .unwrap();
        // The person's switcher still lists the organization. It cannot
        // override the current tenant directory after access is removed.
        assert!(Tenancy::rebuild_in(&store, &account)
            .unwrap()
            .contains(&tenant.id));
        assert!(matches!(
            selected_owner_scope(&store, alice, &tenant.id),
            Err(AdmitError::Rejected(_))
        ));
    }
}
