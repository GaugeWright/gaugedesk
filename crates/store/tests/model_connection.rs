//! Real SQLite admission/replay evidence for GAUGEAPP-6, not hosted KMS proof.
use gaugedesk_core::ids::{
    AuthorityId, CredentialVersionId, ModelConnectionId, ObservationId, ScopeId, SecretHandleId,
};
use gaugedesk_core::model_connection::{
    AuthenticationKind, AuthorityBinding, Basis, Capability, Command, ConnectionDefinition,
    ConnectionStatus, ExecutionClass, Material, ModelConnection, ModelPolicy, Operation,
    ProviderBinding,
};
use gaugedesk_store::Store;
use std::sync::{Arc, Barrier};

#[path = "model_connection/spend.rs"]
mod spend;

const SCOPE: &str = "organization-acme";
fn id() -> ModelConnectionId {
    ModelConnectionId::new("connection")
}
fn version() -> CredentialVersionId {
    CredentialVersionId::new("version")
}
fn handle() -> SecretHandleId {
    SecretHandleId::new("opaque-handle")
}
fn command(revision: u64, capability: Capability, operation: Operation) -> Command {
    Command {
        binding: AuthorityBinding {
            authority: AuthorityId::new("credential-authority"),
            organization: ScopeId::new(SCOPE),
            environment: "test".into(),
        },
        actor: AuthorityId::new("authenticated-actor"),
        capability,
        basis: Basis::Metadata(revision),
        now: revision + 1,
        operation,
    }
}
fn begin() -> Operation {
    Operation::BeginIntake {
        connection: id(),
        reconnects: None,
        definition: ConnectionDefinition {
            name: "Team".into(),
            provider: ProviderBinding {
                provider: "test".into(),
                endpoint: "https://provider.invalid".into(),
                authentication: AuthenticationKind::ApiKey,
            },
            policy: ModelPolicy {
                models: ["test-model".into()].into(),
                execution_classes: [ExecutionClass::PrivateBroker].into(),
            },
        },
        version: version(),
        expires_at: 1000,
    }
}

#[test]
fn interrupted_erasure_restores_the_obligation_and_exact_retries_do_not_repeat_events() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("custody.sqlite");
    let mut store = Store::open(path.to_str().unwrap()).unwrap();
    store
        .admit_materialized::<ModelConnection>(
            SCOPE,
            "begin",
            command(0, Capability::ManageConnections, begin()),
        )
        .unwrap();
    store
        .admit_materialized::<ModelConnection>(
            SCOPE,
            "seal",
            command(
                1,
                Capability::SealCandidate,
                Operation::RecordSealed {
                    connection: id(),
                    version: version(),
                    handle: handle(),
                },
            ),
        )
        .unwrap();
    let request = command(
        2,
        Capability::ManageConnections,
        Operation::RequestErasure { connection: id() },
    );
    let pending = store
        .admit_materialized::<ModelConnection>(SCOPE, "erase", request.clone())
        .unwrap();
    assert_eq!(
        pending.state.connections[&id()].status,
        ConnectionStatus::Revoked
    );
    assert_eq!(
        pending.state.connections[&id()].versions[&version()].material,
        Material::ErasureRequired {
            handle: Some(handle())
        }
    );
    drop(store);

    let mut restored = Store::open(path.to_str().unwrap()).unwrap();
    assert_eq!(
        restored.fold::<ModelConnection>(SCOPE).unwrap(),
        pending.state
    );
    let replay = restored
        .admit_materialized::<ModelConnection>(SCOPE, "erase", request.clone())
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.state, pending.state);
    let mut changed = request;
    changed.binding.environment = "live".into();
    assert!(restored
        .admit_materialized::<ModelConnection>(SCOPE, "erase", changed)
        .is_err());
    assert_eq!(
        restored.fold::<ModelConnection>(SCOPE).unwrap(),
        pending.state
    );

    let confirmation = command(
        pending.state.revision,
        Capability::ConfirmErasure,
        Operation::RecordMaterialErased {
            connection: id(),
            version: version(),
            expected_handle: Some(handle()),
            evidence: ObservationId::new("kms-erasure-receipt"),
        },
    );
    let final_state = restored
        .admit_materialized::<ModelConnection>(SCOPE, "confirm", confirmation)
        .unwrap()
        .state;
    assert_eq!(
        final_state.connections[&id()].status,
        ConnectionStatus::Erased
    );
    drop(restored);
    assert_eq!(
        Store::open(path.to_str().unwrap())
            .unwrap()
            .fold::<ModelConnection>(SCOPE)
            .unwrap(),
        final_state
    );
}

#[test]
fn unobserved_intake_retains_a_namespace_cleanup_obligation_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unobserved-intake.sqlite");
    let mut store = Store::open(path.to_str().unwrap()).unwrap();
    store
        .admit_materialized::<ModelConnection>(
            SCOPE,
            "begin",
            command(0, Capability::ManageConnections, begin()),
        )
        .unwrap();
    // Custody could have sealed material here, before the process admitted a
    // seal receipt. Absence of that receipt must not complete erasure.
    let pending = store
        .admit_materialized::<ModelConnection>(
            SCOPE,
            "erase",
            command(
                1,
                Capability::ManageConnections,
                Operation::RequestErasure { connection: id() },
            ),
        )
        .unwrap()
        .state;
    assert_eq!(pending.connections[&id()].status, ConnectionStatus::Revoked);
    assert_eq!(
        pending.connections[&id()].versions[&version()].material,
        Material::ErasureRequired { handle: None }
    );
    drop(store);

    let mut restored = Store::open(path.to_str().unwrap()).unwrap();
    assert_eq!(restored.fold::<ModelConnection>(SCOPE).unwrap(), pending);
    let confirmation = command(
        pending.revision,
        Capability::ConfirmErasure,
        Operation::RecordMaterialErased {
            connection: id(),
            version: version(),
            expected_handle: None,
            evidence: ObservationId::new("custody-namespace-fenced-and-erased"),
        },
    );
    let erased = restored
        .admit_materialized::<ModelConnection>(SCOPE, "confirm", confirmation)
        .unwrap()
        .state;
    assert_eq!(erased.connections[&id()].status, ConnectionStatus::Erased);
    assert!(restored
        .admit_materialized::<ModelConnection>(
            SCOPE,
            "late-seal",
            command(
                erased.revision,
                Capability::SealCandidate,
                Operation::RecordSealed {
                    connection: id(),
                    version: version(),
                    handle: handle(),
                }
            ),
        )
        .is_err());
    assert_eq!(restored.fold::<ModelConnection>(SCOPE).unwrap(), erased);
}

#[test]
fn two_database_connections_cannot_admit_against_the_same_stale_organization_basis() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ordered.sqlite");
    drop(Store::open(path.to_str().unwrap()).unwrap());
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|n| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut store = Store::open(path.to_str().unwrap()).unwrap();
                let mut operation = begin();
                if let Operation::BeginIntake { connection, .. } = &mut operation {
                    *connection = ModelConnectionId::new(format!("connection-{n}"));
                }
                let input = command(0, Capability::ManageConnections, operation);
                barrier.wait();
                store
                    .admit_materialized::<ModelConnection>(SCOPE, &format!("create-{n}"), input)
                    .map(|result| result.state)
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let error = results
        .iter()
        .find_map(|result| result.as_ref().err())
        .unwrap();
    assert!(
        format!("{error:?}").contains("stale connection authority basis"),
        "{error:?}"
    );
    let restored = Store::open(path.to_str().unwrap())
        .unwrap()
        .fold::<ModelConnection>(SCOPE)
        .unwrap();
    assert_eq!(restored.revision, 1);
    assert_eq!(restored.connections.len(), 1);
}
