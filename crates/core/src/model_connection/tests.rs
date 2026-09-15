use super::*;
use proptest::prelude::*;

mod spend;

fn id() -> ModelConnectionId {
    ModelConnectionId::new("connection-a")
}
fn version(n: u8) -> CredentialVersionId {
    CredentialVersionId::new(format!("version-{n}"))
}
fn handle(n: u8) -> SecretHandleId {
    SecretHandleId::new(format!("opaque-handle-{n}"))
}
fn evidence() -> ObservationId {
    ObservationId::new("authenticated-observation")
}
fn binding() -> AuthorityBinding {
    AuthorityBinding {
        authority: AuthorityId::new("credential-authority"),
        organization: ScopeId::new("organization-acme"),
        environment: "test".into(),
    }
}
fn provider() -> ProviderBinding {
    ProviderBinding {
        provider: "test-provider".into(),
        endpoint: "https://provider.invalid/models".into(),
        authentication: AuthenticationKind::ApiKey,
    }
}
fn policy() -> ModelPolicy {
    ModelPolicy {
        models: ["model-a".into(), "model-b".into()].into(),
        execution_classes: [ExecutionClass::PrivateBroker].into(),
    }
}
fn begin() -> Operation {
    Operation::BeginIntake {
        connection: id(),
        reconnects: None,
        definition: ConnectionDefinition {
            name: "Team connection".into(),
            provider: provider(),
            policy: policy(),
        },
        version: version(1),
        expires_at: 1000,
    }
}
fn replacement() -> Operation {
    Operation::BeginReplacement {
        connection: id(),
        version: version(2),
        expires_at: 1000,
    }
}
fn seal(n: u8) -> Operation {
    Operation::RecordSealed {
        connection: id(),
        version: version(n),
        handle: handle(n),
    }
}
fn verify(n: u8, passed: bool) -> Operation {
    Operation::RecordVerification {
        connection: id(),
        version: version(n),
        provider: provider(),
        handle: handle(n),
        evidence: evidence(),
        check: VerificationCheck::ModelCatalogRead,
        passed,
    }
}
fn activate(n: u8) -> Operation {
    Operation::Activate {
        connection: id(),
        version: version(n),
    }
}
fn erase(n: u8) -> Operation {
    Operation::RecordMaterialErased {
        connection: id(),
        version: version(n),
        expected_handle: Some(handle(n)),
        evidence: evidence(),
    }
}

#[derive(Default)]
struct Driver {
    state: State,
    events: Vec<Event>,
}
impl Driver {
    fn command(&self, capability: Capability, operation: Operation) -> Command {
        Command {
            binding: binding(),
            actor: AuthorityId::new("authenticated-actor"),
            capability,
            basis: Basis::Metadata(self.state.revision),
            now: self.state.last_at + 1,
            operation,
        }
    }
    fn submit(&mut self, command: Command) -> Result<(), Rejection> {
        for event in decide(&self.state, command)? {
            self.state = evolve(&self.state, event.clone());
            self.events.push(event);
        }
        Ok(())
    }
    fn apply(&mut self, capability: Capability, operation: Operation) {
        self.submit(self.command(capability, operation)).unwrap();
        self.assert_replay();
    }
    fn manage(&mut self, operation: Operation) {
        self.apply(Capability::ManageConnections, operation);
    }
    fn deny(&mut self, capability: Capability, operation: Operation) {
        let state = self.state.clone();
        assert!(self.submit(self.command(capability, operation)).is_err());
        assert_eq!(self.state, state);
    }
    fn assert_replay(&self) {
        let mut restored = State::default();
        for event in &self.events {
            let mut bytes = Vec::new();
            ciborium::into_writer(event, &mut bytes).unwrap();
            let restored_event: Event = ciborium::from_reader(bytes.as_slice()).unwrap();
            assert_eq!(&restored_event, event);
            restored = evolve(&restored, restored_event);
        }
        assert_eq!(restored, self.state);
    }
    fn ready(n: u8, driver: &mut Self) {
        driver.apply(Capability::SealCandidate, seal(n));
        driver.apply(Capability::VerifyCandidate, verify(n, true));
    }
    fn active() -> Self {
        let mut driver = Self::default();
        driver.manage(begin());
        Self::ready(1, &mut driver);
        driver.manage(activate(1));
        driver
    }
    fn current(&self) -> &Connection {
        &self.state.connections[&id()]
    }
}

#[test]
fn activation_requires_a_sealed_verified_candidate_and_explicit_management() {
    let mut driver = Driver::default();
    driver.manage(begin());
    driver.deny(Capability::ManageConnections, activate(1));
    driver.apply(Capability::SealCandidate, seal(1));
    driver.deny(Capability::ManageConnections, activate(1));
    driver.apply(Capability::VerifyCandidate, verify(1, true));
    assert_eq!(driver.current().status, ConnectionStatus::Pending);
    assert!(driver.current().active_version().is_none());
    driver.deny(Capability::VerifyCandidate, activate(1));
    driver.manage(activate(1));
    assert_eq!(driver.current().active_version(), Some(&version(1)));
}

#[test]
fn verification_preserves_the_tested_capability_through_activation_and_replay() {
    let mut driver = Driver::default();
    driver.manage(begin());
    driver.apply(Capability::SealCandidate, seal(1));
    driver.apply(Capability::VerifyCandidate, verify(1, true));
    let tested = Verification {
        check: VerificationCheck::ModelCatalogRead,
        observed_at: driver.state.last_at,
    };
    assert_eq!(
        driver.current().versions[&version(1)].verification,
        Some(tested.clone())
    );
    driver.manage(activate(1));
    assert_eq!(
        driver.current().versions[&version(1)].verification,
        Some(tested)
    );
    driver.assert_replay();
}

#[test]
fn failed_check_keeps_its_kind_and_time_without_becoming_an_activation() {
    let mut driver = Driver::default();
    driver.manage(begin());
    driver.apply(Capability::SealCandidate, seal(1));
    driver.apply(Capability::VerifyCandidate, verify(1, false));
    assert_eq!(
        driver.current().versions[&version(1)].verification,
        Some(Verification {
            check: VerificationCheck::ModelCatalogRead,
            observed_at: driver.state.last_at,
        })
    );
    driver.deny(Capability::ManageConnections, activate(1));
    assert!(matches!(
        driver.current().versions[&version(1)].material,
        Material::ErasureRequired { .. }
    ));
    let verification = driver.current().versions[&version(1)].verification.clone();
    driver.apply(Capability::ConfirmErasure, erase(1));
    assert_eq!(
        driver.current().versions[&version(1)].verification,
        verification
    );
    driver.assert_replay();
}

#[test]
fn legacy_verification_replays_without_inventing_a_check_or_allowing_new_activation() {
    let mut driver = Driver::default();
    driver.manage(begin());
    driver.apply(Capability::SealCandidate, seal(1));
    // Deserialize the historical event shape rather than constructing a new
    // observation with a fabricated default. Events remain append-only.
    #[derive(serde::Serialize)]
    enum LegacyChange {
        CandidateVerified {
            connection: ModelConnectionId,
            version: CredentialVersionId,
            evidence: ObservationId,
        },
    }
    let mut bytes = Vec::new();
    ciborium::into_writer(
        &LegacyChange::CandidateVerified {
            connection: id(),
            version: version(1),
            evidence: evidence(),
        },
        &mut bytes,
    )
    .unwrap();
    let legacy: Change = ciborium::from_reader(bytes.as_slice()).unwrap();
    let event = Event {
        binding: binding(),
        actor: AuthorityId::new("old-authority"),
        at: driver.state.last_at + 1,
        change: legacy,
    };
    driver.state = evolve(&driver.state, event.clone());
    driver.events.push(event);
    assert!(driver.current().versions[&version(1)]
        .verification
        .is_none());
    driver.assert_replay();
    driver.deny(Capability::ManageConnections, activate(1));
    // A pending legacy candidate can still be cancelled and replaced.
    driver.manage(Operation::CancelCandidate {
        connection: id(),
        version: version(1),
    });
    driver.manage(replacement());
    Driver::ready(2, &mut driver);
    driver.manage(activate(2));
}

#[test]
fn roles_cannot_assert_verification_sealing_or_erasure() {
    let mut driver = Driver::default();
    driver.deny(Capability::SealCandidate, begin());
    driver.manage(begin());
    driver.deny(Capability::ManageConnections, seal(1));
    driver.apply(Capability::SealCandidate, seal(1));
    driver.deny(Capability::ManageConnections, verify(1, true));
    driver.apply(Capability::VerifyCandidate, verify(1, true));
    driver.manage(activate(1));
    driver.manage(Operation::RequestErasure { connection: id() });
    driver.deny(Capability::ManageConnections, erase(1));
    driver.apply(Capability::ConfirmErasure, erase(1));
    assert_eq!(driver.current().status, ConnectionStatus::Erased);
}

#[test]
fn cross_authority_organization_environment_and_stale_basis_are_denied() {
    let mut driver = Driver::active();
    for field in 0..5 {
        let mut command = driver.command(
            Capability::ManageConnections,
            Operation::Suspend { connection: id() },
        );
        match field {
            0 => command.binding.authority = AuthorityId::new("other-authority"),
            1 => command.binding.organization = ScopeId::new("other-organization"),
            2 => command.binding.environment = "live".into(),
            3 => command.basis = Basis::Metadata(driver.state.revision - 1),
            _ => command.now = 0,
        }
        let before = driver.state.clone();
        assert!(driver.submit(command).is_err());
        assert_eq!(before, driver.state);
    }
}

#[test]
fn verification_is_bound_to_the_exact_provider_endpoint_authentication_and_handle() {
    let mut driver = Driver::default();
    driver.manage(begin());
    driver.apply(Capability::SealCandidate, seal(1));
    for field in 0..4 {
        let mut operation = verify(1, true);
        if let Operation::RecordVerification {
            provider, handle, ..
        } = &mut operation
        {
            match field {
                0 => provider.provider = "other-provider".into(),
                1 => provider.endpoint = "https://other.invalid".into(),
                2 => provider.authentication = AuthenticationKind::OrganizationOauth,
                _ => *handle = SecretHandleId::new("other-material"),
            }
        }
        driver.deny(Capability::VerifyCandidate, operation);
    }
    driver.apply(Capability::VerifyCandidate, verify(1, true));
}

#[test]
fn replacement_never_silently_activates_and_does_not_resume_suspension() {
    let mut driver = Driver::active();
    driver.manage(Operation::Suspend { connection: id() });
    driver.manage(replacement());
    Driver::ready(2, &mut driver);
    assert_eq!(driver.current().current_version, Some(version(1)));
    driver.manage(activate(2));
    assert_eq!(driver.current().status, ConnectionStatus::Suspended);
    assert_eq!(driver.current().current_version, Some(version(2)));
    assert!(driver.current().active_version().is_none());
    driver.manage(Operation::Resume { connection: id() });
    assert_eq!(driver.current().active_version(), Some(&version(2)));
    // The superseded version remains historical evidence.
    assert!(matches!(
        driver.current().versions[&version(1)].phase,
        VersionPhase::Activated { .. }
    ));
}

#[test]
fn failed_replacement_preserves_old_standing_and_requires_material_cleanup() {
    let mut driver = Driver::active();
    driver.manage(replacement());
    driver.apply(Capability::SealCandidate, seal(2));
    driver.apply(Capability::VerifyCandidate, verify(2, false));
    assert_eq!(driver.current().active_version(), Some(&version(1)));
    assert_eq!(
        driver.current().versions[&version(2)].material,
        Material::ErasureRequired {
            handle: Some(handle(2))
        }
    );
    driver.deny(Capability::ManageConnections, activate(2));
    driver.apply(Capability::ConfirmErasure, erase(2));
    assert!(matches!(
        driver.current().versions[&version(2)].material,
        Material::Erased { .. }
    ));
    assert_eq!(driver.current().active_version(), Some(&version(1)));
}

#[test]
fn every_candidate_phase_has_cancel_and_deadline_escape() {
    for stage in 0..3 {
        for expire in [false, true] {
            let mut driver = Driver::default();
            driver.manage(begin());
            if stage >= 1 {
                driver.apply(Capability::SealCandidate, seal(1));
            }
            if stage >= 2 {
                driver.apply(Capability::VerifyCandidate, verify(1, true));
            }
            if expire {
                let operation = Operation::ExpireCandidate {
                    connection: id(),
                    version: version(1),
                };
                driver.deny(Capability::ObserveDeadline, operation.clone());
                let mut command = driver.command(Capability::ObserveDeadline, operation);
                command.now = 1000;
                driver.submit(command).unwrap();
                assert_eq!(
                    driver.current().versions[&version(1)].phase,
                    VersionPhase::Expired
                );
            } else {
                driver.manage(Operation::CancelCandidate {
                    connection: id(),
                    version: version(1),
                });
                assert_eq!(
                    driver.current().versions[&version(1)].phase,
                    VersionPhase::Cancelled
                );
            }
            let material = &driver.current().versions[&version(1)].material;
            assert_eq!(
                material,
                &if stage == 0 {
                    Material::ErasureRequired { handle: None }
                } else {
                    Material::ErasureRequired {
                        handle: Some(handle(1)),
                    }
                }
            );
            driver.deny(Capability::ManageConnections, activate(1));
            driver.assert_replay();
        }
    }
}

#[test]
fn a_candidate_cannot_be_sealed_verified_or_activated_at_its_deadline() {
    for stage in 0..3 {
        let mut driver = Driver::default();
        driver.manage(begin());
        if stage >= 1 {
            driver.apply(Capability::SealCandidate, seal(1));
        }
        if stage >= 2 {
            driver.apply(Capability::VerifyCandidate, verify(1, true));
        }
        let (capability, operation) = match stage {
            0 => (Capability::SealCandidate, seal(1)),
            1 => (Capability::VerifyCandidate, verify(1, true)),
            _ => (Capability::ManageConnections, activate(1)),
        };
        let mut command = driver.command(capability, operation);
        command.now = 1000;
        assert!(driver.submit(command).is_err());
    }
}

#[test]
fn identities_and_open_candidates_cannot_be_overwritten() {
    let mut driver = Driver::default();
    driver.manage(begin());
    driver.deny(Capability::ManageConnections, begin());
    driver.deny(Capability::ManageConnections, replacement());
    driver.manage(Operation::CancelCandidate {
        connection: id(),
        version: version(1),
    });
    let same_version = Operation::BeginReplacement {
        connection: id(),
        version: version(1),
        expires_at: 1000,
    };
    driver.deny(Capability::ManageConnections, same_version);
    driver.manage(replacement());
    driver.apply(Capability::SealCandidate, seal(2));
    driver.deny(Capability::SealCandidate, seal(2));
}

#[test]
fn revoked_connections_stay_terminal_and_in_flight_material_is_not_claimed_erased() {
    let mut driver = Driver::active();
    driver.manage(replacement());
    driver.apply(Capability::SealCandidate, seal(2));
    driver.manage(Operation::Revoke { connection: id() });
    assert!(driver.current().active_version().is_none());
    assert_eq!(
        driver.current().versions[&version(1)].material,
        Material::Held { handle: handle(1) }
    );
    assert_eq!(
        driver.current().versions[&version(2)].phase,
        VersionPhase::Cancelled
    );
    assert_eq!(
        driver.current().versions[&version(2)].material,
        Material::ErasureRequired {
            handle: Some(handle(2))
        }
    );
    for operation in [
        Operation::Resume { connection: id() },
        activate(1),
        replacement(),
        Operation::Rename {
            connection: id(),
            name: "revived".into(),
        },
    ] {
        driver.deny(Capability::ManageConnections, operation);
    }
    driver.deny(Capability::ConfirmErasure, erase(1));
}

#[test]
fn connection_erasure_waits_for_every_exact_material_receipt_and_replays() {
    let mut driver = Driver::active();
    driver.manage(replacement());
    Driver::ready(2, &mut driver);
    driver.manage(activate(2));
    driver.manage(Operation::RequestErasure { connection: id() });
    assert_eq!(driver.current().status, ConnectionStatus::Revoked);
    assert!(driver.current().erasure_requested);
    driver.apply(Capability::ConfirmErasure, erase(1));
    assert_eq!(driver.current().status, ConnectionStatus::Revoked);
    driver.deny(Capability::ConfirmErasure, erase(1));
    let mut wrong = erase(2);
    if let Operation::RecordMaterialErased {
        expected_handle, ..
    } = &mut wrong
    {
        *expected_handle = Some(SecretHandleId::new("wrong"));
    }
    driver.deny(Capability::ConfirmErasure, wrong);
    driver.apply(Capability::ConfirmErasure, erase(2));
    assert_eq!(driver.current().status, ConnectionStatus::Erased);
    assert!(driver.current().material_gone());
    assert_eq!(driver.current().versions.len(), 2);
    driver.deny(Capability::ManageConnections, replacement());
}

#[test]
fn missing_seal_receipt_does_not_prove_material_absent_after_a_crash() {
    let mut driver = Driver::default();
    driver.manage(begin());
    driver.apply(
        Capability::OrganizationClosure,
        Operation::RequestErasure { connection: id() },
    );
    assert_eq!(driver.current().status, ConnectionStatus::Revoked);
    assert_eq!(
        driver.current().versions[&version(1)].material,
        Material::ErasureRequired { handle: None }
    );
    assert_eq!(
        driver.current().versions[&version(1)].phase,
        VersionPhase::Cancelled
    );
    driver.deny(Capability::ConfirmErasure, erase(1));
    driver.apply(
        Capability::ConfirmErasure,
        Operation::RecordMaterialErased {
            connection: id(),
            version: version(1),
            expected_handle: None,
            evidence: evidence(),
        },
    );
    assert_eq!(driver.current().status, ConnectionStatus::Erased);
    // A late seal observation cannot resurrect the fenced candidate.
    driver.deny(Capability::SealCandidate, seal(1));
}

#[test]
fn destroyed_handles_cannot_be_reused_for_new_versions() {
    let mut driver = Driver::default();
    driver.manage(begin());
    driver.apply(Capability::SealCandidate, seal(1));
    driver.manage(Operation::CancelCandidate {
        connection: id(),
        version: version(1),
    });
    driver.apply(Capability::ConfirmErasure, erase(1));
    driver.manage(replacement());
    let operation = Operation::RecordSealed {
        connection: id(),
        version: version(2),
        handle: handle(1),
    };
    driver.deny(Capability::SealCandidate, operation);
    driver.apply(Capability::SealCandidate, seal(2));
}

#[test]
fn defaults_are_explicit_approved_and_unavailable_without_fallback() {
    let mut driver = Driver::active();
    let selection = ModelSelection {
        connection: id(),
        model: "model-a".into(),
    };
    driver.manage(Operation::SetDefault {
        selection: Some(selection.clone()),
    });
    assert_eq!(driver.state.available_default(), Some(&selection));
    driver.manage(Operation::Suspend { connection: id() });
    assert!(driver.state.available_default().is_none());
    assert_eq!(driver.state.default, Some(selection));
    driver.manage(Operation::Resume { connection: id() });
    driver.manage(Operation::SetModelPolicy {
        connection: id(),
        policy: ModelPolicy {
            models: ["model-b".into()].into(),
            ..policy()
        },
    });
    assert!(driver.state.available_default().is_none());
    driver.deny(
        Capability::ManageConnections,
        Operation::SetDefault {
            selection: Some(ModelSelection {
                connection: id(),
                model: "unknown".into(),
            }),
        },
    );
    driver.manage(Operation::SetDefault {
        selection: Some(ModelSelection {
            connection: id(),
            model: "model-b".into(),
        }),
    });
    driver.manage(Operation::SetModelPolicy {
        connection: id(),
        policy: ModelPolicy {
            models: BTreeSet::new(),
            ..policy()
        },
    });
    assert!(driver.state.available_default().is_none());
    assert!(driver.state.default.is_some());
    driver.manage(Operation::SetDefault { selection: None });
    assert!(driver.state.default.is_none());
}

#[test]
fn past_deadline_and_revision_overflow_are_denied() {
    let mut driver = Driver::default();
    let mut operation = begin();
    if let Operation::BeginIntake { expires_at, .. } = &mut operation {
        *expires_at = 1;
    }
    driver.deny(Capability::ManageConnections, operation);
    driver.manage(begin());
    driver.state.revision = u64::MAX;
    driver.deny(
        Capability::ManageConnections,
        Operation::Rename {
            connection: id(),
            name: "No overflow".into(),
        },
    );
}

proptest! {
    #[test]
    fn every_reachable_state_preserves_history_and_has_no_unverified_active_key(steps in prop::collection::vec(0u8..20, 1..60)) {
        let mut driver = Driver::default();
        for step in steps {
            let (capability, operation) = match step {
                0 => (Capability::ManageConnections, begin()),
                1 => (Capability::ManageConnections, replacement()),
                2 => (Capability::SealCandidate, seal(1)),
                3 => (Capability::SealCandidate, seal(2)),
                4 => (Capability::VerifyCandidate, verify(1, true)),
                5 => (Capability::VerifyCandidate, verify(2, true)),
                6 => (Capability::VerifyCandidate, verify(1, false)),
                7 => (Capability::VerifyCandidate, verify(2, false)),
                8 => (Capability::ManageConnections, activate(1)),
                9 => (Capability::ManageConnections, activate(2)),
                10 => (Capability::ManageConnections, Operation::Suspend { connection: id() }),
                11 => (Capability::ManageConnections, Operation::Resume { connection: id() }),
                12 => (Capability::ManageConnections, Operation::CancelCandidate { connection: id(), version: version(1) }),
                13 => (Capability::ManageConnections, Operation::CancelCandidate { connection: id(), version: version(2) }),
                14 => (Capability::ManageConnections, Operation::Revoke { connection: id() }),
                15 => (Capability::ManageConnections, Operation::RequestErasure { connection: id() }),
                16 => (Capability::ConfirmErasure, erase(1)),
                17 => (Capability::ConfirmErasure, erase(2)),
                18 => (Capability::ObserveDeadline, Operation::ExpireCandidate { connection: id(), version: version(1) }),
                _ => (Capability::ObserveDeadline, Operation::ExpireCandidate { connection: id(), version: version(2) }),
            };
            let old = driver.state.clone();
            let mut command = driver.command(capability, operation);
            if step >= 18 { command.now = command.now.max(1000); }
            let result = driver.submit(command);
            if result.is_err() { prop_assert_eq!(&driver.state, &old); }
            prop_assert!(old.used_handles.is_subset(&driver.state.used_handles));
            if let Some(current) = driver.state.connections.get(&id()) {
                if let Some(previous) = old.connections.get(&id()) {
                    prop_assert!(previous.versions.keys().all(|key| current.versions.contains_key(key)));
                    if !previous.mutable() { prop_assert!(!current.mutable()); }
                }
                if let Some(active) = current.active_version() {
                    prop_assert!(matches!(current.versions[active].phase, VersionPhase::Activated { .. }), "active version must have been activated");
                    prop_assert!(matches!(current.versions[active].material, Material::Held { .. }), "active version must retain material");
                }
                if current.status == ConnectionStatus::Erased { prop_assert!(current.material_gone()); }
                for version in current.versions.values() {
                    if matches!(version.phase, VersionPhase::Cancelled | VersionPhase::Expired | VersionPhase::Failed { .. }) {
                        prop_assert!(!matches!(version.material, Material::Held { .. }), "ended candidate must schedule cleanup");
                    }
                }
            }
        }
        driver.assert_replay();
    }
}
