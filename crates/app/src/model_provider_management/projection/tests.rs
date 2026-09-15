use super::*;
use crate::model_provider_management::tests::{binding, connection, ready, scope, version};
use gaugedesk_core::ids::{HomeId, ModelAttemptId};

struct Fixture {
    store: Store,
    state: State,
}

#[test]
fn operated_setup_choices_invalidate_review_without_changing_connection_state() {
    let fixture = Fixture::new();
    let page = fixture.page();
    let definition = &fixture.state.connections[&connection()].definition;
    let configured = page.clone().with_setup(ModelProviderSetup {
        api_key_intake: true,
        providers: vec![ProviderOption::new(
            &definition.provider,
            &definition.policy,
        )],
    });
    assert_ne!(page.resource_basis(), configured.resource_basis());
    let before = serde_json::to_value(page).unwrap();
    let after = serde_json::to_value(&configured).unwrap();
    assert_eq!(before["connections"], after["connections"]);
    assert_eq!(before["management_revision"], after["management_revision"]);
    assert_eq!(
        after["setup"]["providers"][0]["policy"]["models"],
        serde_json::json!(["model-a"])
    );
    assert_ne!(
        configured
            .clone()
            .with_setup(ModelProviderSetup::default())
            .resource_basis(),
        configured.resource_basis()
    );
}

#[test]
fn organization_dependency_check_fails_closed_without_exposing_authority_rows() {
    assert_eq!(
        Fixture::new().page().has_organization_dependencies(),
        Some(true)
    );
    assert_eq!(
        ModelProvidersPage::Unavailable {
            reason: UnavailableReason::AuthorityUnavailable,
        }
        .has_organization_dependencies(),
        None,
    );
}
impl Fixture {
    fn new() -> Self {
        let mut store = Store::open_in_memory().unwrap();
        ready(&mut store);
        let state = store.fold::<ModelConnection>(&scope()).unwrap();
        let mut fixture = Self { store, state };
        fixture.apply(
            Capability::ManageGrants,
            Operation::Grant(access::Operation::Create {
                id: ModelGrantId::new("grant-a"),
                definition: access::GrantDefinition {
                    connection: connection(),
                    subject: access::Subject::Member(AuthorityId::new("member-a")),
                    policy: fixture.state.connections[&connection()]
                        .definition
                        .policy
                        .clone(),
                    audiences: [access::PrincipalClass::Member].into(),
                    caps: access::Caps {
                        tokens: Some(u64::MAX),
                        money: None,
                    },
                },
                subject_admission: ObservationId::new("must-not-expose-subject-proof"),
            }),
        );
        fixture
    }
    fn apply(&mut self, capability: Capability, operation: Operation) {
        let basis = match &operation {
            Operation::Spend(spend::Operation::Dispatch { id, .. }) => Basis::Dispatch {
                metadata: self.state.revision,
                attempt: id.clone(),
                revision: self.state.attempts[id].revision,
            },
            Operation::Spend(operation)
                if !matches!(operation, spend::Operation::Reserve { .. }) =>
            {
                let id = match operation {
                    spend::Operation::OutcomeUnknown { id, .. }
                    | spend::Operation::Correct { id, .. } => id.clone(),
                    _ => panic!("unexpected fixture operation"),
                };
                Basis::Attempt {
                    revision: self.state.attempts[&id].revision,
                    id,
                }
            }
            _ => Basis::Metadata(self.state.revision),
        };
        let command = Command {
            binding: binding(),
            actor: AuthorityId::new("trusted-fetch"),
            capability,
            basis,
            now: self.state.last_at + 1,
            operation,
        };
        self.state = self
            .store
            .admit::<ModelConnection>(&scope(), command)
            .unwrap();
    }
    fn invocation(&self) -> access::Invocation {
        access::Invocation {
            connection: connection(),
            version: version(),
            provider: self.state.connections[&connection()]
                .definition
                .provider
                .clone(),
            model: "model-a".into(),
            class: ExecutionClass::PrivateBroker,
            initiator: access::Initiator::Member(AuthorityId::new("member-a")),
            project: None,
            home: Some(HomeId::new("must-not-expose-work-home")),
            work: ObservationId::new("must-not-expose-work-proof"),
            final_fetch: AuthorityId::new("trusted-fetch"),
            request_digest: [74; 32],
        }
    }
    fn evidence(&self) -> access::ExecutionEvidence {
        access::ExecutionEvidence {
            observed: self.invocation(),
            current_identity_and_work: true,
            funding_admitted: true,
            private_plaintext_admitted: true,
            public_deployment_and_budget_admitted: false,
            observation: ObservationId::new("must-not-expose-execution-proof"),
        }
    }
    fn bound(tokens: u64) -> spend::Bound {
        spend::Bound {
            tokens,
            money: None,
            rate: None,
            enforcement: ObservationId::new("must-not-expose-adapter-revision"),
        }
    }
    fn reserve(&mut self, id: &str, tokens: u64) {
        self.apply(
            Capability::InvokeProvider,
            Operation::Spend(spend::Operation::Reserve {
                id: ModelAttemptId::new(id),
                invocation: self.invocation().into(),
                evidence: self.evidence().into(),
                bound: Self::bound(tokens),
                reserved_until: 1000,
                reconcile_by: 2000,
            }),
        );
    }
    fn dispatch(&mut self, id: &str) {
        let id = ModelAttemptId::new(id);
        let bound = self.state.attempts[&id].bound.clone();
        self.apply(
            Capability::InvokeProvider,
            Operation::Spend(spend::Operation::Dispatch {
                id,
                evidence: self.evidence().into(),
                bound,
            }),
        );
    }
    fn page(&self) -> ModelProvidersPage {
        project(&self.state, &binding(), self.state.last_at + 1).unwrap()
    }
    fn value(&self) -> Value {
        serde_json::to_value(self.page()).unwrap()
    }
}

#[test]
fn page_contains_metadata_not_custody_or_work_evidence_and_replays() {
    let mut fixture = Fixture::new();
    fixture.reserve("attempt-a", 5);
    fixture.dispatch("attempt-a");
    let value = fixture.value();
    // Shared with the real TypeScript wire reader. Fixture drift from this
    // event-derived producer fails the ordinary repository gate.
    assert_eq!(
        value,
        serde_json::from_str::<Value>(include_str!("page.fixture.json")).unwrap()
    );
    let text = serde_json::to_string(&value).unwrap();
    for prohibited in [
        "test-opaque-custody-handle",
        "isolated-provider-check",
        "must-not-expose",
        "request_digest",
        "final_fetch",
        "enforcement",
        "handle",
        "evidence",
        "refresh_token",
    ] {
        assert!(!text.contains(prohibited), "{prohibited}");
    }
    assert_eq!(value["connections"][0]["versions"][0]["phase"], "activated");
    assert_eq!(value["connections"][0]["versions"][0]["material"], "held");
    assert_eq!(value["grants"][0]["caps"]["tokens"], u64::MAX.to_string());
    assert_eq!(value["grants"][0]["usage"]["reserved"]["tokens"], "5");
    assert_eq!(
        value["grants"][0]["usage"]["reserved"]["unknown_money"],
        true
    );
    let decoded: ModelProvidersPage = serde_json::from_value(value).unwrap();
    assert_eq!(decoded, fixture.page());
    assert_eq!(
        project(
            &fixture.store.fold::<ModelConnection>(&scope()).unwrap(),
            &binding(),
            fixture.state.last_at + 1
        )
        .unwrap(),
        decoded
    );
}

#[test]
fn live_usage_and_clock_do_not_stale_settings_but_management_and_authority_do() {
    let mut fixture = Fixture::new();
    let basis = fixture.page().resource_basis();
    fixture.reserve("attempt-a", 2);
    fixture.dispatch("attempt-a");
    assert_eq!(fixture.page().resource_basis(), basis);
    assert_eq!(
        project(&fixture.state, &binding(), 10_000)
            .unwrap()
            .resource_basis(),
        basis
    );
    fixture.apply(
        Capability::ManageGrants,
        Operation::Grant(access::Operation::SetCaps {
            id: ModelGrantId::new("grant-a"),
            caps: access::Caps {
                tokens: Some(1),
                money: None,
            },
        }),
    );
    assert_ne!(fixture.page().resource_basis(), basis);
    for field in 0..3 {
        let mut other = binding();
        match field {
            0 => other.organization = ScopeId::new("wrong-organization"),
            1 => other.authority = AuthorityId::new("wrong-authority"),
            _ => other.environment = "live".into(),
        };
        assert!(project(&fixture.state, &other, 10_000).is_err());
        assert_ne!(
            project(&State::default(), &binding(), 1)
                .unwrap()
                .resource_basis(),
            project(&State::default(), &other, 1)
                .unwrap()
                .resource_basis()
        );
    }
    assert!(project(&fixture.state, &binding(), 1).is_err());
}

#[test]
fn unknown_bound_accounting_and_late_measurement_stay_distinct() {
    let mut fixture = Fixture::new();
    fixture.reserve("attempt-a", 10);
    fixture.dispatch("attempt-a");
    fixture.apply(
        Capability::ObserveUsage,
        Operation::Spend(spend::Operation::OutcomeUnknown {
            id: ModelAttemptId::new("attempt-a"),
            evidence: ObservationId::new("unknown-reference"),
        }),
    );
    let value = fixture.value();
    assert_eq!(value["grants"][0]["usage"]["unknown_outcomes"], "1");
    // Supply a genuine admitted deadline rather than changing folded state.
    let id = ModelAttemptId::new("attempt-a");
    fixture.state = fixture
        .store
        .admit::<ModelConnection>(
            &scope(),
            Command {
                binding: binding(),
                actor: AuthorityId::new("deadline-observer"),
                capability: Capability::ObserveDeadline,
                basis: Basis::Attempt {
                    id: id.clone(),
                    revision: fixture.state.attempts[&id].revision,
                },
                now: 2000,
                operation: Operation::Spend(spend::Operation::ReconcileDeadline { id: id.clone() }),
            },
        )
        .unwrap();
    let value = fixture.value();
    let usage = &value["grants"][0]["usage"];
    assert_eq!(usage["reserved"]["tokens"], "0");
    assert_eq!(usage["accounted_at_bound"]["tokens"], "10");
    assert_eq!(usage["measured"]["tokens"], "0");
    fixture.apply(
        Capability::ObserveUsage,
        Operation::Spend(spend::Operation::Correct {
            id,
            usage: spend::Usage {
                tokens: 7,
                money: None,
                rate: None,
                runtime: ObservationId::new("must-not-expose-runtime-reference"),
            },
            evidence: ObservationId::new("correction-reference"),
        }),
    );
    let value = fixture.value();
    let usage = &value["grants"][0]["usage"];
    assert_eq!(usage["accounted_at_bound"]["tokens"], "0");
    assert_eq!(usage["measured"]["tokens"], "7");
    assert_eq!(usage["unknown_outcomes"], "0");
    let month = spend::Month::at(fixture.state.last_at);
    let budget = &fixture.state.grants[&ModelGrantId::new("grant-a")].budget;
    assert_eq!(
        spend::period_usage(&fixture.state, budget, month)
            .unwrap()
            .total()
            .unwrap(),
        spend::totals(&fixture.state, budget, month).unwrap()
    );
    let next =
        serde_json::to_value(project(&fixture.state, &binding(), 31 * 86_400).unwrap()).unwrap();
    assert_eq!(next["grants"][0]["usage"]["measured"]["tokens"], "0");
}

#[test]
fn unavailable_is_not_an_empty_available_account_or_zero_allowance() {
    let page = ModelProvidersPage::Unavailable {
        reason: UnavailableReason::NotConfigured,
    };
    assert_eq!(
        serde_json::to_value(&page).unwrap(),
        serde_json::json!({"availability":"unavailable","reason":"not_configured"})
    );
    assert_eq!(page.management_revision(), None);
    assert_ne!(
        page.resource_basis(),
        project(&State::default(), &binding(), 1)
            .unwrap()
            .resource_basis()
    );
    let mut value = Fixture::new().value();
    value["connections"][0]["secret"] = serde_json::json!("must-not-accept");
    assert!(serde_json::from_value::<ModelProvidersPage>(value).is_err());
}

#[test]
fn totals_above_u64_and_unavailable_defaults_remain_explicit() {
    let mut fixture = Fixture::new();
    fixture.apply(
        Capability::ManageGrants,
        Operation::Grant(access::Operation::SetCaps {
            id: ModelGrantId::new("grant-a"),
            caps: access::Caps::default(),
        }),
    );
    fixture.reserve("attempt-a", u64::MAX);
    fixture.reserve("attempt-b", u64::MAX);
    assert_eq!(
        fixture.value()["grants"][0]["usage"]["reserved"]["tokens"],
        (u128::from(u64::MAX) * 2).to_string()
    );
    fixture.apply(
        Capability::ManageConnections,
        Operation::SetDefault {
            selection: Some(ModelSelection {
                connection: connection(),
                model: "model-a".into(),
            }),
        },
    );
    assert_eq!(fixture.value()["default_model"]["available"], true);
    fixture.apply(
        Capability::ManageConnections,
        Operation::Suspend {
            connection: connection(),
        },
    );
    assert_eq!(
        fixture.value()["default_model"],
        serde_json::json!({"connection":"connection-a","model":"model-a","available":false})
    );
}
