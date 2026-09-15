use super::*;
use gaugedesk_core::ids::{HomeId, ModelAttemptId, ModelGrantId, ProjectId};
use gaugedesk_core::model_connection::access::{
    self, Caps, ExecutionEvidence, GrantDefinition, Initiator, Invocation, Money, PrincipalClass,
    Project, Subject,
};
use gaugedesk_core::model_connection::spend::{self as ledger, Bound, Month, Phase, Usage};
use gaugedesk_core::model_connection::State;

fn member() -> AuthorityId {
    AuthorityId::new("member")
}
fn fetch() -> AuthorityId {
    AuthorityId::new("trusted-final-fetch")
}
fn project() -> Project {
    Project {
        authority: AuthorityId::new("client-authority"),
        id: ProjectId::new("project"),
    }
}
fn grant(n: u8) -> ModelGrantId {
    ModelGrantId::new(format!("grant-{n}"))
}
fn attempt(n: u8) -> ModelAttemptId {
    ModelAttemptId::new(format!("attempt-{n}"))
}
fn money(tokens: u64) -> Money {
    Money {
        currency: "USD".to_owned().try_into().unwrap(),
        micros: tokens,
    }
}
fn ready(store: &mut Store, member_cap: u64, project_cap: u64) -> State {
    let start = store
        .admit_materialized::<ModelConnection>(
            SCOPE,
            "begin",
            command(0, Capability::ManageConnections, begin()),
        )
        .unwrap()
        .state;
    let provider = start.connections[&id()].definition.provider.clone();
    let policy = start.connections[&id()].definition.policy.clone();
    let mut state = start;
    for (key, capability, operation) in [
        (
            "seal",
            Capability::SealCandidate,
            Operation::RecordSealed {
                connection: id(),
                version: version(),
                handle: handle(),
            },
        ),
        (
            "verify",
            Capability::VerifyCandidate,
            Operation::RecordVerification {
                connection: id(),
                version: version(),
                provider,
                handle: handle(),
                evidence: ObservationId::new("verified"),
                check: gaugedesk_core::model_connection::VerificationCheck::ModelCatalogRead,
                passed: true,
            },
        ),
        (
            "activate",
            Capability::ManageConnections,
            Operation::Activate {
                connection: id(),
                version: version(),
            },
        ),
    ] {
        state = store
            .admit_materialized::<ModelConnection>(
                SCOPE,
                key,
                command(state.revision, capability, operation),
            )
            .unwrap()
            .state;
    }
    for (n, subject, cap) in [
        (1, Subject::Member(member()), member_cap),
        (2, Subject::Project(project()), project_cap),
    ] {
        state = store
            .admit_materialized::<ModelConnection>(
                SCOPE,
                &format!("grant-{n}"),
                command(
                    state.revision,
                    Capability::ManageGrants,
                    Operation::Grant(access::Operation::Create {
                        id: grant(n),
                        definition: GrantDefinition {
                            connection: id(),
                            subject,
                            policy: policy.clone(),
                            audiences: [PrincipalClass::Member].into(),
                            caps: Caps {
                                tokens: Some(cap),
                                money: Some(money(cap)),
                            },
                        },
                        subject_admission: ObservationId::new("current-subject"),
                    }),
                ),
            )
            .unwrap()
            .state;
    }
    state
}
fn invocation(state: &State) -> Invocation {
    Invocation {
        connection: id(),
        version: version(),
        provider: state.connections[&id()].definition.provider.clone(),
        model: "test-model".into(),
        class: ExecutionClass::PrivateBroker,
        initiator: Initiator::Member(member()),
        project: Some(project()),
        home: Some(HomeId::new("project-home")),
        work: ObservationId::new("current-work"),
        final_fetch: fetch(),
        request_digest: [9; 32],
    }
}
fn evidence(invocation: &Invocation) -> ExecutionEvidence {
    ExecutionEvidence {
        observed: invocation.clone(),
        current_identity_and_work: true,
        funding_admitted: true,
        private_plaintext_admitted: true,
        public_deployment_and_budget_admitted: false,
        observation: ObservationId::new("admission"),
    }
}
fn reserve(state: &State, n: u8, tokens: u64) -> Command {
    let invocation = invocation(state);
    let mut input = command(
        state.revision,
        Capability::InvokeProvider,
        Operation::Spend(ledger::Operation::Reserve {
            id: attempt(n),
            evidence: evidence(&invocation).into(),
            invocation: invocation.into(),
            bound: Bound {
                tokens,
                money: Some(money(tokens)),
                rate: Some(ObservationId::new("rate")),
                enforcement: ObservationId::new("bounded-adapter"),
            },
            reserved_until: 1000,
            reconcile_by: 2000,
        }),
    );
    input.actor = fetch();
    input.now = 100;
    input
}
fn subsequent(
    state: &State,
    n: u8,
    capability: Capability,
    operation: ledger::Operation,
) -> Command {
    let mut input = command(
        state.revision,
        capability,
        Operation::Spend(operation.clone()),
    );
    input.actor = fetch();
    input.now = state.last_at + 1;
    input.basis = if matches!(operation, ledger::Operation::Dispatch { .. }) {
        Basis::Dispatch {
            metadata: state.revision,
            attempt: attempt(n),
            revision: state.attempts[&attempt(n)].revision,
        }
    } else {
        Basis::Attempt {
            id: attempt(n),
            revision: state.attempts[&attempt(n)].revision,
        }
    };
    input
}
fn dispatch(state: &State, n: u8) -> Command {
    let current = &state.attempts[&attempt(n)];
    subsequent(
        state,
        n,
        Capability::InvokeProvider,
        ledger::Operation::Dispatch {
            id: attempt(n),
            evidence: evidence(&current.invocation).into(),
            bound: current.bound.clone(),
        },
    )
}
fn reopen(path: &std::path::Path, expected: &State) -> Store {
    let store = Store::open(path.to_str().unwrap()).unwrap();
    assert_eq!(store.fold::<ModelConnection>(SCOPE).unwrap(), *expected);
    store
}

#[test]
fn separate_sqlite_writers_reserve_all_subject_caps_without_a_partial_commit() {
    for (member_cap, project_cap) in [(10, 20), (20, 10)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spend.sqlite");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        let state = ready(&mut store, member_cap, project_cap);
        let barrier = Arc::new(Barrier::new(2));
        let mut threads = Vec::new();
        for n in 0..2 {
            let path = path.clone();
            let barrier = barrier.clone();
            let input = reserve(&state, n, 7);
            threads.push(std::thread::spawn(move || {
                let mut store = Store::open(path.to_str().unwrap()).unwrap();
                barrier.wait();
                store.admit_materialized::<ModelConnection>(SCOPE, &format!("reserve-{n}"), input)
            }));
        }
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
            format!("{error:?}").contains("monthly token cap exhausted"),
            "{error:?}"
        );
        let folded = store.fold::<ModelConnection>(SCOPE).unwrap();
        assert_eq!(folded.attempts.len(), 1);
        assert_eq!(
            folded.revision, state.revision,
            "budget checks, not stale metadata, denied the competitor"
        );
        for n in 1..=2 {
            assert_eq!(
                ledger::totals(&folded, &folded.grants[&grant(n)].budget, Month::at(100))
                    .unwrap()
                    .tokens,
                7
            );
        }
        let first = folded.attempts.keys().next().unwrap();
        let n = if first == &attempt(0) { 0 } else { 1 };
        let retry = store
            .admit_materialized::<ModelConnection>(
                SCOPE,
                &format!("reserve-{n}"),
                reserve(&state, n, 7),
            )
            .unwrap();
        assert!(retry.replayed);
        assert_eq!(retry.state, folded);
        assert!(store
            .admit_materialized::<ModelConnection>(
                SCOPE,
                &format!("reserve-{n}"),
                reserve(&state, n, 8)
            )
            .is_err());
        assert!(store
            .admit_materialized::<ModelConnection>(
                SCOPE,
                "different-key-same-attempt",
                reserve(&state, n, 8)
            )
            .is_err());
        drop(store);
        drop(reopen(&path, &folded));
    }
}

#[test]
fn competing_dispatches_consume_one_fence_and_restart_keeps_unknown_accounting() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attempt.sqlite");
    let mut store = Store::open(path.to_str().unwrap()).unwrap();
    let mut state = ready(&mut store, 10, 10);
    state = store
        .admit_materialized::<ModelConnection>(SCOPE, "reserve", reserve(&state, 1, 7))
        .unwrap()
        .state;
    drop(store);
    let store = reopen(&path, &state);
    drop(store);
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|n| {
            let path = path.clone();
            let barrier = barrier.clone();
            let input = dispatch(&state, 1);
            std::thread::spawn(move || {
                let mut store = Store::open(path.to_str().unwrap()).unwrap();
                barrier.wait();
                store.admit_materialized::<ModelConnection>(SCOPE, &format!("dispatch-{n}"), input)
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    state = results.into_iter().find_map(Result::ok).unwrap().state;
    assert_eq!(state.attempts[&attempt(1)].phase, Phase::Dispatched);
    let mut store = reopen(&path, &state);
    // An adapter must never turn a replayed dispatch receipt into another fetch.
    // The ledger also rejects a newly keyed dispatch against the current state.
    assert!(store
        .admit_materialized::<ModelConnection>(SCOPE, "second-fetch", dispatch(&state, 1))
        .is_err());
    state = store
        .admit_materialized::<ModelConnection>(
            SCOPE,
            "unknown",
            subsequent(
                &state,
                1,
                Capability::ObserveUsage,
                ledger::Operation::OutcomeUnknown {
                    id: attempt(1),
                    evidence: ObservationId::new("timeout"),
                },
            ),
        )
        .unwrap()
        .state;
    drop(store);
    let mut store = reopen(&path, &state);
    let mut deadline = subsequent(
        &state,
        1,
        Capability::ObserveDeadline,
        ledger::Operation::ReconcileDeadline { id: attempt(1) },
    );
    deadline.now = 2000;
    state = store
        .admit_materialized::<ModelConnection>(SCOPE, "deadline", deadline)
        .unwrap()
        .state;
    assert_eq!(state.attempts[&attempt(1)].phase, Phase::AccountedAtBound);
    drop(store);
    let mut store = reopen(&path, &state);
    let correction = subsequent(
        &state,
        1,
        Capability::ObserveUsage,
        ledger::Operation::Correct {
            id: attempt(1),
            usage: Usage {
                tokens: 5,
                money: Some(money(5)),
                rate: Some(ObservationId::new("rate")),
                runtime: ObservationId::new("runtime-usage"),
            },
            evidence: ObservationId::new("actual-usage"),
        },
    );
    state = store
        .admit_materialized::<ModelConnection>(SCOPE, "actual", correction.clone())
        .unwrap()
        .state;
    drop(store);
    let mut store = reopen(&path, &state);
    let replay = store
        .admit_materialized::<ModelConnection>(SCOPE, "actual", correction)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.state, state);
    for n in 1..=2 {
        assert_eq!(
            ledger::totals(&state, &state.grants[&grant(n)].budget, Month::at(100))
                .unwrap()
                .tokens,
            5
        );
    }
}
