use super::*;
use crate::ids::{HomeId, ProjectId};
use crate::model_connection::access::{
    self, Caps, ExecutionEvidence, GrantDefinition, GrantStatus, Initiator, Invocation, Money,
    PrincipalClass, Project, Subject,
};
use crate::model_connection::spend::{self as ledger, Bound, Month, Phase, Usage};

fn member() -> AuthorityId {
    AuthorityId::new("member-a")
}
fn fetch() -> AuthorityId {
    AuthorityId::new("trusted-final-fetch")
}
fn project() -> Project {
    Project {
        authority: AuthorityId::new("client-project-authority"),
        id: ProjectId::new("project-a"),
    }
}
fn grant(n: u8) -> ModelGrantId {
    ModelGrantId::new(format!("grant-{n}"))
}
fn attempt(n: u8) -> ModelAttemptId {
    ModelAttemptId::new(format!("attempt-{n}"))
}
fn money(micros: u64) -> Money {
    Money {
        currency: "USD".to_owned().try_into().unwrap(),
        micros,
    }
}
fn caps(tokens: Option<u64>, micros: Option<u64>) -> Caps {
    Caps {
        tokens,
        money: micros.map(money),
    }
}
fn bound(tokens: u64) -> Bound {
    Bound {
        tokens,
        money: Some(money(tokens)),
        rate: Some(ObservationId::new("rate-v1")),
        enforcement: ObservationId::new("adapter-v1"),
    }
}
fn usage(tokens: u64) -> Usage {
    Usage {
        tokens,
        money: Some(money(tokens)),
        rate: Some(ObservationId::new("rate-v1")),
        runtime: ObservationId::new("trusted-runtime-usage"),
    }
}
fn invocation() -> Invocation {
    Invocation {
        connection: id(),
        version: version(1),
        provider: provider(),
        model: "model-a".into(),
        class: ExecutionClass::PrivateBroker,
        initiator: Initiator::Member(member()),
        project: Some(project()),
        home: Some(HomeId::new("project-home")),
        work: ObservationId::new("admitted-work"),
        final_fetch: fetch(),
        request_digest: [7; 32],
    }
}
fn admitted(invocation: &Invocation) -> ExecutionEvidence {
    ExecutionEvidence {
        observed: invocation.clone(),
        current_identity_and_work: true,
        funding_admitted: true,
        private_plaintext_admitted: true,
        public_deployment_and_budget_admitted: false,
        observation: ObservationId::new("current-admission"),
    }
}
fn create(n: u8, subject: Subject, caps: Caps) -> access::Operation {
    access::Operation::Create {
        id: grant(n),
        definition: GrantDefinition {
            connection: id(),
            subject,
            policy: policy(),
            audiences: [PrincipalClass::Member].into(),
            caps,
        },
        subject_admission: ObservationId::new("current-subject-admission"),
    }
}
fn reserve(n: u8, tokens: u64) -> ledger::Operation {
    let invocation = invocation();
    ledger::Operation::Reserve {
        id: attempt(n),
        evidence: admitted(&invocation).into(),
        invocation: invocation.into(),
        bound: bound(tokens),
        reserved_until: 100,
        reconcile_by: 200,
    }
}
fn dispatch(d: &Driver, n: u8) -> ledger::Operation {
    ledger::Operation::Dispatch {
        id: attempt(n),
        evidence: admitted(&invocation()).into(),
        bound: d.state.attempts[&attempt(n)].bound.clone(),
    }
}
fn settle(n: u8, tokens: u64) -> ledger::Operation {
    ledger::Operation::Settle {
        id: attempt(n),
        usage: usage(tokens),
        evidence: ObservationId::new(format!("settlement-{n}")),
    }
}

impl Driver {
    fn grant(&mut self, operation: access::Operation) {
        self.apply(Capability::ManageGrants, Operation::Grant(operation));
    }
    fn funded(member_cap: Caps, project_cap: Caps) -> Self {
        let mut driver = Self::active();
        driver.grant(create(1, Subject::Member(member()), member_cap));
        driver.grant(create(2, Subject::Project(project()), project_cap));
        driver
    }
    fn spending_command(&self, operation: ledger::Operation) -> Command {
        let mut command = self.command(operation.capability(), Operation::Spend(operation.clone()));
        command.actor = fetch();
        command.basis = match operation {
            ledger::Operation::Reserve { .. } => Basis::Metadata(self.state.revision),
            ledger::Operation::Dispatch { id, .. } => Basis::Dispatch {
                metadata: self.state.revision,
                revision: self.state.attempts[&id].revision,
                attempt: id,
            },
            ledger::Operation::Cancel { id }
            | ledger::Operation::Expire { id }
            | ledger::Operation::OutcomeUnknown { id, .. }
            | ledger::Operation::Settle { id, .. }
            | ledger::Operation::ReconcileDeadline { id }
            | ledger::Operation::Correct { id, .. }
            | ledger::Operation::ReconcileOverrun { id, .. } => Basis::Attempt {
                revision: self.state.attempts[&id].revision,
                id,
            },
        };
        command
    }
    fn spend(&mut self, operation: ledger::Operation) {
        self.submit(self.spending_command(operation)).unwrap();
        self.assert_replay();
    }
    fn deny_spend(&mut self, operation: ledger::Operation) {
        let before = self.state.clone();
        assert!(self.submit(self.spending_command(operation)).is_err());
        assert_eq!(before, self.state);
    }
    fn used(&self, n: u8, month: Month) -> ledger::Totals {
        ledger::totals(&self.state, &self.state.grants[&grant(n)].budget, month).unwrap()
    }
}

#[test]
fn both_subject_caps_apply_atomically_and_duplicate_subject_grants_count_once() {
    let mut d = Driver::funded(caps(Some(10), Some(10)), caps(Some(15), Some(15)));
    d.grant(create(3, Subject::Member(member()), Caps::default()));
    let metadata = d.state.revision;
    d.spend(reserve(1, 6));
    d.deny_spend(reserve(2, 5));
    assert_eq!(d.state.attempts.len(), 1);
    let month = Month::at(d.state.last_at);
    for n in 1..=3 {
        assert_eq!(d.used(n, month).tokens, 6);
    }
    d.spend(reserve(2, 4));
    assert_eq!(d.used(1, month).tokens, 10);
    assert_eq!(d.used(2, month).tokens, 10);
    assert_eq!(
        d.state.revision, metadata,
        "traffic must not churn management basis"
    );
}

#[test]
fn private_selection_discovery_is_exact_current_and_not_dispatch_authority() {
    let mut d = Driver::funded(Caps::default(), Caps::default());
    let choices = access::private_selection_options(&d.state, &member(), Some(&project()));
    assert_eq!(
        choices,
        vec![access::PrivateSelectionOption {
            connection: id(),
            models: ["model-a".into(), "model-b".into()].into(),
        }]
    );

    // A different project sees the member grant but not the exact-project
    // grant; narrowing that member grant therefore narrows its picker without
    // mutating or copying the underlying connection.
    d.grant(access::Operation::Edit {
        id: grant(1),
        policy: ModelPolicy {
            models: ["model-b".into()].into(),
            execution_classes: [ExecutionClass::PrivateBroker].into(),
        },
        audiences: [PrincipalClass::Member].into(),
        caps: Caps::default(),
    });
    let other = Project {
        authority: project().authority,
        id: ProjectId::new("project-b"),
    };
    assert_eq!(
        access::private_selection_options(&d.state, &member(), Some(&other))[0].models,
        ["model-b".into()].into(),
    );
    assert_eq!(
        access::private_selection_options(
            &d.state,
            &AuthorityId::new("different-member"),
            Some(&other),
        ),
        Vec::new(),
    );

    // Project and member grants are independent authorization sources. A
    // suspended member grant does not erase a current project grant, while a
    // suspended connection removes every selectable model.
    d.grant(access::Operation::Suspend { id: grant(1) });
    assert_eq!(
        access::private_selection_options(&d.state, &member(), Some(&project()))[0].models,
        ["model-a".into(), "model-b".into()].into(),
    );
    d.manage(Operation::Suspend { connection: id() });
    assert!(access::private_selection_options(&d.state, &member(), Some(&project())).is_empty());
}

#[test]
fn zero_caps_mean_no_use_and_absent_caps_are_independent() {
    for cap in [caps(Some(0), None), caps(None, Some(0))] {
        let mut d = Driver::funded(cap, Caps::default());
        d.deny_spend(reserve(1, 1));
    }
    let mut d = Driver::funded(caps(None, Some(5)), caps(Some(10), None));
    d.deny_spend(reserve(1, 6));
    d.spend(reserve(1, 5));
    d.deny_spend(reserve(2, 1));
}

#[test]
fn dedicated_cap_edits_preserve_consumption_and_do_not_widen_model_admission() {
    let mut d = Driver::funded(caps(Some(10), None), Caps::default());
    d.spend(reserve(1, 6));
    let original = d.state.grants[&grant(1)].clone();
    d.grant(access::Operation::SetCaps {
        id: grant(1),
        caps: caps(Some(5), None),
    });
    assert_eq!(d.used(1, Month::at(1)).tokens, 6);
    assert_eq!(d.state.grants[&grant(1)].budget, original.budget);
    assert_eq!(
        d.state.grants[&grant(1)].definition.policy,
        original.definition.policy
    );
    d.deny_spend(reserve(2, 1));
    d.grant(access::Operation::SetCaps {
        id: grant(1),
        caps: caps(Some(10), None),
    });
    d.spend(reserve(2, 4));
    d.deny_spend(reserve(3, 1));
    d.manage(Operation::SetModelPolicy {
        connection: id(),
        policy: ModelPolicy {
            models: BTreeSet::new(),
            execution_classes: [ExecutionClass::PrivateBroker].into(),
        },
    });
    d.grant(access::Operation::SetCaps {
        id: grant(1),
        caps: Caps::default(),
    });
    d.deny_spend(reserve(3, 1));
    d.grant(access::Operation::Revoke { id: grant(1) });
    d.deny(
        Capability::ManageGrants,
        Operation::Grant(access::Operation::SetCaps {
            id: grant(1),
            caps: Caps::default(),
        }),
    );
}

#[test]
fn request_identity_retries_cannot_rebind_scope_amount_or_deadline() {
    let mut d = Driver::funded(Caps::default(), Caps::default());
    d.spend(reserve(1, 3));
    let before = d.state.clone();
    d.spend(reserve(1, 3));
    assert_eq!(d.state, before);
    for field in 0..6 {
        let mut changed = reserve(1, 3);
        if let ledger::Operation::Reserve {
            invocation,
            bound,
            reserved_until,
            evidence,
            ..
        } = &mut changed
        {
            match field {
                0 => invocation.request_digest[0] = 8,
                1 => invocation.project = None,
                2 => invocation.initiator = Initiator::Service(member()),
                3 => bound.tokens += 1,
                4 => *reserved_until += 1,
                _ => invocation.final_fetch = AuthorityId::new("other-fetch"),
            }
            *evidence = admitted(invocation).into();
        }
        d.deny_spend(changed);
    }
    d.spend(dispatch(&d, 1));
    d.deny_spend(dispatch(&d, 1));
    d.spend(settle(1, 2));
    let terminal = d.state.clone();
    d.spend(reserve(1, 3));
    d.spend(settle(1, 2));
    assert_eq!(d.state, terminal);
}

#[test]
fn removing_a_known_project_member_or_plaintext_basis_is_not_an_escape() {
    for field in 0..9 {
        let mut d = Driver::funded(caps(Some(0), None), Caps::default());
        let mut request = reserve(1, 1);
        if let ledger::Operation::Reserve {
            invocation,
            evidence,
            ..
        } = &mut request
        {
            match field {
                0 => invocation.initiator = Initiator::Service(member()),
                1 => invocation.project = None,
                2 => evidence.current_identity_and_work = false,
                3 => evidence.funding_admitted = false,
                4 => evidence.private_plaintext_admitted = false,
                5 => invocation.provider.endpoint = "https://other.invalid".into(),
                6 => invocation.version = version(2),
                7 => invocation.home = None,
                _ => invocation.model = "unapproved-model".into(),
            }
            if field >= 5 {
                evidence.observed = (**invocation).clone();
            }
        }
        d.deny_spend(request);
    }
    // Genuine independently admitted service work has no fabricated member.
    let mut d = Driver::funded(caps(Some(0), None), Caps::default());
    d.grant(access::Operation::Edit {
        id: grant(2),
        policy: policy(),
        audiences: [PrincipalClass::Service].into(),
        caps: Caps::default(),
    });
    let mut request = reserve(1, 1);
    if let ledger::Operation::Reserve {
        invocation,
        evidence,
        ..
    } = &mut request
    {
        invocation.initiator = Initiator::Service(AuthorityId::new("admitted-service"));
        *evidence = admitted(invocation).into();
    }
    d.spend(request);
    assert_eq!(d.used(1, Month::at(1)).tokens, 0);
    assert_eq!(d.used(2, Month::at(1)).tokens, 1);
}

#[test]
fn a_more_permissive_model_grant_does_not_avoid_the_same_subject_budget() {
    let mut d = Driver::funded(caps(Some(0), None), Caps::default());
    let mut restricted = policy();
    restricted.models = ["model-b".into()].into();
    d.grant(access::Operation::Edit {
        id: grant(1),
        policy: restricted,
        audiences: [PrincipalClass::Member].into(),
        caps: caps(Some(0), None),
    });
    d.deny_spend(reserve(1, 1)); // project authorizes model-a; member still caps it
    d.grant(access::Operation::Revoke { id: grant(1) });
    d.spend(reserve(1, 1)); // revocation removes that source, not an eternal deny
}

#[test]
fn personal_work_can_select_member_funding_without_a_project_grant() {
    let mut d = Driver::active();
    d.grant(create(1, Subject::Member(member()), caps(Some(2), None)));
    let mut request = reserve(1, 2);
    if let ledger::Operation::Reserve {
        invocation,
        evidence,
        ..
    } = &mut request
    {
        invocation.project = None;
        *evidence = admitted(invocation).into();
    }
    d.spend(request);
    assert_eq!(d.state.attempts[&attempt(1)].grants.len(), 1);
}

#[test]
fn public_use_requires_project_grant_owner_deployment_budget_and_no_private_home() {
    let mut d = Driver::active();
    let mut public_policy = policy();
    public_policy
        .execution_classes
        .insert(ExecutionClass::PublicDirect);
    d.manage(Operation::SetModelPolicy {
        connection: id(),
        policy: public_policy.clone(),
    });
    let mut request = create(1, Subject::Project(project()), Caps::default());
    if let access::Operation::Create { definition, .. } = &mut request {
        definition.policy = public_policy.clone();
        definition.audiences = [PrincipalClass::PublicSession].into();
    }
    d.grant(request);
    let mut request = reserve(1, 1);
    if let ledger::Operation::Reserve {
        invocation,
        evidence,
        ..
    } = &mut request
    {
        invocation.class = ExecutionClass::PublicDirect;
        invocation.initiator = Initiator::PublicSession {
            deployment: "deployment".into(),
            session: "session".into(),
        };
        invocation.home = None;
        *evidence = admitted(invocation).into();
    }
    d.deny_spend(request.clone());
    if let ledger::Operation::Reserve { evidence, .. } = &mut request {
        evidence.public_deployment_and_budget_admitted = true;
    }
    d.spend(request);
    let mut member_request = create(2, Subject::Member(member()), Caps::default());
    if let access::Operation::Create { definition, .. } = &mut member_request {
        definition.policy = public_policy;
    }
    d.deny(Capability::ManageGrants, Operation::Grant(member_request));
}

#[test]
fn current_grants_and_membership_are_checked_again_before_single_dispatch() {
    for change in 0..6 {
        let mut d = Driver::funded(Caps::default(), Caps::default());
        d.spend(reserve(1, 3));
        let stale = d.spending_command(dispatch(&d, 1));
        match change {
            0 => d.grant(access::Operation::Suspend { id: grant(1) }),
            1 => d.grant(access::Operation::Edit {
                id: grant(1),
                policy: policy(),
                audiences: [PrincipalClass::Member].into(),
                caps: caps(Some(0), None),
            }),
            2 => {
                d.manage(replacement());
                Driver::ready(2, &mut d);
                d.manage(activate(2));
            }
            3 => d.manage(Operation::Suspend { connection: id() }),
            4 => d.manage(Operation::RequestErasure { connection: id() }),
            _ => d.grant(create(3, Subject::Member(member()), caps(Some(0), None))),
        }
        assert!(d.submit(stale).is_err());
        d.deny_spend(dispatch(&d, 1));
        d.spend(ledger::Operation::Cancel { id: attempt(1) });
    }
    let mut d = Driver::funded(Caps::default(), Caps::default());
    d.spend(reserve(1, 3));
    let mut request = dispatch(&d, 1);
    if let ledger::Operation::Dispatch { evidence, .. } = &mut request {
        evidence.current_identity_and_work = false;
    }
    d.deny_spend(request);
    d.spend(dispatch(&d, 1));
    d.deny_spend(dispatch(&d, 1));
}

#[test]
fn revocation_does_not_prevent_or_refund_inflight_settlement() {
    let mut d = Driver::funded(caps(Some(10), None), Caps::default());
    d.spend(reserve(1, 8));
    d.spend(dispatch(&d, 1));
    let mut settlement = d.spending_command(settle(1, 7));
    d.grant(access::Operation::Revoke { id: grant(1) });
    d.manage(Operation::RequestErasure { connection: id() });
    settlement.now = d.state.last_at + 1; // shell stamps admission, not provider time
    let mut wrong_actor = settlement.clone();
    wrong_actor.actor = member();
    assert!(d.submit(wrong_actor).is_err());
    d.submit(settlement).unwrap();
    assert_eq!(d.used(1, Month::at(1)).tokens, 7);
    assert_eq!(d.state.grants[&grant(1)].status, GrantStatus::Revoked);
    d.assert_replay();
}

#[test]
fn unknown_outcome_retains_bound_until_terminal_accounting_and_late_correction() {
    let mut d = Driver::funded(caps(Some(8), None), Caps::default());
    d.spend(reserve(1, 8));
    d.spend(dispatch(&d, 1));
    d.deny_spend(ledger::Operation::Cancel { id: attempt(1) });
    d.spend(ledger::Operation::OutcomeUnknown {
        id: attempt(1),
        evidence: evidence(),
    });
    d.deny_spend(reserve(2, 1));
    d.deny_spend(ledger::Operation::ReconcileDeadline { id: attempt(1) });
    let mut deadline = d.spending_command(ledger::Operation::ReconcileDeadline { id: attempt(1) });
    deadline.now = 200;
    d.submit(deadline).unwrap();
    assert_eq!(d.state.attempts[&attempt(1)].phase, Phase::AccountedAtBound);
    assert_eq!(d.used(1, Month::at(1)).tokens, 8);
    d.spend(ledger::Operation::Correct {
        id: attempt(1),
        usage: usage(5),
        evidence: ObservationId::new("late-actual"),
    });
    assert_eq!(d.used(1, Month::at(1)).tokens, 5);
    let terminal = d.state.clone();
    d.spend(ledger::Operation::Correct {
        id: attempt(1),
        usage: usage(5),
        evidence: ObservationId::new("late-actual"),
    });
    assert_eq!(d.state, terminal);
    d.deny_spend(ledger::Operation::Correct {
        id: attempt(1),
        usage: usage(4),
        evidence: ObservationId::new("late-actual"),
    });
}

#[test]
fn reserved_nonuse_releases_but_never_allows_later_dispatch() {
    let mut d = Driver::funded(caps(Some(2), None), Caps::default());
    d.spend(reserve(1, 2));
    d.deny_spend(ledger::Operation::Expire { id: attempt(1) });
    let mut expire = d.spending_command(ledger::Operation::Expire { id: attempt(1) });
    expire.now = 100;
    d.submit(expire).unwrap();
    assert_eq!(d.used(1, Month::at(1)).tokens, 0);
    d.deny_spend(dispatch(&d, 1));
    d.deny_spend(settle(1, 1));
    d.assert_replay();
}

#[test]
fn settlement_and_correction_remain_in_original_utc_month() {
    let mut d = Driver::funded(caps(Some(10), None), Caps::default());
    let mut request = reserve(1, 8);
    if let ledger::Operation::Reserve {
        reserved_until,
        reconcile_by,
        ..
    } = &mut request
    {
        *reserved_until = 2_678_410;
        *reconcile_by = 2_678_500;
    }
    let mut command = d.spending_command(request);
    command.now = 2_678_399; // Jan 31 23:59:59, 1970
    d.submit(command).unwrap();
    d.spend(dispatch(&d, 1)); // February
    d.spend(settle(1, 6));
    d.spend(ledger::Operation::Correct {
        id: attempt(1),
        usage: usage(7),
        evidence: ObservationId::new("correction"),
    });
    assert_eq!(
        d.used(
            1,
            Month {
                year: 1970,
                month: 1
            }
        )
        .tokens,
        7
    );
    assert_eq!(
        d.used(
            1,
            Month {
                year: 1970,
                month: 2
            }
        )
        .tokens,
        0
    );
    d.assert_replay();
}

#[test]
fn utc_month_uses_gregorian_centuries_and_bounded_large_timestamps() {
    for (seconds, year, month) in [
        (0, 1970, 1),
        (2_678_399, 1970, 1),
        (2_678_400, 1970, 2),
        (951_782_400, 2000, 2),
        (951_868_800, 2000, 3),
        (4_107_542_400, 2100, 3),
    ] {
        assert_eq!(Month::at(seconds), Month { year, month });
    }
    assert!((1..=12).contains(&Month::at(u64::MAX).month));
}

#[test]
fn grant_recreation_cap_edits_and_reconnection_keep_consumed_allowance() {
    let mut d = Driver::funded(caps(Some(5), None), Caps::default());
    d.spend(reserve(1, 5));
    d.spend(dispatch(&d, 1));
    d.spend(settle(1, 5));
    d.grant(access::Operation::Revoke { id: grant(1) });
    d.grant(create(3, Subject::Member(member()), caps(Some(5), None)));
    assert_eq!(
        d.state.grants[&grant(1)].budget,
        d.state.grants[&grant(3)].budget
    );
    d.deny_spend(reserve(2, 1));
    d.grant(access::Operation::Edit {
        id: grant(3),
        policy: policy(),
        audiences: [PrincipalClass::Member].into(),
        caps: caps(Some(4), None),
    });
    d.deny_spend(reserve(2, 1));
    d.manage(Operation::Revoke { connection: id() });
    let new_id = ModelConnectionId::new("reconnected");
    let mut reconnect = begin();
    if let Operation::BeginIntake {
        connection,
        reconnects,
        ..
    } = &mut reconnect
    {
        *connection = new_id.clone();
        *reconnects = Some(id());
    }
    d.manage(reconnect);
    for (capability, mut operation) in [
        (Capability::SealCandidate, seal(1)),
        (Capability::VerifyCandidate, verify(1, true)),
        (Capability::ManageConnections, activate(1)),
    ] {
        match &mut operation {
            Operation::RecordSealed {
                connection,
                handle: value,
                ..
            }
            | Operation::RecordVerification {
                connection,
                handle: value,
                ..
            } => {
                *connection = new_id.clone();
                *value = handle(2);
            }
            Operation::Activate { connection, .. } => *connection = new_id.clone(),
            _ => unreachable!(),
        }
        d.apply(capability, operation);
    }
    let mut recreated = create(4, Subject::Member(member()), caps(Some(5), None));
    if let access::Operation::Create { definition, .. } = &mut recreated {
        definition.connection = new_id.clone();
    }
    d.grant(recreated);
    assert_eq!(d.used(4, Month::at(1)).tokens, 5);
    let mut request = reserve(2, 1);
    if let ledger::Operation::Reserve {
        invocation,
        evidence,
        ..
    } = &mut request
    {
        invocation.connection = new_id;
        *evidence = admitted(invocation).into();
    }
    d.deny_spend(request);
}

#[test]
fn unsupported_pricing_currency_changes_and_large_integers_fail_closed() {
    let mut d = Driver::funded(caps(None, Some(10)), Caps::default());
    for field in 0..4 {
        let mut request = reserve(1, 1);
        if let ledger::Operation::Reserve { bound, .. } = &mut request {
            match field {
                0 => bound.money = None,
                1 => bound.rate = None,
                2 => bound.money.as_mut().unwrap().currency = "EUR".to_owned().try_into().unwrap(),
                _ => bound.tokens = 0,
            }
        }
        d.deny_spend(request);
    }
    let mut d = Driver::funded(caps(Some(u64::MAX), Some(u64::MAX)), Caps::default());
    d.spend(reserve(1, u64::MAX));
    d.deny_spend(reserve(2, 1));
    d.spend(dispatch(&d, 1));
    d.spend(settle(1, u64::MAX));
    d.deny_spend(reserve(2, 1));
    assert_eq!(d.used(1, Month::at(1)).tokens, u128::from(u64::MAX));
}

#[test]
fn introducing_a_money_cap_cannot_treat_unpriced_history_as_free() {
    let mut d = Driver::funded(caps(Some(100), None), Caps::default());
    let mut request = reserve(1, 5);
    if let ledger::Operation::Reserve { bound, .. } = &mut request {
        bound.money = None;
        bound.rate = None;
    }
    d.spend(request);
    d.spend(dispatch(&d, 1));
    let mut unpriced = usage(5);
    unpriced.money = None;
    unpriced.rate = None;
    d.spend(ledger::Operation::Settle {
        id: attempt(1),
        usage: unpriced,
        evidence: evidence(),
    });
    d.grant(access::Operation::Edit {
        id: grant(1),
        policy: policy(),
        audiences: [PrincipalClass::Member].into(),
        caps: caps(Some(100), Some(20)),
    });
    d.deny_spend(reserve(2, 1));
    d.spend(ledger::Operation::Correct {
        id: attempt(1),
        usage: usage(5),
        evidence: ObservationId::new("cost-reconciled"),
    });
    d.spend(reserve(2, 1));
}

#[test]
fn actual_overruns_are_unclamped_and_require_bound_repair_not_a_cap_reset() {
    let mut d = Driver::funded(caps(Some(100), Some(100)), Caps::default());
    d.spend(reserve(1, 5));
    d.spend(dispatch(&d, 1));
    d.spend(settle(1, 8));
    assert_eq!(d.used(1, Month::at(1)).tokens, 8);
    assert!(d.state.attempts[&attempt(1)].overrun);
    d.deny_spend(reserve(2, 1));
    let repair = ledger::Operation::ReconcileOverrun {
        id: attempt(1),
        repaired_enforcement: ObservationId::new("adapter-v2"),
        evidence: ObservationId::new("verified-bound-repair"),
    };
    let mut forged = d.spending_command(repair.clone());
    forged.capability = Capability::ManageGrants;
    assert!(d.submit(forged).is_err());
    d.spend(repair);
    d.deny_spend(reserve(2, 1)); // old broken enforcement never becomes eligible
    let mut request = reserve(2, 1);
    if let ledger::Operation::Reserve { bound, .. } = &mut request {
        bound.enforcement = ObservationId::new("adapter-v2");
    }
    d.spend(request);
    assert_eq!(d.used(1, Month::at(1)).tokens, 9);
}

#[test]
fn grants_have_exact_basis_approved_models_and_terminal_revocation() {
    let mut d = Driver::active();
    let request = create(1, Subject::Member(member()), Caps::default());
    d.deny(
        Capability::ManageConnections,
        Operation::Grant(request.clone()),
    );
    let stale = d.command(Capability::ManageGrants, Operation::Grant(request.clone()));
    d.grant(request.clone());
    assert!(d.submit(stale).is_err());
    d.deny(Capability::ManageGrants, Operation::Grant(request));
    let mut invalid_policy = policy();
    invalid_policy.models.insert("unknown-model".into());
    d.deny(
        Capability::ManageGrants,
        Operation::Grant(access::Operation::Edit {
            id: grant(1),
            policy: invalid_policy,
            audiences: [PrincipalClass::Member].into(),
            caps: Caps::default(),
        }),
    );
    d.grant(access::Operation::Suspend { id: grant(1) });
    d.deny_spend(reserve(1, 1));
    d.grant(access::Operation::Resume {
        id: grant(1),
        subject_admission: evidence(),
    });
    d.spend(reserve(1, 1));
    d.grant(access::Operation::Revoke { id: grant(1) });
    d.deny(
        Capability::ManageGrants,
        Operation::Grant(access::Operation::Resume {
            id: grant(1),
            subject_admission: evidence(),
        }),
    );
    d.deny(
        Capability::ManageGrants,
        Operation::Grant(access::Operation::Edit {
            id: grant(1),
            policy: policy(),
            audiences: [PrincipalClass::Member].into(),
            caps: Caps::default(),
        }),
    );
}

#[test]
fn a_recreated_member_cap_includes_use_funded_while_the_grant_was_revoked() {
    let mut d = Driver::funded(caps(Some(10), None), Caps::default());
    d.spend(reserve(1, 4));
    d.spend(dispatch(&d, 1));
    d.spend(settle(1, 4));
    d.grant(access::Operation::Revoke { id: grant(1) });
    d.spend(reserve(2, 6));
    assert_eq!(d.used(1, Month::at(1)).tokens, 10);
    d.grant(create(3, Subject::Member(member()), caps(Some(10), None)));
    d.deny_spend(reserve(3, 1));
}

#[test]
fn dispatch_requires_the_revalidated_exact_request_bound_and_audience() {
    let mut d = Driver::funded(Caps::default(), Caps::default());
    d.spend(reserve(1, 5));
    for field in 0..4 {
        let mut request = dispatch(&d, 1);
        if let ledger::Operation::Dispatch { bound, .. } = &mut request {
            match field {
                0 => bound.tokens += 1,
                1 => bound.rate = Some(ObservationId::new("different-rate")),
                2 => bound.enforcement = ObservationId::new("different-adapter"),
                _ => bound.money = None,
            }
        }
        d.deny_spend(request);
    }
    let mut wrong = d.spending_command(dispatch(&d, 1));
    wrong.actor = member();
    assert!(d.submit(wrong).is_err());
    d.spend(dispatch(&d, 1));
    let mut unknown_cost = settle(1, 3);
    if let ledger::Operation::Settle { usage, .. } = &mut unknown_cost {
        usage.money = None;
    }
    d.deny_spend(unknown_cost);
    assert_eq!(d.used(1, Month::at(1)).tokens, 5);
}

#[test]
fn accounting_wider_than_u64_is_retained_and_never_wraps_into_allowance() {
    let mut d = Driver::funded(Caps::default(), Caps::default());
    d.spend(reserve(1, u64::MAX));
    d.spend(reserve(2, u64::MAX));
    assert_eq!(d.used(1, Month::at(1)).tokens, u128::from(u64::MAX) * 2);
    d.grant(access::Operation::Edit {
        id: grant(1),
        policy: policy(),
        audiences: [PrincipalClass::Member].into(),
        caps: caps(Some(u64::MAX), Some(u64::MAX)),
    });
    d.deny_spend(reserve(3, 1));
}

#[test]
fn reconnect_cannot_widen_endpoint_or_supplant_a_live_connection() {
    let mut d = Driver::active();
    let mut request = begin();
    if let Operation::BeginIntake {
        connection,
        reconnects,
        ..
    } = &mut request
    {
        *connection = ModelConnectionId::new("reconnect");
        *reconnects = Some(id());
    }
    d.deny(Capability::ManageConnections, request.clone());
    d.manage(Operation::Revoke { connection: id() });
    if let Operation::BeginIntake { definition, .. } = &mut request {
        definition.provider.endpoint = "https://different.invalid".into();
    }
    d.deny(Capability::ManageConnections, request);
}

#[test]
fn original_intake_event_without_reconnection_field_keeps_its_budget_identity() {
    let d = Driver::active();
    let mut bytes = Vec::new();
    ciborium::into_writer(&d.events[0], &mut bytes).unwrap();
    let mut legacy: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
    if let ciborium::Value::Map(event) = &mut legacy {
        let change = event
            .iter_mut()
            .find(|(key, _)| key.as_text() == Some("change"))
            .unwrap();
        if let ciborium::Value::Map(change) = &mut change.1 {
            if let ciborium::Value::Map(intake) = &mut change[0].1 {
                let length = intake.len();
                intake.retain(|(key, _)| key.as_text() != Some("reconnects"));
                assert_eq!(intake.len(), length - 1);
            } else {
                panic!("intake fields");
            }
        } else {
            panic!("change variant");
        }
    } else {
        panic!("event fields");
    }
    let mut bytes = Vec::new();
    ciborium::into_writer(&legacy, &mut bytes).unwrap();
    let event: Event = ciborium::from_reader(bytes.as_slice()).unwrap();
    let state = evolve(&State::default(), event);
    assert_eq!(state.connections[&id()].budget_family, id());
}

proptest! {
    #[test]
    fn arbitrary_reservation_order_never_exceeds_either_subject_cap(
        member_cap in 0u64..100, project_cap in 0u64..100, sizes in prop::collection::vec(1u64..20, 0..25)
    ) {
        let mut d = Driver::funded(caps(Some(member_cap), Some(member_cap)), caps(Some(project_cap), Some(project_cap)));
        let mut expected = 0u128;
        for (index, size) in sizes.into_iter().enumerate() {
            let result = d.submit(d.spending_command(reserve(index as u8, size)));
            if expected + u128::from(size) <= u128::from(member_cap.min(project_cap)) {
                prop_assert!(result.is_ok()); expected += u128::from(size);
            } else { prop_assert!(result.is_err()); }
            prop_assert_eq!(d.used(1, Month::at(1)).tokens, expected);
            prop_assert_eq!(d.used(2, Month::at(1)).tokens, expected);
        }
        d.assert_replay();
    }
}
