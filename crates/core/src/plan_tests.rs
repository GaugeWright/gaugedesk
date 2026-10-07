use super::*;
use proptest::prelude::*;

const HOUR: u64 = 3_600_000;

fn a(name: &str) -> Authority {
    Authority::from(name)
}

fn apply(state: &PlanState, command: PlanCommand) -> Result<PlanState, Rejection> {
    decide(state, command)
        .map(|events| events.into_iter().fold(state.clone(), |s, e| evolve(&s, e)))
}

fn proposed(policy: SettlementPolicy) -> PlanState {
    apply(
        &PlanState::default(),
        PlanCommand::Propose {
            plan_id: "plan-1".into(),
            title: "Ship the importer".into(),
            proposer: a("P"),
            steps: vec![
                StepSpec {
                    id: "s1".into(),
                    title: "Parse".into(),
                    blocked_by: BTreeSet::new(),
                },
                StepSpec {
                    id: "s2".into(),
                    title: "Load".into(),
                    blocked_by: BTreeSet::from(["s1".to_string()]),
                },
            ],
            policy,
            at_ms: 0,
        },
    )
    .unwrap()
}

fn claim(step: &str, holder: &str, at_ms: u64) -> PlanCommand {
    PlanCommand::ClaimStep {
        step: step.into(),
        holder: a(holder),
        at_ms,
        lease_until_ms: at_ms + HOUR,
    }
}

fn record(step: &str, kind: EvidenceKind, author: &str, at_ms: u64) -> PlanCommand {
    PlanCommand::RecordEvidence {
        step: step.into(),
        kind,
        author: a(author),
        reference: "cut:abc123".into(),
        at_ms,
    }
}

fn settle(step: &str, evidence: &str, at_ms: u64) -> PlanCommand {
    PlanCommand::SettleStep {
        step: step.into(),
        evidence: evidence.into(),
        by: a("A"),
        at_ms,
    }
}

fn cause(reference: &str, reason: &str) -> ReopenCause {
    ReopenCause {
        reference: reference.into(),
        reason: reason.into(),
    }
}

#[test]
fn claim_work_attest_settle() {
    let s = proposed(SettlementPolicy::independent_attestation());
    assert_eq!(
        s.readiness("s2", 1),
        Some(Readiness::Blocked {
            by: BTreeSet::from(["s1".to_string()])
        })
    );
    let s = apply(&s, claim("s1", "A", 1)).unwrap();
    let s = apply(&s, record("s1", EvidenceKind::WorkRecord, "A", 2)).unwrap();
    let s = apply(&s, record("s1", EvidenceKind::Attestation, "B", 3)).unwrap();
    let s = apply(&s, settle("s1", "evidence-2", 4)).unwrap();
    assert_eq!(s.readiness("s1", 5), Some(Readiness::Settled));
    assert_eq!(s.steps["s1"].settlement.as_ref().unwrap().epoch, 0);
    assert_eq!(s.readiness("s2", 5), Some(Readiness::Ready));
    apply(&s, claim("s2", "B", 5)).unwrap();
}

#[test]
fn a_second_live_claim_is_refused_until_the_lease_lapses() {
    let s = apply(
        &proposed(SettlementPolicy::independent_attestation()),
        claim("s1", "A", 1),
    )
    .unwrap();
    assert!(apply(&s, claim("s1", "B", 2)).is_err());
    assert!(
        apply(&s, claim("s1", "A", 2)).is_err(),
        "even the holder's own"
    );
    let lapsed = apply(&s, claim("s1", "B", 1 + HOUR)).unwrap();
    assert_eq!(lapsed.steps["s1"].claim.as_ref().unwrap().holder, a("B"));
}

#[test]
fn release_frees_the_step() {
    let s = apply(
        &proposed(SettlementPolicy::independent_attestation()),
        claim("s1", "A", 1),
    )
    .unwrap();
    let release = |holder: &str| PlanCommand::ReleaseStep {
        step: "s1".into(),
        holder: a(holder),
        at_ms: 2,
    };
    assert!(apply(&s, release("B")).is_err());
    let s = apply(&s, release("A")).unwrap();
    apply(&s, claim("s1", "B", 3)).unwrap();
}

#[test]
fn a_blocked_step_cannot_be_claimed() {
    let s = proposed(SettlementPolicy::independent_attestation());
    assert_eq!(
        apply(&s, claim("s2", "A", 1)).unwrap_err().reason,
        "claim: a step blocking this one is not settled"
    );
}

#[test]
fn the_claimants_own_record_settles_only_where_policy_permits() {
    let s = apply(
        &proposed(SettlementPolicy::independent_attestation()),
        claim("s1", "A", 1),
    )
    .unwrap();
    let s = apply(&s, record("s1", EvidenceKind::Attestation, "A", 2)).unwrap();
    let s = apply(&s, record("s1", EvidenceKind::WorkRecord, "B", 3)).unwrap();
    assert_eq!(
        apply(&s, settle("s1", "evidence-1", 4)).unwrap_err().reason,
        "settle: the policy epoch does not accept the claimant's own record"
    );
    assert_eq!(
        apply(&s, settle("s1", "evidence-2", 4)).unwrap_err().reason,
        "settle: the policy epoch does not accept this kind of evidence"
    );
    let revised = apply(
        &s,
        PlanCommand::ReviseSettlementPolicy {
            policy: SettlementPolicy {
                accepts: BTreeSet::from([EvidenceKind::Attestation]),
                claimant_may_settle: true,
            },
            by: a("P"),
            at_ms: 5,
        },
    )
    .unwrap();
    assert_eq!(revised.epoch(), Some(1));
    assert_eq!(
        revised.policies[0],
        SettlementPolicy::independent_attestation()
    );
    let settled = apply(&revised, settle("s1", "evidence-1", 6)).unwrap();
    assert_eq!(settled.steps["s1"].settlement.as_ref().unwrap().epoch, 1);
}

#[test]
fn settlement_needs_a_claim_and_this_steps_evidence() {
    let s = proposed(SettlementPolicy::independent_attestation());
    let s = apply(&s, record("s1", EvidenceKind::Attestation, "B", 1)).unwrap();
    assert!(
        apply(&s, settle("s1", "evidence-1", 2)).is_err(),
        "unclaimed"
    );
    let s = apply(&s, claim("s1", "A", 2)).unwrap();
    assert!(
        apply(&s, settle("s2", "evidence-1", 3)).is_err(),
        "another step's"
    );
    assert!(apply(&s, settle("s1", "evidence-9", 3)).is_err(), "unknown");
}

#[test]
fn reopen_cites_a_cause_and_starts_a_new_cycle() {
    let s = apply(
        &proposed(SettlementPolicy::independent_attestation()),
        claim("s1", "A", 1),
    )
    .unwrap();
    let s = apply(&s, record("s1", EvidenceKind::Attestation, "B", 2)).unwrap();
    let s = apply(&s, settle("s1", "evidence-1", 3)).unwrap();
    let reopen = |c: ReopenCause| PlanCommand::ReopenStep {
        step: "s1".into(),
        cause: c,
        by: a("B"),
        at_ms: 4,
    };
    assert!(apply(&s, reopen(cause("", "regressed"))).is_err());
    assert!(apply(&s, reopen(cause("run:9", " "))).is_err());
    let s = apply(&s, reopen(cause("run:9", "the load step regressed"))).unwrap();
    assert_eq!(s.steps["s1"].cycle, 1);
    assert_eq!(s.readiness("s1", 5), Some(Readiness::Ready));
    assert_eq!(
        s.readiness("s2", 5).unwrap(),
        Readiness::Blocked {
            by: BTreeSet::from(["s1".to_string()])
        }
    );
    let s = apply(&s, claim("s1", "A", 5)).unwrap();
    assert_eq!(
        apply(&s, settle("s1", "evidence-1", 6)).unwrap_err().reason,
        "settle: the evidence predates the step's reopening"
    );
    let s = apply(&s, record("s1", EvidenceKind::Attestation, "B", 7)).unwrap();
    apply(&s, settle("s1", "evidence-2", 8)).unwrap();
}

#[test]
fn a_superseded_plan_refuses_every_decision() {
    let s = proposed(SettlementPolicy::independent_attestation());
    let supersede = |successor: &str| PlanCommand::Supersede {
        successor: successor.into(),
        reason: "split into two plans".into(),
        by: a("P"),
        at_ms: 1,
    };
    assert!(apply(&s, supersede("plan-1")).is_err(), "not itself");
    let s = apply(&s, supersede("plan-2")).unwrap();
    assert_eq!(s.phase, PlanPhase::Superseded);
    assert!(apply(&s, claim("s1", "A", 2)).is_err());
    assert!(apply(&s, supersede("plan-3")).is_err());
}

#[test]
fn a_proposal_must_be_well_formed() {
    let propose = |steps: Vec<StepSpec>| PlanCommand::Propose {
        plan_id: "p".into(),
        title: "t".into(),
        proposer: a("P"),
        steps,
        policy: SettlementPolicy::independent_attestation(),
        at_ms: 0,
    };
    let step = |id: &str, blocked: &[&str]| StepSpec {
        id: id.into(),
        title: id.into(),
        blocked_by: blocked.iter().map(|b| b.to_string()).collect(),
    };
    let init = PlanState::default();
    assert!(apply(&init, propose(vec![])).is_err());
    assert!(apply(&init, propose(vec![step("x", &["y"])])).is_err());
    assert!(apply(&init, propose(vec![step("x", &["y"]), step("y", &["x"])])).is_err());
    assert!(apply(&init, propose(vec![step("x", &["x"])])).is_err());
    assert!(apply(&init, propose(vec![step("x", &[]), step("x", &[])])).is_err());
    let s = apply(&init, propose(vec![step("x", &[]), step("y", &["x"])])).unwrap();
    assert!(
        apply(&s, propose(vec![step("z", &[])])).is_err(),
        "only once"
    );
}

#[derive(Clone, Debug)]
enum Op {
    Claim(usize, usize, u64),
    Release(usize, usize),
    Record(usize, bool, usize),
    Settle(usize, usize),
    Reopen(usize, bool),
    Revise(bool),
    Tick(u64),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0..2usize, 0..2usize, 1..3u64).prop_map(|(s, h, l)| Op::Claim(s, h, l)),
        (0..2usize, 0..2usize).prop_map(|(s, h)| Op::Release(s, h)),
        (0..2usize, any::<bool>(), 0..2usize).prop_map(|(s, k, a)| Op::Record(s, k, a)),
        (0..2usize, 1..6usize).prop_map(|(s, e)| Op::Settle(s, e)),
        (0..2usize, any::<bool>()).prop_map(|(s, c)| Op::Reopen(s, c)),
        any::<bool>().prop_map(Op::Revise),
        (1..3u64).prop_map(Op::Tick),
    ]
}

proptest! {
    /// The model's invariants, over random admitted histories.
    #[test]
    fn the_three_rules_hold(ops in proptest::collection::vec(op(), 0..40)) {
        let steps = ["s1", "s2"];
        let people = ["A", "B"];
        let mut s = proposed(SettlementPolicy::independent_attestation());
        let mut now = 1u64;
        for op in ops {
            let command = match op {
                Op::Tick(t) => { now += t * HOUR / 2; continue; }
                Op::Claim(i, h, l) => PlanCommand::ClaimStep {
                    step: steps[i].into(), holder: a(people[h]), at_ms: now,
                    lease_until_ms: now + l * HOUR / 2,
                },
                Op::Release(i, h) => PlanCommand::ReleaseStep {
                    step: steps[i].into(), holder: a(people[h]), at_ms: now,
                },
                Op::Record(i, k, au) => record(
                    steps[i],
                    if k { EvidenceKind::Attestation } else { EvidenceKind::WorkRecord },
                    people[au],
                    now,
                ),
                Op::Settle(i, e) => settle(steps[i], &format!("evidence-{e}"), now),
                Op::Reopen(i, c) => PlanCommand::ReopenStep {
                    step: steps[i].into(),
                    cause: if c { cause("run:1", "regressed") } else { cause("", "") },
                    by: a("B"), at_ms: now,
                },
                Op::Revise(own) => PlanCommand::ReviseSettlementPolicy {
                    policy: SettlementPolicy {
                        accepts: BTreeSet::from([EvidenceKind::Attestation, EvidenceKind::WorkRecord]),
                        claimant_may_settle: own,
                    },
                    by: a("P"), at_ms: now,
                },
            };
            let before = s.clone();
            let Ok(events) = decide(&s, command) else { continue };
            for event in events {
                match &event {
                    // Rule 1: never a claim over a live one.
                    PlanEvent::StepClaimed { step, at_ms, .. } => {
                        let st = &before.steps[step];
                        prop_assert!(!st.claim.as_ref().is_some_and(|c| c.is_live(*at_ms)));
                        prop_assert!(before.unsettled_blockers(st).is_empty());
                    }
                    // Rule 2: settled on accepted evidence of the current cycle.
                    PlanEvent::StepSettled { step, evidence, epoch, .. } => {
                        let st = &before.steps[step];
                        let ev = &before.evidence[evidence];
                        let policy = &before.policies[*epoch as usize];
                        prop_assert_eq!(Some(*epoch), before.epoch());
                        prop_assert_eq!(ev.cycle, st.cycle);
                        prop_assert!(policy.accepts.contains(&ev.kind));
                        prop_assert!(ev.author != st.claim.as_ref().unwrap().holder
                            || policy.claimant_may_settle);
                    }
                    // Rule 3: a cause is cited.
                    PlanEvent::StepReopened { cause, .. } => {
                        prop_assert!(!cause.reference.trim().is_empty());
                        prop_assert!(!cause.reason.trim().is_empty());
                    }
                    _ => {}
                }
                s = evolve(&s, event);
            }
        }
    }
}
