//! Plan standing — the `(decide, evolve)` reducer for a plan as governed work,
//! ported from `specs/models/plan.qnt` (DR-0386; GaugeWright DR-0103 row 4).
//!
//! A plan is a parent work item and its steps are work items linked by
//! `blocks`. Readiness is computed from those links and from claims, never
//! stored. The Home admits the plan's standing as decisions — `stepClaimed`,
//! `stepSettled`, `stepReopened` and `planSuperseded`, beside the proposal,
//! release, evidence and policy-revision events that give them something to
//! decide over — under three rules:
//!
//! 1. **One live claim per step.** A claim is refused while another claim on
//!    the step is live (its lease has not lapsed at the admitted time).
//! 2. **Settlement only on evidence the current policy epoch accepts.** The
//!    evidence must be recorded against the step in its current cycle, be of a
//!    kind the current epoch accepts, and, when its author is the step's
//!    holder, the epoch must permit the claimant's own record to settle.
//! 3. **A reopen cites a cause.** A reference and a reason, both non-empty.
//!
//! Both functions are pure: the admission shell authenticates every actor and
//! stamps every time before a command reaches `decide`.

use std::collections::{BTreeMap, BTreeSet};

use crate::boundary::Authority;
use crate::Rejection;

/// The log discriminator of a plan's events, which are customer content.
pub const PLAN_KIND: &str = "work_plan";

/// What a piece of evidence is. A person records either; who recorded it,
/// relative to the step's holder, is what the policy rules on.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Someone vouches for the exact version of the work they examined.
    Attestation,
    /// A record of the work itself, such as the cut or run it produced.
    WorkRecord,
}

/// The settlement policy of one epoch. A published epoch is never edited; a
/// revision mints the next epoch (policy-epoch.qnt's discipline).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettlementPolicy {
    /// The kinds of evidence this epoch accepts.
    pub accepts: BTreeSet<EvidenceKind>,
    /// Whether evidence recorded by the step's own holder may settle it.
    pub claimant_may_settle: bool,
}

impl SettlementPolicy {
    /// The default: an attestation by someone other than the holder.
    pub fn independent_attestation() -> Self {
        Self {
            accepts: BTreeSet::from([EvidenceKind::Attestation]),
            claimant_may_settle: false,
        }
    }
}

/// A step as proposed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepSpec {
    pub id: String,
    pub title: String,
    /// The steps that block this one: it is ready only once each is settled.
    #[serde(default)]
    pub blocked_by: BTreeSet<String>,
}

/// A claim on a step. It stays the step's record of who holds the current
/// cycle after its lease lapses; it is *live* only until `lease_until_ms`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StepClaim {
    pub holder: Authority,
    pub claimed_at_ms: u64,
    pub lease_until_ms: u64,
}

impl StepClaim {
    pub fn is_live(&self, now_ms: u64) -> bool {
        now_ms < self.lease_until_ms
    }
}

/// Evidence recorded against a step, as an observation the Home admitted.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Evidence {
    pub id: String,
    pub step: String,
    pub kind: EvidenceKind,
    pub author: Authority,
    /// What it vouches for — the version reviewed, the cut produced.
    pub reference: String,
    /// The step's cycle when it was recorded; a reopen starts a new cycle.
    pub cycle: u32,
    pub recorded_at_ms: u64,
}

/// Why a settled step is reopened.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReopenCause {
    /// What the cause is about: the finding, the regression, the run.
    pub reference: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StepSettlement {
    pub evidence: String,
    pub epoch: u32,
    pub by: Authority,
    pub at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StepState {
    pub title: String,
    pub blocked_by: BTreeSet<String>,
    pub cycle: u32,
    pub claim: Option<StepClaim>,
    pub settlement: Option<StepSettlement>,
    pub reopened: Vec<ReopenCause>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PlanPhase {
    Init,
    Active,
    /// Terminal: every later decision is refused.
    Superseded,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PlanState {
    pub phase: PlanPhase,
    pub plan_id: String,
    pub title: String,
    pub proposer: Option<Authority>,
    /// One policy per epoch; the current epoch is the last.
    pub policies: Vec<SettlementPolicy>,
    pub steps: BTreeMap<String, StepState>,
    pub evidence: BTreeMap<String, Evidence>,
    pub superseded_by: Option<String>,
}

impl Default for PlanState {
    fn default() -> Self {
        Self {
            phase: PlanPhase::Init,
            plan_id: String::new(),
            title: String::new(),
            proposer: None,
            policies: Vec::new(),
            steps: BTreeMap::new(),
            evidence: BTreeMap::new(),
            superseded_by: None,
        }
    }
}

/// Where a step stands at a moment — computed, never stored.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Readiness {
    /// Waiting on the named unsettled steps.
    Blocked {
        by: BTreeSet<String>,
    },
    Ready,
    Claimed {
        holder: Authority,
        lease_until_ms: u64,
    },
    Settled,
}

impl PlanState {
    /// The current epoch, if the plan has been proposed.
    pub fn epoch(&self) -> Option<u32> {
        self.policies.len().checked_sub(1).map(|e| e as u32)
    }

    pub fn readiness(&self, step: &str, now_ms: u64) -> Option<Readiness> {
        let state = self.steps.get(step)?;
        if state.settlement.is_some() {
            return Some(Readiness::Settled);
        }
        if let Some(claim) = state.claim.as_ref().filter(|c| c.is_live(now_ms)) {
            return Some(Readiness::Claimed {
                holder: claim.holder.clone(),
                lease_until_ms: claim.lease_until_ms,
            });
        }
        let by = self.unsettled_blockers(state);
        Some(if by.is_empty() {
            Readiness::Ready
        } else {
            Readiness::Blocked { by }
        })
    }

    fn unsettled_blockers(&self, step: &StepState) -> BTreeSet<String> {
        step.blocked_by
            .iter()
            .filter(|b| self.steps.get(*b).is_none_or(|s| s.settlement.is_none()))
            .cloned()
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PlanCommand {
    Propose {
        plan_id: String,
        title: String,
        proposer: Authority,
        steps: Vec<StepSpec>,
        policy: SettlementPolicy,
        at_ms: u64,
    },
    ClaimStep {
        step: String,
        holder: Authority,
        at_ms: u64,
        lease_until_ms: u64,
    },
    ReleaseStep {
        step: String,
        holder: Authority,
        at_ms: u64,
    },
    RecordEvidence {
        step: String,
        kind: EvidenceKind,
        author: Authority,
        reference: String,
        at_ms: u64,
    },
    SettleStep {
        step: String,
        evidence: String,
        by: Authority,
        at_ms: u64,
    },
    ReopenStep {
        step: String,
        cause: ReopenCause,
        by: Authority,
        at_ms: u64,
    },
    ReviseSettlementPolicy {
        policy: SettlementPolicy,
        by: Authority,
        at_ms: u64,
    },
    Supersede {
        successor: String,
        reason: String,
        by: Authority,
        at_ms: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PlanEvent {
    PlanProposed {
        plan_id: String,
        title: String,
        proposer: Authority,
        steps: Vec<StepSpec>,
        policy: SettlementPolicy,
        at_ms: u64,
    },
    StepClaimed {
        step: String,
        holder: Authority,
        at_ms: u64,
        lease_until_ms: u64,
    },
    StepReleased {
        step: String,
        holder: Authority,
        at_ms: u64,
    },
    EvidenceRecorded(Evidence),
    StepSettled {
        step: String,
        evidence: String,
        epoch: u32,
        by: Authority,
        at_ms: u64,
    },
    StepReopened {
        step: String,
        cause: ReopenCause,
        by: Authority,
        at_ms: u64,
    },
    SettlementPolicyRevised {
        epoch: u32,
        policy: SettlementPolicy,
        by: Authority,
        at_ms: u64,
    },
    PlanSuperseded {
        successor: String,
        reason: String,
        by: Authority,
        at_ms: u64,
    },
}

fn reject(reason: &'static str) -> Result<Vec<PlanEvent>, Rejection> {
    Err(Rejection { reason })
}

fn blank(s: &str) -> bool {
    s.trim().is_empty()
}

fn valid_policy(policy: &SettlementPolicy) -> bool {
    !policy.accepts.is_empty()
}

/// Steps must be named, unique, blocked only by steps of this plan, and
/// acyclic, so readiness is always computable.
fn valid_steps(steps: &[StepSpec]) -> Result<(), &'static str> {
    if steps.is_empty() {
        return Err("propose: a plan needs at least one step");
    }
    let mut ids = BTreeSet::new();
    for step in steps {
        if blank(&step.id) || blank(&step.title) {
            return Err("propose: every step needs an id and a title");
        }
        if !ids.insert(step.id.as_str()) {
            return Err("propose: step ids must be unique");
        }
    }
    let graph: BTreeMap<&str, &BTreeSet<String>> = steps
        .iter()
        .map(|s| (s.id.as_str(), &s.blocked_by))
        .collect();
    if graph
        .values()
        .any(|blockers| blockers.iter().any(|b| !graph.contains_key(b.as_str())))
    {
        return Err("propose: a step is blocked by a step outside the plan");
    }
    // Kahn's algorithm: every step must eventually have no unsettled blocker.
    let mut done: BTreeSet<&str> = BTreeSet::new();
    loop {
        let next: Vec<&str> = graph
            .iter()
            .filter(|(id, blockers)| {
                !done.contains(*id) && blockers.iter().all(|b| done.contains(b.as_str()))
            })
            .map(|(id, _)| *id)
            .collect();
        if next.is_empty() {
            break;
        }
        done.extend(next);
    }
    if done.len() != graph.len() {
        return Err("propose: the steps' blocks relations form a cycle");
    }
    Ok(())
}

/// `decide` — **pure**. Reads only state and command.
pub fn decide(state: &PlanState, command: PlanCommand) -> Result<Vec<PlanEvent>, Rejection> {
    if let PlanCommand::Propose {
        plan_id,
        title,
        proposer,
        steps,
        policy,
        at_ms,
    } = command
    {
        if state.phase != PlanPhase::Init {
            return reject("propose: the plan already exists");
        }
        if blank(&plan_id) || blank(&title) {
            return reject("propose: a plan needs an id and a title");
        }
        if !valid_policy(&policy) {
            return reject("propose: the settlement policy accepts no evidence");
        }
        valid_steps(&steps).map_err(|reason| Rejection { reason })?;
        return Ok(vec![PlanEvent::PlanProposed {
            plan_id,
            title,
            proposer,
            steps,
            policy,
            at_ms,
        }]);
    }
    match state.phase {
        PlanPhase::Init => return reject("the plan has not been proposed"),
        PlanPhase::Superseded => return reject("the plan is superseded"),
        PlanPhase::Active => {}
    }
    match command {
        PlanCommand::Propose { .. } => unreachable!("handled above"),
        PlanCommand::ClaimStep {
            step,
            holder,
            at_ms,
            lease_until_ms,
        } => {
            let Some(current) = state.steps.get(&step) else {
                return reject("claim: no such step");
            };
            if current.settlement.is_some() {
                return reject("claim: the step is settled");
            }
            // Rule 1: one live claim per step — the holder's own included;
            // a claim is extended by releasing and claiming again.
            if current.claim.as_ref().is_some_and(|c| c.is_live(at_ms)) {
                return reject("claim: the step already has a live claim");
            }
            if !state.unsettled_blockers(current).is_empty() {
                return reject("claim: a step blocking this one is not settled");
            }
            if lease_until_ms <= at_ms {
                return reject("claim: the lease must end after it begins");
            }
            Ok(vec![PlanEvent::StepClaimed {
                step,
                holder,
                at_ms,
                lease_until_ms,
            }])
        }
        PlanCommand::ReleaseStep {
            step,
            holder,
            at_ms,
        } => {
            let Some(current) = state.steps.get(&step) else {
                return reject("release: no such step");
            };
            match &current.claim {
                Some(claim)
                    if claim.holder == holder
                        && claim.is_live(at_ms)
                        && current.settlement.is_none() =>
                {
                    Ok(vec![PlanEvent::StepReleased {
                        step,
                        holder,
                        at_ms,
                    }])
                }
                _ => reject("release: the step has no live claim of yours"),
            }
        }
        PlanCommand::RecordEvidence {
            step,
            kind,
            author,
            reference,
            at_ms,
        } => {
            let Some(current) = state.steps.get(&step) else {
                return reject("evidence: no such step");
            };
            if current.settlement.is_some() {
                return reject("evidence: the step is settled");
            }
            if blank(&reference) {
                return reject("evidence: it must name what it vouches for");
            }
            Ok(vec![PlanEvent::EvidenceRecorded(Evidence {
                id: format!("evidence-{}", state.evidence.len() + 1),
                step,
                kind,
                author,
                reference,
                cycle: current.cycle,
                recorded_at_ms: at_ms,
            })])
        }
        PlanCommand::SettleStep {
            step,
            evidence,
            by,
            at_ms,
        } => {
            let Some(current) = state.steps.get(&step) else {
                return reject("settle: no such step");
            };
            if current.settlement.is_some() {
                return reject("settle: the step is already settled");
            }
            let Some(claim) = &current.claim else {
                return reject("settle: nobody has claimed the step");
            };
            let Some(record) = state.evidence.get(&evidence).filter(|e| e.step == step) else {
                return reject("settle: no such evidence for this step");
            };
            // Rule 2: evidence of the current cycle that the current epoch accepts.
            if record.cycle != current.cycle {
                return reject("settle: the evidence predates the step's reopening");
            }
            let (Some(epoch), Some(policy)) = (state.epoch(), state.policies.last()) else {
                return reject("settle: the plan has no settlement policy");
            };
            if !policy.accepts.contains(&record.kind) {
                return reject("settle: the policy epoch does not accept this kind of evidence");
            }
            if record.author == claim.holder && !policy.claimant_may_settle {
                return reject(
                    "settle: the policy epoch does not accept the claimant's own record",
                );
            }
            Ok(vec![PlanEvent::StepSettled {
                step,
                evidence,
                epoch,
                by,
                at_ms,
            }])
        }
        PlanCommand::ReopenStep {
            step,
            cause,
            by,
            at_ms,
        } => {
            let Some(current) = state.steps.get(&step) else {
                return reject("reopen: no such step");
            };
            if current.settlement.is_none() {
                return reject("reopen: the step is not settled");
            }
            // Rule 3: a reopen cites its cause.
            if blank(&cause.reference) || blank(&cause.reason) {
                return reject("reopen: it must cite a cause");
            }
            Ok(vec![PlanEvent::StepReopened {
                step,
                cause,
                by,
                at_ms,
            }])
        }
        PlanCommand::ReviseSettlementPolicy { policy, by, at_ms } => {
            if !valid_policy(&policy) {
                return reject("revise: the settlement policy accepts no evidence");
            }
            if state.policies.last() == Some(&policy) {
                return reject("revise: the policy is unchanged");
            }
            Ok(vec![PlanEvent::SettlementPolicyRevised {
                epoch: state.policies.len() as u32,
                policy,
                by,
                at_ms,
            }])
        }
        PlanCommand::Supersede {
            successor,
            reason,
            by,
            at_ms,
        } => {
            if blank(&successor) || successor == state.plan_id {
                return reject("supersede: it must name a different successor plan");
            }
            if blank(&reason) {
                return reject("supersede: it must give a reason");
            }
            Ok(vec![PlanEvent::PlanSuperseded {
                successor,
                reason,
                by,
                at_ms,
            }])
        }
    }
}

/// `evolve` — **pure** fold.
pub fn evolve(state: &PlanState, event: PlanEvent) -> PlanState {
    let mut s = state.clone();
    match event {
        PlanEvent::PlanProposed {
            plan_id,
            title,
            proposer,
            steps,
            policy,
            ..
        } => {
            s.phase = PlanPhase::Active;
            s.plan_id = plan_id;
            s.title = title;
            s.proposer = Some(proposer);
            s.policies = vec![policy];
            s.steps = steps
                .into_iter()
                .map(|spec| {
                    (
                        spec.id,
                        StepState {
                            title: spec.title,
                            blocked_by: spec.blocked_by,
                            cycle: 0,
                            claim: None,
                            settlement: None,
                            reopened: Vec::new(),
                        },
                    )
                })
                .collect();
        }
        PlanEvent::StepClaimed {
            step,
            holder,
            at_ms,
            lease_until_ms,
        } => {
            if let Some(st) = s.steps.get_mut(&step) {
                st.claim = Some(StepClaim {
                    holder,
                    claimed_at_ms: at_ms,
                    lease_until_ms,
                });
            }
        }
        PlanEvent::StepReleased { step, .. } => {
            if let Some(st) = s.steps.get_mut(&step) {
                st.claim = None;
            }
        }
        PlanEvent::EvidenceRecorded(evidence) => {
            s.evidence.insert(evidence.id.clone(), evidence);
        }
        PlanEvent::StepSettled {
            step,
            evidence,
            epoch,
            by,
            at_ms,
        } => {
            if let Some(st) = s.steps.get_mut(&step) {
                // The claim stays as the record of who held the settled cycle,
                // but it is no longer live.
                if let Some(claim) = st.claim.as_mut() {
                    claim.lease_until_ms = claim.lease_until_ms.min(at_ms);
                }
                st.settlement = Some(StepSettlement {
                    evidence,
                    epoch,
                    by,
                    at_ms,
                });
            }
        }
        PlanEvent::StepReopened { step, cause, .. } => {
            if let Some(st) = s.steps.get_mut(&step) {
                st.settlement = None;
                st.claim = None;
                st.cycle += 1;
                st.reopened.push(cause);
            }
        }
        PlanEvent::SettlementPolicyRevised { policy, .. } => s.policies.push(policy),
        PlanEvent::PlanSuperseded { successor, .. } => {
            s.phase = PlanPhase::Superseded;
            s.superseded_by = Some(successor);
        }
    }
    s
}

impl crate::Lifecycle for PlanState {
    type State = PlanState;
    type Command = PlanCommand;
    type Event = PlanEvent;
    const KIND: &'static str = PLAN_KIND;
    fn decide(state: &PlanState, command: PlanCommand) -> Result<Vec<PlanEvent>, Rejection> {
        decide(state, command)
    }
    fn evolve(state: &PlanState, event: PlanEvent) -> PlanState {
        evolve(state, event)
    }
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod tests;
