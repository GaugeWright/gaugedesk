//! One atomic attempt ledger under the parent connection lifecycle. No I/O,
//! client counters, floating point, provider secrets or model bodies here.
//! Commands/evidence are materialized by authenticated final-fetch adapters.

use std::collections::BTreeMap;

use super::access::{
    self, ApplicableGrant, BudgetKey, Caps, Currency, ExecutionEvidence, Initiator, Invocation,
    Money, Subject,
};
use super::{require, Basis, Capability, State};
use crate::ids::{AuthorityId, ModelAttemptId, ModelConnectionId, ObservationId};
use crate::Rejection;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Month {
    pub year: u64,
    pub month: u8,
}

impl Month {
    /// UTC calendar month, derived from the admission shell's Unix seconds.
    /// Gregorian 400-year cycles bound the work even for a u64 timestamp.
    pub fn at(seconds: u64) -> Self {
        let days = seconds / 86_400;
        let mut year = 1970 + (days / 146_097) * 400;
        let mut remaining = days % 146_097;
        let leap = |year: u64| {
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
        };
        loop {
            let length = if leap(year) { 366 } else { 365 };
            if remaining < length {
                break;
            }
            remaining -= length;
            year += 1;
        }
        let lengths = [
            31,
            if leap(year) { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        for (index, length) in lengths.into_iter().enumerate() {
            if remaining < length {
                return Self {
                    year,
                    month: index as u8 + 1,
                };
            }
            remaining -= length;
        }
        unreachable!("bounded Gregorian year")
    }
}

/// Conservative maximum validated/enforced by the trusted provider adapter on
/// the exact request. Unsupported/unbounded work must never produce this input.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Bound {
    pub tokens: u64,
    pub money: Option<Money>,
    pub rate: Option<ObservationId>,
    pub enforcement: ObservationId,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Usage {
    pub tokens: u64,
    pub money: Option<Money>,
    pub rate: Option<ObservationId>,
    pub runtime: ObservationId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Phase {
    Reserved,
    Dispatched,
    Unknown,
    Settled,
    AccountedAtBound,
    Released,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Attempt {
    pub invocation: Invocation,
    pub grants: Vec<ApplicableGrant>,
    pub month: Month,
    pub bound: Bound,
    pub reserved_until: u64,
    pub reconcile_by: u64,
    pub revision: u64,
    pub phase: Phase,
    pub usage: Option<Usage>,
    pub measurements: BTreeMap<ObservationId, Usage>,
    pub unknown_evidence: Option<ObservationId>,
    /// Sticky even if a later correction is smaller: the failed enforcement
    /// needs explicit repair, not an accounting edit masquerading as repair.
    pub overrun: bool,
    pub reconciled_with: Option<ObservationId>,
}

impl Attempt {
    fn counted(&self) -> Option<(u64, Option<&Money>)> {
        match self.phase {
            Phase::Released => None,
            Phase::Settled => self
                .usage
                .as_ref()
                .map(|usage| (usage.tokens, usage.money.as_ref())),
            _ => Some((self.bound.tokens, self.bound.money.as_ref())),
        }
    }
    fn family(&self) -> &ModelConnectionId {
        &self.grants[0].budget.connection_family
    }
    fn charges(&self, budget: &BudgetKey) -> bool {
        self.family() == &budget.connection_family
            && match &budget.subject {
                Subject::Member(member) => {
                    matches!(&self.invocation.initiator, Initiator::Member(actual) if actual == member)
                }
                Subject::Project(project) => self.invocation.project.as_ref() == Some(project),
            }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum Operation {
    Reserve {
        id: ModelAttemptId,
        invocation: Box<Invocation>,
        evidence: Box<ExecutionEvidence>,
        bound: Bound,
        reserved_until: u64,
        reconcile_by: u64,
    },
    Dispatch {
        id: ModelAttemptId,
        evidence: Box<ExecutionEvidence>,
        /// Revalidated against the actual request by final fetch, not echoed
        /// from a browser. A changed/unsupported route must re-admit work.
        bound: Bound,
    },
    Cancel {
        id: ModelAttemptId,
    },
    Expire {
        id: ModelAttemptId,
    },
    OutcomeUnknown {
        id: ModelAttemptId,
        evidence: ObservationId,
    },
    Settle {
        id: ModelAttemptId,
        usage: Usage,
        evidence: ObservationId,
    },
    ReconcileDeadline {
        id: ModelAttemptId,
    },
    Correct {
        id: ModelAttemptId,
        usage: Usage,
        evidence: ObservationId,
    },
    ReconcileOverrun {
        id: ModelAttemptId,
        repaired_enforcement: ObservationId,
        evidence: ObservationId,
    },
}

impl Operation {
    pub(super) fn capability(&self) -> Capability {
        match self {
            Self::Reserve { .. } | Self::Dispatch { .. } | Self::Cancel { .. } => {
                Capability::InvokeProvider
            }
            Self::Expire { .. } | Self::ReconcileDeadline { .. } => Capability::ObserveDeadline,
            Self::OutcomeUnknown { .. } | Self::Settle { .. } | Self::Correct { .. } => {
                Capability::ObserveUsage
            }
            Self::ReconcileOverrun { .. } => Capability::ReconcileBounds,
        }
    }
    fn id(&self) -> &ModelAttemptId {
        match self {
            Self::Reserve { id, .. }
            | Self::Dispatch { id, .. }
            | Self::Cancel { id }
            | Self::Expire { id }
            | Self::OutcomeUnknown { id, .. }
            | Self::Settle { id, .. }
            | Self::ReconcileDeadline { id }
            | Self::Correct { id, .. }
            | Self::ReconcileOverrun { id, .. } => id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Change {
    Reserved {
        id: ModelAttemptId,
        attempt: Box<Attempt>,
        evidence: ObservationId,
    },
    Dispatched {
        id: ModelAttemptId,
        evidence: ObservationId,
    },
    Released {
        id: ModelAttemptId,
    },
    OutcomeUnknown {
        id: ModelAttemptId,
        evidence: ObservationId,
    },
    Settled {
        id: ModelAttemptId,
        usage: Usage,
        evidence: ObservationId,
        overrun: bool,
    },
    AccountedAtBound {
        id: ModelAttemptId,
    },
    Corrected {
        id: ModelAttemptId,
        usage: Usage,
        evidence: ObservationId,
        overrun: bool,
    },
    OverrunReconciled {
        id: ModelAttemptId,
        repaired_enforcement: ObservationId,
        evidence: ObservationId,
    },
}

fn attempt<'a>(state: &'a State, id: &ModelAttemptId) -> Result<&'a Attempt, Rejection> {
    state.attempts.get(id).ok_or(Rejection {
        reason: "unknown provider attempt",
    })
}

pub(super) fn check_basis(
    state: &State,
    operation: &Operation,
    basis: &Basis,
) -> Result<(), Rejection> {
    let expected = match operation {
        Operation::Reserve { .. } => Basis::Metadata(state.revision),
        Operation::Dispatch { id, .. } => Basis::Dispatch {
            metadata: state.revision,
            attempt: id.clone(),
            revision: attempt(state, id)?.revision,
        },
        _ => Basis::Attempt {
            id: operation.id().clone(),
            revision: attempt(state, operation.id())?.revision,
        },
    };
    require(*basis == expected, "stale or mismatched spend basis")
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub tokens: u128,
    pub money: BTreeMap<Currency, u128>,
    pub unknown_money: bool,
}

impl Totals {
    fn add(
        &mut self,
        tokens: u128,
        money: &BTreeMap<Currency, u128>,
        unknown: bool,
    ) -> Result<(), Rejection> {
        self.tokens = self.tokens.checked_add(tokens).ok_or(Rejection {
            reason: "token accounting overflow",
        })?;
        for (currency, micros) in money {
            let amount = self.money.entry(currency.clone()).or_default();
            *amount = amount.checked_add(*micros).ok_or(Rejection {
                reason: "money accounting overflow",
            })?;
        }
        self.unknown_money |= unknown;
        Ok(())
    }
}

/// Display buckets over the SAME attempt ledger used to enforce caps. In-flight
/// and unknown reservations remain committed allowance; accounted-at-bound is
/// not presented as measured consumption. Corrections move the original month
/// into measured usage without rewriting history.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeriodUsage {
    pub measured: Totals,
    pub reserved: Totals,
    pub accounted_at_bound: Totals,
    pub unknown_outcomes: u64,
}

impl PeriodUsage {
    pub fn total(&self) -> Result<Totals, Rejection> {
        let mut total = Totals::default();
        for part in [&self.measured, &self.reserved, &self.accounted_at_bound] {
            total.add(part.tokens, &part.money, part.unknown_money)?;
        }
        Ok(total)
    }
}

/// Rebuildable read, never a second ledger. A shared attempt counts once per
/// subject budget, even when several grants name that same stable subject.
/// Known subjects retain their use even while they have no active cap; creating
/// or recreating a grant must not make prior project-funded member usage free.
pub fn totals(state: &State, budget: &BudgetKey, month: Month) -> Result<Totals, Rejection> {
    period_usage(state, budget, month)?.total()
}

pub fn period_usage(
    state: &State,
    budget: &BudgetKey,
    month: Month,
) -> Result<PeriodUsage, Rejection> {
    let mut usage = PeriodUsage::default();
    for attempt in state
        .attempts
        .values()
        .filter(|attempt| attempt.month == month && attempt.charges(budget))
    {
        if let Some((tokens, money)) = attempt.counted() {
            let target = match attempt.phase {
                Phase::Settled => &mut usage.measured,
                Phase::AccountedAtBound => &mut usage.accounted_at_bound,
                _ => &mut usage.reserved,
            };
            let amounts = money
                .map(|value| [(value.currency.clone(), u128::from(value.micros))].into())
                .unwrap_or_default();
            target.add(u128::from(tokens), &amounts, money.is_none())?;
            if matches!(attempt.phase, Phase::Unknown | Phase::AccountedAtBound) {
                usage.unknown_outcomes =
                    usage.unknown_outcomes.checked_add(1).ok_or(Rejection {
                        reason: "outcome count overflow",
                    })?;
            }
        }
    }
    Ok(usage)
}

pub fn overrun_pending(state: &State, family: &ModelConnectionId) -> bool {
    state.attempts.values().any(|attempt| {
        attempt.family() == family && attempt.overrun && attempt.reconciled_with.is_none()
    })
}

fn within(total: &Totals, bound: &Bound, caps: &Caps) -> Result<(), Rejection> {
    if let Some(cap) = caps.tokens {
        require(
            total
                .tokens
                .checked_add(u128::from(bound.tokens))
                .is_some_and(|value| value <= u128::from(cap)),
            "monthly token cap exhausted",
        )?;
    }
    if let Some(cap) = &caps.money {
        require(cap.micros > 0, "monthly money cap is zero")?;
        let maximum = bound.money.as_ref().ok_or(Rejection {
            reason: "money cap requires a supported conservative price",
        })?;
        require(
            maximum.currency == cap.currency
                && !total.unknown_money
                && total.money.keys().all(|currency| currency == &cap.currency),
            "money allowance has unknown or incompatible pricing",
        )?;
        let used = total.money.get(&cap.currency).copied().unwrap_or(0);
        require(
            used.checked_add(u128::from(maximum.micros))
                .is_some_and(|value| value <= u128::from(cap.micros)),
            "monthly money cap exhausted",
        )?;
    }
    Ok(())
}

fn eligible(state: &State, family: &ModelConnectionId, bound: &Bound) -> Result<(), Rejection> {
    require(
        !state.failed_enforcements.contains(&bound.enforcement),
        "provider bound enforcement has failed",
    )?;
    require(
        !overrun_pending(state, family),
        "connection has an unreconciled overrun",
    )
}

fn measured(
    attempt: &Attempt,
    usage: &Usage,
    evidence: &ObservationId,
) -> Result<Option<bool>, Rejection> {
    if let Some(previous) = attempt.measurements.get(evidence) {
        require(previous == usage, "usage evidence identity collision")?;
        return Ok(None);
    }
    require(
        usage.money.is_none() || usage.rate.is_some(),
        "measured cost requires its rate basis",
    )?;
    let money_overrun = if let Some(maximum) = &attempt.bound.money {
        let actual = usage.money.as_ref().ok_or(Rejection {
            reason: "unknown cost cannot release a priced reservation",
        })?;
        actual.currency != maximum.currency || actual.micros > maximum.micros
    } else {
        false
    };
    Ok(Some(usage.tokens > attempt.bound.tokens || money_overrun))
}

pub(super) fn decide(
    state: &State,
    operation: Operation,
    actor: &AuthorityId,
    now: u64,
) -> Result<Option<Change>, Rejection> {
    if let Operation::Reserve {
        id,
        invocation,
        evidence,
        bound,
        reserved_until,
        reconcile_by,
    } = operation
    {
        let invocation = *invocation;
        let evidence = *evidence;
        require(
            &invocation.final_fetch == actor && evidence.observed == invocation,
            "reservation audience or invocation mismatch",
        )?;
        if let Some(previous) = state.attempts.get(&id) {
            require(
                previous.invocation == invocation
                    && previous.bound == bound
                    && previous.reserved_until == reserved_until
                    && previous.reconcile_by == reconcile_by,
                "provider attempt identity collision",
            )?;
            // A replay confirms a reservation, not a fresh dispatch or key lease.
            return Ok(None);
        }
        require(
            bound.tokens > 0 && (bound.money.is_none() || bound.rate.is_some()),
            "unsupported conservative request bound",
        )?;
        require(
            reserved_until > now && reconcile_by > reserved_until,
            "attempt requires ordered future deadlines",
        )?;
        let grants = access::applicable(state, &invocation, &evidence, actor)?;
        eligible(state, &grants[0].budget.connection_family, &bound)?;
        let month = Month::at(now);
        for (budget, caps) in access::budgets(&grants) {
            let total = totals(state, &budget, month)?;
            for cap in caps {
                within(&total, &bound, &cap)?;
            }
        }
        return Ok(Some(Change::Reserved {
            id,
            attempt: Box::new(Attempt {
                invocation,
                grants,
                month,
                bound,
                reserved_until,
                reconcile_by,
                revision: 1,
                phase: Phase::Reserved,
                usage: None,
                measurements: BTreeMap::new(),
                unknown_evidence: None,
                overrun: false,
                reconciled_with: None,
            }),
            evidence: evidence.observation,
        }));
    }
    let id = operation.id().clone();
    let current = attempt(state, &id)?;
    require(
        current.revision.checked_add(1).is_some(),
        "attempt revision exhausted",
    )?;
    if matches!(
        operation.capability(),
        Capability::InvokeProvider | Capability::ObserveUsage
    ) {
        require(
            &current.invocation.final_fetch == actor,
            "wrong attempt final-fetch actor",
        )?;
    }
    let change = match operation {
        Operation::Dispatch {
            evidence, bound, ..
        } => {
            require(
                bound == current.bound,
                "actual request bound no longer matches reservation",
            )?;
            require(
                current.phase == Phase::Reserved && now < current.reserved_until,
                "attempt is not dispatchable",
            )?;
            let grants = access::applicable(state, &current.invocation, &evidence, actor)?;
            require(
                grants == current.grants,
                "grant basis changed; re-admit undispatched work",
            )?;
            eligible(state, current.family(), &current.bound)?;
            Change::Dispatched {
                id,
                evidence: evidence.observation,
            }
        }
        Operation::Cancel { .. } | Operation::Expire { .. } => {
            require(
                current.phase == Phase::Reserved,
                "only definite pre-dispatch non-use can release allowance",
            )?;
            if matches!(operation, Operation::Expire { .. }) {
                require(
                    now >= current.reserved_until,
                    "reservation deadline has not elapsed",
                )?;
            }
            Change::Released { id }
        }
        Operation::OutcomeUnknown { evidence, .. } => {
            if current.phase == Phase::Unknown
                && current.unknown_evidence.as_ref() == Some(&evidence)
            {
                return Ok(None);
            }
            require(
                current.phase == Phase::Dispatched,
                "unknown outcome requires a dispatched attempt",
            )?;
            Change::OutcomeUnknown { id, evidence }
        }
        Operation::Settle {
            usage, evidence, ..
        } => {
            let Some(overrun) = measured(current, &usage, &evidence)? else {
                return Ok(None);
            };
            require(
                matches!(current.phase, Phase::Dispatched | Phase::Unknown),
                "attempt requires a correction, not another settlement",
            )?;
            Change::Settled {
                id,
                usage,
                evidence,
                overrun,
            }
        }
        Operation::ReconcileDeadline { .. } => {
            require(
                now >= current.reconcile_by,
                "reconciliation deadline has not elapsed",
            )?;
            if current.phase == Phase::AccountedAtBound {
                return Ok(None);
            }
            require(
                matches!(current.phase, Phase::Dispatched | Phase::Unknown),
                "attempt has no unknown charge to reconcile",
            )?;
            Change::AccountedAtBound { id }
        }
        Operation::Correct {
            usage, evidence, ..
        } => {
            let Some(overrun) = measured(current, &usage, &evidence)? else {
                return Ok(None);
            };
            require(
                matches!(current.phase, Phase::Settled | Phase::AccountedAtBound),
                "only terminal accounting can be corrected",
            )?;
            Change::Corrected {
                id,
                usage,
                evidence,
                overrun,
            }
        }
        Operation::ReconcileOverrun {
            repaired_enforcement,
            evidence,
            ..
        } => {
            require(
                current.overrun && current.reconciled_with.is_none(),
                "no unreconciled overrun",
            )?;
            require(
                repaired_enforcement != current.bound.enforcement
                    && !state.failed_enforcements.contains(&repaired_enforcement),
                "repair must name a new eligible enforcement revision",
            )?;
            Change::OverrunReconciled {
                id,
                repaired_enforcement,
                evidence,
            }
        }
        Operation::Reserve { .. } => unreachable!("handled above"),
    };
    Ok(Some(change))
}

pub(super) fn evolve(state: &mut State, change: Change) {
    let (id, phase) = match change {
        Change::Reserved { id, attempt, .. } => {
            state.attempts.insert(id, *attempt);
            return;
        }
        Change::Dispatched { id, .. } => (id, Phase::Dispatched),
        Change::Released { id } => (id, Phase::Released),
        Change::OutcomeUnknown { id, evidence } => {
            state
                .attempts
                .get_mut(&id)
                .expect("admitted attempt")
                .unknown_evidence = Some(evidence);
            (id, Phase::Unknown)
        }
        Change::Settled {
            id,
            usage,
            evidence,
            overrun,
        }
        | Change::Corrected {
            id,
            usage,
            evidence,
            overrun,
        } => {
            let attempt = state.attempts.get_mut(&id).expect("admitted attempt");
            attempt.measurements.insert(evidence, usage.clone());
            attempt.usage = Some(usage);
            if overrun {
                state
                    .failed_enforcements
                    .insert(attempt.bound.enforcement.clone());
                attempt.overrun = true;
                // Newly admitted evidence can reopen an already reconciled fault.
                attempt.reconciled_with = None;
            }
            (id, Phase::Settled)
        }
        Change::AccountedAtBound { id } => (id, Phase::AccountedAtBound),
        Change::OverrunReconciled {
            id,
            repaired_enforcement,
            ..
        } => {
            let attempt = state.attempts.get_mut(&id).expect("admitted attempt");
            attempt.reconciled_with = Some(repaired_enforcement);
            attempt.revision += 1;
            return;
        }
    };
    let attempt = state.attempts.get_mut(&id).expect("admitted attempt");
    attempt.phase = phase;
    attempt.revision += 1;
}
