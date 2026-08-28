//! Receipt-driven multi-target settlement coordination (ADR 0150/0151).
//!
//! This is the single pure \`(decide, evolve)\` lifecycle for a declaration's
//! effects. Adapters perform I/O only after this reducer admits a start. They
//! return authenticated receipts (or an authoritative unknown-outcome query)
//! as commands; filesystem observations and UI projections never settle a
//! member.

use std::collections::{BTreeMap, BTreeSet};

use crate::{Lifecycle, Rejection};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementAct {
    Propose,
    Apply,
    Publish,
    Release,
    ManagedAdvance,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SettlementMemberDeclaration {
    pub member_id: String,
    pub target_id: String,
    pub operation_id: String,
    pub expected_basis: String,
    pub candidate_digest: String,
    pub expected_result_digest: String,
    pub policy_decision_handle: String,
    pub adapter: String,
    pub act: SettlementAct,
    /// A known provider refusal may be retried with the same operation id only
    /// when the adapter proves that the refusal performed no effect.
    pub retry_safe_after_failure: bool,
    /// An eligible adapter must answer an authoritative operation query after
    /// timeout. Managed WhippleScript effects satisfy this via their receipt log.
    pub authoritative_query: bool,
}

impl SettlementMemberDeclaration {
    fn valid(&self) -> bool {
        [
            &self.member_id,
            &self.target_id,
            &self.operation_id,
            &self.expected_basis,
            &self.candidate_digest,
            &self.expected_result_digest,
            &self.policy_decision_handle,
            &self.adapter,
        ]
        .into_iter()
        .all(valid_identity)
            && self.authoritative_query
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TargetSettlementDeclaration {
    pub declaration_id: String,
    pub project_id: String,
    pub chat_id: String,
    pub source_change_set_ref: String,
    pub promotion_manifest_ref: Option<String>,
    pub members: Vec<SettlementMemberDeclaration>,
}

impl TargetSettlementDeclaration {
    fn valid(&self) -> bool {
        if !valid_identity(&self.declaration_id)
            || !valid_identity(&self.project_id)
            || !valid_identity(&self.chat_id)
            || !valid_identity(&self.source_change_set_ref)
            || self.members.is_empty()
            || self
                .promotion_manifest_ref
                .as_ref()
                .is_some_and(|value| !valid_identity(value))
        {
            return false;
        }
        let mut member_ids = BTreeSet::new();
        let mut operation_ids = BTreeSet::new();
        self.members.iter().all(|member| {
            member.valid()
                && member_ids.insert(member.member_id.clone())
                && operation_ids.insert(member.operation_id.clone())
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct MemberPreflightEvidence {
    pub member_id: String,
    pub observed_basis: String,
    pub observed_candidate_digest: String,
    pub adapter_contract_ref: String,
    pub governance_decision_ref: String,
    pub admitted: bool,
    pub refusal_reason: Option<String>,
}

impl MemberPreflightEvidence {
    fn exact_for(&self, member: &SettlementMemberDeclaration) -> bool {
        self.member_id == member.member_id
            && self.governance_decision_ref == member.policy_decision_handle
            && valid_identity(&self.adapter_contract_ref)
            && if self.admitted {
                self.observed_basis == member.expected_basis
                    && self.observed_candidate_digest == member.candidate_digest
                    && self.refusal_reason.is_none()
            } else {
                valid_identity(&self.observed_basis)
                    && valid_identity(&self.observed_candidate_digest)
                    && self.refusal_reason.as_ref().is_some_and(valid_identity)
            }
    }
}

/// Evidence from the Home-owned ordered lane for one stable target.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TargetLanePermit {
    pub lane_id: String,
    pub target_id: String,
    pub member_id: String,
    pub operation_id: String,
    pub sequence: u64,
    pub authority_position: String,
}

impl TargetLanePermit {
    fn exact_for(&self, member: &SettlementMemberDeclaration) -> bool {
        self.target_id == member.target_id
            && self.member_id == member.member_id
            && self.operation_id == member.operation_id
            && self.sequence > 0
            && valid_identity(&self.lane_id)
            && valid_identity(&self.authority_position)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOutcome {
    Succeeded,
    Failed,
}

/// A receipt only after the target adapter's authority has authenticated it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct AuthenticatedTargetReceipt {
    pub receipt_ref: String,
    pub member_id: String,
    pub target_id: String,
    pub operation_id: String,
    pub expected_basis: String,
    pub resulting_basis: Option<String>,
    pub resulting_digest: Option<String>,
    pub outcome: ReceiptOutcome,
    pub authority_ref: String,
    pub authentication_ref: String,
    pub failure_reason: Option<String>,
}

impl AuthenticatedTargetReceipt {
    fn exact_for(&self, member: &SettlementMemberDeclaration) -> bool {
        if self.member_id != member.member_id
            || self.target_id != member.target_id
            || self.operation_id != member.operation_id
            || self.expected_basis != member.expected_basis
            || !valid_identity(&self.receipt_ref)
            || !valid_identity(&self.authority_ref)
            || !valid_identity(&self.authentication_ref)
        {
            return false;
        }
        match self.outcome {
            ReceiptOutcome::Succeeded => {
                self.resulting_basis.as_ref().is_some_and(valid_identity)
                    && self.resulting_digest.as_deref()
                        == Some(member.expected_result_digest.as_str())
                    && self.failure_reason.is_none()
            }
            ReceiptOutcome::Failed => {
                self.resulting_digest.is_none()
                    && self.failure_reason.as_ref().is_some_and(valid_identity)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementPhase {
    #[default]
    Undeclared,
    Declared,
    Preflighting,
    Ready,
    Applying,
    Completed,
    PartiallyApplied,
    ReconciliationRequired,
    Refused,
    Cancelled,
    Expired,
    Compensated,
    AbandonedPartial,
}

impl SettlementPhase {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Refused
                | Self::Cancelled
                | Self::Expired
                | Self::Compensated
                | Self::AbandonedPartial
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementMemberPhase {
    #[default]
    Pending,
    PreflightPassed,
    Started,
    Succeeded,
    Failed,
    Unknown,
    CancelledBeforeStart,
    SupersededBeforeStart,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SettlementMemberState {
    pub phase: SettlementMemberPhase,
    pub preflight_evidence: Option<MemberPreflightEvidence>,
    pub lane_permit: Option<TargetLanePermit>,
    pub attempts: u32,
    pub receipt: Option<AuthenticatedTargetReceipt>,
    pub unknown_evidence_ref: Option<String>,
    pub query_refs: Vec<String>,
    pub superseded_by: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TargetSettlementState {
    pub phase: SettlementPhase,
    pub declaration: Option<TargetSettlementDeclaration>,
    pub members: BTreeMap<String, SettlementMemberState>,
    pub started_effects: u32,
    pub terminal_reason: Option<String>,
    pub compensation_receipt_refs: Vec<String>,
    pub history_events: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum TargetSettlementCommand {
    Declare(TargetSettlementDeclaration),
    BeginPreflight,
    RecordPreflight(MemberPreflightEvidence),
    CancelBeforeEffects {
        reason: String,
    },
    ExpireBeforeEffects {
        reason: String,
    },
    StartMember {
        member_id: String,
        lane_permit: TargetLanePermit,
    },
    RecordReceipt(AuthenticatedTargetReceipt),
    RecordUnknown {
        member_id: String,
        evidence_ref: String,
    },
    RequestAuthoritativeQuery {
        member_id: String,
        query_ref: String,
    },
    RecordQueryReceipt(AuthenticatedTargetReceipt),
    RetryKnownFailure {
        member_id: String,
        lane_permit: TargetLanePermit,
    },
    CancelUnstarted {
        reason: String,
    },
    SupersedeNotStarted {
        member_id: String,
        later_member_ref: String,
    },
    MarkCompensated {
        receipt_refs: Vec<String>,
        reconciliation_complete: bool,
    },
    AbandonPartial {
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum TargetSettlementEvent {
    DeclarationRecorded(TargetSettlementDeclaration),
    PreflightStarted,
    MemberPreflightPassed(MemberPreflightEvidence),
    MemberPreflightRefused(MemberPreflightEvidence),
    CoordinatorReady,
    CoordinatorRefused {
        reason: String,
    },
    CoordinatorCancelled {
        reason: String,
    },
    CoordinatorExpired {
        reason: String,
    },
    MemberStarted {
        member_id: String,
        lane_permit: TargetLanePermit,
    },
    MemberReceiptRecorded(AuthenticatedTargetReceipt),
    MemberOutcomeUnknown {
        member_id: String,
        evidence_ref: String,
    },
    AuthoritativeQueryRequested {
        member_id: String,
        query_ref: String,
    },
    MemberRetryStarted {
        member_id: String,
        lane_permit: TargetLanePermit,
    },
    MemberCancelledBeforeStart {
        member_id: String,
        reason: String,
    },
    MemberSupersededBeforeStart {
        member_id: String,
        later_member_ref: String,
    },
    CoordinatorPhaseChanged(SettlementPhase),
    CoordinatorCompensated {
        receipt_refs: Vec<String>,
    },
    CoordinatorAbandonedPartial {
        reason: String,
    },
}

fn valid_identity(value: impl AsRef<str>) -> bool {
    let value = value.as_ref();
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn reject(reason: &'static str) -> Result<Vec<TargetSettlementEvent>, Rejection> {
    Err(Rejection { reason })
}

fn declaration(state: &TargetSettlementState) -> Result<&TargetSettlementDeclaration, Rejection> {
    state.declaration.as_ref().ok_or(Rejection {
        reason: "target settlement declaration is absent",
    })
}

fn member<'a>(
    state: &'a TargetSettlementState,
    member_id: &str,
) -> Result<(&'a SettlementMemberDeclaration, &'a SettlementMemberState), Rejection> {
    let declaration = declaration(state)?;
    let declared = declaration
        .members
        .iter()
        .find(|member| member.member_id == member_id)
        .ok_or(Rejection {
            reason: "target settlement member is not declared",
        })?;
    let current = state.members.get(member_id).ok_or(Rejection {
        reason: "target settlement member state is absent",
    })?;
    Ok((declared, current))
}

fn phase_after_member_change(
    state: &TargetSettlementState,
    changed_id: &str,
    changed_phase: SettlementMemberPhase,
) -> SettlementPhase {
    let mut projected = state.clone();
    projected
        .members
        .get_mut(changed_id)
        .expect("declared member")
        .phase = changed_phase;
    projected_phase(&projected)
}

fn projected_phase(state: &TargetSettlementState) -> SettlementPhase {
    let mut succeeded = 0;
    let mut resolved_not_success = 0;
    let mut unknown = false;
    let mut active = false;
    for member in state.members.values() {
        match member.phase {
            SettlementMemberPhase::Succeeded => succeeded += 1,
            SettlementMemberPhase::Failed
            | SettlementMemberPhase::CancelledBeforeStart
            | SettlementMemberPhase::SupersededBeforeStart => resolved_not_success += 1,
            SettlementMemberPhase::Unknown => unknown = true,
            SettlementMemberPhase::Pending
            | SettlementMemberPhase::PreflightPassed
            | SettlementMemberPhase::Started => active = true,
        }
    }
    if unknown {
        SettlementPhase::ReconciliationRequired
    } else if !active && resolved_not_success == 0 && succeeded == state.members.len() {
        SettlementPhase::Completed
    } else if !active && succeeded > 0 && resolved_not_success > 0 {
        SettlementPhase::PartiallyApplied
    } else {
        SettlementPhase::Applying
    }
}

pub fn decide(
    state: &TargetSettlementState,
    command: TargetSettlementCommand,
) -> Result<Vec<TargetSettlementEvent>, Rejection> {
    use SettlementMemberPhase as M;
    use SettlementPhase as P;
    use TargetSettlementCommand as C;
    use TargetSettlementEvent as E;

    match command {
        C::Declare(declaration) => {
            if state.phase != P::Undeclared || state.declaration.is_some() {
                return reject("declare: coordinator is already declared");
            }
            if !declaration.valid() {
                return reject("declare: exact unique declaration members are required");
            }
            Ok(vec![E::DeclarationRecorded(declaration)])
        }
        C::BeginPreflight => {
            if state.phase != P::Declared {
                return reject("beginPreflight: coordinator is not declared");
            }
            Ok(vec![E::PreflightStarted])
        }
        C::RecordPreflight(evidence) => {
            if state.phase != P::Preflighting {
                return reject("recordPreflight: coordinator is not preflighting");
            }
            let (declared, current) = member(state, &evidence.member_id)?;
            if current.phase != M::Pending || current.preflight_evidence.is_some() {
                return reject("recordPreflight: member was already preflighted");
            }
            if !evidence.exact_for(declared) {
                return reject("recordPreflight: evidence does not match the declaration");
            }
            if !evidence.admitted {
                let reason = evidence.refusal_reason.clone().expect("validated reason");
                return Ok(vec![
                    E::MemberPreflightRefused(evidence),
                    E::CoordinatorRefused { reason },
                ]);
            }
            let all_others_passed = state.members.iter().all(|(id, member)| {
                id == &declared.member_id || member.phase == M::PreflightPassed
            });
            let mut events = vec![E::MemberPreflightPassed(evidence)];
            if all_others_passed {
                events.push(E::CoordinatorReady);
            }
            Ok(events)
        }
        C::CancelBeforeEffects { reason } => {
            if !matches!(state.phase, P::Declared | P::Preflighting | P::Ready)
                || state.started_effects != 0
                || !valid_identity(&reason)
            {
                return reject("cancelBeforeEffects: cancellation is invalid or effects started");
            }
            Ok(vec![E::CoordinatorCancelled { reason }])
        }
        C::ExpireBeforeEffects { reason } => {
            if !matches!(state.phase, P::Declared | P::Preflighting | P::Ready)
                || state.started_effects != 0
                || !valid_identity(&reason)
            {
                return reject("expireBeforeEffects: expiry is invalid or effects started");
            }
            Ok(vec![E::CoordinatorExpired { reason }])
        }
        C::StartMember {
            member_id,
            lane_permit,
        } => {
            if !matches!(state.phase, P::Ready | P::Applying) {
                return reject("startMember: all-member preflight is not ready");
            }
            let (declared, current) = member(state, &member_id)?;
            if current.phase != M::PreflightPassed || current.receipt.is_some() {
                return reject("startMember: member is not startable");
            }
            if !lane_permit.exact_for(declared) {
                return reject("startMember: ordered target-lane permit is not exact");
            }
            Ok(vec![
                E::MemberStarted {
                    member_id,
                    lane_permit,
                },
                E::CoordinatorPhaseChanged(P::Applying),
            ])
        }
        C::RecordReceipt(receipt) => record_receipt(state, receipt, false),
        C::RecordUnknown {
            member_id,
            evidence_ref,
        } => {
            let (_, current) = member(state, &member_id)?;
            if current.phase != M::Started || !valid_identity(&evidence_ref) {
                return reject("recordUnknown: only a started member may become unknown");
            }
            Ok(vec![
                E::MemberOutcomeUnknown {
                    member_id,
                    evidence_ref,
                },
                E::CoordinatorPhaseChanged(P::ReconciliationRequired),
            ])
        }
        C::RequestAuthoritativeQuery {
            member_id,
            query_ref,
        } => {
            let (declared, current) = member(state, &member_id)?;
            if current.phase != M::Unknown
                || !declared.authoritative_query
                || !valid_identity(&query_ref)
                || current.query_refs.contains(&query_ref)
            {
                return reject("requestAuthoritativeQuery: member is not queryable");
            }
            Ok(vec![E::AuthoritativeQueryRequested {
                member_id,
                query_ref,
            }])
        }
        C::RecordQueryReceipt(receipt) => record_receipt(state, receipt, true),
        C::RetryKnownFailure {
            member_id,
            lane_permit,
        } => {
            let (declared, current) = member(state, &member_id)?;
            if current.phase != M::Failed || !declared.retry_safe_after_failure {
                return reject("retryKnownFailure: member is not safely retryable");
            }
            if !lane_permit.exact_for(declared)
                || current
                    .lane_permit
                    .as_ref()
                    .is_some_and(|old| lane_permit.sequence <= old.sequence)
            {
                return reject("retryKnownFailure: a newer exact lane permit is required");
            }
            Ok(vec![
                E::MemberRetryStarted {
                    member_id,
                    lane_permit,
                },
                E::CoordinatorPhaseChanged(P::Applying),
            ])
        }
        C::CancelUnstarted { reason } => {
            if state.phase.terminal() || state.started_effects == 0 || !valid_identity(&reason) {
                return reject("cancelUnstarted: effects have not started or state is terminal");
            }
            let ids = state
                .members
                .iter()
                .filter(|(_, member)| matches!(member.phase, M::Pending | M::PreflightPassed))
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>();
            if ids.is_empty() {
                return reject("cancelUnstarted: no unstarted member remains");
            }
            let mut events = ids
                .iter()
                .map(|member_id| E::MemberCancelledBeforeStart {
                    member_id: member_id.clone(),
                    reason: reason.clone(),
                })
                .collect::<Vec<_>>();
            let mut projected = state.clone();
            for id in ids {
                projected.members.get_mut(&id).expect("member").phase = M::CancelledBeforeStart;
            }
            events.push(E::CoordinatorPhaseChanged(projected_phase(&projected)));
            Ok(events)
        }
        C::SupersedeNotStarted {
            member_id,
            later_member_ref,
        } => {
            let (_, current) = member(state, &member_id)?;
            if !matches!(current.phase, M::Pending | M::PreflightPassed)
                || !valid_identity(&later_member_ref)
            {
                return reject(
                    "supersedeNotStarted: only an exact not-started member may supersede",
                );
            }
            let phase = phase_after_member_change(state, &member_id, M::SupersededBeforeStart);
            Ok(vec![
                E::MemberSupersededBeforeStart {
                    member_id,
                    later_member_ref,
                },
                E::CoordinatorPhaseChanged(phase),
            ])
        }
        C::MarkCompensated {
            receipt_refs,
            reconciliation_complete,
        } => {
            if !matches!(state.phase, P::PartiallyApplied | P::ReconciliationRequired)
                || receipt_refs.is_empty()
                || receipt_refs.iter().any(|value| !valid_identity(value))
                || state.phase == P::ReconciliationRequired && !reconciliation_complete
            {
                return reject(
                    "markCompensated: authenticated forward-repair evidence is required",
                );
            }
            Ok(vec![E::CoordinatorCompensated { receipt_refs }])
        }
        C::AbandonPartial { reason } => {
            if !matches!(
                state.phase,
                P::Applying | P::PartiallyApplied | P::ReconciliationRequired
            ) || state.started_effects == 0
                || !valid_identity(&reason)
            {
                return reject("abandonPartial: an explicit nonterminal partial state is required");
            }
            Ok(vec![E::CoordinatorAbandonedPartial { reason }])
        }
    }
}

fn record_receipt(
    state: &TargetSettlementState,
    receipt: AuthenticatedTargetReceipt,
    from_query: bool,
) -> Result<Vec<TargetSettlementEvent>, Rejection> {
    use SettlementMemberPhase as M;
    use TargetSettlementEvent as E;
    let (declared, current) = member(state, &receipt.member_id)?;
    let expected_phase = if from_query { M::Unknown } else { M::Started };
    if current.phase != expected_phase || current.receipt.is_some() {
        return reject("recordReceipt: member is not awaiting this receipt");
    }
    if from_query && current.query_refs.is_empty() {
        return reject("recordReceipt: unknown member was not authoritatively queried");
    }
    if !receipt.exact_for(declared) {
        return reject("recordReceipt: authenticated receipt does not match declaration");
    }
    let changed = match receipt.outcome {
        ReceiptOutcome::Succeeded => M::Succeeded,
        ReceiptOutcome::Failed => M::Failed,
    };
    let next_phase = phase_after_member_change(state, &receipt.member_id, changed);
    Ok(vec![
        E::MemberReceiptRecorded(receipt),
        E::CoordinatorPhaseChanged(next_phase),
    ])
}

pub fn evolve(
    state: &TargetSettlementState,
    event: TargetSettlementEvent,
) -> TargetSettlementState {
    use SettlementMemberPhase as M;
    use SettlementPhase as P;
    use TargetSettlementEvent as E;

    let mut next = state.clone();
    next.history_events = next.history_events.saturating_add(1);
    match event {
        E::DeclarationRecorded(declaration) => {
            next.phase = P::Declared;
            next.members = declaration
                .members
                .iter()
                .map(|member| (member.member_id.clone(), SettlementMemberState::default()))
                .collect();
            next.declaration = Some(declaration);
        }
        E::PreflightStarted => next.phase = P::Preflighting,
        E::MemberPreflightPassed(evidence) => {
            let member = next
                .members
                .get_mut(&evidence.member_id)
                .expect("declared member");
            member.phase = M::PreflightPassed;
            member.preflight_evidence = Some(evidence);
        }
        E::MemberPreflightRefused(evidence) => {
            let member_id = evidence.member_id.clone();
            next.members
                .get_mut(&member_id)
                .expect("declared member")
                .preflight_evidence = Some(evidence);
        }
        E::CoordinatorReady => next.phase = P::Ready,
        E::CoordinatorRefused { reason } => {
            next.phase = P::Refused;
            next.terminal_reason = Some(reason);
        }
        E::CoordinatorCancelled { reason } => {
            next.phase = P::Cancelled;
            next.terminal_reason = Some(reason);
        }
        E::CoordinatorExpired { reason } => {
            next.phase = P::Expired;
            next.terminal_reason = Some(reason);
        }
        E::MemberStarted {
            member_id,
            lane_permit,
        }
        | E::MemberRetryStarted {
            member_id,
            lane_permit,
        } => {
            let member = next.members.get_mut(&member_id).expect("declared member");
            member.phase = M::Started;
            member.lane_permit = Some(lane_permit);
            member.attempts = member.attempts.saturating_add(1);
            member.receipt = None;
            member.unknown_evidence_ref = None;
            next.started_effects = next.started_effects.saturating_add(1);
        }
        E::MemberReceiptRecorded(receipt) => {
            let member = next
                .members
                .get_mut(&receipt.member_id)
                .expect("declared member");
            member.phase = match receipt.outcome {
                ReceiptOutcome::Succeeded => M::Succeeded,
                ReceiptOutcome::Failed => M::Failed,
            };
            member.receipt = Some(receipt);
            member.unknown_evidence_ref = None;
        }
        E::MemberOutcomeUnknown {
            member_id,
            evidence_ref,
        } => {
            let member = next.members.get_mut(&member_id).expect("declared member");
            member.phase = M::Unknown;
            member.unknown_evidence_ref = Some(evidence_ref);
        }
        E::AuthoritativeQueryRequested {
            member_id,
            query_ref,
        } => next
            .members
            .get_mut(&member_id)
            .expect("declared member")
            .query_refs
            .push(query_ref),
        E::MemberCancelledBeforeStart {
            member_id,
            reason: _,
        } => {
            next.members
                .get_mut(&member_id)
                .expect("declared member")
                .phase = M::CancelledBeforeStart;
        }
        E::MemberSupersededBeforeStart {
            member_id,
            later_member_ref,
        } => {
            let member = next.members.get_mut(&member_id).expect("declared member");
            member.phase = M::SupersededBeforeStart;
            member.superseded_by = Some(later_member_ref);
        }
        E::CoordinatorPhaseChanged(phase) => next.phase = phase,
        E::CoordinatorCompensated { receipt_refs } => {
            next.phase = P::Compensated;
            next.compensation_receipt_refs = receipt_refs;
        }
        E::CoordinatorAbandonedPartial { reason } => {
            next.phase = P::AbandonedPartial;
            next.terminal_reason = Some(reason);
        }
    }
    next
}

impl Lifecycle for TargetSettlementState {
    type State = TargetSettlementState;
    type Command = TargetSettlementCommand;
    type Event = TargetSettlementEvent;

    const KIND: &'static str = "target_settlement";

    fn decide(state: &Self::State, command: Self::Command) -> Result<Vec<Self::Event>, Rejection> {
        decide(state, command)
    }

    fn evolve(state: &Self::State, event: Self::Event) -> Self::State {
        evolve(state, event)
    }
}

/// One declaration member queued in the stable target's Home-owned lane.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TargetLaneMember {
    pub settlement_scope: String,
    pub declaration_id: String,
    pub member_id: String,
    pub target_id: String,
    pub operation_id: String,
    pub expected_basis: String,
    pub expected_result_digest: String,
    pub attempt: u32,
}

impl TargetLaneMember {
    pub fn member_ref(&self) -> String {
        format!(
            "{}#{}#attempt:{}",
            self.settlement_scope, self.member_id, self.attempt
        )
    }

    fn valid(&self) -> bool {
        [
            &self.settlement_scope,
            &self.declaration_id,
            &self.member_id,
            &self.target_id,
            &self.operation_id,
            &self.expected_basis,
            &self.expected_result_digest,
        ]
        .into_iter()
        .all(valid_identity)
            && self.attempt > 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetLaneEntryPhase {
    Queued,
    Granted,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TargetLaneEntry {
    pub member: TargetLaneMember,
    pub phase: TargetLaneEntryPhase,
    pub permit: Option<TargetLanePermit>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TargetLaneResolution {
    pub member_ref: String,
    pub operation_id: String,
    pub outcome_ref: String,
    pub superseded: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TargetSettlementLaneState {
    pub target_id: Option<String>,
    pub queue: Vec<TargetLaneEntry>,
    pub resolved: Vec<TargetLaneResolution>,
    pub last_sequence: u64,
    pub history_events: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum TargetSettlementLaneCommand {
    Enqueue(TargetLaneMember),
    Grant {
        member_ref: String,
    },
    RecordKnownOutcome {
        member_ref: String,
        receipt_ref: String,
    },
    RecordUnknownOutcome {
        member_ref: String,
        evidence_ref: String,
    },
    ReconcileUnknown {
        member_ref: String,
        receipt_ref: String,
    },
    CancelQueued {
        member_ref: String,
        cancellation_ref: String,
    },
    SupersedeQueued {
        earlier_member_ref: String,
        later_member_ref: String,
        preflight_ref: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum TargetSettlementLaneEvent {
    MemberEnqueued(TargetLaneMember),
    MemberGranted {
        member_ref: String,
        permit: TargetLanePermit,
    },
    KnownOutcomeRecorded {
        member_ref: String,
        operation_id: String,
        receipt_ref: String,
    },
    UnknownOutcomeRecorded {
        member_ref: String,
        evidence_ref: String,
    },
    UnknownOutcomeReconciled {
        member_ref: String,
        operation_id: String,
        receipt_ref: String,
    },
    QueuedMemberCancelled {
        member_ref: String,
        operation_id: String,
        cancellation_ref: String,
    },
    QueuedMemberSuperseded {
        earlier_member_ref: String,
        operation_id: String,
        later_member_ref: String,
        preflight_ref: String,
    },
}

fn lane_reject(reason: &'static str) -> Result<Vec<TargetSettlementLaneEvent>, Rejection> {
    Err(Rejection { reason })
}

fn lane_entry<'a>(
    state: &'a TargetSettlementLaneState,
    member_ref: &str,
) -> Result<&'a TargetLaneEntry, Rejection> {
    state
        .queue
        .iter()
        .find(|entry| entry.member.member_ref() == member_ref)
        .ok_or(Rejection {
            reason: "target lane member is not queued",
        })
}

pub fn decide_target_lane(
    state: &TargetSettlementLaneState,
    command: TargetSettlementLaneCommand,
) -> Result<Vec<TargetSettlementLaneEvent>, Rejection> {
    use TargetLaneEntryPhase as P;
    use TargetSettlementLaneCommand as C;
    use TargetSettlementLaneEvent as E;

    match command {
        C::Enqueue(member) => {
            if !member.valid()
                || state
                    .target_id
                    .as_ref()
                    .is_some_and(|target| target != &member.target_id)
                || state
                    .queue
                    .iter()
                    .any(|entry| entry.member.member_ref() == member.member_ref())
                || state
                    .resolved
                    .iter()
                    .any(|entry| entry.member_ref == member.member_ref())
            {
                return lane_reject("enqueue: exact unique member for this target is required");
            }
            Ok(vec![E::MemberEnqueued(member)])
        }
        C::Grant { member_ref } => {
            let Some(first) = state.queue.first() else {
                return lane_reject("grant: target lane is empty");
            };
            if first.member.member_ref() != member_ref || first.phase != P::Queued {
                return lane_reject("grant: an earlier or unresolved target member blocks");
            }
            let sequence = state.last_sequence.checked_add(1).ok_or(Rejection {
                reason: "grant: target lane sequence overflowed",
            })?;
            let permit = TargetLanePermit {
                lane_id: format!("target-lane:{}", first.member.target_id),
                target_id: first.member.target_id.clone(),
                member_id: first.member.member_id.clone(),
                operation_id: first.member.operation_id.clone(),
                sequence,
                authority_position: format!("target-lane:{}:{sequence}", first.member.target_id),
            };
            Ok(vec![E::MemberGranted { member_ref, permit }])
        }
        C::RecordKnownOutcome {
            member_ref,
            receipt_ref,
        } => {
            let entry = lane_entry(state, &member_ref)?;
            if state.queue.first() != Some(entry)
                || entry.phase != P::Granted
                || !valid_identity(&receipt_ref)
            {
                return lane_reject("recordKnownOutcome: active granted member receipt required");
            }
            Ok(vec![E::KnownOutcomeRecorded {
                member_ref,
                operation_id: entry.member.operation_id.clone(),
                receipt_ref,
            }])
        }
        C::RecordUnknownOutcome {
            member_ref,
            evidence_ref,
        } => {
            let entry = lane_entry(state, &member_ref)?;
            if state.queue.first() != Some(entry)
                || entry.phase != P::Granted
                || !valid_identity(&evidence_ref)
            {
                return lane_reject("recordUnknownOutcome: active granted member required");
            }
            Ok(vec![E::UnknownOutcomeRecorded {
                member_ref,
                evidence_ref,
            }])
        }
        C::ReconcileUnknown {
            member_ref,
            receipt_ref,
        } => {
            let entry = lane_entry(state, &member_ref)?;
            if state.queue.first() != Some(entry)
                || entry.phase != P::OutcomeUnknown
                || !valid_identity(&receipt_ref)
            {
                return lane_reject("reconcileUnknown: authoritative receipt is required");
            }
            Ok(vec![E::UnknownOutcomeReconciled {
                member_ref,
                operation_id: entry.member.operation_id.clone(),
                receipt_ref,
            }])
        }
        C::CancelQueued {
            member_ref,
            cancellation_ref,
        } => {
            let entry = lane_entry(state, &member_ref)?;
            if entry.phase != P::Queued || !valid_identity(&cancellation_ref) {
                return lane_reject(
                    "cancelQueued: cancellation may remove only an unstarted member",
                );
            }
            Ok(vec![E::QueuedMemberCancelled {
                member_ref,
                operation_id: entry.member.operation_id.clone(),
                cancellation_ref,
            }])
        }
        C::SupersedeQueued {
            earlier_member_ref,
            later_member_ref,
            preflight_ref,
        } => {
            let earlier = lane_entry(state, &earlier_member_ref)?;
            let later = lane_entry(state, &later_member_ref)?;
            if earlier.phase != P::Queued
                || earlier_member_ref == later_member_ref
                || !valid_identity(&preflight_ref)
                || earlier.member.target_id != later.member.target_id
            {
                return lane_reject(
                    "supersedeQueued: later exact preflight may replace only an unstarted member",
                );
            }
            Ok(vec![E::QueuedMemberSuperseded {
                earlier_member_ref,
                operation_id: earlier.member.operation_id.clone(),
                later_member_ref,
                preflight_ref,
            }])
        }
    }
}

pub fn evolve_target_lane(
    state: &TargetSettlementLaneState,
    event: TargetSettlementLaneEvent,
) -> TargetSettlementLaneState {
    use TargetLaneEntryPhase as P;
    use TargetSettlementLaneEvent as E;
    let mut next = state.clone();
    next.history_events = next.history_events.saturating_add(1);
    match event {
        E::MemberEnqueued(member) => {
            next.target_id
                .get_or_insert_with(|| member.target_id.clone());
            next.queue.push(TargetLaneEntry {
                member,
                phase: P::Queued,
                permit: None,
            });
        }
        E::MemberGranted { member_ref, permit } => {
            let entry = next
                .queue
                .iter_mut()
                .find(|entry| entry.member.member_ref() == member_ref)
                .expect("queued member");
            next.last_sequence = permit.sequence;
            entry.phase = P::Granted;
            entry.permit = Some(permit);
        }
        E::KnownOutcomeRecorded {
            member_ref,
            operation_id,
            receipt_ref,
        }
        | E::UnknownOutcomeReconciled {
            member_ref,
            operation_id,
            receipt_ref,
        } => {
            next.queue.remove(0);
            next.resolved.push(TargetLaneResolution {
                member_ref,
                operation_id,
                outcome_ref: receipt_ref,
                superseded: false,
            });
        }
        E::UnknownOutcomeRecorded {
            member_ref,
            evidence_ref: _,
        } => {
            next.queue
                .iter_mut()
                .find(|entry| entry.member.member_ref() == member_ref)
                .expect("queued member")
                .phase = P::OutcomeUnknown;
        }
        E::QueuedMemberCancelled {
            member_ref,
            operation_id,
            cancellation_ref,
        } => {
            let index = next
                .queue
                .iter()
                .position(|entry| entry.member.member_ref() == member_ref)
                .expect("queued member");
            next.queue.remove(index);
            next.resolved.push(TargetLaneResolution {
                member_ref,
                operation_id,
                outcome_ref: cancellation_ref,
                superseded: true,
            });
        }
        E::QueuedMemberSuperseded {
            earlier_member_ref,
            operation_id,
            later_member_ref,
            preflight_ref,
        } => {
            let index = next
                .queue
                .iter()
                .position(|entry| entry.member.member_ref() == earlier_member_ref)
                .expect("queued member");
            next.queue.remove(index);
            next.resolved.push(TargetLaneResolution {
                member_ref: earlier_member_ref,
                operation_id,
                outcome_ref: format!("superseded-by:{later_member_ref}:{preflight_ref}"),
                superseded: true,
            });
        }
    }
    next
}

impl Lifecycle for TargetSettlementLaneState {
    type State = TargetSettlementLaneState;
    type Command = TargetSettlementLaneCommand;
    type Event = TargetSettlementLaneEvent;

    const KIND: &'static str = "target_settlement_lane";

    fn decide(state: &Self::State, command: Self::Command) -> Result<Vec<Self::Event>, Rejection> {
        decide_target_lane(state, command)
    }

    fn evolve(state: &Self::State, event: Self::Event) -> Self::State {
        evolve_target_lane(state, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn declared_member(id: &str, target: &str) -> SettlementMemberDeclaration {
        SettlementMemberDeclaration {
            member_id: id.into(),
            target_id: target.into(),
            operation_id: format!("operation:{id}"),
            expected_basis: format!("basis:{id}"),
            candidate_digest: format!("candidate:{id}"),
            expected_result_digest: format!("result:{id}"),
            policy_decision_handle: format!("policy:{id}"),
            adapter: "git/v1".into(),
            act: SettlementAct::Publish,
            retry_safe_after_failure: true,
            authoritative_query: true,
        }
    }

    fn declaration() -> TargetSettlementDeclaration {
        TargetSettlementDeclaration {
            declaration_id: "declaration:one".into(),
            project_id: "project:one".into(),
            chat_id: "chat:one".into(),
            source_change_set_ref: "target-change-set:one".into(),
            promotion_manifest_ref: Some("promotion:one".into()),
            members: vec![
                declared_member("a", "target-a"),
                declared_member("b", "target-b"),
            ],
        }
    }

    fn preflight(member: &SettlementMemberDeclaration, admitted: bool) -> MemberPreflightEvidence {
        MemberPreflightEvidence {
            member_id: member.member_id.clone(),
            observed_basis: member.expected_basis.clone(),
            observed_candidate_digest: member.candidate_digest.clone(),
            adapter_contract_ref: format!("adapter-contract:{}", member.adapter),
            governance_decision_ref: member.policy_decision_handle.clone(),
            admitted,
            refusal_reason: (!admitted).then(|| "stale basis".into()),
        }
    }

    fn permit(member: &SettlementMemberDeclaration, sequence: u64) -> TargetLanePermit {
        TargetLanePermit {
            lane_id: format!("lane:{}", member.target_id),
            target_id: member.target_id.clone(),
            member_id: member.member_id.clone(),
            operation_id: member.operation_id.clone(),
            sequence,
            authority_position: format!("position:{sequence}"),
        }
    }

    fn receipt(
        member: &SettlementMemberDeclaration,
        outcome: ReceiptOutcome,
    ) -> AuthenticatedTargetReceipt {
        AuthenticatedTargetReceipt {
            receipt_ref: format!("receipt:{}", member.member_id),
            member_id: member.member_id.clone(),
            target_id: member.target_id.clone(),
            operation_id: member.operation_id.clone(),
            expected_basis: member.expected_basis.clone(),
            resulting_basis: (outcome == ReceiptOutcome::Succeeded)
                .then(|| format!("basis:result:{}", member.member_id)),
            resulting_digest: (outcome == ReceiptOutcome::Succeeded)
                .then(|| member.expected_result_digest.clone()),
            outcome,
            authority_ref: format!("authority:{}", member.target_id),
            authentication_ref: format!("signature:{}", member.member_id),
            failure_reason: (outcome == ReceiptOutcome::Failed).then(|| "provider refused".into()),
        }
    }

    fn admit(state: &mut TargetSettlementState, command: TargetSettlementCommand) {
        let events = decide(state, command).expect("command admits");
        for event in events {
            *state = evolve(state, event);
        }
    }

    fn ready() -> TargetSettlementState {
        let mut state = TargetSettlementState::default();
        let declaration = declaration();
        let members = declaration.members.clone();
        admit(&mut state, TargetSettlementCommand::Declare(declaration));
        admit(&mut state, TargetSettlementCommand::BeginPreflight);
        for member in &members {
            admit(
                &mut state,
                TargetSettlementCommand::RecordPreflight(preflight(member, true)),
            );
        }
        assert_eq!(state.phase, SettlementPhase::Ready);
        state
    }

    #[test]
    fn one_failed_preflight_starts_nothing_and_is_terminal() {
        let mut state = TargetSettlementState::default();
        let declaration = declaration();
        let members = declaration.members.clone();
        admit(&mut state, TargetSettlementCommand::Declare(declaration));
        admit(&mut state, TargetSettlementCommand::BeginPreflight);
        admit(
            &mut state,
            TargetSettlementCommand::RecordPreflight(preflight(&members[0], true)),
        );
        admit(
            &mut state,
            TargetSettlementCommand::RecordPreflight(preflight(&members[1], false)),
        );
        assert_eq!(state.phase, SettlementPhase::Refused);
        assert_eq!(state.started_effects, 0);
        assert!(decide(
            &state,
            TargetSettlementCommand::StartMember {
                member_id: "a".into(),
                lane_permit: permit(&members[0], 1),
            }
        )
        .is_err());
    }

    #[test]
    fn successful_receipts_are_exact_and_nonrepeatable() {
        let mut state = ready();
        let members = declaration().members;
        for (index, member) in members.iter().enumerate() {
            admit(
                &mut state,
                TargetSettlementCommand::StartMember {
                    member_id: member.member_id.clone(),
                    lane_permit: permit(member, index as u64 + 1),
                },
            );
            let exact = receipt(member, ReceiptOutcome::Succeeded);
            admit(
                &mut state,
                TargetSettlementCommand::RecordReceipt(exact.clone()),
            );
            assert!(decide(&state, TargetSettlementCommand::RecordReceipt(exact)).is_err());
        }
        assert_eq!(state.phase, SettlementPhase::Completed);
    }

    #[test]
    fn unknown_outcome_can_only_settle_after_authoritative_query() {
        let mut state = ready();
        let member = declaration().members.remove(0);
        admit(
            &mut state,
            TargetSettlementCommand::StartMember {
                member_id: member.member_id.clone(),
                lane_permit: permit(&member, 1),
            },
        );
        admit(
            &mut state,
            TargetSettlementCommand::RecordUnknown {
                member_id: member.member_id.clone(),
                evidence_ref: "timeout:provider".into(),
            },
        );
        assert_eq!(state.phase, SettlementPhase::ReconciliationRequired);
        assert!(decide(
            &state,
            TargetSettlementCommand::RetryKnownFailure {
                member_id: member.member_id.clone(),
                lane_permit: permit(&member, 2),
            }
        )
        .is_err());
        assert!(decide(
            &state,
            TargetSettlementCommand::RecordQueryReceipt(receipt(
                &member,
                ReceiptOutcome::Succeeded
            ))
        )
        .is_err());
        admit(
            &mut state,
            TargetSettlementCommand::RequestAuthoritativeQuery {
                member_id: member.member_id.clone(),
                query_ref: "query:provider:one".into(),
            },
        );
        admit(
            &mut state,
            TargetSettlementCommand::RecordQueryReceipt(receipt(
                &member,
                ReceiptOutcome::Succeeded,
            )),
        );
        assert_eq!(
            state.members[&member.member_id].phase,
            SettlementMemberPhase::Succeeded
        );
        assert_ne!(
            state.phase,
            SettlementPhase::Completed,
            "one reconciled member cannot hide another member that has not started"
        );
        admit(
            &mut state,
            TargetSettlementCommand::CancelUnstarted {
                reason: "operator chose forward recovery".into(),
            },
        );
        assert_eq!(state.phase, SettlementPhase::PartiallyApplied);
    }

    #[test]
    fn only_not_started_members_can_be_superseded() {
        let mut state = ready();
        let members = declaration().members;
        admit(
            &mut state,
            TargetSettlementCommand::StartMember {
                member_id: members[0].member_id.clone(),
                lane_permit: permit(&members[0], 1),
            },
        );
        assert!(decide(
            &state,
            TargetSettlementCommand::SupersedeNotStarted {
                member_id: members[0].member_id.clone(),
                later_member_ref: "later:a".into(),
            }
        )
        .is_err());
        admit(
            &mut state,
            TargetSettlementCommand::SupersedeNotStarted {
                member_id: members[1].member_id.clone(),
                later_member_ref: "later:b".into(),
            },
        );
        assert_eq!(
            state.members[&members[1].member_id].phase,
            SettlementMemberPhase::SupersededBeforeStart
        );
    }

    #[test]
    fn a_mismatched_result_digest_never_completes_a_member() {
        let mut state = ready();
        let member = declaration().members.remove(0);
        admit(
            &mut state,
            TargetSettlementCommand::StartMember {
                member_id: member.member_id.clone(),
                lane_permit: permit(&member, 1),
            },
        );
        let mut forged = receipt(&member, ReceiptOutcome::Succeeded);
        forged.resulting_digest = Some("result:other".into());
        assert!(decide(&state, TargetSettlementCommand::RecordReceipt(forged)).is_err());
        assert_eq!(
            state.members[&member.member_id].phase,
            SettlementMemberPhase::Started
        );
    }

    fn lane_member(scope: &str, id: &str) -> TargetLaneMember {
        TargetLaneMember {
            settlement_scope: scope.into(),
            declaration_id: format!("declaration:{scope}"),
            member_id: id.into(),
            target_id: "target-a".into(),
            operation_id: format!("operation:{scope}:{id}"),
            expected_basis: format!("basis:{scope}"),
            expected_result_digest: format!("result:{scope}"),
            attempt: 1,
        }
    }

    fn admit_lane(state: &mut TargetSettlementLaneState, command: TargetSettlementLaneCommand) {
        let events = decide_target_lane(state, command).expect("lane command admits");
        for event in events {
            *state = evolve_target_lane(state, event);
        }
    }

    #[test]
    fn same_target_lane_blocks_later_effect_until_known_receipt() {
        let mut lane = TargetSettlementLaneState::default();
        let first = lane_member("settlement:one", "a");
        let second = lane_member("settlement:two", "a");
        let first_ref = first.member_ref();
        let second_ref = second.member_ref();
        admit_lane(&mut lane, TargetSettlementLaneCommand::Enqueue(first));
        admit_lane(&mut lane, TargetSettlementLaneCommand::Enqueue(second));
        assert!(decide_target_lane(
            &lane,
            TargetSettlementLaneCommand::Grant {
                member_ref: second_ref.clone(),
            }
        )
        .is_err());
        admit_lane(
            &mut lane,
            TargetSettlementLaneCommand::Grant {
                member_ref: first_ref.clone(),
            },
        );
        admit_lane(
            &mut lane,
            TargetSettlementLaneCommand::RecordUnknownOutcome {
                member_ref: first_ref.clone(),
                evidence_ref: "timeout:first".into(),
            },
        );
        assert!(decide_target_lane(
            &lane,
            TargetSettlementLaneCommand::Grant {
                member_ref: second_ref.clone(),
            }
        )
        .is_err());
        admit_lane(
            &mut lane,
            TargetSettlementLaneCommand::ReconcileUnknown {
                member_ref: first_ref,
                receipt_ref: "receipt:first".into(),
            },
        );
        admit_lane(
            &mut lane,
            TargetSettlementLaneCommand::Grant {
                member_ref: second_ref,
            },
        );
        assert_eq!(lane.queue[0].phase, TargetLaneEntryPhase::Granted);
    }

    #[test]
    fn lane_supersession_cannot_replace_a_started_or_unknown_member() {
        let mut lane = TargetSettlementLaneState::default();
        let first = lane_member("settlement:one", "a");
        let second = lane_member("settlement:two", "a");
        let first_ref = first.member_ref();
        let second_ref = second.member_ref();
        admit_lane(&mut lane, TargetSettlementLaneCommand::Enqueue(first));
        admit_lane(&mut lane, TargetSettlementLaneCommand::Enqueue(second));
        admit_lane(
            &mut lane,
            TargetSettlementLaneCommand::Grant {
                member_ref: first_ref.clone(),
            },
        );
        assert!(decide_target_lane(
            &lane,
            TargetSettlementLaneCommand::SupersedeQueued {
                earlier_member_ref: first_ref.clone(),
                later_member_ref: second_ref.clone(),
                preflight_ref: "preflight:current-basis".into(),
            }
        )
        .is_err());
        admit_lane(
            &mut lane,
            TargetSettlementLaneCommand::RecordUnknownOutcome {
                member_ref: first_ref.clone(),
                evidence_ref: "timeout:first".into(),
            },
        );
        assert!(decide_target_lane(
            &lane,
            TargetSettlementLaneCommand::SupersedeQueued {
                earlier_member_ref: first_ref,
                later_member_ref: second_ref,
                preflight_ref: "preflight:current-basis".into(),
            }
        )
        .is_err());
    }

    #[test]
    fn lane_cancellation_removes_only_an_unstarted_member() {
        let mut lane = TargetSettlementLaneState::default();
        let first = lane_member("settlement:cancel", "a");
        let first_ref = first.member_ref();
        admit_lane(&mut lane, TargetSettlementLaneCommand::Enqueue(first));
        admit_lane(
            &mut lane,
            TargetSettlementLaneCommand::CancelQueued {
                member_ref: first_ref.clone(),
                cancellation_ref: "cancellation:user".into(),
            },
        );
        assert!(lane.queue.is_empty());
        assert_eq!(lane.resolved[0].member_ref, first_ref);
        assert!(lane.resolved[0].superseded);

        let started = lane_member("settlement:started", "a");
        let started_ref = started.member_ref();
        admit_lane(&mut lane, TargetSettlementLaneCommand::Enqueue(started));
        admit_lane(
            &mut lane,
            TargetSettlementLaneCommand::Grant {
                member_ref: started_ref.clone(),
            },
        );
        assert!(decide_target_lane(
            &lane,
            TargetSettlementLaneCommand::CancelQueued {
                member_ref: started_ref,
                cancellation_ref: "cancellation:user".into(),
            }
        )
        .is_err());
    }

    proptest! {
        #[test]
        fn any_refused_preflight_preserves_zero_effects(
            decisions in prop::collection::vec(any::<bool>(), 1..8)
        ) {
            let declarations = decisions
                .iter()
                .enumerate()
                .map(|(index, _)| declared_member(&format!("m{index}"), &format!("t{index}")))
                .collect::<Vec<_>>();
            let declaration = TargetSettlementDeclaration {
                declaration_id: "declaration:property".into(),
                project_id: "project:property".into(),
                chat_id: "chat:property".into(),
                source_change_set_ref: "change-set:property".into(),
                promotion_manifest_ref: None,
                members: declarations.clone(),
            };
            let mut state = TargetSettlementState::default();
            admit(&mut state, TargetSettlementCommand::Declare(declaration));
            admit(&mut state, TargetSettlementCommand::BeginPreflight);
            for (member, admitted) in declarations.iter().zip(decisions.iter().copied()) {
                if state.phase == SettlementPhase::Refused {
                    break;
                }
                admit(
                    &mut state,
                    TargetSettlementCommand::RecordPreflight(preflight(member, admitted)),
                );
            }
            prop_assert_eq!(state.started_effects, 0);
            if decisions.iter().any(|admitted| !admitted) {
                prop_assert_eq!(state.phase, SettlementPhase::Refused);
            } else {
                prop_assert_eq!(state.phase, SettlementPhase::Ready);
            }
        }

        #[test]
        fn a_target_lane_grants_in_enqueue_order(count in 1usize..12) {
            let mut lane = TargetSettlementLaneState::default();
            let members = (0..count)
                .map(|index| lane_member(&format!("settlement:{index}"), "member"))
                .collect::<Vec<_>>();
            for member in &members {
                admit_lane(
                    &mut lane,
                    TargetSettlementLaneCommand::Enqueue(member.clone()),
                );
            }
            for (index, member) in members.iter().enumerate() {
                let member_ref = member.member_ref();
                admit_lane(
                    &mut lane,
                    TargetSettlementLaneCommand::Grant {
                        member_ref: member_ref.clone(),
                    },
                );
                prop_assert_eq!(
                    lane.queue[0].permit.as_ref().map(|permit| permit.sequence),
                    Some(index as u64 + 1),
                );
                admit_lane(
                    &mut lane,
                    TargetSettlementLaneCommand::RecordKnownOutcome {
                        member_ref,
                        receipt_ref: format!("receipt:{index}"),
                    },
                );
            }
            prop_assert!(lane.queue.is_empty());
            prop_assert_eq!(lane.resolved.len(), count);
        }
    }
}
