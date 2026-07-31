//! Engagement→`main` merge lifecycle — policy-gated, conflict-repairable. Ported
//! from `specs/models/merge-lifecycle.qnt` (itself from the TLA+
//! `WorkstreamMergeRepair`).
//!
//! Workspace reconciliation is automatic, but advancing the standing line (`main`)
//! is **admitted**: it happens only on a clean substrate merge AND admitted policy.
//! Shared-line policy auto-admits ordinary clean turns; an explicit per-change review
//! defers that admission to the human. A
//! workspace conflict or a policy reject **isolates** the
//! engagement with a preserved candidate and a repair context; repair retries are
//! idempotent (the ref advances at most once). A partial merge is never settled.
//!
//! The reducer is pure: the imperative shell asks the workspace for a verdict and
//! surfaces requested review, then issues `WorkspaceClean`/`WorkspaceConflict` and the policy
//! command. Discharges (`INV`-grade): standing-advance-requires-workspace-and-policy ·
//! rejected-preserves-repair-basis · partial-merge-never-standing ·
//! repair-retry-idempotent · isolated-thread-not-current-without-repair ·
//! mainline-integration-requires-boundary (`[M1]`).

use std::collections::BTreeSet;

use crate::Rejection;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MergePhase {
    Idle,
    Merging,
    Clean,
    Rejected,
    Repairing,
    Advanced,
    /// `[M1]` the workstream→mainline hop.
    Integrated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WorkspaceOutcome {
    Unknown,
    Success,
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PolicyOutcome {
    Unknown,
    Admitted,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ThreadState {
    Current,
    MergePending,
    Isolated,
    Repairing,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct MergeState {
    pub phase: MergePhase,
    /// Serialized under the historical `git_outcome` field for replay and
    /// mixed-client compatibility; its semantics are substrate-neutral.
    #[serde(rename = "git_outcome")]
    pub workspace_outcome: WorkspaceOutcome,
    pub policy_outcome: PolicyOutcome,
    pub candidate_preserved: bool,
    pub repair_context_created: bool,
    pub thread_state: ThreadState,
    pub partial_merge_exposed: bool,
    pub standing_advanced: bool,
    pub standing_advance_count: u32,
    pub retry_keys_used: BTreeSet<String>,
    pub boundary_command_admitted: bool,
    /// The current clean candidate was explicitly held for human review. Clean by
    /// itself is a workspace verdict; this fact distinguishes an intentional hold
    /// from the auto-admit default (ADR 0096).
    pub review_requested: bool,
}

impl Default for MergeState {
    fn default() -> Self {
        Self {
            phase: MergePhase::Idle,
            workspace_outcome: WorkspaceOutcome::Unknown,
            policy_outcome: PolicyOutcome::Unknown,
            candidate_preserved: false,
            repair_context_created: false,
            thread_state: ThreadState::Current,
            partial_merge_exposed: false,
            standing_advanced: false,
            standing_advance_count: 0,
            retry_keys_used: BTreeSet::new(),
            boundary_command_admitted: false,
            review_requested: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeCommand {
    /// The engagement's work is committed; attempt to merge into the standing ref.
    StartMerge,
    /// Workspace reports a clean merge (no partial state exposed).
    WorkspaceClean,
    /// Workspace reports a conflict (isolate and preserve the candidate).
    WorkspaceConflict,
    /// Hold this clean candidate for explicit per-change review.
    RequestReview,
    /// The human reviewed the diff and admitted.
    PolicyAdmit,
    /// The human reviewed the diff and rejected.
    PolicyReject,
    /// Advance the standing line (`main`) — only on a clean workspace verdict + policy.
    AdvanceStandingRef,
    /// Submit a repair for an isolated engagement.
    SubmitRepair,
    /// Retry the merge after repair (idempotent by `key`).
    RetryRepair(String),
    /// `[M1]` admit the boundary command for workstream→mainline.
    AdmitBoundaryIntegration,
    /// `[M1]` integrate the workstream into mainline.
    IntegrateToMainline,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MergeEvent {
    MergeStarted,
    /// Historical logs and clients retain the pre-SUB-2 event spelling.
    #[serde(rename = "GitCleaned")]
    WorkspaceCleaned,
    #[serde(rename = "GitConflicted")]
    WorkspaceConflicted,
    ReviewRequested,
    PolicyAdmitted,
    PolicyRejected,
    StandingRefAdvanced,
    RepairSubmitted,
    RepairRetried(String),
    BoundaryIntegrationAdmitted,
    IntegratedToMainline,
}

fn reject(reason: &'static str) -> Result<Vec<MergeEvent>, Rejection> {
    Err(Rejection { reason })
}

pub fn decide(state: &MergeState, command: MergeCommand) -> Result<Vec<MergeEvent>, Rejection> {
    use MergePhase::*;
    match command {
        // Re-enters and resets the cycle: the merge is branch-vs-`main`,
        // re-evaluated each turn. Only the transient `Merging` (substrate verdict pending) blocks.
        MergeCommand::StartMerge => match state.phase {
            Merging => reject("startMerge: a merge is already running"),
            _ => Ok(vec![MergeEvent::MergeStarted]),
        },
        MergeCommand::WorkspaceClean => match state.phase {
            Merging => Ok(vec![MergeEvent::WorkspaceCleaned]),
            _ => reject("workspaceClean: not merging"),
        },
        MergeCommand::WorkspaceConflict => match state.phase {
            Merging => Ok(vec![MergeEvent::WorkspaceConflicted]),
            _ => reject("workspaceConflict: not merging"),
        },
        MergeCommand::RequestReview => match state.phase {
            Clean => Ok(vec![MergeEvent::ReviewRequested]),
            _ => reject("requestReview: not a clean candidate"),
        },
        MergeCommand::PolicyAdmit => {
            if state.phase == Clean && state.workspace_outcome == WorkspaceOutcome::Success {
                Ok(vec![MergeEvent::PolicyAdmitted])
            } else {
                reject("policyAdmit: not a clean merge awaiting review")
            }
        }
        MergeCommand::PolicyReject => match state.phase {
            Clean => Ok(vec![MergeEvent::PolicyRejected]),
            _ => reject("policyReject: not a clean merge awaiting review"),
        },
        // STANDING_ADVANCE_REQUIRES_GIT_AND_POLICY + idempotent (≤ once).
        MergeCommand::AdvanceStandingRef => {
            let gated = state.phase == Clean
                && state.workspace_outcome == WorkspaceOutcome::Success
                && state.policy_outcome == PolicyOutcome::Admitted;
            if gated && state.standing_advance_count == 0 {
                Ok(vec![MergeEvent::StandingRefAdvanced])
            } else {
                reject("advanceStandingRef: needs clean workspace + admitted policy, once")
            }
        }
        MergeCommand::SubmitRepair => {
            if state.phase == Rejected && state.repair_context_created {
                Ok(vec![MergeEvent::RepairSubmitted])
            } else {
                reject("submitRepair: no repair context")
            }
        }
        // Idempotent: a used key cannot re-advance; advances at most once.
        MergeCommand::RetryRepair(key) => {
            let ok = state.phase == Repairing
                && !state.retry_keys_used.contains(&key)
                && state.standing_advance_count == 0;
            if ok {
                Ok(vec![MergeEvent::RepairRetried(key)])
            } else {
                reject("retryRepair: not repairing, key used, or already advanced")
            }
        }
        MergeCommand::AdmitBoundaryIntegration => match state.phase {
            Advanced => Ok(vec![MergeEvent::BoundaryIntegrationAdmitted]),
            _ => reject("admitBoundaryIntegration: not advanced"),
        },
        // MAINLINE_INTEGRATION_REQUIRES_BOUNDARY.
        MergeCommand::IntegrateToMainline => {
            if state.phase == Advanced && state.boundary_command_admitted {
                Ok(vec![MergeEvent::IntegratedToMainline])
            } else {
                reject("integrateToMainline: needs an admitted boundary command")
            }
        }
    }
}

pub fn evolve(state: &MergeState, event: MergeEvent) -> MergeState {
    use MergePhase as P;
    let mut s = state.clone();
    match event {
        MergeEvent::MergeStarted => {
            // Reset the cycle (re-entrant per turn), then enter merging.
            s = MergeState {
                phase: P::Merging,
                thread_state: ThreadState::MergePending,
                ..MergeState::default()
            };
        }
        MergeEvent::WorkspaceCleaned => {
            s.phase = P::Clean;
            s.workspace_outcome = WorkspaceOutcome::Success;
        }
        MergeEvent::WorkspaceConflicted => {
            s.phase = P::Rejected;
            s.workspace_outcome = WorkspaceOutcome::Conflict;
            s.candidate_preserved = true;
            s.repair_context_created = true;
            s.thread_state = ThreadState::Isolated;
        }
        MergeEvent::ReviewRequested => s.review_requested = true,
        MergeEvent::PolicyAdmitted => s.policy_outcome = PolicyOutcome::Admitted,
        MergeEvent::PolicyRejected => {
            s.phase = P::Rejected;
            s.policy_outcome = PolicyOutcome::Rejected;
            s.candidate_preserved = true;
            s.repair_context_created = true;
            s.thread_state = ThreadState::Isolated;
        }
        MergeEvent::StandingRefAdvanced => {
            s.phase = P::Advanced;
            s.standing_advanced = true;
            s.standing_advance_count += 1;
            s.thread_state = ThreadState::Current;
        }
        MergeEvent::RepairSubmitted => {
            s.phase = P::Repairing;
            s.thread_state = ThreadState::Repairing;
        }
        MergeEvent::RepairRetried(key) => {
            s.retry_keys_used.insert(key);
            s.workspace_outcome = WorkspaceOutcome::Success;
            s.policy_outcome = PolicyOutcome::Admitted;
            s.standing_advanced = true;
            s.standing_advance_count += 1;
            s.phase = P::Advanced;
            s.thread_state = ThreadState::Current;
        }
        MergeEvent::BoundaryIntegrationAdmitted => s.boundary_command_admitted = true,
        MergeEvent::IntegratedToMainline => s.phase = P::Integrated,
    }
    s
}

impl crate::Lifecycle for MergeState {
    type State = MergeState;
    type Command = MergeCommand;
    type Event = MergeEvent;
    const KIND: &'static str = "merge";
    fn decide(state: &MergeState, command: MergeCommand) -> Result<Vec<MergeEvent>, Rejection> {
        decide(state, command)
    }
    fn evolve(state: &MergeState, event: MergeEvent) -> MergeState {
        evolve(state, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn apply(state: &MergeState, command: MergeCommand) -> MergeState {
        match decide(state, command) {
            Ok(events) => events.into_iter().fold(state.clone(), |s, e| evolve(&s, e)),
            Err(_) => state.clone(),
        }
    }

    #[test]
    fn clean_admit_advances() {
        use MergeCommand::*;
        let s = MergeState::default();
        let s = apply(&s, StartMerge);
        let s = apply(&s, WorkspaceClean);
        let s = apply(&s, PolicyAdmit);
        let s = apply(&s, AdvanceStandingRef);
        assert_eq!(s.phase, MergePhase::Advanced);
        assert!(s.standing_advanced && s.standing_advance_count == 1);
    }

    #[test]
    fn explicit_review_is_a_durable_fact_on_the_clean_candidate() {
        use MergeCommand::*;
        let s = apply(&MergeState::default(), StartMerge);
        let s = apply(&s, WorkspaceClean);
        let s = apply(&s, RequestReview);
        assert_eq!(s.phase, MergePhase::Clean);
        assert!(s.review_requested);

        let next = apply(&s, StartMerge);
        assert_eq!(next.phase, MergePhase::Merging);
        assert!(
            !next.review_requested,
            "the hold applies to one candidate only"
        );
    }

    #[test]
    fn conflict_isolates_then_repairs() {
        use MergeCommand::*;
        let s = MergeState::default();
        let s = apply(&s, StartMerge);
        let s = apply(&s, WorkspaceConflict);
        assert_eq!(s.phase, MergePhase::Rejected);
        assert!(s.candidate_preserved && s.thread_state == ThreadState::Isolated);
        let s = apply(&s, SubmitRepair);
        let s = apply(&s, RetryRepair("k1".into()));
        assert_eq!(s.phase, MergePhase::Advanced);
        assert_eq!(s.standing_advance_count, 1);
    }

    #[test]
    fn policy_reject_isolates_main_untouched() {
        use MergeCommand::*;
        let s = MergeState::default();
        let s = apply(&s, StartMerge);
        let s = apply(&s, WorkspaceClean);
        let s = apply(&s, PolicyReject);
        assert_eq!(s.phase, MergePhase::Rejected);
        assert!(!s.standing_advanced && s.thread_state == ThreadState::Isolated);
    }

    fn arb_command() -> impl Strategy<Value = MergeCommand> {
        use MergeCommand::*;
        let key = prop_oneof![Just("k1".to_string()), Just("k2".to_string())];
        prop_oneof![
            Just(StartMerge),
            Just(WorkspaceClean),
            Just(WorkspaceConflict),
            Just(RequestReview),
            Just(PolicyAdmit),
            Just(PolicyReject),
            Just(AdvanceStandingRef),
            Just(SubmitRepair),
            key.prop_map(RetryRepair),
            Just(AdmitBoundaryIntegration),
            Just(IntegrateToMainline),
        ]
    }

    proptest! {
        /// All six merge invariants hold over every reachable trace.
        #[test]
        fn merge_invariants(commands in prop::collection::vec(arb_command(), 0..60)) {
            let mut s = MergeState::default();
            for c in commands {
                s = apply(&s, c);
                // STANDING_ADVANCE_REQUIRES_GIT_AND_POLICY
                if s.standing_advanced {
                    prop_assert_eq!(s.workspace_outcome, WorkspaceOutcome::Success);
                    prop_assert_eq!(s.policy_outcome, PolicyOutcome::Admitted);
                }
                // REJECTED_MERGE_PRESERVES_REPAIR_BASIS
                if s.phase == MergePhase::Rejected {
                    prop_assert!(s.candidate_preserved && s.repair_context_created);
                }
                // PARTIAL_MERGE_NOT_STANDING
                prop_assert!(!s.partial_merge_exposed);
                // REPAIR_RETRY_IDEMPOTENT
                prop_assert!(s.standing_advance_count <= 1);
                // ISOLATED_THREAD_NOT_CURRENT_WITHOUT_REPAIR
                if s.phase == MergePhase::Rejected {
                    prop_assert_eq!(s.thread_state, ThreadState::Isolated);
                }
                // MAINLINE_INTEGRATION_REQUIRES_BOUNDARY
                if s.phase == MergePhase::Integrated {
                    prop_assert!(s.boundary_command_admitted);
                }
            }
        }
    }
}
