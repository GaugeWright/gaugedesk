//! Agent run lifecycle — the `(decide, evolve)` reducer pair (ADR 0004), ported
//! from `specs/models/run-lifecycle.qnt`.
//!
//! A run is one episode of agent work (ADR 0026). It discharges `INV-11`
//! (execution consumes admitted work): a run reaches `Running` only after
//! admission, and a retried run must be re-admitted before it can run again.

/// Legal run states. `Completed | Failed | Canceled` are terminal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RunPhase {
    #[default]
    Init,
    Requested,
    Admitted,
    Running,
    Completed,
    Failed,
    Canceled,
}

use crate::ids::ClientRequestId;

/// Folded run state. `admitted_once` is the history bit `INV-11` rests on; a
/// retry resets it so a fresh attempt cannot run without being re-admitted.
/// `observations` counts admitted execution-evidence records (`INV-4`).
///
/// `pending_commands` is the optimistic-reconcile ledger (MOB-003): while the
/// run is running, the client tags each command it issues with a
/// [`ClientRequestId`] and that id sits here until the authoritative effect is
/// observed and the client reconciles it away. The ledger is scoped to the
/// running attempt — any terminal/retry transition clears it, so a client never
/// reconciles against a dead run (`PENDING_ONLY_WHILE_RUNNING`).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RunState {
    pub phase: RunPhase,
    pub admitted_once: bool,
    pub observations: u32,
    /// Outstanding optimistic client commands awaiting reconciliation (MOB-003).
    #[serde(default)]
    pub pending_commands: Vec<ClientRequestId>,
}

/// Accepted commands (requests; `INV-2`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RunCommand {
    RequestRun,
    AdmitRun,
    StartRun,
    /// Admit one execution-evidence record from the runtime (`INV-4`).
    RecordObservation,
    /// Pause the current admitted attempt at a labeled runtime question.
    /// Resume the same admitted attempt after GaugeDesk authenticates the respondent.
    /// Record one optimistic client command, tagged with its [`ClientRequestId`],
    /// while the run is running (MOB-003).
    RecordPending(ClientRequestId),
    /// Settle a pending optimistic command once its effect is observed (MOB-003).
    Reconcile(ClientRequestId),
    CompleteRun,
    FailRun,
    CancelRun,
    RetryRun,
}

/// Emitted events (facts; `INV-3`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RunEvent {
    RunRequested,
    RunAdmitted,
    RunStarted,
    ObservationRecorded,
    /// An optimistic client command was recorded as pending (MOB-003).
    PendingRecorded(ClientRequestId),
    /// A pending optimistic command was reconciled away (MOB-003).
    Reconciled(ClientRequestId),
    RunCompleted,
    RunFailed,
    RunCanceled,
    RunRetried,
}

pub use crate::Rejection;

fn reject(reason: &'static str) -> Result<Vec<RunEvent>, Rejection> {
    Err(Rejection { reason })
}

/// `decide: (state, command) -> events | rejection` — **pure**. Reads only the
/// state and the command; emits nothing on an illegal command.
pub fn decide(state: &RunState, command: RunCommand) -> Result<Vec<RunEvent>, Rejection> {
    use RunCommand as C;
    use RunEvent as E;
    use RunPhase::*;
    match command {
        C::RequestRun => match state.phase {
            Init => Ok(vec![E::RunRequested]),
            _ => reject("requestRun: not in init"),
        },
        C::AdmitRun => match state.phase {
            Requested => Ok(vec![E::RunAdmitted]),
            _ => reject("admitRun: not requested"),
        },
        // INV-11: the only path to Running, and it requires Admitted.
        C::StartRun => match state.phase {
            Admitted => Ok(vec![E::RunStarted]),
            _ => reject("startRun: not admitted (INV-11)"),
        },
        // INV-4: execution evidence becomes standing state only by admission here,
        // and only while the run is running.
        C::RecordObservation => match state.phase {
            Running => Ok(vec![E::ObservationRecorded]),
            _ => reject("recordObservation: run is not running (INV-4)"),
        },
        // MOB-003: an optimistic command may only be recorded while running, and
        // its id must be fresh so two distinct optimistic commands never collapse.
        C::RecordPending(rid) => match state.phase {
            Running if !state.pending_commands.contains(&rid) => Ok(vec![E::PendingRecorded(rid)]),
            Running => reject("recordPending: clientRequestId already pending"),
            _ => reject("recordPending: run is not running (MOB-003)"),
        },
        // MOB-003: only a currently-pending command may be reconciled.
        C::Reconcile(rid) => {
            if state.pending_commands.contains(&rid) {
                Ok(vec![E::Reconciled(rid)])
            } else {
                reject("reconcile: clientRequestId is not pending")
            }
        }
        C::CompleteRun => match state.phase {
            Running => Ok(vec![E::RunCompleted]),
            _ => reject("completeRun: not running"),
        },
        C::FailRun => match state.phase {
            Running => Ok(vec![E::RunFailed]),
            _ => reject("failRun: not running"),
        },
        C::CancelRun => match state.phase {
            Requested | Admitted | Running => Ok(vec![E::RunCanceled]),
            _ => reject("cancelRun: already terminal"),
        },
        // Re-entry from any terminal state: failed/canceled is a retry; completed
        // begins the engagement's next turn (ADR 0026). Re-admission still required.
        C::RetryRun => match state.phase {
            Completed | Failed | Canceled => Ok(vec![E::RunRetried]),
            _ => reject("retryRun: run is not terminal"),
        },
    }
}

/// `evolve: (state, event) -> state` — **pure** fold. A terminal/retry event
/// clears `pending_commands`: optimistic work is scoped to the running attempt,
/// so it never survives into a dead run (MOB-003, `PENDING_ONLY_WHILE_RUNNING`).
pub fn evolve(state: &RunState, event: RunEvent) -> RunState {
    use RunEvent::*;
    use RunPhase as P;
    // A terminal/retry state holds no pending optimistic commands.
    let terminal = |phase, admitted_once| RunState {
        phase,
        admitted_once,
        observations: state.observations,
        pending_commands: Vec::new(),
    };
    match event {
        RunRequested => RunState {
            phase: P::Requested,
            ..state.clone()
        },
        RunAdmitted => RunState {
            phase: P::Admitted,
            admitted_once: true,
            ..state.clone()
        },
        RunStarted => RunState {
            phase: P::Running,
            ..state.clone()
        },
        // INV-4: an admitted observation updates run evidence without a phase change.
        ObservationRecorded => RunState {
            observations: state.observations + 1,
            ..state.clone()
        },
        // MOB-003: append the optimistic command to the pending ledger.
        PendingRecorded(rid) => {
            let mut pending = state.pending_commands.clone();
            pending.push(rid);
            RunState {
                pending_commands: pending,
                ..state.clone()
            }
        }
        // MOB-003: drop the reconciled command from the pending ledger.
        Reconciled(rid) => {
            let pending = state
                .pending_commands
                .iter()
                .filter(|p| **p != rid)
                .cloned()
                .collect();
            RunState {
                pending_commands: pending,
                ..state.clone()
            }
        }
        RunCompleted => terminal(P::Completed, state.admitted_once),
        RunFailed => terminal(P::Failed, state.admitted_once),
        RunCanceled => terminal(P::Canceled, state.admitted_once),
        // a retry returns to Requested and clears admission + evidence (re-admit).
        RunRetried => RunState {
            phase: P::Requested,
            admitted_once: false,
            observations: 0,
            pending_commands: Vec::new(),
        },
    }
}

impl crate::Lifecycle for RunState {
    type State = RunState;
    type Command = RunCommand;
    type Event = RunEvent;
    const KIND: &'static str = "run";
    fn decide(state: &RunState, command: RunCommand) -> Result<Vec<RunEvent>, Rejection> {
        decide(state, command)
    }
    fn evolve(state: &RunState, event: RunEvent) -> RunState {
        evolve(state, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Drive one command: admit on success (commands → events → fold), no change
    /// on rejection (commands are requests, not facts — `INV-2`).
    fn apply(state: &RunState, command: RunCommand) -> RunState {
        match decide(state, command) {
            Ok(events) => events.into_iter().fold(state.clone(), |s, e| evolve(&s, e)),
            Err(_) => state.clone(),
        }
    }

    fn drive(commands: &[RunCommand]) -> RunState {
        commands
            .iter()
            .fold(RunState::default(), |s, c| apply(&s, c.clone()))
    }

    // Deterministic scenarios mirroring run-lifecycle.qnt's runs.
    #[test]
    fn happy_run() {
        use RunCommand::*;
        let s = drive(&[RequestRun, AdmitRun, StartRun, CompleteRun]);
        assert_eq!(s.phase, RunPhase::Completed);
    }

    #[test]
    fn cancel_mid_run() {
        use RunCommand::*;
        let s = drive(&[RequestRun, AdmitRun, StartRun, CancelRun]);
        assert_eq!(s.phase, RunPhase::Canceled);
    }

    #[test]
    fn retry_readmits() {
        use RunCommand::*;
        let s = drive(&[RequestRun, AdmitRun, StartRun, FailRun, RetryRun]);
        assert_eq!(s.phase, RunPhase::Requested);
        assert!(
            !s.admitted_once,
            "a retried run must be re-admitted before running"
        );
    }

    #[test]
    fn start_without_admission_is_rejected() {
        use RunCommand::*;
        let s = drive(&[RequestRun, StartRun]); // skip AdmitRun
        assert_eq!(
            s.phase,
            RunPhase::Requested,
            "StartRun must be rejected from Requested"
        );
    }

    // run-lifecycle.qnt observationDuringRun: an observation is admitted only while
    // running, and updates evidence without changing the phase (INV-4).
    #[test]
    fn observation_during_run() {
        use RunCommand::*;
        let s = drive(&[RequestRun, AdmitRun, StartRun, RecordObservation]);
        assert_eq!(s.phase, RunPhase::Running);
        assert_eq!(s.observations, 1);
        // an observation before running is rejected (no admission of evidence yet).
        let s2 = drive(&[RequestRun, AdmitRun, RecordObservation]);
        assert_eq!(
            s2.observations, 0,
            "no observation before the run is running"
        );
    }

    // MOB-003: a run with a pending optimistic command and not running is the
    // bug `PENDING_ONLY_WHILE_RUNNING` forbids; a `terminal`/`retry` evolve that
    // forgot to clear `pending_commands` would let the proptest below trip.
    #[test]
    fn optimistic_command_is_pending_then_reconciled() {
        use RunCommand::*;
        let rid = ClientRequestId::new("req-1");
        let s = drive(&[RequestRun, AdmitRun, StartRun, RecordPending(rid.clone())]);
        assert_eq!(s.phase, RunPhase::Running);
        assert_eq!(s.pending_commands, vec![rid.clone()]);
        // Reconciling the id settles it; the run is otherwise unchanged.
        let s2 = apply(&s, Reconcile(rid.clone()));
        assert!(
            s2.pending_commands.is_empty(),
            "reconcile drops the pending command"
        );
        assert_eq!(s2.phase, RunPhase::Running);
        // A pending command before the run is running is rejected.
        let s3 = drive(&[RequestRun, AdmitRun, RecordPending(rid)]);
        assert!(
            s3.pending_commands.is_empty(),
            "no optimistic command before running"
        );
    }

    // MOB-003: a terminal run holds nothing pending to reconcile against.
    #[test]
    fn terminal_run_clears_pending() {
        use RunCommand::*;
        let rid = ClientRequestId::new("req-1");
        let s = drive(&[
            RequestRun,
            AdmitRun,
            StartRun,
            RecordPending(rid),
            CompleteRun,
        ]);
        assert_eq!(s.phase, RunPhase::Completed);
        assert!(
            s.pending_commands.is_empty(),
            "PENDING_ONLY_WHILE_RUNNING: terminal clears pending"
        );
    }

    fn arb_command() -> impl Strategy<Value = RunCommand> {
        use RunCommand::*;
        // Two representative optimistic ids mirror the Quint model's RIDS.
        let rid = prop_oneof![Just("c1"), Just("c2")].prop_map(ClientRequestId::new);
        prop_oneof![
            Just(RequestRun),
            Just(AdmitRun),
            Just(StartRun),
            Just(RecordObservation),
            rid.clone().prop_map(RecordPending),
            rid.prop_map(Reconcile),
            Just(CompleteRun),
            Just(FailRun),
            Just(CancelRun),
            Just(RetryRun),
        ]
    }

    proptest! {
        /// INV-11 / RUN_NEEDS_ADMISSION: a run is `Running` only if admitted; and
        /// INV-4: any admitted observation was recorded while running, so a run with
        /// observations must have been admitted. MOB-003 /
        /// PENDING_ONLY_WHILE_RUNNING: an optimistic command is only ever pending
        /// while running, so the client never reconciles a dead run.
        /// (Quint: run-lifecycle.qnt.)
        #[test]
        fn run_needs_admission(commands in prop::collection::vec(arb_command(), 0..40)) {
            let mut s = RunState::default();
            for c in &commands {
                s = apply(&s, c.clone());
                if matches!(s.phase, RunPhase::Running) {
                    prop_assert!(s.admitted_once, "INV-11 violated: running without admission");
                }
                // INV-4: evidence only enters via admission while running.
                if s.observations > 0 {
                    prop_assert!(s.admitted_once, "INV-4 violated: observation without admission");
                }
                // MOB-003: a pending optimistic command implies the run is running.
                if !s.pending_commands.is_empty() {
                    prop_assert_eq!(
                        s.phase,
                        RunPhase::Running,
                        "PENDING_ONLY_WHILE_RUNNING violated: pending command in a non-running run"
                    );
                }
            }
        }
    }
}
