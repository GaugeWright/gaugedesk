//! Runtime execution-attempt lifecycle — one *turn* of an engagement, ported
//! from `specs/models/runtime-session.qnt`.
//!
//! This is the reducer the runtime shell drives: it materializes the
//! prerequisites (run admitted, boundary session active, bases granted) and then
//! prepares → executes → records observations → admits them → mediates egress →
//! terminates. Discharges:
//! - `SESSION_REQUIRES_RUN_AND_BOUNDARY` — execution starts only from an admitted
//!   run in an active boundary session (`INV-11`).
//! - `HANDLE_REQUIRES_BASIS_AND_BOUNDARY` — payload handles resolve only through
//!   boundary + granted basis (`INV-10/11/12`).
//! - `OBSERVATION_REQUIRES_OWNER_ADMISSION` — a raw observation affects product
//!   truth only after **owner** admission, never the runtime's say-so (`INV-4`).
//! - `EGRESS_REQUIRES_BOUNDARY` — external effects are boundary-mediated.
//! - `TERMINAL_PRESERVES_EVIDENCE` — terminating never erases evidence (`INV-18`).

use crate::Rejection;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SessionPhase {
    Init,
    Prepared,
    Executing,
    Terminal,
}

/// Who admitted an observation into product truth. Only the owner may — the
/// runtime is never the admitting authority (`INV-4`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AdmittedBy {
    None,
    Owner,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionState {
    pub phase: SessionPhase,
    pub run_admitted: bool,
    pub boundary_active: bool,
    pub bases_granted: bool,
    pub prepared: bool,
    pub executing: bool,
    pub handle_resolved: bool,
    pub observation_produced: bool,
    pub observation_admitted: bool,
    pub observation_admitted_by: AdmittedBy,
    pub product_truth_has_observation: bool,
    pub egress_requested: bool,
    pub egress_mediated_by_boundary: bool,
    pub terminal: bool,
    pub evidence_present: bool,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            phase: SessionPhase::Init,
            run_admitted: false,
            boundary_active: false,
            bases_granted: false,
            prepared: false,
            executing: false,
            handle_resolved: false,
            observation_produced: false,
            observation_admitted: false,
            observation_admitted_by: AdmittedBy::None,
            product_truth_has_observation: false,
            egress_requested: false,
            egress_mediated_by_boundary: false,
            terminal: false,
            evidence_present: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionCommand {
    AdmitRun,
    StartBoundarySession,
    GrantBases,
    PrepareRuntimeSession,
    StartRuntimeSession,
    ResolveRuntimeHandle,
    RecordRuntimeObservation,
    OwnerAdmitObservation,
    RequestBoundaryEgress,
    TerminalOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SessionEvent {
    RunAdmitted,
    BoundarySessionStarted,
    BasesGranted,
    RuntimeSessionPrepared,
    RuntimeSessionStarted,
    RuntimeHandleResolved,
    RuntimeObservationRecorded,
    ObservationOwnerAdmitted,
    BoundaryEgressRequested,
    Terminated,
}

fn reject(reason: &'static str) -> Result<Vec<SessionEvent>, Rejection> {
    Err(Rejection { reason })
}

pub fn decide(
    state: &SessionState,
    command: SessionCommand,
) -> Result<Vec<SessionEvent>, Rejection> {
    use SessionCommand as C;
    use SessionPhase::*;
    match command {
        // Prerequisites — only from Init, before any execution.
        C::AdmitRun => match state.phase {
            Init => Ok(vec![SessionEvent::RunAdmitted]),
            _ => reject("admitRun: session already past init"),
        },
        C::StartBoundarySession => match state.phase {
            Init => Ok(vec![SessionEvent::BoundarySessionStarted]),
            _ => reject("startBoundarySession: session already past init"),
        },
        C::GrantBases => match state.phase {
            Init => Ok(vec![SessionEvent::BasesGranted]),
            _ => reject("grantBases: session already past init"),
        },
        // SESSION_REQUIRES_RUN_AND_BOUNDARY: prepare/start need both.
        C::PrepareRuntimeSession => {
            if state.phase == Init && state.run_admitted && state.boundary_active {
                Ok(vec![SessionEvent::RuntimeSessionPrepared])
            } else {
                reject("prepare: needs an admitted run in an active boundary session")
            }
        }
        C::StartRuntimeSession => {
            if state.phase == Prepared && state.run_admitted && state.boundary_active {
                Ok(vec![SessionEvent::RuntimeSessionStarted])
            } else {
                reject(
                    "start: not prepared with run + boundary (SESSION_REQUIRES_RUN_AND_BOUNDARY)",
                )
            }
        }
        // HANDLE_REQUIRES_BASIS_AND_BOUNDARY.
        C::ResolveRuntimeHandle => {
            if state.executing && state.boundary_active && state.bases_granted {
                Ok(vec![SessionEvent::RuntimeHandleResolved])
            } else {
                reject("resolveHandle: needs execution + boundary + granted basis")
            }
        }
        // OBSERVATION_REQUIRES_EXECUTION.
        C::RecordRuntimeObservation => {
            if state.executing {
                Ok(vec![SessionEvent::RuntimeObservationRecorded])
            } else {
                reject("recordObservation: only during execution")
            }
        }
        // OBSERVATION_REQUIRES_OWNER_ADMISSION: owner is the only admitter.
        C::OwnerAdmitObservation => {
            if state.observation_produced {
                Ok(vec![SessionEvent::ObservationOwnerAdmitted])
            } else {
                reject("ownerAdmit: no observation to admit")
            }
        }
        // EGRESS_REQUIRES_BOUNDARY: only during execution, mediated by boundary.
        C::RequestBoundaryEgress => {
            if state.executing && state.boundary_active {
                Ok(vec![SessionEvent::BoundaryEgressRequested])
            } else {
                reject("egress: needs execution within an active boundary session")
            }
        }
        C::TerminalOutcome => match state.phase {
            Prepared | Executing => Ok(vec![SessionEvent::Terminated]),
            _ => reject("terminal: only from prepared/executing"),
        },
    }
}

pub fn evolve(state: &SessionState, event: SessionEvent) -> SessionState {
    use SessionEvent as E;
    use SessionPhase::*;
    let mut s = state.clone();
    match event {
        E::RunAdmitted => s.run_admitted = true,
        E::BoundarySessionStarted => s.boundary_active = true,
        E::BasesGranted => s.bases_granted = true,
        E::RuntimeSessionPrepared => {
            s.phase = Prepared;
            s.prepared = true;
            s.evidence_present = true;
        }
        E::RuntimeSessionStarted => {
            s.phase = Executing;
            s.executing = true;
            s.evidence_present = true;
        }
        E::RuntimeHandleResolved => {
            s.handle_resolved = true;
            s.evidence_present = true;
        }
        E::RuntimeObservationRecorded => {
            s.observation_produced = true;
            s.evidence_present = true;
        }
        E::ObservationOwnerAdmitted => {
            s.observation_admitted = true;
            s.observation_admitted_by = AdmittedBy::Owner;
            s.product_truth_has_observation = true;
            s.evidence_present = true;
        }
        E::BoundaryEgressRequested => {
            s.egress_requested = true;
            s.egress_mediated_by_boundary = s.boundary_active; // boundary-mediated
            s.evidence_present = true;
        }
        E::Terminated => {
            s.phase = Terminal;
            s.executing = false;
            s.terminal = true;
            // evidence_present is preserved — terminating never erases it.
        }
    }
    s
}

impl crate::Lifecycle for SessionState {
    type State = SessionState;
    type Command = SessionCommand;
    type Event = SessionEvent;
    const KIND: &'static str = "runtime_session";
    fn decide(
        state: &SessionState,
        command: SessionCommand,
    ) -> Result<Vec<SessionEvent>, Rejection> {
        decide(state, command)
    }
    fn evolve(state: &SessionState, event: SessionEvent) -> SessionState {
        evolve(state, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn apply(state: &SessionState, command: SessionCommand) -> SessionState {
        match decide(state, command) {
            Ok(events) => events.into_iter().fold(state.clone(), |s, e| evolve(&s, e)),
            Err(_) => state.clone(),
        }
    }

    #[test]
    fn canonical_turn() {
        use SessionCommand::*;
        let s = SessionState::default();
        let s = apply(&s, AdmitRun);
        let s = apply(&s, StartBoundarySession);
        let s = apply(&s, GrantBases);
        let s = apply(&s, PrepareRuntimeSession);
        let s = apply(&s, StartRuntimeSession);
        assert_eq!(s.phase, SessionPhase::Executing);
        let s = apply(&s, ResolveRuntimeHandle);
        assert!(s.handle_resolved);
        let s = apply(&s, RecordRuntimeObservation);
        let s = apply(&s, RequestBoundaryEgress);
        assert!(s.egress_mediated_by_boundary, "egress is boundary-mediated");
        let s = apply(&s, OwnerAdmitObservation);
        assert_eq!(s.observation_admitted_by, AdmittedBy::Owner);
        let s = apply(&s, TerminalOutcome);
        assert!(
            s.terminal && s.evidence_present,
            "terminal preserves evidence"
        );
    }

    #[test]
    fn cannot_execute_without_run_and_boundary() {
        use SessionCommand::*;
        let s = SessionState::default();
        let s = apply(&s, AdmitRun); // boundary not started
        assert!(decide(&s, PrepareRuntimeSession).is_err());
    }

    fn arb_command() -> impl Strategy<Value = SessionCommand> {
        use SessionCommand::*;
        prop_oneof![
            Just(AdmitRun),
            Just(StartBoundarySession),
            Just(GrantBases),
            Just(PrepareRuntimeSession),
            Just(StartRuntimeSession),
            Just(ResolveRuntimeHandle),
            Just(RecordRuntimeObservation),
            Just(OwnerAdmitObservation),
            Just(RequestBoundaryEgress),
            Just(TerminalOutcome),
        ]
    }

    proptest! {
        /// The runtime-session invariants hold over every reachable trace.
        #[test]
        fn session_invariants(commands in prop::collection::vec(arb_command(), 0..60)) {
            let mut s = SessionState::default();
            for c in commands {
                s = apply(&s, c);
                // SESSION_REQUIRES_RUN_AND_BOUNDARY
                if s.executing {
                    prop_assert!(s.run_admitted && s.boundary_active);
                }
                // HANDLE_REQUIRES_BASIS_AND_BOUNDARY
                if s.handle_resolved {
                    prop_assert!(s.bases_granted && s.boundary_active);
                }
                // OBSERVATION_REQUIRES_OWNER_ADMISSION
                if s.product_truth_has_observation {
                    prop_assert_eq!(s.observation_admitted_by, AdmittedBy::Owner);
                }
                // EGRESS_REQUIRES_BOUNDARY
                if s.egress_requested {
                    prop_assert!(s.egress_mediated_by_boundary);
                }
                // TERMINAL_PRESERVES_EVIDENCE
                if s.terminal
                    && (s.observation_produced || s.egress_requested || s.handle_resolved)
                {
                    prop_assert!(s.evidence_present);
                }
            }
        }
    }
}
