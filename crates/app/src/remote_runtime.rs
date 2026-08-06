//! Remote runtime observation return (RT-1 / OBSERVATION-FEDERATION-1): a runtime
//! at a **non-local placement** returns its execution observations to the owning
//! admission shell *through federation* (FED-2), where they become run evidence
//! only when the **owner** admits them (`INV-4`).
//!
//! A remote-placed runtime is reached as a [`RemoteHarness`] (`REMOTE-RPC-1`): the
//! turn runs in a *different* trust authority and its [`Observation`]s come back
//! across the `PROTO-1` RPC envelope. Those observations are **not** local truth —
//! they cross the owner's bridge as signed federated messages over the
//! [`FederationRelay`] seam (`RELAY-TRAIT-1`, `INV-21`), and only the **owner's**
//! `RecordObservation` admission turns each one into standing run state (`INV-4`).
//! The relay is transport only: it never writes the run fact and holds no payload
//! basis (`INV-13`/`INV-14`), and only the observation's **handle** crosses, never
//! its body (`INV-10`).
//!
//! Exercised in the loopback two-authority shape; a real cross-machine runtime is
//! the `D-REMOTE` follow-on, and TEE-attested placement is `D-ATTEST` — the return
//! mechanism is the same regardless.

use gaugedesk_core::run::{RunCommand, RunState};
use gaugedesk_harness::{EgressGate, Observation, RemoteHarness};
use gaugedesk_store::{AdmitError, Store};

use crate::federation_relay::{FederationRelay, Message};

/// The error surface of a federated remote turn: the remote turn failed over the
/// RPC transport, or admission rejected a crossing/observation.
#[derive(Debug)]
pub enum RemoteRuntimeError {
    /// The remote harness turn failed (transport / peer error).
    Turn(std::io::Error),
    /// The owner's admission shell rejected a crossing or observation.
    Admit(AdmitError),
}

impl From<AdmitError> for RemoteRuntimeError {
    fn from(e: AdmitError) -> Self {
        Self::Admit(e)
    }
}

/// The payload **handle** an observation crosses the bridge as: the relay routes a
/// reference to the observation, never the observation body (`INV-10`).
fn observation_handle(run_scope: &str, index: usize, obs: &Observation) -> String {
    format!("obs::{run_scope}::{index}::{}", obs.kind)
}

/// Drive one turn on a **remote-placed** runtime and return its observations to the
/// owning run *through federation* (`OBSERVATION-FEDERATION-1`).
///
/// 1. The turn runs on the [`RemoteHarness`] in its own authority and its
///    [`Observation`]s come back over the `PROTO-1` envelope (`REMOTE-RPC-1`).
/// 2. **Each** observation crosses the owner's bridge as a *signed* federated
///    message over the [`relay`](FederationRelay) seam (`RELAY-TRAIT-1`,
///    `INV-21`): a handle, never the body.
/// 3. Only the observations the bridge **admitted** are then admitted by the
///    **owner** into the run lifecycle via `RecordObservation` (`INV-4`).
///
/// Returns the run's admitted-observation count. The run must be `Running` (the
/// admission shell's precondition).
pub fn federate_remote_turn(
    store: &mut Store,
    run_scope: &str,
    harness: &mut dyn RemoteHarness,
    gate: &dyn EgressGate,
    prompt: &str,
) -> Result<u32, RemoteRuntimeError> {
    // 1. Run the turn in the remote authority; the orchestrator's only view of the
    //    remote runtime is the observations that cross back on the envelope.
    let address = harness.address().to_string();
    let outcome = harness
        .run_turn(gate, prompt, &[], &mut |_| {})
        .map_err(RemoteRuntimeError::Turn)?;

    // 2. + 3. Return each observation through the bridge, then owner-admit it.
    let mut count = store.fold::<RunState>(run_scope)?.observations;
    for (i, obs) in outcome.observations.iter().enumerate() {
        let msg = Message {
            correlation: format!("{run_scope}::{i}"),
            source: address.clone(),
            target: run_scope.to_string(),
            payload_handle: observation_handle(run_scope, i, obs),
        };
        count = return_observation(store, run_scope, &msg)?;
    }
    Ok(count)
}

/// A remote-placed runtime returns **one** observation to the owning shell. It
/// first **crosses the federation bridge** — over the [`FederationRelay`] seam,
/// signed and anti-replay-bound (`RELAY-TRAIT-1`/`INV-21`) — into the owner's run
/// scope as evidence, then becomes standing run truth only when the **owner**
/// admits it into the run lifecycle (`INV-4`). Returns the run's admitted-
/// observation count. The run must be `Running` (the admission shell's
/// precondition).
pub fn return_observation(
    store: &mut Store,
    run_scope: &str,
    msg: &Message,
) -> Result<u32, AdmitError> {
    return_observation_via(
        &crate::federation_relay::LoopbackRelay,
        store,
        run_scope,
        msg,
    )
}

/// As [`return_observation`], but over a caller-chosen [`FederationRelay`]. The
/// loopback relay is the in-process special case; a real cross-machine relay
/// attaches behind this same seam with no rearchitecture (ADR 0020). The crossing
/// is signed-and-verified inside the relay; the **owner's** admission alone makes
/// it run truth (`INV-4`).
pub fn return_observation_via<R: FederationRelay + ?Sized>(
    relay: &R,
    store: &mut Store,
    run_scope: &str,
    msg: &Message,
) -> Result<u32, AdmitError> {
    // 1. the observation crosses the bridge into the owner's scope — evidence only.
    //    The relay verifies the source signature before the target admits (INV-21)
    //    and writes nothing into the run scope itself (INV-13/INV-14).
    relay.deliver(store, run_scope, msg)?;
    // 2. the OWNER admits it into the run lifecycle — only now is it run truth.
    Ok(store
        .admit::<RunState>(run_scope, RunCommand::RecordObservation)?
        .observations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation_relay::{self, LoopbackRelay};
    use gaugedesk_core::run::{RunPhase, RunState};
    use gaugedesk_harness::{AllowAllGate, Harness};
    use gaugedesk_pi_bridge::RemoteLoopbackHarness;

    fn running_run(store: &mut Store, scope: &str) {
        store
            .admit::<RunState>(scope, RunCommand::RequestRun)
            .unwrap();
        store
            .admit::<RunState>(scope, RunCommand::AdmitRun)
            .unwrap();
        store
            .admit::<RunState>(scope, RunCommand::StartRun)
            .unwrap();
    }

    #[test]
    fn a_remote_observation_is_run_evidence_only_after_owner_admission() {
        let mut store = Store::open_in_memory().unwrap();
        let run_scope = "run-1";
        running_run(&mut store, run_scope);
        assert_eq!(store.fold::<RunState>(run_scope).unwrap().observations, 0);

        let msg = Message {
            correlation: "obs-1".into(),
            source: "remote-runtime".into(),
            target: "owner".into(),
            payload_handle: "observation-1".into(),
        };
        let count = return_observation(&mut store, run_scope, &msg).unwrap();

        // the observation crossed the bridge into the owner's scope…
        assert_eq!(
            federation_relay::admitted(&store, run_scope).unwrap().len(),
            1
        );
        // …and became standing run evidence only via the owner's admission (INV-4).
        assert_eq!(count, 1);
        assert_eq!(
            store.fold::<RunState>(run_scope).unwrap().phase,
            RunPhase::Running
        );
    }

    #[test]
    fn the_crossing_rides_the_federation_relay_seam() {
        // RELAY-TRAIT-1: the return routes through the `FederationRelay` trait, not
        // the free function — the seam a real cross-machine relay attaches behind.
        let mut store = Store::open_in_memory().unwrap();
        let run_scope = "run-seam";
        running_run(&mut store, run_scope);

        let relay: &dyn FederationRelay = &LoopbackRelay;
        let msg = Message {
            correlation: "seam-1".into(),
            source: "remote".into(),
            target: run_scope.into(),
            payload_handle: "obs::seam".into(),
        };
        let count = return_observation_via(relay, &mut store, run_scope, &msg).unwrap();
        assert_eq!(
            count, 1,
            "owner-admitted exactly the one crossed observation"
        );
        assert_eq!(
            federation_relay::admitted(&store, run_scope).unwrap().len(),
            1
        );
    }

    #[test]
    fn a_remote_turns_observations_federate_into_the_owners_run() {
        // OBSERVATION-FEDERATION-1 end to end: a turn on a *remote* harness
        // (REMOTE-RPC-1) returns its observations through the relay (RELAY-TRAIT-1,
        // signed crossing) and they become run truth only by the owner's admission
        // (INV-4). The remote agent streams two text tokens, so two observations
        // cross back and two are admitted.
        let mut store = Store::open_in_memory().unwrap();
        let run_scope = "run-remote";
        running_run(&mut store, run_scope);

        let mut harness = RemoteLoopbackHarness::new(
            "127.0.0.1:7777",
            [
                r#"{"type":"agent_start"}"#,
                r#"{"type":"text_delta","delta":"remote "}"#,
                r#"{"type":"text_delta","delta":"reply"}"#,
                r#"{"type":"agent_end","messages":[]}"#,
                r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":"remote reply"}}"#,
            ],
        );

        // The remote turn streams at least its two text tokens as observations;
        // record how many crossed so the assertions track the harness exactly.
        let expected = {
            let mut h = RemoteLoopbackHarness::new(
                "127.0.0.1:7777",
                [
                    r#"{"type":"agent_start"}"#,
                    r#"{"type":"text_delta","delta":"remote "}"#,
                    r#"{"type":"text_delta","delta":"reply"}"#,
                    r#"{"type":"agent_end","messages":[]}"#,
                    r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":"remote reply"}}"#,
                ],
            );
            h.run_turn(&AllowAllGate, "go", &[], &mut |_| {})
                .unwrap()
                .observations
                .len()
        };
        assert!(
            expected >= 2,
            "the remote turn produces the two text observations (and possibly more)"
        );

        let count =
            federate_remote_turn(&mut store, run_scope, &mut harness, &AllowAllGate, "go").unwrap();

        // Every remote observation crossed the bridge into the owner's scope (handles
        // only, never the body — INV-10) and was admitted by the owner (INV-4).
        let crossed = federation_relay::admitted(&store, run_scope).unwrap();
        assert_eq!(
            crossed.len(),
            expected,
            "every remote observation federated across the bridge"
        );
        assert_eq!(
            count as usize, expected,
            "the owner admitted each into run truth"
        );
        for fact in &crossed {
            let handle = fact["payload_handle"].as_str().unwrap();
            assert!(
                handle.starts_with("obs::run-remote::"),
                "a handle crossed, not the payload body"
            );
        }
        // The run is still running; federation neither completes nor fails it.
        assert_eq!(
            store.fold::<RunState>(run_scope).unwrap().phase,
            RunPhase::Running
        );
        assert_eq!(
            store.fold::<RunState>(run_scope).unwrap().observations as usize,
            expected
        );
    }

    #[test]
    fn the_relay_never_writes_the_run_fact_itself() {
        // INV-13/INV-14: the relay is transport only. With no owner admission the
        // run holds no observation, even though the bridge carried the message.
        let mut store = Store::open_in_memory().unwrap();
        let run_scope = "run-no-admit";
        running_run(&mut store, run_scope);

        let msg = Message {
            correlation: "x-1".into(),
            source: "remote".into(),
            target: run_scope.into(),
            payload_handle: "obs::x".into(),
        };
        // Cross the bridge *without* the owner's run-admission step.
        assert!(federation_relay::deliver(&mut store, run_scope, &msg).unwrap());
        // The run fact is still zero — only the owner's admission creates it.
        assert_eq!(store.fold::<RunState>(run_scope).unwrap().observations, 0);
    }
}
