//! Neutral loopback remote peer for federation tests.

use std::collections::VecDeque;
use std::io;

use gaugedesk_core::remote_session::{decide, evolve, RemoteCommand, RemotePhase, RemoteState};
use gaugedesk_harness::{
    EgressGate, Harness, ImageContent, Observation, RemoteHarness, TurnOutcome,
};

use super::remote_wire::{RpcRequest, RpcResponse};

pub(crate) struct RemoteLoopbackHarness {
    address: String,
    turns: VecDeque<TurnOutcome>,
}

impl RemoteLoopbackHarness {
    pub(crate) fn new(address: impl Into<String>, turns: Vec<TurnOutcome>) -> Self {
        Self {
            address: address.into(),
            turns: turns.into(),
        }
    }

    pub(crate) fn text(address: impl Into<String>, tokens: &[&str]) -> Self {
        Self::new(
            address,
            vec![TurnOutcome {
                assistant_text: tokens.concat(),
                observations: tokens
                    .iter()
                    .map(|token| Observation {
                        kind: "text",
                        detail: (*token).to_owned(),
                        tool: None,
                    })
                    .collect(),
                ..TurnOutcome::default()
            }],
        )
    }
}

fn step(state: &mut RemoteState, command: RemoteCommand) -> io::Result<()> {
    let events = decide(state, command)
        .map_err(|rejection| io::Error::new(io::ErrorKind::InvalidData, rejection.reason))?;
    for event in events {
        *state = evolve(state, event);
    }
    Ok(())
}

impl Harness for RemoteLoopbackHarness {
    fn run_turn(
        &mut self,
        _gate: &dyn EgressGate,
        prompt: &str,
        _images: &[ImageContent],
        sink: &mut dyn FnMut(&Observation),
    ) -> io::Result<TurnOutcome> {
        let mut state = RemoteState::default();
        step(&mut state, RemoteCommand::DialPeer)?;
        let request = RpcRequest::RunTurn {
            prompt: prompt.to_owned(),
        }
        .to_line();
        step(&mut state, RemoteCommand::SendTurnRequest)?;

        let RpcRequest::RunTurn { .. } = RpcRequest::parse(&request)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let peer_outcome = self
            .turns
            .pop_front()
            .ok_or_else(|| io::Error::other("remote peer has no scripted turn"))?;
        let response = RpcResponse::turn_complete(&peer_outcome).to_line();
        step(&mut state, RemoteCommand::ReceiveTurnResponse)?;

        let outcome = RpcResponse::parse(&response)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .into_outcome();
        for observation in &outcome.observations {
            sink(observation);
        }
        step(&mut state, RemoteCommand::SourceAdmitOutcome)?;
        step(&mut state, RemoteCommand::CompleteSession)?;
        debug_assert_eq!(state.phase, RemotePhase::Completed);
        Ok(outcome)
    }
}

impl RemoteHarness for RemoteLoopbackHarness {
    fn address(&self) -> &str {
        &self.address
    }
}
