//! Neutral test doubles for the harness seam.
//!
//! Nothing here is adapter-shaped: the doubles fabricate the seam's own types
//! directly, proving the [`Harness`] contract needs no runtime wire behind it.
//! GaugeDesk's `GAUGEDESK_FAKE_AGENT` path uses this double directly, so its
//! deterministic acceptance suite does not depend on Pi's wire protocol.

use std::collections::VecDeque;
use std::io;

use crate::{
    EgressGate, GateDecision, Harness, ImageContent, Observation, RuntimePosition, ToolInfo,
    TurnOutcome,
};

/// One neutral scripted tool call. The double asks the supplied [`EgressGate`]
/// for the decision at turn time, just like a real adapter, then projects the
/// decision and result onto the harness seam's own observation types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptedToolCall {
    pub name: String,
    pub call_id: String,
    pub target: Option<String>,
    pub args: String,
    pub result: Option<String>,
    pub ok: bool,
}

/// A deterministic turn expressed only in harness-neutral types.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScriptedTurn {
    pub assistant_text: String,
    pub observations: Vec<Observation>,
    pub tool_calls: Vec<ScriptedToolCall>,
    pub runtime_start_position: Option<RuntimePosition>,
    pub runtime_terminal_position: Option<RuntimePosition>,
    /// Scripted context-window reading, so fixture environments exercise the
    /// composer's meter the way a reporting runtime would.
    pub context_reading: Option<crate::ContextWindowReading>,
}

enum TurnScript {
    Outcome(Box<TurnOutcome>),
    Neutral(ScriptedTurn),
}

/// A scripted [`Harness`] that fabricates its turn evidence directly: each
/// queued [`TurnOutcome`] serves exactly one turn, its `observations` streamed
/// to the sink before the outcome is returned (the order every real adapter
/// honors). No Pi wire, no subprocess, no runtime — the template for a future
/// adapter conformance run (SUB-1).
///
/// Running past the script is an error, matching a one-shot transport; a
/// factory over this double should report `reuse_across_turns() == false`.
pub struct ScriptedHarness {
    turns: VecDeque<TurnScript>,
}

impl ScriptedHarness {
    pub fn new(turns: Vec<TurnOutcome>) -> Self {
        Self {
            turns: turns
                .into_iter()
                .map(Box::new)
                .map(TurnScript::Outcome)
                .collect(),
        }
    }

    /// Build a script whose tool calls are classified by the turn's real gate.
    pub fn from_neutral_turns(turns: Vec<ScriptedTurn>) -> Self {
        Self {
            turns: turns.into_iter().map(TurnScript::Neutral).collect(),
        }
    }
}

impl Harness for ScriptedHarness {
    fn run_turn(
        &mut self,
        gate: &dyn EgressGate,
        _prompt: &str,
        _images: &[ImageContent],
        sink: &mut dyn FnMut(&Observation),
    ) -> io::Result<TurnOutcome> {
        let script = self
            .turns
            .pop_front()
            .ok_or_else(|| io::Error::other("scripted harness: no turn scripted"))?;
        let outcome = match script {
            TurnScript::Outcome(outcome) => *outcome,
            TurnScript::Neutral(turn) => project_neutral_turn(turn, gate),
        };
        for obs in &outcome.observations {
            sink(obs);
        }
        Ok(outcome)
    }
}

fn project_neutral_turn(turn: ScriptedTurn, gate: &dyn EgressGate) -> TurnOutcome {
    let mut outcome = TurnOutcome {
        assistant_text: turn.assistant_text,
        observations: turn.observations,
        runtime_start_position: turn.runtime_start_position,
        runtime_terminal_position: turn.runtime_terminal_position,
        context_reading: turn.context_reading,
        ..TurnOutcome::default()
    };
    for call in turn.tool_calls {
        let info = |ok, result| ToolInfo {
            name: call.name.clone(),
            call_id: call.call_id.clone(),
            target: call.target.clone(),
            args: call.args.clone(),
            ok,
            result,
        };
        let decision = match gate.classify_tool(&call.name, call.target.as_deref()) {
            GateDecision::Allow => {
                outcome.mediated_tool_calls.push(call.name.clone());
                Observation {
                    kind: "egress",
                    detail: format!("tool {} mediated by boundary", call.name),
                    tool: Some(info(None, None)),
                }
            }
            GateDecision::Block(reason) => Observation {
                kind: "egress_blocked",
                detail: format!("tool {} blocked by membrane: {reason}", call.name),
                tool: Some(info(Some(false), None)),
            },
            GateDecision::Stage(reason) => {
                outcome
                    .pending_approvals
                    .push(format!("tool {}: {reason}", call.name));
                Observation {
                    kind: "egress_staged",
                    detail: format!("tool {} staged: {reason}", call.name),
                    tool: Some(info(None, None)),
                }
            }
        };
        outcome.observations.push(decision);

        let result = Observation {
            kind: "tool_result",
            detail: if call.ok {
                "tool ok".into()
            } else {
                "tool errored".into()
            },
            tool: Some(info(Some(call.ok), call.result.clone())),
        };
        outcome.observations.push(result);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AllowAllGate;

    /// The double streams a turn's observations before returning its outcome,
    /// serves one outcome per turn, and fails cleanly past the script.
    #[test]
    fn scripted_harness_streams_then_returns_each_scripted_turn() {
        let mut harness = ScriptedHarness::new(vec![TurnOutcome {
            assistant_text: "done".into(),
            observations: vec![Observation {
                kind: "text",
                detail: "working".into(),
                tool: None,
            }],
            ..TurnOutcome::default()
        }]);

        let mut streamed = Vec::new();
        let outcome = harness
            .run_turn(&AllowAllGate, "go", &[], &mut |o| {
                streamed.push(o.detail.clone())
            })
            .unwrap();
        assert_eq!(streamed, vec!["working".to_string()]);
        assert_eq!(outcome.assistant_text, "done");

        let past_script = harness.run_turn(&AllowAllGate, "again", &[], &mut |_| {});
        assert!(past_script.is_err(), "running past the script is an error");
    }

    struct BlockBash;
    impl EgressGate for BlockBash {
        fn classify_tool(&self, tool: &str, _target: Option<&str>) -> GateDecision {
            if tool == "bash" {
                GateDecision::Block("scripts disabled".into())
            } else {
                GateDecision::Allow
            }
        }
    }

    /// Neutral scripts still cross the real gate: allowed calls are mediated and
    /// blocked calls surface as blocked observations without any Pi event parser.
    #[test]
    fn neutral_script_classifies_each_tool_through_the_gate() {
        let tool = |name: &str| ScriptedToolCall {
            name: name.into(),
            call_id: format!("{name}-1"),
            target: Some("target".into()),
            args: "{}".into(),
            result: Some("done".into()),
            ok: true,
        };
        let mut harness = ScriptedHarness::from_neutral_turns(vec![ScriptedTurn {
            assistant_text: "done".into(),
            tool_calls: vec![tool("write"), tool("bash")],
            ..ScriptedTurn::default()
        }]);

        let mut streamed = Vec::new();
        let outcome = harness
            .run_turn(&BlockBash, "go", &[], &mut |obs| streamed.push(obs.kind))
            .unwrap();

        assert_eq!(outcome.mediated_tool_calls, vec!["write".to_string()]);
        assert!(outcome.observations.iter().any(|obs| {
            obs.kind == "egress_blocked" && obs.detail.contains("bash blocked by membrane")
        }));
        assert_eq!(
            streamed,
            vec!["egress", "tool_result", "egress_blocked", "tool_result"]
        );
    }
}
