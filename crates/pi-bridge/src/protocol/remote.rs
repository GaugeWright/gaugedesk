//! The remote-harness RPC envelope (`PROTO-1`).
//!
//! This is **not** the Pi wire protocol (its parent [`super`]) — that is the
//! local subprocess's stdio. This is the framing for the *engine ↔ remote
//! harness* boundary: the local orchestrator hands a turn to a [`RemoteHarness`]
//! living in a different trust authority, reached over the federation relay
//! ([`crate::RemoteHarness`], ADR 0020/0031). The turn's inputs and outputs must
//! cross that boundary as bytes, so a single turn is one
//! [`RpcRequest::RunTurn`] line out and one [`RpcResponse::TurnComplete`] line
//! back.
//!
//! Loopback-first (ADR 0020): the envelope is line-delimited JSON, exercised
//! end-to-end in one process by [`loopback_roundtrip`]. `REMOTE-RPC-1` attaches
//! the real `RemoteLoopbackHarness` transport behind the same envelope; the
//! cross-NAT relay (`RENDEZVOUS-STUB-1`) attaches later with no rearchitecture —
//! the bytes on the wire never change.
//!
//! The in-memory [`Observation`]/[`TurnOutcome`] carry a `&'static str` `kind`
//! and so are not directly `Deserialize`; the wire mirrors ([`WireObservation`])
//! own a `String` and convert at the boundary via [`intern_kind`], which maps a
//! received kind back to its `'static` interned form (unknown kinds become
//! `"other"` rather than leaking memory).

use serde::{Deserialize, Serialize};

use crate::{ModelUsage, Observation, ToolInfo, TurnOutcome};

/// One turn handed to a remote harness — the request line the orchestrator sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RpcRequest {
    /// Run one turn with `prompt`; the egress gate stays the *remote* peer's
    /// concern (it mediates its own effects), so it is not carried here.
    #[serde(rename = "run_turn")]
    RunTurn { prompt: String },
}

/// The result a remote harness returns — the response line for one [`RpcRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RpcResponse {
    /// The neutral [`TurnOutcome`], serialized field-for-field.
    #[serde(rename = "turn_complete")]
    TurnComplete(WireTurnOutcome),
}

/// Wire mirror of [`TurnOutcome`]: identical fields, all owned/`Deserialize`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireTurnOutcome {
    #[serde(default)]
    pub assistant_text: String,
    #[serde(default)]
    pub observations: Vec<WireObservation>,
    #[serde(default)]
    pub mediated_tool_calls: Vec<String>,
    #[serde(default)]
    pub pending_approvals: Vec<String>,
    #[serde(default)]
    pub runtime_evidence_pointers: Vec<String>,
    #[serde(default)]
    pub managed_usage: Option<ModelUsage>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Wire mirror of [`Observation`]: a `String` `kind` (the in-memory one is
/// `&'static str`), re-interned on the way back in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireObservation {
    pub kind: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub tool: Option<ToolInfo>,
}

impl From<&Observation> for WireObservation {
    fn from(o: &Observation) -> Self {
        Self {
            kind: o.kind.to_string(),
            detail: o.detail.clone(),
            tool: o.tool.clone(),
        }
    }
}

impl From<&WireObservation> for Observation {
    fn from(w: &WireObservation) -> Self {
        Observation {
            kind: intern_kind(&w.kind),
            detail: w.detail.clone(),
            tool: w.tool.clone(),
        }
    }
}

impl From<&TurnOutcome> for WireTurnOutcome {
    fn from(o: &TurnOutcome) -> Self {
        Self {
            assistant_text: o.assistant_text.clone(),
            observations: o.observations.iter().map(WireObservation::from).collect(),
            mediated_tool_calls: o.mediated_tool_calls.clone(),
            pending_approvals: o.pending_approvals.clone(),
            runtime_evidence_pointers: o.runtime_evidence_pointers.clone(),
            managed_usage: o.managed_usage.clone(),
            error: o.error.clone(),
        }
    }
}

impl From<&WireTurnOutcome> for TurnOutcome {
    fn from(w: &WireTurnOutcome) -> Self {
        TurnOutcome {
            assistant_text: w.assistant_text.clone(),
            observations: w.observations.iter().map(Observation::from).collect(),
            mediated_tool_calls: w.mediated_tool_calls.clone(),
            pending_approvals: w.pending_approvals.clone(),
            // The wire protocol carries no questions: a remote peer asks its own
            // people, not ours (ADR 0113).
            asked_questions: Vec::new(),
            runtime_evidence_pointers: w.runtime_evidence_pointers.clone(),
            output_flow_signature: Vec::new(),
            // The wire protocol predates DR-0036; a remote peer certifies no
            // guarantees here — consumers fall back to local truth.
            guarantee_outcomes: Vec::new(),
            runtime_start_position: None,
            runtime_terminal_position: None,
            managed_usage: w.managed_usage.clone(),
            error: w.error.clone(),
        }
    }
}

/// Map a received observation `kind` back to its `'static` interned form. The
/// kinds the turn loop emits are a closed set (`crate` `run_turn_streaming`);
/// anything else is `"other"` so a malformed/extended peer can't widen our
/// `&'static str` lifetimes nor leak by `Box::leak`.
pub fn intern_kind(kind: &str) -> &'static str {
    match kind {
        "text" => "text",
        "progress" => "progress",
        "approval" => "approval",
        "go" => "go",
        "egress" => "egress",
        "egress_blocked" => "egress_blocked",
        "egress_staged" => "egress_staged",
        "tool_result" => "tool_result",
        _ => "other",
    }
}

impl RpcRequest {
    /// Serialize to one JSON line (no trailing newline; the transport adds it).
    pub fn to_line(&self) -> String {
        // Owned, finite values — serde_json never fails here.
        serde_json::to_string(self).expect("serialize remote RPC request")
    }
    pub fn parse(s: &str) -> Result<RpcRequest, serde_json::Error> {
        serde_json::from_str(s)
    }
}

impl RpcResponse {
    /// Build the response for a finished turn.
    pub fn turn_complete(outcome: &TurnOutcome) -> Self {
        RpcResponse::TurnComplete(WireTurnOutcome::from(outcome))
    }
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).expect("serialize remote RPC response")
    }
    pub fn parse(s: &str) -> Result<RpcResponse, serde_json::Error> {
        serde_json::from_str(s)
    }
    /// Recover the neutral [`TurnOutcome`] from a response.
    pub fn into_outcome(self) -> TurnOutcome {
        let RpcResponse::TurnComplete(w) = self;
        TurnOutcome::from(&w)
    }
}

/// Drive one turn across the envelope in-process: serialize `outcome` as the
/// peer would, ship it over the (loopback) wire, and recover it on the other
/// side. The single-process proof that the framing round-trips before any real
/// transport (`REMOTE-RPC-1`) or network (`RENDEZVOUS-STUB-1`) is introduced.
pub fn loopback_roundtrip(prompt: &str, outcome: &TurnOutcome) -> (RpcRequest, TurnOutcome) {
    let req_line = RpcRequest::RunTurn {
        prompt: prompt.to_string(),
    }
    .to_line();
    let req = RpcRequest::parse(&req_line).expect("request round-trips");

    let resp_line = RpcResponse::turn_complete(outcome).to_line();
    let resp = RpcResponse::parse(&resp_line).expect("response round-trips");

    (req, resp.into_outcome())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_outcome() -> TurnOutcome {
        TurnOutcome {
            assistant_text: "done".into(),
            observations: vec![
                Observation {
                    kind: "text",
                    detail: "hi".into(),
                    tool: None,
                },
                Observation {
                    kind: "egress",
                    detail: "tool bash mediated by boundary".into(),
                    tool: Some(ToolInfo {
                        name: "bash".into(),
                        call_id: "call_1".into(),
                        target: Some("echo hi".into()),
                        args: r#"{"command":"echo hi"}"#.into(),
                        ok: None,
                        result: None,
                    }),
                },
            ],
            mediated_tool_calls: vec!["bash".into()],
            pending_approvals: vec!["fs:read (id-7)".into()],
            asked_questions: Vec::new(),
            runtime_evidence_pointers: vec!["{\"pointer_kind\":\"event\"}".into()],
            output_flow_signature: Vec::new(),
            guarantee_outcomes: Vec::new(),
            runtime_start_position: None,
            runtime_terminal_position: None,
            managed_usage: None,
            error: None,
        }
    }

    #[test]
    fn request_is_one_tagged_json_line() {
        let line = RpcRequest::RunTurn {
            prompt: "go".into(),
        }
        .to_line();
        assert_eq!(line, r#"{"type":"run_turn","prompt":"go"}"#);
        assert!(!line.contains('\n'));
        assert_eq!(
            RpcRequest::parse(&line).unwrap(),
            RpcRequest::RunTurn {
                prompt: "go".into()
            }
        );
    }

    #[test]
    fn turn_outcome_round_trips_through_the_envelope() {
        let original = sample_outcome();
        let (req, recovered) = loopback_roundtrip("prompt-text", &original);

        assert_eq!(
            req,
            RpcRequest::RunTurn {
                prompt: "prompt-text".into()
            }
        );
        // every field crosses the wire and comes back identical (kind re-interned)
        assert_eq!(recovered.assistant_text, original.assistant_text);
        assert_eq!(recovered.observations, original.observations);
        assert_eq!(recovered.mediated_tool_calls, original.mediated_tool_calls);
        assert_eq!(recovered.pending_approvals, original.pending_approvals);
        assert_eq!(recovered.error, original.error);
    }

    #[test]
    fn every_emitted_kind_re_interns_to_itself() {
        // The closed set the turn loop emits must survive the String→&'static
        // round-trip unchanged, or a remote observation would be mislabeled.
        for kind in [
            "text",
            "progress",
            "approval",
            "go",
            "egress",
            "egress_blocked",
            "egress_staged",
            "tool_result",
        ] {
            assert_eq!(intern_kind(kind), kind);
        }
        // an unknown/extended kind degrades to "other", never leaks or panics
        assert_eq!(intern_kind("something_new"), "other");
    }

    #[test]
    fn response_carries_an_error_outcome() {
        let outcome = TurnOutcome {
            error: Some("peer stream ended".into()),
            ..Default::default()
        };
        let line = RpcResponse::turn_complete(&outcome).to_line();
        let recovered = RpcResponse::parse(&line).unwrap().into_outcome();
        assert_eq!(recovered.error.as_deref(), Some("peer stream ended"));
        assert!(recovered.observations.is_empty());
    }
}
