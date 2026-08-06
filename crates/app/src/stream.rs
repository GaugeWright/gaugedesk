//! The live event stream: operational + admitted events pushed to the
//! workbench as they happen, so the client transcript is a true *reduction of
//! the server stream* (`app-stack.md`) rather than client-invented truth.
//!
//! Wire shape matches `web/src/state/transcript.ts`'s `StreamEvent` union so the
//! client reducer consumes it directly. Transport is SSE over the same loopback
//! control plane; a `tokio::broadcast` per engagement fans events to subscribers
//! (and drops silently when no one listens — events are also durable in the log).

use gaugedesk_harness::Observation;
use serde::Serialize;
use tokio::sync::broadcast;

use crate::library;
use crate::workbench_state::Workbench;

/// One event on an engagement's live stream. `#[serde(tag = "type")]` so it
/// deserializes into the client's discriminated union unchanged.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerEvent {
    /// A durable user message (the task prompt) — admitted run evidence.
    User { text: String },
    /// A durable assistant message (the turn's final text) — admitted run evidence.
    Assistant { text: String },
    /// A streamed operational text delta.
    Text { delta: String },
    /// A tool effect that passed the membrane (boundary-mediated). The structured
    /// fields drive the B4 tool line (`▸ {tool} {target}`, expand, click-to-open).
    Tool {
        tool: String,
        mediated: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        call_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        target: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        args: Option<String>,
    },
    /// A tool's ✓/✗ and output, correlated to its [`Tool`] line by `call_id`.
    ToolResult {
        call_id: String,
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<String>,
    },
    /// A tool effect the membrane blocked.
    Blocked { tool: String, reason: String },
    /// A turn that failed: the runtime/model error text, surfaced to the user as a
    /// durable transcript line so a failed turn shows *why* (not just "didn't
    /// finish"). The reason is operational diagnostic text, not protected content.
    /// An optional machine-readable `code` (e.g. `"no_credential"`) lets the client
    /// render an actionable affordance — a link into settings — rather than plain text.
    Error {
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    },
    /// Run truth the lifecycle admitted (durable; shown as admitted tier).
    Admitted { kind: String, text: String },
    /// A **library/workspace change** on the workspace event stream — a *reference*
    /// to what changed (the record kind
    /// `archetype|project|placement|chat|workstream`, its id, and the op
    /// `upsert|tombstone`), never protected content (`INV-10`). Per the ADR 0037
    /// push model the client resolves the affected workspace **delta projection**
    /// (through the freshness carriage) on receipt; the event carries only the pointer.
    WorkspaceChanged {
        record: String,
        id: String,
        op: String,
    },
}

impl ServerEvent {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("serialize ServerEvent")
    }

    /// Map a bridge [`Observation`] onto the wire stream. Operational text and
    /// progress collapse to `Text`; egress decisions become `Tool`/`Blocked`.
    pub fn from_observation(obs: &Observation) -> ServerEvent {
        match obs.kind {
            "egress" | "egress_staged" => {
                let t = obs.tool.as_ref();
                ServerEvent::Tool {
                    tool: t
                        .map(|i| i.name.clone())
                        .unwrap_or_else(|| obs.detail.clone()),
                    mediated: obs.kind == "egress",
                    call_id: t.map(|i| i.call_id.clone()).filter(|s| !s.is_empty()),
                    target: t.and_then(|i| i.target.clone()),
                    args: t
                        .map(|i| i.args.clone())
                        .filter(|s| !s.is_empty() && s != "null"),
                }
            }
            "tool_result" => {
                let t = obs.tool.as_ref();
                ServerEvent::ToolResult {
                    call_id: t.map(|i| i.call_id.clone()).unwrap_or_default(),
                    ok: t.and_then(|i| i.ok).unwrap_or(true),
                    result: t.and_then(|i| i.result.clone()),
                }
            }
            // `detail` already reads "tool X blocked by membrane: …"; pass it through.
            "egress_blocked" => ServerEvent::Blocked {
                tool: obs.detail.clone(),
                reason: String::new(),
            },
            _ => ServerEvent::Text {
                delta: obs.detail.clone(),
            },
        }
    }
}

impl Workbench {
    /// The broadcast sender for a private engagement's live stream, created on
    /// demand.
    pub fn sender(&mut self, id: &str) -> broadcast::Sender<ServerEvent> {
        self.streams
            .entry(id.to_string())
            .or_insert_with(|| broadcast::channel(256).0)
            .clone()
    }

    /// Publish an event to an engagement's stream. A send with no subscribers is
    /// a no-op — the durable truth is the event log, not the stream.
    pub fn publish(&mut self, id: &str, event: ServerEvent) {
        let _ = self.sender(id).send(event);
    }

    /// Push a **library change reference** on the workspace event stream (the
    /// sibling of the per-chat SSE) so every connected client resolves the affected
    /// workspace delta projection through the freshness carriage live (ADR 0037's
    /// push-a-reference model). `record` is the changed kind
    /// (`archetype|project|placement|chat|workstream`), `id` its id, `op`
    /// `upsert|tombstone`;
    /// no protected content crosses (`INV-10`). Called from every library mutation;
    /// the library scope is the reserved stream key (chat ids are `chat-...`, never
    /// `library`). A send with no subscribers is a no-op (safe during seeding).
    pub fn notify_library_changed(&mut self, record: &str, id: &str, op: &str) {
        let _ = self
            .sender(library::LIBRARY_SCOPE)
            .send(ServerEvent::WorkspaceChanged {
                record: record.to_string(),
                id: id.to_string(),
                op: op.to_string(),
            });
    }
}
