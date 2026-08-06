//! The one harness decision point (SUB-0, ADR 0071 §3): which
//! [`HarnessFactory`] drives a turn. Everything else in the engine is
//! adapter-blind — it resolves the turn's *policy* into a
//! [`HarnessSpec`](gaugedesk_harness::HarnessSpec) and lets the selected
//! factory construct the runtime.

use std::io;
use std::path::Path;
use std::sync::Arc;

use gaugedesk_harness::testing::{ScriptedHarness, ScriptedToolCall, ScriptedTurn};
use gaugedesk_harness::{CredentialProbe, Harness, HarnessFactory, HarnessSpec, Observation};
use gaugedesk_whip_runtime::WhipHarnessFactory;

/// Select the factory for ONE turn. Consulted per turn, never cached at
/// startup: tests flip `GAUGEDESK_FAKE_AGENT` against a live workbench. The
/// fake stays deterministic; every real local turn targets WhippleScript.
pub fn factory_for_turn(whip: WhipHarnessFactory) -> Arc<dyn HarnessFactory> {
    if gaugedesk_env::var("FAKE_AGENT").is_some() {
        Arc::new(ScriptedFakeFactory)
    } else {
        Arc::new(whip)
    }
}

/// The mock-LLM adapter (`GAUGEDESK_FAKE_AGENT`): no runtime, no model call.
/// A fresh neutral [`ScriptedHarness`] projects deterministic observations and
/// tool calls through the real membrane every turn. No WhippleScript runtime or
/// provider credential participates in the fake path (SUB-1).
pub struct ScriptedFakeFactory;

impl ScriptedFakeFactory {
    /// The stable adapter id the engine branches on for the fake's shell-side
    /// differences: skip provider resolution and the fail-closed credential
    /// precheck, and run [`Self::pre_turn`] first.
    pub const KIND: &'static str = "scripted-fake";

    /// The fake's pre-turn side effects, verbatim from the pre-seam engine: a
    /// `[slow]` task holds the turn open (so the client's busy state — and the
    /// send queue stacked on top of the composer — is observable to the e2e
    /// driver), and the agent appends a line to a note file so the diff/keep
    /// flow — and multi-turn accumulation — is real and deterministic.
    ///
    /// MUST run before the workbench lock is taken (the engine calls it from
    /// the blocking pool, pre-lock): the e2e suite opens chats and queues
    /// messages DURING the `[slow]` window, so holding the workbench mutex
    /// through the sleep would serialize what the tests observe as concurrent.
    pub fn pre_turn(worktree: &Path, task: &str) -> Result<(), String> {
        use std::io::Write;
        if task.contains("[slow]") {
            std::thread::sleep(std::time::Duration::from_millis(3500));
        }
        // A `[no-write]` task skips the note append — the deterministic **no-op
        // turn** (a settled turn with an empty diff), so tests can drive the
        // ATTN-1 auto-advance rule the same way `[slow]` drives the busy state.
        if task.contains("[no-write]") {
            return Ok(());
        }
        let note = worktree.join("agent-note.txt");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&note)
            .map_err(|e| format!("fake agent open: {e}"))?;
        writeln!(f, "agent-note for task: {task}").map_err(|e| format!("fake agent write: {e}"))?;
        Ok(())
    }
}

impl HarnessFactory for ScriptedFakeFactory {
    fn kind(&self) -> &'static str {
        Self::KIND
    }

    /// A fresh neutral script; the spec is ignored (the fake needs no runtime
    /// config — its worktree side effects run in
    /// [`Self::pre_turn`], outside the workbench lock).
    fn create(&self, _spec: &HarnessSpec) -> io::Result<Box<dyn Harness>> {
        Ok(Box::new(ScriptedHarness::from_neutral_turns(vec![
            fake_turn(),
        ])))
    }

    /// Never cached: a scripted transport is one-shot, so caching it across
    /// turns would fail turn 2 with "stream ended". This preserves the
    /// fresh-transport-per-turn behavior exactly.
    fn reuse_across_turns(&self) -> bool {
        false
    }

    /// The fake needs no credentials. (The engine's fail-closed precheck skips
    /// the fake branch anyway — shell policy, unchanged from the pre-seam
    /// engine.)
    fn credential_status(
        &self,
        _provider: &str,
        _capability: Option<&dyn gaugedesk_harness::CredentialCapability>,
    ) -> CredentialProbe {
        CredentialProbe::Ready
    }
}

/// The neutral mock-LLM turn: one text observation, an in-workspace `write`,
/// and a `bash` request for the membrane to allow/block/stage from real policy.
fn fake_turn() -> ScriptedTurn {
    ScriptedTurn {
        assistant_text: "Wrote agent-note.txt.".into(),
        observations: vec![Observation {
            kind: "text",
            detail: "Wrote agent-note.txt.".into(),
            tool: None,
        }],
        tool_calls: vec![
            ScriptedToolCall {
                name: "write".into(),
                call_id: "t1".into(),
                target: Some("agent-note.txt".into()),
                args: r#"{"path":"agent-note.txt"}"#.into(),
                result: Some("wrote 1 file".into()),
                ok: true,
            },
            ScriptedToolCall {
                name: "bash".into(),
                call_id: "t2".into(),
                target: Some("echo hi".into()),
                args: r#"{"command":"echo hi"}"#.into(),
                result: None,
                ok: true,
            },
        ],
        runtime_start_position: Some(gaugedesk_harness::RuntimePosition {
            instance_ref: "scripted-fake".into(),
            sequence: 0,
        }),
        runtime_terminal_position: Some(gaugedesk_harness::RuntimePosition {
            instance_ref: "scripted-fake".into(),
            sequence: 1,
        }),
    }
}
