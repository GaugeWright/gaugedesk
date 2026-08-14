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

/// The interruptible half of the fake's `[slow]` hold.
///
/// The hold is the only thing the scripted fake does that takes any time, and it
/// runs *before* a harness exists — so there was nothing for Stop to reach, and
/// `POST /stop` answered "nothing running" while a turn was plainly running.
/// Every e2e scenario that appeared to cover Stop was really watching the sleep
/// expire. Now the engine binds one of these as the turn's interrupt handle for
/// the duration of the hold, so Stop lands in the fake path exactly as it does
/// against a real runtime, and a test can tell the difference.
#[derive(Default)]
pub struct SlowHold {
    stopped: std::sync::Mutex<bool>,
    woken: std::sync::Condvar,
}

impl SlowHold {
    /// Wait out `hold`, or return early the moment [`Self::stop`] is called.
    /// `true` means it was stopped rather than served.
    pub fn wait(&self, hold: std::time::Duration) -> bool {
        let stopped = self
            .stopped
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (stopped, _) = self
            .woken
            .wait_timeout_while(stopped, hold, |stopped| !*stopped)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *stopped
    }

    /// Whether the hold was released by a Stop rather than served in full.
    pub fn was_stopped(&self) -> bool {
        *self
            .stopped
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Release the hold. Safe to call when nothing is waiting.
    pub fn stop(&self) {
        *self
            .stopped
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        self.woken.notify_all();
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

    /// How long a `[startup]` task spends between its claim and its interrupt
    /// handle. Comfortably wider than a driver's Enter-then-Stop, and wider
    /// than the 124-222ms a real turn measured, so the window is pressed rather
    /// than raced.
    const STARTUP_WINDOW: std::time::Duration = std::time::Duration::from_millis(1500);

    /// Reproduce a real turn's uninterruptible startup, for a `[startup]` task.
    ///
    /// A real turn resolves a provider, prechecks a credential over the network
    /// twice, takes the workbench lock and builds a harness before it has
    /// anything Stop can fire. The fake does none of that, so the gap a person
    /// actually presses Stop in did not exist in the lane that gates every
    /// merge — the defect it hid was reachable only by the opt-in live lane,
    /// which costs tokens and is not run on a pull request.
    ///
    /// Called BEFORE the hold is bound as the interrupt handle, because that is
    /// the whole point: a Stop landing in here has nothing to fire and must be
    /// honoured by the claim's own checkpoint.
    pub fn startup_window(task: &str) {
        if task.contains("[startup]") {
            std::thread::sleep(Self::STARTUP_WINDOW);
        }
    }

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
    pub fn pre_turn(worktree: &Path, task: &str, hold: &SlowHold) -> Result<(), String> {
        use std::io::Write;
        // `[slow]` opens a window wide enough to observe a busy composer and
        // queue behind it. `[hold]` opens one nothing outlasts, so a test of
        // *Stop* cannot pass by waiting: the turn ends when it is interrupted or
        // the scenario fails. The distinction matters — while the hold was not
        // interruptible at all, the one scenario covering Stop passed by
        // watching `[slow]` expire on its own.
        let holds_for = if task.contains("[hold]") {
            Some(std::time::Duration::from_secs(30))
        } else if task.contains("[slow]") {
            Some(std::time::Duration::from_millis(3500))
        } else {
            None
        };
        if holds_for.is_some_and(|window| hold.wait(window)) {
            // Stopped mid-hold. Return without the note append and let the caller
            // read the hold: an interrupted turn is not a failed one, and only
            // the caller can say so in the turn's own vocabulary.
            return Ok(());
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
