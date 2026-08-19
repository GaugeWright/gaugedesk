//! The canonical agent loop: task an agent against a folder and let it work —
//! headlessly, end-to-end through the verified spine.
//!
//! This is the orchestrator the Phase-2 gate names: it creates an engagement
//! worktree off the instance's `main`, admits the [[run]] lifecycle into the
//! durable store, drives one [[runtime-session]] turn through the selected harness and egress
//! membrane, auto-commits the worktree, and surfaces the diff + output. The
//! durable truth (run events) lives in the store; the worktree holds the work;
//! the membrane is the chokepoint for every effect.
//!
//! Each collaborator is the verified piece built in its own crate — this module
//! only sequences them; it owns no protection logic of its own.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::workbench_state::SharedHarness;

/// Test-only **conflict injection** (`UX-7`): when set, a completing turn's merge probe is
/// forced to `Conflict`, driving the engagement into the isolated/repair-context path
/// (`INV-24`) so a browser BDD can exercise conflict-repair without staging a real adversarial
/// workspace conflict. Toggled by the `POST /test/force-conflict` route (gated by
/// `GAUGEDESK_TEST_RESET`); cleared by `POST /test/reset`. Inert in a normal run.
static FORCE_MERGE_CONFLICT: AtomicBool = AtomicBool::new(false);

/// The chats with a turn executing **in this process**, each mapped to its
/// [`InterruptHandle`] if the harness driving it offers one. Kept outside the
/// workbench mutex so a Stop request can terminate a running turn's runtime
/// without blocking on the lock the turn itself holds.
///
/// *Presence* is the liveness record the one-turn-per-chat refusal keys on
/// (ADR 0138 §6): an entry means a turn is executing here, whether or not it can
/// be interrupted. Those two facts used to be one — the map was written only when
/// a harness had an interrupt handle, so a turn that could not be interrupted was
/// invisible to it.
///
/// Deliberately in-process, and deliberately not durable. A run left `Running` by
/// a process that died has no entry here after a restart, which is exactly what
/// stops a crashed turn from refusing its chat forever.
static RUNNING_TURNS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, LiveTurn>>,
> = std::sync::OnceLock::new();

/// What is known about one chat's live turn while it executes here.
#[derive(Default)]
struct LiveTurn {
    /// Its interrupt handle, when the harness driving it offers one. Absent for
    /// the whole of turn startup — provider resolution, the credential
    /// precheck, the workbench lock, the harness build — which is exactly the
    /// stretch a person presses Stop in, having just changed their mind.
    interrupt: Option<InterruptHandle>,
    /// Whether a Stop was asked for. Recorded against the *claim*, which exists
    /// for the whole turn, rather than against the handle, which does not: an
    /// intent that outlives the moment it arrived in is honoured by whichever
    /// mechanism reaches it first, so Stop's answer stops depending on how far
    /// startup happened to have got.
    ///
    /// It is also the only record of **who ended the turn**. A real harness
    /// reports a turn cut short the only way it can — a dead stream — and that
    /// is indistinguishable from breaking.
    stop_requested: bool,
}

fn running_turns() -> &'static std::sync::Mutex<std::collections::HashMap<String, LiveTurn>> {
    RUNNING_TURNS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// An exclusive claim on a chat's one live turn (ADR 0138 §1).
///
/// Held for the whole execution and released on drop, so an early return, an
/// error path or a panic cannot strand the chat as permanently busy.
pub(crate) struct TurnClaim {
    chat: String,
}

impl Drop for TurnClaim {
    fn drop(&mut self) {
        running_turns().lock_unpoisoned().remove(&self.chat);
    }
}

/// Claim this chat's turn slot, or `None` when a turn is already executing for
/// it — the refusal ADR 0138 §2 makes a normal outcome rather than a race.
pub(crate) fn claim_turn(id: &str) -> Option<TurnClaim> {
    let mut turns = running_turns().lock_unpoisoned();
    if turns.contains_key(id) {
        return None;
    }
    turns.insert(id.to_string(), LiveTurn::default());
    Some(TurnClaim {
        chat: id.to_string(),
    })
}

/// Attach a running turn's interrupt handle to its claim, so a concurrent Stop
/// can reach it. A harness with nothing to interrupt never calls this; the claim
/// is what records that the turn is live, not the handle.
///
/// A Stop that already landed is fired here, the instant there is something to
/// fire. Without that, an intent recorded during startup would be honoured only
/// by the checkpoints — and the last checkpoint is before the harness exists, so
/// a Stop arriving between it and this line would have been kept and never
/// acted on.
pub(crate) fn bind_turn_interrupt(id: &str, interrupt: InterruptHandle) {
    let already_stopped = {
        let mut turns = running_turns().lock_unpoisoned();
        match turns.get_mut(id) {
            Some(live) => {
                live.interrupt = Some(Arc::clone(&interrupt));
                live.stop_requested
            }
            None => false,
        }
    };
    // Fired with the registry lock released: an arbitrary handle must never run
    // while this mutex is held.
    if already_stopped {
        interrupt();
    }
}

/// Whether a turn is executing for this chat **in this process** — the liveness
/// half of the one-turn-per-chat rule (ADR 0138 §6). Distinct from the run's
/// durable phase, which stays `Running` after a process dies mid-turn.
///
/// Never admit a turn on this: production takes the *claim* to do that, and a
/// separate read would be a race — free when checked, taken by the time it was
/// acted on. Stop read it too, to tell its two refusals apart; it has only one
/// refusal now, so this is left to the tests that assert the invariant itself.
#[cfg(test)]
pub(crate) fn turn_is_live(id: &str) -> bool {
    running_turns().lock_unpoisoned().contains_key(id)
}

/// The interrupt handle for a running turn, if it has one. `None` covers both
/// "no turn running" and "running but not interruptible"; Stop treats them the
/// same, because neither can be interrupted.
pub fn running_turn_interrupt(id: &str) -> Option<InterruptHandle> {
    running_turns()
        .lock_unpoisoned()
        .get(id)
        .and_then(|live| live.interrupt.clone())
}

/// Record that this chat's live turn is to be stopped, and hand back its
/// interrupt handle if one is already bound. Returned rather than called here so
/// an arbitrary handle never runs while this mutex is held.
///
/// `None` means there is no claim — nothing is running. The inner `None` is not
/// a refusal: the intent is recorded either way, and the turn is ended by the
/// next mechanism to reach it (a startup checkpoint, or `bind_turn_interrupt`
/// firing the handle the moment it exists). A turn under a claim is always
/// stoppable, so "running but not interruptible" is no longer a state this can
/// be in.
pub(crate) fn request_turn_stop(id: &str) -> Option<Option<InterruptHandle>> {
    let mut turns = running_turns().lock_unpoisoned();
    let live = turns.get_mut(id)?;
    live.stop_requested = true;
    Some(live.interrupt.clone())
}

/// Whether a Stop was asked for against this chat's live turn.
///
/// Read once the turn has returned, while its claim is still held, to tell "it
/// broke" from "you stopped it". A production harness cannot say which: killing
/// its runtime ends the stream, and a dead stream is reported as an `io` error
/// or a `Failed` phase either way.
///
/// Also read *during* the turn, at the startup checkpoints below, where it is
/// the whole mechanism: a turn interrupts itself at the next boundary it
/// crosses, needing no handle at all.
pub(crate) fn turn_was_stopped(id: &str) -> bool {
    running_turns()
        .lock_unpoisoned()
        .get(id)
        .is_some_and(|live| live.stop_requested)
}

/// Fail this turn now if a Stop has landed against its claim.
///
/// Called at each boundary turn startup already crosses. Startup is the stretch
/// with no interrupt handle to fire — measured at 124-222ms against a real
/// provider, most of it two credential round trips — so this is what makes a
/// Stop pressed straight after Enter end the turn rather than be refused by it.
fn stop_checkpoint(id: &str) -> Result<(), EngineError> {
    if turn_was_stopped(id) {
        tracing::debug!(chat = %id, "turn stopped before it reached its harness");
        return Err(EngineError::Interrupted);
    }
    Ok(())
}

/// Clear all running-turn interrupt handles, used by the test reset route
/// (which, like this helper, exists only in debug builds — DR-0054 Phase A).
#[cfg(debug_assertions)]
pub(crate) fn clear_running_turns() {
    running_turns().lock_unpoisoned().clear();
}

/// Set the test-only merge-conflict injection flag (`UX-7`).
pub fn set_force_merge_conflict(on: bool) {
    FORCE_MERGE_CONFLICT.store(on, Ordering::Relaxed);
}

/// Whether merge-conflict injection is armed (`UX-7`).
pub fn force_merge_conflict() -> bool {
    FORCE_MERGE_CONFLICT.load(Ordering::Relaxed)
}

use gaugedesk_boundary::{definition, AgentConfig, AuthoringMode, Decision, Effect, Membrane};
use tokio::sync::broadcast;

use crate::harness_select::ScriptedFakeFactory;
use crate::library::ChatMode;
use crate::policy_compiler::PolicyCompilationInput;
use crate::stream::ServerEvent;
use crate::{LockUnpoisoned, SharedWorkbench, Workbench};

impl Workbench {
    fn record_completed_target_apply(&mut self, id: &str) {
        self.refresh_work_target_basis_from_chat(id);
        let Some(binding) = self.library_chat_target_binding(id) else {
            return;
        };
        let candidate = self
            .engagements
            .get(id)
            .and_then(|engagement| engagement.current_cut().ok())
            .flatten();
        let resulting_revision = self
            .library
            .work_targets
            .get(&binding.target_id)
            .and_then(|target| target.current_basis.clone());
        let _ = self.record_target_act(
            Some(id),
            &binding.target_id,
            crate::target_adapter::TargetActKind::Apply,
            candidate,
            Vec::new(),
            resulting_revision,
            crate::target_adapter::TargetActStatus::Completed,
            None,
        );
    }

    /// Place a chat's runtime in a *different* trust authority: register its
    /// **remote** harness alongside the local sessions (`WORKBENCH-REMOTE-1`). A
    /// chat is local or remote, never both, so an existing local session under the
    /// same id is retired (shut down) first — the workbench holds one runtime per
    /// chat, just at one of two placements.
    pub fn register_remote_session(
        &mut self,
        chat_id: impl Into<String>,
        harness: Box<dyn gaugedesk_harness::RemoteHarness>,
    ) {
        let chat_id = chat_id.into();
        if let Some(local) = self.sessions.remove(&chat_id) {
            crate::workbench_state::shutdown_shared_harness(local);
        }
        self.remote_sessions.insert(chat_id, harness);
    }

    /// Whether a chat is placed remotely (has a registered remote harness). The
    /// engine consults this to route a turn down the local or the remote path.
    pub fn is_remote(&self, chat_id: &str) -> bool {
        self.remote_sessions.contains_key(chat_id)
    }

    #[cfg(test)]
    pub(crate) fn seed_local_session_for_test(
        &mut self,
        chat_id: impl Into<String>,
        harness: Box<dyn gaugedesk_harness::Harness>,
    ) {
        self.sessions
            .insert(chat_id.into(), Arc::new(Mutex::new(harness)));
    }

    #[cfg(test)]
    pub(crate) fn has_local_session_for_test(&self, chat_id: &str) -> bool {
        self.sessions.contains_key(chat_id)
    }

    /// The peer endpoint a remotely-placed chat is reached at, if any — the relay
    /// resolves it (ADR 0020); the workbench only records *which* placement holds.
    pub fn remote_address(&self, chat_id: &str) -> Option<&str> {
        self.remote_sessions.get(chat_id).map(|h| h.address())
    }

    /// The network egress posture for a chat, resolved through its project
    /// (see [`crate::library::Library::chat_network_isolated`]). Open by default;
    /// an explicit per-project opt-in isolates. Read by the engine when building
    /// the selected harness's egress policy.
    pub fn chat_network_isolated(&self, chat_id: &str) -> bool {
        self.library_chat_network_isolated(chat_id)
    }

    /// Stop and forget all in-memory local/remote agent sessions before the
    /// test-only reset swaps the durable workbench state. Debug builds only,
    /// like the reset route that calls it (DR-0054 Phase A).
    #[cfg(debug_assertions)]
    pub(crate) fn shutdown_sessions_for_reset(&mut self) {
        for (_, session) in std::mem::take(&mut self.sessions) {
            crate::workbench_state::shutdown_shared_harness(session);
        }
        self.remote_sessions.clear();
    }
}

/// The editor persona used in **edit mode**: the agent you edit *with* (ADR
/// 0027). It works on the *current* agent's definition — prefixed to the prompt
/// so the model edits the agent rather than doing end-user work.
pub const EDITOR_FRAMING: &str =
    "You are the editor: you improve THIS agent's own definition in the current workspace. \
Its authored WhippleScript package lives in `.whipple/draft`; frozen package versions are read-only. \
Edit the draft persona, workflow, and capability registry to satisfy the request, then briefly explain what you changed. \
Do not perform end-user tasks in edit mode — refine the agent itself.";

/// Append a durable transcript record (admitted run evidence) to the engagement's
/// log — the snapshot the client reduces on load (`app-stack.md`: repairable).
fn record_transcript(store: &mut Store, scope: &str, event: &ServerEvent) {
    let _ = append_transcript(store, scope, event);
}

fn append_transcript(
    store: &mut Store,
    scope: &str,
    event: &ServerEvent,
) -> Result<i64, gaugedesk_store::AdmitError> {
    store.append_record(scope, "transcript", &event.to_json())
}

fn turn_reads(
    store: &Store,
    scope: &str,
    signature: &[gaugedesk_harness::OutputFieldFlow],
) -> Result<Vec<gaugedesk_core::resource::ResourceId>, AdmitError> {
    if signature.is_empty() {
        // Legacy/test adapters publish no signature. Preserve the existing
        // conservative rule: every granted context may have flowed.
        crate::resource_store::granted_context(store, scope)
    } else {
        crate::resource_store::certified_output_reads(store, scope, signature)
    }
}

#[allow(clippy::too_many_arguments)]
fn admit_turn_summary(
    store: &mut Store,
    scope: &str,
    user_entry_id: i64,
    receipt_status: crate::turn_summary::ReceiptStatus,
    error: Option<String>,
    diff: &str,
    reads: &[gaugedesk_core::resource::ResourceId],
) -> Result<(), AdmitError> {
    let changed_paths = crate::advancement::TurnFacts::changed_paths_of(diff);
    let summary = crate::turn_summary::TurnSummary {
        user_entry_id,
        receipt_status,
        error,
        changed_count: changed_paths.len(),
        changed_paths,
        policy_diff_direction: crate::turn_summary::policy_diff_direction(diff),
        certified_reads: crate::turn_summary::join_certified_reads(store, scope, reads)?,
    };
    crate::turn_summary::append(store, scope, &summary)?;
    Ok(())
}

pub(crate) const TURN_BOUNDARY_KIND: &str = "turn_boundary";

/// One settled context-window reading per turn (the composer's context meter).
/// Engagement-scoped only — this is a gauge of the chat's own window, never
/// billing evidence, so it deliberately does not join the managed-usage
/// dual-write to billing scopes. The latest record is the reading.
pub(crate) const CONTEXT_READING_KIND: &str = "context_window_reading";

/// Exact coordinates needed to fork either side of one completed turn.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct TurnBoundaryRecord {
    pub(crate) user_entry_id: i64,
    pub(crate) assistant_entry_id: i64,
    pub(crate) before_workspace_cut: String,
    pub(crate) after_workspace_cut: String,
    pub(crate) runtime_before: gaugedesk_harness::RuntimePosition,
    pub(crate) runtime_after: gaugedesk_harness::RuntimePosition,
    pub(crate) reads_before: Vec<String>,
    pub(crate) reads_after: Vec<String>,
}

const RUNTIME_EVIDENCE_POINTER_KIND: &str = "runtime_evidence_pointer";

#[derive(serde::Serialize)]
struct RuntimeEvidenceCrossing<'a> {
    runtime: &'static str,
    pointer: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_cut_ref: Option<WorkspaceCutRef<'a>>,
}

#[derive(serde::Serialize)]
struct WorkspaceCutRef<'a> {
    substrate: &'static str,
    revision: &'a str,
}

/// Admit body-free WhippleScript pointers at most once. The record's assigned
/// GaugeDesk scope position and the WhippleScript position inside `pointer`
/// form the cross-store cut. The workspace revision is a WhippleScript-native
/// manifest cut, not a commit in a second authority store.
fn admit_runtime_evidence_pointers(
    store: &mut Store,
    scope: &str,
    pointers: &[String],
    workspace_revision: Option<&str>,
) -> Result<Vec<i64>, AdmitError> {
    use sha2::{Digest, Sha256};

    let mut positions = Vec::with_capacity(pointers.len());
    for pointer in pointers {
        let key = format!(
            "whip:pointer:{}",
            hex::encode(Sha256::digest(pointer.as_bytes()))
        );
        let crossing = RuntimeEvidenceCrossing {
            runtime: "whipplescript",
            pointer,
            workspace_cut_ref: workspace_revision.map(|revision| WorkspaceCutRef {
                substrate: "whipplescript",
                revision,
            }),
        };
        let payload = serde_json::to_string(&crossing)?;
        let (position, _) =
            store.append_record_with_key(scope, &key, RUNTIME_EVIDENCE_POINTER_KIND, &payload)?;
        positions.push(position);
    }
    Ok(positions)
}
use gaugedesk_core::merge::{MergeCommand, MergePhase, MergeState};
use gaugedesk_core::run::{RunCommand, RunPhase, RunState};
use gaugedesk_harness::{
    CredentialProbe, EgressGate, GateDecision, Harness, HarnessFactory, HarnessSpec, ImageContent,
    InterruptHandle, Observation, TurnOutcome,
};
use gaugedesk_store::{AdmitError, Store};
use gaugedesk_workspace::{ChatWorkspace, MergeOutcome};

/// A membrane-backed egress gate: maps a harness tool name to an [`Effect`] and asks
/// the [`Membrane`] to rule. Tools known to leave the workspace (network) are
/// classified as external; everything else as an in-workspace effect.
pub struct MembraneGate {
    membrane: Membrane,
    external_tools: BTreeSet<String>,
}

impl MembraneGate {
    pub fn new(config: &AgentConfig, external_tools: BTreeSet<String>) -> Self {
        Self {
            membrane: Membrane::new(config.policy.clone()),
            external_tools,
        }
    }

    /// Bind the engagement's chat mode so the membrane can enforce the
    /// method-definition write-gate (`INV-24`): edit may edit the agent's own
    /// definition, use is read-only to it.
    pub fn with_mode(mut self, mode: ChatMode) -> Self {
        let authoring = match mode {
            ChatMode::Edit => AuthoringMode::Edit,
            ChatMode::Use => AuthoringMode::Use,
        };
        self.membrane = self.membrane.with_mode(authoring);
        self
    }
}

impl EgressGate for MembraneGate {
    fn classify_tool(&self, tool: &str, target: Option<&str>) -> GateDecision {
        let effect = if self.external_tools.contains(tool) {
            Effect::external(tool)
        } else {
            Effect::in_workspace(tool)
        }
        .with_target(target.map(|s| s.to_string()));
        match self.membrane.classify(&effect) {
            Decision::Allow => GateDecision::Allow,
            Decision::Block(r) => GateDecision::Block(r.to_string()),
            Decision::Stage(r) => GateDecision::Stage(r.to_string()),
        }
    }
}

/// Tools known to leave the workspace (network). The membrane treats everything
/// else as an in-workspace effect.
fn default_external_tools() -> BTreeSet<String> {
    ["fetch", "web", "curl", "http", "download"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Defense-in-depth package/control roots: work chats protect all package bytes;
/// edit chats protect frozen versions while leaving only the draft writable;
/// GaugeDesk runtime selection is always protected.
/// The egress hosts the model endpoint needs, by provider (RF-B3). This is the
/// single deliberate network grant the bridge declares so a deny-by-default
/// sandbox can still reach the model — every *other* destination (a `curl` to an
/// attacker host) is outside this declared set. The host list is intentionally
/// conservative per provider; it is the allowlist the per-host egress proxy will
/// enforce once that routing lands (until then it records intent and flips the
/// posture to allow). An unknown provider falls back to the OpenAI/codex set.
/// Resolve a private turn's provider: a non-empty managed-Home override wins
/// over the chat's `.agent-config.json` provider, which wins over the Codex
/// OAuth default. Public releases do not execute through this engine.
pub(crate) fn resolve_turn_provider(
    host_override: Option<String>,
    config_provider: Option<String>,
) -> String {
    host_override
        .filter(|s| !s.is_empty())
        .or(config_provider.filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "openai-codex".to_string())
}

/// Resolve a turn's model: a non-empty host override (`GAUGEDESK_MODEL`) wins over the chat's
/// configured model; `None` leaves the selected provider's default. Paired with
/// [`resolve_turn_provider`] so a host that forces the provider can pin a compatible model.
pub(crate) fn resolve_turn_model(
    host_override: Option<String>,
    config_model: Option<String>,
) -> Option<String> {
    host_override
        .filter(|s| !s.is_empty())
        .or(config_model.filter(|s| !s.is_empty()))
}

fn model_endpoint_hosts(provider: Option<&str>) -> Vec<String> {
    let hosts: &[&str] = match provider.unwrap_or("openai-codex") {
        // Managed-Home providers egress only to their gateway endpoint;
        // provider-token details live in the private managed-service host.
        p if p.contains("cloudflare") => &["gateway.ai.cloudflare.com", "api.cloudflare.com"],
        p if p.starts_with("openai") || p.contains("codex") => {
            &["api.openai.com", "chatgpt.com", "auth.openai.com"]
        }
        p if p.contains("anthropic") => &["api.anthropic.com"],
        "xai" => &["api.x.ai"],
        p if p.contains("azure") => &["openai.azure.com"],
        // Unknown provider: default to the codex/OpenAI endpoints rather than
        // opening the network wide — a misconfigured provider fails closed-ish.
        _ => &["api.openai.com", "chatgpt.com", "auth.openai.com"],
    };
    hosts.iter().map(|s| s.to_string()).collect()
}

/// The network egress posture a turn runs under (RF-B3, CORE-5). Pure so the
/// precedence is unit-testable:
///
/// - operator forced unfiltered egress (`GAUGEDESK_ALLOW_UNFILTERED_EGRESS=1`) ⇒
///   [`Network::Allow`] — the conscious unfiltered opt-in wins over everything;
/// - the project isolates its network ⇒ [`Network::Deny`];
/// - a non-isolated project ⇒ [`Network::Filtered`], admitting only the resolved
///   model endpoint.
///
/// WhippleScript owns the provider client, fixes its request URL from the admitted
/// binding, and refuses redirects. It can therefore enforce the model-endpoint
/// filter directly without depending on the legacy Pi subprocess/netns routing
/// capability. Isolation (`Deny`) and the conscious unfiltered opt-in (`Allow`)
/// remain GaugeDesk product-policy decisions.
fn egress_posture(
    project_isolated: bool,
    forced_unfiltered: bool,
) -> gaugedesk_harness::sandbox::Network {
    use gaugedesk_harness::sandbox::Network;
    if forced_unfiltered {
        Network::Allow
    } else if project_isolated {
        Network::Deny
    } else {
        Network::Filtered
    }
}

fn method_surface_readonly_roots(worktree: &Path, mode: ChatMode) -> Vec<std::path::PathBuf> {
    let package_roots = match mode {
        ChatMode::Use => definition::READONLY_ROOTS,
        ChatMode::Edit => definition::EDIT_READONLY_ROOTS,
    };
    package_roots
        .iter()
        .chain(definition::CONTROL_READONLY_ROOTS.iter())
        .map(|s| worktree.join(s))
        .filter(|p| p.exists())
        .collect()
}

fn target_writable_roots(worktree: &Path, path_scope: &[String]) -> Vec<std::path::PathBuf> {
    path_scope
        .iter()
        .map(|scope| {
            if scope == "." {
                worktree.to_path_buf()
            } else {
                worktree.join(scope)
            }
        })
        .collect()
}

/// The result of one tasked turn.
#[derive(Debug, serde::Serialize)]
pub struct TaskResult {
    pub run_phase: RunPhase,
    pub assistant_text: String,
    /// The diff produced by this turn. It remains useful as settled-turn evidence
    /// even when default auto-sync has already made the branch-vs-line diff empty.
    pub diff: String,
    /// The turn's opaque WhippleScript cut id, if the turn changed anything.
    pub commit: Option<String>,
    /// The merge lifecycle phase after the turn: `Clean` (awaiting the human's
    /// admit/reject of the diff) or `Rejected` (a workspace conflict → isolated).
    pub merge_phase: MergePhase,
    pub mediated_tool_calls: Vec<String>,
    /// Effects the membrane blocked (the out-of-policy path).
    pub blocked_effects: Vec<String>,
    pub pending_approvals: Vec<String>,
    /// Questions the agent asked this turn, not yet filed. Persisted by the
    /// workbench-holding caller, which is the layer that can resolve a recipient
    /// against the roster (ADR 0113 §4).
    #[serde(skip)]
    pub asked_questions: Vec<gaugedesk_harness::AskedQuestion>,
    /// The runtime/model error that failed this turn, if any — lets the client show
    /// an honest status immediately (the same text is also a durable transcript line).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The turn's certified dynamic guarantee outcomes (DR-0036 §2), matched by
    /// name at settle by the advancement policy (ADR 0082 §5). Empty when the
    /// runtime published no report — the local-truth path decides.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub guarantee_outcomes: Vec<gaugedesk_harness::GuaranteeOutcome>,
    /// Runtime-owned usage evidence projected for an in-process funding ledger.
    /// It is admitted durably below and deliberately omitted from the public
    /// task response; callers receive only their normal turn projection.
    #[serde(skip)]
    pub usage_observation: Option<gaugedesk_harness::ModelUsage>,
}

#[derive(Debug)]
pub enum EngineError {
    Admit(AdmitError),
    Workspace(gaugedesk_workspace::WorkspaceError),
    Harness(std::io::Error),
    /// A leg that only ever had a message. Carrying it keeps the turn chain on
    /// one error type, so a classified failure is not flattened to `String` by
    /// the first `?` that happens to sit above it.
    Message(String),
    /// Not a failure: a turn is already executing for this chat, so this one was
    /// refused rather than started (ADR 0138 §2). `INV-2` — a refusal is a normal
    /// outcome carrying its reason, which is why the routes answer it 409 rather
    /// than 502, and why nothing about the chat changed.
    AlreadyRunning,
    /// Not a failure either: someone stopped this turn on purpose. It ends
    /// incomplete, but a person asking for exactly this outcome and being shown a
    /// gateway error for it is the composer calling their own decision a fault —
    /// and, worse, the message they cancelled being kept for a retry they did not
    /// ask for. Carried as its own leg so every layer above can tell "it broke"
    /// from "you stopped it".
    Interrupted,
}
impl From<AdmitError> for EngineError {
    fn from(e: AdmitError) -> Self {
        EngineError::Admit(e)
    }
}
impl From<gaugedesk_workspace::WorkspaceError> for EngineError {
    fn from(e: gaugedesk_workspace::WorkspaceError) -> Self {
        EngineError::Workspace(e)
    }
}
impl From<String> for EngineError {
    fn from(e: String) -> Self {
        EngineError::Message(e)
    }
}
/// Human-readable turn-failure text — what the turn routes surface as the HTTP
/// error body. The workspace/harness legs carry impl-minted messages; an
/// admission error has no Display and keeps its Debug rendering.
impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Admit(e) => write!(f, "{e:?}"),
            EngineError::Workspace(e) => write!(f, "{e}"),
            EngineError::Harness(e) => write!(f, "{e}"),
            EngineError::Message(e) => write!(f, "{e}"),
            EngineError::AlreadyRunning => {
                write!(f, "a turn is already running for this chat")
            }
            EngineError::Interrupted => write!(f, "stopped"),
        }
    }
}
impl EngineError {
    /// Whether this failure is the runtime **refusing** the turn on policy — an
    /// information-flow denial or a rejected package — as opposed to something
    /// breaking.
    ///
    /// The distinction is not cosmetic. A refusal is a decision the caller must
    /// see and act on, so it belongs in the 4xx range; reporting it as `502`
    /// tells the caller to retry something that will be refused identically
    /// every time, and — because Cloudflare substitutes its own body for origin
    /// 5xx — replaces the runtime's explanation with "the origin is overloaded
    /// or misconfigured". The wiring canary chased exactly that phantom.
    ///
    /// The classification is minted where the type still exists, in
    /// `gaugedesk-whip-runtime`, as `io::ErrorKind::PermissionDenied`.
    pub fn is_policy_denial(&self) -> bool {
        matches!(self, EngineError::Harness(e) if e.kind() == std::io::ErrorKind::PermissionDenied)
    }
}

/// Run one task turn against an existing engagement worktree.
///
/// `harness` drives the engagement's selected runtime; `gate` is the membrane. The run
/// lifecycle is admitted into `store` under `scope`; the runtime-session is
/// seeded to `executing` and advanced by the turn.
pub fn run_task<G: EgressGate>(
    store: &mut Store,
    scope: &str,
    engagement: &dyn ChatWorkspace,
    harness: &mut dyn Harness,
    gate: &G,
    task: &str,
    images: &[ImageContent],
) -> Result<TaskResult, EngineError> {
    run_task_streaming(
        store,
        scope,
        engagement,
        harness,
        gate,
        task,
        images,
        &mut |_| {},
    )
}

/// As [`run_task`], but `sink` receives each operational [`Observation`] as the
/// turn produces it — the control plane forwards these onto the live SSE stream.
/// `images` are native image content blocks sent to the harness as model input
/// for this turn; they are **never** recorded in the durable transcript.
#[allow(clippy::too_many_arguments)]
pub fn run_task_streaming<G: EgressGate>(
    store: &mut Store,
    scope: &str,
    engagement: &dyn ChatWorkspace,
    harness: &mut dyn Harness,
    gate: &G,
    task: &str,
    images: &[ImageContent],
    sink: &mut dyn FnMut(&Observation),
) -> Result<TaskResult, EngineError> {
    run_task_streaming_billed(
        store, engagement, scope, harness, gate, task, images, sink, None, None, "",
    )
}

#[allow(clippy::too_many_arguments)]
fn run_task_streaming_billed<G: EgressGate>(
    store: &mut Store,
    engagement: &dyn ChatWorkspace,
    scope: &str,
    harness: &mut dyn Harness,
    gate: &G,
    task: &str,
    images: &[ImageContent],
    sink: &mut dyn FnMut(&Observation),
    managed_billing_scope: Option<&str>,
    managed_funding_ref: Option<&str>,
    // Context the model sees ahead of the task but the transcript does not record
    // as user text — currently answers to questions this agent asked (ADR 0113).
    prompt_prefix: &str,
) -> Result<TaskResult, EngineError> {
    // Observability span (RF-A8): scope + task size only — never the task text or
    // any content (those are protected; the span is operational metadata). The
    // span covers the whole turn; a completion event records the outcome below.
    let _span = tracing::info_span!("engine.turn", scope, task_len = task.len()).entered();
    // 1. Admit the run into durable truth. Each task is a fresh run (ADR 0026):
    //    a fresh engagement begins from Init (requestRun); a subsequent turn
    //    re-enters from the prior run's terminal state (retryRun). Either way the
    //    run must be re-admitted before it can start (INV-11).
    let initial_phase = store.fold::<RunState>(scope)?.phase;
    match initial_phase {
        RunPhase::Init => {
            store.admit::<RunState>(scope, RunCommand::RequestRun)?;
            store.admit::<RunState>(scope, RunCommand::AdmitRun)?;
            store.admit::<RunState>(scope, RunCommand::StartRun)?;
        }
        RunPhase::Requested => {
            store.admit::<RunState>(scope, RunCommand::AdmitRun)?;
            store.admit::<RunState>(scope, RunCommand::StartRun)?;
        }
        RunPhase::Admitted => {
            store.admit::<RunState>(scope, RunCommand::StartRun)?;
        }
        // Reachable only for a run whose process died mid-turn: a live turn holds
        // this chat's claim, so a concurrent one is refused before it gets here
        // (ADR 0138 §6). `Running` with nothing executing is therefore a crashed
        // run, and re-entering it is the recovery — which is why this stays a
        // pass-through rather than becoming the refusal. Refusing on the durable
        // phase alone would strand that chat forever.
        RunPhase::Running => {}
        RunPhase::Completed | RunPhase::Failed | RunPhase::Canceled => {
            store.admit::<RunState>(scope, RunCommand::RetryRun)?;
            store.admit::<RunState>(scope, RunCommand::AdmitRun)?;
            store.admit::<RunState>(scope, RunCommand::StartRun)?;
        }
    }

    let before_workspace_cut = engagement.boundary_cut()?;
    let reads_before = crate::resource_store::engagement_reads(store, scope)?
        .items()
        .iter()
        .cloned()
        .collect::<Vec<_>>();

    // Admit the user message as durable transcript evidence (turn-boundary). The
    // transcript records the **raw** task; mode framing is invisible context the
    // model receives, not something the user typed.
    let user_entry_id = append_transcript(
        store,
        scope,
        &ServerEvent::User {
            text: task.to_string(),
        },
    )?;
    debug_assert_eq!(
        managed_billing_scope.is_some(),
        managed_funding_ref.is_some()
    );
    let managed_reservation_id = managed_billing_scope
        .zip(managed_funding_ref)
        .map(|(billing_scope, funding_ref)| {
            let reservation_id = format!("managed:{scope}:{user_entry_id}");
            crate::managed_inference::reserve_turn(
                store,
                scope,
                billing_scope,
                funding_ref,
                &reservation_id,
            )?;
            Ok::<_, EngineError>(reservation_id)
        })
        .transpose()?;

    // 2. Drive one turn through the **harness** (ADR 0031) over the membrane. The
    //    harness owns its protocol + session; the prompt is the raw task. Persona
    //    comes from the selected authored package or separate editor package.
    // The transcript above recorded the raw task. The model additionally receives
    // any answers that arrived since its last turn — invisible context it was
    // promised when `ask` returned, not something the user typed.
    let prompt = if prompt_prefix.is_empty() {
        task.to_string()
    } else {
        format!("{prompt_prefix}{task}")
    };
    let outcome: TurnOutcome = match harness.run_turn(gate, &prompt, images, sink) {
        Ok(outcome) => outcome,
        Err(error) => {
            // A transport death is still a settled attempt. Keep the run and
            // task projections repairable instead of stranding `Running` with
            // no durable failure fact.
            store.admit::<RunState>(scope, RunCommand::FailRun)?;
            let reason = error.to_string();
            record_transcript(
                store,
                scope,
                &ServerEvent::Error {
                    reason: reason.clone(),
                    code: None,
                },
            );
            let diff = engagement.diff_against_main().unwrap_or_default();
            admit_turn_summary(
                store,
                scope,
                user_entry_id,
                crate::turn_summary::ReceiptStatus::Failed,
                Some(reason),
                &diff,
                &[],
            )?;
            if let (Some(reservation_id), Some(billing_scope)) =
                (&managed_reservation_id, managed_billing_scope)
            {
                crate::managed_inference::settle_reservation(
                    store,
                    scope,
                    billing_scope,
                    reservation_id,
                    None,
                    "model_transport_failed_without_usage",
                )?;
            }
            return Err(EngineError::Harness(error));
        }
    };

    // 3a. Admit the runtime's execution evidence into the run (INV-4): each tool
    //     decision the membrane ruled on is an observation that becomes standing
    //     run state only by this admission, while the run is still `running`.
    for _ in &outcome.observations {
        store.admit::<RunState>(scope, RunCommand::RecordObservation)?;
    }

    // 3b. Auto-commit the worktree (per-turn), then capture the reviewer's diff.
    let commit = engagement.commit_turn(task)?;
    let diff = engagement.diff_against_main()?;
    admit_runtime_evidence_pointers(
        store,
        scope,
        &outcome.runtime_evidence_pointers,
        commit.as_ref().map(|commit| commit.0.as_str()),
    )?;

    // 4. Map the turn outcome onto the run lifecycle: clean turn → completed,
    //    a runtime/stream error → failed. Either way the events are durable facts.
    let run_phase = if outcome.error.is_none() {
        store.admit::<RunState>(scope, RunCommand::CompleteRun)?;
        RunPhase::Completed
    } else {
        store.admit::<RunState>(scope, RunCommand::FailRun)?;
        RunPhase::Failed
    };
    if let Some(usage) = &outcome.managed_usage {
        crate::managed_inference::append_usage(
            store,
            scope,
            managed_billing_scope.unwrap_or(scope),
            usage,
        )?;
    }
    if let Some(reading) = &outcome.context_reading {
        let payload = serde_json::to_string(reading).map_err(gaugedesk_store::AdmitError::Json)?;
        store.append_record(scope, CONTEXT_READING_KIND, &payload)?;
    }
    if let (Some(reservation_id), Some(billing_scope)) =
        (&managed_reservation_id, managed_billing_scope)
    {
        crate::managed_inference::settle_reservation(
            store,
            scope,
            billing_scope,
            reservation_id,
            outcome
                .managed_usage
                .as_ref()
                .map(|usage| usage.usage_ref.as_str()),
            "turn_finished_without_usage",
        )?;
    }

    // 5. Drive the merge lifecycle's start: re-enter + probe the branch-vs-`main`
    //    merge (no mutation). The human gates the advance later via the merge API.
    store.admit::<MergeState>(scope, MergeCommand::StartMerge)?;
    let probe = engagement.merge_probe()?;
    // UX-7: a test-only injection forces the conflict path (INV-24 isolate + repair context)
    // so a browser BDD can drive conflict-repair without staging a real workspace conflict.
    let merge_cmd = if force_merge_conflict() {
        MergeCommand::WorkspaceConflict
    } else {
        match probe {
            MergeOutcome::Clean => MergeCommand::WorkspaceClean,
            MergeOutcome::Conflict => MergeCommand::WorkspaceConflict,
        }
    };
    let merge = store.admit::<MergeState>(scope, merge_cmd)?;

    // 6. Record this turn's reads (every granted context resource) into the durable
    //    engagement read-set, then mint/refresh the derived output resource from it.
    //    Taint is engagement-scoped (ADR 0026): the output's stakeholders are the
    //    owners of everything the engagement has read across turns — sound even after
    //    a read context is later revoked or tombstoned — so a later export/review
    //    gates on persisted handles, not a loose stakeholder set.
    let output_reads = turn_reads(store, scope, &outcome.output_flow_signature)?;
    crate::resource_store::record_reads(store, scope, &output_reads)?;
    // The output is owned by the scope's authenticated owning authority
    // (`determine_scope_authority`, the SCOPE-AUTH-1 seam), not the hardcoded
    // local constant (MINT-1). In the single-user collapse a bare engagement
    // scope resolves to itself; under federation a `scope:<authority>:<rest>`
    // scope resolves to the authority the server authenticated for the call, so
    // a minted output is owned by — and governed by — the right keyset (D-REMOTE).
    let owner = gaugedesk_core::determine_scope_authority(scope);
    let _ = crate::resource_store::mint_output(
        store,
        scope,
        owner.as_str(),
        commit.as_ref().map(|c| c.0.as_str()).unwrap_or_default(),
    );

    let blocked_effects: Vec<String> = outcome
        .observations
        .iter()
        .filter(|o| o.kind == "egress_blocked")
        .map(|o| o.detail.clone())
        .collect();

    // Admit the rest of the turn as durable transcript evidence, in order: each
    // boundary decision (tool line, its result, blocks) exactly as it streamed,
    // then the agent's final message, then the run outcome. Replaying the same
    // observations the live stream carried means a reloaded transcript keeps each
    // tool line's target/args/result — click-to-open survives the turn ending
    // (run-chat.md "live vs truth": the durable layer is the same reduction).
    for obs in &outcome.observations {
        match obs.kind {
            "egress" | "egress_staged" | "tool_result" | "egress_blocked" => {
                record_transcript(store, scope, &ServerEvent::from_observation(obs));
            }
            _ => {} // streamed text is operational-only; not durable evidence
        }
    }
    let assistant_entry_id = append_transcript(
        store,
        scope,
        &ServerEvent::Assistant {
            text: outcome.assistant_text.clone(),
        },
    )?;
    if let (Some(runtime_before), Some(runtime_after), Some(after_workspace_cut)) = (
        outcome.runtime_start_position.clone(),
        outcome.runtime_terminal_position.clone(),
        commit.as_ref(),
    ) {
        let reads_after = crate::resource_store::engagement_reads(store, scope)?
            .items()
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let boundary = TurnBoundaryRecord {
            user_entry_id,
            assistant_entry_id,
            before_workspace_cut: before_workspace_cut.0,
            after_workspace_cut: after_workspace_cut.0.clone(),
            runtime_before,
            runtime_after,
            reads_before,
            reads_after,
        };
        let payload =
            serde_json::to_string(&boundary).map_err(gaugedesk_store::AdmitError::Json)?;
        store.append_record(scope, TURN_BOUNDARY_KIND, &payload)?;
    }
    // A failed turn records *why* as durable evidence, so the user sees the reason
    // (e.g. a model rejecting an image) on the next snapshot — not just a generic
    // "didn't finish". The reason is diagnostic text, never protected content.
    if let Some(reason) = &outcome.error {
        record_transcript(
            store,
            scope,
            &ServerEvent::Error {
                reason: reason.clone(),
                code: None,
            },
        );
    }
    record_transcript(
        store,
        scope,
        &ServerEvent::Admitted {
            kind: "run".into(),
            text: format!("run → {run_phase:?}"),
        },
    );

    admit_turn_summary(
        store,
        scope,
        user_entry_id,
        if run_phase == RunPhase::Completed {
            crate::turn_summary::ReceiptStatus::Completed
        } else {
            crate::turn_summary::ReceiptStatus::Failed
        },
        outcome.error.clone(),
        &diff,
        &output_reads,
    )?;

    // Turn outcome as operational metadata only (counts + phases, no content).
    tracing::info!(
        ?run_phase,
        merge_phase = ?merge.phase,
        observations = outcome.observations.len(),
        mediated_tool_calls = outcome.mediated_tool_calls.len(),
        blocked_effects = blocked_effects.len(),
        pending_approvals = outcome.pending_approvals.len(),
        "engine.turn complete"
    );
    Ok(TaskResult {
        run_phase,
        assistant_text: outcome.assistant_text,
        diff,
        guarantee_outcomes: outcome.guarantee_outcomes,
        usage_observation: outcome.managed_usage,
        commit: commit.map(|c| c.0),
        merge_phase: merge.phase,
        mediated_tool_calls: outcome.mediated_tool_calls,
        blocked_effects,
        pending_approvals: outcome.pending_approvals,
        asked_questions: Vec::new(),
        error: outcome.error,
    })
}

/// The result of one **remote-placed** turn (`ENGINE-REMOTE-1`). A turn that runs
/// in a *different* trust authority has no local worktree, so there is no local
/// commit / diff / merge to surface — the orchestrator's truth is the federated
/// observation count (each crossed the owner's bridge and was owner-admitted,
/// `INV-4`) and the minted output handle (owned by the scope's authority, MINT-1).
#[derive(Debug, serde::Serialize)]
pub struct RemoteTaskResult {
    pub run_phase: RunPhase,
    /// The peer endpoint the turn ran at (the relay resolves it, ADR 0020).
    pub remote_address: String,
    /// How many remote observations crossed the bridge and were owner-admitted.
    pub federated_observations: u32,
    /// The owning authority the derived output was minted under (MINT-1).
    pub output_owner: String,
}

/// Drive one task turn against a **remote-placed** runtime, wiring remote-harness
/// support into the engine orchestrator (`ENGINE-REMOTE-1`).
///
/// This is the remote sibling of [`run_task`]: instead of driving a local harness
/// and committing a worktree, it admits the run lifecycle, runs the turn on a
/// [`RemoteHarness`] in its own authority, and returns each observation **through
/// federation** ([`remote_runtime::federate_remote_turn`], `OBSERVATION-FEDERATION-1`)
/// so a relayed outcome becomes run truth only via the owner's admission (`INV-4`).
/// The derived output is minted under the scope's owning authority
/// ([`determine_scope_authority`](gaugedesk_core::determine_scope_authority), MINT-1),
/// not the hardcoded local constant.
///
/// The test-only single-process loopback harness and a real cross-machine relay
/// attach behind the same neutral seam with no rearchitecture
/// (`RENDEZVOUS-STUB-1`).
pub fn run_task_remote(
    store: &mut Store,
    scope: &str,
    harness: &mut dyn gaugedesk_harness::RemoteHarness,
    gate: &dyn EgressGate,
    task: &str,
) -> Result<RemoteTaskResult, EngineError> {
    // 1. Admit the run into durable truth (same precondition as the local path):
    //    a fresh engagement begins from Init, a subsequent turn re-enters from the
    //    prior terminal state. Either way the run must be re-admitted (INV-11).
    let begin = match store.fold::<RunState>(scope)?.phase {
        RunPhase::Init => RunCommand::RequestRun,
        _ => RunCommand::RetryRun,
    };
    store.admit::<RunState>(scope, begin)?;
    store.admit::<RunState>(scope, RunCommand::AdmitRun)?;
    store.admit::<RunState>(scope, RunCommand::StartRun)?;
    let user_entry_id = append_transcript(
        store,
        scope,
        &ServerEvent::User {
            text: task.to_string(),
        },
    )?;

    let remote_address = harness.address().to_string();

    // 2. Run the turn in the remote authority and federate its observations back:
    //    each crosses the owner's bridge as a signed message over the relay seam
    //    and becomes standing run evidence only via the OWNER's admission (INV-4).
    //    A relay/transport failure fails the run; otherwise it completes.
    let federated_observations =
        match crate::remote_runtime::federate_remote_turn(store, scope, harness, gate, task) {
            Ok(count) => {
                store.admit::<RunState>(scope, RunCommand::CompleteRun)?;
                count
            }
            Err(crate::remote_runtime::RemoteRuntimeError::Admit(e)) => {
                return Err(EngineError::Admit(e))
            }
            Err(crate::remote_runtime::RemoteRuntimeError::Turn(e)) => {
                store.admit::<RunState>(scope, RunCommand::FailRun)?;
                let reason = e.to_string();
                record_transcript(
                    store,
                    scope,
                    &ServerEvent::Error {
                        reason: reason.clone(),
                        code: None,
                    },
                );
                admit_turn_summary(
                    store,
                    scope,
                    user_entry_id,
                    crate::turn_summary::ReceiptStatus::Failed,
                    Some(reason),
                    "",
                    &[],
                )?;
                return Err(EngineError::Harness(e));
            }
        };

    // 3. Record this turn's reads, then mint/refresh the derived output under the
    //    scope's owning authority (MINT-1) — the work is owned by, and governed by,
    //    the right keyset even though it ran in a different authority. There is no
    //    local commit, so the output's locator carries no commit hash.
    let reads = crate::resource_store::granted_context(store, scope)?;
    crate::resource_store::record_reads(store, scope, &reads)?;
    let owner = gaugedesk_core::determine_scope_authority(scope);
    let _ = crate::resource_store::mint_output(store, scope, owner.as_str(), "");

    let run_phase = RunPhase::Completed;
    record_transcript(
        store,
        scope,
        &ServerEvent::Admitted {
            kind: "run".into(),
            text: format!("run → {run_phase:?}"),
        },
    );
    admit_turn_summary(
        store,
        scope,
        user_entry_id,
        crate::turn_summary::ReceiptStatus::Completed,
        None,
        "",
        &reads,
    )?;

    Ok(RemoteTaskResult {
        run_phase,
        remote_address,
        federated_observations,
        output_owner: owner.as_str().to_string(),
    })
}

/// Fail-closed model-credential check (LLM-1, [ADR 0062]): does a usable credential
/// resolve for `provider`? A **BYOK** provider needs its exact-reference
/// capability resolved from the account's `SEC-4`-sealed store; an **OAuth**
/// provider (`openai-codex`, …) authenticates via the runtime adapter's own store,
/// which the turn's `factory` answers for ([`HarnessFactory::credential_status`]).
/// The refusal POLICY — whether a turn runs — stays here; the adapter only reports
/// its own state. Returns an **actionable** error when nothing resolves, so a real
/// run refuses up front instead of letting the runtime fail opaquely on a missing key.
fn llm_credential_status(
    provider: &str,
    credential_capability: Option<&dyn gaugedesk_harness::CredentialCapability>,
    factory: &dyn HarnessFactory,
) -> Result<(), String> {
    // BYOK providers require an exact-reference GaugeDesk capability. Secret
    // bytes remain sealed until WhippleScript admits that reference.
    if crate::account::provider_env_var(provider).is_some() {
        return if credential_capability.is_some() {
            Ok(())
        } else {
            Err(format!(
                "No {provider} key is linked, so this model can't run. Link an \
                 {provider} key in Account settings, or pick a different model."
            ))
        };
    }
    match provider {
        // Managed-Home providers: concrete gateway secrets and routing live in
        // the private managed-service host. The
        // open engine only requires a neutral readiness signal from that host.
        "cloudflare-ai-gateway" | "cloudflare-workers-ai" => {
            let get = |k: &str| std::env::var(k).ok();
            host_managed_model_status(provider, &get)
        }
        // OAuth providers authenticate via the adapter's own auth store.
        _ => match factory.credential_status(provider, credential_capability) {
            CredentialProbe::Ready => Ok(()),
            CredentialProbe::Missing(reason) => Err(reason),
        },
    }
}

fn is_host_managed_provider(provider: &str) -> bool {
    matches!(provider, "cloudflare-ai-gateway" | "cloudflare-workers-ai")
}

/// Fail-closed check for managed-Home model providers: the private host
/// validates and injects provider-specific config, then
/// reports a generic readiness flag to the open engine. Pure (takes a `get`
/// resolver) so it is unit-testable without process env or private secret names.
fn host_managed_model_status(
    provider: &str,
    get: &dyn Fn(&str) -> Option<String>,
) -> Result<(), String> {
    let ready = get("GAUGEDESK_HOST_MODEL_READY")
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));
    if ready {
        Ok(())
    } else {
        Err(format!(
            "The {provider} model can't run: the managed host has not reported model \
             readiness. Configure the private managed runtime, then set \
             GAUGEDESK_HOST_MODEL_READY=1."
        ))
    }
}

/// Blocking: holds the workbench lock for the turn (local single-user MVP). SSE
/// subscribers already hold their receivers, so the live stream is unaffected.
#[allow(clippy::too_many_arguments)]
/// Record a fail-closed pre-flight refusal (LLM-1: no model credential resolves for
/// the turn) as a durable failure turn on `scope`: the user's message, then the reason
/// as a coded [`ServerEvent::Error`] line, with the run admitted through to `Failed`.
/// This mirrors the durable shape of a harness-level failure (see [`run_task_streaming`])
/// so the client's existing failed-turn handling surfaces it in the chat log uniformly
/// — and the `code` lets the client render an "open settings" action instead of plain
/// text. Returns the same `TaskResult { Failed, error }` an in-turn failure returns.
fn record_precheck_failure(
    store: &mut Store,
    scope: &str,
    task: &str,
    reason: String,
    code: &str,
) -> Result<TaskResult, EngineError> {
    // The run starts then immediately fails on the gate — the same lifecycle a turn
    // that reaches the harness and errors admits (RequestRun→AdmitRun→StartRun→FailRun),
    // minus the observations no turn produced.
    let begin = match store
        .fold::<RunState>(scope)
        .map_err(|e| format!("{e:?}"))?
        .phase
    {
        RunPhase::Init => RunCommand::RequestRun,
        _ => RunCommand::RetryRun,
    };
    for cmd in [
        begin,
        RunCommand::AdmitRun,
        RunCommand::StartRun,
        RunCommand::FailRun,
    ] {
        store
            .admit::<RunState>(scope, cmd)
            .map_err(|e| format!("{e:?}"))?;
    }
    let user_entry_id = append_transcript(
        store,
        scope,
        &ServerEvent::User {
            text: task.to_string(),
        },
    )
    .map_err(|error| format!("{error:?}"))?;
    record_transcript(
        store,
        scope,
        &ServerEvent::Error {
            reason: reason.clone(),
            code: Some(code.to_string()),
        },
    );
    admit_turn_summary(
        store,
        scope,
        user_entry_id,
        crate::turn_summary::ReceiptStatus::Failed,
        Some(reason.clone()),
        "",
        &[],
    )
    .map_err(|error| format!("{error:?}"))?;
    Ok(TaskResult {
        run_phase: RunPhase::Failed,
        assistant_text: String::new(),
        diff: String::new(),
        commit: None,
        merge_phase: MergePhase::Clean,
        mediated_tool_calls: Vec::new(),
        blocked_effects: Vec::new(),
        pending_approvals: Vec::new(),
        asked_questions: Vec::new(),
        error: Some(reason),
        guarantee_outcomes: Vec::new(),
        usage_observation: None,
    })
}

/// Drive one turn for an engagement, streaming observations live to its
/// broadcast `sender`. The engine resolves the turn's *policy* (mode framing,
/// credentials, provider/model, fail-closed precheck, base sandbox) into a
/// [`HarnessSpec`]; the runtime itself is constructed by the factory the
/// per-turn selector picks ([`crate::harness_select::factory_for_turn`] — the
/// real WhippleScript adapter, or the scripted fake under `GAUGEDESK_FAKE_AGENT`).
/// Returns the turn result, or a human-readable error (the model endpoint may
/// be unauthenticated/offline).
///
/// Blocking: holds the workbench lock for the turn (local single-user MVP). SSE
/// subscribers already hold their receivers, so the live stream is unaffected.
pub struct EngagementTurnInput<'a> {
    pub task: &'a str,
    pub images: &'a [ImageContent],
    pub mode: ChatMode,
    pub authenticated_actor: Option<&'a gaugedesk_core::ids::AuthorityId>,
    /// Authority that drove this turn for workstream contribution attribution.
    /// This is distinct from the runtime actor: a verified federated crossing may
    /// drive a hub-resident chat while the hub still owns runtime execution.
    pub contribution_by: Option<&'a str>,
    /// Scope of the authenticated person's account subscription.
    pub account_scope: &'a str,
    /// Scope of the current tenant's organization-funded subscription.
    pub tenant_scope: &'a str,
    /// Stable Home-admitted command identity for unattended execution. A retry
    /// reuses this exact WhippleScript command/receipt. Foreground turns omit it.
    pub runtime_command_id: Option<&'a str>,
    /// An admitted execution shell may supply the same WhippleScript factory
    /// with a command-scoped transport (for example a Home-signed private
    /// Durable workflow). Foreground turns use the workbench default.
    pub harness_factory: Option<Arc<dyn HarnessFactory>>,
}

/// Non-secret, immutable inputs a managed Isolated-workspace scheduler must
/// bind before acknowledging a background turn. The actual credential remains
/// behind the Home's exact-reference capability and final-fetch boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsolatedTurnDescriptor {
    pub package_root: PathBuf,
    pub package_version_ref: String,
    pub provider: String,
    pub model: String,
    pub base_url: String,
    pub endpoint_url: String,
    pub credential_ref: String,
}

pub fn isolated_turn_descriptor(
    wb: &SharedWorkbench,
    chat_id: &str,
    actor: &str,
) -> Result<IsolatedTurnDescriptor, String> {
    let guard = wb.lock_unpoisoned();
    let config = AgentConfig::from_json(&guard.effective_agent_config_for_chat(chat_id)?)
        .unwrap_or_default();
    let provider = resolve_turn_provider(gaugedesk_env::var("MODEL_PROVIDER"), config.provider);
    let model = resolve_turn_model(gaugedesk_env::var("MODEL"), config.model);
    let class = guard.model_execution_class();
    let base_url_override = if provider == "openai-generic" {
        guard.credential_base_url_for_chat_in_class(chat_id, &provider, actor, class)
    } else {
        None
    };
    let provider_descriptor = gaugedesk_whip_runtime::native_provider_descriptor(
        &provider,
        model.as_deref(),
        base_url_override.as_deref(),
    )
    .map_err(|error| error.to_string())?;
    let (version, package_version_ref) = guard
        .package_selection_for_chat(chat_id)
        .ok_or_else(|| "chat has no immutable WhippleScript package".to_owned())?;
    let package_root = guard
        .package_root_for_chat(chat_id, version)
        .ok_or_else(|| "chat package root is unavailable".to_owned())?;
    let credential_ref = guard.credential_ref_for_chat_in_class(chat_id, &provider, actor, class);
    let endpoint_url = match provider.as_str() {
        "openai-codex" => format!(
            "{}/backend-api/codex/responses",
            provider_descriptor.base_url.trim_end_matches('/')
        ),
        "openai-generic" => format!(
            "{}/chat/completions",
            provider_descriptor.base_url.trim_end_matches('/')
        ),
        // Same Chat Completions shape; the descriptor base already ends in /v1.
        "xai" => format!(
            "{}/chat/completions",
            provider_descriptor.base_url.trim_end_matches('/')
        ),
        "openai" => format!(
            "{}/v1/responses",
            provider_descriptor.base_url.trim_end_matches('/')
        ),
        "anthropic" => format!(
            "{}/v1/messages",
            provider_descriptor.base_url.trim_end_matches('/')
        ),
        _ => return Err(format!("unsupported Isolated provider `{provider}`")),
    };
    Ok(IsolatedTurnDescriptor {
        package_root,
        package_version_ref,
        provider,
        model: provider_descriptor.model,
        base_url: provider_descriptor.base_url,
        endpoint_url,
        credential_ref,
    })
}

/// Drive one turn for a chat, refusing if one is already running.
///
/// The refusal lives here rather than on a route because a route is not the only
/// way in — a federated crossing drives turns through this same function — and a
/// guard bolted to one entry point would make the invariant true of that caller
/// and false of the next (ADR 0138 §3).
///
/// The claim is released when this returns, by its guard, so an error path or a
/// panic cannot leave a chat permanently busy.
pub fn run_engagement_turn(
    wb: &SharedWorkbench,
    id: &str,
    worktree: &Path,
    sender: &broadcast::Sender<ServerEvent>,
    input: EngagementTurnInput<'_>,
) -> Result<TaskResult, EngineError> {
    let Some(_claim) = claim_turn(id) else {
        return Err(EngineError::AlreadyRunning);
    };
    run_claimed_engagement_turn(wb, id, worktree, sender, input)
}

/// The turn itself, with this chat's claim already held.
fn run_claimed_engagement_turn(
    wb: &SharedWorkbench,
    id: &str,
    worktree: &Path,
    sender: &broadcast::Sender<ServerEvent>,
    input: EngagementTurnInput<'_>,
) -> Result<TaskResult, EngineError> {
    let EngagementTurnInput {
        task,
        images,
        mode,
        authenticated_actor,
        contribution_by,
        account_scope,
        tenant_scope,
        runtime_command_id,
        harness_factory,
    } = input;
    let config = {
        let g = wb.lock_unpoisoned();
        AgentConfig::from_json(&g.effective_agent_config_for_chat(id)?).unwrap_or_default()
    };
    stop_checkpoint(id)?;
    let gate = MembraneGate::new(&config, default_external_tools()).with_mode(mode);

    // GaugeDesk keeps credential custody. The selected provider material is
    // resolved later into one exact-reference in-memory capability; the turn no
    // longer receives an ambient environment-shaped secret vector.
    let (whip_factory, actor, package_selection, selected_package_root) = {
        let g = wb.lock_unpoisoned();
        if g.package_selection_for_chat(id).is_some() {
            g.refresh_chat_discipline_mount(id)?;
        }
        let factory = g
            .whip_harness_factory()
            .map_err(|error| error.to_string())?;
        let package_selection = g.package_selection_for_chat(id);
        let selected_package_root = package_selection
            .as_ref()
            .and_then(|(version, _)| g.package_root_for_chat(id, *version));
        (
            factory,
            authenticated_actor
                .cloned()
                .unwrap_or_else(|| g.authority().clone()),
            package_selection,
            selected_package_root,
        )
    };

    let (package_root, package_version_ref) = match mode {
        ChatMode::Edit => (None, None),
        ChatMode::Use => package_selection
            .map(|(_, package_ref)| (selected_package_root, Some(package_ref)))
            .unwrap_or((None, None)),
    };

    // Persona is package content (ADR 0081), never host runtime configuration:
    // work chats select the placement's exact authored package; edit chats
    // select GaugeDesk's separate editor package.
    let system_prompt: Option<String> = match mode {
        ChatMode::Edit => Some(EDITOR_FRAMING.to_string()),
        ChatMode::Use => None,
    };

    stop_checkpoint(id)?;

    // The one harness decision point (SUB-0): which adapter drives this turn.
    // Consulted per turn — tests flip `GAUGEDESK_FAKE_AGENT` against a live
    // workbench, so the selection must never be cached at startup.
    let factory =
        harness_factory.unwrap_or_else(|| crate::harness_select::factory_for_turn(whip_factory));

    // Mock-LLM mode: no WhippleScript runtime, no model call. The scripted fake drives the
    // exact same turn loop (membrane + reducers unchanged); its pre-turn side
    // effects — the `[slow]` hold and the note append — run here, in the
    // blocking pool BEFORE any lock is taken (see `ScriptedFakeFactory::pre_turn`).
    let result = if factory.kind() == ScriptedFakeFactory::KIND {
        // The hold is the fake's whole duration and it runs before any harness
        // exists, so bind it as this turn's interrupt handle for as long as it
        // lasts. Without this the one moment a fake turn is interruptible is the
        // one moment Stop could not reach it.
        let hold = std::sync::Arc::new(crate::harness_select::SlowHold::default());
        let releases = std::sync::Arc::clone(&hold);
        // A real turn spends 124-222ms between its claim and its handle. The
        // fake binds in microseconds, so the window that actually bit a person
        // did not exist in the lane that gates every merge, and only the
        // opt-in live lane could fail on it. `[startup]` reproduces the shape
        // deliberately: the wait is before the bind, so a Stop pressed during
        // it has nothing to fire and must be honoured by a checkpoint.
        ScriptedFakeFactory::startup_window(task);
        stop_checkpoint(id)?;
        bind_turn_interrupt(id, std::sync::Arc::new(move || releases.stop()));
        // A real failure in here is still a failure; only the hold being cut
        // short is an interrupt.
        ScriptedFakeFactory::pre_turn(worktree, task, &hold)?;
        if hold.was_stopped() {
            return Err(EngineError::Interrupted);
        }
        // The fake ignores the runtime config; the spec carries the shell's
        // minimal base policy for the seam's sake. Provider resolution and the
        // fail-closed credential precheck are real-run policy, skipped here as
        // before.
        let spec = HarnessSpec {
            chat_id: id.to_string(),
            worktree: worktree.to_path_buf(),
            mode,
            package_root: package_root.clone(),
            package_version_ref: package_version_ref.clone(),
            policy_epoch: None,
            signed_policy_envelope: None,
            provider_binding_ref: None,
            credential_ref: None,
            placement_ceiling_ref: None,
            runtime_placement_id: None,
            provider: None,
            model: None,
            base_url: None,
            thinking: None,
            system_prompt,
            credential_capability: None,
            credentials: Vec::new(),
            sandbox: gaugedesk_harness::sandbox::SandboxPolicy::new(vec![worktree.to_path_buf()]),
            // The fake seam offers no people: this path never reaches a model, so
            // there is no tool schema for a roster to appear on.
            roster: Vec::new(),
        };
        drive_persistent_turn(
            wb,
            id,
            &gate,
            task,
            images,
            sender,
            factory.as_ref(),
            &spec,
            actor.as_str(),
            None,
            None,
            runtime_command_id,
        )?
    } else {
        // The private composition may override the authored provider/model. Public
        // releases do not execute through this GaugeDesk engine.
        let provider = resolve_turn_provider(
            gaugedesk_env::var("MODEL_PROVIDER"),
            config.provider.clone(),
        );
        let effective_execution_class = wb.lock_unpoisoned().model_execution_class();
        if provider == "openai-codex"
            && effective_execution_class == crate::account::ModelExecutionClass::LocalInteractive
        {
            if let Err(reason) = crate::codex_oauth::ensure_local_credential_record(wb) {
                let _ = sender.send(ServerEvent::Error {
                    reason: reason.clone(),
                    code: Some("credential_migration_failed".into()),
                });
                let mut workbench = wb.lock_unpoisoned();
                return record_precheck_failure(
                    &mut workbench.store,
                    id,
                    task,
                    reason,
                    "credential_migration_failed",
                );
            }
        }
        // The credential legs are the widest part of startup — two provider
        // round trips before anything interruptible exists.
        stop_checkpoint(id)?;
        let credential_ref = {
            let g = wb.lock_unpoisoned();
            g.credential_ref_for_chat_in_class(
                id,
                &provider,
                actor.as_str(),
                effective_execution_class,
            )
        };
        let credential_capability = if provider == "openai-codex" {
            match crate::codex_oauth::resolve_turn_credential(
                wb,
                actor.as_str(),
                effective_execution_class,
            ) {
                Ok(Some(credential)) => Some(crate::account::resolved_credential_capability(
                    credential_ref.clone(),
                    credential.access,
                    Some(credential.account_id),
                )),
                Ok(None) => None,
                Err(reason) => {
                    let _ = sender.send(ServerEvent::Error {
                        reason: reason.clone(),
                        code: Some("credential_refresh_failed".into()),
                    });
                    let mut workbench = wb.lock_unpoisoned();
                    return record_precheck_failure(
                        &mut workbench.store,
                        id,
                        task,
                        reason,
                        "credential_refresh_failed",
                    );
                }
            }
        } else {
            let g = wb.lock_unpoisoned();
            g.credential_capability_for_chat_in_class(
                id,
                &provider,
                actor.as_str(),
                effective_execution_class,
            )
        };
        stop_checkpoint(id)?;
        let model = resolve_turn_model(gaugedesk_env::var("MODEL"), config.model.clone());
        // openai-generic (ADR 0083) carries its endpoint with the linked credential;
        // resolve it nearest-scope-wins so the descriptor derives the admitted host
        // from the same base_url the request will use. Other providers ignore it.
        let base_url_override = if provider == "openai-generic" {
            let g = wb.lock_unpoisoned();
            g.credential_base_url_for_chat_in_class(
                id,
                &provider,
                actor.as_str(),
                effective_execution_class,
            )
        } else {
            None
        };
        let provider_descriptor = gaugedesk_whip_runtime::native_provider_descriptor(
            &provider,
            model.as_deref(),
            base_url_override.as_deref(),
        )
        .map_err(|error| error.to_string())?;
        // Fail closed (LLM-1, ADR 0062): refuse a real run when no model credential resolves for
        // the resolved provider. Record it as a durable, coded failure turn so the chat log
        // shows *why* with an actionable "open settings" affordance — not just a status line —
        // then return the same Failed shape an in-turn failure returns (never let the runtime fail opaquely).
        if let Err(reason) = llm_credential_status(
            &provider,
            credential_capability.as_deref(),
            factory.as_ref(),
        ) {
            let _ = sender.send(ServerEvent::Error {
                reason: reason.clone(),
                code: Some("no_credential".into()),
            });
            let mut g = wb.lock_unpoisoned();
            return record_precheck_failure(&mut g.store, id, task, reason, "no_credential");
        }
        let mut resolved_funding_ref = credential_ref.clone();
        let managed_billing_scope = if is_host_managed_provider(&provider) {
            let resolved = {
                let g = wb.lock_unpoisoned();
                crate::managed_inference::resolve_plan(g.store_ref(), account_scope, tenant_scope)
                    .map_err(|error| format!("{error:?}"))?
            };
            let Some((plan, scope)) = resolved else {
                let reason = "Managed inference needs an active account or organization plan. Open Account settings or ask a billing admin to choose a plan.".to_owned();
                let _ = sender.send(ServerEvent::Error {
                    reason: reason.clone(),
                    code: Some("managed_plan_required".into()),
                });
                let mut g = wb.lock_unpoisoned();
                return record_precheck_failure(
                    &mut g.store,
                    id,
                    task,
                    reason,
                    "managed_plan_required",
                );
            };
            if !plan.admits_future_run() {
                let reason = format!(
                    "Managed inference plan `{}` is {:?}; future model runs are suspended, while prior usage and history remain unchanged.",
                    plan.plan, plan.status
                );
                let _ = sender.send(ServerEvent::Error {
                    reason: reason.clone(),
                    code: Some("managed_plan_suspended".into()),
                });
                let mut g = wb.lock_unpoisoned();
                return record_precheck_failure(
                    &mut g.store,
                    id,
                    task,
                    reason,
                    "managed_plan_suspended",
                );
            }
            resolved_funding_ref = crate::managed_inference::funding_ref(&scope, &plan);
            Some(scope)
        } else {
            None
        };

        // Who this agent may name (`GATE-3f`), read while the workbench is in hand.
        // Offered on the `ask` tool so the choice of a person is made from a list;
        // the host still resolves the answer, because a roster can change between
        // here and the call arriving.
        let roster_for_spec: Vec<(String, String)> = wb
            .lock_unpoisoned()
            .roster()
            .into_iter()
            .map(|person| (person.authority, person.display))
            .collect();

        // GaugeDesk's workspace and egress policy for this turn (ADR 0030): the
        // worktree is writable, while use mode marks the method definition
        // read-only. WhippleScript resolves that policy into confined native
        // workspace capabilities, so writes outside the grant or into protected
        // subtrees fail before filesystem execution (INV-24).
        let sandbox_policy = {
            use gaugedesk_harness::sandbox::Network;
            let path_scope = wb
                .lock_unpoisoned()
                .library_chat_target_binding(id)
                .map(|binding| binding.path_scope)
                .ok_or_else(|| "chat target binding is unavailable".to_owned())?;
            let writable = target_writable_roots(worktree, &path_scope);
            // Network egress posture (RF-B3, CORE-5) is a **per-project** choice. A
            // non-isolated project reaches ONLY the model endpoints (Filtered, enforced
            // by the host-filtering egress proxy) **where the host can enforce that**;
            // where it can't, it keeps the accepted open-by-default posture (unfiltered
            // with a disclosed lower ceiling — the 2026-06-17 product decision) rather
            // than breaking model access. The model endpoint is named explicitly
            // (recorded + auditable; load-bearing under Filtered).
            // `GAUGEDESK_ALLOW_UNFILTERED_EGRESS=1` force-opens to UNFILTERED egress
            // regardless (the conscious opt-in, mirroring `GAUGEDESK_SANDBOX=0`); an
            // isolated project denies network entirely. A `Filtered` request the host
            // can't enforce is failed closed to `Deny` by the harness — never silently
            // to `Allow` — which is exactly why the engine only requests it when enforceable.
            // openai-generic's endpoint is user-configured (ADR 0083): admit ONLY the
            // host derived from the credential's base_url — the same host the request
            // resolves to — so the exact-match allowlist (RF-B3) stays load-bearing.
            let egress_hosts = if provider == "openai-generic" {
                vec![provider_descriptor.endpoint_host.clone()]
            } else {
                model_endpoint_hosts(Some(&provider))
            };
            let project_isolated = wb.lock_unpoisoned().chat_network_isolated(id);
            let forced_unfiltered =
                gaugedesk_env::var("ALLOW_UNFILTERED_EGRESS").as_deref() == Some("1");
            let posture = egress_posture(project_isolated, forced_unfiltered);
            match posture {
                Network::Deny => eprintln!(
                    "[gaugewright] NOTE: this project denies WhippleScript provider egress; \
                     the model endpoint ({}) is unreachable. Turn off isolation for \
                     the project to let the agent reach the model.",
                    egress_hosts.join(", ")
                ),
                Network::Filtered => eprintln!(
                    "[gaugewright] NOTE: WhippleScript provider egress is restricted to \
                     the admitted model endpoint ({}) and redirects fail closed.",
                    egress_hosts.join(", ")
                ),
                Network::Allow => eprintln!(
                    "[gaugewright] NOTE: project policy allows unfiltered egress \
                     (GAUGEDESK_ALLOW_UNFILTERED_EGRESS=1); the current WhippleScript \
                     package still exposes only its governed provider endpoint ({}).",
                    egress_hosts.join(", ")
                ),
            }
            let base = gaugedesk_harness::sandbox::SandboxPolicy::new(writable)
                .read_only(method_surface_readonly_roots(worktree, mode));
            match posture {
                // Filtered: the allowlist is load-bearing (enforced by the proxy).
                Network::Filtered => base.filter_egress(egress_hosts),
                // Unfiltered opt-in: record the intended targets, then open wide.
                Network::Allow => base.allow_hosts(egress_hosts).allow_unfiltered_egress(true),
                // Isolated: record intent for audit; posture stays Deny.
                Network::Deny => base.allow_hosts(egress_hosts),
            }
        };
        let package_capabilities: BTreeSet<String> = match mode {
            ChatMode::Use => {
                let root = package_root.as_deref().ok_or_else(|| {
                    "a work chat has no selected WhippleScript package root".to_owned()
                })?;
                gaugedesk_whip_runtime::AuthoredAgentPackage::load(root)
                    .map_err(|error| error.to_string())?
                    .capabilities()
                    .iter()
                    .cloned()
                    .collect()
            }
            ChatMode::Edit => gaugedesk_whip_runtime::editor_package_capabilities()
                .map_err(|error| error.to_string())?,
        };
        let runtime_placement_id;
        let policy_epoch = {
            let mut g = wb.lock_unpoisoned();
            runtime_placement_id = g.library_placement_of_chat(id);
            let project_id = g.library_project_of_chat(id);
            let turn_purpose = g.library_chat_run_purpose(id);
            let granted = crate::resource_store::granted_context(&g.store, id)
                .map_err(|error| format!("{error:?}"))?
                .into_iter()
                .collect::<BTreeSet<_>>();
            let mut resources =
                crate::resource_store::list(&g.store, id).map_err(|error| format!("{error:?}"))?;
            resources.retain(|record| granted.contains(&record.resource.id));
            let org = crate::org::Org::rebuild_in(g.store_ref(), tenant_scope)
                .map_err(|error| format!("{error:?}"))?;
            // The operator's auto-keep scopes (ATTN-3) become an envelope
            // guarantee declaration the runtime evaluates per turn (ADR 0082
            // §5). A scope change re-canonicalizes the policy → new epoch.
            // (Read before the mutable compile call below.)
            let advancement_scopes = crate::advancement::AdvancementRules::parse(
                g.account_settings()
                    .ok()
                    .and_then(|s| {
                        s.get(crate::advancement::ADVANCEMENT_RULES_SETTING)
                            .cloned()
                    })
                    .as_deref(),
            )
            .declared_scopes();
            let actor_attributes = g.idp.as_ref().map_or_else(
                || gaugedesk_core::abac::AuthorityAttributes {
                    clearance: gaugedesk_core::abac::Clearance(3),
                    roles: BTreeSet::from([gaugedesk_core::abac::Role::owner()]),
                    region: org
                        .security
                        .as_ref()
                        .and_then(|security| security.residency_region.as_deref())
                        .or_else(|| {
                            org.org
                                .as_ref()
                                .and_then(|record| record.default_region.as_deref())
                        })
                        .map(gaugedesk_core::abac::Region::new),
                    ..gaugedesk_core::abac::AuthorityAttributes::default()
                },
                // The directory supplies the role the IdP does not carry (RBAC-5).
                |idp| org.with_directory_role(idp.claims(&actor), actor.as_str()),
            );
            g.compile_whipple_policy(PolicyCompilationInput {
                chat_id: id.to_owned(),
                project_id,
                actor: actor.as_str().to_owned(),
                actor_attributes,
                org_policy: org.policy(),
                turn_purpose,
                package_capabilities,
                provider: provider.clone(),
                model: provider_descriptor.model.clone(),
                base_url: provider_descriptor.base_url.clone(),
                credential_ref,
                placement_kind: if factory.kind() == "whip-do" {
                    "do".to_owned()
                } else {
                    "local".to_owned()
                },
                command_network: sandbox_policy.network
                    != gaugedesk_harness::sandbox::Network::Deny,
                resources,
                advancement_scopes,
            })?
        };
        let spec = HarnessSpec {
            chat_id: id.to_string(),
            worktree: worktree.to_path_buf(),
            mode,
            package_root,
            package_version_ref,
            policy_epoch: Some(policy_epoch.epoch),
            signed_policy_envelope: Some(policy_epoch.signed_envelope),
            provider_binding_ref: Some(policy_epoch.provider_binding_ref),
            credential_ref: Some(policy_epoch.credential_ref),
            placement_ceiling_ref: Some(policy_epoch.placement_ceiling_ref),
            runtime_placement_id,
            // Pin the codex endpoint by default (the authed OAuth provider) so a bare
            // model name can't silently resolve to an unauthenticated provider. Resolved
            // once above for the fail-closed credential check.
            provider: Some(provider),
            model: Some(provider_descriptor.model),
            // openai-generic's configured endpoint (ADR 0083); None for fixed-host
            // providers, which resolve their compile-time endpoint in the runtime.
            base_url: base_url_override,
            // Per-chat reasoning effort (LLM-1, ADR 0062): unset → the provider default.
            thinking: config.thinking.clone(),
            // Only the editor package receives host-supplied editor framing.
            // Work-chat persona is immutable authored package content.
            system_prompt,
            credential_capability,
            // A linked provider account (ACCT-1), if any — resolved above,
            // nearest-scope-wins (LLM-2, ADR 0062).
            credentials: Vec::new(),
            sandbox: sandbox_policy,
            // Who this turn's agent may name (`GATE-3f`). Read here, where the
            // workbench is in hand, rather than inside the turn: resolving a person
            // needs the directory, and the turn deliberately holds no lock.
            roster: roster_for_spec,
        };
        let outcome = drive_persistent_turn(
            wb,
            id,
            &gate,
            task,
            images,
            sender,
            factory.as_ref(),
            &spec,
            actor.as_str(),
            managed_billing_scope.as_deref(),
            managed_billing_scope
                .as_ref()
                .map(|_| resolved_funding_ref.as_str()),
            runtime_command_id,
        );
        // A real harness reports a turn Stop cut short as its stream dying —
        // either an `io` error or a `Failed` phase — and neither says who ended
        // it. The claim does: it recorded the interrupt landing. Without asking
        // it, the `Interrupted` leg (and so the `499` this whole path exists for)
        // would be reachable only by the scripted fake, and every production Stop
        // would still surface as a failed delivery whose message the composer
        // keeps for a retry nobody asked for.
        match outcome {
            Err(error) if turn_was_stopped(id) => {
                tracing::debug!(chat = %id, %error, "turn ended by Stop");
                return Err(EngineError::Interrupted);
            }
            Ok(result) if result.run_phase == RunPhase::Failed && turn_was_stopped(id) => {
                return Err(EngineError::Interrupted);
            }
            // A turn that ran to a *successful* end despite a Stop is the one
            // residual failure of this whole path: every mechanism that should
            // have ended it — the checkpoints, the bind, the runtime's own
            // cancellation — was passed and none took. Its work is durable, so
            // it is reported as what it is rather than dressed as a stop; but
            // it is a broken promise and it says so here.
            Ok(result) if turn_was_stopped(id) => {
                tracing::warn!(
                    chat = %id,
                    phase = ?result.run_phase,
                    "a stopped turn ran to completion anyway",
                );
                result
            }
            other => other?,
        }
    };

    // A completed candidate is a `propose` act, independent from any later
    // apply/publish/release authority. Record its exact basis, candidate cut,
    // and certified checks before an auto-advance policy can settle it.
    {
        let mut g = wb.lock_unpoisoned();
        if let Some(binding) = g.library_chat_target_binding(id) {
            let checks = result
                .guarantee_outcomes
                .iter()
                .map(|check| format!("{}={}", check.name, check.outcome))
                .collect();
            g.record_target_act(
                Some(id),
                &binding.target_id,
                crate::target_adapter::TargetActKind::Propose,
                result.commit.clone(),
                checks,
                None,
                crate::target_adapter::TargetActStatus::Completed,
                None,
            )?;
        }
    }

    // Every chat targets one shared line: implicit Main or a named workstream. A clean
    // completion greedily advances that target and reconciles its siblings; named lines
    // additionally record membership attribution. There is no per-change hold —
    // work is held by line, not by change (ADR 0136).
    greedy_autosync(wb, id, sender, contribution_by);

    // Legacy advancement rules are evaluated only if a future/older path leaves a
    // clean candidate behind. The shared-line path above normally settles every
    // clean turn.
    auto_advance_turn(wb, id, sender, &result.guarantee_outcomes);

    let _ = sender.send(ServerEvent::Admitted {
        kind: "run".into(),
        text: format!("run → {:?}", result.run_phase),
    });
    Ok(result)
}

/// The greedy auto-sync hop (`WS-D`). When the just-finished turn's chat is a member of
/// a workstream (its worktree targets `workstream/<id>/main`, not `main`) **and** its
/// merge probe came back Clean, this:
///   1. admits the membership-gated `Contribute` on the workstream scope (attribution +
///      the gate: a non-member or archived stream is rejected, and we bail);
///   2. auto-admits the clean merge into the stream main (PolicyAdmit → real merge →
///      AdvanceStandingRef) — the auto-admit-in-stream policy that makes it feel
///      automatic while every advance stays an admitted event (`INV-2`/`INV-4`);
///   3. has every sibling member of the same stream `sync_from_main`, picking the work up.
///
/// A conflict at any step leaves that contribution isolated for the existing merge repair
/// flow — the shared ref only ever advances on a clean merge.
fn greedy_autosync(
    wb: &SharedWorkbench,
    id: &str,
    sender: &broadcast::Sender<ServerEvent>,
    contribution_by: Option<&str>,
) {
    let mut g = wb.lock_unpoisoned();
    g.greedy_autosync(id, sender, contribution_by);
}

/// The settle-time auto-advance (ADR 0082 §4): a settled turn on a **mainline**
/// chat auto-admits and advances its Clean merge when either
///
/// 1. **the shipped no-op rule** (ATTN-1) applies — the diff names no file at
///    all, so the keep would gate nothing (strictly empty only: an
///    internal-only dotfile diff still holds, `.agent-config.json` is where a
///    policy loosening lives); or
/// 2. **an operator advancement rule** (ATTN-3, `advancement.rs`) covers it —
///    fail-closed, with unwaivable config-touch and external-read guards.
///
/// Every advance stays admitted events (`INV-2`/`INV-4`) plus a transcript
/// citation saying *why* no human gated it. Mainline chats only: a workstream
/// member's clean turn is `greedy_autosync`'s job; advancing it here would
/// bypass the membership `Contribute` gate (WS-G).
fn auto_advance_turn(
    wb: &SharedWorkbench,
    id: &str,
    sender: &broadcast::Sender<ServerEvent>,
    guarantee_outcomes: &[gaugedesk_harness::GuaranteeOutcome],
) {
    let mut g = wb.lock_unpoisoned();
    g.auto_advance_turn(id, sender, guarantee_outcomes);
}

/// Whether a unified diff names no file — mirrors the web client's `diffHasFiles`
/// (changed-files.ts), so "nothing to review" means the same thing on both sides.
fn diff_names_no_files(diff: &str) -> bool {
    !diff.lines().any(|line| line.starts_with("diff --git "))
}

impl Workbench {
    // Membership is encoded in the worktree target. Main is the implicit shared line;
    // named lines additionally need the workstream reducer's contribution admission.
    fn greedy_autosync(
        &mut self,
        id: &str,
        sender: &broadcast::Sender<ServerEvent>,
        contribution_by: Option<&str>,
    ) {
        use gaugedesk_core::workstream::{WorkstreamCommand, WorkstreamState};
        if !self
            .library_chat_target_binding(id)
            .and_then(|binding| self.library.work_targets.get(&binding.target_id))
            .is_some_and(|target| target.kind == crate::library::WorkTargetKind::Managed)
        {
            return;
        }
        let Some(target) = self.engagements.get(id).map(|e| e.target().to_string()) else {
            return;
        };
        // The owning workspace impl parses the ref token — the engine holds no
        // ref-format knowledge (W7).
        let ws_id = self
            .engagement_index
            .get(id)
            .and_then(|iid| self.targets.get(iid))
            .and_then(|inst| inst.workstream_id_of(&target));
        let store = &mut self.store;
        let engagements = &mut self.engagements;

        // Only a clean turn advances the stream; a conflict stays isolated (the merge
        // reducer already moved it to Rejected/Repairing) for repair.
        if store
            .fold::<MergeState>(id)
            .map(|m| m.phase != MergePhase::Clean)
            .unwrap_or(true)
        {
            return;
        }
        if let Some(ref ws_id) = ws_id {
            // Named-line membership + attribution. Main is implicit and therefore has
            // no duplicate membership record to admit.
            let by = contribution_by
                .filter(|authority| !authority.trim().is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    gaugedesk_core::determine_scope_authority(id)
                        .as_str()
                        .to_string()
                });
            if store
                .admit::<WorkstreamState>(
                    ws_id,
                    WorkstreamCommand::Contribute {
                        chat: id.to_string(),
                        by,
                    },
                )
                .is_err()
            {
                return;
            }
        }
        // Auto-admit the clean merge into the stream main.
        if store
            .admit::<MergeState>(id, MergeCommand::PolicyAdmit)
            .is_err()
        {
            return;
        }
        match engagements.get(id).map(|e| e.merge_into_main()) {
            Some(Ok(MergeOutcome::Clean)) => {
                let _ = store.admit::<MergeState>(id, MergeCommand::AdvanceStandingRef);
            }
            Some(Ok(MergeOutcome::Conflict)) => {
                // The line advanced after the clean probe. Make that race a first-class
                // incoming conflict with this chat as repair owner; never strand it as
                // a policy-admitted Clean candidate.
                let _ = store.admit::<MergeState>(id, MergeCommand::StartMerge);
                let _ = store.admit::<MergeState>(id, MergeCommand::WorkspaceConflict);
                return;
            }
            Some(Err(_)) | None => return,
        }
        record_transcript(
            store,
            id,
            &ServerEvent::Admitted {
                kind: "merge".into(),
                text: if ws_id.is_some() {
                    "synced into the workstream"
                } else {
                    "synced into Main"
                }
                .into(),
            },
        );
        let _ = sender.send(ServerEvent::Admitted {
            kind: "merge".into(),
            text: if ws_id.is_some() {
                "synced into the workstream"
            } else {
                "synced into Main"
            }
            .into(),
        });

        // Sibling auto-pull: every other member of the same stream picks the work up. A
        // sibling conflict aborts cleanly (its worktree is unchanged) and surfaces on its
        // next interaction — the shared ref is unaffected.
        let siblings: Vec<String> = engagements
            .iter()
            .filter(|(cid, e)| cid.as_str() != id && e.target() == target)
            .map(|(cid, _)| cid.clone())
            .collect();
        for sib in siblings {
            if let Some(se) = engagements.get(&sib) {
                let _ = se.sync_from_main();
            }
        }
        self.record_completed_target_apply(id);
    }

    // Legacy mainline-only advancement rules remain a no-op after the shared-line
    // auto-sync path above has advanced a clean candidate.
    fn auto_advance_turn(
        &mut self,
        id: &str,
        sender: &broadcast::Sender<ServerEvent>,
        guarantee_outcomes: &[gaugedesk_harness::GuaranteeOutcome],
    ) {
        if !self
            .library_chat_target_binding(id)
            .and_then(|binding| self.library.work_targets.get(&binding.target_id))
            .is_some_and(|target| target.kind == crate::library::WorkTargetKind::Managed)
        {
            return;
        }
        let Some(target) = self.engagements.get(id).map(|e| e.target().to_string()) else {
            return;
        };
        // A workstream member is greedy_autosync's job — never advanced from here.
        let is_member = self
            .engagement_index
            .get(id)
            .and_then(|iid| self.targets.get(iid))
            .and_then(|inst| inst.workstream_id_of(&target))
            .is_some();
        if is_member {
            return;
        }
        if self
            .store
            .fold::<MergeState>(id)
            .map(|m| m.phase != MergePhase::Clean)
            .unwrap_or(true)
        {
            return;
        }
        let Some(diff) = self
            .engagements
            .get(id)
            .and_then(|e| e.diff_against_main().ok())
        else {
            return; // unreadable diff → hold (fail-closed)
        };
        let (citation, noop) = if diff_names_no_files(&diff) {
            // ATTN-1, the shipped no-op rule: any named file — internal
            // dotfiles included — falls through to the operator rules below.
            (
                "the turn changed no files (no-op rule, ADR 0082)".to_string(),
                true,
            )
        } else {
            // ATTN-3, the operator's advancement rules: fail-closed. Facts are
            // GaugeDesk-owned workspace truth (write side) + the engagement's
            // certified read-set stakeholders (read side); a fact that can't
            // be resolved holds rather than advances.
            let rules = crate::advancement::AdvancementRules::parse(
                self.account_settings()
                    .ok()
                    .and_then(|s| {
                        s.get(crate::advancement::ADVANCEMENT_RULES_SETTING)
                            .cloned()
                    })
                    .as_deref(),
            );
            if rules.is_empty() {
                return;
            }
            let owner = gaugedesk_core::determine_scope_authority(id);
            let external =
                crate::resource_store::external_read_stakeholders(&self.store, id, owner.as_str())
                    .unwrap_or_else(|_| vec!["<unresolved>".to_string()]);
            let facts = crate::advancement::TurnFacts {
                changed_paths: crate::advancement::TurnFacts::changed_paths_of(&diff),
                external_read_stakeholders: external,
            };
            // The unwaivable guards apply before EITHER decision path — a
            // certified write guarantee does not certify these axes.
            if facts.violates_safety().is_some() {
                return;
            }
            // Certified-first (ADR 0082 §5): a held operator guarantee advances
            // on the runtime's certificate; a certified violation holds hard,
            // never consulting local truth against it; unwitnessed falls back
            // to the local-truth coverage check.
            let citation = match rules.decide_from_guarantees(guarantee_outcomes) {
                crate::advancement::GuaranteeVerdict::AdvanceHeld(citation) => {
                    format!("{citation} (ADR 0082)")
                }
                crate::advancement::GuaranteeVerdict::HoldViolated(_) => return,
                crate::advancement::GuaranteeVerdict::Unwitnessed => match rules.decide(&facts) {
                    Some(citation) => format!("{citation} (ADR 0082)"),
                    None => return,
                },
            };
            (citation, false)
        };
        let store = &mut self.store;
        let engagements = &self.engagements;
        if store
            .admit::<MergeState>(id, MergeCommand::PolicyAdmit)
            .is_err()
        {
            return;
        }
        match engagements.get(id).map(|e| e.merge_into_main()) {
            Some(Ok(MergeOutcome::Clean)) => {
                let _ = store.admit::<MergeState>(id, MergeCommand::AdvanceStandingRef);
            }
            // Raced with another writer — leave it Clean for the review surface.
            _ => return,
        }
        // ADR 0082 §4: every auto-advance is admitted as durable evidence
        // citing the rule it matched. That WHY is governance audit, not
        // conversation — it lands on the engagement's audit record
        // (`GET /chats/:id/audit`), never in the user's transcript. The user
        // surface stays silent for a no-op turn (nothing they can see moved)
        // and says it in plain words when real changes advanced.
        let _ = store.append_record(
            id,
            "audit",
            &serde_json::json!({ "kind": "auto_advance", "citation": citation }).to_string(),
        );
        if !noop {
            let advanced = ServerEvent::Admitted {
                kind: "merge".into(),
                text: "merged to main automatically".to_string(),
            };
            record_transcript(store, id, &advanced);
            let _ = sender.send(advanced);
        }
        self.record_completed_target_apply(id);
    }
}

/// The sink that fans a turn's observations onto the live `sender` (skipping
/// internal lifecycle progress).
fn live_sink(sender: &broadcast::Sender<ServerEvent>) -> impl FnMut(&Observation) + '_ {
    move |obs: &Observation| {
        if obs.kind == "progress" {
            return;
        }
        let _ = sender.send(ServerEvent::from_observation(obs));
    }
}

/// Drive one turn over the engagement's session, constructed by `factory` from
/// `spec`. A caching adapter's harness ([`HarnessFactory::reuse_across_turns`])
/// is **persistent** — created on the first turn and reused thereafter, so
/// the conversation thread carries context across turns; a turn
/// that errors retires the (likely dead) harness so the next turn recreates a
/// fresh thread. A non-caching adapter (the scripted fake) gets a fresh harness
/// every turn.
///
/// **The turn does not hold the workbench lock.** It checks out its three
/// resources under a brief lock — its own store connection, an owned copy of the
/// chat workspace, and the chat's independently-locked harness — and then runs
/// holding none of the workbench. Holding it across a model call serialized every
/// other chat behind this one, which is the opposite of what a multi-agent
/// workbench is for. Per-scope serialization is the store's own job (immediate
/// transactions + WAL + `busy_timeout`), not a process-wide lock's.
#[allow(clippy::too_many_arguments)]
fn drive_persistent_turn(
    wb: &SharedWorkbench,
    id: &str,
    gate: &MembraneGate,
    task: &str,
    images: &[ImageContent],
    sender: &broadcast::Sender<ServerEvent>,
    factory: &dyn HarnessFactory,
    spec: &HarnessSpec,
    actor_ref: &str,
    managed_billing_scope: Option<&str>,
    managed_funding_ref: Option<&str>,
    runtime_command_id: Option<&str>,
) -> Result<TaskResult, EngineError> {
    // 1. Check out this turn's resources under a brief lock, then drop it.
    let (mut store, engagement, harness, persistent, answers) = {
        let mut g = wb.lock_unpoisoned();
        let engagement = g
            .engagements
            .get(id)
            .ok_or_else(|| "engagement gone".to_string())?
            .boxed_clone();
        let store = g
            .store
            .sibling()
            .map_err(|e| format!("open a turn store connection: {e}"))?;
        // A non-caching adapter never enters the session map: a fresh harness
        // per turn (the scripted fake's one-shot transport — caching it would
        // fail turn 2 with "stream ended"), dropped when the turn ends.
        let persistent = factory.reuse_across_turns();
        let harness = if persistent {
            match g.sessions.get(id) {
                Some(existing) => Arc::clone(existing),
                None => {
                    let harness = factory
                        .create(spec)
                        .map_err(|e| format!("spawn {}: {e}", factory.kind()))?;
                    let harness: SharedHarness = Arc::new(Mutex::new(harness));
                    g.sessions.insert(id.to_string(), Arc::clone(&harness));
                    harness
                }
            }
        } else {
            let harness = factory
                .create(spec)
                .map_err(|e| format!("spawn {}: {e}", factory.kind()))?;
            Arc::new(Mutex::new(harness))
        };
        // Answers that arrived since this chat's last turn ride this turn's prompt
        // (ADR 0113 §1). Taken under the same brief lock, and marked delivered as
        // they are taken, so the agent is told each answer exactly once.
        let answers = crate::agent_question::answers_context(&g.take_undelivered_answers(id));
        (store, engagement, harness, persistent, answers)
    };

    // 2. Run the turn holding only this chat's harness. A second turn on the same
    //    chat waits here; a turn on any *other* chat is unaffected.
    let result = {
        let mut guard = harness.lock_unpoisoned();
        let harness: &mut dyn Harness = guard.as_mut();
        // Refresh on every request: a persistent chat may be answered by a
        // different authenticated member than the one who created its harness.
        harness.bind_authenticated_actor(actor_ref);
        harness.bind_runtime_command_id(runtime_command_id);
        // Publish this turn's interrupt handle so a concurrent Stop can terminate it
        // out-of-band (unblocking `recv`). A harness with nothing to interrupt binds
        // nothing — the claim taken in `run_engagement_turn` is what records that a
        // turn is live, so an uninterruptible one is still visible (ADR 0138 §6).
        if let Some(interrupt) = harness.interrupt_handle() {
            bind_turn_interrupt(id, interrupt);
        }
        // The last checkpoint, and the only one past the bind: a turn stopped
        // while it waited for another turn's harness lock must not now go and
        // call a model. Past this line the handle carries it.
        stop_checkpoint(id)?;
        let mut sink = live_sink(sender);
        let result = run_task_streaming_billed(
            &mut store,
            engagement.as_ref(),
            id,
            harness,
            gate,
            task,
            images,
            &mut sink,
            managed_billing_scope,
            managed_funding_ref,
            &answers,
        );
        // The claim is released by its guard when the turn returns, not here: the
        // bookkeeping below is still part of this turn, and freeing the chat before
        // it finished would let the next turn in mid-way through.
        result
    };

    // 3. Re-take the lock for the bookkeeping that genuinely needs the workbench.
    let mut g = wb.lock_unpoisoned();

    // A turn that errored (or was Stop-killed: its `recv` hit EOF and reported a
    // stream error) retires the now-dead process so the next turn respawns. A
    // Stop-killed turn reports `outcome.error`, so retire that too.
    let stream_died = result
        .as_ref()
        .map(|r| r.run_phase == RunPhase::Failed)
        .unwrap_or(true);
    if persistent && stream_died {
        if let Some(dead) = g.sessions.remove(id) {
            drop(harness);
            crate::workbench_state::shutdown_shared_harness(dead);
        }
    }

    // File any question the agent asked (ADR 0113). Here rather than inside the
    // turn because resolving a recipient needs the roster.
    if let Ok(settled) = &result {
        for asked in &settled.asked_questions {
            if let Err(error) = g.ask_question(
                id,
                &asked.question,
                &asked.choices,
                asked.to.as_deref(),
                asked.blocking,
            ) {
                // A question that could not be filed must not fail the turn that
                // asked it; the agent sees the refusal on its next turn instead.
                tracing::warn!(error = %error, chat = %id, "could not file agent question");
            }
        }
    }
    // Advance the onboarding checklist on a completed turn (ADR 0075 Phase 2).
    // Idempotent: once the "first_turn" item is closed, later turns match nothing.
    // Best-effort, under the lock we already hold; never affects the turn result.
    if matches!(&result, Ok(r) if r.run_phase == RunPhase::Completed) {
        g.advance_onboarding("first_turn", &serde_json::json!({ "chat": id }).to_string());
    }
    result
}

/// Drive one turn over an engagement's **remote** session — a runtime placed in a
/// different trust authority and held in the workbench's `remote_sessions` map
/// alongside the local ones (`WORKBENCH-REMOTE-1`). This is the workbench-level
/// sibling of [`drive_persistent_turn`]: it pulls the registered
/// [`RemoteHarness`](gaugedesk_harness::RemoteHarness) for `id` and routes the turn
/// through [`run_task_remote`] (`ENGINE-REMOTE-1`), so the remote outcome becomes
/// run truth only via the owner's federated admission (`INV-4`). The remote path
/// has no local worktree, so there is no commit/diff/merge to surface.
pub fn drive_remote_turn(
    wb: &SharedWorkbench,
    id: &str,
    gate: &dyn EgressGate,
    task: &str,
) -> Result<RemoteTaskResult, String> {
    let mut g = wb.lock_unpoisoned();
    g.drive_registered_remote_turn(id, gate, task)
}

impl Workbench {
    fn drive_registered_remote_turn(
        &mut self,
        id: &str,
        gate: &dyn EgressGate,
        task: &str,
    ) -> Result<RemoteTaskResult, String> {
        let store = &mut self.store;
        let remote_sessions = &mut self.remote_sessions;
        let harness = remote_sessions
            .get_mut(id)
            .ok_or_else(|| format!("no remote session for {id}"))?;
        run_task_remote(store, id, harness.as_mut(), gate, task).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fake_agent_env;
    use gaugedesk_pi_bridge::{run_rpc_turn, RpcTransport, ScriptedTransport};
    use gaugedesk_workspace::Instance;
    use std::collections::VecDeque;
    use std::io;

    #[derive(Debug)]
    struct PresentCredential;

    struct PositionedHarness {
        worktree: std::path::PathBuf,
    }

    struct SummaryHarness {
        worktree: std::path::PathBuf,
        resource_handle: String,
    }

    impl gaugedesk_harness::Harness for PositionedHarness {
        fn run_turn(
            &mut self,
            _gate: &dyn gaugedesk_harness::EgressGate,
            _prompt: &str,
            _images: &[gaugedesk_harness::ImageContent],
            _sink: &mut dyn FnMut(&gaugedesk_harness::Observation),
        ) -> io::Result<TurnOutcome> {
            std::fs::write(self.worktree.join("point.txt"), "after").unwrap();
            Ok(TurnOutcome {
                assistant_text: "done".into(),
                runtime_start_position: Some(gaugedesk_harness::RuntimePosition {
                    instance_ref: "whip:source".into(),
                    sequence: 4,
                }),
                runtime_terminal_position: Some(gaugedesk_harness::RuntimePosition {
                    instance_ref: "whip:source".into(),
                    sequence: 9,
                }),
                ..TurnOutcome::default()
            })
        }
    }

    impl gaugedesk_harness::Harness for SummaryHarness {
        fn run_turn(
            &mut self,
            _gate: &dyn gaugedesk_harness::EgressGate,
            _prompt: &str,
            _images: &[gaugedesk_harness::ImageContent],
            _sink: &mut dyn FnMut(&gaugedesk_harness::Observation),
        ) -> io::Result<TurnOutcome> {
            std::fs::write(
                self.worktree.join(".agent-config.json"),
                r#"{"allow_tools":["bash"]}"#,
            )
            .unwrap();
            Ok(TurnOutcome {
                assistant_text: "configured".into(),
                output_flow_signature: vec![gaugedesk_harness::OutputFieldFlow {
                    field: "assistant_text".into(),
                    read_handles: vec![format!("resource:{}", self.resource_handle)],
                }],
                ..TurnOutcome::default()
            })
        }
    }

    #[test]
    fn settle_admits_diff_policy_and_certified_read_facts_once() {
        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let eng = inst.create_engagement("summary-chat").unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let resource = crate::resource_store::mint_context(
            &mut store,
            "summary-chat",
            "context-owner",
            "/context",
            "base",
        )
        .unwrap();
        let mut harness = SummaryHarness {
            worktree: eng.path().to_path_buf(),
            resource_handle: resource.resource.id.as_str().to_string(),
        };

        run_task(
            &mut store,
            "summary-chat",
            &eng,
            &mut harness,
            &gaugedesk_harness::AllowAllGate,
            "configure it",
            &[],
        )
        .unwrap();

        let summaries = store
            .records("summary-chat", crate::turn_summary::TURN_SUMMARY_KIND)
            .unwrap();
        assert_eq!(summaries.len(), 1, "one summary per settled attempt");
        let summary: crate::turn_summary::TurnSummary =
            serde_json::from_str(&summaries[0]).unwrap();
        assert_eq!(
            summary.receipt_status,
            crate::turn_summary::ReceiptStatus::Completed
        );
        assert_eq!(summary.changed_paths, vec![".agent-config.json"]);
        assert_eq!(summary.changed_count, 1);
        assert_eq!(
            summary.policy_diff_direction,
            crate::turn_summary::PolicyDiffDirection::Loosens
        );
        assert_eq!(summary.certified_reads.len(), 1);
        assert_eq!(
            summary.certified_reads[0].stakeholders,
            vec!["context-owner"]
        );
    }

    #[test]
    fn completed_turn_records_exact_point_fork_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let eng = inst.create_engagement("chat-1").unwrap();
        let mut harness = PositionedHarness {
            worktree: eng.path().to_path_buf(),
        };
        let mut store = Store::open_in_memory().unwrap();
        run_task(
            &mut store,
            "chat-1",
            &eng,
            &mut harness,
            &gaugedesk_harness::AllowAllGate,
            "change it",
            &[],
        )
        .unwrap();

        let boundary: TurnBoundaryRecord =
            serde_json::from_str(&store.records("chat-1", TURN_BOUNDARY_KIND).unwrap()[0]).unwrap();
        assert_ne!(boundary.before_workspace_cut, boundary.after_workspace_cut);
        assert_eq!(boundary.runtime_before.sequence, 4);
        assert_eq!(boundary.runtime_after.sequence, 9);
        let transcript_positions = store
            .events("chat-1")
            .unwrap()
            .into_iter()
            .filter(|(_, kind, _)| kind == "transcript")
            .map(|(position, _, _)| position)
            .collect::<Vec<_>>();
        assert!(transcript_positions.contains(&boundary.user_entry_id));
        assert!(transcript_positions.contains(&boundary.assistant_entry_id));
    }

    impl gaugedesk_harness::CredentialCapability for PresentCredential {
        fn credential_ref(&self) -> &str {
            "credential:test"
        }

        fn resolve(
            &self,
            credential_ref: &str,
        ) -> io::Result<gaugedesk_harness::CredentialMaterial> {
            if credential_ref != self.credential_ref() {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "wrong ref"));
            }
            Ok(gaugedesk_harness::CredentialMaterial::new("secret", None))
        }
    }

    #[test]
    fn runtime_evidence_crossing_is_pointer_only_position_paired_and_idempotent() {
        let mut store = Store::open_in_memory().unwrap();
        let pointer = r#"{"pointer_kind":"event","pointer":{"position":{"instance_ref":"whip:1","sequence":7},"evidence_ref":"whip:evidence:7"}}"#.to_owned();
        let first = admit_runtime_evidence_pointers(
            &mut store,
            "chat-1",
            std::slice::from_ref(&pointer),
            Some("whipple-cut-1"),
        )
        .unwrap();
        let replay = admit_runtime_evidence_pointers(
            &mut store,
            "chat-1",
            std::slice::from_ref(&pointer),
            Some("whipple-cut-1"),
        )
        .unwrap();
        assert_eq!(first, replay);
        let rows = store
            .records("chat-1", RUNTIME_EVIDENCE_POINTER_KIND)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].contains("whip:evidence:7"));
        assert!(rows[0].contains("whipple-cut-1"));
        assert!(!rows[0].contains("evidence_body"));
    }

    // Fail-closed credential check (LLM-1, ADR 0062): a BYOK provider needs its
    // reference-bound capability; absent ⇒ an actionable refusal, never a silent run.
    // The BYOK leg is shell policy — the factory is never consulted for it.
    #[test]
    fn byok_provider_requires_its_linked_key() {
        let pi = gaugedesk_pi_bridge::PiHarnessFactory;
        let capability = PresentCredential;
        assert!(llm_credential_status("openai", Some(&capability), &pi).is_ok());
        // nothing linked ⇒ refused with an actionable message
        let err = llm_credential_status("anthropic", None, &pi).unwrap_err();
        assert!(err.contains("anthropic"), "names the provider: {err}");
        assert!(
            err.to_lowercase().contains("account settings"),
            "points to the fix: {err}"
        );
    }

    // A managed-Home provider's fail-closed check trusts only a neutral
    // readiness signal from the private host, keeping
    // provider-specific secret names out of the open engine.
    #[test]
    fn host_managed_provider_requires_host_readiness() {
        use std::collections::HashMap;
        let env = |pairs: &[(&str, &str)]| {
            let m: HashMap<String, String> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            move |k: &str| m.get(k).cloned()
        };

        let ready = env(&[("GAUGEDESK_HOST_MODEL_READY", "1")]);
        assert!(host_managed_model_status("cloudflare-ai-gateway", &ready).is_ok());

        let not_ready = env(&[]);
        let err = host_managed_model_status("cloudflare-ai-gateway", &not_ready).unwrap_err();
        assert!(
            err.contains("GAUGEDESK_HOST_MODEL_READY"),
            "names the readiness flag: {err}"
        );

        let false_value = env(&[("GAUGEDESK_HOST_MODEL_READY", "0")]);
        assert!(host_managed_model_status("cloudflare-workers-ai", &false_value).is_err());
    }

    // A SERVE-2 deployment host forces every turn's provider/model (so a method authored with
    // `openai-codex` still egresses via the gateway); absent the override the chat's config wins.
    #[test]
    fn host_override_wins_then_config_then_default() {
        // Host override beats everything (the SERVE-2 membrane).
        assert_eq!(
            resolve_turn_provider(
                Some("cloudflare-ai-gateway".into()),
                Some("anthropic".into())
            ),
            "cloudflare-ai-gateway"
        );
        // No override ⇒ the chat's configured provider.
        assert_eq!(
            resolve_turn_provider(None, Some("anthropic".into())),
            "anthropic"
        );
        // Neither ⇒ the codex OAuth default. An empty override/config is ignored, not honored.
        assert_eq!(
            resolve_turn_provider(Some(String::new()), None),
            "openai-codex"
        );
        // Model: override wins, else config, else None (provider default).
        assert_eq!(
            resolve_turn_model(Some("claude-3.5-sonnet".into()), Some("gpt-x".into())).as_deref(),
            Some("claude-3.5-sonnet")
        );
        assert_eq!(
            resolve_turn_model(None, Some("gpt-x".into())).as_deref(),
            Some("gpt-x")
        );
        assert_eq!(resolve_turn_model(Some(String::new()), None), None);
    }

    // The egress allowlist routes Cloudflare providers to Cloudflare's hosts only — the upstream
    // model key never reaches the sandbox (ADR 0064 membrane).
    #[test]
    fn model_endpoint_hosts_allows_cloudflare_gateway() {
        let hosts = model_endpoint_hosts(Some("cloudflare-ai-gateway"));
        assert!(
            hosts.iter().any(|h| h == "gateway.ai.cloudflare.com"),
            "gateway host: {hosts:?}"
        );
        // The gateway proxies upstream server-side, so the upstream endpoints are NOT opened.
        assert!(
            !hosts.iter().any(|h| h == "api.anthropic.com"),
            "no upstream egress: {hosts:?}"
        );
        // Workers AI direct resolves to the Cloudflare API host.
        assert!(model_endpoint_hosts(Some("cloudflare-workers-ai"))
            .iter()
            .any(|h| h == "api.cloudflare.com"));
    }

    // CORE-5: GaugeDesk decides the per-turn egress posture; WhippleScript enforces
    // the admitted provider endpoint without relying on Pi's netns capability.
    #[test]
    fn egress_posture_filters_provider_calls_unless_policy_overrides() {
        use gaugedesk_harness::sandbox::Network;
        assert_eq!(egress_posture(false, false), Network::Filtered);
        assert_eq!(egress_posture(true, false), Network::Deny);
        // The explicit operator escape hatch preserves its existing precedence.
        assert_eq!(egress_posture(false, true), Network::Allow);
        assert_eq!(egress_posture(true, true), Network::Allow);
    }

    /// A scripted Pi transport: canned stdout lines in, sent commands recorded.
    struct Scripted {
        out: VecDeque<String>,
        sent: Vec<String>,
    }
    impl Scripted {
        fn new(lines: &[&str]) -> Self {
            Self {
                out: lines.iter().map(|s| s.to_string()).collect(),
                sent: Vec::new(),
            }
        }
    }
    impl RpcTransport for Scripted {
        fn send(&mut self, line: &str) -> io::Result<()> {
            self.sent.push(line.to_string());
            Ok(())
        }
        fn recv(&mut self) -> io::Result<Option<String>> {
            Ok(self.out.pop_front())
        }
    }
    // The scripted transport is also a Harness (ADR 0031) so tests drive the engine
    // through the same harness-agnostic seam the real Pi adapter uses.
    impl Harness for Scripted {
        fn run_turn(
            &mut self,
            gate: &dyn EgressGate,
            prompt: &str,
            images: &[ImageContent],
            sink: &mut dyn FnMut(&Observation),
        ) -> io::Result<TurnOutcome> {
            run_rpc_turn(self, gate, prompt, images, sink)
        }
    }

    /// The compatibility membrane mirrors native package/control ownership for
    /// fake and retired adapters. WhippleScript is the production authority.
    #[test]
    fn membrane_gate_enforces_the_edit_use_write_gate() {
        use gaugedesk_harness::GateDecision;
        let cfg = AgentConfig::default();
        let use_gate = MembraneGate::new(&cfg, default_external_tools()).with_mode(ChatMode::Use);
        // use mode: writing the definition surface is blocked…
        assert!(matches!(
            use_gate.classify_tool("edit", Some(".whipple/draft/persona.md")),
            GateDecision::Block(_)
        ));
        assert!(matches!(
            use_gate.classify_tool("edit", Some(".agent-config.json")),
            GateDecision::Block(_)
        ));
        // …but ordinary work is allowed, and reading its own definition is allowed.
        assert!(matches!(
            use_gate.classify_tool("edit", Some("src/main.rs")),
            GateDecision::Allow
        ));
        assert!(matches!(
            use_gate.classify_tool("read", Some(".whipple/versions/1/persona.md")),
            GateDecision::Allow
        ));
        assert!(matches!(
            use_gate.classify_tool("edit", Some("AGENTS.md")),
            GateDecision::Allow
        ));

        // edit mode: the editor may write the definition surface.
        let edit_gate = MembraneGate::new(&cfg, default_external_tools()).with_mode(ChatMode::Edit);
        assert!(matches!(
            edit_gate.classify_tool("edit", Some(".whipple/draft/persona.md")),
            GateDecision::Allow
        ));
        assert!(matches!(
            edit_gate.classify_tool("edit", Some(".agent-config.json")),
            GateDecision::Block(_)
        ));
    }

    /// Package selection is load-bearing; the OS roots are defense in depth.
    #[test]
    fn method_surface_readonly_roots_use_vs_edit() {
        let dir = tempfile::tempdir().unwrap();
        let wt = dir.path();
        std::fs::create_dir_all(wt.join(".whipple/versions/1")).unwrap();
        std::fs::create_dir_all(wt.join(".whipple/draft")).unwrap();
        std::fs::create_dir_all(wt.join(".gaugedesk-runtime/discipline")).unwrap();

        let ro = method_surface_readonly_roots(wt, ChatMode::Use);
        assert!(ro.contains(&wt.join(".whipple")));
        assert!(ro.contains(&wt.join(".gaugedesk-runtime")));

        let edit_ro = method_surface_readonly_roots(wt, ChatMode::Edit);
        assert!(edit_ro.contains(&wt.join(".whipple/versions")));
        assert!(edit_ro.contains(&wt.join(".gaugedesk-runtime")));
        assert!(!edit_ro.contains(&wt.join(".whipple/draft")));
    }

    #[test]
    fn target_path_scope_becomes_the_only_writable_sandbox_roots() {
        let worktree = Path::new("/target/candidate");
        assert_eq!(
            target_writable_roots(worktree, &["src".to_owned(), "docs/api".to_owned()]),
            vec![worktree.join("src"), worktree.join("docs/api")]
        );
        assert_eq!(
            target_writable_roots(worktree, &[".".to_owned()]),
            vec![worktree.to_path_buf()]
        );
    }

    /// The Phase-2 gate, end-to-end and headless: a default agent works in a
    /// worktree via (scripted) Pi, auto-commits, produces a diff + output — and
    /// the membrane blocks an out-of-policy effect.
    #[test]
    fn canonical_loop_works_in_worktree_and_blocks_out_of_policy_effect() {
        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let eng = inst.create_engagement("e1").unwrap();

        // default agent: trust-by-default in-workspace, but `bash` is blocked.
        let config = AgentConfig::from_json(
            r#"{ "model": "gpt-5.5", "policy": { "block_tools": ["bash"] } }"#,
        )
        .unwrap();
        let gate = MembraneGate::new(&config, BTreeSet::new());

        // Pi: edits a file (in-policy), then attempts bash (blocked), then ends.
        // The edit's effect on the worktree is simulated by the test writing the
        // file — the bridge mediates the *decision*, the plugin does the write.
        std::fs::write(eng.path().join("answer.txt"), "42\n").unwrap();
        let mut transport = Scripted::new(&[
            r#"{"type":"agent_start"}"#,
            r#"{"type":"text_delta","delta":"Writing the answer."}"#,
            r#"{"type":"tool_execution_start","toolCallId":"t1","toolName":"write","args":{}}"#,
            r#"{"type":"tool_execution_end","toolCallId":"t1"}"#,
            r#"{"type":"tool_execution_start","toolCallId":"t2","toolName":"bash","args":{}}"#,
            r#"{"type":"agent_end","messages":[]}"#,
            r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":"Done. The answer is 42."}}"#,
        ]);

        let mut store = Store::open_in_memory().unwrap();
        let result = run_task(
            &mut store,
            "eng-1",
            &eng,
            &mut transport,
            &gate,
            "write the answer",
            &[],
        )
        .unwrap();

        // the run completed and is durable in the log
        assert_eq!(result.run_phase, RunPhase::Completed);
        assert_eq!(
            store.fold::<RunState>("eng-1").unwrap().phase,
            RunPhase::Completed
        );

        // it produced output + a diff, auto-committed in the worktree
        assert_eq!(result.assistant_text, "Done. The answer is 42.");
        assert!(result.commit.is_some(), "the turn auto-committed");
        assert!(result.diff.contains("answer.txt") && result.diff.contains("42"));

        // the in-policy write was mediated; the out-of-policy bash was blocked
        assert_eq!(result.mediated_tool_calls, vec!["write".to_string()]);
        assert!(
            result.blocked_effects.iter().any(|b| b.contains("bash")),
            "the membrane blocked the out-of-policy effect: {:?}",
            result.blocked_effects
        );

        // keeping the work merges it into main
        eng.merge_into_main().unwrap();
        assert!(inst.repo().join("answer.txt").exists());
    }

    /// The durable transcript keeps each tool line's target/args/result, so a
    /// reloaded chat stays clickable (run-chat.md click-to-open survives the turn).
    #[test]
    fn durable_transcript_keeps_tool_target_and_result() {
        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let eng = inst.create_engagement("e1").unwrap();
        let gate = MembraneGate::new(&AgentConfig::default(), default_external_tools());
        let mut transport = Scripted::new(&[
            r#"{"type":"tool_execution_start","toolCallId":"t1","toolName":"write","args":{"path":"answer.txt"}}"#,
            r#"{"type":"tool_execution_end","toolCallId":"t1","result":"wrote 1 file","isError":false}"#,
            r#"{"type":"agent_end","messages":[]}"#,
            r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":"ok"}}"#,
        ]);
        let mut store = Store::open_in_memory().unwrap();
        run_task(&mut store, "eng-1", &eng, &mut transport, &gate, "go", &[]).unwrap();

        let rows = store.records("eng-1", "transcript").unwrap();
        let joined = rows.join("\n");
        assert!(
            joined.contains(r#""type":"tool""#),
            "a durable tool line: {joined}"
        );
        assert!(
            joined.contains(r#""target":"answer.txt""#),
            "tool target survives: {joined}"
        );
        assert!(
            joined.contains(r#""type":"toolresult""#),
            "the result is durable: {joined}"
        );
        assert!(
            joined.contains("wrote 1 file"),
            "the result body survives: {joined}"
        );
    }

    /// A failed turn surfaces *why*: the runtime error becomes `TaskResult.error`
    /// AND a durable `error` transcript record — so the user sees the reason (e.g. a
    /// model rejecting an image), not just a generic "didn't finish" (UX-14).
    #[test]
    fn a_failed_turn_records_its_error_reason() {
        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let eng = inst.create_engagement("e1").unwrap();
        let gate = MembraneGate::new(&AgentConfig::default(), default_external_tools());
        // Pi reports a model-level error (e.g. an image to a non-vision model), then ends.
        let mut transport = Scripted::new(&[
            r#"{"type":"agent_start"}"#,
            r#"{"type":"error","error":"model gpt-x does not support image input"}"#,
            r#"{"type":"agent_end","messages":[]}"#,
            r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":""}}"#,
        ]);
        let mut store = Store::open_in_memory().unwrap();
        let result = run_task(
            &mut store,
            "eng-1",
            &eng,
            &mut transport,
            &gate,
            "describe the image",
            &[],
        )
        .unwrap();

        assert_eq!(result.run_phase, RunPhase::Failed);
        assert_eq!(
            result.error.as_deref(),
            Some("model gpt-x does not support image input")
        );

        // …and it's durable: a reloaded transcript shows the reason as an error line.
        let joined = store.records("eng-1", "transcript").unwrap().join("\n");
        assert!(
            joined.contains(r#""type":"error""#) && joined.contains("does not support image input"),
            "the failure reason is a durable transcript line: {joined}"
        );
    }

    #[test]
    fn a_harness_transport_death_terminalizes_and_summarizes_the_attempt() {
        struct DeadHarness;
        impl Harness for DeadHarness {
            fn run_turn(
                &mut self,
                _gate: &dyn EgressGate,
                _prompt: &str,
                _images: &[ImageContent],
                _sink: &mut dyn FnMut(&Observation),
            ) -> io::Result<TurnOutcome> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "runtime died"))
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let eng = inst.create_engagement("e1").unwrap();
        let gate = MembraneGate::new(&AgentConfig::default(), default_external_tools());
        let mut transport = DeadHarness;
        let mut store = Store::open_in_memory().unwrap();

        let error = run_task(
            &mut store,
            "eng-transport",
            &eng,
            &mut transport,
            &gate,
            "go",
            &[],
        )
        .unwrap_err();

        assert!(matches!(error, EngineError::Harness(_)));
        assert_eq!(
            store.fold::<RunState>("eng-transport").unwrap().phase,
            RunPhase::Failed,
            "a dead harness must not strand a durable Running state"
        );
        let summary = crate::turn_summary::latest(&store, "eng-transport")
            .unwrap()
            .unwrap();
        assert_eq!(
            summary.receipt_status,
            crate::turn_summary::ReceiptStatus::Failed
        );
        assert!(summary.error.is_some());
    }

    /// A fail-closed pre-flight refusal (no model credential) is a durable, coded
    /// failure turn — the user message plus a `code:"no_credential"` error line — so the
    /// chat log shows it and the client can render an "open settings" action (LLM-1).
    #[test]
    fn precheck_failure_is_a_durable_coded_error_turn() {
        let mut store = Store::open_in_memory().unwrap();
        let result = record_precheck_failure(
            &mut store,
            "eng-nc",
            "summarize the deck",
            "No model sign-in found. Link a key in Account settings.".to_string(),
            "no_credential",
        )
        .unwrap();

        assert_eq!(result.run_phase, RunPhase::Failed);
        assert_eq!(
            result.error.as_deref(),
            Some("No model sign-in found. Link a key in Account settings.")
        );
        assert_eq!(
            store.fold::<RunState>("eng-nc").unwrap().phase,
            RunPhase::Failed
        );

        // Durable: the user's message and a machine-readable error line both persist.
        let joined = store.records("eng-nc", "transcript").unwrap().join("\n");
        assert!(
            joined.contains(r#""type":"user""#) && joined.contains("summarize the deck"),
            "the user message is durable: {joined}"
        );
        assert!(
            joined.contains(r#""type":"error""#) && joined.contains(r#""code":"no_credential""#),
            "the error line carries the machine-readable code: {joined}"
        );
    }

    /// The streaming sink receives each observation live (the SSE seam).
    #[test]
    fn streaming_sink_receives_observations_live() {
        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let eng = inst.create_engagement("e1").unwrap();
        let gate = MembraneGate::new(&AgentConfig::default(), default_external_tools());

        let mut transport = Scripted::new(&[
            r#"{"type":"text_delta","delta":"hi"}"#,
            r#"{"type":"tool_execution_start","toolCallId":"t1","toolName":"read","args":{}}"#,
            r#"{"type":"agent_end","messages":[]}"#,
            r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":"hi"}}"#,
        ]);
        let mut store = Store::open_in_memory().unwrap();

        let mut streamed: Vec<String> = Vec::new();
        let mut sink = |obs: &Observation| streamed.push(obs.kind.to_string());
        run_task_streaming(
            &mut store,
            "e1",
            &eng,
            &mut transport,
            &gate,
            "go",
            &[],
            &mut sink,
        )
        .unwrap();

        // the text delta and the mediated tool both reached the sink live
        assert!(streamed.contains(&"text".to_string()));
        assert!(streamed.contains(&"egress".to_string()));
    }

    #[test]
    fn context_reading_is_recorded_in_the_engagement_scope_only() {
        use gaugedesk_harness::testing::ScriptedHarness;

        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let eng = inst.create_engagement("e1").unwrap();
        let gate = MembraneGate::new(&AgentConfig::default(), default_external_tools());
        let mut harness = ScriptedHarness::new(vec![TurnOutcome {
            assistant_text: "done".into(),
            context_reading: Some(gaugedesk_harness::ContextWindowReading {
                provider: "anthropic".into(),
                model: "claude-sonnet-5".into(),
                last_input_tokens: 34_000,
            }),
            ..TurnOutcome::default()
        }]);
        let mut store = Store::open_in_memory().unwrap();
        run_task_streaming(
            &mut store,
            "e1",
            &eng,
            &mut harness,
            &gate,
            "go",
            &[],
            &mut |_| {},
        )
        .unwrap();

        let readings = store.records("e1", CONTEXT_READING_KIND).unwrap();
        assert_eq!(readings.len(), 1);
        let reading: gaugedesk_harness::ContextWindowReading =
            serde_json::from_str(&readings[0]).unwrap();
        assert_eq!(reading.last_input_tokens, 34_000);
        // A gauge of this chat's window, never billing evidence: nothing landed
        // in the account scope.
        assert!(store
            .events(crate::account::ACCOUNT_SCOPE)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn managed_usage_is_admitted_to_run_and_billing_scopes() {
        use gaugedesk_harness::testing::ScriptedHarness;

        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let eng = inst.create_engagement("e1").unwrap();
        let gate = MembraneGate::new(&AgentConfig::default(), default_external_tools());
        let mut harness = ScriptedHarness::new(vec![TurnOutcome {
            assistant_text: "done".into(),
            managed_usage: Some(gaugedesk_harness::ModelUsage {
                usage_ref: "whip:evidence:usage:1".into(),
                provider: "cloudflare-workers-ai".into(),
                model: "@cf/model".into(),
                input_tokens: 8,
                output_tokens: 3,
            }),
            ..TurnOutcome::default()
        }]);
        let mut store = Store::open_in_memory().unwrap();
        run_task_streaming_billed(
            &mut store,
            &eng,
            "e1",
            &mut harness,
            &gate,
            "go",
            &[],
            &mut |_| {},
            Some(crate::account::ACCOUNT_SCOPE),
            Some("gaugedesk:managed-plan:v1:test"),
            "",
        )
        .unwrap();

        let run_usage = crate::managed_inference::fold_usage(&store, "e1", 0).unwrap();
        let billed =
            crate::managed_inference::fold_usage(&store, crate::account::ACCOUNT_SCOPE, 10)
                .unwrap();
        assert_eq!(run_usage.total_tokens, 11);
        assert_eq!(billed.runs, 1);
        assert_eq!(billed.overage_tokens, 1);
        assert_eq!(
            crate::managed_inference::fold_reservations(&store, crate::account::ACCOUNT_SCOPE)
                .unwrap(),
            crate::managed_inference::ManagedReservationSummary {
                reserved: 1,
                settled: 1,
                released: 0,
                outstanding: 0,
            }
        );
        let kinds = store
            .events(crate::account::ACCOUNT_SCOPE)
            .unwrap()
            .into_iter()
            .map(|(_, kind, _)| kind)
            .collect::<Vec<_>>();
        let reservation = kinds
            .iter()
            .position(|kind| kind == crate::managed_inference::MANAGED_RESERVATION_KIND)
            .unwrap();
        let usage = kinds
            .iter()
            .position(|kind| kind == crate::managed_inference::MANAGED_USAGE_KIND)
            .unwrap();
        let settlement = kinds
            .iter()
            .position(|kind| kind == crate::managed_inference::MANAGED_SETTLEMENT_KIND)
            .unwrap();
        assert!(reservation < usage && usage < settlement);
    }

    /// The prompt sent to the model is the **raw task** — no framing prefix.
    /// Persona belongs to the selected authored package (or editor package),
    /// while the transcript records only the raw user task.
    #[test]
    fn the_prompt_sent_is_the_raw_task_no_framing_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let eng = inst.create_engagement("e1").unwrap();
        let gate = MembraneGate::new(&AgentConfig::default(), default_external_tools());
        let mut transport = Scripted::new(&[
            r#"{"type":"agent_end","messages":[]}"#,
            r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":"ok"}}"#,
        ]);
        let mut store = Store::open_in_memory().unwrap();
        let mut sink = |_: &Observation| {};
        run_task_streaming(
            &mut store,
            "e1",
            &eng,
            &mut transport,
            &gate,
            "tighten the policy",
            &[],
            &mut sink,
        )
        .unwrap();

        // the model receives the raw task, not a persona prefix.
        assert!(transport.sent[0].contains("tighten the policy"));
        assert!(
            !transport.sent[0].contains("You are the editor"),
            "no framing prefix: {}",
            transport.sent[0]
        );
        // the durable transcript shows the raw task the user typed.
        let user = store
            .records("e1", "transcript")
            .unwrap()
            .into_iter()
            .find(|r| r.contains("\"user\""))
            .unwrap();
        assert!(
            user.contains("tighten the policy"),
            "raw transcript: {user}"
        );
    }

    /// Mock-LLM mode: `run_engagement_turn` completes a turn deterministically
    /// (no runtime/model call) with a real worktree diff — the E2E path.
    #[test]
    fn fake_agent_mode_completes_a_turn_with_a_real_diff() {
        use std::sync::{Arc, Mutex};
        use tokio::sync::broadcast;

        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let eng = inst.create_engagement("e1").unwrap();
        let worktree = eng.path().to_path_buf();
        let store = Store::open_in_memory().unwrap();
        let wb = Arc::new(Mutex::new(crate::Workbench::with_target(
            "inst-test",
            inst,
            store,
        )));
        wb.lock()
            .unwrap()
            .register_engagement("e1", "inst-test", Box::new(eng));

        let _fake_agent = fake_agent_env();
        let (tx, _rx) = broadcast::channel(16);
        let result = run_engagement_turn(
            &wb,
            "e1",
            &worktree,
            &tx,
            EngagementTurnInput {
                task: "do the thing",
                images: &[],
                mode: ChatMode::Use,
                authenticated_actor: None,
                contribution_by: None,
                account_scope: crate::account::ACCOUNT_SCOPE,
                tenant_scope: crate::org::ORG_SCOPE,
                runtime_command_id: None,
                harness_factory: None,
            },
        )
        .unwrap();

        assert_eq!(result.run_phase, RunPhase::Completed);
        assert!(result.commit.is_some(), "the fake turn auto-committed");
        assert!(
            result.diff.contains("agent-note.txt"),
            "real diff: {}",
            result.diff
        );
        // default policy (trust-by-default) mediates both in-workspace tools
        assert_eq!(
            result.mediated_tool_calls,
            vec!["write".to_string(), "bash".to_string()]
        );
        // INV-4: the turn's execution evidence was admitted into the run.
        let obs = wb.lock().unwrap().run_state("e1").unwrap().observations;
        assert!(obs > 0, "run recorded admitted observations: {obs}");
        let transcript = wb.lock().unwrap().engagement_transcript_json("e1").unwrap();
        assert!(
            transcript.contains(r#""forkable":true"#),
            "the controlled provider simulator must expose real point-fork coordinates: {transcript}"
        );
    }

    /// A settled turn leaves a listable derived output (`MINT-1`).
    ///
    /// MINT-1's own verification criterion is this module's tests, and none of
    /// them asserted the mint it names — so the only thing checking it was a
    /// production canary whose predicate read a shape the endpoint does not
    /// answer, which could neither pass nor fail meaningfully. The claim now has
    /// a check that runs on every commit.
    #[test]
    fn a_settled_turn_mints_a_listable_output_resource() {
        use std::sync::{Arc, Mutex};
        use tokio::sync::broadcast;

        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let eng = inst.create_engagement("e1").unwrap();
        let worktree = eng.path().to_path_buf();
        let store = Store::open_in_memory().unwrap();
        let wb = Arc::new(Mutex::new(crate::Workbench::with_target(
            "inst-test",
            inst,
            store,
        )));
        wb.lock()
            .unwrap()
            .register_engagement("e1", "inst-test", Box::new(eng));

        let _fake_agent = fake_agent_env();
        let (tx, _rx) = broadcast::channel(16);
        let result = run_engagement_turn(
            &wb,
            "e1",
            &worktree,
            &tx,
            EngagementTurnInput {
                task: "do the thing",
                images: &[],
                mode: ChatMode::Use,
                authenticated_actor: None,
                contribution_by: None,
                account_scope: crate::account::ACCOUNT_SCOPE,
                tenant_scope: crate::org::ORG_SCOPE,
                runtime_command_id: None,
                harness_factory: None,
            },
        )
        .unwrap();
        assert_eq!(result.run_phase, RunPhase::Completed);

        // The id the route surfaces and the canary looks for.
        let listed = wb.lock().unwrap().list_resource_contexts("e1").unwrap();
        let ids: Vec<String> = listed
            .iter()
            .map(|(record, _)| record.resource.id.as_str().to_string())
            .collect();
        assert!(
            ids.contains(&"out-e1".to_string()),
            "a settled turn minted no listable output resource: {ids:?}",
        );

        // Owned by the scope's authority (MINT-1), not a hardcoded local constant.
        let output = listed
            .iter()
            .find(|(record, _)| record.resource.id.as_str() == "out-e1")
            .expect("output resource");
        assert_eq!(
            output.0.resource.owner.as_str(),
            gaugedesk_core::determine_scope_authority("e1").as_str(),
        );
    }

    /// A target-local file cannot override control-plane runtime policy.
    #[test]
    fn fake_agent_ignores_target_local_runtime_config() {
        use std::sync::{Arc, Mutex};
        use tokio::sync::broadcast;

        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let eng = inst.create_engagement("e1").unwrap();
        let worktree = eng.path().to_path_buf();
        // A file with the retired name is ordinary target content and has no
        // authority to change the runtime membrane.
        std::fs::write(
            worktree.join(".agent-config.json"),
            r#"{"policy":{"block_tools":["bash"]}}"#,
        )
        .unwrap();
        let store = Store::open_in_memory().unwrap();
        let wb = Arc::new(Mutex::new(crate::Workbench::with_target(
            "inst-test",
            inst,
            store,
        )));
        wb.lock()
            .unwrap()
            .register_engagement("e1", "inst-test", Box::new(eng));

        let _fake_agent = fake_agent_env();
        let (tx, _rx) = broadcast::channel(16);
        let result = run_engagement_turn(
            &wb,
            "e1",
            &worktree,
            &tx,
            EngagementTurnInput {
                task: "go",
                images: &[],
                mode: ChatMode::Use,
                authenticated_actor: None,
                contribution_by: None,
                account_scope: crate::account::ACCOUNT_SCOPE,
                tenant_scope: crate::org::ORG_SCOPE,
                runtime_command_id: None,
                harness_factory: None,
            },
        )
        .unwrap();

        assert_eq!(
            result.mediated_tool_calls,
            vec!["write".to_string(), "bash".to_string()]
        );
        assert!(result.blocked_effects.is_empty());
    }

    /// MINT-1: a turn's derived output is minted under the scope's owning
    /// authority (`determine_scope_authority`), not the hardcoded local constant.
    /// A federated `scope:<authority>:<rest>` scope resolves to that authority, so
    /// the minted output is owned by — and governed by — the right keyset.
    #[test]
    fn output_is_minted_under_the_scopes_owning_authority() {
        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let eng = inst.create_engagement("e1").unwrap();
        let gate = MembraneGate::new(&AgentConfig::default(), default_external_tools());
        let mut transport = Scripted::new(&[
            r#"{"type":"agent_end","messages":[]}"#,
            r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":"ok"}}"#,
        ]);
        let mut store = Store::open_in_memory().unwrap();

        // A federated scope owned by `acme` (the second `:`-segment).
        let scope = "scope:acme:run-1";
        run_task(&mut store, scope, &eng, &mut transport, &gate, "go", &[]).unwrap();

        // The derived output exists and is owned by `acme`, not `local-user`.
        let out_id = crate::resource_store::output_id(scope);
        let rec = crate::resource_store::get(&store, scope, &out_id)
            .unwrap()
            .expect("a derived output was minted");
        assert_eq!(
            rec.resource.owner.as_str(),
            "acme",
            "owned by the scope's authority"
        );
        assert_ne!(
            rec.resource.owner.as_str(),
            crate::LOCAL_AUTHORITY,
            "not the hardcoded local owner"
        );
    }

    /// ENGINE-REMOTE-1: the engine orchestrator drives a turn against a
    /// **remote-placed** runtime (`RemoteLoopbackHarness`, REMOTE-RPC-1). The run
    /// lifecycle is admitted, the remote turn's observations come back *through
    /// federation* (OBSERVATION-FEDERATION-1) and become run truth only via the
    /// owner's admission (INV-4), the run completes, and the derived output is
    /// minted under the scope's owning authority (MINT-1) — no local worktree.
    #[test]
    fn engine_drives_a_remote_placed_turn_and_federates_its_observations() {
        use gaugedesk_pi_bridge::RemoteLoopbackHarness;

        let mut store = Store::open_in_memory().unwrap();
        // A federated scope owned by `acme` (the second `:`-segment), so the minted
        // output is governed by that authority, not the hardcoded local owner.
        let scope = "scope:acme:remote-run";
        let gate = MembraneGate::new(&AgentConfig::default(), default_external_tools());

        // The remote peer streams two text tokens, so two observations cross back.
        let mut harness = RemoteLoopbackHarness::new(
            "127.0.0.1:7788",
            [
                r#"{"type":"agent_start"}"#,
                r#"{"type":"text_delta","delta":"remote "}"#,
                r#"{"type":"text_delta","delta":"work"}"#,
                r#"{"type":"agent_end","messages":[]}"#,
                r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":"remote work"}}"#,
            ],
        );

        let result =
            run_task_remote(&mut store, scope, &mut harness, &gate, "do it remotely").unwrap();

        // The run completed and is durable in the log.
        assert_eq!(result.run_phase, RunPhase::Completed);
        assert_eq!(
            store.fold::<RunState>(scope).unwrap().phase,
            RunPhase::Completed
        );
        assert_eq!(
            result.remote_address, "127.0.0.1:7788",
            "the peer endpoint the turn ran at"
        );

        // INV-4: each remote observation crossed the bridge and was owner-admitted;
        // the run's admitted-observation count matches what federated across.
        assert!(
            result.federated_observations >= 2,
            "the two text tokens federated back"
        );
        assert_eq!(
            store.fold::<RunState>(scope).unwrap().observations,
            result.federated_observations,
            "the owner admitted exactly the federated observations into run truth",
        );
        let crossed = crate::federation_relay::admitted(&store, scope).unwrap();
        assert_eq!(crossed.len() as u32, result.federated_observations);
        for fact in &crossed {
            let handle = fact["payload_handle"].as_str().unwrap();
            assert!(
                handle.starts_with("obs::"),
                "a handle crossed, never the body (INV-10)"
            );
        }

        // MINT-1: the derived output is owned by the scope's authority (`acme`).
        assert_eq!(result.output_owner, "acme");
        let out_id = crate::resource_store::output_id(scope);
        let rec = crate::resource_store::get(&store, scope, &out_id)
            .unwrap()
            .expect("a derived output was minted");
        assert_eq!(
            rec.resource.owner.as_str(),
            "acme",
            "owned by the scope's authority"
        );
        assert_ne!(
            rec.resource.owner.as_str(),
            crate::LOCAL_AUTHORITY,
            "not the hardcoded local owner"
        );
    }

    /// WORKBENCH-REMOTE-1: the workbench holds a chat's **remote** harness session
    /// alongside the local ones, and [`drive_remote_turn`] routes a turn against it
    /// through the same `run_task_remote` orchestrator (ENGINE-REMOTE-1) — the
    /// observations federate back and become run truth via the owner's admission
    /// (INV-4), with no local worktree.
    #[test]
    fn workbench_holds_a_remote_session_and_drives_a_turn_against_it() {
        use gaugedesk_pi_bridge::RemoteLoopbackHarness;
        use gaugedesk_workspace::Instance;
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let store = Store::open_in_memory().unwrap();
        let wb = Arc::new(Mutex::new(crate::Workbench::with_target(
            "inst-test",
            inst,
            store,
        )));

        // Place this chat's runtime in a different authority (`acme`): register its
        // remote harness on the workbench, where it lives beside any local session.
        let scope = "scope:acme:wb-remote";
        wb.lock_unpoisoned().register_remote_session(
            scope,
            Box::new(RemoteLoopbackHarness::new(
                "127.0.0.1:7799",
                [
                    r#"{"type":"agent_start"}"#,
                    r#"{"type":"text_delta","delta":"remote "}"#,
                    r#"{"type":"text_delta","delta":"work"}"#,
                    r#"{"type":"agent_end","messages":[]}"#,
                    r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":"remote work"}}"#,
                ],
            )),
        );

        // The workbench reports the chat as remotely placed, at the peer endpoint.
        assert!(
            wb.lock_unpoisoned().is_remote(scope),
            "the chat is placed remotely"
        );
        assert_eq!(
            wb.lock_unpoisoned().remote_address(scope),
            Some("127.0.0.1:7799")
        );

        let gate = MembraneGate::new(&AgentConfig::default(), default_external_tools());
        let result = drive_remote_turn(&wb, scope, &gate, "do it remotely").unwrap();

        // The run completed via the remote orchestrator; its observations federated
        // back and were owner-admitted into run truth (INV-4).
        assert_eq!(result.run_phase, RunPhase::Completed);
        assert_eq!(result.remote_address, "127.0.0.1:7799");
        assert!(
            result.federated_observations >= 2,
            "the text tokens federated back"
        );
        assert_eq!(
            wb.lock_unpoisoned().run_state(scope).unwrap().observations,
            result.federated_observations,
            "the owner admitted exactly the federated observations",
        );
        // MINT-1: the output is minted under the scope's authority (`acme`).
        assert_eq!(result.output_owner, "acme");
    }

    /// E2E-TEST-1: the whole D-REMOTE two-authority loopback story in one turn —
    /// an owner drives a turn whose runtime is *placed in another authority*
    /// (`scope:acme:…`, `RemoteLoopbackHarness`), the remote observations cross the
    /// owner's bridge **through federation** as signed handle-only messages and
    /// become run truth only via the owner's admission (INV-4 / INV-10), and the
    /// derived output is minted under the scope's authority (MINT-1). The crossing's
    /// security teeth (INV-21) are asserted on the same relay the turn rides: a
    /// genuine signed envelope admits, while a forged signature, a mismatched bridge
    /// grant, and a replayed nonce each deny target admission.
    ///
    /// Marked `#[ignore]` (run via `-- --ignored`): the heavier end-to-end
    /// composition over the loopback substrate, distinct from the focused
    /// orchestrator/workbench units above. A real cross-machine relay attaches
    /// behind the same seam with no rearchitecture (ADR 0020).
    #[test]
    #[ignore = "E2E-TEST-1: end-to-end two-authority loopback; run with --ignored"]
    fn e2e_two_authority_loopback_federation_with_signatures() {
        use gaugedesk_core::federated_delivery::{
            Authority, DeliveryCommand, DeliveryEnvelope, DeliveryPhase, DeliveryState,
        };
        use gaugedesk_core::ids::{BridgeGrantId, Nonce, PublicKey};
        use gaugedesk_core::signature::Signature;
        use gaugedesk_pi_bridge::RemoteLoopbackHarness;
        use gaugedesk_store::AdmitError;

        let mut store = Store::open_in_memory().unwrap();
        // The owner federates work to a runtime placed in the `acme` authority.
        let scope = "scope:acme:e2e-run";
        let gate = MembraneGate::new(&AgentConfig::default(), default_external_tools());

        // --- 1. A remote-placed turn whose observations federate back ------------
        // Two streamed text tokens cross the owner's bridge as handle-only facts.
        let mut harness = RemoteLoopbackHarness::new(
            "127.0.0.1:7900",
            [
                r#"{"type":"agent_start"}"#,
                r#"{"type":"text_delta","delta":"remote "}"#,
                r#"{"type":"text_delta","delta":"work"}"#,
                r#"{"type":"agent_end","messages":[]}"#,
                r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":"remote work"}}"#,
            ],
        );

        let result =
            run_task_remote(&mut store, scope, &mut harness, &gate, "do it remotely").unwrap();

        // The run completed and is durable; the turn ran at the peer endpoint.
        assert_eq!(result.run_phase, RunPhase::Completed);
        assert_eq!(
            store.fold::<RunState>(scope).unwrap().phase,
            RunPhase::Completed
        );
        assert_eq!(result.remote_address, "127.0.0.1:7900");

        // INV-4: each remote observation crossed the bridge and was owner-admitted;
        // the run's admitted-observation count matches what federated across.
        assert!(
            result.federated_observations >= 2,
            "the two text tokens federated back"
        );
        assert_eq!(
            store.fold::<RunState>(scope).unwrap().observations,
            result.federated_observations,
            "the owner admitted exactly the federated observations into run truth",
        );
        // INV-10: only handles crossed the bridge — never the observation body.
        let crossed = crate::federation_relay::admitted(&store, scope).unwrap();
        assert_eq!(crossed.len() as u32, result.federated_observations);
        for fact in &crossed {
            let handle = fact["payload_handle"].as_str().unwrap();
            assert!(
                handle.starts_with("obs::"),
                "a handle crossed, never the body (INV-10)"
            );
        }

        // MINT-1: the derived output is owned by the scope's authority (`acme`),
        // governed by the right keyset though it ran in a different authority.
        assert_eq!(result.output_owner, "acme");
        let out_id = crate::resource_store::output_id(scope);
        let rec = crate::resource_store::get(&store, scope, &out_id)
            .unwrap()
            .expect("a derived output was minted");
        assert_eq!(
            rec.resource.owner.as_str(),
            "acme",
            "owned by the scope's authority"
        );
        assert_ne!(
            rec.resource.owner.as_str(),
            crate::LOCAL_AUTHORITY,
            "not the hardcoded local owner"
        );

        // --- 2. The crossing's security teeth on the same delivery shell (INV-21) -
        // A genuine signed envelope under the bound grant admits at the target.
        let signed = |correlation: &str| DeliveryEnvelope {
            signed_bytes: correlation.as_bytes().to_vec(),
            signature: Signature::new(vec![0u8; 64]),
            source_pubkey: PublicKey::new("04loopback-source"),
            nonce: Nonce::new(format!("nonce::{correlation}")),
            bridge_grant_id: BridgeGrantId::new("bridge-grant-7"),
            device_key: PublicKey::new("04dev1ce0ke7"),
            device_active: true,
        };
        let cross = |store: &mut Store, correlation: &str, envelope: DeliveryEnvelope| -> bool {
            let ds = crate::federation_relay::delivery_scope(correlation);
            store
                .admit::<DeliveryState>(&ds, DeliveryCommand::AuthorizeFederatedMessage)
                .unwrap();
            store
                .admit::<DeliveryState>(&ds, DeliveryCommand::EnqueueFederatedMessage)
                .unwrap();
            store
                .admit::<DeliveryState>(&ds, DeliveryCommand::RecordRelayDelivery)
                .unwrap();
            match store
                .admit::<DeliveryState>(&ds, DeliveryCommand::AdmitTargetReceipt { envelope })
            {
                Ok(s) => s.phase == DeliveryPhase::TargetAdmitted,
                Err(AdmitError::Rejected(_)) => false,
                Err(e) => panic!("unexpected delivery error: {e:?}"),
            }
        };

        // A genuine crossing admits: target authority + verified signature, relay-blind.
        assert!(
            cross(&mut store, "e2e-ok", signed("e2e-ok")),
            "a signed envelope admits"
        );
        let s = store
            .fold::<DeliveryState>(&crate::federation_relay::delivery_scope("e2e-ok"))
            .unwrap();
        assert_eq!(
            s.target_admitted_by,
            Authority::Target,
            "INV-13: only the target admits"
        );
        assert!(
            s.signature_verified,
            "INV-21: the source signature was verified before admission"
        );
        assert!(
            !s.relay_has_payload_access,
            "INV-10: the relay gained no payload read"
        );
        assert_ne!(
            s.payload_authority,
            Authority::Relay,
            "INV-14: the relay is never payload authority"
        );

        // A forged (malformed) signature is denied (fails closed).
        let mut forged = signed("e2e-forged");
        forged.signature = Signature::new(vec![0u8; 8]);
        assert!(
            !cross(&mut store, "e2e-forged", forged),
            "INV-21: an unverifiable signature denies admission"
        );

        // A mismatched bridge grant is denied.
        let mut wrong_grant = signed("e2e-wrong-grant");
        wrong_grant.bridge_grant_id = BridgeGrantId::new("bridge-grant-OTHER");
        assert!(
            !cross(&mut store, "e2e-wrong-grant", wrong_grant),
            "INV-21: a mismatched grant denies admission"
        );

        // Anti-replay: re-presenting an admitted envelope spends no second nonce.
        let env = signed("e2e-replay");
        assert!(
            cross(&mut store, "e2e-replay", env.clone()),
            "first crossing admits"
        );
        let ds = crate::federation_relay::delivery_scope("e2e-replay");
        match store
            .admit::<DeliveryState>(&ds, DeliveryCommand::AdmitTargetReceipt { envelope: env })
        {
            Err(AdmitError::Rejected(_)) => {}
            other => {
                panic!("INV-21: re-presenting an admitted envelope must be denied, got {other:?}")
            }
        }
        let s = store.fold::<DeliveryState>(&ds).unwrap();
        assert_eq!(
            s.seen_nonces.len(),
            1,
            "INV-21: the replay spent no further nonce"
        );
    }

    /// The per-chat serialization unit is the **harness**, not the workbench.
    ///
    /// A turn needs exclusive access to one chat's agent for as long as the model
    /// call takes. It used to take that by holding the workbench mutex, which
    /// serialized every other chat — and every unrelated read — behind it. Now it
    /// holds only the chat's own harness, so the workbench stays lockable while a
    /// turn is in flight, and a second turn on the *same* chat still waits.
    #[test]
    fn a_turn_holds_its_own_harness_not_the_workbench() {
        use crate::app_support::LockUnpoisoned;
        use gaugedesk_workspace::Instance;
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let store = Store::open_in_memory().unwrap();
        let mut wb = crate::Workbench::with_target("inst-test", inst, store);
        wb.seed_local_session_for_test(
            "c1",
            Box::new(ScriptedTransport::new(Vec::<String>::new())),
        );
        let harness = wb.sessions.get("c1").cloned().expect("the seeded session");
        let wb = Arc::new(Mutex::new(wb));

        // Stand in for a turn in flight: the harness is checked out and held.
        let turn = harness.lock_unpoisoned();

        assert!(
            wb.try_lock().is_ok(),
            "the workbench must stay lockable while a turn holds its harness"
        );
        assert!(
            harness.try_lock().is_err(),
            "a second turn on the same chat must still wait for the harness"
        );

        drop(turn);
        assert!(
            harness.try_lock().is_ok(),
            "the harness frees when the turn finishes"
        );
    }

    /// WORKBENCH-REMOTE-1: a chat is local *or* remote, never both. Placing a remote
    /// session retires any local one under the same id, so the two maps stay disjoint.
    #[test]
    fn registering_a_remote_session_retires_a_local_one() {
        use gaugedesk_pi_bridge::RemoteLoopbackHarness;
        use gaugedesk_workspace::Instance;
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let store = Store::open_in_memory().unwrap();
        let mut wb = crate::Workbench::with_target("inst-test", inst, store);

        // Seed a local session under the chat id, then place it remotely.
        wb.seed_local_session_for_test(
            "c1",
            Box::new(ScriptedTransport::new(Vec::<String>::new())),
        );
        assert!(!wb.is_remote("c1"));

        wb.register_remote_session(
            "c1",
            Box::new(RemoteLoopbackHarness::new(
                "127.0.0.1:7800",
                Vec::<String>::new(),
            )),
        );
        assert!(wb.is_remote("c1"), "now placed remotely");
        assert!(
            !wb.has_local_session_for_test("c1"),
            "the local session was retired"
        );

        let _ = Arc::new(Mutex::new(wb)); // exercises the SharedWorkbench shape
    }
}
