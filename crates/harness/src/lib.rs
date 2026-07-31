//! gaugewright harness seam — the adapter-free runtime contract.
//!
//! Home of the neutral types every agent-runtime adapter implements or crosses:
//! the [`Harness`]/[`RemoteHarness`] turn seam (ADR 0031), the [`EgressGate`]
//! mediation chokepoint, the [`Observation`]/[`TurnOutcome`] turn evidence, the
//! [`ImageContent`] content block, and the OS [`sandbox`] (ADR 0030). Adapters
//! (`gaugewright-pi-bridge` is the Pi one) depend on this crate for the seam;
//! nothing here is adapter-specific.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

pub mod egress_proxy;
pub mod sandbox;
pub mod sni_proxy;
pub mod testing;

/// The host's egress decision for one tool effect, as the membrane would rule.
/// Decoupled from [`gaugewright_boundary`] so the bridge depends only on `core`; the
/// orchestrator supplies the concrete membrane-backed gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateDecision {
    /// Mediate and execute — record it as a boundary egress.
    Allow,
    /// Block the effect; it does not happen.
    Block(String),
    /// Hold pending an explicit grant (surfaced as a pending approval).
    Stage(String),
}

/// The egress chokepoint the bridge consults for every tool effect. `target` is
/// the path/url the tool acts on (when it reports one), so the gate can rule on
/// *where* an effect lands — e.g. the method-definition write-gate (INV-24).
pub trait EgressGate {
    fn classify_tool(&self, tool: &str, target: Option<&str>) -> GateDecision;
}

/// Trust-everything gate — only for tests / a membrane-free smoke run.
pub struct AllowAllGate;
impl EgressGate for AllowAllGate {
    fn classify_tool(&self, _tool: &str, _target: Option<&str>) -> GateDecision {
        GateDecision::Allow
    }
}

/// One operational runtime-session observation (not yet run truth).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Observation {
    pub kind: &'static str,
    pub detail: String,
    /// Structured tool metadata for tool-execution observations, so the B4 tool
    /// line can show `▸ {tool} {target}`, expand to args + result, and open the
    /// target in the content viewer. `None` for text/progress/approval lines.
    pub tool: Option<ToolInfo>,
}

/// The structured shape behind a tool-execution observation (B4 tool line).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub call_id: String,
    /// What the tool acts on (file, command, url) — the clickable target.
    pub target: Option<String>,
    /// The call's arguments as compact JSON, for the expanded view.
    pub args: String,
    /// `Some(true)` ok / `Some(false)` errored, once the tool has ended.
    pub ok: Option<bool>,
    /// A truncated digest of the tool's output, for the expanded view.
    pub result: Option<String>,
}

/// What one turn produced: the final assistant text, the operational
/// observations, the boundary-mediated tool calls, and any surfaced approval
/// prompts. The caller (admission shell) decides what to admit into run truth.
#[derive(Debug, Default)]
pub struct TurnOutcome {
    pub assistant_text: String,
    pub observations: Vec<Observation>,
    pub mediated_tool_calls: Vec<String>,
    pub pending_approvals: Vec<String>,
    /// Questions the agent asked this turn (ADR 0113). Collected here rather
    /// than written during the turn because the engine holds the store across
    /// `run_turn`; the same reason `pending_approvals` rides the outcome. The
    /// engine persists them once the turn settles.
    pub asked_questions: Vec<AskedQuestion>,
    /// Serialized values from the runtime's own published pointer schema.
    /// These name authoritative evidence; they never contain evidence bodies.
    pub runtime_evidence_pointers: Vec<String>,
    /// Runtime-certified per-field resource dependencies for the host-visible
    /// output projection. Empty only for legacy/test adapters that do not
    /// publish an IFC signature.
    pub output_flow_signature: Vec<OutputFieldFlow>,
    /// Runtime-certified dynamic guarantee outcomes from the turn's guarantee
    /// report (WhippleScript DR-0036 §2). Empty for adapters that publish no
    /// report — consumers fall back to host-local truth (ADR 0082 §5).
    pub guarantee_outcomes: Vec<GuaranteeOutcome>,
    /// Exact WhippleScript event coordinates bracketing this turn. Governed
    /// adapters populate these so a transcript point can reproduce runtime
    /// continuity rather than merely cloning the latest thread state.
    pub runtime_start_position: Option<RuntimePosition>,
    pub runtime_terminal_position: Option<RuntimePosition>,
    /// A narrow product-metering projection published by the governed runtime.
    /// `usage_ref` points back to the runtime-owned evidence body.
    pub managed_usage: Option<ModelUsage>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelUsage {
    pub usage_ref: String,
    pub provider: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// Adapter-neutral representation of a governed runtime event coordinate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuntimePosition {
    pub instance_ref: String,
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputFieldFlow {
    pub field: String,
    pub read_handles: Vec<String>,
}

/// One dynamic guarantee outcome from the runtime's guarantee report
/// (DR-0036 §2): a **named**, per-turn certified fact — `held` / `violated` /
/// `not_evaluated`. Consumers match names; they never re-evaluate semantics.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuaranteeOutcome {
    pub name: String,
    pub outcome: String,
    pub detail: String,
}

impl GuaranteeOutcome {
    /// Parse a guarantee report's `dynamic` section. Total: an absent or
    /// malformed section yields no outcomes — consumers fall back to local truth.
    pub fn from_report(report: &serde_json::Value) -> Vec<Self> {
        report
            .get("dynamic")
            .and_then(|d| d.as_array())
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| {
                        Some(Self {
                            name: entry.get("name")?.as_str()?.to_string(),
                            outcome: entry.get("outcome")?.as_str()?.to_string(),
                            detail: entry
                                .get("detail")
                                .and_then(|d| d.as_str())
                                .unwrap_or_default()
                                .to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// One question an agent asked during a turn, before the engine files it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AskedQuestion {
    pub question: String,
    #[serde(default)]
    pub choices: Vec<String>,
    /// Who should answer. `None` means the chat owner.
    #[serde(default)]
    pub to: Option<String>,
    /// The agent declaring it cannot usefully proceed without an answer.
    #[serde(default)]
    pub blocking: bool,
}

/// The fixed `"image"` tag on an image content block. A one-variant enum so the
/// `type` field always serializes to exactly `"image"`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImageKind {
    #[serde(rename = "image")]
    Image,
}

fn default_image_kind() -> ImageKind {
    ImageKind::Image
}

/// A neutral image content block: `{ "type":"image", "data":<base64>, "mimeType":… }`
/// — generic base64 + mime. This serde shape is **frozen** as the blessed
/// content-block wire (it is part of the public HTTP contract); each adapter maps
/// it to its runtime's native form (the Pi adapter sends it verbatim over RPC,
/// verified against `@mariozechner/pi-ai` 0.73).
///
/// These are **message-scoped model input**: the base64 bytes are sent to the
/// runtime but must never be written to the durable transcript / event log
/// (`INV-10`, content-behind-handles). The web client sends `{ data, mimeType }`;
/// the `type` tag defaults in so callers don't have to repeat it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageContent {
    #[serde(rename = "type", default = "default_image_kind")]
    pub kind: ImageKind,
    /// Base64-encoded image bytes (no data-URL prefix).
    pub data: String,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
}

/// A chat's **kind**, derived from its root object (ADR 0035): a chat rooted on
/// an archetype (its authoring instance) is an **edit** chat (improve the method);
/// a chat rooted on a placement (a using instance) is a **work** chat (do the
/// job). This is no longer a stored field/toggle — it is read from the chat's
/// instance kind. The enum survives because the engine's membrane is keyed off it
/// (`Edit` ⇒ editor persona + write-gate open; `Use`/work ⇒ method read-only).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum ChatMode {
    #[default]
    Use,
    /// Serialized as `"edit"`. Accepts the legacy `"build"` so chat records
    /// persisted before the build→edit rename still deserialize.
    #[serde(alias = "build")]
    Edit,
}

/// An out-of-band interrupt for a turn in flight, captured at turn start. It is
/// invokable **without the harness**: the workbench mutex is held for the whole
/// turn, so the Stop route can never reach `&self` — it only ever holds a handle
/// registered before the turn blocked.
pub type InterruptHandle = Arc<dyn Fn() + Send + Sync>;

/// The seam between the admission shell and any agent runtime (ADR 0031): drive one
/// turn → a neutral [`TurnOutcome`]. Pi is one adapter ([`PiProcess`]); Codex /
/// Claude Code are future adapters — each only implements this trait.
pub trait Harness: Send {
    /// Refresh the GaugeDesk-authenticated actor for the next turn. Persistent
    /// harnesses must not retain the actor from the turn that created them.
    /// Adapters may use this only for attribution; authentication stays in the
    /// product shell. The default is a no-op for runtimes without human input.
    fn bind_authenticated_actor(&mut self, _actor_ref: &str) {}

    /// Bind a caller-admitted durable command identity to the next turn. Hosted
    /// schedulers use this so crash/retry addresses the same WhippleScript
    /// command and receipt instead of minting a second effect.
    fn bind_runtime_command_id(&mut self, _command_id: Option<&str>) {}

    /// Deliver `prompt` (+ any native `images` for this turn), mediate every tool
    /// call through `gate`, stream each [`Observation`] to `sink`, and return the
    /// neutral outcome. `images` are model input only — never durable evidence.
    fn run_turn(
        &mut self,
        gate: &dyn EgressGate,
        prompt: &str,
        images: &[ImageContent],
        sink: &mut dyn FnMut(&Observation),
    ) -> io::Result<TurnOutcome>;
    /// The OS pid of an underlying process, if any. Legacy: survives only to
    /// feed the default [`interrupt_handle`](Harness::interrupt_handle);
    /// retired with the Pi adapter.
    fn process_id(&self) -> Option<u32> {
        None
    }
    /// The out-of-band interrupt for a turn in flight (`None` = nothing to
    /// interrupt). Default: derived from [`process_id`](Harness::process_id) —
    /// the same `kill -KILL <pid>` the Stop route used to perform against the
    /// pid registry (SIGKILL is reliable; a runtime may ignore TERM mid-stream).
    /// A pid-less harness (in-process, remote) overrides this with its own
    /// cancel, so Stop is never silently impossible.
    fn interrupt_handle(&self) -> Option<InterruptHandle> {
        let pid = self.process_id()?;
        Some(Arc::new(move || {
            let _ = std::process::Command::new("kill")
                .arg("-KILL")
                .arg(pid.to_string())
                .status();
        }))
    }
    /// Terminate the harness, consuming it.
    fn shutdown(self: Box<Self>) -> io::Result<()> {
        Ok(())
    }
}

/// A [`Harness`] that runs in a *different* trust authority, reached over the
/// federation relay rather than as a local subprocess (ADR 0020/0031). It is the
/// same turn seam as a local `Harness`; the only extra fact is *where* it lives —
/// [`address`](RemoteHarness::address), the peer endpoint the RPC transport dials.
/// `PROTO-1`/`REMOTE-RPC-1` attach the real loopback-RPC transport behind this
/// seam; the cross-NAT relay (`RENDEZVOUS-STUB-1`) attaches later with no
/// rearchitecture.
pub trait RemoteHarness: Harness {
    /// The peer endpoint this remote harness is reached at (e.g. a loopback
    /// `host:port`, later a relay/SNI address). The local orchestrator never
    /// resolves it itself — it hands it to the relay.
    fn address(&self) -> &str;
}

/// Everything the shell resolves (**policy**) before a turn; the adapter owns
/// the rest (its runtime config, session continuity, sandbox extensions).
#[derive(Clone, Debug)]
pub struct HarnessSpec {
    pub chat_id: String,
    /// The chat workspace's materialized directory — a real on-disk dir usable
    /// as the harness cwd for the life of the chat (the `ChatWorkspace::path()`
    /// guarantee any workspace impl must honor).
    pub worktree: PathBuf,
    pub mode: ChatMode,
    /// Exact authored WhippleScript package directory selected by GaugeDesk for
    /// a work chat. Edit chats select GaugeDesk's built-in editor package.
    pub package_root: Option<PathBuf>,
    /// Content-addressed WhippleScript package reference admitted at publish and
    /// pinned by the placement. The runtime refuses different bytes at this path.
    pub package_version_ref: Option<String>,
    /// Immutable WhippleScript governance epoch and signed envelope compiled by
    /// the product authority. Required by the real WhippleScript adapter; absent
    /// only for test/legacy adapters that do not consume the host protocol.
    pub policy_epoch: Option<u64>,
    pub signed_policy_envelope: Option<String>,
    /// Typed, non-secret resolver references carried durably by the host command.
    pub provider_binding_ref: Option<String>,
    pub credential_ref: Option<String>,
    pub placement_ceiling_ref: Option<String>,
    /// Product placement identity used only to address a remote host. This is
    /// distinct from the governed placement-ceiling handle above.
    pub runtime_placement_id: Option<String>,
    /// Resolved by the shell (env ▸ config ▸ default). `None` leaves the
    /// adapter's own default resolution in force (the federation peer path
    /// deliberately keeps provider/model unset).
    pub provider: Option<String>,
    pub model: Option<String>,
    /// The OpenAI-compatible endpoint base URL for an **endpoint-configurable**
    /// provider (`openai-generic`, ADR 0083), resolved from the linked
    /// credential. `None` leaves the provider's fixed compile-time endpoint in
    /// force (every other provider). The runtime derives the admitted egress
    /// host from this and fixes the request URL to it (ADR 0080).
    pub base_url: Option<String>,
    pub thinking: Option<String>,
    /// `Some` in edit mode (the built-in editor package persona). Work chats
    /// leave this unset because persona is immutable package content.
    pub system_prompt: Option<String>,
    /// Reference-bound provider material for native governed runtimes. Secret
    /// bytes are released only for the exact admitted `credential_ref`.
    pub credential_capability: Option<Arc<dyn CredentialCapability>>,
    /// Legacy Pi compatibility only. Foreground GaugeDesk turns leave this
    /// empty; it retires with the Pi adapter.
    pub credentials: Vec<(String, String)>,
    /// The shell's sandbox POLICY (worktree writable, read-only definition
    /// surface in use mode, provider hosts, egress ack); the adapter EXTENDS it
    /// with adapter-private needs (e.g. Pi's session dir + `~/.pi`).
    pub sandbox: sandbox::SandboxPolicy,
    /// Who this agent may name, as `(authority, who they are)` (`GATE-3f`).
    /// Offered on the `ask` tool so the choice of a person is made from a list
    /// rather than guessed; the host still resolves and may still refuse, since a
    /// roster can change between a turn being prepared and the call arriving.
    /// Empty is valid — an environment with no directory offers no choice.
    pub roster: Vec<(String, String)>,
}

/// Runtime continuity identity at a chat fork. This intentionally carries only
/// package/context inputs; credentials, provider selection, and workspace
/// authority are resolved afresh when the fork runs its first turn.
#[derive(Clone, Debug)]
pub struct HarnessContinuitySpec {
    pub chat_id: String,
    /// Product placement identity used to address a hosted runtime. Native
    /// adapters ignore it; cross-placement hosts must bind source and target to
    /// the same admitted placement before transferring continuity.
    pub runtime_placement_id: Option<String>,
    pub worktree: PathBuf,
    pub mode: ChatMode,
    pub package_root: Option<PathBuf>,
    pub package_version_ref: Option<String>,
    pub system_prompt: Option<String>,
    /// The already-published source policy epoch governing the continuity
    /// transaction. A target compiles its own current policy before its first
    /// turn; the fork itself remains attributable to this immutable source cut.
    pub policy_epoch: Option<u64>,
    pub signed_policy_envelope: Option<String>,
    /// When present, fork this exact source event rather than the source
    /// instance's current head.
    pub source_position: Option<RuntimePosition>,
}

/// An adapter's answer to "is the runtime's own credential state ready for this
/// provider?" ([`HarnessFactory::credential_status`]). The shell keeps the
/// fail-closed precheck POLICY — whether and when a turn is refused — the
/// adapter only reports its own store's state, with an actionable user-facing
/// reason when nothing usable is present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialProbe {
    /// A usable credential resolves in the adapter's own store.
    Ready,
    /// Nothing usable — the actionable, user-facing reason.
    Missing(String),
}

/// Provider material released by a GaugeDesk-owned credential capability.
/// Fields are private and its `Debug` representation is redacted.
#[derive(Clone)]
pub struct CredentialMaterial {
    secret: String,
    account_id: Option<String>,
}

impl CredentialMaterial {
    pub fn new(secret: impl Into<String>, account_id: Option<String>) -> Self {
        Self {
            secret: secret.into(),
            account_id,
        }
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }
}

impl std::fmt::Debug for CredentialMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialMaterial")
            .field("secret", &"[REDACTED]")
            .field(
                "account_id",
                &self.account_id.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// A non-serializable capability over GaugeDesk-custodied provider material.
/// Implementations reject every reference except the exact value returned by
/// [`CredentialCapability::credential_ref`].
pub trait CredentialCapability: Send + Sync + std::fmt::Debug {
    fn credential_ref(&self) -> &str;
    fn resolve(&self, credential_ref: &str) -> io::Result<CredentialMaterial>;
}

/// Constructs a [`Harness`] per chat from a resolved [`HarnessSpec`] — the
/// construction seam beside the settled [`Harness::run_turn`] contract.
///
/// CONTRACT (membrane, adapter-supplied): each adapter must provide in-process
/// enforcement equivalent to the [`EgressGate`]'s policy — no tool effect may
/// escape the gate's ruling. Pi meets it with its in-process plugin + the OS
/// [`sandbox`]; a runtime that mediates every effect by construction meets it
/// natively (ADR 0071 §3).
pub trait HarnessFactory: Send + Sync {
    /// The adapter's stable id (`"pi"`, `"scripted-fake"`, later `"whip"`).
    fn kind(&self) -> &'static str;
    fn create(&self, spec: &HarnessSpec) -> io::Result<Box<dyn Harness>>;
    /// Cache the created harness across turns in the workbench's session map?
    /// Pi: `true` (one persistent subprocess per chat). The scripted fake:
    /// `false` (today's fresh-transport-per-turn behavior, preserved exactly).
    fn reuse_across_turns(&self) -> bool {
        true
    }
    /// Fork per-chat continuity state into a distinct runtime identity. Package
    /// and prompt inputs are explicit; credentials and provider bindings are
    /// deliberately absent and must be resolved afresh on the target's turn.
    /// Default: no continuity state.
    fn clone_continuity(
        &self,
        _source: &HarnessContinuitySpec,
        _target: &HarnessContinuitySpec,
    ) -> io::Result<()> {
        Ok(())
    }
    /// Adapter-answerable credential probe: is the runtime's own credential
    /// state ready for `provider`? Native governed adapters receive only the
    /// exact-reference capability selected for this turn.
    fn credential_status(
        &self,
        provider: &str,
        capability: Option<&dyn CredentialCapability>,
    ) -> CredentialProbe;
}

// Compile-time proof the factory seam stays object-safe — the shell selects a
// factory per turn and holds it as `Arc<dyn HarnessFactory>`.
const _: fn(&dyn HarnessFactory) = |_| {};

#[cfg(test)]
mod tests {
    use super::*;

    /// The default interrupt handle derives strictly from `process_id`: a
    /// pid-backed harness is interruptible, a pid-less one reports `None`
    /// (Stop stays a clean no-op) unless it overrides with its own cancel.
    #[test]
    fn default_interrupt_handle_derives_from_process_id() {
        struct WithPid;
        impl Harness for WithPid {
            fn run_turn(
                &mut self,
                _gate: &dyn EgressGate,
                _prompt: &str,
                _images: &[ImageContent],
                _sink: &mut dyn FnMut(&Observation),
            ) -> io::Result<TurnOutcome> {
                unreachable!("not driven in this test")
            }
            fn process_id(&self) -> Option<u32> {
                Some(4242)
            }
        }
        struct PidLess;
        impl Harness for PidLess {
            fn run_turn(
                &mut self,
                _gate: &dyn EgressGate,
                _prompt: &str,
                _images: &[ImageContent],
                _sink: &mut dyn FnMut(&Observation),
            ) -> io::Result<TurnOutcome> {
                unreachable!("not driven in this test")
            }
        }
        assert!(WithPid.interrupt_handle().is_some());
        assert!(PidLess.interrupt_handle().is_none());
    }
}
