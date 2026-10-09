//! gaugewright harness seam — the adapter-free runtime contract.
//!
//! Home of the neutral types every agent-runtime adapter implements or crosses:
//! the [`Harness`]/[`RemoteHarness`] turn seam (ADR 0031), the [`EgressGate`]
//! mediation chokepoint, the [`Observation`]/[`TurnOutcome`] turn evidence, the
//! [`ImageContent`] content block, and the OS [`sandbox`] (ADR 0030). Adapters
//! depend on this crate for the seam; nothing here is adapter-specific.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

pub mod egress_proxy;
pub mod sandbox;
pub mod sni_proxy;
pub mod testing;

/// The host's egress decision for one tool effect, as the membrane would rule.
/// Decoupled from [`gaugedesk_boundary`] so the bridge depends only on `core`; the
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
    /// Original completed-turn workspace evidence read through the runtime
    /// owner under current access. Absence is uncertified, never an empty diff.
    /// This is evidence for admission, not authority to import or publish files.
    pub runtime_workspace_witness: Option<RuntimeWorkspaceWitness>,
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
    /// The runtime's settled context-window reading: the final main model
    /// call's prompt size, the same number its own compaction trigger reads.
    /// A gauge, never a meter — `managed_usage` sums a turn's calls for
    /// billing; this says how full the window was when the turn settled.
    /// Present on any runtime that reports it, managed or BYOK; `None` where
    /// the runtime published none.
    pub context_reading: Option<ContextWindowReading>,
    pub error: Option<String>,
}

/// Neutral carriage of the owner-verified original workspace cut. The receipt
/// uses the owner's published schema; consumers parse it through that owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeWorkspaceWitness {
    pub receipt_json: String,
    pub writes: Vec<WorkspaceWriteWitness>,
    pub reads: Vec<String>,
}

/// Exact per-file evidence, with the original full SHA-256 and byte length.
/// The native admission boundary must still validate kind, path and current
/// bytes under the original command's authority before admitting a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceWriteWitness {
    pub path: String,
    pub kind: String,
    pub content_hash: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelUsage {
    pub usage_ref: String,
    pub provider: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// One settled context-window reading, carrying the model that read it so the
/// window it is measured against is the window of the model that actually ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextWindowReading {
    pub provider: String,
    pub model: String,
    /// The final main call's prompt tokens, as the provider counted them.
    pub last_input_tokens: u64,
}

/// Adapter-neutral representation of a governed runtime event coordinate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuntimePosition {
    pub instance_ref: String,
    pub sequence: u64,
}

/// Original prepared runtime intent for a product-owned phase. This contains
/// references and input text, never credential secrets or image bytes. It is
/// customer content when retained, and supplies no execution or recovery grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTurnPreparation {
    pub input_digest: String,
    pub command_json: String,
    pub start_position: RuntimePosition,
    pub start_head_digest: String,
    pub workspace_targets: Vec<WorkspaceTargetBinding>,
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
/// it to its runtime's native form.
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

/// One stable target root declared to a runtime process before a turn starts.
/// The host derives this list from the immutable chat target-set revision; a
/// model or tool cannot add an entry by writing a manifest or naming a path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceTargetBinding {
    pub target_id: String,
    pub resource_handle: String,
    pub root: String,
    /// The target's name on the chat's line: the folder the agent sees
    /// instead of `root` (DR-0248). Empty keeps the root visible as itself.
    #[serde(default)]
    pub name: String,
    pub readable: bool,
    pub writable: bool,
    pub output: bool,
}

/// An out-of-band interrupt for a turn in flight, captured at turn start. It is
/// invokable **without the harness**: the workbench mutex is held for the whole
/// turn, so the Stop route can never reach `&self` — it only ever holds a handle
/// registered before the turn blocked.
pub type InterruptHandle = Arc<dyn Fn() + Send + Sync>;

/// A privileged, out-of-band read of the current provider request capture.
/// The product must authorize the person before invoking this handle. A
/// missing capture is reported by the adapter, never reconstructed here.
pub type ModelContextHandle = Arc<dyn Fn() -> std::io::Result<String> + Send + Sync>;

/// Product implementation of a package-declared external tool. The first
/// argument is the durable turn/call identity; a successful return is the
/// tool's receipt and must follow persistence of its effect.
pub type ExternalToolHandler =
    Arc<dyn Fn(&str, &str, &serde_json::Value) -> Result<String, String> + Send + Sync>;

/// Original product authority for one submitted turn. Implementations recheck
/// current access without replacing its captured parent or extending its bounds.
pub trait TurnAccess: Send + Sync {
    fn check_current(&self) -> Result<(), String>;
}

/// Exact owner-prepared file intent. Capture alone does not prove a successful write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedWorkspaceFile {
    pub path: String,
    pub kind: String,
    pub sha256: String,
    pub bytes: u64,
}

/// Custody of prepared bytes under the original product task, before mutation.
pub trait WorkspacePayloadRetention: Send + Sync {
    fn retain(&self, file: &PreparedWorkspaceFile, body: &[u8]) -> Result<(), String>;
}

/// One provider call a runtime has prepared and is about to send on a
/// host-managed (credit-funded) model route. Borrowed correlation only: no
/// credential, header, or response is exposed, and nothing here authorizes
/// the send by itself.
#[derive(Clone, Copy, Debug)]
pub struct ManagedModelCall<'a> {
    /// The runtime command this call belongs to.
    pub command_id: &'a str,
    /// 1-based position of this call within the command. Every call the
    /// runtime makes counts, a compaction summary included, so the pair
    /// `(command_id, ordinal)` names exactly one provider spend.
    pub ordinal: u64,
    pub url: &'a str,
    /// The exact provider request body the runtime built.
    pub body: &'a serde_json::Value,
    /// The most output tokens the runtime asks this call for.
    pub output_limit: u64,
}

/// Holds credit for each managed provider call before it is sent
/// (GaugeWright DR-0203). An error refuses that call, and the runtime sends
/// nothing for it. The product owns settlement; this seam only admits.
pub trait ManagedCallMeter: Send + Sync {
    fn admit_call(&self, call: &ManagedModelCall<'_>) -> Result<(), String>;
}

/// The seam between the admission shell and any agent runtime (DR-0031): drive one
/// turn to a neutral [`TurnOutcome`]. WhippleScript implements this trait.
pub trait Harness: Send {
    /// A line the chat must show before this harness's first turn, taken once.
    /// A runtime that carried the conversation past a turn whose outcome is
    /// unknown says so here (DR-0412), because nothing the model now holds
    /// may read as though it received that turn. The default has none.
    fn take_continuity_notice(&mut self) -> Option<String> {
        None
    }

    /// Refresh the GaugeDesk-authenticated actor for the next turn. Persistent
    /// harnesses must not retain the actor from the turn that created them.
    /// Adapters may use this only for attribution; authentication stays in the
    /// product shell. The default is a no-op for runtimes without human input.
    fn bind_authenticated_actor(&mut self, _actor_ref: &str) {}

    /// Bind a caller-admitted durable command identity to the next turn. Hosted
    /// schedulers use this so crash/retry addresses the same WhippleScript
    /// command and receipt instead of minting a second effect.
    fn bind_runtime_command_id(&mut self, _command_id: Option<&str>) {}

    /// Capture the exact next admitted command and original runtime coordinate
    /// before execution. The shell must retain this through its original task
    /// writer; preparing intent itself admits no work or execution permission.
    fn prepare_runtime_turn(
        &mut self,
        _prompt: &str,
        _images: &[ImageContent],
    ) -> io::Result<RuntimeTurnPreparation> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "runtime preparation unsupported",
        ))
    }

    /// The shell may prepend answer context to this turn's user text. Each
    /// exact answer needs a source handle for the server's current read check;
    /// `None` means the shell cannot attest the full added context.
    fn bind_user_context_provenance(&mut self, _sources: Option<&[String]>) {}

    /// Bind the Home's current, authenticated project-task filing operation for
    /// this turn. The adapter never derives tracker authority from a package.
    fn bind_task_filer(&mut self, _filer: Option<Arc<dyn TaskFiler>>) {}
    /// Bind this turn's target roots, with the names the chat shows them under
    /// (DR-0248). A persistent harness keeps the ones it was created with
    /// unless its adapter rebinds them here.
    fn bind_workspace_targets(
        &mut self,
        _targets: Vec<WorkspaceTargetBinding>,
    ) -> std::io::Result<()> {
        Ok(())
    }
    /// Bind the Home's recorder of target-folder renames for this turn. An
    /// adapter without one refuses every rename.
    fn bind_target_renamer(&mut self, _renamer: Option<Arc<dyn TargetRenamer>>) {}
    fn bind_external_tool_handler(&mut self, _handler: Option<ExternalToolHandler>) {}

    /// Replace the next turn's access check. Unsupported adapters refuse office
    /// work rather than accepting a binding they cannot enforce.
    fn bind_turn_access(&mut self, access: Option<Arc<dyn TurnAccess>>) -> io::Result<()> {
        if access.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "turn access unsupported",
            ));
        }
        Ok(())
    }

    /// Replace the next turn's file custody callback. Unsupported adapters refuse
    /// a required binding. Persistent adapters consume it once per turn.
    fn bind_workspace_payload_retention(
        &mut self,
        retention: Option<Arc<dyn WorkspacePayloadRetention>>,
    ) -> io::Result<()> {
        if retention.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "workspace payload retention unsupported",
            ));
        }
        Ok(())
    }

    /// Meter the next turn's managed provider calls one by one. An adapter
    /// that cannot hold credit before each call refuses a required meter, so
    /// a credit-funded turn never runs unmetered. Consumed once per turn.
    fn bind_managed_call_meter(
        &mut self,
        meter: Option<Arc<dyn ManagedCallMeter>>,
    ) -> io::Result<()> {
        if meter.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this runtime cannot hold credit before each managed model call",
            ));
        }
        Ok(())
    }

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
    /// The out-of-band interrupt for a turn in flight (`None` = nothing to
    /// interrupt). Runtimes with cancellation override this with their own
    /// handle.
    fn interrupt_handle(&self) -> Option<InterruptHandle> {
        None
    }
    fn model_context_handle(&self) -> Option<ModelContextHandle> {
        None
    }
    /// Terminate the harness, consuming it.
    fn shutdown(self: Box<Self>) -> io::Result<()> {
        Ok(())
    }
}

/// A product-authorized operation that returns a tracker issue id only after
/// the issue has committed. Each call id is stable within its turn.
/// Records an agent's rename of a target's folder on the chat's line
/// (DR-0248). `root` is the target's stored root, `targets/t-...`; a refusal
/// refuses the whole command that renamed it, before any file changes.
pub trait TargetRenamer: Send + Sync {
    fn rename_target(&self, root: &str, from: &str, to: &str) -> Result<(), String>;
    /// A rename the Home refused after the command that made it had already
    /// finished, as on a hosted placement that admits a rename itself and
    /// hands it back for ratification (DR-0248). The chat is told; the target
    /// keeps its old name from the next turn.
    fn report_refused(&self, _from: &str, _to: &str, _reason: &str) {}
}

pub trait TaskFiler: Send + Sync {
    fn file_task(
        &self,
        call_id: &str,
        content: &str,
        assigned_to: Option<&str>,
    ) -> Result<String, String>;

    /// Current project readers the model may assign to. Filing checks again at
    /// use, since this projection may change during a turn.
    fn assignable_recipients(&self) -> Vec<(String, String)> {
        Vec::new()
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
    /// The chat's earlier signed epochs, oldest first, as `(epoch, envelope)`.
    /// A chat reopened under a newer epoch opens the runtime its recorded
    /// thread was written under from one of these, so the conversation is
    /// carried forward rather than started again (DR-0412). Empty when the
    /// chat has no earlier epoch.
    pub prior_policy_envelopes: Vec<(u64, String)>,
    /// Typed, non-secret resolver references carried durably by the host command.
    pub provider_binding_ref: Option<String>,
    pub credential_ref: Option<String>,
    pub placement_ceiling_ref: Option<String>,
    /// Complete process-level target I/O declaration for this turn. Empty is
    /// the exact compatibility shape for an archetype edit workspace or a
    /// legacy/test harness with one undivided workspace capability.
    pub workspace_targets: Vec<WorkspaceTargetBinding>,
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
    /// `Some` under the office-controlled healthcare profile: the one approved
    /// inference endpoint this turn may reach. The runtime refuses the turn
    /// rather than reach any other provider, endpoint, model, broker or host.
    /// `None` keeps ordinary provider resolution.
    pub office_inference: Option<OfficeInferenceEndpoint>,
    /// The shell's sandbox POLICY (worktree writable, read-only definition
    /// surface in use mode, provider hosts, egress ack); the adapter EXTENDS it
    /// with any runtime-private needs.
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

/// The office-approved inference endpoint a turn under the office-controlled
/// healthcare profile must reach, and nothing else (HIPAA-2,
/// `specs/experience/office-healthcare.md`).
///
/// It is the exact approved base URL and model, the socket addresses the
/// request may connect to, and — for anything but literal loopback — the trust
/// roots and SHA-256 leaf-certificate pins its TLS identity must present. A
/// runtime that receives one connects only to these addresses, never resolves
/// the host through DNS, never follows a redirect or proxy, and refuses any
/// provider, model, endpoint, broker or managed route that differs from it.
/// It grants no office authority of its own: who may start a turn, and under
/// which original command, is decided elsewhere.
#[derive(Clone, PartialEq, Eq)]
pub struct OfficeInferenceEndpoint {
    pub base_url: String,
    pub model: String,
    pub addresses: Vec<std::net::SocketAddr>,
    /// `None` only for a literal-loopback `http` endpoint.
    pub tls: Option<OfficeTlsIdentity>,
}

/// The approved TLS identity of an office inference endpoint: DER trust roots
/// (used instead of the platform's) and the SHA-256 of each admitted leaf.
#[derive(Clone, PartialEq, Eq)]
pub struct OfficeTlsIdentity {
    pub trust_roots_der: Vec<Vec<u8>>,
    pub certificate_sha256: Vec<[u8; 32]>,
}

impl std::fmt::Debug for OfficeInferenceEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OfficeInferenceEndpoint")
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("addresses", &self.addresses)
            .field("tls", &self.tls.as_ref().map(|_| "[pinned]"))
            .finish()
    }
}

impl std::fmt::Debug for OfficeTlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OfficeTlsIdentity { [pinned] }")
    }
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

/// Inputs for observing an original completed runtime turn. No provider,
/// credential, package or execution capability participates in this path.
pub struct RecordedRuntimeSpec<'a> {
    pub chat_id: &'a str,
    pub command_id: &'a str,
    pub policy_epoch: u64,
    pub signed_policy_envelope: &'a str,
    pub preparation: &'a RuntimeTurnPreparation,
    pub images: &'a [ImageContent],
    pub access: &'a dyn TurnAccess,
}

/// Read-only native evidence for an already verified completed product origin.
/// The product retains its exact pair/phase proof and current reader boundary;
/// these borrowed coordinates alone grant no access or original task authority.
/// Unlike pending recovery, this does not ask a reader to resubmit old images.
/// The synchronous check may borrow the actual thread-confined product writer;
/// no task capability or check can be retained after this observation returns.
pub struct CompletedProductRuntimeSpec<'a> {
    pub chat_id: &'a str,
    pub command_id: &'a str,
    pub policy_epoch: u64,
    pub signed_policy_envelope: &'a str,
    pub preparation: &'a RuntimeTurnPreparation,
    pub access: &'a dyn Fn() -> Result<(), String>,
}

/// Constructs a [`Harness`] per chat from a resolved [`HarnessSpec`] — the
/// construction seam beside the settled [`Harness::run_turn`] contract.
///
/// CONTRACT (membrane, adapter-supplied): each adapter must provide in-process
/// enforcement equivalent to the [`EgressGate`]'s policy — no tool effect may
/// escape the gate's ruling. A runtime that mediates every effect by
/// construction meets it natively (ADR 0071 §3).
pub trait HarnessFactory: Send + Sync {
    /// The adapter's stable id (`"whip"` or `"scripted-fake"`).
    fn kind(&self) -> &'static str;
    fn create(&self, spec: &HarnessSpec) -> io::Result<Box<dyn Harness>>;
    /// Read the original command's policy locator. This is not a verified
    /// envelope or an access grant; observation verifies the selected envelope.
    fn recorded_policy_epoch(&self, _preparation: &RuntimeTurnPreparation) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "original runtime observation unavailable",
        ))
    }
    /// Observe saved evidence only; absence refuses, never executes.
    fn observe_recorded_runtime(&self, _spec: &RecordedRuntimeSpec<'_>) -> io::Result<TurnOutcome> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "original runtime observation unavailable",
        ))
    }

    /// Observe original saved native evidence under a verified completed product
    /// origin. No images, provider, credentials or execution participate.
    fn observe_completed_product_runtime(
        &self,
        _spec: &CompletedProductRuntimeSpec<'_>,
    ) -> io::Result<TurnOutcome> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "completed product runtime observation unavailable",
        ))
    }

    /// Cache the created harness across turns in the workbench's session map?
    /// The scripted fake returns `false` for a fresh harness per turn.
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
    /// Best-effort compensation for a continuity clone that could not be
    /// admitted as a live chat. Implementations with durable per-chat state
    /// must make this idempotent.
    fn discard_continuity(&self, _target: &HarnessContinuitySpec) -> io::Result<()> {
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

/// Witness exact semantic model inputs without retaining image contents.
pub fn runtime_input_digest(prompt: &str, images: &[ImageContent]) -> String {
    use sha2::{Digest, Sha256};
    fn field(hash: &mut Sha256, bytes: &[u8]) {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    let mut hash = Sha256::new();
    hash.update(b"gaugedesk.runtime-input/v1\0");
    field(&mut hash, prompt.as_bytes());
    hash.update((images.len() as u64).to_be_bytes());
    for image in images {
        let kind = match image.kind {
            ImageKind::Image => "image",
        };
        field(&mut hash, kind.as_bytes());
        field(&mut hash, image.mime_type.as_bytes());
        field(&mut hash, image.data.as_bytes());
    }
    format!("sha256:{:x}", hash.finalize())
}

#[cfg(test)]
mod runtime_input_tests {
    use super::*;
    #[test]
    fn witnesses_ordered_model_inputs_and_field_boundaries() {
        let image = ImageContent {
            kind: ImageKind::Image,
            data: "AA==".into(),
            mime_type: "image/png".into(),
        };
        let original = runtime_input_digest("original", std::slice::from_ref(&image));
        assert_eq!(
            original,
            runtime_input_digest("original", std::slice::from_ref(&image))
        );
        assert_ne!(
            original,
            runtime_input_digest("changed", std::slice::from_ref(&image))
        );
        assert_ne!(original, runtime_input_digest("original", &[]));
        let mut other = image.clone();
        other.data = "AQ==".into();
        assert_ne!(original, runtime_input_digest("original", &[other.clone()]));
        assert_ne!(
            runtime_input_digest("original", &[image.clone(), other.clone()]),
            runtime_input_digest("original", &[other.clone(), image.clone()])
        );
        other = image.clone();
        other.mime_type = "image/jpeg".into();
        assert_ne!(original, runtime_input_digest("original", &[other]));
        let a = ImageContent {
            mime_type: "ab".into(),
            data: "c".into(),
            ..image.clone()
        };
        let b = ImageContent {
            mime_type: "a".into(),
            data: "bc".into(),
            ..image
        };
        assert_ne!(
            runtime_input_digest("original", &[a]),
            runtime_input_digest("original", &[b])
        );
        assert!(original.starts_with("sha256:"));
        assert_eq!(original.len(), 71);
    }
}
