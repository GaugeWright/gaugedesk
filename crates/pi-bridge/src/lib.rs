//! gaugewright Pi bridge — the runtime adapter.
//!
//! Spawns and drives `pi --mode rpc` as **one subprocess per engagement**,
//! hosting the engagement's persistent Pi thread across turns (`pi-rpc.md`). Each
//! turn is a `prompt`; the bridge folds Pi's event stream into the pure
//! [`gaugedesk_core::runtime_session`] reducer so the model's invariants govern the
//! adapter:
//! - every streamed event is **operational runtime-session evidence** only — the
//!   bridge never admits it into run truth (`OBSERVATION_REQUIRES_OWNER_ADMISSION`
//!   stays the admission shell's job);
//! - every tool call routes through `requestBoundaryEgress` before it counts —
//!   there is no unmediated effect path (`EGRESS_REQUIRES_BOUNDARY`);
//! - the turn ends at `agent_end` via `terminalOutcome`, preserving evidence.
//!
//! The transport is abstracted ([`RpcTransport`]) so the event→observation→reducer
//! mapping — the part the spec's Build Checks pin — is tested without live model
//! calls; the real [`PiProcess`] is a thin stdio wrapper over the child.

use std::io::{self, BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command as ProcCommand, Stdio};

use gaugedesk_core::runtime_session::{decide, evolve, SessionCommand, SessionState};

pub mod protocol;
/// The seam types live in `gaugedesk-harness` (SUB-0); re-exported here at
/// their pre-extraction paths so existing callers keep compiling unchanged.
pub use gaugedesk_harness::{
    sandbox, AllowAllGate, ContextWindowReading, EgressGate, GateDecision, Harness, ModelUsage,
    Observation, RemoteHarness, ToolInfo, TurnOutcome,
};
use gaugedesk_harness::{
    ChatMode, CredentialProbe, HarnessContinuitySpec, HarnessFactory, HarnessSpec,
};
/// Native Pi image content block, re-exported for the engine + control plane that
/// thread it from the HTTP task body into the turn.
pub use protocol::ImageContent;
use protocol::{Command, Line};

/// A line-delimited JSON transport to a Pi RPC peer.
pub trait RpcTransport {
    /// Send one command line (no trailing newline; the transport adds it).
    fn send(&mut self, line: &str) -> io::Result<()>;
    /// Receive the next line, or `None` at end of stream.
    fn recv(&mut self) -> io::Result<Option<String>>;
    /// The tail of Pi's stderr captured so far, if any. Pi's RPC channel reports a
    /// provider error (rate limit / quota / auth / a crash) as a clean empty turn or
    /// an abrupt EOF; the human-readable reason is on **stderr**. Capturing it lets a
    /// failed turn surface *why* instead of an opaque "stream ended". `None` for
    /// transports with no stderr (the mock/scripted transports).
    fn stderr_tail(&self) -> Option<String> {
        None
    }
}

/// Drive one turn over `transport`, folding Pi's events into `session`.
///
/// `session` must already be `executing` (the admission shell admitted
/// `startRuntimeSession` first, per the preconditions). Returns the turn outcome;
/// on return `session` has advanced through `terminalOutcome`.
pub fn run_turn<T: RpcTransport, G: EgressGate + ?Sized>(
    transport: &mut T,
    session: &mut SessionState,
    gate: &G,
    prompt: &str,
    images: &[ImageContent],
) -> io::Result<TurnOutcome> {
    run_turn_streaming(transport, session, gate, prompt, images, &mut |_| {})
}

/// As [`run_turn`], but `sink` is called with each [`Observation`] **as it is
/// produced** — the seam the control plane uses to fan a turn's tokens and tool
/// decisions onto the live event stream.
///
/// `images` are native Pi image content blocks for this turn (empty for a plain
/// text turn) — sent to Pi as model input, never recorded in the durable log.
pub fn run_turn_streaming<T: RpcTransport, G: EgressGate + ?Sized>(
    transport: &mut T,
    session: &mut SessionState,
    gate: &G,
    prompt: &str,
    images: &[ImageContent],
    sink: &mut dyn FnMut(&Observation),
) -> io::Result<TurnOutcome> {
    let mut outcome = TurnOutcome::default();

    // A dead/unreachable child is a **turn outcome**, not a transport `Err`
    // (RF-C5 finding): returning `Err` here would propagate out of the engine
    // *before* `FailRun` is admitted, stranding the run lifecycle mid-flight
    // (an INV-23 stuck state). Reporting it as `outcome.error` routes it
    // through the engine's normal failure path instead.
    if let Err(e) = transport.send(
        &Command::Prompt {
            message: prompt.to_string(),
            images: images.to_vec(),
        }
        .to_line(),
    ) {
        outcome.error = Some(format!("pi send failed: {e}"));
        apply(session, SessionCommand::TerminalOutcome);
        return Ok(outcome);
    }

    let mut text = String::new();

    loop {
        let raw = match transport.recv() {
            Ok(Some(raw)) => raw,
            Ok(None) => {
                let tail = transport.stderr_tail();
                outcome.error.get_or_insert_with(|| match tail {
                    Some(t) => format!("pi stream ended before agent_end — stderr: {t}"),
                    None => "pi stream ended before agent_end".into(),
                });
                break;
            }
            // Same rationale as the send: a mid-stream io error terminates the
            // turn as a reported failure, never an abandoned run.
            Err(e) => {
                outcome
                    .error
                    .get_or_insert_with(|| format!("pi stream error: {e}"));
                break;
            }
        };
        let line = match Line::parse(&raw) {
            Ok(l) => l,
            Err(_) => continue, // ignore unparseable noise on the stream
        };

        match line {
            Line::TextDelta { delta } => {
                text.push_str(&delta);
                record(session, &mut outcome, sink, "text", delta);
            }
            // The model's streamed tokens arrive nested under message_update.
            Line::MessageUpdate {
                assistant_message_event,
            } => {
                if let Some(ev) = assistant_message_event {
                    if ev.kind == "text_delta" {
                        if let Some(delta) = ev.delta {
                            text.push_str(&delta);
                            record(session, &mut outcome, sink, "text", delta);
                        }
                    }
                }
            }
            Line::ToolExecutionStart {
                tool_name,
                call_id,
                args,
            } => {
                // Distil the structured tool line: target (clickable) + compact args.
                let target = protocol::tool_target(&args);
                let info = |ok| ToolInfo {
                    name: tool_name.clone(),
                    call_id: call_id.clone(),
                    target: target.clone(),
                    args: args.to_string(),
                    ok,
                    result: None,
                };
                // The membrane is the chokepoint: classify the effect (and where it
                // lands) first.
                match gate.classify_tool(&tool_name, target.as_deref()) {
                    // EGRESS_REQUIRES_BOUNDARY: an allowed effect counts only as a
                    // boundary-mediated egress request through the reducer.
                    GateDecision::Allow
                        if apply(session, SessionCommand::RequestBoundaryEgress) =>
                    {
                        outcome.mediated_tool_calls.push(tool_name.clone());
                        emit(
                            &mut outcome,
                            sink,
                            Observation {
                                kind: "egress",
                                detail: format!("tool {tool_name} mediated by boundary"),
                                tool: Some(info(None)),
                            },
                        );
                    }
                    GateDecision::Allow => {
                        emit(
                            &mut outcome,
                            sink,
                            Observation {
                                kind: "egress_blocked",
                                detail: format!("tool {tool_name} blocked: no boundary mediation"),
                                tool: Some(info(Some(false))),
                            },
                        );
                    }
                    GateDecision::Block(reason) => {
                        emit(
                            &mut outcome,
                            sink,
                            Observation {
                                kind: "egress_blocked",
                                detail: format!("tool {tool_name} blocked by membrane: {reason}"),
                                tool: Some(info(Some(false))),
                            },
                        );
                    }
                    GateDecision::Stage(reason) => {
                        outcome
                            .pending_approvals
                            .push(format!("tool {tool_name}: {reason}"));
                        emit(
                            &mut outcome,
                            sink,
                            Observation {
                                kind: "egress_staged",
                                detail: format!("tool {tool_name} staged: {reason}"),
                                tool: Some(info(None)),
                            },
                        );
                    }
                }
            }
            Line::ToolExecutionEnd {
                call_id,
                result,
                is_error,
            } => {
                // The ✓/✗ and output for the matching tool line (correlated by id).
                apply(session, SessionCommand::RecordRuntimeObservation);
                emit(
                    &mut outcome,
                    sink,
                    Observation {
                        kind: "tool_result",
                        detail: if is_error {
                            "tool errored".into()
                        } else {
                            "tool ok".into()
                        },
                        tool: Some(ToolInfo {
                            call_id,
                            ok: Some(!is_error),
                            result: protocol::result_summary(&result),
                            ..Default::default()
                        }),
                    },
                );
            }
            Line::TurnStart | Line::TurnEnd | Line::AgentStart => {
                record(session, &mut outcome, sink, "progress", format!("{line:?}"));
            }
            Line::ExtensionUiRequest { id, method, title } => {
                // A5b: surfaced as a pending approval; answered out-of-band by a
                // resource-access / resource-export grant, not auto-confirmed here.
                outcome
                    .pending_approvals
                    .push(format!("{method}:{title} ({id})"));
                record(
                    session,
                    &mut outcome,
                    sink,
                    "approval",
                    format!("{method}: {title}"),
                );
            }
            Line::Error { error } => {
                outcome.error = error.or_else(|| Some("pi error".into()));
            }
            Line::AgentEnd => break, // turn complete; subprocess persists
            Line::Response { .. } | Line::Other => {}
        }
    }

    // Fetch the authoritative final assistant text (robust to partial deltas).
    // Best-effort: on a dead child this fails with EPIPE/EOF — keep the
    // streamed text and the already-recorded turn error rather than turning a
    // finished turn into a transport `Err` (the stranded-run hazard above).
    if let Ok(Some(raw)) = transport
        .send(&Command::GetLastAssistantText.to_line())
        .and_then(|()| transport.recv())
    {
        if let Ok(Line::Response {
            command,
            success,
            data,
            ..
        }) = Line::parse(&raw)
        {
            if command == "get_last_assistant_text" && success {
                if let Some(t) = data.get("text").and_then(|v| v.as_str()) {
                    text = t.to_string();
                }
            }
        }
    }
    outcome.assistant_text = text;

    // A no-op turn — the model produced no text and the agent ran no tools and asked for
    // nothing — is almost always a **swallowed provider error**: Pi's RPC mode reports a
    // rate-limit / quota / auth failure as a clean, empty turn (the human-readable reason
    // is on Pi's stderr, not the RPC channel). Surface it as the turn's error instead of
    // a silent "agent finished this turn" (LLM-1, ADR 0062).
    if outcome.error.is_none()
        && outcome.assistant_text.trim().is_empty()
        && outcome.mediated_tool_calls.is_empty()
        && outcome.pending_approvals.is_empty()
    {
        let base = "The model returned no response — this usually means a provider error (rate \
             limit, quota, or expired credentials). Try again, switch the model in the \
             composer, or check your plan.";
        outcome.error = Some(match transport.stderr_tail() {
            Some(t) => format!("{base} (pi stderr: {t})"),
            None => base.to_string(),
        });
    }

    // agent_end ends the *turn*: terminalOutcome, preserving evidence.
    apply(session, SessionCommand::TerminalOutcome);
    Ok(outcome)
}

/// Fold one command into the session via the pure reducer; report admission.
fn apply(session: &mut SessionState, command: SessionCommand) -> bool {
    match decide(session, command) {
        Ok(events) => {
            for e in events {
                *session = evolve(session, e);
            }
            true
        }
        Err(_) => false,
    }
}

/// Push an observation onto the outcome and fan it to the live `sink` at once.
fn emit(outcome: &mut TurnOutcome, sink: &mut dyn FnMut(&Observation), obs: Observation) {
    sink(&obs);
    outcome.observations.push(obs);
}

/// A streamed event is operational evidence: record it on the runtime-session
/// (never admit it into run truth — that is the owning shell's decision).
fn record(
    session: &mut SessionState,
    outcome: &mut TurnOutcome,
    sink: &mut dyn FnMut(&Observation),
    kind: &'static str,
    detail: String,
) {
    apply(session, SessionCommand::RecordRuntimeObservation);
    emit(
        outcome,
        sink,
        Observation {
            kind,
            detail,
            tool: None,
        },
    );
}

/// Spawn options for the per-engagement Pi subprocess.
/// Seed a runtime-session to `executing` — the admission-shell precondition before
/// a turn drives (the verified runtime-session reducer; `pi-rpc.md`).
pub fn prepared_executing_session() -> SessionState {
    let mut s = SessionState::default();
    for c in [
        SessionCommand::AdmitRun,
        SessionCommand::StartBoundarySession,
        SessionCommand::GrantBases,
        SessionCommand::PrepareRuntimeSession,
        SessionCommand::StartRuntimeSession,
    ] {
        if let Ok(events) = decide(&s, c) {
            for e in events {
                s = evolve(&s, e);
            }
        }
    }
    s
}

/// Drive one turn over any line-delimited RPC transport: seed the session, run the
/// turn loop. The default `Harness::run_turn` for RPC-style adapters (Pi, scripted).
pub fn run_rpc_turn<T: RpcTransport>(
    transport: &mut T,
    gate: &dyn EgressGate,
    prompt: &str,
    images: &[ImageContent],
    sink: &mut dyn FnMut(&Observation),
) -> io::Result<TurnOutcome> {
    let mut session = prepared_executing_session();
    run_turn_streaming(transport, &mut session, gate, prompt, images, sink)
}

/// Loopback `RemoteHarness` that drives turns over the `PROTO-1` RPC **envelope**
/// (`REMOTE-RPC-1`), not the local Pi-wire transport. A turn no longer runs in the
/// caller's process: it is serialized as one [`RpcRequest::RunTurn`] line, shipped
/// over the (in-process) loopback wire to a [`peer`](LoopbackPeer) that owns the
/// agent runtime, and the agent's [`TurnOutcome`] comes back as one
/// [`RpcResponse::TurnComplete`] line. The orchestrator side then sequences the
/// exchange through the verified [`remote_session`](gaugedesk_core::remote_session)
/// reducer, so the returned outcome becomes the caller's truth **only via source
/// admission** (`OUTCOME_REQUIRES_SOURCE_ADMISSION`, `INV-4`) — the relay's
/// say-so never suffices.
///
/// This is still single-process (ADR 0020 loopback-first): the "wire" is a
/// `String` round-trip, and the peer replays scripted Pi lines instead of calling
/// a model. The cross-NAT relay (`RENDEZVOUS-STUB-1`) attaches behind the same
/// envelope with no rearchitecture — the request/response bytes never change.
pub struct RemoteLoopbackHarness {
    address: String,
    peer: LoopbackPeer,
}

/// The peer side of the loopback RPC: it owns the agent runtime (here a scripted
/// Pi transport) and answers one [`RpcRequest`] line with one [`RpcResponse`]
/// line. On a real deployment this lives in a different trust authority reached
/// over the relay; on loopback it lives in the same process behind the same bytes.
struct LoopbackPeer {
    lines: Vec<String>,
}

impl LoopbackPeer {
    /// Serve one request line: parse the envelope, run the turn on the peer's own
    /// runtime (mediating effects through the peer's `gate`), and return the
    /// response line. The orchestrator never sees the peer's Pi-wire bytes — only
    /// the `PROTO-1` envelope crosses the boundary.
    fn serve(&self, gate: &dyn EgressGate, request_line: &str) -> io::Result<String> {
        let req = protocol::remote::RpcRequest::parse(request_line)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let protocol::remote::RpcRequest::RunTurn { prompt } = req;
        // The peer streams to its *own* sink — the orchestrator can't see the
        // peer's live Pi stream across the boundary; only the envelope's
        // `WireTurnOutcome` crosses back. The orchestrator re-streams those
        // observations from the envelope on the far side.
        let mut transport = ScriptedTransport::new(self.lines.iter().cloned());
        // The PROTO-1 remote wire does not carry images yet — remote turns are
        // text-only (image attachments are a local-turn feature for now).
        let outcome = run_rpc_turn(&mut transport, gate, &prompt, &[], &mut |_| {})?;
        Ok(protocol::remote::RpcResponse::turn_complete(&outcome).to_line())
    }
}

impl RemoteLoopbackHarness {
    /// A loopback remote harness at `address`, whose peer replays `lines` as the
    /// agent's turn output (the same scripting the local fake-agent path uses).
    pub fn new<I, S>(address: impl Into<String>, lines: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            address: address.into(),
            peer: LoopbackPeer {
                lines: lines.into_iter().map(Into::into).collect(),
            },
        }
    }
}

impl Harness for RemoteLoopbackHarness {
    /// Drive one turn across the `PROTO-1` envelope and sequence it through the
    /// `remote_session` reducer. The caller's process ships an `RpcRequest`, the
    /// peer runs the turn and returns an `RpcResponse`, and the recovered outcome
    /// is admitted into the caller's truth only after the reducer reaches
    /// `Completed` via source admission (`INV-4`).
    fn run_turn(
        &mut self,
        gate: &dyn EgressGate,
        prompt: &str,
        _images: &[ImageContent],
        sink: &mut dyn FnMut(&Observation),
    ) -> io::Result<TurnOutcome> {
        use gaugedesk_core::remote_session::{
            decide as rdecide, evolve as revolve, RemoteCommand, RemoteState,
        };

        // Apply one reducer command, or fail the turn if the lifecycle rejects it
        // (the reducer is the authority on what crossing is admissible).
        fn step(state: &mut RemoteState, cmd: RemoteCommand) -> io::Result<()> {
            let events = rdecide(state, cmd)
                .map_err(|r| io::Error::new(io::ErrorKind::InvalidData, r.reason))?;
            for e in events {
                *state = revolve(state, e);
            }
            Ok(())
        }

        let mut session = RemoteState::default();
        // Dial the peer (the relay resolves `address`), then ship the turn request.
        step(&mut session, RemoteCommand::DialPeer)?;
        let request_line = protocol::remote::RpcRequest::RunTurn {
            prompt: prompt.to_string(),
        }
        .to_line();
        step(&mut session, RemoteCommand::SendTurnRequest)?;

        // The peer runs the turn over its own runtime and answers one response line.
        let response_line = self.peer.serve(gate, &request_line)?;
        step(&mut session, RemoteCommand::ReceiveTurnResponse)?;

        // Recover the neutral outcome from the envelope. INV-4: a relayed outcome
        // is not product truth until the source authority admits it — the reducer
        // refuses `CompleteSession` otherwise, so a returned outcome is surfaced
        // only after this gate passes.
        let outcome = protocol::remote::RpcResponse::parse(&response_line)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .into_outcome();
        // Re-stream the peer's observations from the envelope to the caller's sink
        // (the orchestrator's only view of the remote turn is the bytes it got back).
        for obs in &outcome.observations {
            sink(obs);
        }
        step(&mut session, RemoteCommand::SourceAdmitOutcome)?;
        step(&mut session, RemoteCommand::CompleteSession)?;
        debug_assert_eq!(
            session.phase,
            gaugedesk_core::remote_session::RemotePhase::Completed
        );

        Ok(outcome)
    }
}

impl RemoteHarness for RemoteLoopbackHarness {
    fn address(&self) -> &str {
        &self.address
    }
}

pub struct PiConfig {
    pub program: String,
    /// The provider to pin (e.g. `openai-codex`). Pinning matters: a bare model
    /// like `gpt-5.5` resolves to `azure-openai-responses` (unauthed); pinning
    /// `openai-codex` uses the user's OAuth codex endpoint (`pi-rpc.md` A6).
    pub provider: Option<String>,
    pub model: Option<String>,
    /// Reasoning-effort level (`--thinking`: off|minimal|low|medium|high|xhigh).
    /// `None` leaves Pi's per-model default.
    pub thinking: Option<String>,
    pub session_dir: Option<String>,
    pub working_dir: Option<String>,
    /// Replace Pi's default system prompt for this process (`--system-prompt`).
    /// Edit mode sets the editor persona here so it overrides the agent's own
    /// `.pi/SYSTEM.md`; use mode leaves it `None` so Pi discovers the agent's own
    /// definition from the worktree (ADR 0029).
    pub system_prompt: Option<String>,
    /// Environment variables to set on the child (e.g. `GAUGEDESK_CHAT_MODE` so the
    /// in-process plugin can enforce the edit/use write-gate, ADR 0029).
    pub env: Vec<(String, String)>,
    /// OS sandbox to run Pi (and its children, incl. `bash`) under (ADR 0030).
    /// `None` runs Pi unwrapped. The definition surface is passed as a
    /// `read_only_root` so writes to it fail at the kernel.
    pub sandbox: Option<sandbox::SandboxPolicy>,
    /// Extra args (e.g. `-e <plugin>`, `-t <tools>`).
    pub extra_args: Vec<String>,
    /// Resume the most recent session in `session_dir` (`--continue`) instead of
    /// starting fresh. Set when the dir already has history — a forked chat (whose
    /// parent's session was copied in) inherits the conversation, and any chat
    /// survives the Pi process dying/restarting (ADR 0038).
    pub continue_session: bool,
}

/// Resolve the Pi executable for the retained conformance adapter. A manual
/// test may override `GAUGEDESK_PI_BIN`; otherwise it finds `pi` on PATH.
fn resolve_pi_bin() -> String {
    pi_bin_from(gaugedesk_env::var("PI_BIN"))
}

/// The pure resolution (pulled out of [`resolve_pi_bin`] so it is testable without
/// touching the process env): a non-empty override wins, else `pi` on PATH.
fn pi_bin_from(override_var: Option<String>) -> String {
    override_var
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "pi".into())
}

impl Default for PiConfig {
    fn default() -> Self {
        Self {
            program: resolve_pi_bin(),
            provider: None,
            model: None,
            thinking: None,
            session_dir: None,
            working_dir: None,
            system_prompt: None,
            env: Vec::new(),
            sandbox: None,
            extra_args: Vec::new(),
            continue_session: false,
        }
    }
}

/// The CLI args (after the program name) a config spawns Pi with. Pulled out of
/// `spawn` so the arg mapping — notably the edit-mode `--system-prompt` — is
/// unit-testable without launching a process.
pub fn pi_args(config: &PiConfig) -> Vec<String> {
    let mut args = vec!["--mode".to_string(), "rpc".to_string()];
    if let Some(p) = &config.provider {
        args.extend(["--provider".to_string(), p.clone()]);
    }
    if let Some(m) = &config.model {
        args.extend(["--model".to_string(), m.clone()]);
    }
    if let Some(t) = &config.thinking {
        args.extend(["--thinking".to_string(), t.clone()]);
    }
    if let Some(d) = &config.session_dir {
        args.extend(["--session-dir".to_string(), d.clone()]);
    }
    if config.continue_session {
        args.push("--continue".to_string());
    }
    if let Some(sp) = &config.system_prompt {
        args.extend(["--system-prompt".to_string(), sp.clone()]);
    }
    args.extend(config.extra_args.iter().cloned());
    args
}

/// The real transport: a live `pi --mode rpc` child, one per engagement,
/// persistent across turns.
pub struct PiProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// Bounded tail of Pi's stderr, filled by a background drain thread. Read on a
    /// failed/empty turn to surface the real provider error (see [`RpcTransport::stderr_tail`]).
    stderr_log: std::sync::Arc<std::sync::Mutex<String>>,
    /// The host-side transparent SNI egress proxy for [`Network::Filtered`]
    /// (CORE-5, ADR 0079), present only when this process runs under the transparent
    /// composition. Held here so the egress checkpoint lives exactly as long as the
    /// sandboxed process: dropping/`shutdown`ing `PiProcess` drops this guard, which
    /// tears the proxy down. `None` for every other posture.
    _egress_proxy: Option<gaugedesk_harness::sni_proxy::SniProxyGuard>,
}

impl PiProcess {
    pub fn spawn(config: &PiConfig) -> io::Result<Self> {
        let args = pi_args(config);
        let cwd = config.working_dir.as_ref().map(std::path::Path::new);
        // Wrap Pi (and every child it spawns, incl. `bash`) in an OS sandbox so the
        // definition surface is read-only at the kernel (ADR 0030). A backend that
        // can't wrap either fails closed or warns-and-runs (RF-B1) — that decision
        // lives in [`sandbox::wrap_or_refuse`].
        //
        // CORE-5 transparent egress (ADR 0079): when the posture resolves to
        // `Filtered` and this host can enforce it (pasta + verified routing), the
        // sandbox is composed inside a pasta-owned netns whose sole outbound path is
        // a host SNI proxy. We start that proxy here and hold its guard on the
        // `PiProcess`, so the checkpoint is up for every turn and torn down with the
        // process. Every other posture takes the unchanged `wrap_or_refuse` path.
        let mut egress_proxy = None;
        let mut cmd = match &config.sandbox {
            Some(policy) if sandbox::wants_transparent_egress(policy) => {
                let guard = gaugedesk_harness::sni_proxy::SniProxyGuard::spawn(
                    policy.allowed_hosts.clone(),
                )?;
                let argv =
                    sandbox::filtered_wrap(policy, &config.program, &args, cwd, guard.addr())
                        .ok_or_else(|| {
                            io::Error::other(
                        "transparent egress requested but its composition is unavailable here",
                    )
                        })?;
                tracing::info!(
                    proxy = %guard.addr(),
                    allowed_hosts = policy.allowed_hosts.len(),
                    "pi spawn: transparent SNI egress (pasta + nft + host proxy)"
                );
                egress_proxy = Some(guard);
                let mut c = ProcCommand::new(&argv[0]);
                c.args(&argv[1..]);
                c
            }
            Some(policy) => sandbox::wrap_or_refuse(policy, &config.program, &args, cwd)?,
            None => {
                let mut c = ProcCommand::new(&config.program);
                c.args(&args);
                c
            }
        };
        if let Some(wd) = &config.working_dir {
            cmd.current_dir(wd);
        }
        for (k, v) in &config.env {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Capture (not discard) Pi's stderr: the human-readable reason behind a
            // swallowed provider error / crash lives here, not on the RPC channel.
            .stderr(Stdio::piped());

        let mut child = cmd.spawn()?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        // Drain stderr on a background thread into a bounded tail buffer, so it never
        // blocks the turn (a full pipe would wedge Pi) and the last few KiB — the part
        // that names the failure — is available when the turn ends.
        let stderr_log = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        if let Some(err) = child.stderr.take() {
            let log = stderr_log.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(err);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            if let Ok(mut buf) = log.lock() {
                                buf.push_str(&line);
                                // Keep only the last ~4 KiB (on a char boundary).
                                if buf.len() > 4096 {
                                    let cut = buf.len() - 4096;
                                    let cut = (cut..=buf.len())
                                        .find(|&i| buf.is_char_boundary(i))
                                        .unwrap_or(buf.len());
                                    *buf = buf.split_off(cut);
                                }
                            }
                        }
                    }
                }
            });
        }
        Ok(Self {
            child,
            stdin,
            stdout,
            stderr_log,
            _egress_proxy: egress_proxy,
        })
    }

    /// The OS process id of the live `pi` child — so a concurrent Stop request can
    /// terminate it out-of-band (unblocking the turn's `recv`) without holding the
    /// workbench lock the running turn owns.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Stop the subprocess (engagement close / idle reap). The on-disk Pi thread
    /// remains for a later resume.
    ///
    /// The reap is **bounded** (RF-A5): `kill()` sends SIGKILL, but a blocking
    /// `wait()` could in rare pipe/kernel states hang the caller. We poll
    /// `try_wait` against a deadline instead — a child that somehow survives the
    /// kill surfaces as a `TimedOut` error rather than a hung shutdown (and at
    /// worst a zombie, never a wedged control plane). The deadline is a generous
    /// backstop (a SIGKILL'd child normally reaps in milliseconds; the headroom
    /// only matters under severe CPU starvation, where the dying child needs a
    /// scheduler slot) — it bounds a *pathologically* stuck child, not the
    /// common case.
    pub fn shutdown(mut self) -> io::Result<()> {
        let _ = self.stdin.write_all(b"\n");
        self.child.kill().ok();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            // A transient `try_wait` error (e.g. EINTR under heavy signal/scheduler
            // contention) is not terminal: keep polling until the child reaps or
            // the deadline. Only a child that genuinely outlives the deadline is a
            // `TimedOut` failure.
            match self.child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) | Err(_) if std::time::Instant::now() >= deadline => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "pi child did not exit within 10s of SIGKILL",
                    ));
                }
                Ok(None) | Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
    }
}

impl RpcTransport for PiProcess {
    fn send(&mut self, line: &str) -> io::Result<()> {
        self.stdin.write_all(line.as_bytes())?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()
    }
    fn recv(&mut self) -> io::Result<Option<String>> {
        let mut buf = String::new();
        let n = self.stdout.read_line(&mut buf)?;
        if n == 0 {
            Ok(None)
        } else {
            Ok(Some(buf.trim_end().to_string()))
        }
    }
    fn stderr_tail(&self) -> Option<String> {
        self.stderr_log.lock().ok().and_then(|b| {
            let t = b.trim();
            (!t.is_empty()).then(|| t.to_string())
        })
    }
}

/// A transport that replays canned stdout lines and discards sent commands — the
/// **mock-LLM** transport used by the control plane's `GAUGEDESK_FAKE_AGENT` mode and
/// by tests. It drives the exact same turn loop as a real Pi process, so the
/// membrane/reducer path is exercised identically; only the bytes are scripted.
pub struct ScriptedTransport {
    lines: std::collections::VecDeque<String>,
    pub sent: Vec<String>,
}

impl ScriptedTransport {
    pub fn new<I, S>(lines: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            lines: lines.into_iter().map(Into::into).collect(),
            sent: Vec::new(),
        }
    }
}

impl RpcTransport for ScriptedTransport {
    fn send(&mut self, line: &str) -> io::Result<()> {
        self.sent.push(line.to_string());
        Ok(())
    }
    fn recv(&mut self) -> io::Result<Option<String>> {
        Ok(self.lines.pop_front())
    }
}

/// Pi is one [`Harness`] adapter: a persistent `pi --mode rpc` subprocess driving
/// turns over its RPC stdio (ADR 0031).
impl Harness for PiProcess {
    fn run_turn(
        &mut self,
        gate: &dyn EgressGate,
        prompt: &str,
        images: &[ImageContent],
        sink: &mut dyn FnMut(&Observation),
    ) -> io::Result<TurnOutcome> {
        run_rpc_turn(self, gate, prompt, images, sink)
    }
    fn process_id(&self) -> Option<u32> {
        Some(self.pid())
    }
    fn shutdown(self: Box<Self>) -> io::Result<()> {
        (*self).shutdown() // the inherent terminate-the-child shutdown
    }
}

/// The scripted/mock transport is a [`Harness`] too — the fake-agent turn path.
impl Harness for ScriptedTransport {
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

/// The Pi adapter's construction seam (SUB-0): assembles the exact [`PiConfig`]
/// the engine used to build inline and spawns [`PiProcess`]. The real branch of
/// the app's per-turn factory selector; the golden parity test pins
/// byte-equality with the engine's pre-seam inline assembly.
pub struct PiHarnessFactory;

impl HarnessFactory for PiHarnessFactory {
    fn kind(&self) -> &'static str {
        "pi"
    }

    fn create(&self, spec: &HarnessSpec) -> io::Result<Box<dyn Harness>> {
        Ok(Box::new(PiProcess::spawn(&pi_config_for(spec))?))
    }

    /// The Pi adapter's own credential state — the OAuth leg of the shell's
    /// fail-closed precheck: any `~/.pi/<user>/auth.json` counts as a sign-in
    /// (`pi-rpc.md` §A6). The BYOK and host-managed legs stay shell policy, so
    /// `resolved_envs` is unused here.
    fn credential_status(
        &self,
        provider: &str,
        _capability: Option<&dyn gaugedesk_harness::CredentialCapability>,
    ) -> CredentialProbe {
        if pi_oauth_present() {
            CredentialProbe::Ready
        } else {
            CredentialProbe::Missing(format!(
                "No model sign-in found for {provider}. Sign in with `pi`, or link an \
                 API key in Account settings and pick that model."
            ))
        }
    }

    /// Chat-fork continuity: Pi's session lives in a `<worktree>.pisession`
    /// sibling dir (ADR 0038, see [`pi_config_from`]), so a forked chat clones
    /// the source session and rebinds the absolute worktree paths inside it.
    /// Path-keyed, so the chat ids are unused. Copy failures are swallowed
    /// exactly as the pre-seam app code did — a fork never fails on continuity,
    /// and the rebind still runs over whatever was copied.
    fn clone_continuity(
        &self,
        source: &HarnessContinuitySpec,
        target: &HarnessContinuitySpec,
    ) -> io::Result<()> {
        let src_worktree = &source.worktree;
        let dst_worktree = &target.worktree;
        let src_session = std::path::PathBuf::from(format!("{}.pisession", src_worktree.display()));
        if src_session.is_dir() {
            let dst_session =
                std::path::PathBuf::from(format!("{}.pisession", dst_worktree.display()));
            let _ = copy_dir_all(&src_session, &dst_session);
            rebind_paths(
                &dst_session,
                &src_worktree.to_string_lossy(),
                &dst_worktree.to_string_lossy(),
            );
        }
        Ok(())
    }
}

/// The [`PiConfig`] a [`HarnessSpec`] assembles to — everything Pi-specific the
/// engine used to build inline: the session dir + `--continue` detection, the
/// sandbox extension, the membrane plugin `-e` arg, and `GAUGEDESK_CHAT_MODE`.
/// The spec carries the shell's resolved policy; this adds the adapter-private
/// pieces.
pub fn pi_config_for(spec: &HarnessSpec) -> PiConfig {
    pi_config_from(
        spec,
        gaugedesk_env::var("PLUGIN_PATH"),
        std::env::current_dir().ok(),
        std::env::var_os("HOME"),
    )
}

/// The assembly itself, with the process-env reads (`GAUGEDESK_PLUGIN_PATH`,
/// cwd, `HOME`) parameterized — mirroring [`pi_bin_from`]'s pure-resolution
/// shape — so the golden parity test is deterministic.
pub fn pi_config_from(
    spec: &HarnessSpec,
    plugin_override: Option<String>,
    cwd: Option<std::path::PathBuf>,
    home: Option<std::ffi::OsString>,
) -> PiConfig {
    // Manage Pi's session location ourselves (a `<worktree>.pisession` sibling,
    // outside the git tree) so chat fork can deterministically clone it — Pi
    // otherwise keys sessions by cwd under ~/.pi (ADR 0038). If the dir already
    // holds history (a forked chat's copied session, or a chat whose Pi process
    // died), `--continue` resumes it rather than starting fresh. Create it up front:
    // both the `--continue` check and bubblewrap's `--bind` need the path to exist.
    let worktree = &spec.worktree;
    let session_dir = format!("{}.pisession", worktree.display());
    let _ = std::fs::create_dir_all(&session_dir);
    let continue_session = std::fs::read_dir(&session_dir)
        .map(|mut d| d.next().is_some())
        .unwrap_or(false);

    // Extend the shell's sandbox POLICY with the adapter-private needs: Pi writes
    // its session/transcript into `--session-dir` (a worktree sibling, OUTSIDE
    // the worktree bind) and its auth/tool cache under `~/.pi`, so both must be
    // writable roots or Pi's SessionManager fails with EROFS under the OS
    // sandbox before the turn starts.
    let mut sandbox_policy = spec.sandbox.clone();
    sandbox_policy
        .writable_roots
        .push(std::path::PathBuf::from(&session_dir));
    if let Some(home) = home {
        sandbox_policy
            .writable_roots
            .push(std::path::Path::new(&home).join(".pi"));
    }

    let mut pc = PiConfig {
        working_dir: Some(worktree.to_string_lossy().into_owned()),
        session_dir: Some(session_dir),
        continue_session,
        provider: spec.provider.clone(),
        model: spec.model.clone(),
        thinking: spec.thinking.clone(),
        system_prompt: spec.system_prompt.clone(),
        // Tell the in-process plugin the mode so it enforces the write-gate
        // (INV-24) before an effect executes — defense-in-depth + clean errors.
        env: {
            let mut env = vec![(
                "GAUGEDESK_CHAT_MODE".to_string(),
                match spec.mode {
                    ChatMode::Edit => "edit".to_string(),
                    ChatMode::Use => "use".to_string(),
                },
            )];
            env.extend(spec.credentials.iter().cloned());
            env
        },
        sandbox: Some(sandbox_policy),
        ..Default::default()
    };
    // The plugin path must be absolute: Pi's cwd is the worktree, not ours. A
    // conformance run may override it; source-tree tests fall back to the
    // retained historical plugin under `plugin/`.
    if let Some(plugin) = plugin_path_candidate(plugin_override, cwd) {
        if plugin.exists() {
            pc.extra_args = vec!["-e".into(), plugin.to_string_lossy().into_owned()];
        }
    }
    pc
}

/// Resolve the retained membrane plugin for a conformance run. An explicit
/// `GAUGEDESK_PLUGIN_PATH` wins; source-tree tests fall back to
/// `plugin/gaugewright-plugin.ts` under the cwd. Pure candidate-selector (no
/// filesystem) so it is unit-testable; the caller `.exists()`-guards before
/// handing the path to Pi.
fn plugin_path_candidate(
    override_var: Option<String>,
    cwd: Option<std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
    if let Some(p) = override_var.filter(|s| !s.is_empty()) {
        return Some(std::path::PathBuf::from(p));
    }
    cwd.map(|c| c.join("plugin/gaugewright-plugin.ts"))
}

/// Whether Pi holds an OAuth credential — any `~/.pi/<user>/auth.json` (`pi-rpc.md` §A6
/// `auth/{userId}/auth.json`). Conservative: a missing `~/.pi` means no sign-in (refuse);
/// an existing-but-unreadable `~/.pi` (or no `HOME`) is *not* blocked — we never refuse a
/// run we cannot disprove. (Verbatim from the engine, whose copy retires when the
/// shell's precheck consults the factory.)
fn pi_oauth_present() -> bool {
    let Some(home) = std::env::var_os("HOME") else {
        return true;
    };
    let pi = std::path::Path::new(&home).join(".pi");
    if !pi.exists() {
        return false;
    }
    match std::fs::read_dir(&pi) {
        Ok(entries) => entries
            .flatten()
            .any(|e| e.path().join("auth.json").is_file()),
        Err(_) => true,
    }
}

/// Recursive dir copy for the forked chat's session clone
/// ([`HarnessFactory::clone_continuity`]). (Moved verbatim from the app's
/// `fork_chat` when continuity became the Pi factory's hook.)
fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

/// Rewrite absolute worktree paths inside a cloned session dir so the fork's
/// session resumes against its own worktree, not the parent's. Best-effort by
/// design (unreadable/binary files are skipped), matching the pre-seam app
/// code. (Moved verbatim alongside [`copy_dir_all`].)
fn rebind_paths(dir: &std::path::Path, from: &str, to: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rebind_paths(&path, from, to);
        } else if let Ok(contents) = std::fs::read_to_string(&path) {
            if contents.contains(from) {
                let _ = std::fs::write(&path, contents.replace(from, to));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// RF-C5: a hostile/buggy Pi stream — garbage lines, out-of-order tool
    /// events, empty wrappers, error lines, missing terminators — must never
    /// panic the turn, never produce an unmediated tool call, and must always
    /// drive the session to a terminal phase (evidence preserved).
    mod stream_fuzz {
        use super::*;
        use proptest::prelude::*;

        #[derive(Clone, Debug)]
        enum FuzzLine {
            Garbage(String),
            /// `tool_execution_end` for a call that never started.
            OrphanToolEnd,
            /// `message_update` with no assistant event payload.
            EmptyMessageUpdate,
            ErrorLine,
            TextDelta(String),
            /// A well-formed start+end tool pair.
            ToolPair,
            /// A start with no matching end (Pi died mid-tool).
            DanglingToolStart,
        }

        fn arb_line() -> impl Strategy<Value = FuzzLine> {
            prop_oneof![
                ".*".prop_map(FuzzLine::Garbage),
                Just(FuzzLine::OrphanToolEnd),
                Just(FuzzLine::EmptyMessageUpdate),
                Just(FuzzLine::ErrorLine),
                "[a-z ]{0,12}".prop_map(FuzzLine::TextDelta),
                Just(FuzzLine::ToolPair),
                Just(FuzzLine::DanglingToolStart),
            ]
        }

        fn render(lines: &[FuzzLine], terminate: bool) -> Vec<String> {
            let mut out = Vec::new();
            for (i, l) in lines.iter().enumerate() {
                match l {
                    FuzzLine::Garbage(s) => out.push(s.clone()),
                    FuzzLine::OrphanToolEnd => out.push(format!(
                        r#"{{"type":"tool_execution_end","toolCallId":"orphan-{i}","result":"?","isError":true}}"#
                    )),
                    FuzzLine::EmptyMessageUpdate => {
                        out.push(r#"{"type":"message_update"}"#.into())
                    }
                    FuzzLine::ErrorLine => {
                        out.push(r#"{"type":"error","error":"model unavailable"}"#.into())
                    }
                    FuzzLine::TextDelta(t) => out.push(
                        serde_json::json!({"type":"text_delta","delta":t}).to_string(),
                    ),
                    FuzzLine::ToolPair => {
                        out.push(format!(
                            r#"{{"type":"tool_execution_start","toolName":"read","toolCallId":"c{i}","args":{{"path":"f.txt"}}}}"#
                        ));
                        out.push(format!(
                            r#"{{"type":"tool_execution_end","toolCallId":"c{i}","result":"ok","isError":false}}"#
                        ));
                    }
                    FuzzLine::DanglingToolStart => out.push(format!(
                        r#"{{"type":"tool_execution_start","toolName":"bash","toolCallId":"d{i}","args":{{"command":"true"}}}}"#
                    )),
                }
            }
            if terminate {
                out.push(r#"{"type":"agent_end"}"#.into());
            }
            out
        }

        proptest! {
            #[test]
            fn hostile_streams_never_panic_and_always_terminate_the_session(
                lines in prop::collection::vec(arb_line(), 0..30),
                terminate in any::<bool>(),
            ) {
                let rendered = render(&lines, terminate);
                let refs: Vec<&str> = rendered.iter().map(|s| s.as_str()).collect();
                let mut transport = Scripted::new(&refs);
                let mut session = executing_session();
                let outcome = run_turn(&mut transport, &mut session, &AllowAllGate, "go", &[])
                    .expect("a hostile stream is handled, not an Err");

                // No terminator ⇒ the turn reports the truncation, never hangs.
                if !terminate {
                    prop_assert!(outcome.error.is_some(), "EOF without agent_end must surface");
                }
                // Every mediated call passed the gate; the count can never
                // exceed the tool starts the stream actually carried.
                let starts = lines.iter().filter(|l| matches!(
                    l, FuzzLine::ToolPair | FuzzLine::DanglingToolStart
                )).count();
                prop_assert!(outcome.mediated_tool_calls.len() <= starts);
                // The session always reaches a terminal outcome (INV-23 flavor:
                // the adapter cannot leave a runtime session stuck).
                prop_assert!(session.terminal, "session must terminate: {session:?}");
            }
        }
    }

    /// RF-C5 (real subprocess): drive `PiProcess` against fake-pi shell scripts
    /// — an echoing peer, a crashing peer, and a stdin-deaf survivor — so the
    /// spawn/transport/shutdown plumbing is tested without a live Pi.
    #[cfg(unix)]
    mod real_subprocess {
        use super::*;

        fn fake_pi(dir: &std::path::Path, body: &str) -> PiConfig {
            use std::os::unix::fs::PermissionsExt;
            let script = dir.join("fake-pi.sh");
            std::fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            PiConfig {
                program: script.to_string_lossy().into_owned(),
                ..PiConfig::default()
            }
        }

        fn spawn_with_retry(cfg: &PiConfig) -> PiProcess {
            let mut last = None;
            for _ in 0..5 {
                match PiProcess::spawn(cfg) {
                    Ok(proc) => return proc,
                    Err(err) => {
                        last = Some(err);
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            }
            panic!("PiProcess spawned within a few attempts; last error: {last:?}");
        }

        #[test]
        fn the_transport_round_trips_lines_through_a_real_child() {
            let dir = tempfile::tempdir().unwrap();
            // Ignores its argv, echoes stdin back — a line-protocol mirror.
            let cfg = fake_pi(dir.path(), r#"while read l; do echo "$l"; done"#);
            let msg = r#"{"type":"get_state","id":"x"}"#;
            // The property under test is the transport round-trip, not the OS's
            // ability to start a shell under a fork-storm: a fresh child that
            // fails to spawn or returns EOF before echoing (rare startup hiccups
            // when the whole workspace forks thousands of processes at once) is
            // retried, not a transport failure. A genuinely broken transport
            // fails all attempts.
            let mut last = None;
            for _ in 0..5 {
                let mut proc = spawn_with_retry(&cfg);
                proc.send(msg).unwrap();
                match proc.recv().unwrap() {
                    Some(line) => {
                        let _ = proc.shutdown();
                        last = Some(line);
                        break;
                    }
                    None => {
                        let _ = proc.shutdown();
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            }
            assert_eq!(
                last.expect("the child echoed within a few attempts"),
                msg,
                "the transport round-trips a line through a real child"
            );
        }

        #[test]
        fn a_crashed_child_surfaces_a_clean_turn_error_not_a_hang() {
            let dir = tempfile::tempdir().unwrap();
            let cfg = fake_pi(dir.path(), "exit 1"); // Pi dies instantly
            let mut proc = spawn_with_retry(&cfg);
            let mut session = executing_session();
            let outcome = run_turn(&mut proc, &mut session, &AllowAllGate, "go", &[]).unwrap();
            assert!(
                outcome.error.is_some(),
                "a dead child is a reported turn error, not a hang"
            );
            assert!(session.terminal, "the session still terminates");
            proc.shutdown().unwrap();
        }

        #[test]
        fn shutdown_reaps_a_stdin_deaf_child_within_the_deadline() {
            let dir = tempfile::tempdir().unwrap();
            // Never reads stdin, never exits on its own (RF-A5's target case).
            let cfg = fake_pi(dir.path(), "exec sleep 30");
            let proc = spawn_with_retry(&cfg);
            let start = std::time::Instant::now();
            proc.shutdown().unwrap();
            // The property: SIGKILL + bounded reap returns well before the child's
            // own 30s sleep would. A generous bound (the reap is ~ms normally; the
            // margin only absorbs CPU starvation under parallel test load) so the
            // assertion proves "didn't wait out the sleep" without racing the
            // internal backstop deadline.
            assert!(
                start.elapsed() < std::time::Duration::from_secs(28),
                "SIGKILL + bounded reap must not wait out the 30s sleep"
            );
        }
    }

    // Moved with `plugin_path_candidate` when the engine's inline twin (and its
    // test) retired in favor of the factory (SUB-0 H5).
    #[test]
    fn plugin_path_prefers_override_then_cwd_relative_dev_fallback() {
        // A conformance runner may point at an explicit plugin — taken verbatim.
        assert_eq!(
            plugin_path_candidate(
                Some("/opt/gaugewright/plugin/gaugewright-plugin.ts".into()),
                Some("/some/cwd".into())
            ),
            Some(std::path::PathBuf::from(
                "/opt/gaugewright/plugin/gaugewright-plugin.ts"
            ))
        );
        // Dev build (no override): the cwd-relative path the repo ships.
        assert_eq!(
            plugin_path_candidate(None, Some("/repo".into())),
            Some(std::path::PathBuf::from(
                "/repo/plugin/gaugewright-plugin.ts"
            ))
        );
        // An empty override is ignored, not treated as a path.
        assert_eq!(
            plugin_path_candidate(Some(String::new()), Some("/repo".into())),
            Some(std::path::PathBuf::from(
                "/repo/plugin/gaugewright-plugin.ts"
            ))
        );
        // No override and no resolvable cwd → nothing to pass (caller skips -e).
        assert_eq!(plugin_path_candidate(None, None), None);
    }

    /// H4 golden parity (SUB-0): the factory must reproduce, byte for byte, the
    /// `PiConfig` the engine's inline assembly produced before the extraction.
    /// The expected values are a SNAPSHOT captured by running the pre-refactor
    /// inline block (engine.rs:918-1022 at commit 2853a06c) over these same
    /// inputs — regenerate them only from that block, never from the factory.
    mod pi_factory_golden {
        use super::*;
        use gaugedesk_harness::sandbox::Network;

        #[test]
        fn use_mode_full_spec_reproduces_the_inline_assembly() {
            let base = tempfile::tempdir().unwrap();
            let wt = base.path().join("wt");
            std::fs::create_dir_all(&wt).unwrap();
            let home = base.path().join("home");
            std::fs::create_dir_all(&home).unwrap();
            let plugin = base.path().join("plugin.ts");
            std::fs::write(&plugin, "// plugin").unwrap();
            let plugin_str = plugin.to_string_lossy().into_owned();

            let spec = HarnessSpec {
                chat_id: "e1".into(),
                worktree: wt.clone(),
                mode: ChatMode::Use,
                package_root: None,
                package_version_ref: None,
                policy_epoch: None,
                signed_policy_envelope: None,
                provider_binding_ref: None,
                credential_ref: None,
                placement_ceiling_ref: None,
                workspace_targets: Vec::new(),
                runtime_placement_id: None,
                provider: Some("openai-codex".into()),
                model: Some("gpt-5.5".into()),
                base_url: None,
                thinking: Some("low".into()),
                system_prompt: None,
                credential_capability: None,
                credentials: vec![("OPENAI_API_KEY".into(), "sk-test-123".into())],
                sandbox: sandbox::SandboxPolicy::new(vec![wt.clone()])
                    .read_only(vec![wt.join(".pi"), wt.join("AGENTS.md")])
                    .allow_hosts(vec![
                        "api.openai.com".into(),
                        "chatgpt.com".into(),
                        "auth.openai.com".into(),
                    ])
                    .allow_unfiltered_egress(true),
                // The Pi adapter carries no `ask` tool, so it offers no roster.
                roster: Vec::new(),
            };
            let pc = pi_config_from(
                &spec,
                Some(plugin_str.clone()),
                None,
                Some(home.clone().into_os_string()),
            );

            let session = format!("{}.pisession", wt.display());
            // The factory leaves the program at the default env resolution,
            // exactly as the inline assembly's `..Default::default()` did.
            assert_eq!(pc.program, PiConfig::default().program);
            let expected_args: Vec<String> = [
                "--mode",
                "rpc",
                "--provider",
                "openai-codex",
                "--model",
                "gpt-5.5",
                "--thinking",
                "low",
                "--session-dir",
                session.as_str(),
                "-e",
                plugin_str.as_str(),
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            assert_eq!(pi_args(&pc), expected_args);
            assert_eq!(
                pc.env,
                vec![
                    ("GAUGEDESK_CHAT_MODE".to_string(), "use".to_string()),
                    ("OPENAI_API_KEY".to_string(), "sk-test-123".to_string()),
                ]
            );
            assert_eq!(pc.working_dir.as_deref(), Some(wt.to_str().unwrap()));
            assert_eq!(pc.session_dir.as_deref(), Some(session.as_str()));
            assert!(!pc.continue_session, "an empty session dir starts fresh");
            assert_eq!(pc.extra_args, vec!["-e".to_string(), plugin_str.clone()]);
            let sb = pc.sandbox.as_ref().expect("a real turn is sandboxed");
            assert_eq!(
                sb.writable_roots,
                vec![
                    wt.clone(),
                    std::path::PathBuf::from(&session),
                    home.join(".pi"),
                ],
                "the adapter extends the shell's policy with the session dir + ~/.pi, in that order"
            );
            assert_eq!(
                sb.read_only_roots,
                vec![wt.join(".pi"), wt.join("AGENTS.md")]
            );
            assert_eq!(sb.network, Network::Allow);
            assert_eq!(
                sb.allowed_hosts,
                vec![
                    "api.openai.com".to_string(),
                    "chatgpt.com".to_string(),
                    "auth.openai.com".to_string(),
                ]
            );
        }

        #[test]
        fn unset_provider_edit_spec_with_history_reproduces_the_inline_assembly() {
            let base = tempfile::tempdir().unwrap();
            let wt = base.path().join("wt2");
            std::fs::create_dir_all(&wt).unwrap();
            // A session dir that already holds history (a forked chat's copied
            // session, or a chat whose Pi process died) must resume.
            let session = format!("{}.pisession", wt.display());
            std::fs::create_dir_all(&session).unwrap();
            std::fs::write(std::path::Path::new(&session).join("h.json"), "{}").unwrap();

            let spec = HarnessSpec {
                chat_id: "e2".into(),
                worktree: wt.clone(),
                mode: ChatMode::Edit,
                package_root: None,
                package_version_ref: None,
                policy_epoch: None,
                signed_policy_envelope: None,
                provider_binding_ref: None,
                credential_ref: None,
                placement_ceiling_ref: None,
                workspace_targets: Vec::new(),
                runtime_placement_id: None,
                // AM-9: the federation peer path keeps provider/model unset so
                // Pi's own default resolution (the authed OAuth provider) holds.
                provider: None,
                model: None,
                base_url: None,
                thinking: None,
                system_prompt: Some("EDITOR PERSONA".into()),
                credential_capability: None,
                credentials: vec![],
                sandbox: sandbox::SandboxPolicy::new(vec![wt.clone()]),
                roster: Vec::new(),
            };
            let pc = pi_config_from(&spec, None, None, None);

            let expected_args: Vec<String> = [
                "--mode",
                "rpc",
                "--session-dir",
                session.as_str(),
                "--continue",
                "--system-prompt",
                "EDITOR PERSONA",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            assert_eq!(pi_args(&pc), expected_args);
            assert_eq!(
                pc.env,
                vec![("GAUGEDESK_CHAT_MODE".to_string(), "edit".to_string())]
            );
            assert_eq!(pc.working_dir.as_deref(), Some(wt.to_str().unwrap()));
            assert!(pc.continue_session, "existing history must resume");
            assert!(pc.extra_args.is_empty(), "no plugin candidate, no -e arg");
            let sb = pc.sandbox.as_ref().unwrap();
            assert_eq!(
                sb.writable_roots,
                vec![wt.clone(), std::path::PathBuf::from(&session)],
                "no HOME ⇒ no ~/.pi writable root"
            );
            assert!(sb.read_only_roots.is_empty());
            assert_eq!(sb.network, Network::Deny);
            assert!(sb.allowed_hosts.is_empty());
        }
    }

    /// A scripted transport: replays canned stdout lines, records sent commands.
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

    /// A session prepared and started, as the admission shell would leave it.
    fn executing_session() -> SessionState {
        let mut s = SessionState::default();
        for c in [
            SessionCommand::AdmitRun,
            SessionCommand::StartBoundarySession,
            SessionCommand::GrantBases,
            SessionCommand::PrepareRuntimeSession,
            SessionCommand::StartRuntimeSession,
        ] {
            apply(&mut s, c);
        }
        s
    }

    #[test]
    fn drives_a_turn_and_mediates_tool_calls() {
        let mut transport = Scripted::new(&[
            r#"{"type":"agent_start"}"#,
            r#"{"type":"turn_start"}"#,
            r#"{"type":"text_delta","delta":"Hello "}"#,
            r#"{"type":"tool_execution_start","toolCallId":"t1","toolName":"read","args":{}}"#,
            r#"{"type":"tool_execution_end","toolCallId":"t1"}"#,
            r#"{"type":"text_delta","delta":"world"}"#,
            r#"{"type":"agent_end","messages":[]}"#,
            r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":"Hello world"}}"#,
        ]);
        let mut session = executing_session();
        let outcome = run_turn(&mut transport, &mut session, &AllowAllGate, "do it", &[]).unwrap();

        assert_eq!(outcome.assistant_text, "Hello world");
        assert_eq!(outcome.mediated_tool_calls, vec!["read".to_string()]);
        assert!(outcome.error.is_none());
        // first sent command is the prompt
        assert!(transport.sent[0].contains("\"prompt\""));

        // the session went through execution → terminal, evidence preserved,
        // and product truth was NOT auto-admitted (owner admission still required).
        use gaugedesk_core::runtime_session::SessionPhase;
        assert_eq!(session.phase, SessionPhase::Terminal);
        assert!(session.evidence_present);
        assert!(
            !session.product_truth_has_observation,
            "no auto-admit into run truth"
        );
        assert!(
            session.egress_requested,
            "the tool call was a boundary egress"
        );
    }

    #[test]
    fn tool_observations_carry_target_args_and_result() {
        let mut transport = Scripted::new(&[
            r#"{"type":"agent_start"}"#,
            r#"{"type":"tool_execution_start","toolCallId":"t1","toolName":"read","args":{"path":"auth.ts"}}"#,
            r#"{"type":"tool_execution_end","toolCallId":"t1","result":"file body","isError":false}"#,
            r#"{"type":"agent_end","messages":[]}"#,
            r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":"ok"}}"#,
        ]);
        let mut session = executing_session();
        let outcome = run_turn(&mut transport, &mut session, &AllowAllGate, "do it", &[]).unwrap();

        // the start observation distils the clickable target + compact args
        let start = outcome
            .observations
            .iter()
            .find(|o| o.kind == "egress")
            .unwrap();
        let info = start.tool.as_ref().expect("structured tool info");
        assert_eq!(info.name, "read");
        assert_eq!(info.call_id, "t1");
        assert_eq!(info.target.as_deref(), Some("auth.ts"));
        assert!(info.args.contains("auth.ts"));

        // the end observation correlates by call_id and carries ✓ + output
        let end = outcome
            .observations
            .iter()
            .find(|o| o.kind == "tool_result")
            .unwrap();
        let res = end.tool.as_ref().expect("structured result");
        assert_eq!(res.call_id, "t1");
        assert_eq!(res.ok, Some(true));
        assert_eq!(res.result.as_deref(), Some("file body"));
    }

    #[test]
    fn surfaces_approval_requests_without_auto_confirming() {
        let mut transport = Scripted::new(&[
            r#"{"type":"extension_ui_request","id":"u1","method":"confirm","title":"Write outside workspace?"}"#,
            r#"{"type":"agent_end","messages":[]}"#,
            r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":""}}"#,
        ]);
        let mut session = executing_session();
        let outcome = run_turn(&mut transport, &mut session, &AllowAllGate, "go", &[]).unwrap();
        assert_eq!(outcome.pending_approvals.len(), 1);
        assert!(outcome.pending_approvals[0].contains("Write outside workspace?"));
    }

    #[test]
    fn surfaces_a_no_op_turn_as_a_provider_error() {
        // Pi's RPC mode reports a swallowed provider error (rate limit / quota / auth) as
        // a clean, empty turn — no text, no tools, no approval. We surface it instead of a
        // silent "agent finished this turn" (LLM-1).
        let mut transport = Scripted::new(&[
            r#"{"type":"agent_start"}"#,
            r#"{"type":"agent_end","messages":[]}"#,
            r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":""}}"#,
        ]);
        let mut session = executing_session();
        let outcome = run_turn(&mut transport, &mut session, &AllowAllGate, "hello", &[]).unwrap();
        assert!(outcome.assistant_text.is_empty());
        let err = outcome
            .error
            .expect("a no-op turn must surface an error, not finish silently");
        assert!(
            err.to_lowercase().contains("no response"),
            "actionable: {err}"
        );
        assert!(
            err.to_lowercase().contains("provider"),
            "names the likely cause: {err}"
        );
    }

    #[test]
    fn pi_args_maps_edit_mode_system_prompt_and_omits_it_otherwise() {
        // Use mode: no system-prompt override → Pi discovers the agent's own .pi/SYSTEM.md.
        let use_args = pi_args(&PiConfig {
            provider: Some("openai-codex".into()),
            ..Default::default()
        });
        assert!(use_args.starts_with(&["--mode".to_string(), "rpc".to_string()]));
        assert!(
            !use_args.iter().any(|a| a == "--system-prompt"),
            "use mode passes no override: {use_args:?}"
        );

        // Edit mode: the editor persona is passed as --system-prompt (replaces SYSTEM.md).
        let edit_args = pi_args(&PiConfig {
            system_prompt: Some("You are the editor.".into()),
            extra_args: vec!["-e".into(), "plugin.ts".into()],
            ..Default::default()
        });
        let i = edit_args
            .iter()
            .position(|a| a == "--system-prompt")
            .expect("edit sets --system-prompt");
        assert_eq!(edit_args[i + 1], "You are the editor.");
        // extra args (the membrane plugin) still follow.
        assert!(edit_args.windows(2).any(|w| w == ["-e", "plugin.ts"]));

        // Reasoning effort (LLM-1): a pinned `thinking` level passes `--thinking <level>`;
        // unset passes nothing (Pi's per-model default).
        let effort = pi_args(&PiConfig {
            thinking: Some("high".into()),
            ..Default::default()
        });
        assert!(
            effort.windows(2).any(|w| w == ["--thinking", "high"]),
            "thinking pins --thinking: {effort:?}"
        );
        assert!(
            !use_args.iter().any(|a| a == "--thinking"),
            "no thinking → no --thinking flag: {use_args:?}"
        );
    }

    #[test]
    fn pi_bin_resolves_override_then_path_default() {
        // Unset / empty → the PATH default `pi`.
        assert_eq!(pi_bin_from(None), "pi");
        assert_eq!(pi_bin_from(Some(String::new())), "pi");
        // A non-empty conformance override wins.
        assert_eq!(
            pi_bin_from(Some("/opt/gaugewright/bin/pi".into())),
            "/opt/gaugewright/bin/pi"
        );
    }

    #[test]
    fn reports_stream_ending_early() {
        let mut transport = Scripted::new(&[r#"{"type":"turn_start"}"#]);
        let mut session = executing_session();
        let outcome = run_turn(&mut transport, &mut session, &AllowAllGate, "go", &[]).unwrap();
        assert!(outcome.error.is_some(), "early EOF is reported faithfully");
    }

    #[test]
    fn remote_harness_exposes_its_address() {
        let harness = RemoteLoopbackHarness::new("127.0.0.1:7777", Vec::<String>::new());
        // the only extra fact a remote harness carries over a local one
        assert_eq!(harness.address(), "127.0.0.1:7777");
        // and it is usable as the trait object the relay will hand around
        let dynamic: &dyn RemoteHarness = &harness;
        assert_eq!(dynamic.address(), "127.0.0.1:7777");
    }

    #[test]
    fn remote_loopback_harness_drives_a_turn_over_the_rpc_envelope() {
        // REMOTE-RPC-1: the turn crosses the PROTO-1 envelope and the recovered
        // outcome — assistant text and the peer's observations — arrives intact.
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
        // The caller's only view of the remote turn is what crosses back on the
        // envelope: the orchestrator re-streams the peer's observations to its sink.
        let mut streamed = Vec::new();
        let outcome = harness
            .run_turn(&AllowAllGate, "go", &[], &mut |o| streamed.push(o.clone()))
            .unwrap();
        assert_eq!(outcome.assistant_text, "remote reply");
        assert!(outcome.error.is_none());
        // the text observations made it across the wire and back out the sink
        assert!(
            !streamed.is_empty(),
            "peer observations re-stream from the envelope"
        );
        assert_eq!(streamed, outcome.observations);
        // the streamed text tokens crossed the wire and came back as observations
        let text: String = streamed
            .iter()
            .filter(|o| o.kind == "text")
            .map(|o| o.detail.as_str())
            .collect();
        assert_eq!(text, "remote reply");
    }

    #[test]
    fn remote_turn_outcome_only_surfaces_via_a_completed_remote_session() {
        // REMOTE-RPC-1 / INV-4: a turn that returns an outcome must have driven the
        // remote_session reducer all the way to `Completed` (dial → request →
        // response → source-admit → complete). We prove the reducer sequence the
        // harness runs reaches that terminal state for a well-formed exchange — the
        // outcome is product truth only past source admission, not on relay say-so.
        use gaugedesk_core::remote_session::{
            decide, evolve, RemoteCommand, RemotePhase, RemoteState,
        };
        let mut s = RemoteState::default();
        for c in [
            RemoteCommand::DialPeer,
            RemoteCommand::SendTurnRequest,
            RemoteCommand::ReceiveTurnResponse,
            RemoteCommand::SourceAdmitOutcome,
            RemoteCommand::CompleteSession,
        ] {
            for e in decide(&s, c).expect("the harness's crossing sequence is admissible") {
                s = evolve(&s, e);
            }
        }
        assert_eq!(s.phase, RemotePhase::Completed);
        assert!(
            !s.relay_has_payload_access,
            "relaying grants no payload read (INV-10/14)"
        );

        // And the harness, end to end, produces the source-admitted outcome.
        let mut harness = RemoteLoopbackHarness::new(
            "127.0.0.1:7777",
            [
                r#"{"type":"agent_start"}"#,
                r#"{"type":"text_delta","delta":"ok"}"#,
                r#"{"type":"agent_end","messages":[]}"#,
                r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":"ok"}}"#,
            ],
        );
        let outcome = harness
            .run_turn(&AllowAllGate, "go", &[], &mut |_| {})
            .unwrap();
        assert_eq!(outcome.assistant_text, "ok");
    }

    /// Smoke-test the real `PiProcess` transport against an installed `pi`,
    /// using `get_state` (no model call). Ignored by default — requires `pi` on
    /// PATH. Run with `cargo test -p gaugedesk-pi-bridge -- --ignored`.
    #[test]
    #[ignore = "requires pi binary on PATH"]
    fn real_pi_process_round_trips_get_state() {
        let config = PiConfig {
            extra_args: vec!["--no-session".into()],
            ..Default::default()
        };
        let mut proc = PiProcess::spawn(&config).expect("spawn pi --mode rpc");
        proc.send(r#"{"type":"get_state","id":"smoke"}"#).unwrap();
        let line = proc.recv().unwrap().expect("a response line");
        let parsed = Line::parse(&line).expect("parseable JSON line");
        match parsed {
            Line::Response {
                command, success, ..
            } => {
                assert_eq!(command, "get_state");
                assert!(success);
            }
            other => panic!("expected a response, got {other:?}"),
        }
        proc.shutdown().unwrap();
    }
}
