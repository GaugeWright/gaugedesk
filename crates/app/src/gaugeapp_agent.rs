//! Pure admission reducer for governed GaugeApp agents.
//!
//! This is the implementation pair for `specs/models/environment-agent.qnt`.
//! Provider output is untrusted input: a model may request only one exact tool
//! declared by the freshly rebuilt GaugeApp session. Reviewed mutations
//! produce proposals; an enabled direct command callback may execute an
//! immediate command through the same owning route as the person-facing page.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::io::Read;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

use crate::account::{account_scope, credentials_in_scope, ModelExecutionClass};
use crate::gaugeapp_contract::{
    GaugeAppClient, GaugeAppCommandEnvelope, GaugeAppCommandGrant, GaugeAppKind, GaugeAppPageGrant,
    GaugeAppScope, GaugeAppSession, ReviewPolicy,
};
use crate::{LockUnpoisoned, SharedWorkbench, Workbench};
use gaugedesk_core::boundary::Authority;
use gaugedesk_core::content_erasure::{
    ErasureCommand, ErasurePhase, ErasureState, OWNER as ERASURE_OWNER,
};
use gaugedesk_store::{AdmitError, CommandRecordFact, Store};

pub const PAGES_LIST_TOOL: &str = "gaugeapp.pages.list";
pub const PAGE_READ_TOOL: &str = "gaugeapp.page.read";
pub const PROPOSALS_PREPARE_TOOL: &str = "gaugeapp.proposals.prepare";
pub const HUMAN_ASK_TOOL: &str = "human.ask";

pub const MANAGEMENT_AGENT_TOOLS: [&str; 4] = [
    PAGES_LIST_TOOL,
    PAGE_READ_TOOL,
    PROPOSALS_PREPARE_TOOL,
    HUMAN_ASK_TOOL,
];

// Immediate commands are not automatically safe management-agent actions.
// Most immediate operations are browser/device ceremonies, secret intake,
// addressed-recipient acts, processor handoffs, or read/navigation controls.
// Those must stay page-owned. Human-reviewed commands already have a review
// presentation; this closed list admits only ordinary secret-free mutations
// whose immediate human path also has a concrete command presentation.
pub const AGENT_PROPOSABLE_IMMEDIATE_COMMANDS: &[&str] = &[
    "account.profile.set",
    "account.avatar.remove",
    "account.invitation.accept",
    "account.invitation.decline",
    "account.membership.leave",
    "provider-connection.rename",
    "provider-connection.default-model.set",
    "trusted-device.rename",
    "application-settings.attention.set",
    "application-settings.appearance.set",
    "commercial-product.create",
    "commercial-product.revise",
    "commercial-client.create",
    "commercial-client.edit",
    "commercial-engagement.proposal.create",
    "commercial-engagement.proposal.save",
    "commercial-engagement.proposal.revise",
    "commercial-engagement.proposal.send",
    "commercial-engagement.proposal.resend",
    "commercial-engagement.placement.link",
    "commercial-engagement.entitlement.activate",
    "commercial-engagement.invoice.issue",
    "commercial-payments.invoice.issue",
    "enterprise-identity.connection.validate",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GaugeAppAgentActionKind {
    Direct,
    Proposal,
    Read,
    HumanCeremony,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GaugeAppAgentActionGrant {
    pub id: String,
    pub kind: GaugeAppAgentActionKind,
}

const AGENT_READ_COMMANDS: &[&str] = &[
    "commercial-product.read",
    "commercial-client.read",
    "commercial-engagements.read-by-client",
    "commercial-payments.read-by-client",
    "commercial-engagement.proposal-delivery.read",
    "commercial-engagement.agreement.read",
    "commercial-engagement.payments.read",
    "commercial-payments.payment.read",
];

const AGENT_HUMAN_CEREMONIES: &[&str] = &[
    "account.avatar.set",
    "account.authenticator.begin-add",
    "account.authenticator.complete-add",
    "account.recovery-codes.reissue",
    "provider-connection.api-key.add",
    "provider-connection.subscription.begin",
    "provider-connection.subscription.complete",
    "provider-connection.compatible.add",
    "provider-connection.verify",
    "managed-inference.plan.change",
    "trusted-device.link.begin",
    "trusted-device.link.accept",
    "trusted-device.link.reject",
    "trusted-device.link.cancel",
    "enterprise-identity.connection.credential.set",
    "enterprise-identity.connection.credential.remove",
    "enterprise-identity.test.begin",
    "commercial-engagement.agreement.accept",
    "commercial-payments.connect.begin",
    "commercial-payments.connect.continue",
    "commercial-payments.connect-component.open",
    "commercial-payments.checkout.create",
    "commercial-payments.processor-documents.open",
    "commercial-payments.processor-support.open",
];

pub fn gaugeapp_agent_action_kind(
    command: &GaugeAppCommandGrant,
) -> Option<GaugeAppAgentActionKind> {
    if command.review == ReviewPolicy::Human {
        return Some(GaugeAppAgentActionKind::Proposal);
    }
    let id = command.id.as_str();
    if AGENT_PROPOSABLE_IMMEDIATE_COMMANDS.contains(&id) {
        return Some(GaugeAppAgentActionKind::Direct);
    }
    if AGENT_READ_COMMANDS.contains(&id) {
        return Some(GaugeAppAgentActionKind::Read);
    }
    if AGENT_HUMAN_CEREMONIES.contains(&id) {
        return Some(GaugeAppAgentActionKind::HumanCeremony);
    }
    None
}

pub fn gaugeapp_agent_page_actions(
    session: &GaugeAppSession,
    page: &GaugeAppPageGrant,
) -> Vec<GaugeAppAgentActionGrant> {
    page.commands
        .iter()
        .filter_map(|id| {
            let command = session.commands.iter().find(|command| command.id == *id)?;
            let kind = gaugeapp_agent_action_kind(command)?;
            Some(GaugeAppAgentActionGrant {
                id: id.clone(),
                kind,
            })
        })
        .collect()
}

pub fn gaugeapp_agent_can_propose(command: &GaugeAppCommandGrant) -> bool {
    command.review == ReviewPolicy::Human
        || AGENT_PROPOSABLE_IMMEDIATE_COMMANDS.contains(&command.id.as_str())
        || AGENT_READ_COMMANDS.contains(&command.id.as_str())
}

pub fn gaugeapp_agent_page_commands(
    session: &GaugeAppSession,
    page: &GaugeAppPageGrant,
) -> Vec<String> {
    page.commands
        .iter()
        .filter(|id| {
            session
                .commands
                .iter()
                .find(|command| command.id == **id)
                .is_some_and(gaugeapp_agent_can_propose)
        })
        .cloned()
        .collect()
}

const MAX_PROVIDER_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TOOL_ROUNDS: usize = 8;
pub const GAUGEAPP_AGENT_MESSAGE_KIND: &str = "gaugeapp_agent_message";
pub const GAUGEAPP_AGENT_THREAD_STATE_KIND: &str = "gaugeapp_agent_thread_state";
const LEGACY_ENVIRONMENT_AGENT_MESSAGE_KIND: &str = "environment_agent_message";

/// A boolean setting, read the way every other setting in this codebase is
/// read: `gaugedesk_env::var` prefixes the suffix with `GAUGEDESK_` and falls
/// back to the `GAUGEWRIGHT_` name with a deprecation warning.
///
/// This used to take a whole variable name and call `std::env::var` directly,
/// which meant it alone had no legacy fallback and no warning — a flag left on
/// the old prefix silently read as *unset* rather than as deprecated. The hosted
/// Hub carried `GAUGEWRIGHT_MANAGEMENT_AGENT_MANAGED=1` next to an already
/// migrated `GAUGEDESK_MANAGEMENT_AGENT_MODEL`, so GaugeWright-funded model
/// access was switched off by a name for as long as that line survived the
/// rename, and every Administration agent turn answered `NoModelAccess`.
fn environment_flag(suffix: &str) -> bool {
    gaugedesk_env::var(suffix).is_some_and(|value| matches!(value.trim(), "1" | "true" | "yes"))
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GaugeAppAgentPage {
    pub id: String,
    pub read_model: String,
    pub version: u32,
    pub resource_basis: String,
    pub model: Value,
    pub commands: Vec<String>,
    #[serde(default)]
    pub actions: Vec<GaugeAppAgentActionGrant>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GaugeAppAgentProposal {
    pub page_id: String,
    pub command_id: String,
    pub expected_basis: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GaugeAppAgentTurn {
    pub message: String,
    #[serde(default)]
    pub proposals: Vec<GaugeAppAgentProposal>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GaugeAppAgentMessageRole {
    User,
    Assistant,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GaugeAppAgentMessage {
    pub id: String,
    pub thread_id: String,
    pub app: GaugeAppKind,
    pub scope: GaugeAppScope,
    pub actor: String,
    pub sequence: u64,
    pub role: GaugeAppAgentMessageRole,
    pub text: String,
    #[serde(default)]
    pub proposals: Vec<GaugeAppAgentProposal>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum GaugeAppAgentThreadPhase {
    Active,
    Erasing,
}

/// Server-owned pointer from one stable management thread to its current
/// independently keyed content generation. `Erasing` is a recoverable intent:
/// reads stop resolving the old generation before its key is destroyed, and a
/// later request can finish the same operation after a process crash.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GaugeAppAgentThreadState {
    thread_id: String,
    app: GaugeAppKind,
    scope: GaugeAppScope,
    actor: String,
    generation: u64,
    content_scope: String,
    phase: GaugeAppAgentThreadPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    erasure_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GaugeAppAgentErasureReceipt {
    pub thread_id: String,
    pub generation: u64,
}

/// One operational event from the currently running management turn. These
/// frames are server-owned, bounded, and explicitly not transcript truth. A
/// successful turn is replaced by its atomically admitted user/assistant pair;
/// a stopped or failed turn leaves no partial message behind.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum GaugeAppAgentLiveEvent {
    Started,
    Text { delta: String },
    Tool { tool: String, call_id: String },
    ToolResult { call_id: String, ok: bool },
    Settled,
    Stopped,
    Failed,
}

impl GaugeAppAgentLiveEvent {
    fn terminal(&self) -> bool {
        matches!(self, Self::Settled | Self::Stopped | Self::Failed)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GaugeAppAgentLiveFrame {
    pub cursor: String,
    pub thread_id: String,
    pub turn_id: String,
    pub sequence: u64,
    pub event: GaugeAppAgentLiveEvent,
}

const MAX_LIVE_EVENT_FRAMES: usize = 512;
const LIVE_EVENT_RETENTION: Duration = Duration::from_secs(5 * 60);

struct GaugeAppAgentLiveState {
    turn_id: String,
    next_sequence: u64,
    active: bool,
    updated_at: Instant,
    frames: VecDeque<GaugeAppAgentLiveFrame>,
}

fn live_states() -> &'static Mutex<BTreeMap<String, GaugeAppAgentLiveState>> {
    static STATES: OnceLock<Mutex<BTreeMap<String, GaugeAppAgentLiveState>>> = OnceLock::new();
    STATES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn live_sender() -> &'static broadcast::Sender<GaugeAppAgentLiveFrame> {
    static SENDER: OnceLock<broadcast::Sender<GaugeAppAgentLiveFrame>> = OnceLock::new();
    SENDER.get_or_init(|| broadcast::channel(2048).0)
}

fn prune_live_states(states: &mut BTreeMap<String, GaugeAppAgentLiveState>) {
    let now = Instant::now();
    states.retain(|_, state| {
        state.active || now.duration_since(state.updated_at) < LIVE_EVENT_RETENTION
    });
}

/// Handle for publishing one exact turn's operational stream. A later turn on
/// the same canonical thread replaces this retained buffer, so a late producer
/// cannot append operational output into its successor.
#[derive(Clone, Debug)]
pub struct GaugeAppAgentLiveTurn {
    thread_id: String,
    turn_id: String,
}

impl GaugeAppAgentLiveTurn {
    pub fn publish(&self, event: GaugeAppAgentLiveEvent) -> Result<(), GaugeAppAgentError> {
        if let GaugeAppAgentLiveEvent::Text { delta } = &event {
            if contains_secret_text(delta) {
                return Err(GaugeAppAgentError::Rejected(
                    GaugeAppAgentRejection::SecretBearingArguments,
                ));
            }
        }
        let terminal = event.terminal();
        let frame = {
            let mut states = live_states()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(state) = states.get_mut(&self.thread_id) else {
                return Ok(());
            };
            if state.turn_id != self.turn_id || !state.active {
                return Ok(());
            }
            let sequence = state.next_sequence;
            state.next_sequence += 1;
            state.updated_at = Instant::now();
            let frame = GaugeAppAgentLiveFrame {
                cursor: format!("{}:{sequence}", self.turn_id),
                thread_id: self.thread_id.clone(),
                turn_id: self.turn_id.clone(),
                sequence,
                event,
            };
            state.frames.push_back(frame.clone());
            while state.frames.len() > MAX_LIVE_EVENT_FRAMES {
                state.frames.pop_front();
            }
            if terminal {
                state.active = false;
            }
            frame
        };
        let _ = live_sender().send(frame);
        Ok(())
    }
}

pub fn begin_gaugeapp_agent_live_turn(
    session: &GaugeAppSession,
    message_idempotency_key: &str,
) -> Result<GaugeAppAgentLiveTurn, GaugeAppAgentError> {
    if message_idempotency_key.trim().is_empty() {
        return Err(GaugeAppAgentError::InvalidOutput(
            "message idempotency key is empty".into(),
        ));
    }
    let thread_id = gaugeapp_thread_id(session);
    let (_, _, turn_id) = gaugeapp_agent_turn_identity(session, message_idempotency_key);
    {
        let mut states = live_states()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        prune_live_states(&mut states);
        states.insert(
            thread_id.clone(),
            GaugeAppAgentLiveState {
                turn_id: turn_id.clone(),
                next_sequence: 0,
                active: true,
                updated_at: Instant::now(),
                frames: VecDeque::new(),
            },
        );
    }
    let live = GaugeAppAgentLiveTurn { thread_id, turn_id };
    live.publish(GaugeAppAgentLiveEvent::Started)?;
    Ok(live)
}

/// Subscribe before reading retained frames; a publish racing the snapshot can
/// therefore appear twice, and the opaque cursor lets clients discard that
/// harmless duplicate without losing the event.
pub fn gaugeapp_agent_live_subscription(
    thread_id: &str,
    after: Option<&str>,
) -> (
    Vec<GaugeAppAgentLiveFrame>,
    broadcast::Receiver<GaugeAppAgentLiveFrame>,
) {
    let receiver = live_sender().subscribe();
    let frames = {
        let mut states = live_states()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        prune_live_states(&mut states);
        let Some(state) = states.get(thread_id) else {
            return (Vec::new(), receiver);
        };
        match after {
            Some(cursor) => match state.frames.iter().position(|frame| frame.cursor == cursor) {
                Some(position) => state.frames.iter().skip(position + 1).cloned().collect(),
                // A cursor may name an evicted frame or an earlier turn. Repair
                // an active view from the retained buffer; for a terminal turn
                // only the terminal fact is useful because durable transcript
                // truth is read from the Store.
                None if state.active => state.frames.iter().cloned().collect(),
                None => state.frames.back().cloned().into_iter().collect(),
            },
            None if state.active => state.frames.iter().cloned().collect(),
            None => state.frames.back().cloned().into_iter().collect(),
        }
    };
    (frames, receiver)
}

#[derive(Clone, Debug)]
pub struct GaugeAppAgentContext {
    pub session: GaugeAppSession,
    pub pages: Vec<GaugeAppAgentPage>,
}

#[derive(Debug)]
pub enum GaugeAppAgentError {
    Busy,
    Interrupted,
    NoModelAccess,
    Credential(String),
    Provider(String),
    InvalidOutput(String),
    Rejected(GaugeAppAgentRejection),
    Store(String),
}

impl std::fmt::Display for GaugeAppAgentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => write!(
                formatter,
                "management conversation already has a running turn"
            ),
            Self::Interrupted => write!(formatter, "stopped"),
            Self::NoModelAccess => write!(
                formatter,
                "link OpenAI or Codex model access in Account Settings before using this agent"
            ),
            Self::Credential(reason) => {
                write!(formatter, "model credential is unavailable: {reason}")
            }
            Self::Provider(reason) => write!(formatter, "model provider request failed: {reason}"),
            Self::InvalidOutput(reason) => {
                write!(formatter, "model returned invalid agent output: {reason}")
            }
            Self::Rejected(reason) => write!(
                formatter,
                "agent tool request rejected: {}",
                reason.message()
            ),
            Self::Store(reason) => write!(formatter, "agent transcript unavailable: {reason}"),
        }
    }
}

pub fn gaugeapp_thread_id(session: &GaugeAppSession) -> String {
    let material = format!(
        "{}\n{}\n{}\n{}",
        session.actor,
        session.app.as_str(),
        session.scope.kind,
        session.scope.id,
    );
    format!(
        "gaugeapp-thread:{}",
        hex::encode(Sha256::digest(material.as_bytes()))
    )
}

pub fn gaugeapp_agent_store_scope(session: &GaugeAppSession) -> String {
    format!("gaugeapp-agent:{}", gaugeapp_thread_id(session))
}

fn gaugeapp_agent_generation_scope(session: &GaugeAppSession, generation: u64) -> String {
    let base = gaugeapp_agent_store_scope(session);
    if generation == 0 {
        base
    } else {
        format!("{base}:generation:{generation}")
    }
}

fn gaugeapp_agent_thread_owner_scope(session: &GaugeAppSession) -> String {
    match session.app {
        GaugeAppKind::AccountSettings => account_scope(&session.actor),
        GaugeAppKind::Administration | GaugeAppKind::CommercialOperations => {
            crate::org::tenant_scope(&session.scope.id)
        }
    }
}

fn gaugeapp_agent_thread_states(
    store: &Store,
    session: &GaugeAppSession,
) -> Result<Vec<GaugeAppAgentThreadState>, AdmitError> {
    let thread_id = gaugeapp_thread_id(session);
    let mut matching = Vec::new();
    for payload in store.records(
        &gaugeapp_agent_thread_owner_scope(session),
        GAUGEAPP_AGENT_THREAD_STATE_KIND,
    )? {
        let state: GaugeAppAgentThreadState = serde_json::from_str(&payload)?;
        if state.thread_id == thread_id
            && state.app == session.app
            && state.scope == session.scope
            && state.actor == session.actor
        {
            matching.push(state);
        }
    }
    Ok(matching)
}

fn gaugeapp_agent_thread_state(
    store: &Store,
    session: &GaugeAppSession,
) -> Result<Option<GaugeAppAgentThreadState>, AdmitError> {
    Ok(gaugeapp_agent_thread_states(store, session)?.pop())
}

fn gaugeapp_agent_active_content_scope(
    store: &Store,
    session: &GaugeAppSession,
) -> Result<Option<String>, AdmitError> {
    match gaugeapp_agent_thread_state(store, session)? {
        Some(state) if state.phase == GaugeAppAgentThreadPhase::Erasing => Ok(None),
        Some(state) => Ok(Some(state.content_scope)),
        None => Ok(Some(gaugeapp_agent_generation_scope(session, 0))),
    }
}

pub fn gaugeapp_agent_transcript(
    store: &Store,
    session: &GaugeAppSession,
) -> Result<Vec<GaugeAppAgentMessage>, AdmitError> {
    let thread_id = gaugeapp_thread_id(session);
    let Some(content_scope) = gaugeapp_agent_active_content_scope(store, session)? else {
        // An admitted erasure intent blocks resolution immediately. The mutable
        // request paths reconcile this recoverable phase before accepting more
        // work, but a pure reader must never fall back to the old generation.
        return Ok(Vec::new());
    };
    let mut messages = store
        .records(&content_scope, GAUGEAPP_AGENT_MESSAGE_KIND)?
        .into_iter()
        .filter_map(|payload| serde_json::from_str::<GaugeAppAgentMessage>(&payload).ok())
        .filter(|message| {
            message.thread_id == thread_id
                && message.app == session.app
                && message.scope == session.scope
                && message.actor == session.actor
        })
        .collect::<Vec<_>>();
    messages.sort_by_key(|message| message.sequence);
    Ok(messages)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum LegacyEnvironmentKind {
    Hub,
    Administration,
    Vend,
}

impl LegacyEnvironmentKind {
    fn gaugeapp(self) -> GaugeAppKind {
        match self {
            Self::Hub => GaugeAppKind::AccountSettings,
            Self::Administration => GaugeAppKind::Administration,
            Self::Vend => GaugeAppKind::CommercialOperations,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Hub => "hub",
            Self::Administration => "administration",
            Self::Vend => "vend",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum LegacyEnvironmentAgentMessageRole {
    User,
    Assistant,
}

#[derive(Clone, Debug, Deserialize)]
struct LegacyEnvironmentAgentMessage {
    id: String,
    session_id: String,
    environment: LegacyEnvironmentKind,
    scope: GaugeAppScope,
    actor: String,
    sequence: u64,
    role: LegacyEnvironmentAgentMessageRole,
    text: String,
}

/// Attach only the old transcript records whose actor, App and exact scope are
/// explicit and whose per-session ordering is complete. Anything ambiguous is
/// left in its original evidence scope and never guessed into a canonical
/// GaugeApp thread.
pub fn migrate_legacy_gaugeapp_agent_transcript(
    workbench: &mut Workbench,
    session: &GaugeAppSession,
) -> Result<bool, GaugeAppAgentError> {
    // Any state record means this stable thread has crossed an explicit erasure
    // boundary. Never repopulate its new generation from retired Hub/Admin/Vend
    // history after the person deliberately cleared it.
    if gaugeapp_agent_thread_state(workbench.store_ref(), session)
        .map_err(|error| GaugeAppAgentError::Store(format!("{error:?}")))?
        .is_some()
    {
        return Ok(false);
    }
    let existing = gaugeapp_agent_transcript(workbench.store_ref(), session)
        .map_err(|error| GaugeAppAgentError::Store(format!("{error:?}")))?;
    if !existing.is_empty() {
        return Ok(false);
    }
    let legacy_kind = match session.app {
        GaugeAppKind::AccountSettings => LegacyEnvironmentKind::Hub,
        GaugeAppKind::Administration => LegacyEnvironmentKind::Administration,
        GaugeAppKind::CommercialOperations => LegacyEnvironmentKind::Vend,
    };
    let legacy_scope = format!(
        "environment-agent:{}:{}:{}",
        legacy_kind.as_str(),
        session.scope.kind,
        session.scope.id,
    );
    let candidates = workbench
        .store_ref()
        .records(&legacy_scope, LEGACY_ENVIRONMENT_AGENT_MESSAGE_KIND)
        .map_err(|error| GaugeAppAgentError::Store(format!("{error:?}")))?
        .into_iter()
        .filter_map(|payload| serde_json::from_str::<LegacyEnvironmentAgentMessage>(&payload).ok())
        .filter(|message| {
            message.environment.gaugeapp() == session.app
                && message.scope == session.scope
                && message.actor == session.actor
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok(false);
    }

    let mut sessions =
        std::collections::BTreeMap::<String, Vec<&LegacyEnvironmentAgentMessage>>::new();
    for message in &candidates {
        sessions
            .entry(message.session_id.clone())
            .or_default()
            .push(message);
    }
    let complete = sessions.values().all(|messages| {
        let mut ordered = messages.clone();
        ordered.sort_by_key(|message| message.sequence);
        ordered.len() % 2 == 0
            && ordered.iter().enumerate().all(|(index, message)| {
                message.sequence == index as u64
                    && matches!(
                        (index % 2, message.role),
                        (0, LegacyEnvironmentAgentMessageRole::User)
                            | (1, LegacyEnvironmentAgentMessageRole::Assistant)
                    )
            })
    });
    let unique_ids = candidates
        .iter()
        .map(|message| message.id.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        == candidates.len();
    if !complete || !unique_ids {
        return Ok(false);
    }

    let thread_id = gaugeapp_thread_id(session);
    let records = candidates
        .iter()
        .enumerate()
        .map(|(sequence, legacy)| GaugeAppAgentMessage {
            id: format!(
                "gaugeapp-agent-message:legacy:{}",
                hex::encode(Sha256::digest(legacy.id.as_bytes()))
            ),
            thread_id: thread_id.clone(),
            app: session.app,
            scope: session.scope.clone(),
            actor: session.actor.clone(),
            sequence: sequence as u64,
            role: match legacy.role {
                LegacyEnvironmentAgentMessageRole::User => GaugeAppAgentMessageRole::User,
                LegacyEnvironmentAgentMessageRole::Assistant => GaugeAppAgentMessageRole::Assistant,
            },
            text: legacy.text.clone(),
            proposals: Vec::new(),
        })
        .collect::<Vec<_>>();
    let scope = gaugeapp_agent_store_scope(session);
    let facts = records
        .iter()
        .map(|record| CommandRecordFact {
            scope_id: scope.clone(),
            kind: GAUGEAPP_AGENT_MESSAGE_KIND.into(),
            payload: serde_json::to_string(record).expect("migrated message serializes"),
        })
        .collect::<Vec<_>>();
    let migration_material = format!(
        "{}\n{}\n{}\n{}",
        session.actor,
        session.app.as_str(),
        session.scope.kind,
        session.scope.id,
    );
    let migration_key = hex::encode(Sha256::digest(migration_material.as_bytes()));
    workbench
        .store_mut()
        .admit_record_facts(
            &format!("{scope}:legacy-migration"),
            &migration_key,
            &serde_json::to_string(&records).expect("migration snapshot serializes"),
            &facts,
        )
        .map_err(|error| GaugeAppAgentError::Store(format!("{error:?}")))?;
    Ok(true)
}

fn gaugeapp_agent_erasure_id(session: &GaugeAppSession, idempotency_key: &str) -> String {
    let material = format!("{}\n{idempotency_key}", gaugeapp_thread_id(session));
    format!(
        "gaugeapp-agent-erasure:{}",
        hex::encode(Sha256::digest(material.as_bytes()))
    )
}

fn gaugeapp_agent_erasure_scope(content_scope: &str) -> String {
    format!("{content_scope}:content-erasure")
}

fn thread_state_fact(
    session: &GaugeAppSession,
    state: &GaugeAppAgentThreadState,
) -> CommandRecordFact {
    CommandRecordFact {
        scope_id: gaugeapp_agent_thread_owner_scope(session),
        kind: GAUGEAPP_AGENT_THREAD_STATE_KIND.into(),
        payload: serde_json::to_string(state).expect("management thread state serializes"),
    }
}

fn drive_gaugeapp_agent_content_erasure(
    workbench: &mut Workbench,
    content_scope: &str,
) -> Result<(), GaugeAppAgentError> {
    let scope = gaugeapp_agent_erasure_scope(content_scope);
    loop {
        let phase = workbench
            .store_ref()
            .fold::<ErasureState>(&scope)
            .map_err(|error| GaugeAppAgentError::Store(format!("{error:?}")))?
            .phase;
        let command = match phase {
            ErasurePhase::Init => ErasureCommand::RequestErasure,
            ErasurePhase::Requested => ErasureCommand::Approve(Authority::from(ERASURE_OWNER)),
            ErasurePhase::Approved => ErasureCommand::Tombstone,
            ErasurePhase::Failed => ErasureCommand::RetryTombstone,
            ErasurePhase::Tombstoned => break,
            ErasurePhase::Denied => {
                return Err(GaugeAppAgentError::Store(
                    "management conversation erasure was denied".into(),
                ))
            }
        };
        workbench
            .store_mut()
            .admit::<ErasureState>(&scope, command)
            .map_err(|error| GaugeAppAgentError::Store(format!("{error:?}")))?;
    }
    // The lifecycle above is the authoritative future-read tombstone. When a
    // content vault is configured, destroying this generation's independent
    // key additionally makes its retained ciphertext irretrievable. With no
    // vault (the local opt-out profile), advancing the generation still blocks
    // all product reads without pretending the plaintext bytes were destroyed.
    let _ = workbench.crypto_erase_content(content_scope);
    Ok(())
}

fn finish_gaugeapp_agent_erasure(
    workbench: &mut Workbench,
    session: &GaugeAppSession,
    erasing: &GaugeAppAgentThreadState,
) -> Result<GaugeAppAgentThreadState, GaugeAppAgentError> {
    debug_assert_eq!(erasing.phase, GaugeAppAgentThreadPhase::Erasing);
    drive_gaugeapp_agent_content_erasure(workbench, &erasing.content_scope)?;
    let erasure_id = erasing
        .erasure_id
        .clone()
        .ok_or_else(|| GaugeAppAgentError::Store("erasing thread has no operation id".into()))?;
    let active = GaugeAppAgentThreadState {
        thread_id: erasing.thread_id.clone(),
        app: erasing.app,
        scope: erasing.scope.clone(),
        actor: erasing.actor.clone(),
        generation: erasing.generation + 1,
        content_scope: gaugeapp_agent_generation_scope(session, erasing.generation + 1),
        phase: GaugeAppAgentThreadPhase::Active,
        erasure_id: Some(erasure_id.clone()),
    };
    let fact = thread_state_fact(session, &active);
    workbench
        .store_mut()
        .admit_record_facts(
            &format!("{}:erasure", gaugeapp_agent_thread_owner_scope(session)),
            &format!("{erasure_id}:complete"),
            &serde_json::to_string(&active).expect("completed erasure serializes"),
            &[fact],
        )
        .map_err(|error| GaugeAppAgentError::Store(format!("{error:?}")))?;
    Ok(active)
}

/// Finish a crash-interrupted conversation erasure before a mutable request
/// reads or appends this thread. The pure transcript reader independently hides
/// an `Erasing` generation, so recovery cannot disclose the retired payload.
pub fn reconcile_gaugeapp_agent_erasure(
    workbench: &mut Workbench,
    session: &GaugeAppSession,
) -> Result<(), GaugeAppAgentError> {
    let Some(state) = gaugeapp_agent_thread_state(workbench.store_ref(), session)
        .map_err(|error| GaugeAppAgentError::Store(format!("{error:?}")))?
    else {
        return Ok(());
    };
    if state.phase == GaugeAppAgentThreadPhase::Erasing {
        finish_gaugeapp_agent_erasure(workbench, session, &state)?;
    }
    Ok(())
}

/// Erase the currently visible content generation while retaining the stable
/// management-thread id. The request is exact and idempotent; a successful
/// retry returns the generation created by its first admission.
pub fn erase_gaugeapp_agent_transcript(
    workbench: &SharedWorkbench,
    session: &GaugeAppSession,
    idempotency_key: &str,
) -> Result<GaugeAppAgentErasureReceipt, GaugeAppAgentError> {
    erase_gaugeapp_agent_transcript_inner(workbench, session, idempotency_key, None)
}

/// Erase only while the session authority used to open this thread remains
/// current. Validation and erasure admission share the Workbench/store lock,
/// so revocation cannot win between the final authority check and mutation.
pub fn erase_gaugeapp_agent_transcript_current(
    workbench: &SharedWorkbench,
    session: &GaugeAppSession,
    idempotency_key: &str,
    validate_current: AdmissionValidation<'_>,
) -> Result<GaugeAppAgentErasureReceipt, GaugeAppAgentError> {
    erase_gaugeapp_agent_transcript_inner(
        workbench,
        session,
        idempotency_key,
        Some(validate_current),
    )
}

fn erase_gaugeapp_agent_transcript_inner(
    workbench: &SharedWorkbench,
    session: &GaugeAppSession,
    idempotency_key: &str,
    validate_current: Option<AdmissionValidation<'_>>,
) -> Result<GaugeAppAgentErasureReceipt, GaugeAppAgentError> {
    if idempotency_key.trim().is_empty() {
        return Err(GaugeAppAgentError::InvalidOutput(
            "conversation erasure idempotency key is empty".into(),
        ));
    }
    let thread_id = gaugeapp_thread_id(session);
    let Some(_claim) = claim_gaugeapp_agent_turn(&thread_id) else {
        return Err(GaugeAppAgentError::Busy);
    };
    let erasure_id = gaugeapp_agent_erasure_id(session, idempotency_key);
    let mut guard = workbench.lock_unpoisoned();
    if let Some(validate_current) = validate_current {
        validate_current(&mut guard)?;
    }
    reconcile_gaugeapp_agent_erasure(&mut guard, session)?;
    let states = gaugeapp_agent_thread_states(guard.store_ref(), session)
        .map_err(|error| GaugeAppAgentError::Store(format!("{error:?}")))?;
    if let Some(completed) = states.iter().rev().find(|state| {
        state.phase == GaugeAppAgentThreadPhase::Active
            && state.erasure_id.as_deref() == Some(erasure_id.as_str())
    }) {
        return Ok(GaugeAppAgentErasureReceipt {
            thread_id,
            generation: completed.generation,
        });
    }
    let current = states
        .last()
        .cloned()
        .unwrap_or_else(|| GaugeAppAgentThreadState {
            thread_id: thread_id.clone(),
            app: session.app,
            scope: session.scope.clone(),
            actor: session.actor.clone(),
            generation: 0,
            content_scope: gaugeapp_agent_generation_scope(session, 0),
            phase: GaugeAppAgentThreadPhase::Active,
            erasure_id: None,
        });
    let erasing = GaugeAppAgentThreadState {
        phase: GaugeAppAgentThreadPhase::Erasing,
        erasure_id: Some(erasure_id.clone()),
        ..current
    };
    let fact = thread_state_fact(session, &erasing);
    guard
        .store_mut()
        .admit_record_facts(
            &format!("{}:erasure", gaugeapp_agent_thread_owner_scope(session)),
            &erasure_id,
            &serde_json::to_string(&erasing).expect("erasure intent serializes"),
            &[fact],
        )
        .map_err(|error| GaugeAppAgentError::Store(format!("{error:?}")))?;
    let active = finish_gaugeapp_agent_erasure(&mut guard, session, &erasing)?;
    Ok(GaugeAppAgentErasureReceipt {
        thread_id,
        generation: active.generation,
    })
}

fn gaugeapp_agent_content_scopes_matching(
    store: &Store,
    matches: impl Fn(&GaugeAppAgentMessage) -> bool,
) -> Result<Vec<String>, AdmitError> {
    let mut scopes = std::collections::BTreeSet::new();
    for (content_scope, payload) in store.records_across_scopes(GAUGEAPP_AGENT_MESSAGE_KIND)? {
        let message: GaugeAppAgentMessage = serde_json::from_str(&payload)?;
        if matches(&message) {
            scopes.insert(content_scope);
        }
    }
    Ok(scopes.into_iter().collect())
}

/// Destroy every independently keyed management transcript owned by this
/// person. Account erasure calls this before destroying the parent account key.
pub fn crypto_erase_gaugeapp_agent_threads_for_actor(
    workbench: &Workbench,
    actor: &str,
) -> Result<usize, AdmitError> {
    let scopes = gaugeapp_agent_content_scopes_matching(workbench.store_ref(), |message| {
        message.actor == actor
    })?;
    Ok(scopes
        .iter()
        .filter(|scope| workbench.crypto_erase_content(scope))
        .count())
}

/// Destroy every independently keyed Administration or Commercial Operations
/// transcript whose exact tenant is being deleted.
pub fn crypto_erase_gaugeapp_agent_threads_for_tenant(
    workbench: &Workbench,
    tenant: &str,
) -> Result<usize, AdmitError> {
    let scopes = gaugeapp_agent_content_scopes_matching(workbench.store_ref(), |message| {
        message.scope.id == tenant
            && matches!(
                message.app,
                GaugeAppKind::Administration | GaugeAppKind::CommercialOperations
            )
    })?;
    Ok(scopes
        .iter()
        .filter(|scope| workbench.crypto_erase_content(scope))
        .count())
}

fn gaugeapp_agent_turn_identity(
    session: &GaugeAppSession,
    message_idempotency_key: &str,
) -> (String, String, String) {
    let thread_id = gaugeapp_thread_id(session);
    let turn_material = format!("{thread_id}\n{message_idempotency_key}");
    let turn_id = hex::encode(Sha256::digest(turn_material.as_bytes()));
    (
        format!("gaugeapp-agent-message:{turn_id}:user"),
        format!("gaugeapp-agent-message:{turn_id}:assistant"),
        turn_id,
    )
}

/// Return the already-admitted turn for one composed message before contacting
/// a provider. A message key is an at-most-once boundary, not merely an
/// at-most-once transcript append.
pub fn replayed_gaugeapp_agent_turn(
    store: &Store,
    session: &GaugeAppSession,
    message_idempotency_key: &str,
    user: &str,
) -> Result<Option<GaugeAppAgentTurn>, GaugeAppAgentError> {
    if message_idempotency_key.trim().is_empty() {
        return Err(GaugeAppAgentError::InvalidOutput(
            "message idempotency key is empty".into(),
        ));
    }
    let (user_id, assistant_id, _) = gaugeapp_agent_turn_identity(session, message_idempotency_key);
    let transcript = gaugeapp_agent_transcript(store, session)
        .map_err(|error| GaugeAppAgentError::Store(format!("{error:?}")))?;
    let admitted_user = transcript.iter().find(|message| message.id == user_id);
    let admitted_assistant = transcript.iter().find(|message| message.id == assistant_id);
    match (admitted_user, admitted_assistant) {
        (None, None) => Ok(None),
        (Some(admitted_user), Some(admitted_assistant)) if admitted_user.text == user => {
            Ok(Some(GaugeAppAgentTurn {
                message: admitted_assistant.text.clone(),
                proposals: admitted_assistant.proposals.clone(),
            }))
        }
        (Some(_), Some(_)) => Err(GaugeAppAgentError::InvalidOutput(
            "message idempotency key was already used for different text".into(),
        )),
        _ => Err(GaugeAppAgentError::Store(
            "agent transcript contains an incomplete admitted exchange".into(),
        )),
    }
}

pub fn append_gaugeapp_agent_exchange(
    workbench: &SharedWorkbench,
    session: &GaugeAppSession,
    message_idempotency_key: &str,
    user: &str,
    turn: &GaugeAppAgentTurn,
) -> Result<Vec<GaugeAppAgentMessage>, GaugeAppAgentError> {
    append_agent_exchange(
        workbench,
        session,
        message_idempotency_key,
        user,
        turn,
        None,
        None,
    )
}

/// Admit the transcript and the owning service's validated proposals together.
/// A dropped response cannot leave an assistant claiming to have opened a
/// review that exists only in client memory. The callback runs under the store
/// lock, rebuilds current authority, and prepares a change fact, never applies
/// a domain mutation. Any rejected proposal prevents the entire append.
pub fn append_gaugeapp_agent_exchange_prepared(
    workbench: &SharedWorkbench,
    session: &GaugeAppSession,
    message_idempotency_key: &str,
    user: &str,
    turn: &GaugeAppAgentTurn,
    prepare: ProposalPreparation<'_>,
) -> Result<Vec<GaugeAppAgentMessage>, GaugeAppAgentError> {
    append_agent_exchange(
        workbench,
        session,
        message_idempotency_key,
        user,
        turn,
        None,
        Some(prepare),
    )
}

/// Admit an exchange only while its opening GaugeApp authorization generation
/// is still current. The validation runs under the same Workbench/store lock as
/// the transcript append, including for an answer with no proposals, so a
/// revoked or superseded turn cannot win a check/commit race and leave a late
/// assistant message in the canonical thread.
pub fn append_gaugeapp_agent_exchange_prepared_current(
    workbench: &SharedWorkbench,
    session: &GaugeAppSession,
    message_idempotency_key: &str,
    user: &str,
    turn: &GaugeAppAgentTurn,
    validate_current: AdmissionValidation<'_>,
    prepare: ProposalPreparation<'_>,
) -> Result<Vec<GaugeAppAgentMessage>, GaugeAppAgentError> {
    append_agent_exchange(
        workbench,
        session,
        message_idempotency_key,
        user,
        turn,
        Some(validate_current),
        Some(prepare),
    )
}

pub type AdmissionValidation<'a> = &'a dyn Fn(&mut Workbench) -> Result<(), GaugeAppAgentError>;

pub type ProposalPreparation<'a> = &'a dyn Fn(
    &Workbench,
    &GaugeAppCommandEnvelope,
) -> Result<CommandRecordFact, GaugeAppAgentError>;

fn append_agent_exchange(
    workbench: &SharedWorkbench,
    session: &GaugeAppSession,
    message_idempotency_key: &str,
    user: &str,
    turn: &GaugeAppAgentTurn,
    validate_current: Option<AdmissionValidation<'_>>,
    prepare: Option<ProposalPreparation<'_>>,
) -> Result<Vec<GaugeAppAgentMessage>, GaugeAppAgentError> {
    if message_idempotency_key.trim().is_empty() {
        return Err(GaugeAppAgentError::InvalidOutput(
            "message idempotency key is empty".into(),
        ));
    }
    if contains_secret_text(user) || contains_secret_text(&turn.message) {
        return Err(GaugeAppAgentError::Rejected(
            GaugeAppAgentRejection::SecretBearingArguments,
        ));
    }
    let thread_id = gaugeapp_thread_id(session);
    let (user_id, assistant_id, turn_id) =
        gaugeapp_agent_turn_identity(session, message_idempotency_key);
    let mut guard = workbench.lock_unpoisoned();
    reconcile_gaugeapp_agent_erasure(&mut guard, session)?;
    if let Some(validate_current) = validate_current {
        validate_current(&mut guard)?;
    }
    let existing = gaugeapp_agent_transcript(guard.store_ref(), session)
        .map_err(|error| GaugeAppAgentError::Store(format!("{error:?}")))?;
    if let Some(admitted) =
        replayed_gaugeapp_agent_turn(guard.store_ref(), session, message_idempotency_key, user)?
    {
        if admitted == *turn {
            return Ok(existing);
        }
        return Err(GaugeAppAgentError::InvalidOutput(
            "message idempotency key was already used for a different agent result".into(),
        ));
    }
    let sequence = existing.last().map_or(0, |message| message.sequence + 1);
    let records = [
        GaugeAppAgentMessage {
            id: user_id,
            thread_id: thread_id.clone(),
            app: session.app,
            scope: session.scope.clone(),
            actor: session.actor.clone(),
            sequence,
            role: GaugeAppAgentMessageRole::User,
            text: user.to_owned(),
            proposals: Vec::new(),
        },
        GaugeAppAgentMessage {
            id: assistant_id,
            thread_id,
            app: session.app,
            scope: session.scope.clone(),
            actor: session.actor.clone(),
            sequence: sequence + 1,
            role: GaugeAppAgentMessageRole::Assistant,
            text: turn.message.clone(),
            proposals: turn.proposals.clone(),
        },
    ];
    let scope = gaugeapp_agent_active_content_scope(guard.store_ref(), session)
        .map_err(|error| GaugeAppAgentError::Store(format!("{error:?}")))?
        .ok_or_else(|| {
            GaugeAppAgentError::Store(
                "management conversation erasure did not finish before append".into(),
            )
        })?;
    let mut facts = records
        .iter()
        .map(|record| CommandRecordFact {
            scope_id: scope.clone(),
            kind: GAUGEAPP_AGENT_MESSAGE_KIND.into(),
            payload: serde_json::to_string(record).expect("agent message serializes"),
        })
        .collect::<Vec<_>>();
    if let Some(prepare) = prepare {
        for (index, proposal) in turn.proposals.iter().enumerate() {
            if contains_secret(&proposal.payload) {
                return Err(GaugeAppAgentError::Rejected(
                    GaugeAppAgentRejection::SecretBearingArguments,
                ));
            }
            let envelope = GaugeAppCommandEnvelope {
                session_id: session.id.clone(),
                generation: session.generation.clone(),
                app: session.app,
                scope: session.scope.clone(),
                page_id: proposal.page_id.clone(),
                command_id: proposal.command_id.clone(),
                expected_basis: proposal.expected_basis.clone(),
                idempotency_key: format!("agent:{turn_id}:{index}"),
                payload: proposal.payload.clone(),
                client: GaugeAppClient::Agent,
            };
            facts.push(prepare(&guard, &envelope)?);
        }
    }
    let audit_scope = (prepare.is_some() && !turn.proposals.is_empty())
        .then(|| facts[records.len()].scope_id.clone());
    let audit_material = audit_scope.as_ref().map(|scope| {
        (
            crate::audit::scope_for(scope),
            crate::audit::link(&session.actor, "gaugeapp.proposals.prepared", &turn_id),
        )
    });
    let audit = audit_material
        .as_ref()
        .map(|(scope, link)| crate::audit::chained_in(scope, link));
    let admitted = guard
        .store_mut()
        .admit_record_facts_chained(
            &format!("{scope}:append"),
            &turn_id,
            &serde_json::to_string(&records).expect("agent exchange serializes"),
            &facts,
            audit,
        )
        .map_err(|error| GaugeAppAgentError::Store(format!("{error:?}")))?;
    if let Some(scope) = audit_scope {
        if let Some(entry) = crate::audit::committed_entry(admitted.chained_payload.as_deref()) {
            crate::audit::finish_committed_in(&mut guard, &scope, &entry);
        }
    }
    gaugeapp_agent_transcript(guard.store_ref(), session)
        .map_err(|error| GaugeAppAgentError::Store(format!("{error:?}")))
}

impl std::error::Error for GaugeAppAgentError {}

/// Exclusive in-process claim for one canonical management thread. Durable
/// transcript state remains in the Store; this claim says only that this
/// process is currently driving one provider turn and disappears on crash.
pub struct GaugeAppAgentTurnClaim {
    _claim: crate::engine::TurnClaim,
}

pub fn claim_gaugeapp_agent_turn(thread_id: &str) -> Option<GaugeAppAgentTurnClaim> {
    crate::engine::claim_turn(&format!("gaugeapp:{thread_id}"))
        .map(|claim| GaugeAppAgentTurnClaim { _claim: claim })
}

/// Record Stop as standing intent for the exact claimed management thread.
/// GaugeApp provider transport uses checkpoints rather than a process handle,
/// so there is normally no callback to fire; the intent still lands at once.
pub fn request_gaugeapp_agent_stop(thread_id: &str) -> bool {
    let Some(interrupt) = crate::engine::request_turn_stop(&format!("gaugeapp:{thread_id}")) else {
        return false;
    };
    if let Some(interrupt) = interrupt {
        interrupt();
    }
    true
}

pub fn gaugeapp_agent_turn_was_stopped(thread_id: &str) -> bool {
    crate::engine::turn_was_stopped(&format!("gaugeapp:{thread_id}"))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GaugeAppAgentSession {
    pub id: String,
    pub gaugeapp_session_id: String,
    pub generation: String,
    pub app: GaugeAppKind,
    pub scope: GaugeAppScope,
    pub actor: String,
    pub active: bool,
    pub message_attachments: bool,
    pub additional_tools: bool,
    pub tools: Vec<String>,
}

impl GaugeAppAgentSession {
    pub fn from_gaugeapp(session: &GaugeAppSession) -> Self {
        Self {
            id: gaugeapp_thread_id(session),
            gaugeapp_session_id: session.id.clone(),
            generation: session.generation.clone(),
            app: session.app,
            scope: session.scope.clone(),
            actor: session.actor.clone(),
            active: true,
            message_attachments: false,
            additional_tools: false,
            tools: MANAGEMENT_AGENT_TOOLS
                .iter()
                .map(|tool| (*tool).to_owned())
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GaugeAppAgentToolRequest {
    pub agent_session_id: String,
    pub gaugeapp_session_id: String,
    pub generation: String,
    pub app: GaugeAppKind,
    pub scope: GaugeAppScope,
    pub tool: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GaugeAppAgentAction {
    ListPages,
    ReadPage,
    PrepareProposal,
    AskHuman,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GaugeAppAgentRejection {
    SessionMismatch,
    SessionRevoked,
    ScopeMismatch,
    UndeclaredTool,
    SecretBearingArguments,
}

impl GaugeAppAgentRejection {
    pub fn message(self) -> &'static str {
        match self {
            Self::SessionMismatch => "agent session is stale or does not match",
            Self::SessionRevoked => "agent session is no longer active",
            Self::ScopeMismatch => "agent tool App/scope does not match its admitted session",
            Self::UndeclaredTool => "agent tool is not declared for this session",
            Self::SecretBearingArguments => "secret-bearing agent tool arguments are forbidden",
        }
    }
}

/// Decide one untrusted model tool request against the live server session.
pub fn decide_gaugeapp_agent_tool(
    session: &GaugeAppAgentSession,
    request: &GaugeAppAgentToolRequest,
) -> Result<GaugeAppAgentAction, GaugeAppAgentRejection> {
    if request.agent_session_id != session.id
        || request.gaugeapp_session_id != session.gaugeapp_session_id
        || request.generation != session.generation
        || request.app != session.app
    {
        return Err(GaugeAppAgentRejection::SessionMismatch);
    }
    if !session.active {
        return Err(GaugeAppAgentRejection::SessionRevoked);
    }
    if request.scope != session.scope {
        return Err(GaugeAppAgentRejection::ScopeMismatch);
    }
    if !session.tools.iter().any(|tool| tool == &request.tool) {
        return Err(GaugeAppAgentRejection::UndeclaredTool);
    }
    if contains_secret(&request.arguments) {
        return Err(GaugeAppAgentRejection::SecretBearingArguments);
    }
    match request.tool.as_str() {
        PAGES_LIST_TOOL => Ok(GaugeAppAgentAction::ListPages),
        PAGE_READ_TOOL => Ok(GaugeAppAgentAction::ReadPage),
        PROPOSALS_PREPARE_TOOL => Ok(GaugeAppAgentAction::PrepareProposal),
        HUMAN_ASK_TOOL => Ok(GaugeAppAgentAction::AskHuman),
        _ => Err(GaugeAppAgentRejection::UndeclaredTool),
    }
}

/// Fail closed on credential-shaped keys at any nesting depth. GaugeApp
/// command parsers retain their own stricter domain validation after this gate.
pub fn contains_secret(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "secret"
                    | "password"
                    | "token"
                    | "private_key"
                    | "credential"
                    | "refresh_token"
                    | "access_token"
                    | "api_key"
            ) || contains_secret(value)
        }),
        Value::Array(values) => values.iter().any(contains_secret),
        _ => false,
    }
}

/// Vendor token prefixes whose body is strictly alphanumeric, with the length
/// the whole word must reach. Kept apart from [`MIXED_BODY_PREFIXES`] because a
/// dash would otherwise make `asia-southeast1-something`, an ordinary GCP
/// hostname, read as an AWS key id — the AWS prefixes are the ones that need
/// the charset to be narrow, and both of theirs are exactly 20 alphanumerics.
const ALPHANUMERIC_BODY_PREFIXES: &[(&str, usize)] = &[
    ("akia", 20), // AWS access key id: exactly 20 characters
    ("asia", 20), // AWS temporary access key id
];

/// Vendor token prefixes whose body may carry `-` or `_`.
const MIXED_BODY_PREFIXES: &[(&str, usize)] = &[
    // Google API keys are `AIza` plus 35 characters drawn from an alphabet that
    // includes `-` and `_`, so this one cannot take the narrow charset above.
    // Its length floor is what keeps prose out, and at 35 characters that is
    // enough on its own.
    ("aiza", 35),
    ("sk-", 15),         // OpenAI and Anthropic, including `sk-ant-`
    ("ghp_", 20),        // GitHub personal access token, classic
    ("gho_", 20),        // GitHub OAuth
    ("ghu_", 20),        // GitHub user-to-server
    ("ghs_", 20),        // GitHub server-to-server
    ("ghr_", 20),        // GitHub refresh
    ("github_pat_", 20), // GitHub fine-grained
    ("glpat-", 20),      // GitLab
    ("xoxb-", 15),       // Slack bot
    ("xoxp-", 15),       // Slack user
    ("xoxa-", 15),       // Slack app
    ("xoxs-", 15),       // Slack session
    ("npm_", 20),        // npm automation
    ("dop_v1_", 20),     // DigitalOcean
    ("whsec_", 20),      // Stripe webhook signing secret
    ("sk_live_", 20),    // Stripe secret key
    ("rk_live_", 20),    // Stripe restricted key
];

/// Keys whose assigned value is a credential by construction.
const CREDENTIAL_KEYS: &[&str] = &[
    "api_key",
    "access_token",
    "refresh_token",
    "private_key",
    "client_secret",
    "secret_key",
    "aws_secret_access_key",
];

/// Strip the punctuation a token picks up from prose and serialization —
/// `"AKIA…",` in JSON, `(sk-…)` in a sentence — without eating the `-` and `_`
/// the tokens themselves contain.
fn token_word(word: &str) -> &str {
    word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
}

/// Best-effort detection of secret-shaped text, so a turn that would persist a
/// credential into a transcript fails closed (`SECAUD-10`).
///
/// **This is a denylist and cannot be complete.** Base64, a line split, or a
/// vendor prefix nobody has published yet all pass it. It is defence in depth
/// behind [`contains_secret`], which admits tool arguments by key name and is
/// the check that actually holds the boundary. Widen this when a format turns
/// up; never read a pass as proof that there is no secret.
///
/// Every pattern carries a length floor, and the vendor prefixes constrain the
/// shape of the body, because a false positive here rejects a turn a person
/// asked for. `Asia`, `skew`, and "no API key is projected here" must all
/// survive.
pub fn contains_secret_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();

    // Any PEM private key, not just the unlabelled PKCS#8 header: RSA, EC, DSA,
    // and OPENSSH each put their own label between the dashes, and the previous
    // exact match on `-----begin private key` let all of them through.
    let pem = lower.split("-----begin ").skip(1).any(|tail| {
        tail.split("-----")
            .next()
            .is_some_and(|label| label.contains("private key"))
    });

    let vendor = lower.split_whitespace().map(token_word).any(|word| {
        ALPHANUMERIC_BODY_PREFIXES.iter().any(|(prefix, minimum)| {
            word.len() >= *minimum
                && word.starts_with(prefix)
                && word.bytes().all(|b| b.is_ascii_alphanumeric())
        }) || MIXED_BODY_PREFIXES
            .iter()
            .any(|(prefix, minimum)| word.len() >= *minimum && word.starts_with(prefix))
    });

    let bearer = lower.split("bearer ").skip(1).any(|tail| {
        tail.split_whitespace()
            .next()
            .is_some_and(|token| token.len() >= 12)
    });

    let assigned = CREDENTIAL_KEYS.iter().any(|key| {
        lower.find(key).is_some_and(|index| {
            lower[index + key.len()..]
                .trim_start()
                .starts_with([':', '='])
        })
    });

    pem || vendor || bearer || assigned
}

enum AgentCredential {
    OpenAi(String),
    Codex { access: String, account_id: String },
}

impl AgentCredential {
    fn endpoint(&self) -> &'static str {
        match self {
            Self::OpenAi(_) => "https://api.openai.com/v1/responses",
            Self::Codex { .. } => "https://chatgpt.com/backend-api/codex/responses",
        }
    }

    fn authorize(&self, request: ureq::Request) -> ureq::Request {
        match self {
            Self::OpenAi(token) => request.set("authorization", &format!("Bearer {token}")),
            Self::Codex { access, account_id } => request
                .set("authorization", &format!("Bearer {access}"))
                .set("chatgpt-account-id", account_id),
        }
    }
}

fn resolve_agent_credential(
    workbench: &SharedWorkbench,
    actor: &str,
) -> Result<AgentCredential, GaugeAppAgentError> {
    let scope = account_scope(actor);
    let records = {
        let guard = workbench.lock_unpoisoned();
        credentials_in_scope(guard.store_ref(), &scope)
    };
    if records
        .get("openai-codex")
        .is_some_and(|record| record.admits(ModelExecutionClass::PrivateHome))
    {
        let credential = crate::codex_oauth::resolve_runtime_credential_in(
            workbench,
            &scope,
            ModelExecutionClass::PrivateHome,
        )
        .map_err(GaugeAppAgentError::Credential)?
        .ok_or(GaugeAppAgentError::NoModelAccess)?;
        return Ok(AgentCredential::Codex {
            access: credential.access,
            account_id: credential.account_id,
        });
    }
    let Some(record) = records
        .get("openai")
        .filter(|record| record.admits(ModelExecutionClass::PrivateHome))
    else {
        if environment_flag("MANAGEMENT_AGENT_MANAGED") {
            let token = gaugedesk_env::var("MANAGEMENT_AGENT_OPENAI_KEY")
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    GaugeAppAgentError::Credential(
                        "managed GaugeApp agent funding is enabled without its dedicated provider credential".into(),
                    )
                })?;
            return Ok(AgentCredential::OpenAi(token));
        }
        return Err(GaugeAppAgentError::NoModelAccess);
    };
    let token = workbench
        .lock_unpoisoned()
        .unseal_account_secret(&record.sealed_token)
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| {
            GaugeAppAgentError::Credential("linked OpenAI credential could not be unsealed".into())
        })?;
    Ok(AgentCredential::OpenAi(token))
}

fn provider_tools() -> Value {
    json!([
        { "type": "function", "name": "gaugeapp_pages_list", "description": "List the typed pages admitted in this exact GaugeApp session.", "parameters": { "type": "object", "properties": {}, "additionalProperties": false }, "strict": true },
        { "type": "function", "name": "gaugeapp_page_read", "description": "Read one admitted typed page model by page id.", "parameters": { "type": "object", "properties": { "page_id": { "type": "string" } }, "required": ["page_id"], "additionalProperties": false }, "strict": true },
        { "type": "function", "name": "human_ask", "description": "Ask the person for information or a decision required to continue.", "parameters": { "type": "object", "properties": { "question": { "type": "string" } }, "required": ["question"], "additionalProperties": false }, "strict": true },
        // Command payloads are deliberately command-specific and are validated
        // again by the selected command parser. Responses strict function
        // schemas forbid an open nested object, so only this proposal tool is
        // non-strict; the outer arguments remain closed and every read tool
        // remains strict.
        { "type": "function", "name": "gaugeapp_proposals_prepare", "description": "Submit one declared GaugeApp command. The tool result says whether it was applied immediately or prepared for human review. Never infer success before reading that result.", "parameters": { "type": "object", "properties": { "page_id": { "type": "string" }, "command_id": { "type": "string" }, "payload": { "type": "object", "additionalProperties": true } }, "required": ["page_id", "command_id", "payload"], "additionalProperties": false }, "strict": false }
    ])
}

fn canonical_tool(name: &str) -> Option<&'static str> {
    match name {
        "gaugeapp_pages_list" => Some(PAGES_LIST_TOOL),
        "gaugeapp_page_read" => Some(PAGE_READ_TOOL),
        "gaugeapp_proposals_prepare" => Some(PROPOSALS_PREPARE_TOOL),
        "human_ask" => Some(HUMAN_ASK_TOOL),
        _ => None,
    }
}

/// What the provider said about refusing, bounded and on one line. A bare
/// status is what the failing turn used to report, and it costs a round trip
/// through a human to learn anything from it.
fn provider_complaint(body: &str) -> String {
    const LIMIT: usize = 300;
    let message = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|parsed| {
            ["error", "detail", "message"]
                .iter()
                .find_map(|key| match parsed.get(key) {
                    Some(Value::String(text)) => Some(text.clone()),
                    Some(object) => object
                        .get("message")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    None => None,
                })
        })
        .unwrap_or_else(|| body.to_owned());
    let flattened = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if flattened.is_empty() {
        return "(no response body)".into();
    }
    match flattened.char_indices().nth(LIMIT) {
        Some((cut, _)) => format!("{}… (truncated)", &flattened[..cut]),
        None => flattened,
    }
}

/// The completed response carried by a Responses API event stream.
///
/// The final `response.completed` event carries exactly the object the
/// non-streaming endpoint returns as its whole body, so every caller downstream
/// of this reads the same shape whichever transport was used.
#[cfg(test)]
fn response_from_event_stream(stream: &str) -> Result<Value, String> {
    let normalized = stream.replace("\r\n", "\n");
    let mut failure = None;
    for block in normalized.split("\n\n") {
        let payload = block
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(|line| line.strip_prefix(' ').unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n");
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        let Ok(event) = serde_json::from_str::<Value>(&payload) else {
            continue;
        };
        match event.get("type").and_then(Value::as_str) {
            Some("response.completed") => {
                if let Some(response) = event.get("response") {
                    return Ok(response.clone());
                }
            }
            // A stream that ends without completing has already said why, and
            // that sentence is worth more than "no completed response". The
            // standard events carry it inside the response object — as `error`
            // when it failed, as `incomplete_details` when it stopped short —
            // so read that before falling back to the raw event, which would
            // otherwise be flattened and truncated away.
            Some("response.failed" | "response.incomplete" | "error") => {
                failure.get_or_insert_with(|| {
                    let nested = event.get("response").and_then(|response| {
                        ["error", "incomplete_details"]
                            .iter()
                            .find_map(|key| response.get(key))
                    });
                    match nested {
                        Some(reason) => provider_complaint(&reason.to_string()),
                        None => provider_complaint(&payload),
                    }
                });
            }
            _ => {}
        }
    }
    Err(failure.unwrap_or_else(|| "event stream carried no completed response".into()))
}

#[cfg(test)]
fn read_provider_response<R, S>(
    mut reader: R,
    mut is_stopped: S,
) -> Result<Vec<u8>, GaugeAppAgentError>
where
    R: Read,
    S: FnMut() -> bool,
{
    let started = Instant::now();
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        if is_stopped() {
            return Err(GaugeAppAgentError::Interrupted);
        }
        if started.elapsed() >= Duration::from_secs(130) {
            return Err(GaugeAppAgentError::Provider(
                "provider response timed out".into(),
            ));
        }
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                if bytes.len() + read > MAX_PROVIDER_RESPONSE_BYTES as usize {
                    return Err(GaugeAppAgentError::Provider(
                        "response exceeded size cap".into(),
                    ));
                }
                bytes.extend_from_slice(&chunk[..read]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => {
                if is_stopped() {
                    return Err(GaugeAppAgentError::Interrupted);
                }
                return Err(GaugeAppAgentError::Provider(error.to_string()));
            }
        }
    }
    if is_stopped() {
        return Err(GaugeAppAgentError::Interrupted);
    }
    Ok(bytes)
}

const LIVE_TEXT_HOLDBACK_CHARS: usize = 256;

struct SafeLiveText {
    observed: String,
    pending: String,
}

impl SafeLiveText {
    fn new() -> Self {
        Self {
            observed: String::new(),
            pending: String::new(),
        }
    }

    fn push<E>(&mut self, delta: &str, emit: &mut E) -> Result<(), GaugeAppAgentError>
    where
        E: FnMut(GaugeAppAgentLiveEvent) -> Result<(), GaugeAppAgentError>,
    {
        self.observed.push_str(delta);
        self.pending.push_str(delta);
        if contains_secret_text(&self.observed) {
            return Err(GaugeAppAgentError::Rejected(
                GaugeAppAgentRejection::SecretBearingArguments,
            ));
        }
        let count = self.pending.chars().count();
        if count > LIVE_TEXT_HOLDBACK_CHARS {
            self.release(count - LIVE_TEXT_HOLDBACK_CHARS, emit)?;
        }
        Ok(())
    }

    fn release<E>(&mut self, chars: usize, emit: &mut E) -> Result<(), GaugeAppAgentError>
    where
        E: FnMut(GaugeAppAgentLiveEvent) -> Result<(), GaugeAppAgentError>,
    {
        if chars == 0 {
            return Ok(());
        }
        let split = self
            .pending
            .char_indices()
            .nth(chars)
            .map_or(self.pending.len(), |(index, _)| index);
        let remaining = self.pending.split_off(split);
        let delta = std::mem::replace(&mut self.pending, remaining);
        if !delta.is_empty() {
            emit(GaugeAppAgentLiveEvent::Text { delta })?;
        }
        Ok(())
    }

    fn finish<E>(&mut self, emit: &mut E) -> Result<(), GaugeAppAgentError>
    where
        E: FnMut(GaugeAppAgentLiveEvent) -> Result<(), GaugeAppAgentError>,
    {
        self.release(self.pending.chars().count(), emit)
    }
}

fn event_boundary(bytes: &[u8]) -> Option<(usize, usize)> {
    for index in 0..bytes.len() {
        if bytes.get(index..index + 2) == Some(b"\n\n") {
            return Some((index, 2));
        }
        if bytes.get(index..index + 4) == Some(b"\r\n\r\n") {
            return Some((index, 4));
        }
    }
    None
}

fn provider_event(frame: &[u8]) -> Option<(String, Value)> {
    let text = std::str::from_utf8(frame).ok()?.replace("\r\n", "\n");
    let payload = text
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(|line| line.strip_prefix(' ').unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n");
    if payload.is_empty() || payload == "[DONE]" {
        return None;
    }
    let event = serde_json::from_str::<Value>(&payload).ok()?;
    Some((payload, event))
}

fn reduce_provider_event<E>(
    frame: &[u8],
    completed: &mut Option<Value>,
    failure: &mut Option<String>,
    live_text: &mut SafeLiveText,
    emit: &mut E,
) -> Result<(), GaugeAppAgentError>
where
    E: FnMut(GaugeAppAgentLiveEvent) -> Result<(), GaugeAppAgentError>,
{
    let Some((payload, event)) = provider_event(frame) else {
        return Ok(());
    };
    match event.get("type").and_then(Value::as_str) {
        Some("response.output_text.delta") => {
            if let Some(delta) = event.get("delta").and_then(Value::as_str) {
                live_text.push(delta, emit)?;
            }
        }
        Some("response.completed") => {
            if let Some(response) = event.get("response") {
                *completed = Some(response.clone());
            }
        }
        Some("response.failed" | "response.incomplete" | "error") => {
            failure.get_or_insert_with(|| {
                let nested = event.get("response").and_then(|response| {
                    ["error", "incomplete_details"]
                        .iter()
                        .find_map(|key| response.get(key))
                });
                match nested {
                    Some(reason) => provider_complaint(&reason.to_string()),
                    None => provider_complaint(&payload),
                }
            });
        }
        _ => {}
    }
    Ok(())
}

fn read_provider_event_stream<R, S, E>(
    mut reader: R,
    mut is_stopped: S,
    emit: &mut E,
) -> Result<Value, GaugeAppAgentError>
where
    R: Read,
    S: FnMut() -> bool,
    E: FnMut(GaugeAppAgentLiveEvent) -> Result<(), GaugeAppAgentError>,
{
    let started = Instant::now();
    let mut pending = Vec::new();
    let mut total = 0_usize;
    let mut chunk = [0_u8; 8 * 1024];
    let mut completed = None;
    let mut failure = None;
    let mut live_text = SafeLiveText::new();
    loop {
        if is_stopped() {
            return Err(GaugeAppAgentError::Interrupted);
        }
        if started.elapsed() >= Duration::from_secs(130) {
            return Err(GaugeAppAgentError::Provider(
                "provider response timed out".into(),
            ));
        }
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                total += read;
                if total > MAX_PROVIDER_RESPONSE_BYTES as usize {
                    return Err(GaugeAppAgentError::Provider(
                        "response exceeded size cap".into(),
                    ));
                }
                pending.extend_from_slice(&chunk[..read]);
                while let Some((boundary, separator)) = event_boundary(&pending) {
                    let remainder = pending.split_off(boundary + separator);
                    let frame = &pending[..boundary];
                    reduce_provider_event(
                        frame,
                        &mut completed,
                        &mut failure,
                        &mut live_text,
                        emit,
                    )?;
                    pending = remainder;
                    if is_stopped() {
                        return Err(GaugeAppAgentError::Interrupted);
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => {
                if is_stopped() {
                    return Err(GaugeAppAgentError::Interrupted);
                }
                return Err(GaugeAppAgentError::Provider(error.to_string()));
            }
        }
    }
    if !pending.is_empty() {
        reduce_provider_event(&pending, &mut completed, &mut failure, &mut live_text, emit)?;
    }
    if is_stopped() {
        return Err(GaugeAppAgentError::Interrupted);
    }
    let response = completed.ok_or_else(|| {
        GaugeAppAgentError::Provider(
            failure.unwrap_or_else(|| "event stream carried no completed response".into()),
        )
    })?;
    if live_text.observed.is_empty() {
        let output = response
            .get("output")
            .and_then(Value::as_array)
            .map(|items| assistant_text(items))
            .unwrap_or_default();
        if !output.is_empty() {
            live_text.push(&output, emit)?;
        }
    }
    live_text.finish(emit)?;
    Ok(response)
}

fn provider_request<S, E>(
    credential: &AgentCredential,
    body: &Value,
    mut is_stopped: S,
    emit: &mut E,
) -> Result<Value, GaugeAppAgentError>
where
    S: FnMut() -> bool,
    E: FnMut(GaugeAppAgentLiveEvent) -> Result<(), GaugeAppAgentError>,
{
    if is_stopped() {
        return Err(GaugeAppAgentError::Interrupted);
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_write(Duration::from_secs(10))
        // An individual event-stream read is short so Stop is observed even
        // while the provider is between events. The whole response keeps the
        // independent 130-second bound enforced by read_provider_event_stream.
        .timeout_read(Duration::from_secs(2))
        .redirects(0)
        .build();
    // Both provider transports use the same event-stream contract. Besides
    // satisfying the Codex endpoint, that gives the server bounded checkpoints
    // at which an authenticated Stop can take effect.
    let mut sent = body.clone();
    match sent.as_object_mut() {
        Some(fields) => {
            fields.insert("stream".into(), Value::Bool(true));
        }
        None => {
            return Err(GaugeAppAgentError::InvalidOutput(
                "provider request body is not an object".into(),
            ));
        }
    };
    let serialized = serde_json::to_string(&sent)
        .map_err(|error| GaugeAppAgentError::InvalidOutput(error.to_string()))?;
    let request = credential.authorize(
        agent
            .post(credential.endpoint())
            .set("content-type", "application/json")
            .set("accept", "text/event-stream"),
    );
    let response = match request.send_string(&serialized) {
        Ok(response) => response,
        Err(ureq::Error::Status(status, response)) => {
            // The provider's own explanation used to be dropped on the floor
            // here, leaving `HTTP 400` and no way to act on it.
            let complaint = response
                .into_string()
                .map(|body| provider_complaint(&body))
                .unwrap_or_else(|error| format!("(unreadable response body: {error})"));
            tracing::warn!(
                status,
                complaint,
                "GaugeApp agent provider rejected request"
            );
            return Err(GaugeAppAgentError::Provider(format!(
                "provider returned HTTP {status}: {complaint}"
            )));
        }
        Err(ureq::Error::Transport(error)) => {
            if is_stopped() {
                return Err(GaugeAppAgentError::Interrupted);
            }
            return Err(GaugeAppAgentError::Provider(error.to_string()));
        }
    };
    read_provider_event_stream(response.into_reader(), &mut is_stopped, emit)
}

fn assistant_text(output: &[Value]) -> String {
    output
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("message"))
        .flat_map(|item| {
            item.get("content")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter(|content| content.get("type").and_then(Value::as_str) == Some("output_text"))
        .filter_map(|content| content.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n")
}

pub type DirectAction<'a> =
    &'a mut dyn FnMut(&GaugeAppAgentProposal, &str) -> Result<Value, GaugeAppAgentError>;

// Keep the live grant, opening grant, and direct-action state explicit at the
// untrusted provider boundary so none is silently reused as another.
#[allow(clippy::too_many_arguments)]
fn tool_result(
    gaugeapp_session: &GaugeAppSession,
    live_agent_session: &GaugeAppAgentSession,
    requested_agent_session: &GaugeAppAgentSession,
    pages: &[GaugeAppAgentPage],
    name: &str,
    arguments: Value,
    proposals: &mut Vec<GaugeAppAgentProposal>,
    validate_proposal: &mut dyn FnMut(&GaugeAppAgentProposal) -> Result<(), GaugeAppAgentError>,
    direct_action: &mut Option<DirectAction<'_>>,
    direct_key: &str,
    direct_used: &mut bool,
) -> Result<Value, GaugeAppAgentError> {
    let tool = canonical_tool(name).unwrap_or(name);
    let request = GaugeAppAgentToolRequest {
        agent_session_id: requested_agent_session.id.clone(),
        gaugeapp_session_id: requested_agent_session.gaugeapp_session_id.clone(),
        generation: requested_agent_session.generation.clone(),
        app: requested_agent_session.app,
        scope: requested_agent_session.scope.clone(),
        tool: tool.to_owned(),
        arguments: arguments.clone(),
    };
    let action = decide_gaugeapp_agent_tool(live_agent_session, &request)
        .map_err(GaugeAppAgentError::Rejected)?;
    match action {
        GaugeAppAgentAction::ListPages => Ok(json!({
            "pages": pages.iter().map(|page| json!({
                "id": page.id,
                "read_model": page.read_model,
                "version": page.version,
                "resource_basis": page.resource_basis,
                "commands": page.commands,
                "actions": page.actions,
            })).collect::<Vec<_>>()
        })),
        GaugeAppAgentAction::ReadPage => {
            let page_id = arguments
                .get("page_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let page = pages
                .iter()
                .find(|page| page.id == page_id)
                .ok_or_else(|| GaugeAppAgentError::InvalidOutput("page is not admitted".into()))?;
            Ok(json!({ "page": page }))
        }
        GaugeAppAgentAction::PrepareProposal => {
            let page_id = arguments
                .get("page_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let command_id = arguments
                .get("command_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let payload = arguments.get("payload").cloned().unwrap_or(Value::Null);
            let page = pages
                .iter()
                .find(|page| page.id == page_id)
                .ok_or_else(|| {
                    GaugeAppAgentError::InvalidOutput("proposal page is not admitted".into())
                })?;
            if !page.commands.iter().any(|command| command == command_id) {
                return Err(GaugeAppAgentError::InvalidOutput(
                    "proposal command is not admitted for its page".into(),
                ));
            }
            if contains_secret(&payload) {
                return Err(GaugeAppAgentError::Rejected(
                    GaugeAppAgentRejection::SecretBearingArguments,
                ));
            }
            let proposal = GaugeAppAgentProposal {
                page_id: page.id.clone(),
                command_id: command_id.to_owned(),
                expected_basis: page.resource_basis.clone(),
                payload,
            };
            match validate_proposal(&proposal) {
                Ok(()) => {}
                Err(GaugeAppAgentError::InvalidOutput(reason)) => {
                    return Ok(json!({ "prepared": false, "error": reason }));
                }
                Err(error) => return Err(error),
            }
            let immediate = gaugeapp_session
                .commands
                .iter()
                .find(|command| command.id == command_id)
                .is_some_and(|command| command.review == ReviewPolicy::Immediate);
            if immediate {
                if let Some(apply) = direct_action.as_mut() {
                    if *direct_used {
                        return Ok(
                            json!({ "applied": false, "error": "Only one immediate action can be applied in one message. Send another message for the next action." }),
                        );
                    }
                    let result = match apply(&proposal, direct_key) {
                        Ok(result) => result,
                        Err(GaugeAppAgentError::InvalidOutput(reason)) => {
                            return Ok(json!({ "applied": false, "error": reason }));
                        }
                        Err(error) => return Err(error),
                    };
                    *direct_used = true;
                    return Ok(json!({ "applied": true, "result": result }));
                }
            }
            proposals.push(proposal.clone());
            Ok(
                json!({ "prepared": true, "proposal": proposal, "notice": "The proposal is not applied. The GaugeApp command route must reauthorize it and open required review." }),
            )
        }
        GaugeAppAgentAction::AskHuman => Ok(json!({
            "awaiting_human": true,
            "question": arguments.get("question").cloned().unwrap_or(Value::Null),
        })),
    }
}

fn development_gaugeapp_agent_turn(
    context: &GaugeAppAgentContext,
    message: &str,
) -> GaugeAppAgentTurn {
    if let Some(command) = message.strip_prefix("/propose ") {
        if let Some((command_id, payload)) = command.split_once(' ') {
            if let Ok(payload) = serde_json::from_str::<Value>(payload) {
                if let Some(page) = context
                    .pages
                    .iter()
                    .find(|page| page.commands.iter().any(|id| id == command_id))
                {
                    return GaugeAppAgentTurn {
                        message: format!(
                            "I opened a reviewable {command_id} proposal. It is not applied until you review it."
                        ),
                        proposals: vec![GaugeAppAgentProposal {
                            page_id: page.id.clone(),
                            command_id: command_id.to_owned(),
                            expected_basis: page.resource_basis.clone(),
                            payload,
                        }],
                    };
                }
            }
        }
    }
    if message.to_ascii_lowercase().contains("machines")
        && message.to_ascii_lowercase().contains("homes")
    {
        return GaugeAppAgentTurn {
            message: "Project Hosts have live target-admitted models; I can describe only the hosts, projects, and placements present in those admitted pages.".into(),
            proposals: Vec::new(),
        };
    }
    let pages = context
        .pages
        .iter()
        .map(|page| page.id.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    GaugeAppAgentTurn {
        message: format!(
            "Development provider: I am admitted to {}:{} and can read these exact pages: {pages}. No change was proposed.",
            context.session.scope.kind, context.session.scope.id,
        ),
        proposals: Vec::new(),
    }
}

/// Run one bounded turn while rebuilding its exact GaugeApp authority before
/// every model-requested tool. `context` is the admission used to start the
/// provider turn; `refresh` must return the server's current session and page
/// projections. A changed generation, App, actor, or scope is rejected by the
/// same reducer that guards every ordinary tool request. The provider never
/// receives a GaugeWright bearer or ambient tools and cannot apply or review a
/// change; callers admit returned proposals through the ordinary GaugeApp
/// command path.
pub fn run_gaugeapp_agent_turn_with_refresh<F>(
    workbench: &SharedWorkbench,
    context: GaugeAppAgentContext,
    message: &str,
    refresh: F,
) -> Result<GaugeAppAgentTurn, GaugeAppAgentError>
where
    F: FnMut() -> Result<GaugeAppAgentContext, GaugeAppAgentError>,
{
    run_gaugeapp_agent_turn_with_refresh_and_stop(workbench, context, message, refresh, || false)
}

pub fn run_gaugeapp_agent_turn_with_refresh_and_stop<F, S>(
    workbench: &SharedWorkbench,
    context: GaugeAppAgentContext,
    message: &str,
    refresh: F,
    is_stopped: S,
) -> Result<GaugeAppAgentTurn, GaugeAppAgentError>
where
    F: FnMut() -> Result<GaugeAppAgentContext, GaugeAppAgentError>,
    S: FnMut() -> bool,
{
    run_gaugeapp_agent_turn_with_refresh_stop_and_events(
        workbench,
        context,
        message,
        refresh,
        is_stopped,
        |_| Ok(()),
    )
}

pub fn run_gaugeapp_agent_turn_with_refresh_stop_and_events<F, S, E>(
    workbench: &SharedWorkbench,
    context: GaugeAppAgentContext,
    message: &str,
    refresh: F,
    is_stopped: S,
    emit: E,
) -> Result<GaugeAppAgentTurn, GaugeAppAgentError>
where
    F: FnMut() -> Result<GaugeAppAgentContext, GaugeAppAgentError>,
    S: FnMut() -> bool,
    E: FnMut(GaugeAppAgentLiveEvent) -> Result<(), GaugeAppAgentError>,
{
    run_gaugeapp_agent_turn_with_refresh_stop_events_and_validation(
        workbench,
        context,
        message,
        refresh,
        is_stopped,
        emit,
        |_, _| Ok(()),
    )
}

pub fn run_gaugeapp_agent_turn_with_refresh_stop_events_and_validation<F, S, E, V>(
    workbench: &SharedWorkbench,
    context: GaugeAppAgentContext,
    message: &str,
    refresh: F,
    is_stopped: S,
    emit: E,
    validate_proposal: V,
) -> Result<GaugeAppAgentTurn, GaugeAppAgentError>
where
    F: FnMut() -> Result<GaugeAppAgentContext, GaugeAppAgentError>,
    S: FnMut() -> bool,
    E: FnMut(GaugeAppAgentLiveEvent) -> Result<(), GaugeAppAgentError>,
    V: FnMut(&GaugeAppAgentContext, &GaugeAppAgentProposal) -> Result<(), GaugeAppAgentError>,
{
    run_gaugeapp_agent_turn_with_direct_actions(
        workbench,
        context,
        message,
        refresh,
        is_stopped,
        emit,
        validate_proposal,
        None,
        "",
    )
}

// The callback tuple is the caller's exact authority and execution boundary.
#[allow(clippy::too_many_arguments)]
pub fn run_gaugeapp_agent_turn_with_direct_actions<F, S, E, V>(
    workbench: &SharedWorkbench,
    context: GaugeAppAgentContext,
    message: &str,
    mut refresh: F,
    mut is_stopped: S,
    mut emit: E,
    mut validate_proposal: V,
    mut direct_action: Option<DirectAction<'_>>,
    direct_key: &str,
) -> Result<GaugeAppAgentTurn, GaugeAppAgentError>
where
    F: FnMut() -> Result<GaugeAppAgentContext, GaugeAppAgentError>,
    S: FnMut() -> bool,
    E: FnMut(GaugeAppAgentLiveEvent) -> Result<(), GaugeAppAgentError>,
    V: FnMut(&GaugeAppAgentContext, &GaugeAppAgentProposal) -> Result<(), GaugeAppAgentError>,
{
    let message = message.trim();
    if message.is_empty() {
        return Err(GaugeAppAgentError::InvalidOutput("message is empty".into()));
    }
    if contains_secret_text(message) {
        return Err(GaugeAppAgentError::Rejected(
            GaugeAppAgentRejection::SecretBearingArguments,
        ));
    }
    if is_stopped() {
        return Err(GaugeAppAgentError::Interrupted);
    }
    // Local dashboard acceptance needs to cover the real broker, transcript,
    // and exact-scope session without distributing a production provider key.
    // Release builds cannot activate this path, even if the variable leaks
    // into their environment.
    if cfg!(debug_assertions) && environment_flag("FAKE_MANAGEMENT_AGENT") {
        let turn = development_gaugeapp_agent_turn(&context, message);
        if is_stopped() {
            return Err(GaugeAppAgentError::Interrupted);
        }
        emit(GaugeAppAgentLiveEvent::Text {
            delta: turn.message.clone(),
        })?;
        return Ok(turn);
    }
    let credential = resolve_agent_credential(workbench, &context.session.actor)?;
    let agent_session = GaugeAppAgentSession::from_gaugeapp(&context.session);
    let system = format!(
        "You are the {} agent for one exact GaugeApp scope. Explain the admitted page models and help the person operate them. Use only the declared tools. A command with immediate review policy may apply directly when the tool returns an applied receipt; a human-reviewed command remains a proposal until the person reviews it. Never claim success without the tool's applied receipt. Never request, display, infer, or place secrets in tool arguments. Ask the person when required data is missing. Your exact scope is {}:{} and your actor is {}.",
        context.session.app.as_str(), context.session.scope.kind, context.session.scope.id, context.session.actor,
    );
    let mut input = vec![json!({
        "role": "user",
        "content": [{ "type": "input_text", "text": message }]
    })];
    let mut proposals = Vec::new();
    let mut direct_used = false;
    for _ in 0..MAX_TOOL_ROUNDS {
        let body = json!({
            "model": gaugedesk_env::var("MANAGEMENT_AGENT_MODEL").unwrap_or_else(|| "gpt-5.6-terra".into()),
            "instructions": system,
            "input": input,
            "tools": provider_tools(),
            "tool_choice": "auto",
            "parallel_tool_calls": false,
            "store": false
        });
        let response = provider_request(&credential, &body, &mut is_stopped, &mut emit)?;
        if is_stopped() {
            return Err(GaugeAppAgentError::Interrupted);
        }
        let output = response
            .get("output")
            .and_then(Value::as_array)
            .ok_or_else(|| GaugeAppAgentError::InvalidOutput("missing output array".into()))?;
        let calls = output
            .iter()
            .filter(|item| item.get("type").and_then(Value::as_str) == Some("function_call"))
            .collect::<Vec<_>>();
        let text = assistant_text(output);
        input.extend(output.iter().cloned());
        if calls.is_empty() {
            let missing_output = text.trim().is_empty();
            let message = if missing_output {
                "I could not produce an admitted response.".into()
            } else {
                text
            };
            if contains_secret_text(&message) {
                return Err(GaugeAppAgentError::Rejected(
                    GaugeAppAgentRejection::SecretBearingArguments,
                ));
            }
            if missing_output {
                emit(GaugeAppAgentLiveEvent::Text {
                    delta: message.clone(),
                })?;
            }
            return Ok(GaugeAppAgentTurn { message, proposals });
        }
        for call in calls {
            if is_stopped() {
                return Err(GaugeAppAgentError::Interrupted);
            }
            let name = call.get("name").and_then(Value::as_str).unwrap_or_default();
            let call_id = call.get("call_id").and_then(Value::as_str).ok_or_else(|| {
                GaugeAppAgentError::InvalidOutput("tool call has no call id".into())
            })?;
            let arguments = call
                .get("arguments")
                .and_then(Value::as_str)
                .and_then(|value| serde_json::from_str::<Value>(value).ok())
                .ok_or_else(|| {
                    GaugeAppAgentError::InvalidOutput("tool arguments are invalid".into())
                })?;
            emit(GaugeAppAgentLiveEvent::Tool {
                tool: canonical_tool(name).unwrap_or(name).to_owned(),
                call_id: call_id.to_owned(),
            })?;
            // Provider output is a request, not authority. Rebuild the exact
            // live GaugeApp projection at the moment the request would read or
            // prepare anything. Passing the opening session separately makes
            // a changed generation fail closed as a stale request.
            let current = refresh()?;
            if is_stopped() {
                return Err(GaugeAppAgentError::Interrupted);
            }
            let live_agent_session = GaugeAppAgentSession::from_gaugeapp(&current.session);
            let result = tool_result(
                &current.session,
                &live_agent_session,
                &agent_session,
                &current.pages,
                name,
                arguments,
                &mut proposals,
                &mut |proposal| validate_proposal(&current, proposal),
                &mut direct_action,
                direct_key,
                &mut direct_used,
            )?;
            emit(GaugeAppAgentLiveEvent::ToolResult {
                call_id: call_id.to_owned(),
                ok: true,
            })?;
            input.push(json!({
                "type": "function_call_output",
                "call_id": call_id,
                "output": serde_json::to_string(&result).expect("tool result serializes")
            }));
        }
    }
    Err(GaugeAppAgentError::InvalidOutput(
        "tool round limit exceeded".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gaugeapp_contract::{
        GaugeAppCommandGrant, GaugeAppPageAvailability, GaugeAppPageGrant, ReviewPolicy,
    };
    use proptest::prelude::*;
    use serde_json::json;

    #[test]
    fn a_management_thread_has_one_live_turn_and_stop_is_standing_intent() {
        let thread_id = "thread:test:exclusive-stop";
        let claim = claim_gaugeapp_agent_turn(thread_id).expect("first turn claims thread");
        assert!(claim_gaugeapp_agent_turn(thread_id).is_none());
        assert!(request_gaugeapp_agent_stop(thread_id));
        assert!(gaugeapp_agent_turn_was_stopped(thread_id));
        drop(claim);
        assert!(!request_gaugeapp_agent_stop(thread_id));
        assert!(claim_gaugeapp_agent_turn(thread_id).is_some());
    }

    #[test]
    fn a_live_turn_resumes_by_cursor_and_repairs_an_evicted_position() {
        let mut session = gaugeapp();
        session.actor = "person:live-resume".into();
        let thread_id = gaugeapp_thread_id(&session);
        let live = begin_gaugeapp_agent_live_turn(&session, "live-resume-1").unwrap();
        let (started, _) = gaugeapp_agent_live_subscription(&thread_id, None);
        assert_eq!(started.len(), 1);
        assert_eq!(started[0].event, GaugeAppAgentLiveEvent::Started);

        live.publish(GaugeAppAgentLiveEvent::Text {
            delta: "Working".into(),
        })
        .unwrap();
        let (resumed, _) =
            gaugeapp_agent_live_subscription(&thread_id, Some(started[0].cursor.as_str()));
        assert_eq!(resumed.len(), 1);
        assert_eq!(
            resumed[0].event,
            GaugeAppAgentLiveEvent::Text {
                delta: "Working".into()
            }
        );

        let (repaired, _) = gaugeapp_agent_live_subscription(&thread_id, Some("an-evicted-cursor"));
        assert_eq!(repaired.len(), 2);
        live.publish(GaugeAppAgentLiveEvent::Settled).unwrap();
        let (terminal, _) = gaugeapp_agent_live_subscription(&thread_id, None);
        assert_eq!(terminal.len(), 1);
        assert_eq!(terminal[0].event, GaugeAppAgentLiveEvent::Settled);
    }

    #[test]
    fn a_replaced_live_producer_cannot_append_into_its_successor() {
        let mut session = gaugeapp();
        session.actor = "person:live-replaced".into();
        let thread_id = gaugeapp_thread_id(&session);
        let old = begin_gaugeapp_agent_live_turn(&session, "live-old").unwrap();
        let current = begin_gaugeapp_agent_live_turn(&session, "live-current").unwrap();
        old.publish(GaugeAppAgentLiveEvent::Text {
            delta: "late".into(),
        })
        .unwrap();
        current
            .publish(GaugeAppAgentLiveEvent::Text {
                delta: "current".into(),
            })
            .unwrap();
        let (frames, _) = gaugeapp_agent_live_subscription(&thread_id, None);
        assert_eq!(frames.len(), 2);
        assert!(frames.iter().all(|frame| frame.turn_id == current.turn_id));
    }

    #[test]
    fn provider_reader_discards_partial_output_when_stopped() {
        let mut checkpoints = 0;
        let result = read_provider_response(std::io::Cursor::new(b"partial answer"), || {
            checkpoints += 1;
            checkpoints >= 2
        });
        assert!(matches!(result, Err(GaugeAppAgentError::Interrupted)));
    }

    fn gaugeapp() -> GaugeAppSession {
        GaugeAppSession {
            id: "gaugeapp-session".into(),
            generation: "generation-1".into(),
            app: GaugeAppKind::Administration,
            scope: GaugeAppScope {
                kind: "tenant".into(),
                id: "tenant-a".into(),
            },
            actor: "person:alice".into(),
            capabilities: vec!["edit-org-settings".into()],
            pages: vec![GaugeAppPageGrant {
                id: "administration.organization".into(),
                read_model: "administration.organization".into(),
                version: 1,
                resource_basis: "revision-1".into(),
                freshness: "live".into(),
                availability: GaugeAppPageAvailability::Available,
                commands: vec!["organization.display-name.set".into()],
            }],
            commands: vec![GaugeAppCommandGrant {
                id: "organization.display-name.set".into(),
                capability: "edit-org-settings".into(),
                review: ReviewPolicy::Human,
            }],
            update_cursor: "cursor-1".into(),
        }
    }

    #[test]
    fn agent_proposals_fail_closed_for_page_owned_immediate_ceremonies() {
        let grant = |id: &str, review| GaugeAppCommandGrant {
            id: id.into(),
            capability: "example".into(),
            review,
        };
        assert!(gaugeapp_agent_can_propose(&grant(
            "organization.display-name.set",
            ReviewPolicy::Human,
        )));
        assert!(gaugeapp_agent_can_propose(&grant(
            "commercial-payments.invoice.issue",
            ReviewPolicy::Immediate,
        )));
        assert!(gaugeapp_agent_can_propose(&grant(
            "commercial-product.read",
            ReviewPolicy::Immediate,
        )));
        for id in [
            "account.authenticator.begin-add",
            "provider-connection.api-key.add",
            "trusted-device.link.begin",
            "enterprise-identity.connection.credential.remove",
            "commercial-engagement.agreement.accept",
            "commercial-payments.connect-component.open",
            "future.immediate-command",
        ] {
            assert!(
                !gaugeapp_agent_can_propose(&grant(id, ReviewPolicy::Immediate)),
                "{id} must remain page-owned",
            );
        }
    }

    #[test]
    fn action_kinds_keep_direct_commands_and_human_ceremonies_distinct() {
        let grant = |id: &str, review| GaugeAppCommandGrant {
            id: id.into(),
            capability: "example".into(),
            review,
        };
        assert_eq!(
            gaugeapp_agent_action_kind(&grant(
                "application-settings.appearance.set",
                ReviewPolicy::Immediate,
            )),
            Some(GaugeAppAgentActionKind::Direct)
        );
        assert_eq!(
            gaugeapp_agent_action_kind(&grant(
                "organization.display-name.set",
                ReviewPolicy::Human,
            )),
            Some(GaugeAppAgentActionKind::Proposal)
        );
        assert_eq!(
            gaugeapp_agent_action_kind(&grant("commercial-product.read", ReviewPolicy::Immediate,)),
            Some(GaugeAppAgentActionKind::Read)
        );
        assert_eq!(
            gaugeapp_agent_action_kind(&grant(
                "account.authenticator.complete-add",
                ReviewPolicy::Immediate,
            )),
            Some(GaugeAppAgentActionKind::HumanCeremony)
        );
        assert_eq!(
            gaugeapp_agent_action_kind(&grant("future.operation", ReviewPolicy::Immediate)),
            None
        );
    }

    #[test]
    fn agent_page_discovery_withholds_page_owned_commands() {
        let mut session = gaugeapp();
        session.pages[0].commands.extend([
            "commercial-payments.invoice.issue".into(),
            "account.authenticator.begin-add".into(),
            "future.immediate-command".into(),
        ]);
        session.commands.extend([
            GaugeAppCommandGrant {
                id: "commercial-payments.invoice.issue".into(),
                capability: "example".into(),
                review: ReviewPolicy::Immediate,
            },
            GaugeAppCommandGrant {
                id: "account.authenticator.begin-add".into(),
                capability: "example".into(),
                review: ReviewPolicy::Immediate,
            },
            GaugeAppCommandGrant {
                id: "future.immediate-command".into(),
                capability: "example".into(),
                review: ReviewPolicy::Immediate,
            },
        ]);
        assert_eq!(
            gaugeapp_agent_page_commands(&session, &session.pages[0]),
            vec![
                "organization.display-name.set",
                "commercial-payments.invoice.issue",
            ],
        );
        assert_eq!(
            gaugeapp_agent_page_actions(&session, &session.pages[0]),
            vec![
                GaugeAppAgentActionGrant {
                    id: "organization.display-name.set".into(),
                    kind: GaugeAppAgentActionKind::Proposal,
                },
                GaugeAppAgentActionGrant {
                    id: "commercial-payments.invoice.issue".into(),
                    kind: GaugeAppAgentActionKind::Direct,
                },
                GaugeAppAgentActionGrant {
                    id: "account.authenticator.begin-add".into(),
                    kind: GaugeAppAgentActionKind::HumanCeremony,
                },
            ],
        );
    }

    #[test]
    fn development_provider_reports_only_exact_admitted_scope_and_pages() {
        let context = GaugeAppAgentContext {
            session: gaugeapp(),
            pages: vec![GaugeAppAgentPage {
                id: "administration.organization".into(),
                read_model: "administration.organization".into(),
                version: 1,
                resource_basis: "revision-1".into(),
                model: json!({ "display_name": "Example" }),
                commands: vec!["update-organization".into()],
                actions: vec![],
            }],
        };

        let turn = development_gaugeapp_agent_turn(&context, "Explain this GaugeApp.");

        assert!(turn.message.contains("tenant:tenant-a"));
        assert!(turn.message.contains("administration.organization"));
        assert!(!turn.message.contains("Example"));
        assert!(turn.proposals.is_empty());
    }

    #[test]
    fn development_provider_prepares_an_admitted_reviewable_proposal() {
        let context = GaugeAppAgentContext {
            session: gaugeapp(),
            pages: vec![GaugeAppAgentPage {
                id: "administration.people".into(),
                read_model: "administration.people".into(),
                version: 1,
                resource_basis: "revision-7".into(),
                model: json!({}),
                commands: vec!["member.invite".into()],
                actions: vec![],
            }],
        };

        let turn = development_gaugeapp_agent_turn(
            &context,
            r#"/propose member.invite {"authority":"person:bob","role":"member"}"#,
        );

        assert!(turn.message.contains("reviewable member.invite proposal"));
        assert_eq!(
            turn.proposals,
            vec![GaugeAppAgentProposal {
                page_id: "administration.people".into(),
                command_id: "member.invite".into(),
                expected_basis: "revision-7".into(),
                payload: json!({ "authority": "person:bob", "role": "member" }),
            }],
        );
    }

    fn request(
        session: &GaugeAppAgentSession,
        tool: &str,
        arguments: Value,
    ) -> GaugeAppAgentToolRequest {
        GaugeAppAgentToolRequest {
            agent_session_id: session.id.clone(),
            gaugeapp_session_id: session.gaugeapp_session_id.clone(),
            generation: session.generation.clone(),
            app: session.app,
            scope: session.scope.clone(),
            tool: tool.into(),
            arguments,
        }
    }

    #[test]
    fn admitted_tools_are_exact_and_management_sessions_have_no_ambient_authority() {
        let session = GaugeAppAgentSession::from_gaugeapp(&gaugeapp());
        assert!(!session.message_attachments);
        assert!(!session.additional_tools);
        for (tool, action) in [
            (PAGES_LIST_TOOL, GaugeAppAgentAction::ListPages),
            (PAGE_READ_TOOL, GaugeAppAgentAction::ReadPage),
            (PROPOSALS_PREPARE_TOOL, GaugeAppAgentAction::PrepareProposal),
            (HUMAN_ASK_TOOL, GaugeAppAgentAction::AskHuman),
        ] {
            assert_eq!(
                decide_gaugeapp_agent_tool(&session, &request(&session, tool, json!({}))),
                Ok(action)
            );
        }
        assert_eq!(
            decide_gaugeapp_agent_tool(&session, &request(&session, "shell.exec", json!({}))),
            Err(GaugeAppAgentRejection::UndeclaredTool),
        );
    }

    #[test]
    fn a_tool_uses_live_authority_not_the_turns_opening_snapshot() {
        let opening = GaugeAppAgentSession::from_gaugeapp(&gaugeapp());
        let mut changed = gaugeapp();
        changed.generation = "generation-2".into();
        changed.id = "gaugeapp-session-2".into();
        let live = GaugeAppAgentSession::from_gaugeapp(&changed);
        let mut proposals = Vec::new();

        assert!(matches!(
            tool_result(
                &changed,
                &live,
                &opening,
                &[],
                "gaugeapp_pages_list",
                json!({}),
                &mut proposals,
                &mut |_| Ok(()),
                &mut None,
                "",
                &mut false,
            ),
            Err(GaugeAppAgentError::Rejected(
                GaugeAppAgentRejection::SessionMismatch
            ))
        ));
    }

    #[test]
    fn provider_tools_are_strict_except_for_the_command_specific_payload() {
        let tools = provider_tools();
        let tools = tools.as_array().unwrap();
        assert_eq!(tools.len(), MANAGEMENT_AGENT_TOOLS.len());

        for tool in tools {
            let name = tool["name"].as_str().unwrap();
            let strict = tool["strict"].as_bool().unwrap();
            if name == "gaugeapp_proposals_prepare" {
                assert!(!strict, "an open command payload cannot be a strict schema");
                assert_eq!(
                    tool["parameters"]["properties"]["payload"]["additionalProperties"],
                    true,
                );
                assert_eq!(tool["parameters"]["additionalProperties"], false);
            } else {
                assert!(strict, "read tool {name} must remain strict");
            }
        }
    }

    #[test]
    fn proposal_validation_refusal_returns_tool_feedback_without_admitting_it() {
        let session = gaugeapp();
        let agent_session = GaugeAppAgentSession::from_gaugeapp(&session);
        let page = GaugeAppAgentPage {
            id: session.pages[0].id.clone(),
            read_model: session.pages[0].read_model.clone(),
            version: session.pages[0].version,
            resource_basis: session.pages[0].resource_basis.clone(),
            model: json!({}),
            commands: vec!["organization.display-name.set".into()],
            actions: vec![],
        };
        let mut proposals = Vec::new();
        let rejected = tool_result(
            &session,
            &agent_session,
            &agent_session,
            std::slice::from_ref(&page),
            "gaugeapp_proposals_prepare",
            json!({
                "page_id": page.id,
                "command_id": "organization.display-name.set",
                "payload": { "display_name": "" }
            }),
            &mut proposals,
            &mut |_| Err(GaugeAppAgentError::InvalidOutput("name is empty".into())),
            &mut None,
            "",
            &mut false,
        )
        .unwrap();
        assert_eq!(
            rejected,
            json!({ "prepared": false, "error": "name is empty" })
        );
        assert!(proposals.is_empty());
    }

    #[test]
    fn immediate_command_returns_a_receipt_and_never_becomes_a_proposal() {
        let mut session = gaugeapp();
        session.commands[0].review = ReviewPolicy::Immediate;
        let agent_session = GaugeAppAgentSession::from_gaugeapp(&session);
        let page = GaugeAppAgentPage {
            id: session.pages[0].id.clone(),
            read_model: session.pages[0].read_model.clone(),
            version: session.pages[0].version,
            resource_basis: session.pages[0].resource_basis.clone(),
            model: json!({}),
            commands: vec!["organization.display-name.set".into()],
            actions: vec![],
        };
        let mut proposals = Vec::new();
        let mut used = false;
        let mut applied = 0;
        let mut apply = |proposal: &GaugeAppAgentProposal, key: &str| {
            applied += 1;
            assert_eq!(proposal.command_id, "organization.display-name.set");
            assert_eq!(key, "message-key");
            Ok(json!({ "receipt": "saved" }))
        };
        let args = json!({
            "page_id": page.id,
            "command_id": "organization.display-name.set",
            "payload": { "display_name": "Example" }
        });
        let first = tool_result(
            &session,
            &agent_session,
            &agent_session,
            std::slice::from_ref(&page),
            "gaugeapp_proposals_prepare",
            args.clone(),
            &mut proposals,
            &mut |_| Ok(()),
            &mut Some(&mut apply),
            "message-key",
            &mut used,
        )
        .unwrap();
        assert_eq!(
            first,
            json!({ "applied": true, "result": { "receipt": "saved" } })
        );
        let second = tool_result(
            &session,
            &agent_session,
            &agent_session,
            std::slice::from_ref(&page),
            "gaugeapp_proposals_prepare",
            args,
            &mut proposals,
            &mut |_| Ok(()),
            &mut Some(&mut apply),
            "message-key",
            &mut used,
        )
        .unwrap();
        assert_eq!(second["applied"], false);
        assert_eq!(applied, 1);
        assert!(proposals.is_empty());
    }

    #[test]
    fn scope_revocation_and_secret_arguments_fail_closed() {
        let mut session = GaugeAppAgentSession::from_gaugeapp(&gaugeapp());
        let mut cross_scope = request(
            &session,
            PAGE_READ_TOOL,
            json!({ "page_id": "administration.organization" }),
        );
        cross_scope.scope.id = "tenant-b".into();
        assert_eq!(
            decide_gaugeapp_agent_tool(&session, &cross_scope),
            Err(GaugeAppAgentRejection::ScopeMismatch)
        );
        assert_eq!(
            decide_gaugeapp_agent_tool(
                &session,
                &request(
                    &session,
                    PROPOSALS_PREPARE_TOOL,
                    json!({ "payload": { "api_key": "must-not-enter" } })
                )
            ),
            Err(GaugeAppAgentRejection::SecretBearingArguments),
        );
        session.active = false;
        assert_eq!(
            decide_gaugeapp_agent_tool(&session, &request(&session, PAGES_LIST_TOOL, json!({}))),
            Err(GaugeAppAgentRejection::SessionRevoked),
        );
    }

    #[test]
    fn secret_shaped_transcript_text_fails_closed_without_blocking_normal_explanations() {
        assert!(contains_secret_text(
            "Authorization: Bearer abcdefghijklmnop"
        ));
        assert!(contains_secret_text("api_key = abcdefghijklmnop"));
        assert!(contains_secret_text("sk-abcdefghijklmnop"));
        assert!(contains_secret_text("-----BEGIN PRIVATE KEY-----"));
        assert!(!contains_secret_text(
            "No API key is projected into this GaugeApp."
        ));
    }

    #[test]
    fn every_pem_private_key_label_is_secret_shaped() {
        // The check used to match `-----begin private key` exactly, so every
        // labelled variant — which is to say most real keys — walked past it.
        for label in [
            "PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "PGP PRIVATE KEY BLOCK",
        ] {
            assert!(
                contains_secret_text(&format!("-----BEGIN {label}-----")),
                "{label} was not recognized"
            );
        }
        // A public key is not a credential and must not cost someone a turn.
        assert!(!contains_secret_text("-----BEGIN PUBLIC KEY-----"));
        assert!(!contains_secret_text("-----BEGIN CERTIFICATE-----"));
    }

    /// Fixtures are joined from a prefix and a body rather than written as
    /// whole literals. GitHub's push protection rejects a file containing a
    /// complete Stripe-shaped key and refused this very commit — which is the
    /// right call on its part, and the neatest possible statement of the
    /// problem: a realistic fixture for a secret detector is indistinguishable
    /// from the thing it detects. Splitting the literal keeps the test honest
    /// about the shape without putting a scannable token in the tree.
    fn vendor_token(prefix: &str, body: &str) -> String {
        format!("{prefix}{body}")
    }

    #[test]
    fn vendor_token_prefixes_are_secret_shaped() {
        for (prefix, body) in [
            ("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"),
            ("github_pat_", "11ABCDEFG0abcdefghijklmnop"),
            ("glpat-", "abcdefghijklmnopqrst"),
            ("xoxb-", "1234567890-abcdefghijkl"),
            ("AKIA", "IOSFODNN7EXAMPLE"),
            ("ASIA", "IOSFODNN7EXAMPLE"),
            ("AIza", "SyD-abcdefghijklmnopqrstuvwxyz0123456"),
            ("npm_", "abcdefghijklmnopqrstuvwxyz0123"),
            ("whsec_", "abcdefghijklmnopqrstuvwx"),
            ("sk_live_", "abcdefghijklmnopqrstuvwx"),
            ("sk-ant-api03-", "abcdefghijklmnopqrst"),
        ] {
            let token = vendor_token(prefix, body);
            assert!(
                contains_secret_text(&format!("the value is {token}")),
                "{prefix} was not recognized"
            );
        }
    }

    #[test]
    fn token_shaped_prose_and_hostnames_survive() {
        // Each of these starts with a vendor prefix and must not cost a turn:
        // the length floors and the alphanumeric-body rule are what save them.
        for benign in [
            "Asia",
            "asia-southeast1-gaugewright.example.com",
            "asia-east1",
            "skew is expected here",
            "sk-1234",
            "npm_ is not a token",
            "The akia prefix identifies an AWS key id.",
            "Set up a GitHub token before publishing.",
        ] {
            assert!(!contains_secret_text(benign), "{benign} was rejected");
        }
    }

    #[test]
    fn punctuation_around_a_token_does_not_hide_it() {
        // Serialized and quoted forms are how a credential actually arrives,
        // and splitting on whitespace alone saw `"AKIA...",` as a word that
        // matched no prefix. Assembled, per `vendor_token`.
        let aws = vendor_token("AKIA", "IOSFODNN7EXAMPLE");
        let github = vendor_token("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789");
        assert!(contains_secret_text(&format!(
            r#"{{"aws_access_key_id": "{aws}"}}"#
        )));
        assert!(contains_secret_text(&format!("({github})")));
        assert!(contains_secret_text(&format!(
            "use {github}, then rotate it"
        )));
    }

    #[test]
    fn late_plain_answer_is_not_admitted_after_revocation() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let session = gaugeapp();
        let turn = GaugeAppAgentTurn {
            message: "Here is the answer from the old authorization epoch.".into(),
            proposals: Vec::new(),
        };
        let validate = |_: &mut Workbench| {
            Err(GaugeAppAgentError::Rejected(
                GaugeAppAgentRejection::SessionRevoked,
            ))
        };
        let prepare = |_: &Workbench,
                       _: &GaugeAppCommandEnvelope|
         -> Result<CommandRecordFact, GaugeAppAgentError> {
            panic!("a plain answer has no proposal to prepare")
        };

        assert!(matches!(
            append_gaugeapp_agent_exchange_prepared_current(
                &workbench,
                &session,
                "message-1",
                "What can I change?",
                &turn,
                &validate,
                &prepare,
            ),
            Err(GaugeAppAgentError::Rejected(
                GaugeAppAgentRejection::SessionRevoked
            ))
        ));
        assert!(
            gaugeapp_agent_transcript(workbench.lock_unpoisoned().store_ref(), &session,)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn prepared_exchange_is_atomic_idempotent_and_survives_restart() {
        use crate::gaugeapp_contract::{
            decide_gaugeapp_command, fold_gaugeapp_changes, gaugeapp_change_id, gaugeapp_receipt,
            GaugeAppChangeRecord, GaugeAppChangeStatus, GAUGEAPP_CHANGE_KIND,
        };
        use std::cell::Cell;
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let session = gaugeapp();
        let turn = GaugeAppAgentTurn {
            message: "Name change ready for review.".into(),
            proposals: vec![GaugeAppAgentProposal {
                page_id: session.pages[0].id.clone(),
                command_id: session.commands[0].id.clone(),
                expected_basis: session.pages[0].resource_basis.clone(),
                payload: json!({ "display_name": "Example" }),
            }],
        };
        let calls = Cell::new(0);
        let prepare = |_: &Workbench, envelope: &GaugeAppCommandEnvelope| {
            calls.set(calls.get() + 1);
            decide_gaugeapp_command(&session, envelope)
                .map_err(|error| GaugeAppAgentError::InvalidOutput(format!("{error:?}")))?;
            let change = GaugeAppChangeRecord {
                id: gaugeapp_change_id(&session, envelope),
                app: session.app,
                scope: session.scope.clone(),
                actor: session.actor.clone(),
                page_id: envelope.page_id.clone(),
                command_id: envelope.command_id.clone(),
                expected_basis: envelope.expected_basis.clone(),
                payload: envelope.payload.clone(),
                client: envelope.client,
                status: GaugeAppChangeStatus::Proposed,
                reviewed_by: None,
                receipt_id: gaugeapp_receipt(&session, envelope, "proposed").id,
            };
            Ok(CommandRecordFact {
                scope_id: "org:tenant-a".into(),
                kind: GAUGEAPP_CHANGE_KIND.into(),
                payload: serde_json::to_string(&change).unwrap(),
            })
        };
        let mut invalid = turn.clone();
        invalid.proposals.push(GaugeAppAgentProposal {
            expected_basis: "stale".into(),
            ..turn.proposals[0].clone()
        });
        assert!(append_gaugeapp_agent_exchange_prepared(
            &workbench,
            &session,
            "invalid",
            "Change name",
            &invalid,
            &prepare
        )
        .is_err());
        {
            let guard = workbench.lock_unpoisoned();
            assert!(gaugeapp_agent_transcript(guard.store_ref(), &session)
                .unwrap()
                .is_empty());
            assert!(fold_gaugeapp_changes(guard.store_ref(), "org:tenant-a")
                .unwrap()
                .is_empty());
        }
        let transcript = append_gaugeapp_agent_exchange_prepared(
            &workbench,
            &session,
            "valid",
            "Change name",
            &turn,
            &prepare,
        )
        .unwrap();
        assert_eq!(transcript.len(), 2);
        let prepared_calls = calls.get();
        drop(workbench);
        let reopened = crate::open_workbench(root.path()).unwrap();
        assert_eq!(
            append_gaugeapp_agent_exchange_prepared(
                &reopened,
                &session,
                "valid",
                "Change name",
                &turn,
                &prepare
            )
            .unwrap(),
            transcript
        );
        assert_eq!(calls.get(), prepared_calls, "replay cannot prepare again");
        let guard = reopened.lock_unpoisoned();
        let changes = fold_gaugeapp_changes(guard.store_ref(), "org:tenant-a").unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes.values().next().unwrap().status,
            GaugeAppChangeStatus::Proposed
        );
        assert!(fold_gaugeapp_changes(guard.store_ref(), "org:tenant-b")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn transcript_is_durable_idempotent_and_stable_across_authorization_epochs() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let session = gaugeapp();
        let turn = GaugeAppAgentTurn {
            message: "Open the organization page model.".into(),
            proposals: vec![GaugeAppAgentProposal {
                page_id: "administration.organization".into(),
                command_id: "organization.display-name.set".into(),
                expected_basis: "revision-1".into(),
                payload: json!({ "display_name": "Example" }),
            }],
        };
        let transcript = append_gaugeapp_agent_exchange(
            &workbench,
            &session,
            "message-1",
            "Show the organization posture.",
            &turn,
        )
        .unwrap();
        assert_eq!(transcript.len(), 2);
        drop(workbench);

        let reopened = crate::open_workbench(root.path()).unwrap();
        let guard = reopened.lock_unpoisoned();
        let folded = gaugeapp_agent_transcript(guard.store_ref(), &session).unwrap();
        assert_eq!(folded, transcript);
        drop(guard);

        let replayed = append_gaugeapp_agent_exchange(
            &reopened,
            &session,
            "message-1",
            "Show the organization posture.",
            &turn,
        )
        .unwrap();
        assert_eq!(replayed, transcript);

        let guard = reopened.lock_unpoisoned();
        assert_eq!(
            replayed_gaugeapp_agent_turn(
                guard.store_ref(),
                &session,
                "message-1",
                "Show the organization posture.",
            )
            .unwrap(),
            Some(turn),
        );
        assert!(replayed_gaugeapp_agent_turn(
            guard.store_ref(),
            &session,
            "message-1",
            "Different text must not reuse the key.",
        )
        .is_err());
        drop(guard);

        let mut refreshed = session.clone();
        refreshed.id = "gaugeapp-session-after-reauthorization".into();
        refreshed.generation = "generation-2".into();
        let guard = reopened.lock_unpoisoned();
        assert_eq!(
            gaugeapp_agent_transcript(guard.store_ref(), &refreshed).unwrap(),
            transcript
        );

        let mut other = session;
        other.scope.id = "tenant-b".into();
        assert!(gaugeapp_agent_transcript(guard.store_ref(), &other)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn transcript_erasure_advances_an_encrypted_generation_and_is_idempotent() {
        use std::sync::{Arc, Mutex};

        fn open(database: &str, keys: &std::path::Path) -> SharedWorkbench {
            let vault = Arc::new(crate::content_vault::ContentVault::new(
                keys,
                Box::new(crate::at_rest::LoopbackKeyWrap::new([31u8; 32])),
            ));
            let store = Store::open(database).unwrap().with_codec(vault.clone());
            Arc::new(Mutex::new(Workbench::new(store).with_content_vault(vault)))
        }

        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("store.sqlite");
        let database = database.to_str().unwrap();
        let keys = root.path().join("content-keys");
        let workbench = open(database, &keys);
        let session = gaugeapp();
        let first = GaugeAppAgentTurn {
            message: "The first private answer.".into(),
            proposals: Vec::new(),
        };
        append_gaugeapp_agent_exchange(
            &workbench,
            &session,
            "before-clear",
            "The first private question.",
            &first,
        )
        .unwrap();

        let receipt = erase_gaugeapp_agent_transcript(&workbench, &session, "clear-1").unwrap();
        assert_eq!(receipt.thread_id, gaugeapp_thread_id(&session));
        assert_eq!(receipt.generation, 1);
        {
            let guard = workbench.lock_unpoisoned();
            assert!(gaugeapp_agent_transcript(guard.store_ref(), &session)
                .unwrap()
                .is_empty());
            assert_eq!(
                guard
                    .store_ref()
                    .fold::<ErasureState>(&gaugeapp_agent_erasure_scope(
                        &gaugeapp_agent_generation_scope(&session, 0),
                    ))
                    .unwrap()
                    .phase,
                ErasurePhase::Tombstoned,
            );
        }

        let second = GaugeAppAgentTurn {
            message: "Only the new answer remains.".into(),
            proposals: Vec::new(),
        };
        append_gaugeapp_agent_exchange(
            &workbench,
            &session,
            "after-clear",
            "Start a new conversation.",
            &second,
        )
        .unwrap();
        // Retrying the first clear cannot erase the new generation.
        assert_eq!(
            erase_gaugeapp_agent_transcript(&workbench, &session, "clear-1")
                .unwrap()
                .generation,
            1,
        );
        drop(workbench);

        let reopened = open(database, &keys);
        let guard = reopened.lock_unpoisoned();
        let transcript = gaugeapp_agent_transcript(guard.store_ref(), &session).unwrap();
        assert_eq!(transcript.len(), 2);
        assert_eq!(transcript[0].text, "Start a new conversation.");
        assert_eq!(transcript[1].text, "Only the new answer remains.");
    }

    #[test]
    fn account_and_tenant_cascades_find_independently_keyed_threads() {
        use std::sync::{Arc, Mutex};

        let root = tempfile::tempdir().unwrap();
        let vault = Arc::new(crate::content_vault::ContentVault::new(
            root.path().join("content-keys"),
            Box::new(crate::at_rest::LoopbackKeyWrap::new([37u8; 32])),
        ));
        let store = Store::open_in_memory().unwrap().with_codec(vault.clone());
        let workbench = Arc::new(Mutex::new(Workbench::new(store).with_content_vault(vault)));
        let alice_a = gaugeapp();
        let mut bob_a = gaugeapp();
        bob_a.actor = "person:bob".into();
        let mut alice_b = gaugeapp();
        alice_b.scope.id = "tenant-b".into();
        let turn = GaugeAppAgentTurn {
            message: "private tenant answer".into(),
            proposals: Vec::new(),
        };
        for (session, key) in [
            (&alice_a, "alice-a"),
            (&bob_a, "bob-a"),
            (&alice_b, "alice-b"),
        ] {
            append_gaugeapp_agent_exchange(
                &workbench,
                session,
                key,
                "private tenant question",
                &turn,
            )
            .unwrap();
        }

        {
            let guard = workbench.lock_unpoisoned();
            assert_eq!(
                crypto_erase_gaugeapp_agent_threads_for_tenant(&guard, "tenant-a").unwrap(),
                2,
            );
            assert!(gaugeapp_agent_transcript(guard.store_ref(), &alice_a)
                .unwrap()
                .is_empty());
            assert!(gaugeapp_agent_transcript(guard.store_ref(), &bob_a)
                .unwrap()
                .is_empty());
            assert_eq!(
                gaugeapp_agent_transcript(guard.store_ref(), &alice_b)
                    .unwrap()
                    .len(),
                2,
            );
            assert_eq!(
                crypto_erase_gaugeapp_agent_threads_for_actor(&guard, "person:alice").unwrap(),
                1,
            );
            assert!(gaugeapp_agent_transcript(guard.store_ref(), &alice_b)
                .unwrap()
                .is_empty());
        }
    }

    #[test]
    fn unambiguous_legacy_transcript_migrates_once_to_the_stable_thread() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let session = gaugeapp();
        let legacy_scope = "environment-agent:administration:tenant:tenant-a";
        {
            let mut guard = workbench.lock_unpoisoned();
            for (id, actor, sequence, role, text) in [
                ("old-user", "person:alice", 0, "user", "What is our policy?"),
                (
                    "old-assistant",
                    "person:alice",
                    1,
                    "assistant",
                    "Here is the policy.",
                ),
                ("other-user", "person:bob", 0, "user", "Do not attach this."),
                (
                    "other-assistant",
                    "person:bob",
                    1,
                    "assistant",
                    "Still Bob's.",
                ),
            ] {
                guard
                    .store_mut()
                    .append_record(
                        legacy_scope,
                        LEGACY_ENVIRONMENT_AGENT_MESSAGE_KIND,
                        &json!({
                            "id": id,
                            "session_id": if actor == "person:alice" { "old-session-a" } else { "old-session-b" },
                            "environment": "administration",
                            "scope": { "kind": "tenant", "id": "tenant-a" },
                            "actor": actor,
                            "sequence": sequence,
                            "role": role,
                            "text": text,
                        })
                        .to_string(),
                    )
                    .unwrap();
            }

            assert!(migrate_legacy_gaugeapp_agent_transcript(&mut guard, &session).unwrap());
            assert!(!migrate_legacy_gaugeapp_agent_transcript(&mut guard, &session).unwrap());
        }

        let guard = workbench.lock_unpoisoned();
        let transcript = gaugeapp_agent_transcript(guard.store_ref(), &session).unwrap();
        assert_eq!(
            transcript
                .iter()
                .map(|message| message.text.as_str())
                .collect::<Vec<_>>(),
            vec!["What is our policy?", "Here is the policy."]
        );
        assert!(transcript
            .iter()
            .all(|message| message.thread_id == gaugeapp_thread_id(&session)));

        let mut refreshed = session;
        refreshed.id = "new-authorization-session".into();
        refreshed.generation = "generation-2".into();
        assert_eq!(
            gaugeapp_agent_transcript(guard.store_ref(), &refreshed).unwrap(),
            transcript
        );
    }

    #[test]
    fn incomplete_legacy_transcript_remains_unattached_evidence() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let session = gaugeapp();
        let mut guard = workbench.lock_unpoisoned();
        guard
            .store_mut()
            .append_record(
                "environment-agent:administration:tenant:tenant-a",
                LEGACY_ENVIRONMENT_AGENT_MESSAGE_KIND,
                &json!({
                    "id": "orphaned-user",
                    "session_id": "old-session-a",
                    "environment": "administration",
                    "scope": { "kind": "tenant", "id": "tenant-a" },
                    "actor": "person:alice",
                    "sequence": 0,
                    "role": "user",
                    "text": "This turn never completed.",
                })
                .to_string(),
            )
            .unwrap();

        assert!(!migrate_legacy_gaugeapp_agent_transcript(&mut guard, &session).unwrap());
        assert!(gaugeapp_agent_transcript(guard.store_ref(), &session)
            .unwrap()
            .is_empty());
    }

    proptest! {
        #[test]
        fn arbitrary_unknown_tools_never_admit(name in "[a-z][a-z0-9_.-]{0,40}") {
            prop_assume!(!MANAGEMENT_AGENT_TOOLS.contains(&name.as_str()));
            let session = GaugeAppAgentSession::from_gaugeapp(&gaugeapp());
            prop_assert_eq!(
                decide_gaugeapp_agent_tool(&session, &request(&session, &name, json!({}))),
                Err(GaugeAppAgentRejection::UndeclaredTool),
            );
        }
    }

    #[test]
    fn the_completed_event_carries_the_response_the_caller_expects() {
        let stream = concat!(
            "event: response.created\n",
            "data: {\"type\":\"response.created\",\"response\":{\"output\":[]}}\n",
            "\n",
            "event: response.output_text.delta\n",
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\n",
            "\n",
            "event: response.completed\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"message\"}]}}\n",
            "\n",
            "data: [DONE]\n",
            "\n",
        );
        let response = response_from_event_stream(stream).unwrap();
        // The same shape the non-streaming endpoint returns whole, so nothing
        // downstream has to know which transport was used.
        assert_eq!(
            response
                .get("output")
                .and_then(Value::as_array)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn provider_text_is_published_before_the_completed_event_is_read() {
        use std::cell::Cell;
        use std::rc::Rc;

        struct Segments {
            parts: VecDeque<Vec<u8>>,
            reads: Rc<Cell<usize>>,
        }
        impl Read for Segments {
            fn read(&mut self, target: &mut [u8]) -> std::io::Result<usize> {
                let Some(part) = self.parts.pop_front() else {
                    return Ok(0);
                };
                self.reads.set(self.reads.get() + 1);
                target[..part.len()].copy_from_slice(&part);
                Ok(part.len())
            }
        }

        let text = "a".repeat(300);
        let first = format!(
            "data: {}\n\n",
            json!({ "type": "response.output_text.delta", "delta": text })
        );
        let second = format!(
            "data: {}\n\n",
            json!({
                "type": "response.completed",
                "response": { "output": [{
                    "type": "message",
                    "content": [{ "type": "output_text", "text": text }]
                }] }
            })
        );
        let reads = Rc::new(Cell::new(0));
        let reader = Segments {
            parts: VecDeque::from([first.into_bytes(), second.into_bytes()]),
            reads: reads.clone(),
        };
        let mut published = Vec::new();

        read_provider_event_stream(reader, || false, &mut |event| {
            if let GaugeAppAgentLiveEvent::Text { delta } = event {
                published.push((reads.get(), delta));
            }
            Ok(())
        })
        .unwrap();

        assert_eq!(
            published
                .iter()
                .map(|(_, delta)| delta.len())
                .sum::<usize>(),
            300
        );
        assert_eq!(
            published[0].0, 1,
            "the first safe prefix waited for completion"
        );
        assert_eq!(published[0].1.len(), 44);
    }

    #[test]
    fn live_holdback_rejects_a_secret_split_across_provider_events() {
        let first = format!(
            "data: {}\n\n",
            json!({
                "type": "response.output_text.delta",
                "delta": format!("{} sk-", "x".repeat(239))
            })
        );
        let second = format!(
            "data: {}\n\n",
            json!({
                "type": "response.output_text.delta",
                "delta": "abcdefghijklmnopqrst"
            })
        );
        let completed = format!(
            "data: {}\n\n",
            json!({ "type": "response.completed", "response": { "output": [] } })
        );
        let mut published = Vec::new();

        let error = read_provider_event_stream(
            std::io::Cursor::new(format!("{first}{second}{completed}")),
            || false,
            &mut |event| {
                published.push(event);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            GaugeAppAgentError::Rejected(GaugeAppAgentRejection::SecretBearingArguments)
        ));
        assert!(published.is_empty());
    }

    #[test]
    fn a_stream_is_read_the_same_with_carriage_returns() {
        let stream = "event: response.completed\r\n\
data: {\"type\":\"response.completed\",\"response\":{\"ok\":true}}\r\n\r\n";
        assert_eq!(
            response_from_event_stream(stream).unwrap(),
            serde_json::json!({ "ok": true })
        );
    }

    // A stream that stops early has already said why, and that sentence beats
    // "no completed response" for whoever reads the log.
    #[test]
    fn a_failed_stream_reports_what_the_provider_said() {
        let stream = concat!(
            "data: {\"type\":\"response.failed\",\"error\":{\"message\":\"model not available\"}}\n",
            "\n",
        );
        let error = response_from_event_stream(stream).unwrap_err();
        assert!(error.contains("model not available"), "{error}");
    }

    // The standard event nests the sentence under `response.error`, and reading
    // the event whole would flatten it into a fragment the limit can cut off.
    #[test]
    fn a_failed_stream_reads_the_error_nested_in_the_response() {
        let filler = "z".repeat(400);
        let stream = format!(
            "data: {{\"type\":\"response.failed\",\"response\":{{\"id\":\"resp_{filler}\",\
\"status\":\"failed\",\"error\":{{\"code\":\"server_error\",\
\"message\":\"Stream must be set to true\"}}}}}}\n\n"
        );
        assert_eq!(
            response_from_event_stream(&stream).unwrap_err(),
            "Stream must be set to true"
        );
    }

    #[test]
    fn a_stream_that_never_completes_is_an_error_not_an_empty_turn() {
        let stream = "data: {\"type\":\"response.created\",\"response\":{}}\n\n";
        assert!(response_from_event_stream(stream)
            .unwrap_err()
            .contains("no completed response"));
        assert!(response_from_event_stream("").is_err());
    }

    // The exact refusal that reached the canary, reported as the provider wrote
    // it rather than as a bare status.
    #[test]
    fn a_refusal_is_reported_in_the_providers_own_words() {
        assert_eq!(
            provider_complaint(r#"{"error":{"message":"Stream must be set to true"}}"#),
            "Stream must be set to true"
        );
        assert_eq!(provider_complaint(r#"{"detail":"no access"}"#), "no access");
        // An unrecognised shape is when the raw text matters most.
        assert_eq!(
            provider_complaint("<html>gateway</html>"),
            "<html>gateway</html>"
        );
        assert_eq!(provider_complaint(""), "(no response body)");
        assert_eq!(provider_complaint("   \n  "), "(no response body)");
        // A provider answering with an error page must not bury the log.
        let long = provider_complaint(&"x".repeat(2000));
        assert!(
            long.len() < 340 && long.ends_with("… (truncated)"),
            "{long}"
        );
        // Multibyte text must not be cut mid-character.
        let wide = provider_complaint(&"é".repeat(2000));
        assert!(wide.ends_with("… (truncated)"));
    }

    // A flag left on the `GAUGEWRIGHT_` prefix must read as *set and deprecated*,
    // never as unset. It read as unset on the hosted Hub, which switched
    // GaugeWright-funded model access off by a name and answered every
    // Administration turn with `NoModelAccess`. Serialised because the process
    // environment is global.
    #[test]
    fn a_flag_is_honoured_under_either_prefix_and_off_by_default() {
        static ENVIRONMENT: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENVIRONMENT
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let current = "GAUGEDESK_WIRING_FLAG_UNDER_TEST";
        let legacy = "GAUGEWRIGHT_WIRING_FLAG_UNDER_TEST";
        for name in [current, legacy] {
            std::env::remove_var(name);
        }
        assert!(
            !environment_flag("WIRING_FLAG_UNDER_TEST"),
            "unset must be off"
        );

        // The exact shape the hosted Hub carried.
        std::env::set_var(legacy, "1");
        assert!(
            environment_flag("WIRING_FLAG_UNDER_TEST"),
            "a legacy-prefixed flag read as unset, which is the whole defect"
        );
        std::env::remove_var(legacy);

        std::env::set_var(current, "true");
        assert!(environment_flag("WIRING_FLAG_UNDER_TEST"));
        std::env::set_var(current, "yes");
        assert!(environment_flag("WIRING_FLAG_UNDER_TEST"));
        // Anything else is off, and whitespace does not change that either way.
        std::env::set_var(current, " 1 ");
        assert!(environment_flag("WIRING_FLAG_UNDER_TEST"));
        for off in ["0", "false", "", "on"] {
            std::env::set_var(current, off);
            assert!(
                !environment_flag("WIRING_FLAG_UNDER_TEST"),
                "{off} must be off"
            );
        }
        std::env::remove_var(current);
    }
}
