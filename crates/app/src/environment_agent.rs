//! Pure admission reducer for governed management Environment agents.
//!
//! This is the implementation pair for `specs/models/environment-agent.qnt`.
//! Provider output is untrusted input: a model may request only one exact tool
//! declared by the freshly rebuilt Environment session. Mutating requests can
//! produce a proposal envelope, never a reviewed or applied domain effect.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Read;
use std::time::Duration;

use crate::account::{account_scope, credentials_in_scope, ModelExecutionClass};
use crate::environment_contract::{EnvironmentKind, EnvironmentScope, EnvironmentSession};
use crate::{LockUnpoisoned, SharedWorkbench};
use gaugewright_store::{AdmitError, CommandRecordFact, Store};

pub const FILES_LIST_TOOL: &str = "environment.files.list";
pub const FILES_READ_TOOL: &str = "environment.files.read";
pub const PROJECTIONS_QUERY_TOOL: &str = "environment.projections.query";
pub const CHANGES_PROPOSE_TOOL: &str = "environment.changes.propose";

pub const MANAGEMENT_AGENT_TOOLS: [&str; 4] = [
    FILES_LIST_TOOL,
    FILES_READ_TOOL,
    PROJECTIONS_QUERY_TOOL,
    CHANGES_PROPOSE_TOOL,
];

const MAX_PROVIDER_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TOOL_ROUNDS: usize = 8;
pub const ENVIRONMENT_AGENT_MESSAGE_KIND: &str = "environment_agent_message";

fn environment_flag(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "yes"))
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EnvironmentAgentDocument {
    pub id: String,
    pub path: String,
    pub revision: String,
    pub content: Value,
    pub commands: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EnvironmentAgentProposal {
    pub document_id: String,
    pub command_id: String,
    pub base_revision: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EnvironmentAgentTurn {
    pub message: String,
    #[serde(default)]
    pub proposals: Vec<EnvironmentAgentProposal>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvironmentAgentMessageRole {
    User,
    Assistant,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnvironmentAgentMessage {
    pub id: String,
    pub session_id: String,
    pub environment: EnvironmentKind,
    pub scope: EnvironmentScope,
    pub actor: String,
    pub sequence: u64,
    pub role: EnvironmentAgentMessageRole,
    pub text: String,
}

#[derive(Clone, Debug)]
pub struct EnvironmentAgentContext {
    pub session: EnvironmentSession,
    pub documents: Vec<EnvironmentAgentDocument>,
}

#[derive(Debug)]
pub enum EnvironmentAgentError {
    NoModelAccess,
    Credential(String),
    Provider(String),
    InvalidOutput(String),
    Rejected(EnvironmentAgentRejection),
    Store(String),
}

impl std::fmt::Display for EnvironmentAgentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoModelAccess => write!(
                formatter,
                "link OpenAI or Codex model access in Hub before using this agent"
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

pub fn environment_agent_store_scope(session: &EnvironmentSession) -> String {
    format!(
        "environment-agent:{}:{}:{}",
        session.environment.as_str(),
        session.scope.kind,
        session.scope.id,
    )
}

pub fn environment_agent_transcript(
    store: &Store,
    session: &EnvironmentSession,
) -> Result<Vec<EnvironmentAgentMessage>, AdmitError> {
    let mut messages = store
        .records(
            &environment_agent_store_scope(session),
            ENVIRONMENT_AGENT_MESSAGE_KIND,
        )?
        .into_iter()
        .filter_map(|payload| serde_json::from_str::<EnvironmentAgentMessage>(&payload).ok())
        .filter(|message| {
            message.session_id == session.id
                && message.environment == session.environment
                && message.scope == session.scope
                && message.actor == session.actor
        })
        .collect::<Vec<_>>();
    messages.sort_by_key(|message| message.sequence);
    Ok(messages)
}

pub fn append_environment_agent_exchange(
    workbench: &SharedWorkbench,
    session: &EnvironmentSession,
    user: &str,
    assistant: &str,
) -> Result<Vec<EnvironmentAgentMessage>, EnvironmentAgentError> {
    if contains_secret_text(user) || contains_secret_text(assistant) {
        return Err(EnvironmentAgentError::Rejected(
            EnvironmentAgentRejection::SecretBearingArguments,
        ));
    }
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|error| EnvironmentAgentError::Store(format!("{error:?}")))?;
    let turn_id = hex::encode(random);
    let mut guard = workbench.lock_unpoisoned();
    let existing = environment_agent_transcript(guard.store_ref(), session)
        .map_err(|error| EnvironmentAgentError::Store(format!("{error:?}")))?;
    let sequence = existing.last().map_or(0, |message| message.sequence + 1);
    let records = [
        EnvironmentAgentMessage {
            id: format!("environment-agent-message:{turn_id}:user"),
            session_id: session.id.clone(),
            environment: session.environment,
            scope: session.scope.clone(),
            actor: session.actor.clone(),
            sequence,
            role: EnvironmentAgentMessageRole::User,
            text: user.to_owned(),
        },
        EnvironmentAgentMessage {
            id: format!("environment-agent-message:{turn_id}:assistant"),
            session_id: session.id.clone(),
            environment: session.environment,
            scope: session.scope.clone(),
            actor: session.actor.clone(),
            sequence: sequence + 1,
            role: EnvironmentAgentMessageRole::Assistant,
            text: assistant.to_owned(),
        },
    ];
    let scope = environment_agent_store_scope(session);
    let facts = records
        .iter()
        .map(|record| CommandRecordFact {
            scope_id: scope.clone(),
            kind: ENVIRONMENT_AGENT_MESSAGE_KIND.into(),
            payload: serde_json::to_string(record).expect("agent message serializes"),
        })
        .collect::<Vec<_>>();
    guard
        .store_mut()
        .admit_record_facts(
            &format!("{scope}:append"),
            &turn_id,
            &serde_json::to_string(&records).expect("agent exchange serializes"),
            &facts,
        )
        .map_err(|error| EnvironmentAgentError::Store(format!("{error:?}")))?;
    let mut transcript = existing;
    transcript.extend(records);
    Ok(transcript)
}

impl std::error::Error for EnvironmentAgentError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnvironmentAgentSession {
    pub id: String,
    pub environment_session_id: String,
    pub environment: EnvironmentKind,
    pub scope: EnvironmentScope,
    pub actor: String,
    pub active: bool,
    pub message_attachments: bool,
    pub additional_tools: bool,
    pub tools: Vec<String>,
}

impl EnvironmentAgentSession {
    pub fn from_environment(session: &EnvironmentSession) -> Self {
        Self {
            id: format!("{}:agent", session.id),
            environment_session_id: session.id.clone(),
            environment: session.environment,
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
pub struct EnvironmentAgentToolRequest {
    pub agent_session_id: String,
    pub environment_session_id: String,
    pub environment: EnvironmentKind,
    pub scope: EnvironmentScope,
    pub tool: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvironmentAgentAction {
    ListFiles,
    ReadFile,
    QueryProjections,
    ProposeChange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvironmentAgentRejection {
    SessionMismatch,
    SessionRevoked,
    ScopeMismatch,
    UndeclaredTool,
    SecretBearingArguments,
}

impl EnvironmentAgentRejection {
    pub fn message(self) -> &'static str {
        match self {
            Self::SessionMismatch => "agent session is stale or does not match",
            Self::SessionRevoked => "agent session is no longer active",
            Self::ScopeMismatch => "agent tool scope does not match its admitted session",
            Self::UndeclaredTool => "agent tool is not declared for this session",
            Self::SecretBearingArguments => "secret-bearing agent tool arguments are forbidden",
        }
    }
}

/// Decide one untrusted model tool request against the live server session.
pub fn decide_environment_agent_tool(
    session: &EnvironmentAgentSession,
    request: &EnvironmentAgentToolRequest,
) -> Result<EnvironmentAgentAction, EnvironmentAgentRejection> {
    if request.agent_session_id != session.id
        || request.environment_session_id != session.environment_session_id
        || request.environment != session.environment
    {
        return Err(EnvironmentAgentRejection::SessionMismatch);
    }
    if !session.active {
        return Err(EnvironmentAgentRejection::SessionRevoked);
    }
    if request.scope != session.scope {
        return Err(EnvironmentAgentRejection::ScopeMismatch);
    }
    if !session.tools.iter().any(|tool| tool == &request.tool) {
        return Err(EnvironmentAgentRejection::UndeclaredTool);
    }
    if contains_secret(&request.arguments) {
        return Err(EnvironmentAgentRejection::SecretBearingArguments);
    }
    match request.tool.as_str() {
        FILES_LIST_TOOL => Ok(EnvironmentAgentAction::ListFiles),
        FILES_READ_TOOL => Ok(EnvironmentAgentAction::ReadFile),
        PROJECTIONS_QUERY_TOOL => Ok(EnvironmentAgentAction::QueryProjections),
        CHANGES_PROPOSE_TOOL => Ok(EnvironmentAgentAction::ProposeChange),
        _ => Err(EnvironmentAgentRejection::UndeclaredTool),
    }
}

/// Fail closed on credential-shaped keys at any nesting depth. Environment
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

pub fn contains_secret_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("-----begin private key")
        || lower
            .split_whitespace()
            .any(|word| word.starts_with("sk-") && word.len() >= 15)
        || lower.split("bearer ").skip(1).any(|tail| {
            tail.split_whitespace()
                .next()
                .is_some_and(|token| token.len() >= 12)
        })
        || ["api_key", "access_token", "refresh_token", "private_key"]
            .iter()
            .any(|key| {
                lower.find(key).is_some_and(|index| {
                    lower[index + key.len()..]
                        .trim_start()
                        .starts_with([':', '='])
                })
            })
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
) -> Result<AgentCredential, EnvironmentAgentError> {
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
        .map_err(EnvironmentAgentError::Credential)?
        .ok_or(EnvironmentAgentError::NoModelAccess)?;
        return Ok(AgentCredential::Codex {
            access: credential.access,
            account_id: credential.account_id,
        });
    }
    let Some(record) = records
        .get("openai")
        .filter(|record| record.admits(ModelExecutionClass::PrivateHome))
    else {
        if environment_flag("GAUGEWRIGHT_MANAGEMENT_AGENT_MANAGED") {
            let token = std::env::var("GAUGEWRIGHT_MANAGEMENT_AGENT_OPENAI_KEY")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    EnvironmentAgentError::Credential(
                        "managed Environment agent funding is enabled without its dedicated provider credential".into(),
                    )
                })?;
            return Ok(AgentCredential::OpenAi(token));
        }
        return Err(EnvironmentAgentError::NoModelAccess);
    };
    let token = workbench
        .lock_unpoisoned()
        .unseal_account_secret(&record.sealed_token)
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| {
            EnvironmentAgentError::Credential(
                "linked OpenAI credential could not be unsealed".into(),
            )
        })?;
    Ok(AgentCredential::OpenAi(token))
}

fn provider_tools() -> Value {
    json!([
        { "type": "function", "name": "environment_files_list", "description": "List the files admitted in this exact Environment session.", "parameters": { "type": "object", "properties": {}, "additionalProperties": false }, "strict": true },
        { "type": "function", "name": "environment_files_read", "description": "Read one admitted Environment file by path.", "parameters": { "type": "object", "properties": { "path": { "type": "string" } }, "required": ["path"], "additionalProperties": false }, "strict": true },
        { "type": "function", "name": "environment_projections_query", "description": "Read one admitted projection by document id.", "parameters": { "type": "object", "properties": { "document_id": { "type": "string" } }, "required": ["document_id"], "additionalProperties": false }, "strict": true },
        { "type": "function", "name": "environment_changes_propose", "description": "Prepare, but never apply or review, one declared Environment command proposal.", "parameters": { "type": "object", "properties": { "document_id": { "type": "string" }, "command_id": { "type": "string" }, "payload": { "type": "object", "additionalProperties": true } }, "required": ["document_id", "command_id", "payload"], "additionalProperties": false }, "strict": true }
    ])
}

fn canonical_tool(name: &str) -> Option<&'static str> {
    match name {
        "environment_files_list" => Some(FILES_LIST_TOOL),
        "environment_files_read" => Some(FILES_READ_TOOL),
        "environment_projections_query" => Some(PROJECTIONS_QUERY_TOOL),
        "environment_changes_propose" => Some(CHANGES_PROPOSE_TOOL),
        _ => None,
    }
}

fn provider_request(
    credential: &AgentCredential,
    body: &Value,
) -> Result<Value, EnvironmentAgentError> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(130))
        .redirects(0)
        .build();
    let serialized = serde_json::to_string(body)
        .map_err(|error| EnvironmentAgentError::InvalidOutput(error.to_string()))?;
    let request = credential.authorize(
        agent
            .post(credential.endpoint())
            .set("content-type", "application/json"),
    );
    let response = match request.send_string(&serialized) {
        Ok(response) => response,
        Err(ureq::Error::Status(status, _response)) => {
            tracing::warn!(
                status,
                "management Environment agent provider rejected request"
            );
            return Err(EnvironmentAgentError::Provider(format!(
                "provider returned HTTP {status}"
            )));
        }
        Err(ureq::Error::Transport(error)) => {
            return Err(EnvironmentAgentError::Provider(error.to_string()));
        }
    };
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_PROVIDER_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| EnvironmentAgentError::Provider(error.to_string()))?;
    if bytes.len() as u64 > MAX_PROVIDER_RESPONSE_BYTES {
        return Err(EnvironmentAgentError::Provider(
            "response exceeded size cap".into(),
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| EnvironmentAgentError::Provider("response was not valid JSON".into()))
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

fn tool_result(
    agent_session: &EnvironmentAgentSession,
    documents: &[EnvironmentAgentDocument],
    name: &str,
    arguments: Value,
    proposals: &mut Vec<EnvironmentAgentProposal>,
) -> Result<Value, EnvironmentAgentError> {
    let tool = canonical_tool(name).unwrap_or(name);
    let request = EnvironmentAgentToolRequest {
        agent_session_id: agent_session.id.clone(),
        environment_session_id: agent_session.environment_session_id.clone(),
        environment: agent_session.environment,
        scope: agent_session.scope.clone(),
        tool: tool.to_owned(),
        arguments: arguments.clone(),
    };
    let action = decide_environment_agent_tool(agent_session, &request)
        .map_err(EnvironmentAgentError::Rejected)?;
    match action {
        EnvironmentAgentAction::ListFiles => Ok(json!({
            "files": documents.iter().map(|document| json!({
                "id": document.id,
                "path": document.path,
                "revision": document.revision,
                "commands": document.commands,
            })).collect::<Vec<_>>()
        })),
        EnvironmentAgentAction::ReadFile => {
            let path = arguments
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let document = documents
                .iter()
                .find(|document| document.path == path)
                .ok_or_else(|| {
                    EnvironmentAgentError::InvalidOutput("file is not admitted".into())
                })?;
            Ok(json!({ "document": document }))
        }
        EnvironmentAgentAction::QueryProjections => {
            let id = arguments
                .get("document_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let document = documents
                .iter()
                .find(|document| document.id == id)
                .ok_or_else(|| {
                    EnvironmentAgentError::InvalidOutput("projection is not admitted".into())
                })?;
            Ok(json!({ "document": document }))
        }
        EnvironmentAgentAction::ProposeChange => {
            let document_id = arguments
                .get("document_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let command_id = arguments
                .get("command_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let payload = arguments.get("payload").cloned().unwrap_or(Value::Null);
            let document = documents
                .iter()
                .find(|document| document.id == document_id)
                .ok_or_else(|| {
                    EnvironmentAgentError::InvalidOutput("proposal document is not admitted".into())
                })?;
            if !document
                .commands
                .iter()
                .any(|command| command == command_id)
            {
                return Err(EnvironmentAgentError::InvalidOutput(
                    "proposal command is not admitted for its document".into(),
                ));
            }
            if contains_secret(&payload) {
                return Err(EnvironmentAgentError::Rejected(
                    EnvironmentAgentRejection::SecretBearingArguments,
                ));
            }
            let proposal = EnvironmentAgentProposal {
                document_id: document.id.clone(),
                command_id: command_id.to_owned(),
                base_revision: document.revision.clone(),
                payload,
            };
            proposals.push(proposal.clone());
            Ok(
                json!({ "prepared": true, "proposal": proposal, "notice": "The proposal is not applied. The ordinary Environment command route must reauthorize it and open required review." }),
            )
        }
    }
}

fn development_environment_agent_turn(
    context: &EnvironmentAgentContext,
    message: &str,
) -> EnvironmentAgentTurn {
    if let Some(command) = message.strip_prefix("/propose ") {
        if let Some((command_id, payload)) = command.split_once(' ') {
            if let Ok(payload) = serde_json::from_str::<Value>(payload) {
                if let Some(document) = context
                    .documents
                    .iter()
                    .find(|document| document.commands.iter().any(|id| id == command_id))
                {
                    return EnvironmentAgentTurn {
                        message: format!(
                            "I opened a reviewable {command_id} proposal. It is not applied until you review it."
                        ),
                        proposals: vec![EnvironmentAgentProposal {
                            document_id: document.id.clone(),
                            command_id: command_id.to_owned(),
                            base_revision: document.revision.clone(),
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
        return EnvironmentAgentTurn {
            message: "The registered Homes have live target-admitted projections; I can describe only the Machines, projects, and placements present in those admitted documents.".into(),
            proposals: Vec::new(),
        };
    }
    let paths = context
        .documents
        .iter()
        .map(|document| document.path.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    EnvironmentAgentTurn {
        message: format!(
            "Development provider: I am admitted to {}:{} and can read these exact projections: {paths}. No change was proposed.",
            context.session.scope.kind, context.session.scope.id,
        ),
        proposals: Vec::new(),
    }
}

/// Run one bounded management Environment turn. The provider never receives a
/// bearer for GaugeWright, never receives ambient tools, and cannot apply or
/// review a change. Callers must submit returned proposals through the ordinary
/// Environment command endpoint, which rebuilds authority and validates them.
pub fn run_environment_agent_turn(
    workbench: &SharedWorkbench,
    context: EnvironmentAgentContext,
    message: &str,
) -> Result<EnvironmentAgentTurn, EnvironmentAgentError> {
    let message = message.trim();
    if message.is_empty() {
        return Err(EnvironmentAgentError::InvalidOutput(
            "message is empty".into(),
        ));
    }
    if contains_secret_text(message) {
        return Err(EnvironmentAgentError::Rejected(
            EnvironmentAgentRejection::SecretBearingArguments,
        ));
    }
    // Local dashboard acceptance needs to cover the real broker, transcript,
    // and exact-scope session without distributing a production provider key.
    // Release builds cannot activate this path, even if the variable leaks
    // into their environment.
    if cfg!(debug_assertions) && environment_flag("GAUGEWRIGHT_FAKE_MANAGEMENT_AGENT") {
        return Ok(development_environment_agent_turn(&context, message));
    }
    let credential = resolve_agent_credential(workbench, &context.session.actor)?;
    let agent_session = EnvironmentAgentSession::from_environment(&context.session);
    let system = format!(
        "You are the {} agent for one exact GaugeWright management Environment session. Explain the admitted projections and help the person operate them. Use only the declared tools. Never claim that a proposal is applied or reviewed. Never request, display, infer, or place secrets in tool arguments. Ask the person when required data is missing. Your exact scope is {}:{} and your actor is {}.",
        context.session.environment.as_str(), context.session.scope.kind, context.session.scope.id, context.session.actor,
    );
    let mut input = vec![json!({
        "role": "user",
        "content": [{ "type": "input_text", "text": message }]
    })];
    let mut proposals = Vec::new();
    for _ in 0..MAX_TOOL_ROUNDS {
        let body = json!({
            "model": std::env::var("GAUGEWRIGHT_MANAGEMENT_AGENT_MODEL").unwrap_or_else(|_| "gpt-5.6-terra".into()),
            "instructions": system,
            "input": input,
            "tools": provider_tools(),
            "tool_choice": "auto",
            "parallel_tool_calls": false,
            "store": false
        });
        let response = provider_request(&credential, &body)?;
        let output = response
            .get("output")
            .and_then(Value::as_array)
            .ok_or_else(|| EnvironmentAgentError::InvalidOutput("missing output array".into()))?;
        let calls = output
            .iter()
            .filter(|item| item.get("type").and_then(Value::as_str) == Some("function_call"))
            .collect::<Vec<_>>();
        let text = assistant_text(output);
        input.extend(output.iter().cloned());
        if calls.is_empty() {
            let message = if text.trim().is_empty() {
                "I could not produce an admitted response.".into()
            } else {
                text
            };
            if contains_secret_text(&message) {
                return Err(EnvironmentAgentError::Rejected(
                    EnvironmentAgentRejection::SecretBearingArguments,
                ));
            }
            return Ok(EnvironmentAgentTurn { message, proposals });
        }
        for call in calls {
            let name = call.get("name").and_then(Value::as_str).unwrap_or_default();
            let call_id = call.get("call_id").and_then(Value::as_str).ok_or_else(|| {
                EnvironmentAgentError::InvalidOutput("tool call has no call id".into())
            })?;
            let arguments = call
                .get("arguments")
                .and_then(Value::as_str)
                .and_then(|value| serde_json::from_str::<Value>(value).ok())
                .ok_or_else(|| {
                    EnvironmentAgentError::InvalidOutput("tool arguments are invalid".into())
                })?;
            let result = tool_result(
                &agent_session,
                &context.documents,
                name,
                arguments,
                &mut proposals,
            )?;
            input.push(json!({
                "type": "function_call_output",
                "call_id": call_id,
                "output": serde_json::to_string(&result).expect("tool result serializes")
            }));
        }
    }
    Err(EnvironmentAgentError::InvalidOutput(
        "tool round limit exceeded".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment_contract::{
        EnvironmentCommandGrant, EnvironmentDocumentGrant, ReviewPolicy,
    };
    use proptest::prelude::*;
    use serde_json::json;

    fn environment() -> EnvironmentSession {
        EnvironmentSession {
            id: "environment-session".into(),
            environment: EnvironmentKind::Administration,
            scope: EnvironmentScope {
                kind: "tenant".into(),
                id: "tenant-a".into(),
            },
            actor: "person:alice".into(),
            capabilities: vec!["edit-org-settings".into()],
            documents: vec![EnvironmentDocumentGrant {
                id: "administration.organization".into(),
                path: "organization.json".into(),
                schema: "gw://organization/v1".into(),
                revision: "revision-1".into(),
                freshness: "live".into(),
                readable: true,
                editable: true,
                commands: vec!["organization.update".into()],
            }],
            commands: vec![EnvironmentCommandGrant {
                id: "organization.update".into(),
                capability: "edit-org-settings".into(),
                review: ReviewPolicy::Human,
            }],
        }
    }

    #[test]
    fn development_provider_reports_only_exact_admitted_scope_and_paths() {
        let context = EnvironmentAgentContext {
            session: environment(),
            documents: vec![EnvironmentAgentDocument {
                id: "administration.organization".into(),
                path: "organization.json".into(),
                revision: "revision-1".into(),
                content: json!({ "display_name": "Example" }),
                commands: vec!["update-organization".into()],
            }],
        };

        let turn = development_environment_agent_turn(&context, "Explain this environment.");

        assert!(turn.message.contains("tenant:tenant-a"));
        assert!(turn.message.contains("organization.json"));
        assert!(!turn.message.contains("Example"));
        assert!(turn.proposals.is_empty());
    }

    #[test]
    fn development_provider_prepares_an_admitted_reviewable_proposal() {
        let context = EnvironmentAgentContext {
            session: environment(),
            documents: vec![EnvironmentAgentDocument {
                id: "administration.people".into(),
                path: "people.json".into(),
                revision: "revision-7".into(),
                content: json!({}),
                commands: vec!["member.invite".into()],
            }],
        };

        let turn = development_environment_agent_turn(
            &context,
            r#"/propose member.invite {"authority":"person:bob","role":"member"}"#,
        );

        assert!(turn.message.contains("reviewable member.invite proposal"));
        assert_eq!(
            turn.proposals,
            vec![EnvironmentAgentProposal {
                document_id: "administration.people".into(),
                command_id: "member.invite".into(),
                base_revision: "revision-7".into(),
                payload: json!({ "authority": "person:bob", "role": "member" }),
            }],
        );
    }

    fn request(
        session: &EnvironmentAgentSession,
        tool: &str,
        arguments: Value,
    ) -> EnvironmentAgentToolRequest {
        EnvironmentAgentToolRequest {
            agent_session_id: session.id.clone(),
            environment_session_id: session.environment_session_id.clone(),
            environment: session.environment,
            scope: session.scope.clone(),
            tool: tool.into(),
            arguments,
        }
    }

    #[test]
    fn admitted_tools_are_exact_and_management_sessions_have_no_ambient_authority() {
        let session = EnvironmentAgentSession::from_environment(&environment());
        assert!(!session.message_attachments);
        assert!(!session.additional_tools);
        for (tool, action) in [
            (FILES_LIST_TOOL, EnvironmentAgentAction::ListFiles),
            (FILES_READ_TOOL, EnvironmentAgentAction::ReadFile),
            (
                PROJECTIONS_QUERY_TOOL,
                EnvironmentAgentAction::QueryProjections,
            ),
            (CHANGES_PROPOSE_TOOL, EnvironmentAgentAction::ProposeChange),
        ] {
            assert_eq!(
                decide_environment_agent_tool(&session, &request(&session, tool, json!({}))),
                Ok(action)
            );
        }
        assert_eq!(
            decide_environment_agent_tool(&session, &request(&session, "shell.exec", json!({}))),
            Err(EnvironmentAgentRejection::UndeclaredTool),
        );
    }

    #[test]
    fn scope_revocation_and_secret_arguments_fail_closed() {
        let mut session = EnvironmentAgentSession::from_environment(&environment());
        let mut cross_scope = request(
            &session,
            FILES_READ_TOOL,
            json!({ "path": "organization.json" }),
        );
        cross_scope.scope.id = "tenant-b".into();
        assert_eq!(
            decide_environment_agent_tool(&session, &cross_scope),
            Err(EnvironmentAgentRejection::ScopeMismatch)
        );
        assert_eq!(
            decide_environment_agent_tool(
                &session,
                &request(
                    &session,
                    CHANGES_PROPOSE_TOOL,
                    json!({ "payload": { "api_key": "must-not-enter" } })
                )
            ),
            Err(EnvironmentAgentRejection::SecretBearingArguments),
        );
        session.active = false;
        assert_eq!(
            decide_environment_agent_tool(&session, &request(&session, FILES_LIST_TOOL, json!({}))),
            Err(EnvironmentAgentRejection::SessionRevoked),
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
            "No API key is projected into this Environment."
        ));
    }

    #[test]
    fn transcript_is_durable_and_exact_session_scoped() {
        let root = tempfile::tempdir().unwrap();
        let workbench = crate::open_workbench(root.path()).unwrap();
        let session = environment();
        let transcript = append_environment_agent_exchange(
            &workbench,
            &session,
            "Show the organization posture.",
            "Open organization.json for the admitted projection.",
        )
        .unwrap();
        assert_eq!(transcript.len(), 2);
        drop(workbench);

        let reopened = crate::open_workbench(root.path()).unwrap();
        let guard = reopened.lock_unpoisoned();
        let folded = environment_agent_transcript(guard.store_ref(), &session).unwrap();
        assert_eq!(folded, transcript);

        let mut other = session;
        other.scope.id = "tenant-b".into();
        assert!(environment_agent_transcript(guard.store_ref(), &other)
            .unwrap()
            .is_empty());
    }

    proptest! {
        #[test]
        fn arbitrary_unknown_tools_never_admit(name in "[a-z][a-z0-9_.-]{0,40}") {
            prop_assume!(!MANAGEMENT_AGENT_TOOLS.contains(&name.as_str()));
            let session = EnvironmentAgentSession::from_environment(&environment());
            prop_assert_eq!(
                decide_environment_agent_tool(&session, &request(&session, &name, json!({}))),
                Err(EnvironmentAgentRejection::UndeclaredTool),
            );
        }
    }
}
