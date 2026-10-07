//! The one management host every GaugeApp a Home serves runs on.
//!
//! A GaugeApp here is a [`GaugeAppDefinition`]: its exact admitted scope,
//! grants, projections, closed planners and composition-owned authority hooks.
//! This host owns sessions, retained conversation and live transport, commands,
//! durable proposal admission, Human review, receipts and audit. Each definition
//! enables only its existing route population and response encoding; its owning
//! composition mounts it with [`mount`].
//!
//! Every request and asynchronous turn step rebuilds current admission using
//! the captured composition services. The person and agent share the owning
//! planner and command authority. Approved external work retains its original
//! operation and runs outside the Workbench lock through [`PendingAuthority`].
use axum::{
    extract::{FromRequestParts, Path, Query, State},
    http::{request::Parts, Extensions, HeaderMap, StatusCode},
    response::{
        sse::{Event, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use gaugedesk_store::{AdmitError, CommandRecordFact};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{future::Future, pin::Pin};

use tokio_stream::{wrappers::BroadcastStream, StreamExt};

use crate::{
    gaugeapp_agent::{
        append_gaugeapp_agent_exchange_prepared_current, begin_gaugeapp_agent_live_turn,
        claim_gaugeapp_agent_turn, erase_gaugeapp_agent_transcript_current,
        gaugeapp_agent_live_subscription, gaugeapp_agent_page_actions,
        gaugeapp_agent_page_commands, gaugeapp_agent_thread_owner_scope, gaugeapp_agent_transcript,
        gaugeapp_agent_turn_was_stopped, gaugeapp_thread_id, replayed_gaugeapp_agent_turn,
        request_gaugeapp_agent_stop, run_gaugeapp_agent_turn_with_direct_actions,
        GaugeAppAgentContext, GaugeAppAgentError, GaugeAppAgentLiveEvent, GaugeAppAgentLiveFrame,
        GaugeAppAgentLiveTurn, GaugeAppAgentMessage, GaugeAppAgentPage, GaugeAppAgentProposal,
        GaugeAppAgentRejection,
    },
    gaugeapp_contract::{
        decide_gaugeapp_command, decide_reviewed_gaugeapp_command, fold_gaugeapp_changes,
        gaugeapp_change_id, gaugeapp_receipt, gaugeapp_session_id, AdmissionDisposition,
        GaugeAppChangeRecord, GaugeAppChangeStatus, GaugeAppClient, GaugeAppCommandEnvelope,
        GaugeAppCommandGrant, GaugeAppKind, GaugeAppPageAvailability, GaugeAppPageGrant,
        GaugeAppRejection, GaugeAppScope, GaugeAppSession, ReviewPolicy, GAUGEAPP_CHANGE_KIND,
    },
    workbench_auth::req_scope,
    LockUnpoisoned, SharedWorkbench, Workbench,
};

/// Every GaugeApp this Home serves. Adding one is a line here.
pub fn routes() -> Router<SharedWorkbench> {
    mount::<crate::project_settings_gaugeapp::ProjectSettings>()
        .merge(mount::<crate::agent_settings_gaugeapp::AgentSettings>())
        .merge(mount::<crate::panel_settings_gaugeapp::PanelSettings>())
}

/// What makes one GaugeApp different from another. The host supplies the rest.
pub trait GaugeAppDefinition: 'static {
    /// Composition-owned authority services. The host never depends on an
    /// enterprise authority or learns its credentials.
    type Services: Clone + Default + Send + Sync + 'static;

    /// Capture the services this composition attached to this request.
    fn services(_extensions: &Extensions) -> Self::Services {
        Self::Services::default()
    }

    /// Rebuild the exact admitted context. Definitions with independently
    /// granted pages and commands retain those grants rather than widening
    /// them to a single management capability.
    fn context(
        wb: &Workbench,
        headers: &HeaderMap,
        id: &str,
        _services: &Self::Services,
    ) -> Result<GaugeAppAgentContext, Box<Response>>
    where
        Self: Sized,
    {
        default_context::<Self>(wb, headers, id)
    }

    /// Retained transports declare their existing session and cursor encoding.
    const OPEN_SCOPE_BODY: bool = false;
    const RESUMABLE_CONVERSATION: bool = false;
    const LIVE_EVENTS: bool = false;
    const PAGE_UPDATES: bool = false;

    fn session_stale() -> Response
    where
        Self: Sized,
    {
        stale::<Self>()
    }

    fn transcript_error(reason: String) -> Response {
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("management conversation unavailable: {reason}"),
        )
    }

    fn opened(context: &GaugeAppAgentContext) -> Value {
        json!({ "session": context.session, "pages": context.pages })
    }

    fn prepare_transcript(
        _wb: &mut Workbench,
        _session: &GaugeAppSession,
    ) -> Result<(), GaugeAppAgentError> {
        Ok(())
    }

    fn agent_error(reason: GaugeAppAgentError) -> Response {
        agent_error(reason)
    }

    fn agent_stale() -> Response
    where
        Self: Sized,
    {
        stale::<Self>()
    }

    fn message_idempotency(_headers: &HeaderMap, key: &str) -> Result<(), Box<Response>> {
        if key.trim().is_empty() {
            Err(Box::new(error(
                StatusCode::BAD_REQUEST,
                "idempotency key required",
            )))
        } else {
            Ok(())
        }
    }

    fn direct_key(session: &GaugeAppSession, key: &str) -> String {
        let _ = session;
        format!("agent:{key}")
    }

    fn validate_agent(
        _wb: &Workbench,
        _headers: &HeaderMap,
        context: &GaugeAppAgentContext,
        envelope: &GaugeAppCommandEnvelope,
        _services: &Self::Services,
    ) -> Result<(), GaugeAppAgentError> {
        decide_gaugeapp_command(&context.session, envelope)
            .map_err(|reason| GaugeAppAgentError::InvalidOutput(reason.message().into()))?;
        Self::validate(envelope).map_err(|_| {
            GaugeAppAgentError::InvalidOutput(format!("Invalid {} values", Self::LABEL))
        })
    }

    fn invoke_agent(
        wb: &SharedWorkbench,
        headers: &HeaderMap,
        id: &str,
        opening: &GaugeAppSession,
        proposal: &GaugeAppAgentProposal,
        key: &str,
        services: &Self::Services,
    ) -> Result<Value, GaugeAppAgentError>
    where
        Self: Sized,
    {
        let mut guard = wb.lock_unpoisoned();
        let current = still_current::<Self>(&guard, headers, id, opening, services)?;
        let envelope = agent_envelope::<Self>(&current.session, proposal, key);
        apply_command_with_services::<Self>(&mut guard, headers, id, &envelope, services)
            .map_err(|_| GaugeAppAgentError::InvalidOutput(
                "The setting changed or its values were refused; read the current page and try again.".into()
            ))
    }

    fn prepare_agent_proposal(
        _wb: &Workbench,
        _headers: &HeaderMap,
        _envelope: &GaugeAppCommandEnvelope,
        _services: &Self::Services,
    ) -> Result<CommandRecordFact, GaugeAppAgentError> {
        Err(GaugeAppAgentError::InvalidOutput(
            "Changes here apply directly; no proposal is available.".into(),
        ))
    }

    const HUMAN_REVIEW: bool = false;

    fn command_ceremony(
        _wb: SharedWorkbench,
        _headers: HeaderMap,
        _envelope: GaugeAppCommandEnvelope,
        _key: String,
        _services: Self::Services,
    ) -> CeremonyFuture {
        Box::pin(async { None })
    }

    fn plan_command(
        _wb: &Workbench,
        _headers: &HeaderMap,
        _envelope: &GaugeAppCommandEnvelope,
        _services: &Self::Services,
    ) -> Result<CommandPlan, Box<Response>> {
        Err(Box::new(error(
            StatusCode::FORBIDDEN,
            "command requires its owning planner",
        )))
    }

    fn requires_external_review(_command: &str, _services: &Self::Services) -> bool {
        false
    }

    fn apply_plan(
        _wb: &mut Workbench,
        _headers: &HeaderMap,
        _session: &GaugeAppSession,
        _envelope: &GaugeAppCommandEnvelope,
        _operation_key: &str,
        plan: CommandPlan,
        _services: &Self::Services,
    ) -> Result<CommandPlan, Box<Response>> {
        Ok(plan)
    }

    fn visible_change(
        _wb: &Workbench,
        _headers: &HeaderMap,
        _change: &GaugeAppChangeRecord,
        _services: &Self::Services,
    ) -> bool {
        true
    }

    fn review_evidence(
        _wb: SharedWorkbench,
        _headers: HeaderMap,
        _id: String,
        _body: ReviewBody,
        _services: Self::Services,
    ) -> ReviewEvidenceFuture {
        Box::pin(async { Ok(()) })
    }

    fn recover_review(
        _wb: &mut Workbench,
        _headers: &HeaderMap,
        _session: &GaugeAppSession,
        _change: &GaugeAppChangeRecord,
        _body: &ReviewBody,
        _services: &Self::Services,
    ) -> Option<Result<PendingAuthority, Box<Response>>> {
        None
    }

    fn review_claim_key(change_id: &str) -> String {
        format!("external-review:{change_id}")
    }

    fn begin_external_review(
        _wb: &mut Workbench,
        _headers: &HeaderMap,
        _session: &GaugeAppSession,
        _review: ExternalReview<'_>,
        _services: &Self::Services,
    ) -> Result<PendingAuthority, Box<Response>> {
        Err(Box::new(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "external review handoff is not configured",
        )))
    }

    fn accept_stale_proposal(
        _wb: &Workbench,
        _envelope: &GaugeAppCommandEnvelope,
        _change: &GaugeAppChangeRecord,
    ) -> bool {
        false
    }

    fn authorize_review(
        _session: &GaugeAppSession,
        _envelope: &GaugeAppCommandEnvelope,
        _body: &ReviewBody,
        _services: &Self::Services,
    ) -> Result<(), Box<Response>> {
        Ok(())
    }

    fn reviewed_committed(
        _wb: SharedWorkbench,
        _envelope: &GaugeAppCommandEnvelope,
        _freshly_applied: bool,
    ) {
    }

    fn record_scope(headers: &HeaderMap) -> String {
        req_scope(headers)
    }

    fn command_scope(headers: &HeaderMap) -> String {
        req_scope(headers)
    }

    fn projection_error(reason: impl std::fmt::Debug) -> Response {
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("GaugeApp page projection unavailable: {reason:?}"),
        )
    }

    fn store_error(reason: AdmitError) -> Response {
        match reason {
            AdmitError::Rejected(rejection) => (
                StatusCode::CONFLICT,
                Json(json!({ "error": rejection.reason, "rejected": rejection.reason })),
            )
                .into_response(),
            other => Self::projection_error(other),
        }
    }

    fn after_command(
        _wb: &mut Workbench,
        _headers: &HeaderMap,
        _session: &GaugeAppSession,
        _envelope: &GaugeAppCommandEnvelope,
    ) -> Result<(), Box<Response>> {
        Ok(())
    }

    /// Which GaugeApp this is. Its conversation identity is person + this +
    /// the scope.
    const APP: GaugeAppKind;
    /// Where its routes are served; `{id}` is the exact scope's id. The routes
    /// are this followed by `/sessions`, `/agent/messages`, `/agent/stop`,
    /// `/agent/erase` and `/commands`.
    const PATH: &'static str;
    /// What it manages, as the session's scope and the command response name it.
    const SCOPE: &'static str;
    /// How a refusal names it, such as "project settings".
    const LABEL: &'static str;
    /// The capability its commands need, held only by a person who may manage
    /// the scope.
    const CAPABILITY: &'static str;
    /// Commands granted by the default context builder. Definitions projecting
    /// per-command authority through `context` keep their closed policy there. Each needs
    /// an agent path in [`crate::gaugeapp_agent::gaugeapp_agent_action_kind`].
    const COMMANDS: &'static [&'static str];

    /// Admit the person and the exact scope, refusing anyone who may not read
    /// it, and say whether they may also change it.
    fn admit(_wb: &Workbench, _headers: &HeaderMap, _id: &str) -> Result<Admission, Box<Response>> {
        Err(boxed_error(
            StatusCode::FORBIDDEN,
            "this definition requires its composition's admission",
        ))
    }

    /// The pages a session shows, each with the commands it declares. A person
    /// who may not manage the scope sees the same pages with no commands.
    fn pages(_wb: &Workbench, _id: &str) -> Vec<Page> {
        Vec::new()
    }

    /// Check a command's payload without changing anything, so the agent's
    /// tool can refuse it within the turn.
    fn validate(_envelope: &GaugeAppCommandEnvelope) -> Result<(), Box<Response>> {
        Err(boxed_error(
            StatusCode::FORBIDDEN,
            "this command requires its composition's authority",
        ))
    }

    /// Apply an admitted command through the scope's own state methods, on
    /// behalf of `actor`, the person the session admitted.
    fn apply(
        wb: &mut Workbench,
        actor: &str,
        id: &str,
        envelope: &GaugeAppCommandEnvelope,
    ) -> Result<Applied, Box<Response>> {
        let _ = (wb, actor, id, envelope);
        Err(boxed_error(
            StatusCode::FORBIDDEN,
            "this command requires its composition's authority",
        ))
    }
}

/// The person a definition admitted, and whether they may change the scope.
pub struct Admission {
    pub actor: String,
    pub can_manage: bool,
}

/// One page of a GaugeApp: its read model and the commands it declares.
pub struct Page {
    pub id: &'static str,
    pub read_model: String,
    pub model: Value,
    pub commands: &'static [&'static str],
}

/// Inputs for the approved external review handoff, retained as one transaction.
pub struct ExternalReview<'a> {
    pub envelope: &'a GaugeAppCommandEnvelope,
    pub key: &'a str,
    pub change: &'a GaugeAppChangeRecord,
    pub plan: CommandPlan,
}

pub type ReviewEvidenceFuture = Pin<Box<dyn Future<Output = Result<(), Box<Response>>> + Send>>;
type AuthorityFuture = Pin<Box<dyn Future<Output = Response> + Send>>;

/// An exact already-approved authority operation. The host executes it only
/// after releasing the Workbench lock; its owning definition captures the
/// original operation and composition services, never a refreshed payload.
pub struct PendingAuthority(Box<dyn FnOnce(SharedWorkbench, HeaderMap) -> AuthorityFuture + Send>);

impl PendingAuthority {
    pub fn new<F, Fut>(run: F) -> Self
    where
        F: FnOnce(SharedWorkbench, HeaderMap) -> Fut + Send + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        Self(Box::new(move |wb, headers| Box::pin(run(wb, headers))))
    }
    async fn execute(self, wb: SharedWorkbench, headers: HeaderMap) -> Response {
        (self.0)(wb, headers).await
    }
}

#[derive(Clone, Deserialize)]
pub struct ReviewBody {
    pub session_id: String,
    pub generation: String,
    pub app: GaugeAppKind,
    pub scope: GaugeAppScope,
    pub decision: String,
    #[serde(default = "web_client")]
    pub client: GaugeAppClient,
    #[serde(default)]
    pub authorization_proof: Option<String>,
}
fn web_client() -> GaugeAppClient {
    GaugeAppClient::Web
}

pub type CeremonyFuture = Pin<Box<dyn Future<Output = Option<Response>> + Send>>;

/// Closed domain facts and notices, committed by the host with its receipt.
#[derive(Clone, Debug)]
pub struct CommandPlan {
    pub facts: Vec<CommandRecordFact>,
    pub notices: Vec<(&'static str, String, &'static str)>,
    pub audit_action: &'static str,
    pub audit_target: String,
    pub transient_result: Option<Value>,
}

/// Apply a committed command's projection using its ordered domain-fact positions.
pub type CommittedProjection = Box<dyn FnOnce(&mut Workbench, &[i64])>;

/// What applying a command leaves for the host to make durable.
pub struct Applied {
    /// Records admitted in the same transaction as the command's receipt.
    pub facts: Vec<CommandRecordFact>,
    /// Run once those records are durable, and never for a replay. The positions
    /// match `facts` in order and exclude the receipt and audit suffix.
    pub committed: CommittedProjection,
}

impl Applied {
    /// A command whose state method has already made its change durable.
    pub fn done() -> Self {
        Self {
            facts: Vec::new(),
            committed: Box::new(|_, _| {}),
        }
    }
}

pub(crate) fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

pub(crate) fn boxed_error(status: StatusCode, message: impl Into<String>) -> Box<Response> {
    Box::new(error(status, message))
}

fn digest(value: &Value) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            serde_json::to_vec(value).expect("JSON serializes")
        ))
    )
}

pub fn mount<D: GaugeAppDefinition>() -> Router<SharedWorkbench> {
    let at = |suffix: &str| format!("{}{suffix}", D::PATH);
    let mut routes = conversation_routes::<D>().route(&at("/commands"), post(command::<D>));
    if D::HUMAN_REVIEW {
        routes = routes
            .route(
                &at("/proposals"),
                get(list_changes::<D>).post(submit_proposal::<D>),
            )
            .route(&at("/proposals/{id}/review"), post(review_change::<D>));
    }
    routes
}

/// The common session and conversation lifecycle. Definitions supply exact
/// authority and closed domain hooks; the host owns the retained transport.
pub fn conversation_routes<D: GaugeAppDefinition>() -> Router<SharedWorkbench> {
    let at = |suffix: &str| format!("{}{suffix}", D::PATH);
    let mut routes = Router::new()
        .route(&at("/sessions"), post(open_session::<D>))
        .route(
            &at("/agent/messages"),
            get(messages::<D>).post(message::<D>),
        )
        .route(&at("/agent/stop"), post(stop::<D>))
        .route(&at("/agent/erase"), post(erase::<D>));
    if D::PAGE_UPDATES {
        routes = routes
            .route(&at("/pages/{id}"), get(read_page::<D>))
            .route(&at("/updates"), get(read_updates::<D>));
    }
    if D::LIVE_EVENTS {
        routes = routes.route(&at("/agent/events"), get(events::<D>));
    }
    routes
}

/// Rebuild the admitted session with this definition's default composition.
pub fn context<D: GaugeAppDefinition>(
    wb: &Workbench,
    headers: &HeaderMap,
    id: &str,
) -> Result<GaugeAppAgentContext, Box<Response>> {
    D::context(wb, headers, id, &D::Services::default())
}

fn default_context<D: GaugeAppDefinition>(
    wb: &Workbench,
    headers: &HeaderMap,
    id: &str,
) -> Result<GaugeAppAgentContext, Box<Response>> {
    let Admission { actor, can_manage } = D::admit(wb, headers, id)?;
    let scope = GaugeAppScope {
        kind: D::SCOPE.into(),
        id: id.into(),
    };
    // The session remains stable through ordinary edits. Role or membership
    // changes alter this epoch, and every request also re-admits the scope.
    let generation = digest(&json!({ "actor": actor, "scope": scope, "can_manage": can_manage }));
    let pages = D::pages(wb, id);
    let grants = pages
        .iter()
        .map(|page| GaugeAppPageGrant {
            id: page.id.into(),
            read_model: page.read_model.clone(),
            version: 1,
            resource_basis: digest(&page.model),
            freshness: "live".into(),
            availability: GaugeAppPageAvailability::Available,
            commands: if can_manage {
                page.commands.iter().map(|id| (*id).into()).collect()
            } else {
                Vec::new()
            },
        })
        .collect::<Vec<_>>();
    let session = GaugeAppSession {
        id: gaugeapp_session_id(&actor, D::APP, &scope, &generation),
        generation,
        app: D::APP,
        scope,
        actor,
        capabilities: if can_manage {
            vec![D::CAPABILITY.into()]
        } else {
            Vec::new()
        },
        pages: grants.clone(),
        commands: (if can_manage { D::COMMANDS } else { &[] })
            .iter()
            .map(|id| GaugeAppCommandGrant {
                id: (*id).into(),
                capability: D::CAPABILITY.into(),
                review: ReviewPolicy::Immediate,
            })
            .collect(),
        update_cursor: digest(&json!(grants)),
    };
    let agent_pages = pages
        .into_iter()
        .zip(grants)
        .map(|(page, grant)| GaugeAppAgentPage {
            id: grant.id.clone(),
            read_model: grant.read_model.clone(),
            version: grant.version,
            resource_basis: grant.resource_basis.clone(),
            model: page.model,
            commands: gaugeapp_agent_page_commands(&session, &grant),
            actions: gaugeapp_agent_page_actions(&session, &grant),
        })
        .collect();
    Ok(GaugeAppAgentContext {
        session,
        pages: agent_pages,
    })
}

/// Only the definition interprets composition extensions. Keeping extraction
/// here lets all routes use the same host without an enterprise dependency.
struct DefinitionServices<D: GaugeAppDefinition>(D::Services);

impl<D: GaugeAppDefinition> FromRequestParts<SharedWorkbench> for DefinitionServices<D> {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &SharedWorkbench,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(D::services(&parts.extensions)))
    }
}

pub fn agent_transcript_payload(
    session: &GaugeAppSession,
    transcript: Vec<GaugeAppAgentMessage>,
    after: Option<&str>,
) -> Result<Value, Box<Response>> {
    let thread_id = gaugeapp_thread_id(session);
    let start_cursor = format!("{thread_id}:start");
    let start = match after {
        None => 0,
        Some(cursor) if cursor == start_cursor => 0,
        Some(cursor) => transcript
            .iter()
            .position(|message| message.id == cursor)
            .map(|index| index + 1)
            .ok_or_else(|| {
                (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "management conversation cursor is stale or belongs to another thread",
                        "thread_id": thread_id,
                        "restart_cursor": start_cursor,
                    })),
                )
                    .into_response()
            })?,
    };
    let cursor = transcript
        .last()
        .map(|message| message.id.clone())
        .unwrap_or_else(|| start_cursor.clone());
    Ok(json!({
        "id": thread_id,
        "cursor": cursor,
        "messages": transcript.into_iter().skip(start).collect::<Vec<_>>(),
    }))
}

fn same(session: &GaugeAppSession, candidate: &GaugeAppSession) -> bool {
    session.id == candidate.id
        && session.generation == candidate.generation
        && session.actor == candidate.actor
        && session.scope == candidate.scope
}

fn stale<D: GaugeAppDefinition>() -> Response {
    error(
        StatusCode::UNAUTHORIZED,
        format!("{} session is stale or cross-scope", D::LABEL),
    )
}

/// Refuse unless the session opened earlier is still the current one.
fn still_current<D: GaugeAppDefinition>(
    wb: &Workbench,
    headers: &HeaderMap,
    id: &str,
    opening: &GaugeAppSession,
    services: &D::Services,
) -> Result<GaugeAppAgentContext, GaugeAppAgentError> {
    let current = D::context(wb, headers, id, services)
        .map_err(|_| GaugeAppAgentError::Rejected(GaugeAppAgentRejection::SessionRevoked))?;
    if !same(opening, &current.session) {
        return Err(GaugeAppAgentError::Rejected(
            GaugeAppAgentRejection::SessionMismatch,
        ));
    }
    Ok(current)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    session_id: String,
    generation: String,
    scope: GaugeAppScope,
}

impl Identity {
    fn names(&self, session: &GaugeAppSession) -> bool {
        session.id == self.session_id
            && session.generation == self.generation
            && session.scope == self.scope
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageBody {
    session_id: String,
    generation: String,
    scope: GaugeAppScope,
    idempotency_key: String,
    message: String,
}

#[derive(Deserialize)]
struct MessagesQuery {
    session: String,
    generation: String,
    scope: String,
    after: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EraseBody {
    session_id: String,
    generation: String,
    scope: GaugeAppScope,
    idempotency_key: String,
}

#[derive(Deserialize)]
pub struct OpenScopeBody {
    #[serde(default)]
    scope: Option<GaugeAppScope>,
}

async fn open_session<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    DefinitionServices(services): DefinitionServices<D>,
    path: Option<Path<String>>,
    headers: HeaderMap,
    body: Result<Json<OpenScopeBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let id = path.map(|Path(id)| id).unwrap_or_default();
    let requested = if D::OPEN_SCOPE_BODY {
        match body {
            Ok(Json(body)) => body.scope,
            Err(reason) => return reason.into_response(),
        }
    } else {
        None
    };
    let guard = wb.lock_unpoisoned();
    match D::context(&guard, &headers, &id, &services) {
        Ok(context)
            if requested
                .as_ref()
                .is_some_and(|scope| scope != &context.session.scope) =>
        {
            error(
                StatusCode::FORBIDDEN,
                "requested scope is not the admitted tenant",
            )
        }
        Ok(context) => (StatusCode::OK, Json(D::opened(&context))).into_response(),
        Err(response) => *response,
    }
}

async fn messages<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    DefinitionServices(services): DefinitionServices<D>,
    path: Option<Path<String>>,
    headers: HeaderMap,
    Query(query): Query<MessagesQuery>,
) -> Response {
    let id = path.map(|Path(id)| id).unwrap_or_default();
    let mut guard = wb.lock_unpoisoned();
    let context = match D::context(&guard, &headers, &id, &services) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if context.session.id != query.session
        || context.session.generation != query.generation
        || context.session.scope.id != query.scope
    {
        return D::agent_stale();
    }
    if let Err(reason) = D::prepare_transcript(&mut guard, &context.session) {
        return D::agent_error(reason);
    }
    match gaugeapp_agent_transcript(guard.store_ref(), &context.session) {
        Ok(messages) => {
            let thread = if D::RESUMABLE_CONVERSATION {
                match agent_transcript_payload(&context.session, messages, query.after.as_deref()) {
                    Ok(thread) => thread,
                    Err(response) => return *response,
                }
            } else {
                json!({ "id": gaugeapp_thread_id(&context.session), "messages": messages })
            };
            (StatusCode::OK, Json(json!({ "thread": thread }))).into_response()
        }
        Err(reason) => D::transcript_error(format!("{reason:?}")),
    }
}

#[derive(Deserialize)]
struct SessionQuery {
    session: String,
    generation: String,
    scope: String,
}

impl SessionQuery {
    fn names(&self, session: &GaugeAppSession) -> bool {
        self.session == session.id
            && self.generation == session.generation
            && self.scope == session.scope.id
    }
}

#[derive(Deserialize)]
struct UpdatesQuery {
    #[serde(flatten)]
    identity: SessionQuery,
    after: String,
}

async fn read_page<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    DefinitionServices(services): DefinitionServices<D>,
    Path(id): Path<String>,
    Query(query): Query<SessionQuery>,
    headers: HeaderMap,
) -> Response {
    let guard = wb.lock_unpoisoned();
    let context = match D::context(&guard, &headers, "", &services) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let session = context.session;
    if !query.names(&session) {
        return D::session_stale();
    }
    let Some(page) = context.pages.into_iter().find(|page| page.id == id) else {
        return error(StatusCode::NOT_FOUND, "page is not admitted");
    };
    let grant = session
        .pages
        .iter()
        .find(|page| page.id == id)
        .expect("projected page has grant");
    (
        StatusCode::OK,
        Json(json!({ "page": {
        "app": session.app, "scope": session.scope, "id": page.id,
        "read_model": page.read_model, "version": page.version,
        "resource_basis": grant.resource_basis, "freshness": grant.freshness,
        "model": page.model,
    } })),
    )
        .into_response()
}

async fn read_updates<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    DefinitionServices(services): DefinitionServices<D>,
    Query(query): Query<UpdatesQuery>,
    headers: HeaderMap,
) -> Response {
    let guard = wb.lock_unpoisoned();
    let context = match D::context(&guard, &headers, "", &services) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let session = context.session;
    if !query.identity.names(&session) {
        return D::session_stale();
    }
    let invalidations: Vec<Value> = if query.after == session.update_cursor {
        Vec::new()
    } else {
        session
            .pages
            .iter()
            .map(|page| {
                json!({
                    "page_id": page.id, "resource_basis": page.resource_basis,
                })
            })
            .collect()
    };
    (
        StatusCode::OK,
        Json(json!({ "cursor": session.update_cursor,
        "invalidations": invalidations })),
    )
        .into_response()
}

async fn events<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    DefinitionServices(services): DefinitionServices<D>,
    path: Option<Path<String>>,
    headers: HeaderMap,
    Query(query): Query<MessagesQuery>,
) -> Response {
    let id = path.map(|Path(id)| id).unwrap_or_default();
    let thread_id = {
        let guard = wb.lock_unpoisoned();
        let context = match D::context(&guard, &headers, &id, &services) {
            Ok(context) => context,
            Err(response) => return *response,
        };
        if context.session.id != query.session
            || context.session.generation != query.generation
            || context.session.scope.id != query.scope
        {
            return D::agent_stale();
        }
        gaugeapp_thread_id(&context.session)
    };
    let live_event =
        |frame: GaugeAppAgentLiveFrame| -> Result<Event, std::convert::Infallible> {
            Ok(Event::default()
                .data(serde_json::to_string(&frame).expect("GaugeApp frame serializes")))
        };
    let (retained, receiver) = gaugeapp_agent_live_subscription(&thread_id, query.after.as_deref());
    let retained = tokio_stream::iter(retained.into_iter().map(live_event));
    let current = BroadcastStream::new(receiver)
        .take_while(|message| message.is_ok())
        .filter_map(move |message| match message {
            Ok(frame) if frame.thread_id == thread_id => Some(live_event(frame)),
            _ => None,
        });
    Sse::new(retained.chain(current))
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response()
}

async fn stop<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    DefinitionServices(services): DefinitionServices<D>,
    path: Option<Path<String>>,
    headers: HeaderMap,
    Json(body): Json<Identity>,
) -> Response {
    let id = path.map(|Path(id)| id).unwrap_or_default();
    let guard = wb.lock_unpoisoned();
    let context = match D::context(&guard, &headers, &id, &services) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if !body.names(&context.session) {
        return D::agent_stale();
    }
    let stopped = request_gaugeapp_agent_stop(&gaugeapp_thread_id(&context.session));
    (StatusCode::OK, Json(json!({ "stopped": stopped }))).into_response()
}

async fn erase<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    DefinitionServices(services): DefinitionServices<D>,
    path: Option<Path<String>>,
    headers: HeaderMap,
    Json(body): Json<EraseBody>,
) -> Response {
    let id = path.map(|Path(id)| id).unwrap_or_default();
    let opening = {
        let guard = wb.lock_unpoisoned();
        let context = match D::context(&guard, &headers, &id, &services) {
            Ok(value) => value,
            Err(response) => return *response,
        };
        let identity = Identity {
            session_id: body.session_id,
            generation: body.generation,
            scope: body.scope,
        };
        if !identity.names(&context.session) {
            return D::agent_stale();
        }
        context.session
    };
    let erased =
        erase_gaugeapp_agent_transcript_current(&wb, &opening, &body.idempotency_key, &|guard| {
            still_current::<D>(guard, &headers, &id, &opening, &services).map(|_| ())
        });
    match erased {
        Ok(erasure) => (StatusCode::OK, Json(json!({ "erasure": erasure }))).into_response(),
        Err(reason) => D::agent_error(reason),
    }
}

/// Apply one command, from the page or the agent, against a freshly rebuilt
/// session. A retry with the same idempotency key answers with its first
/// receipt and changes nothing again.
pub fn apply_command<D: GaugeAppDefinition>(
    wb: &mut Workbench,
    headers: &HeaderMap,
    id: &str,
    envelope: &GaugeAppCommandEnvelope,
) -> Result<Value, Box<Response>> {
    apply_command_with_services::<D>(wb, headers, id, envelope, &D::Services::default())
}

fn apply_command_with_services<D: GaugeAppDefinition>(
    wb: &mut Workbench,
    headers: &HeaderMap,
    id: &str,
    envelope: &GaugeAppCommandEnvelope,
    services: &D::Services,
) -> Result<Value, Box<Response>> {
    let context = D::context(wb, headers, id, services)?;
    let session = &context.session;
    let scope = gaugeapp_agent_thread_owner_scope(session);
    let response = |receipt| {
        let mut body = serde_json::Map::new();
        body.insert("receipt".into(), json!(receipt));
        body.insert(D::SCOPE.into(), json!(id));
        Value::Object(body)
    };
    let change_id = gaugeapp_change_id(session, envelope);
    let existing = fold_gaugeapp_changes(wb.store_ref(), &scope).map_err(|reason| {
        boxed_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("settings receipts unavailable: {reason:?}"),
        )
    })?;
    if let Some(change) = existing.get(&change_id) {
        if change.payload != envelope.payload || change.command_id != envelope.command_id {
            return Err(boxed_error(
                StatusCode::CONFLICT,
                "idempotency key was used for another command",
            ));
        }
        return Ok(response(gaugeapp_receipt(session, envelope, "applied")));
    }
    decide_gaugeapp_command(session, envelope).map_err(|reason| {
        boxed_error(
            if matches!(reason, GaugeAppRejection::StaleBasis) {
                StatusCode::CONFLICT
            } else {
                StatusCode::FORBIDDEN
            },
            reason.message(),
        )
    })?;
    let Applied {
        mut facts,
        committed,
    } = D::apply(wb, &session.actor, id, envelope)?;
    let domain_fact_count = facts.len();
    let receipt = gaugeapp_receipt(session, envelope, "applied");
    let change = GaugeAppChangeRecord {
        id: change_id,
        app: D::APP,
        scope: session.scope.clone(),
        actor: session.actor.clone(),
        page_id: envelope.page_id.clone(),
        command_id: envelope.command_id.clone(),
        expected_basis: envelope.expected_basis.clone(),
        payload: envelope.payload.clone(),
        client: envelope.client,
        status: GaugeAppChangeStatus::Applied,
        reviewed_by: Some(session.actor.clone()),
        receipt_id: receipt.id.clone(),
    };
    facts.push(CommandRecordFact {
        scope_id: scope.clone(),
        kind: GAUGEAPP_CHANGE_KIND.into(),
        payload: serde_json::to_string(&change)
            .map_err(|reason| boxed_error(StatusCode::INTERNAL_SERVER_ERROR, reason.to_string()))?,
    });
    let tenant_scope = req_scope(headers);
    let audit_scope = crate::audit::scope_for(&tenant_scope);
    let audit_link = crate::audit::link(&session.actor, &envelope.command_id, id);
    let result = wb
        .store_mut()
        .admit_record_facts_chained(
            &scope,
            &envelope.idempotency_key,
            &serde_json::to_string(envelope).expect("command serializes"),
            &facts,
            Some(crate::audit::chained_in(&audit_scope, &audit_link)),
        )
        .map_err(|reason| {
            boxed_error(
                StatusCode::CONFLICT,
                format!("{} command refused: {reason:?}", D::LABEL),
            )
        })?;
    if !result.replayed {
        committed(wb, &result.positions[..domain_fact_count]);
        if let Some(entry) = crate::audit::committed_entry(result.chained_payload.as_deref()) {
            crate::audit::finish_committed_in(wb, &tenant_scope, &entry);
        }
    }
    Ok(response(receipt))
}

async fn command<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    DefinitionServices(services): DefinitionServices<D>,
    path: Option<Path<String>>,
    headers: HeaderMap,
    Json(envelope): Json<GaugeAppCommandEnvelope>,
) -> Response {
    let id = path.map(|Path(id)| id).unwrap_or_default();
    if D::HUMAN_REVIEW {
        return submit_reviewed_command::<D>(wb, headers, envelope, services).await;
    }
    let mut guard = wb.lock_unpoisoned();
    match apply_command_with_services::<D>(&mut guard, &headers, &id, &envelope, &services) {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(response) => *response,
    }
}

async fn submit_reviewed_command<D: GaugeAppDefinition>(
    wb: SharedWorkbench,
    headers: HeaderMap,
    envelope: GaugeAppCommandEnvelope,
    services: D::Services,
) -> Response {
    if let Err(response) = D::message_idempotency(&headers, &envelope.idempotency_key) {
        return *response;
    }
    let key = envelope.idempotency_key.clone();
    if let Some(response) = D::command_ceremony(
        wb.clone(),
        headers.clone(),
        envelope.clone(),
        key.clone(),
        services.clone(),
    )
    .await
    {
        return response;
    }
    let mut guard = wb.lock_unpoisoned();
    let session = match D::context(&guard, &headers, "", &services) {
        Ok(value) => value.session,
        Err(response) => return *response,
    };
    if envelope.session_id == session.id
        && envelope.generation == session.generation
        && envelope.app == session.app
        && envelope.scope == session.scope
    {
        match replayed_command_response::<D>(&guard, &headers, &session, &envelope, &key) {
            Ok(Some(response)) => return response,
            Ok(None) => {}
            Err(response) => return *response,
        }
    }
    let admission = match decide_gaugeapp_command(&session, &envelope) {
        Ok(value) => value,
        Err(error) => return reject_gaugeapp(error),
    };
    if D::requires_external_review(&envelope.command_id, &services)
        && admission.command.review != ReviewPolicy::Human
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "external authority changes require human review" })),
        )
            .into_response();
    }
    if contains_secret(&envelope.payload) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "secret-bearing fields are forbidden in GaugeApp commands" })),
        )
            .into_response();
    }
    // Parse and validate the owning GaugeApp's closed command before a
    // proposal becomes durable. Review re-runs this planner against fresh state.
    if let Err(response) = D::plan_command(&guard, &headers, &envelope, &services) {
        return *response;
    }
    match admission.disposition {
        AdmissionDisposition::Propose => {
            let change = proposed_change(&session, &envelope);
            let change_fact = match change_fact::<D>(&headers, GAUGEAPP_CHANGE_KIND, &change) {
                Ok(fact) => fact,
                Err(response) => return *response,
            };
            let audit_link =
                crate::audit::link(&session.actor, "gaugeapp.proposal.proposed", &change.id);
            let store_scope = D::record_scope(&headers);
            let audit_scope = crate::audit::scope_for(&store_scope);
            let result = match guard.store_mut().admit_record_facts_chained(
                &D::command_scope(&headers),
                &key,
                &snapshot(&envelope),
                &[change_fact],
                Some(crate::audit::chained_in(&audit_scope, &audit_link)),
            ) {
                Ok(result) => result,
                Err(error) => return D::store_error(error),
            };
            if let Some(entry) = crate::audit::committed_entry(result.chained_payload.as_deref()) {
                crate::audit::finish_committed_in(&mut guard, &store_scope, &entry);
            }
            (StatusCode::OK, Json(json!({ "receipt": gaugeapp_receipt(&session, &envelope, "proposed"), "proposal": change }))).into_response()
        }
        AdmissionDisposition::Apply => {
            let plan = match D::plan_command(&guard, &headers, &envelope, &services) {
                Ok(plan) => plan,
                Err(response) => return *response,
            };
            let plan = match D::apply_plan(
                &mut guard, &headers, &session, &envelope, &key, plan, &services,
            ) {
                Ok(plan) => plan,
                Err(response) => return *response,
            };
            finish_command_in::<D>(
                &mut guard,
                &headers,
                &session,
                &envelope,
                &key,
                None,
                plan,
                &D::command_scope(&headers),
            )
            .0
        }
    }
}

fn replayed_command_response<D: GaugeAppDefinition>(
    wb: &Workbench,
    headers: &HeaderMap,
    session: &GaugeAppSession,
    envelope: &GaugeAppCommandEnvelope,
    key: &str,
) -> Result<Option<Response>, Box<Response>> {
    let record = wb
        .store_ref()
        .command_for_key(&D::command_scope(headers), key)
        .map_err(D::projection_error)?;
    let Some(record) = record else {
        return Ok(None);
    };
    if record.snapshot_json != snapshot(envelope) {
        return Err(Box::new(D::store_error(AdmitError::Rejected(
            gaugedesk_core::Rejection {
                reason: "idempotency key reused with different command",
            },
        ))));
    }
    let id = gaugeapp_change_id(session, envelope);
    let change = fold_gaugeapp_changes(wb.store_ref(), &D::record_scope(headers))
        .map_err(D::projection_error)?
        .remove(&id)
        .ok_or_else(|| {
            D::projection_error(std::io::Error::other(
                "GaugeApp command receipt is missing its durable change",
            ))
        })?;
    let declaration = session
        .commands
        .iter()
        .find(|command| command.id == envelope.command_id)
        .ok_or_else(|| {
            (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "command is no longer available" })),
            )
                .into_response()
        })?;
    // This is the original submission receipt. Its current proposal may already
    // be applying/applied; extension commands must not fabricate an immediate
    // application just because their declaration lives outside the static map.
    let status = match declaration.review {
        ReviewPolicy::Immediate => "applied",
        ReviewPolicy::Human => "proposed",
    };
    Ok(Some(
        (
            StatusCode::OK,
            Json(json!({
                "receipt": gaugeapp_receipt(session, envelope, status),
                "proposal": change,
            })),
        )
            .into_response(),
    ))
}

fn contains_secret(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            matches!(
                key.as_str(),
                "password"
                    | "secret"
                    | "token"
                    | "private_key"
                    | "credential"
                    | "refresh_token"
                    | "access_token"
            ) || contains_secret(value)
        }),
        Value::Array(values) => values.iter().any(contains_secret),
        _ => false,
    }
}

fn reject_gaugeapp(error: GaugeAppRejection) -> Response {
    let status = if matches!(error, GaugeAppRejection::StaleBasis) {
        StatusCode::CONFLICT
    } else {
        StatusCode::FORBIDDEN
    };
    (
        status,
        Json(json!({ "error": error.message(), "rejection": error })),
    )
        .into_response()
}

async fn submit_proposal<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    DefinitionServices(services): DefinitionServices<D>,
    headers: HeaderMap,
    Json(envelope): Json<GaugeAppCommandEnvelope>,
) -> Response {
    if envelope.client != GaugeAppClient::Agent {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "proposal preparation is reserved for the GaugeApp agent",
        );
    }
    submit_reviewed_command::<D>(wb, headers, envelope, services).await
}

async fn list_changes<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    DefinitionServices(services): DefinitionServices<D>,
    Query(query): Query<SessionQuery>,
    headers: HeaderMap,
) -> Response {
    let guard = wb.lock_unpoisoned();
    let session = match D::context(&guard, &headers, "", &services) {
        Ok(context) => context.session,
        Err(response) => return *response,
    };
    if !query.names(&session) {
        return D::session_stale();
    }
    let changes = match fold_gaugeapp_changes(guard.store_ref(), &D::record_scope(&headers)) {
        Ok(changes) => changes,
        Err(reason) => return D::projection_error(reason),
    };
    let values: Vec<_> = changes
        .into_values()
        .filter(|change| {
            change.app == D::APP
                && change.scope == session.scope
                && D::visible_change(&guard, &headers, change, &services)
        })
        .collect();
    (StatusCode::OK, Json(json!({ "proposals": values }))).into_response()
}

async fn review_change<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    DefinitionServices(services): DefinitionServices<D>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ReviewBody>,
) -> Response {
    let key = match crate::command_idempotency::caller_idempotency_key(&headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    if let Err(response) = D::review_evidence(
        wb.clone(),
        headers.clone(),
        id.clone(),
        body.clone(),
        services.clone(),
    )
    .await
    {
        return *response;
    }
    match prepare_review::<D>(wb.clone(), services, id, headers.clone(), body, key) {
        Ok(response) => response,
        Err(job) => job.execute(wb, headers).await,
    }
}

// This synchronous phase never carries a Workbench guard into an await.
fn prepare_review<D: GaugeAppDefinition>(
    wb: SharedWorkbench,
    services: D::Services,
    id: String,
    headers: HeaderMap,
    body: ReviewBody,
    key: String,
) -> Result<Response, PendingAuthority> {
    if body.client == GaugeAppClient::Agent {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "management reviews require a human client" })),
        )
            .into_response());
    }
    let mut guard = wb.lock_unpoisoned();
    let session = match D::context(&guard, &headers, "", &services) {
        Ok(value) => value.session,
        Err(response) => return Ok(*response),
    };
    if body.session_id != session.id
        || body.generation != session.generation
        || body.app != D::APP
        || body.scope != session.scope
    {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "GaugeApp session is stale or cross-scope" })),
        )
            .into_response());
    }
    let changes = match fold_gaugeapp_changes(guard.store_ref(), &D::record_scope(&headers)) {
        Ok(changes) => changes,
        Err(error) => return Ok(D::projection_error(error)),
    };
    let Some(mut change) = changes.get(&id).cloned() else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such GaugeApp proposal" })),
        )
            .into_response());
    };
    let envelope = GaugeAppCommandEnvelope {
        session_id: session.id.clone(),
        generation: session.generation.clone(),
        app: D::APP,
        scope: session.scope.clone(),
        page_id: change.page_id.clone(),
        command_id: change.command_id.clone(),
        expected_basis: change.expected_basis.clone(),
        idempotency_key: key.clone(),
        payload: change.payload.clone(),
        client: body.client,
    };
    if let Some(recovery) =
        D::recover_review(&mut guard, &headers, &session, &change, &body, &services)
    {
        drop(guard);
        return match recovery {
            Ok(job) => Err(job),
            Err(response) => Ok(*response),
        };
    }
    let external = D::requires_external_review(&change.command_id, &services);
    let claim_key = D::review_claim_key(&change.id);
    let claim_snapshot = serde_json::to_string(&json!({ "proposal": id, "decision": body.decision, "actor": session.actor, "command": envelope })).expect("review metadata serializes");
    let terminal_claim = external.then_some(gaugedesk_store::RecordCommandClaim {
        key: &claim_key,
        snapshot: &claim_snapshot,
    });
    if external
        && (change.app != session.app
            || change.scope != session.scope
            || !session.commands.iter().any(|command| {
                command.id == change.command_id
                    && session.capabilities.contains(&command.capability)
            }))
    {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "current capability is required to review this change" })),
        )
            .into_response());
    }
    if change.status != GaugeAppChangeStatus::Proposed {
        let expected_snapshot = if body.decision == "accept" {
            snapshot(&envelope)
        } else {
            serde_json::to_string(&json!({ "proposal": id, "decision": body.decision })).unwrap()
        };
        if let Ok(Some(record)) = guard
            .store_ref()
            .command_for_key(&D::command_scope(&headers), &key)
        {
            if record.status == "applied" && record.snapshot_json == expected_snapshot {
                let status = match change.status {
                    GaugeAppChangeStatus::Applied => "applied",
                    GaugeAppChangeStatus::Rejected => "rejected",
                    GaugeAppChangeStatus::Conflict => "conflict",
                    GaugeAppChangeStatus::Proposed | GaugeAppChangeStatus::Applying => {
                        unreachable!()
                    }
                };
                let code = if change.status == GaugeAppChangeStatus::Conflict {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::OK
                };
                return Ok((
                    code,
                    Json(json!({ "receipt": gaugeapp_receipt(&session, &envelope, status), "proposal": change })),
                )
                    .into_response());
            }
        }
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({ "error": "GaugeApp proposal is already terminal" })),
        )
            .into_response());
    }
    if body.decision == "reject" {
        change.status = GaugeAppChangeStatus::Rejected;
        change.reviewed_by = Some(session.actor.clone());
        let change_fact = match change_fact::<D>(&headers, GAUGEAPP_CHANGE_KIND, &change) {
            Ok(fact) => fact,
            Err(response) => return Ok(*response),
        };
        let audit_link = crate::audit::link(&session.actor, "gaugeapp.proposal.rejected", &id);
        let store_scope = D::record_scope(&headers);
        let audit_scope = crate::audit::scope_for(&store_scope);
        let result = match guard.store_mut().admit_record_facts_with_claims(
            &D::command_scope(&headers),
            &key,
            &serde_json::to_string(&json!({ "proposal": id, "decision": "reject" })).unwrap(),
            &[change_fact],
            Some(crate::audit::chained_in(&audit_scope, &audit_link)),
            terminal_claim.as_slice(),
        ) {
            Ok(result) => result,
            Err(error) => return Ok(D::store_error(error)),
        };
        if let Some(entry) = crate::audit::committed_entry(result.chained_payload.as_deref()) {
            crate::audit::finish_committed_in(&mut guard, &store_scope, &entry);
        }
        return Ok((StatusCode::OK, Json(json!({ "receipt": gaugeapp_receipt(&session, &envelope, "rejected"), "proposal": change }))).into_response());
    }
    if body.decision != "accept" {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "review decision must be accept or reject" })),
        )
            .into_response());
    }
    let local_project_receipt_recovery =
        !external && D::accept_stale_proposal(&guard, &envelope, &change);
    if let Err(error) = decide_reviewed_gaugeapp_command(&session, &envelope) {
        if matches!(error, GaugeAppRejection::StaleBasis) && local_project_receipt_recovery {
            // The exact deterministic Home operation already committed, but
            // the command receipt did not. Resume the same operation below;
            // every other stale proposal still conflicts normally.
        } else if matches!(error, GaugeAppRejection::StaleBasis) {
            change.status = GaugeAppChangeStatus::Conflict;
            change.reviewed_by = Some(session.actor.clone());
            let conflict_fact = match change_fact::<D>(&headers, GAUGEAPP_CHANGE_KIND, &change) {
                Ok(fact) => fact,
                Err(response) => return Ok(*response),
            };
            let audit_link = crate::audit::link(&session.actor, "gaugeapp.proposal.conflict", &id);
            let store_scope = D::record_scope(&headers);
            let audit_scope = crate::audit::scope_for(&store_scope);
            let result = match guard.store_mut().admit_record_facts_with_claims(
                &D::command_scope(&headers),
                &key,
                &snapshot(&envelope),
                &[conflict_fact],
                Some(crate::audit::chained_in(&audit_scope, &audit_link)),
                terminal_claim.as_slice(),
            ) {
                Ok(result) => result,
                Err(error) => return Ok(D::store_error(error)),
            };
            if let Some(entry) = crate::audit::committed_entry(result.chained_payload.as_deref()) {
                crate::audit::finish_committed_in(&mut guard, &store_scope, &entry);
            }
            return Ok((
                StatusCode::CONFLICT,
                Json(json!({
                    "receipt": gaugeapp_receipt(&session, &envelope, "conflict"),
                    "proposal": change,
                    "error": error.message(),
                    "rejection": error,
                })),
            )
                .into_response());
        }
        return Ok(reject_gaugeapp(error));
    }
    if let Err(response) = D::authorize_review(&session, &envelope, &body, &services) {
        return Ok(*response);
    }
    // The review intent gets its own idempotency key, while the applied change
    // retains the original proposal identity.
    if external {
        let plan = match D::plan_command(&guard, &headers, &envelope, &services) {
            Ok(plan) => plan,
            Err(response) => return Ok(*response),
        };
        let prepared = D::begin_external_review(
            &mut guard,
            &headers,
            &session,
            ExternalReview {
                envelope: &envelope,
                key: &key,
                change: &change,
                plan,
            },
            &services,
        );
        drop(guard);
        return match prepared {
            Ok(job) => Err(job),
            Err(response) => Ok(*response),
        };
    }
    let plan = match D::plan_command(&guard, &headers, &envelope, &services) {
        Ok(plan) => plan,
        Err(response) => return Ok(*response),
    };
    let plan = match D::apply_plan(
        &mut guard, &headers, &session, &envelope, &change.id, plan, &services,
    ) {
        Ok(plan) => plan,
        Err(response) => return Ok(*response),
    };
    let (response, freshly_applied) = finish_command_in::<D>(
        &mut guard,
        &headers,
        &session,
        &envelope,
        &key,
        Some(change),
        plan,
        &D::command_scope(&headers),
    );
    drop(guard);
    D::reviewed_committed(wb, &envelope, freshly_applied);
    Ok(response)
}

fn proposed_change(
    session: &GaugeAppSession,
    envelope: &GaugeAppCommandEnvelope,
) -> GaugeAppChangeRecord {
    GaugeAppChangeRecord {
        id: gaugeapp_change_id(session, envelope),
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
        receipt_id: gaugeapp_receipt(session, envelope, "proposed").id,
    }
}

fn snapshot(envelope: &GaugeAppCommandEnvelope) -> String {
    serde_json::to_string(envelope).expect("command serializes")
}

fn change_fact<D: GaugeAppDefinition>(
    headers: &HeaderMap,
    kind: &str,
    value: &GaugeAppChangeRecord,
) -> Result<CommandRecordFact, Box<Response>> {
    Ok(CommandRecordFact {
        scope_id: D::record_scope(headers),
        kind: kind.into(),
        payload: serde_json::to_string(value).map_err(D::projection_error)?,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn finish_command_in<D: GaugeAppDefinition>(
    wb: &mut Workbench,
    headers: &HeaderMap,
    session: &GaugeAppSession,
    envelope: &GaugeAppCommandEnvelope,
    key: &str,
    change: Option<GaugeAppChangeRecord>,
    plan: CommandPlan,
    receipt_scope: &str,
) -> (Response, bool) {
    let mut applied_change = change.unwrap_or_else(|| proposed_change(session, envelope));
    applied_change.status = GaugeAppChangeStatus::Applied;
    applied_change.reviewed_by = Some(session.actor.clone());
    let mut facts = plan.facts.clone();
    let change_fact = match change_fact::<D>(headers, GAUGEAPP_CHANGE_KIND, &applied_change) {
        Ok(fact) => fact,
        Err(response) => return (*response, false),
    };
    facts.push(change_fact);
    let audit_link = crate::audit::link(&session.actor, plan.audit_action, &plan.audit_target);
    let store_scope = D::record_scope(headers);
    let audit_scope = crate::audit::scope_for(&store_scope);
    let result = match wb.store_mut().admit_record_facts_chained(
        receipt_scope,
        key,
        &snapshot(envelope),
        &facts,
        Some(crate::audit::chained_in(&audit_scope, &audit_link)),
    ) {
        Ok(result) => result,
        Err(error) => return (D::store_error(error), false),
    };
    if !result.replayed {
        for (kind, id, op) in &plan.notices {
            wb.notify_library_changed(kind, id, op);
        }
        if let Some(entry) = crate::audit::committed_entry(result.chained_payload.as_deref()) {
            crate::audit::finish_committed_in(wb, &store_scope, &entry);
        }
    }
    if let Err(response) = D::after_command(wb, headers, session, envelope) {
        return (*response, false);
    }
    let freshly_applied = !result.replayed;
    ((StatusCode::OK, Json(json!({
        "receipt": gaugeapp_receipt(session, envelope, "applied"),
        "proposal": applied_change,
        "result": if result.replayed { Value::Null } else { plan.transient_result.unwrap_or(Value::Null) },
    }))).into_response(), freshly_applied)
}

fn agent_error(reason: GaugeAppAgentError) -> Response {
    let status = match reason {
        GaugeAppAgentError::Busy => StatusCode::CONFLICT,
        GaugeAppAgentError::NoModelAccess => StatusCode::PRECONDITION_FAILED,
        GaugeAppAgentError::Interrupted => StatusCode::CONFLICT,
        GaugeAppAgentError::ProviderFunding(_) => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_GATEWAY,
    };
    error(status, reason.to_string())
}

/// The command an agent proposal names, under the current session.
fn agent_envelope<D: GaugeAppDefinition>(
    session: &GaugeAppSession,
    proposal: &GaugeAppAgentProposal,
    idempotency_key: &str,
) -> GaugeAppCommandEnvelope {
    GaugeAppCommandEnvelope {
        session_id: session.id.clone(),
        generation: session.generation.clone(),
        app: D::APP,
        scope: session.scope.clone(),
        page_id: proposal.page_id.clone(),
        command_id: proposal.command_id.clone(),
        expected_basis: proposal.expected_basis.clone(),
        idempotency_key: idempotency_key.into(),
        payload: proposal.payload.clone(),
        client: GaugeAppClient::Agent,
    }
}

async fn message<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    DefinitionServices(services): DefinitionServices<D>,
    path: Option<Path<String>>,
    headers: HeaderMap,
    Json(body): Json<MessageBody>,
) -> Response {
    let id = path.map(|Path(id)| id).unwrap_or_default();
    if let Err(response) = D::message_idempotency(&headers, &body.idempotency_key) {
        return *response;
    }
    let (opened, claim, live) = {
        let mut guard = wb.lock_unpoisoned();
        let opened = match D::context(&guard, &headers, &id, &services) {
            Ok(value) => value,
            Err(response) => return *response,
        };
        let identity = Identity {
            session_id: body.session_id.clone(),
            generation: body.generation.clone(),
            scope: body.scope.clone(),
        };
        if !identity.names(&opened.session) {
            return D::agent_stale();
        }
        if let Err(reason) = D::prepare_transcript(&mut guard, &opened.session) {
            return D::agent_error(reason);
        }
        match replayed_gaugeapp_agent_turn(
            guard.store_ref(),
            &opened.session,
            &body.idempotency_key,
            &body.message,
        ) {
            Ok(Some(turn)) => {
                if !D::RESUMABLE_CONVERSATION {
                    return (StatusCode::OK, Json(json!({ "turn": turn }))).into_response();
                }
                let transcript = match gaugeapp_agent_transcript(guard.store_ref(), &opened.session)
                {
                    Ok(transcript) => transcript,
                    Err(reason) => {
                        return D::agent_error(GaugeAppAgentError::Store(format!("{reason:?}")))
                    }
                };
                let thread = match agent_transcript_payload(&opened.session, transcript, None) {
                    Ok(thread) => thread,
                    Err(response) => return *response,
                };
                return (
                    StatusCode::OK,
                    Json(json!({ "turn": turn, "thread": thread })),
                )
                    .into_response();
            }
            Ok(None) => {}
            Err(reason) => return D::agent_error(reason),
        }
        let Some(claim) = claim_gaugeapp_agent_turn(&gaugeapp_thread_id(&opened.session)) else {
            return D::agent_error(GaugeAppAgentError::Busy);
        };
        let live = if D::LIVE_EVENTS {
            match begin_gaugeapp_agent_live_turn(&opened.session, &body.idempotency_key) {
                Ok(live) => Some(live),
                Err(reason) => return D::agent_error(reason),
            }
        } else {
            None
        };
        (opened, claim, live)
    };
    let opening = opened.session.clone();
    let thread = gaugeapp_thread_id(&opening);
    let runtime_wb = wb.clone();
    let (turn_wb, turn_headers, turn_id, turn_opening) =
        (wb.clone(), headers.clone(), id.clone(), opening.clone());
    let turn_services = services.clone();
    let runtime_thread = thread.clone();
    let runtime_live = live.clone();
    let user = body.message.clone();
    let direct_key = D::direct_key(&opening, &body.idempotency_key);
    let result = tokio::task::spawn_blocking(move || {
        let mut direct = |proposal: &GaugeAppAgentProposal, key: &str| {
            D::invoke_agent(
                &turn_wb,
                &turn_headers,
                &turn_id,
                &turn_opening,
                proposal,
                key,
                &turn_services,
            )
        };
        let result = run_gaugeapp_agent_turn_with_direct_actions(
            &runtime_wb,
            opened,
            &user,
            || {
                let guard = turn_wb.lock_unpoisoned();
                D::context(&guard, &turn_headers, &turn_id, &turn_services).map_err(|_| {
                    GaugeAppAgentError::Rejected(GaugeAppAgentRejection::SessionRevoked)
                })
            },
            || gaugeapp_agent_turn_was_stopped(&runtime_thread),
            |event| {
                if let Some(live) = &runtime_live {
                    live.publish(event)
                } else {
                    Ok(())
                }
            },
            |current, proposal| {
                let guard = turn_wb.lock_unpoisoned();
                let envelope = agent_envelope::<D>(&current.session, proposal, "agent:validation");
                D::validate_agent(&guard, &turn_headers, current, &envelope, &turn_services)
            },
            Some(&mut direct),
            &direct_key,
        );
        // Retained live turns keep their claim through durable exchange append.
        // The existing immediate settings turn releases it when runtime ends.
        let claim = if D::LIVE_EVENTS {
            Some(claim)
        } else {
            drop(claim);
            None
        };
        (claim, result)
    })
    .await;
    let (_claim, turn) = match result {
        Ok((claim, Ok(turn))) => (claim, turn),
        Ok((_claim, Err(reason))) => {
            publish_terminal(&live, &reason);
            return D::agent_error(reason);
        }
        Err(_) => {
            if let Some(live) = &live {
                let _ = live.publish(GaugeAppAgentLiveEvent::Failed);
            }
            return if D::LIVE_EVENTS {
                D::agent_error(GaugeAppAgentError::Provider("agent task failed".into()))
            } else {
                error(StatusCode::BAD_GATEWAY, "management conversation failed")
            };
        }
    };
    let transcript = append_gaugeapp_agent_exchange_prepared_current(
        &wb,
        &opening,
        &body.idempotency_key,
        &body.message,
        &turn,
        &|guard| {
            if D::LIVE_EVENTS && gaugeapp_agent_turn_was_stopped(&thread) {
                return Err(GaugeAppAgentError::Interrupted);
            }
            still_current::<D>(guard, &headers, &id, &opening, &services).map(|_| ())
        },
        &|guard, envelope| D::prepare_agent_proposal(guard, &headers, envelope, &services),
    );
    match transcript {
        Ok(messages) => {
            if let Some(live) = &live {
                let _ = live.publish(GaugeAppAgentLiveEvent::Settled);
            }
            let thread = if D::RESUMABLE_CONVERSATION {
                match agent_transcript_payload(&opening, messages, None) {
                    Ok(thread) => thread,
                    Err(response) => return *response,
                }
            } else {
                json!({ "id": gaugeapp_thread_id(&opening), "messages": messages })
            };
            (
                StatusCode::OK,
                Json(json!({ "turn": turn, "thread": thread })),
            )
                .into_response()
        }
        Err(reason) => {
            publish_terminal(&live, &reason);
            D::agent_error(reason)
        }
    }
}

fn publish_terminal(live: &Option<GaugeAppAgentLiveTurn>, reason: &GaugeAppAgentError) {
    if let Some(live) = live {
        let event = if matches!(reason, GaugeAppAgentError::Interrupted) {
            GaugeAppAgentLiveEvent::Stopped
        } else {
            GaugeAppAgentLiveEvent::Failed
        };
        let _ = live.publish(event);
    }
}

/// Every page a definition serves, for the settings assistant: its model must
/// carry a `guide` — what the page is, its controls by the labels the person
/// sees, and for each command it declares what the command does, which control
/// it stands for and an example payload `validate` admits. Command ids and raw
/// JSON alone left the assistant guessing what a person meant: asked to "turn
/// on collect results", it chose an ability. Each definition's tests call this.
#[cfg(test)]
pub(crate) fn assert_pages_are_guided<D: GaugeAppDefinition>(pages: &[Page]) {
    use crate::gaugeapp_contract::{GaugeAppClient, GaugeAppScope};
    assert!(!pages.is_empty(), "{}: no pages to check", D::LABEL);
    for page in pages {
        let guide = &page.model["guide"];
        let at = format!("{} page {}", D::LABEL, page.id);
        assert!(
            guide["page"].as_str().is_some_and(|text| !text.is_empty()),
            "{at}: guide.page"
        );
        assert!(guide["controls"].is_object(), "{at}: guide.controls");
        let commands = guide["commands"]
            .as_object()
            .unwrap_or_else(|| panic!("{at}: guide.commands"));
        let declared: std::collections::BTreeSet<&str> = page.commands.iter().copied().collect();
        let described: std::collections::BTreeSet<&str> =
            commands.keys().map(String::as_str).collect();
        assert_eq!(
            declared, described,
            "{at}: every declared command, and only those, is described"
        );
        for (command, entry) in commands {
            for field in ["does", "control"] {
                assert!(
                    entry[field].as_str().is_some_and(|text| !text.is_empty()),
                    "{at}: {command}.{field}"
                );
            }
            let envelope = GaugeAppCommandEnvelope {
                session_id: String::new(),
                generation: String::new(),
                app: D::APP,
                scope: GaugeAppScope {
                    kind: D::SCOPE.into(),
                    id: String::new(),
                },
                page_id: page.id.into(),
                command_id: command.clone(),
                expected_basis: String::new(),
                idempotency_key: String::new(),
                payload: entry["payload"].clone(),
                client: GaugeAppClient::Agent,
            };
            assert!(
                D::validate(&envelope).is_ok(),
                "{at}: {command}'s example payload is refused"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gaugeapp_agent::gaugeapp_agent_action_kind;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn call(app: &Router, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header("idempotency-key", format!("{method}:{path}"))
            .body(if method == "GET" {
                Body::empty()
            } else {
                Body::from(body.to_string())
            })
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Both apps answer on their own paths with the same wire shape, and a
    /// session for one is refused by the other's routes.
    #[tokio::test]
    async fn every_definition_is_served_at_its_own_path() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let placement = "inst-panel-host".to_owned();
        let (project, agent) = {
            let mut wb = shared.lock_unpoisoned();
            wb.seed_panel_placement(&placement, crate::library::PanelPublicProfile::default())
                .unwrap();
            let project = crate::library_routes::create_named_project(&mut wb, "proj-host", "Host")
                .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned();
            let agent =
                match wb.create_archetype("Helper".into(), crate::library::AgentKind::Work, None) {
                    Ok(created) => created.id,
                    Err(_) => panic!("the Agent is created"),
                };
            (project, agent)
        };
        let app = routes().with_state(shared);
        let mut sessions = Vec::new();
        for (base, app_id, kind, id) in [
            ("/projects", "project-settings", "project", &project),
            ("/archetypes", "agent-settings", "agent", &agent),
            ("/placements", "panel-settings", "placement", &placement),
        ] {
            let (status, opened) = call(
                &app,
                "POST",
                &format!("{base}/{id}/settings/sessions"),
                json!({}),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{opened}");
            let session = opened["session"].clone();
            assert_eq!(session["app"], app_id);
            assert_eq!(session["scope"], json!({ "kind": kind, "id": id }));
            assert!(opened["pages"]
                .as_array()
                .is_some_and(|pages| !pages.is_empty()));
            let query = format!(
                "session={}&generation={}&scope={id}",
                session["id"].as_str().unwrap(),
                session["generation"].as_str().unwrap(),
            );
            let (status, thread) = call(
                &app,
                "GET",
                &format!("{base}/{id}/settings/agent/messages?{query}"),
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{thread}");
            assert_eq!(thread["thread"]["messages"], json!([]));
            // Tenant live/review routes must not become APIs on settings apps.
            for (method, suffix) in [
                ("GET", "agent/events"),
                ("GET", "pages/organization"),
                ("GET", "updates"),
                ("GET", "proposals"),
                ("POST", "proposals"),
                ("POST", "proposals/unused/review"),
            ] {
                let (status, _) = call(
                    &app,
                    method,
                    &format!("{base}/{id}/settings/{suffix}"),
                    Value::Null,
                )
                .await;
                assert_eq!(
                    status,
                    StatusCode::NOT_FOUND,
                    "{app_id} unexpectedly serves {method} {suffix}"
                );
            }
            sessions.push((base, id, session));
        }
        // A project session names nothing an Agent route admits.
        let (project_base, _, project_session) = &sessions[0];
        let (agent_base, agent_id, _) = &sessions[1];
        assert_eq!(*project_base, "/projects");
        let (status, _) = call(
            &app,
            "POST",
            &format!("{agent_base}/{agent_id}/settings/agent/stop"),
            json!({
                "session_id": project_session["id"],
                "generation": project_session["generation"],
                "scope": project_session["scope"],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    fn commands<D: GaugeAppDefinition>() -> (GaugeAppKind, &'static [&'static str]) {
        (D::APP, D::COMMANDS)
    }

    /// The accepted action inventory for the apps this host serves: every
    /// command a definition declares has an agent path (DR-0205), so a person
    /// action added without one fails here.
    #[test]
    fn every_hosted_command_has_an_agent_path() {
        for (app, declared) in [
            commands::<crate::project_settings_gaugeapp::ProjectSettings>(),
            commands::<crate::agent_settings_gaugeapp::AgentSettings>(),
            commands::<crate::panel_settings_gaugeapp::PanelSettings>(),
        ] {
            for id in declared {
                let grant = GaugeAppCommandGrant {
                    id: (*id).into(),
                    capability: "classified".into(),
                    review: ReviewPolicy::Immediate,
                };
                assert!(
                    gaugeapp_agent_action_kind(&grant).is_some(),
                    "{} command {id} has no agent path",
                    app.as_str()
                );
            }
        }
    }
}
