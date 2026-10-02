//! The one management host every GaugeApp a Home serves runs on.
//!
//! A GaugeApp here is a [`GaugeAppDefinition`]: what it manages, who may
//! manage it, the pages it shows and how a command changes them. Everything
//! else is this module and is the same for every app — the admitted session
//! and its grants, the bounded management conversation (messages, stop and
//! erase), and the command route with its idempotent receipt and audit link.
//! Adding an app is writing a definition and adding one line to [`routes`].
//!
//! Every request rebuilds the session from the definition, so a revoked
//! person or a changed scope is refused on the next read, tool or command.
//! The agent and the person reach a command through the same
//! [`apply_command`], with the same basis, receipt and audit.
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use gaugedesk_store::CommandRecordFact;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    gaugeapp_agent::{
        append_gaugeapp_agent_exchange_prepared_current, claim_gaugeapp_agent_turn,
        erase_gaugeapp_agent_transcript_current, gaugeapp_agent_page_actions,
        gaugeapp_agent_page_commands, gaugeapp_agent_thread_owner_scope, gaugeapp_agent_transcript,
        gaugeapp_agent_turn_was_stopped, gaugeapp_thread_id, replayed_gaugeapp_agent_turn,
        request_gaugeapp_agent_stop, run_gaugeapp_agent_turn_with_direct_actions,
        GaugeAppAgentContext, GaugeAppAgentError, GaugeAppAgentPage, GaugeAppAgentProposal,
        GaugeAppAgentRejection,
    },
    gaugeapp_contract::{
        decide_gaugeapp_command, fold_gaugeapp_changes, gaugeapp_change_id, gaugeapp_receipt,
        gaugeapp_session_id, GaugeAppChangeRecord, GaugeAppChangeStatus, GaugeAppClient,
        GaugeAppCommandEnvelope, GaugeAppCommandGrant, GaugeAppKind, GaugeAppPageAvailability,
        GaugeAppPageGrant, GaugeAppRejection, GaugeAppScope, GaugeAppSession, ReviewPolicy,
        GAUGEAPP_CHANGE_KIND,
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
    /// Every command it accepts, in the order a session grants them. Each needs
    /// an agent path in [`crate::gaugeapp_agent::gaugeapp_agent_action_kind`].
    const COMMANDS: &'static [&'static str];

    /// Admit the person and the exact scope, refusing anyone who may not read
    /// it, and say whether they may also change it.
    fn admit(wb: &Workbench, headers: &HeaderMap, id: &str) -> Result<Admission, Box<Response>>;

    /// The pages a session shows, each with the commands it declares. A person
    /// who may not manage the scope sees the same pages with no commands.
    fn pages(wb: &Workbench, id: &str) -> Vec<Page>;

    /// Check a command's payload without changing anything, so the agent's
    /// tool can refuse it within the turn.
    fn validate(envelope: &GaugeAppCommandEnvelope) -> Result<(), Box<Response>>;

    /// Apply an admitted command through the scope's own state methods, on
    /// behalf of `actor`, the person the session admitted.
    fn apply(
        wb: &mut Workbench,
        actor: &str,
        id: &str,
        envelope: &GaugeAppCommandEnvelope,
    ) -> Result<Applied, Box<Response>>;
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

/// What applying a command leaves for the host to make durable.
pub struct Applied {
    /// Records admitted in the same transaction as the command's receipt.
    pub facts: Vec<CommandRecordFact>,
    /// Run once those records are durable, and never for a replay.
    pub committed: Box<dyn FnOnce(&mut Workbench)>,
}

impl Applied {
    /// A command whose state method has already made its change durable.
    pub fn done() -> Self {
        Self {
            facts: Vec::new(),
            committed: Box::new(|_| {}),
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

fn mount<D: GaugeAppDefinition>() -> Router<SharedWorkbench> {
    let at = |suffix: &str| format!("{}{suffix}", D::PATH);
    Router::new()
        .route(&at("/sessions"), post(open_session::<D>))
        .route(
            &at("/agent/messages"),
            get(messages::<D>).post(message::<D>),
        )
        .route(&at("/agent/stop"), post(stop::<D>))
        .route(&at("/agent/erase"), post(erase::<D>))
        .route(&at("/commands"), post(command::<D>))
}

/// Rebuild the admitted session and its pages from the definition.
pub fn context<D: GaugeAppDefinition>(
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
) -> Result<GaugeAppAgentContext, GaugeAppAgentError> {
    let current = context::<D>(wb, headers, id)
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
struct Identity {
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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EraseBody {
    session_id: String,
    generation: String,
    scope: GaugeAppScope,
    idempotency_key: String,
}

async fn open_session<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let guard = wb.lock_unpoisoned();
    match context::<D>(&guard, &headers, &id) {
        Ok(context) => (
            StatusCode::OK,
            Json(json!({ "session": context.session, "pages": context.pages })),
        )
            .into_response(),
        Err(response) => *response,
    }
}

async fn messages<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<MessagesQuery>,
) -> Response {
    let guard = wb.lock_unpoisoned();
    let context = match context::<D>(&guard, &headers, &id) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if context.session.id != query.session
        || context.session.generation != query.generation
        || context.session.scope.id != query.scope
    {
        return stale::<D>();
    }
    match gaugeapp_agent_transcript(guard.store_ref(), &context.session) {
        Ok(messages) => (
            StatusCode::OK,
            Json(json!({ "thread": {
                "id": gaugeapp_thread_id(&context.session),
                "messages": messages,
            } })),
        )
            .into_response(),
        Err(reason) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("management conversation unavailable: {reason:?}"),
        ),
    }
}

async fn stop<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Identity>,
) -> Response {
    let guard = wb.lock_unpoisoned();
    let context = match context::<D>(&guard, &headers, &id) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if !body.names(&context.session) {
        return stale::<D>();
    }
    let stopped = request_gaugeapp_agent_stop(&gaugeapp_thread_id(&context.session));
    (StatusCode::OK, Json(json!({ "stopped": stopped }))).into_response()
}

async fn erase<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<EraseBody>,
) -> Response {
    let opening = {
        let guard = wb.lock_unpoisoned();
        let context = match context::<D>(&guard, &headers, &id) {
            Ok(value) => value,
            Err(response) => return *response,
        };
        let identity = Identity {
            session_id: body.session_id,
            generation: body.generation,
            scope: body.scope,
        };
        if !identity.names(&context.session) {
            return stale::<D>();
        }
        context.session
    };
    let erased =
        erase_gaugeapp_agent_transcript_current(&wb, &opening, &body.idempotency_key, &|guard| {
            still_current::<D>(guard, &headers, &id, &opening).map(|_| ())
        });
    match erased {
        Ok(erasure) => (StatusCode::OK, Json(json!({ "erasure": erasure }))).into_response(),
        Err(reason) => agent_error(reason),
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
    let context = context::<D>(wb, headers, id)?;
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
        committed(wb);
        if let Some(entry) = crate::audit::committed_entry(result.chained_payload.as_deref()) {
            crate::audit::finish_committed_in(wb, &tenant_scope, &entry);
        }
    }
    Ok(response(receipt))
}

async fn command<D: GaugeAppDefinition>(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(envelope): Json<GaugeAppCommandEnvelope>,
) -> Response {
    let mut guard = wb.lock_unpoisoned();
    match apply_command::<D>(&mut guard, &headers, &id, &envelope) {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(response) => *response,
    }
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
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<MessageBody>,
) -> Response {
    if body.idempotency_key.trim().is_empty() {
        return error(StatusCode::BAD_REQUEST, "idempotency key required");
    }
    let (opened, claim) = {
        let guard = wb.lock_unpoisoned();
        let opened = match context::<D>(&guard, &headers, &id) {
            Ok(value) => value,
            Err(response) => return *response,
        };
        let identity = Identity {
            session_id: body.session_id.clone(),
            generation: body.generation.clone(),
            scope: body.scope.clone(),
        };
        if !identity.names(&opened.session) {
            return stale::<D>();
        }
        match replayed_gaugeapp_agent_turn(
            guard.store_ref(),
            &opened.session,
            &body.idempotency_key,
            &body.message,
        ) {
            Ok(Some(turn)) => {
                return (StatusCode::OK, Json(json!({ "turn": turn }))).into_response()
            }
            Ok(None) => {}
            Err(reason) => return agent_error(reason),
        }
        let Some(claim) = claim_gaugeapp_agent_turn(&gaugeapp_thread_id(&opened.session)) else {
            return agent_error(GaugeAppAgentError::Busy);
        };
        (opened, claim)
    };
    let opening = opened.session.clone();
    let thread = gaugeapp_thread_id(&opening);
    let runtime_wb = wb.clone();
    let (turn_wb, turn_headers, turn_id, turn_opening) =
        (wb.clone(), headers.clone(), id.clone(), opening.clone());
    let user = body.message.clone();
    let direct_key = format!("agent:{}", body.idempotency_key);
    let result = tokio::task::spawn_blocking(move || {
        let _claim = claim;
        let mut direct = |proposal: &GaugeAppAgentProposal,
                          idempotency_key: &str|
         -> Result<Value, GaugeAppAgentError> {
            let mut guard = turn_wb.lock_unpoisoned();
            let current = still_current::<D>(&guard, &turn_headers, &turn_id, &turn_opening)?;
            let envelope = agent_envelope::<D>(&current.session, proposal, idempotency_key);
            apply_command::<D>(&mut guard, &turn_headers, &turn_id, &envelope).map_err(|_| {
                GaugeAppAgentError::InvalidOutput(
                    "The setting changed or its values were refused; read the current page and try again."
                        .into(),
                )
            })
        };
        run_gaugeapp_agent_turn_with_direct_actions(
            &runtime_wb,
            opened,
            &user,
            || {
                let guard = turn_wb.lock_unpoisoned();
                context::<D>(&guard, &turn_headers, &turn_id).map_err(|_| {
                    GaugeAppAgentError::Rejected(GaugeAppAgentRejection::SessionRevoked)
                })
            },
            || gaugeapp_agent_turn_was_stopped(&thread),
            |_| Ok(()),
            |current, proposal| {
                let envelope = agent_envelope::<D>(&current.session, proposal, "agent:validation");
                decide_gaugeapp_command(&current.session, &envelope)
                    .map_err(|reason| GaugeAppAgentError::InvalidOutput(reason.message().into()))?;
                D::validate(&envelope).map_err(|_| {
                    GaugeAppAgentError::InvalidOutput(format!("Invalid {} values", D::LABEL))
                })
            },
            Some(&mut direct),
            &direct_key,
        )
    })
    .await;
    let turn = match result {
        Ok(Ok(turn)) => turn,
        Ok(Err(reason)) => return agent_error(reason),
        Err(_) => return error(StatusCode::BAD_GATEWAY, "management conversation failed"),
    };
    let transcript = append_gaugeapp_agent_exchange_prepared_current(
        &wb,
        &opening,
        &body.idempotency_key,
        &body.message,
        &turn,
        &|guard| still_current::<D>(guard, &headers, &id, &opening).map(|_| ()),
        &|_, _| {
            Err(GaugeAppAgentError::InvalidOutput(
                "Changes here apply directly; no proposal is available.".into(),
            ))
        },
    );
    match transcript {
        Ok(messages) => (
            StatusCode::OK,
            Json(json!({ "turn": turn, "thread": {
                "id": gaugeapp_thread_id(&opening),
                "messages": messages,
            } })),
        )
            .into_response(),
        Err(reason) => agent_error(reason),
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
