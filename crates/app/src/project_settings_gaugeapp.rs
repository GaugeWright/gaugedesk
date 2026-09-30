//! The project-owned management conversation. Every request is re-admitted at
//! the serving Home and is scoped to one project, person, and GaugeApp.
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use gaugedesk_core::abac::Role;
use gaugedesk_store::CommandRecordFact;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    account::project_scope,
    client_admission::ClientBuild,
    gaugeapp_agent::{
        append_gaugeapp_agent_exchange_prepared_current, claim_gaugeapp_agent_turn,
        erase_gaugeapp_agent_transcript_current, gaugeapp_agent_page_actions,
        gaugeapp_agent_page_commands, gaugeapp_agent_transcript, gaugeapp_agent_turn_was_stopped,
        gaugeapp_thread_id, replayed_gaugeapp_agent_turn, request_gaugeapp_agent_stop,
        run_gaugeapp_agent_turn_with_direct_actions, GaugeAppAgentContext, GaugeAppAgentError,
        GaugeAppAgentPage, GaugeAppAgentRejection,
    },
    gaugeapp_contract::{
        decide_gaugeapp_command, fold_gaugeapp_changes, gaugeapp_change_id, gaugeapp_receipt,
        gaugeapp_session_id, GaugeAppChangeRecord, GaugeAppChangeStatus, GaugeAppClient,
        GaugeAppCommandEnvelope, GaugeAppCommandGrant, GaugeAppKind, GaugeAppPageAvailability,
        GaugeAppPageGrant, GaugeAppScope, GaugeAppSession, ReviewPolicy, GAUGEAPP_CHANGE_KIND,
    },
    library::{WorkTargetOwner, LIBRARY_SCOPE},
    net_http,
    workbench_auth::req_scope,
    LockUnpoisoned, SharedWorkbench, Workbench,
};

const APP: GaugeAppKind = GaugeAppKind::ProjectSettings;
const PAGE: &str = "overview";
const CAPABILITY: &str = "project.manage";

fn can_manage_project(role: Option<Role>, provisioned: bool) -> bool {
    !provisioned
        || matches!(role, Some(role)
        if role == Role::owner() || role == Role::admin() || role == Role::member())
}

pub fn routes() -> Router<SharedWorkbench> {
    Router::new()
        .route("/projects/{id}/settings/sessions", post(open_session))
        .route(
            "/projects/{id}/settings/agent/messages",
            get(messages).post(message),
        )
        .route("/projects/{id}/settings/agent/stop", post(stop))
        .route("/projects/{id}/settings/agent/erase", post(erase))
        .route("/projects/{id}/settings/commands", post(command))
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}
fn boxed_error(status: StatusCode, message: impl Into<String>) -> Box<Response> {
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
fn build(
    wb: &Workbench,
    headers: &HeaderMap,
    id: &str,
) -> Result<GaugeAppAgentContext, Box<Response>> {
    let actor = wb
        .admit_data_request_with_client(
            net_http::bearer(headers),
            Some(id),
            &req_scope(headers),
            ClientBuild::from_headers(headers),
            true,
        )
        .map_err(|(status, reason)| boxed_error(status, reason))?;
    if !wb
        .project_visibility_in(net_http::bearer(headers), &req_scope(headers))
        .allows(id)
    {
        return Err(boxed_error(
            StatusCode::FORBIDDEN,
            "project access required",
        ));
    }
    let project = wb
        .library
        .projects
        .get(id)
        .filter(|record| record.op == crate::library::RecordOp::Upsert)
        .ok_or_else(|| boxed_error(StatusCode::NOT_FOUND, "project is unavailable"))?;
    if &project.home_id != wb.home_id() {
        return Err(boxed_error(
            StatusCode::CONFLICT,
            "use the project's authoritative Home",
        ));
    }
    let overview = json!({
        "id": project.id, "name": project.name,
        "network_isolated": project.network_isolated,
        "is_personal": project.is_default,
        "run_purpose": project.run_purpose,
        "home_id": project.home_id,
    });
    let people = json!({
        "project": id,
        "participants": crate::federation::participants_of(wb.store_ref(), id),
    });
    let work_data = json!({
        "project": id,
        "network_isolated": project.network_isolated,
        "run_purpose": project.run_purpose,
        "targets": wb.library.work_targets.values()
            .filter(|target| matches!(&target.owner, WorkTargetOwner::Project { project_id } if project_id == id))
            .map(|target| json!({ "id": target.id, "name": target.name, "kind": target.kind, "status": target.status }))
            .collect::<Vec<_>>(),
    });
    let agents = json!({
        "project": id,
        "placements": wb.library.instances.values()
            .filter(|placement| placement.project_id.as_deref() == Some(id))
            .map(|placement| json!({
                "id": placement.id, "agent_id": placement.agent_id,
                "agent_name": wb.library.agents.get(&placement.agent_id).map(|agent| agent.name.as_str()),
                "kind": placement.placement_kind, "version": placement.version,
                "admission": placement.admission,
            }))
            .collect::<Vec<_>>(),
    });
    let model_access = match crate::project_model_selection::current_selection(wb, id) {
        Ok(selection) => json!({ "project": id, "organization_selection": selection }),
        Err(_) => json!({ "project": id, "unavailable": "Model selection could not be read" }),
    };
    let scope = GaugeAppScope {
        kind: "project".into(),
        id: id.into(),
    };
    let directory =
        crate::org::Org::rebuild_in(wb.store_ref(), &req_scope(headers)).map_err(|_| {
            boxed_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "project membership is unavailable",
            )
        })?;
    let provisioned = directory
        .members
        .values()
        .any(|member| member.status == crate::org::MembershipStatus::Active);
    let can_manage = can_manage_project(directory.role_of(&actor), provisioned);
    // The session remains stable through ordinary edits. Role or membership
    // changes alter this epoch, and every request also re-admits project access.
    let generation = digest(&json!({ "actor": actor, "scope": scope, "can_manage": can_manage }));
    let models = [
        (
            PAGE,
            overview,
            if can_manage {
                vec!["project.name.set", "project.network-isolation.set"]
            } else {
                vec![]
            },
        ),
        ("people", people, vec![]),
        (
            "work-data",
            work_data,
            if can_manage {
                vec!["project.network-isolation.set", "project.target.name.set"]
            } else {
                vec![]
            },
        ),
        ("agents", agents, vec![]),
        ("model-access", model_access, vec![]),
    ];
    let grants = models
        .iter()
        .map(|(id, model, commands)| GaugeAppPageGrant {
            id: (*id).into(),
            read_model: format!("project.settings.{id}"),
            version: 1,
            resource_basis: digest(model),
            freshness: "live".into(),
            availability: GaugeAppPageAvailability::Available,
            commands: commands.iter().map(|id| (*id).into()).collect(),
        })
        .collect::<Vec<_>>();
    let session = GaugeAppSession {
        id: gaugeapp_session_id(&actor, APP, &scope, &generation),
        generation,
        app: APP,
        scope,
        actor,
        capabilities: if can_manage {
            vec![CAPABILITY.into()]
        } else {
            vec![]
        },
        pages: grants.clone(),
        commands: (if can_manage {
            vec![
                "project.name.set",
                "project.network-isolation.set",
                "project.target.name.set",
            ]
        } else {
            vec![]
        })
        .iter()
        .map(|id| GaugeAppCommandGrant {
            id: (*id).into(),
            capability: CAPABILITY.into(),
            review: ReviewPolicy::Immediate,
        })
        .collect(),
        update_cursor: digest(&json!(grants)),
    };
    let agent_pages = models
        .into_iter()
        .zip(grants)
        .map(|((_, model, _), page)| GaugeAppAgentPage {
            id: page.id.clone(),
            read_model: page.read_model.clone(),
            version: page.version,
            resource_basis: page.resource_basis.clone(),
            model,
            commands: gaugeapp_agent_page_commands(&session, &page),
            actions: gaugeapp_agent_page_actions(&session, &page),
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
fn checked_session(session: &GaugeAppSession, body: &Identity) -> Result<(), Box<Response>> {
    if session.id == body.session_id
        && session.generation == body.generation
        && session.scope == body.scope
    {
        Ok(())
    } else {
        Err(boxed_error(
            StatusCode::UNAUTHORIZED,
            "project settings session is stale or cross-scope",
        ))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    session_id: String,
    generation: String,
    scope: GaugeAppScope,
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
impl MessageBody {
    fn identity(&self) -> Identity {
        Identity {
            session_id: self.session_id.clone(),
            generation: self.generation.clone(),
            scope: self.scope.clone(),
        }
    }
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

async fn open_session(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let guard = wb.lock_unpoisoned();
    match build(&guard, &headers, &id) {
        Ok(context) => (
            StatusCode::OK,
            Json(json!({ "session": context.session, "pages": context.pages })),
        )
            .into_response(),
        Err(response) => *response,
    }
}
async fn messages(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<MessagesQuery>,
) -> Response {
    let guard = wb.lock_unpoisoned();
    let context = match build(&guard, &headers, &id) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if context.session.id != query.session
        || context.session.generation != query.generation
        || context.session.scope.id != query.scope
    {
        return error(
            StatusCode::UNAUTHORIZED,
            "project settings session is stale or cross-scope",
        );
    }
    match gaugeapp_agent_transcript(guard.store_ref(), &context.session) {
        Ok(messages) => (StatusCode::OK, Json(json!({ "thread": { "id": gaugeapp_thread_id(&context.session), "messages": messages } }))).into_response(),
        Err(reason) => error(StatusCode::INTERNAL_SERVER_ERROR, format!("management conversation unavailable: {reason:?}")),
    }
}
async fn stop(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Identity>,
) -> Response {
    let guard = wb.lock_unpoisoned();
    let context = match build(&guard, &headers, &id) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if let Err(response) = checked_session(&context.session, &body) {
        return *response;
    }
    (StatusCode::OK, Json(json!({ "stopped": request_gaugeapp_agent_stop(&gaugeapp_thread_id(&context.session)) }))).into_response()
}
async fn erase(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<EraseBody>,
) -> Response {
    let opening = {
        let guard = wb.lock_unpoisoned();
        let context = match build(&guard, &headers, &id) {
            Ok(value) => value,
            Err(response) => return *response,
        };
        if let Err(response) = checked_session(
            &context.session,
            &Identity {
                session_id: body.session_id,
                generation: body.generation,
                scope: body.scope,
            },
        ) {
            return *response;
        }
        context.session
    };
    match erase_gaugeapp_agent_transcript_current(&wb, &opening, &body.idempotency_key, &|guard| {
        let current = build(guard, &headers, &id)
            .map_err(|_| GaugeAppAgentError::Rejected(GaugeAppAgentRejection::SessionRevoked))?;
        if !same(&opening, &current.session) {
            return Err(GaugeAppAgentError::Rejected(
                GaugeAppAgentRejection::SessionMismatch,
            ));
        }
        Ok(())
    }) {
        Ok(erasure) => (StatusCode::OK, Json(json!({ "erasure": erasure }))).into_response(),
        Err(reason) => agent_error(reason),
    }
}
/// What a project settings command changes.
enum SettingsChange {
    Project {
        name: Option<String>,
        isolated: Option<bool>,
    },
    /// A target's name, recorded on collaboration Main (DR-0248).
    TargetName { target_id: String, name: String },
}

fn payload(envelope: &GaugeAppCommandEnvelope) -> Result<SettingsChange, Box<Response>> {
    let object = envelope.payload.as_object().ok_or_else(|| {
        boxed_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "settings command requires an object",
        )
    })?;
    match envelope.command_id.as_str() {
        "project.name.set" if object.len() == 1 => {
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("");
            if name.is_empty() || name.len() > 120 || name.chars().any(char::is_control) {
                return Err(boxed_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "name must be 1–120 printable characters",
                ));
            }
            Ok(SettingsChange::Project {
                name: Some(name.into()),
                isolated: None,
            })
        }
        "project.target.name.set" if object.len() == 2 => {
            let text = |key: &str| object.get(key).and_then(Value::as_str).unwrap_or("");
            let target_id = text("target_id");
            if target_id.is_empty() {
                return Err(boxed_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "target_id is required",
                ));
            }
            // The folder rules and project-wide uniqueness are the target
            // name's own (DR-0248), checked when the rename is applied.
            Ok(SettingsChange::TargetName {
                target_id: target_id.into(),
                name: text("name").into(),
            })
        }
        "project.network-isolation.set" if object.len() == 1 => object
            .get("isolated")
            .and_then(Value::as_bool)
            .map(|isolated| SettingsChange::Project {
                name: None,
                isolated: Some(isolated),
            })
            .ok_or_else(|| {
                boxed_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "isolated must be true or false",
                )
            }),
        _ => Err(boxed_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unknown or invalid project settings command",
        )),
    }
}
fn apply(
    wb: &mut Workbench,
    headers: &HeaderMap,
    id: &str,
    envelope: &GaugeAppCommandEnvelope,
) -> Result<Value, Box<Response>> {
    let context = build(wb, headers, id)?;
    let session = &context.session;
    let scope = project_scope(id);
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
        return Ok(
            json!({ "receipt": gaugeapp_receipt(session, envelope, "applied"), "project": id }),
        );
    }
    decide_gaugeapp_command(session, envelope).map_err(|reason| {
        boxed_error(
            if matches!(
                reason,
                crate::gaugeapp_contract::GaugeAppRejection::StaleBasis
            ) {
                StatusCode::CONFLICT
            } else {
                StatusCode::FORBIDDEN
            },
            reason.message(),
        )
    })?;
    if wb.project_moving(id) {
        return Err(boxed_error(
            StatusCode::CONFLICT,
            crate::federation::PAUSED_FOR_MOVE,
        ));
    }
    let mut project = wb
        .library
        .projects
        .get(id)
        .cloned()
        .ok_or_else(|| boxed_error(StatusCode::NOT_FOUND, "project is unavailable"))?;
    let mut synced_chats = Vec::new();
    let project_changed = match payload(envelope)? {
        SettingsChange::Project { name, isolated } => {
            if let Some(name) = name {
                project.name = name;
            }
            if let Some(isolated) = isolated {
                project.network_isolated = isolated;
            }
            true
        }
        SettingsChange::TargetName { target_id, name } => {
            // The name lives on collaboration Main, which the target record
            // then projects; the receipt below records the command.
            synced_chats = wb
                .rename_project_target(id, &target_id, &name)
                .map_err(|reason| boxed_error(StatusCode::CONFLICT, reason))?;
            false
        }
    };
    let receipt = gaugeapp_receipt(session, envelope, "applied");
    let change = GaugeAppChangeRecord {
        id: change_id,
        app: APP,
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
    let mut facts = Vec::new();
    if project_changed {
        facts.push(CommandRecordFact {
            scope_id: LIBRARY_SCOPE.into(),
            kind: "project".into(),
            payload: serde_json::to_string(&project).map_err(|reason| {
                boxed_error(StatusCode::INTERNAL_SERVER_ERROR, reason.to_string())
            })?,
        });
    }
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
                format!("project settings command refused: {reason:?}"),
            )
        })?;
    if !result.replayed {
        if project_changed {
            wb.library.apply_project(project);
        }
        wb.notify_library_changed("project", id, "upsert");
        for chat in &synced_chats {
            wb.notify_library_changed("chat", chat, "upsert");
        }
        if let Some(entry) = crate::audit::committed_entry(result.chained_payload.as_deref()) {
            crate::audit::finish_committed_in(wb, &tenant_scope, &entry);
        }
    }
    Ok(json!({ "receipt": receipt, "project": id }))
}
async fn command(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(envelope): Json<GaugeAppCommandEnvelope>,
) -> Response {
    let mut guard = wb.lock_unpoisoned();
    match apply(&mut guard, &headers, &id, &envelope) {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(response) => *response,
    }
}
fn agent_error(reason: GaugeAppAgentError) -> Response {
    let status = match reason {
        GaugeAppAgentError::Busy => StatusCode::CONFLICT,
        GaugeAppAgentError::NoModelAccess => StatusCode::PRECONDITION_FAILED,
        GaugeAppAgentError::Interrupted => StatusCode::CONFLICT,
        _ => StatusCode::BAD_GATEWAY,
    };
    error(status, reason.to_string())
}
async fn message(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<MessageBody>,
) -> Response {
    if body.idempotency_key.trim().is_empty() {
        return error(StatusCode::BAD_REQUEST, "idempotency key required");
    }
    let (context, claim) = {
        let guard = wb.lock_unpoisoned();
        let context = match build(&guard, &headers, &id) {
            Ok(value) => value,
            Err(response) => return *response,
        };
        if let Err(response) = checked_session(&context.session, &body.identity()) {
            return *response;
        }
        match replayed_gaugeapp_agent_turn(
            guard.store_ref(),
            &context.session,
            &body.idempotency_key,
            &body.message,
        ) {
            Ok(Some(turn)) => {
                return (StatusCode::OK, Json(json!({ "turn": turn }))).into_response()
            }
            Ok(None) => {}
            Err(reason) => return agent_error(reason),
        }
        let Some(claim) = claim_gaugeapp_agent_turn(&gaugeapp_thread_id(&context.session)) else {
            return agent_error(GaugeAppAgentError::Busy);
        };
        (context, claim)
    };
    let opening = context.session.clone();
    let thread = gaugeapp_thread_id(&opening);
    let runtime_wb = wb.clone();
    let refresh_wb = wb.clone();
    let action_wb = wb.clone();
    let refresh_headers = headers.clone();
    let action_headers = headers.clone();
    let refresh_id = id.clone();
    let action_id = id.clone();
    let key = body.idempotency_key.clone();
    let user = body.message.clone();
    let direct_key = format!("agent:{}", key);
    let action_opening = opening.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _claim = claim;
        let mut direct = |proposal: &crate::gaugeapp_agent::GaugeAppAgentProposal, idempotency_key: &str| -> Result<Value, GaugeAppAgentError> {
            let mut guard = action_wb.lock_unpoisoned();
            let current = build(&guard, &action_headers, &action_id).map_err(|_| GaugeAppAgentError::Rejected(GaugeAppAgentRejection::SessionRevoked))?;
            if !same(&action_opening, &current.session) { return Err(GaugeAppAgentError::Rejected(GaugeAppAgentRejection::SessionMismatch)); }
            let envelope = GaugeAppCommandEnvelope {
                session_id: current.session.id, generation: current.session.generation, app: APP,
                scope: current.session.scope, page_id: proposal.page_id.clone(),
                command_id: proposal.command_id.clone(), expected_basis: proposal.expected_basis.clone(),
                idempotency_key: idempotency_key.into(), payload: proposal.payload.clone(), client: GaugeAppClient::Agent,
            };
            apply(&mut guard, &action_headers, &action_id, &envelope)
                .map_err(|_| GaugeAppAgentError::InvalidOutput("Project setting changed or values were refused; read the current page and try again.".into()))
        };
        run_gaugeapp_agent_turn_with_direct_actions(
            &runtime_wb, context, &user,
            move || {
                let guard = refresh_wb.lock_unpoisoned();
                build(&guard, &refresh_headers, &refresh_id)
                    .map_err(|_| GaugeAppAgentError::Rejected(GaugeAppAgentRejection::SessionRevoked))
            },
            || gaugeapp_agent_turn_was_stopped(&thread),
            |_| Ok(()),
            |current, proposal| {
                let envelope = GaugeAppCommandEnvelope {
                    session_id: current.session.id.clone(), generation: current.session.generation.clone(), app: APP,
                    scope: current.session.scope.clone(), page_id: proposal.page_id.clone(), command_id: proposal.command_id.clone(),
                    expected_basis: proposal.expected_basis.clone(), idempotency_key: "agent:validation".into(),
                    payload: proposal.payload.clone(), client: GaugeAppClient::Agent,
                };
                decide_gaugeapp_command(&current.session, &envelope)
                    .map_err(|reason| GaugeAppAgentError::InvalidOutput(reason.message().into()))?;
                payload(&envelope).map_err(|_| GaugeAppAgentError::InvalidOutput("Invalid project settings values".into()))?;
                Ok(())
            },
            Some(&mut direct), &direct_key,
        )
    }).await;
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
        &|guard| {
            let current = build(guard, &headers, &id).map_err(|_| {
                GaugeAppAgentError::Rejected(GaugeAppAgentRejection::SessionRevoked)
            })?;
            if !same(&opening, &current.session) {
                return Err(GaugeAppAgentError::Rejected(
                    GaugeAppAgentRejection::SessionMismatch,
                ));
            }
            Ok(())
        },
        &|_, _| {
            Err(GaugeAppAgentError::InvalidOutput(
                "Project settings changes apply directly; no proposal is available.".into(),
            ))
        },
    );
    match transcript {
        Ok(messages) => (StatusCode::OK, Json(json!({ "turn": turn, "thread": { "id": gaugeapp_thread_id(&opening), "messages": messages } }))).into_response(),
        Err(reason) => agent_error(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gaugeapp_agent::{append_gaugeapp_agent_exchange, GaugeAppAgentTurn};

    #[test]
    fn viewer_and_auditor_cannot_receive_project_edit_commands() {
        assert!(can_manage_project(None, false)); // solo Home
        assert!(can_manage_project(Some(Role::member()), true));
        assert!(can_manage_project(Some(Role::owner()), true));
        assert!(!can_manage_project(Some(Role::viewer()), true));
        assert!(!can_manage_project(Some(Role::new("auditor")), true));
        assert!(!can_manage_project(None, true));
    }

    #[test]
    fn a_target_is_renamed_on_main_from_project_settings() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let headers = HeaderMap::new();
        let project = {
            let mut wb = shared.lock_unpoisoned();
            crate::library_routes::create_named_project(&mut wb, "proj-rename", "Site").unwrap()
                ["id"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        let (session, target_id) = {
            let wb = shared.lock_unpoisoned();
            let target_id = wb
                .library
                .work_targets
                .values()
                .find(|target| matches!(&target.owner, WorkTargetOwner::Project { project_id } if project_id == &project))
                .unwrap()
                .id
                .clone();
            (build(&wb, &headers, &project).unwrap().session, target_id)
        };
        let work_data = session
            .pages
            .iter()
            .find(|page| page.id == "work-data")
            .unwrap();
        assert!(work_data
            .commands
            .iter()
            .any(|command| command == "project.target.name.set"));
        let envelope = |key: &str, name: &str| GaugeAppCommandEnvelope {
            session_id: session.id.clone(),
            generation: session.generation.clone(),
            app: APP,
            scope: session.scope.clone(),
            page_id: "work-data".into(),
            command_id: "project.target.name.set".into(),
            expected_basis: work_data.resource_basis.clone(),
            idempotency_key: key.into(),
            payload: json!({ "target_id": target_id, "name": name }),
            client: GaugeAppClient::Web,
        };
        let mut wb = shared.lock_unpoisoned();
        for invalid in [".hidden", "a/b", ""] {
            assert!(apply(&mut wb, &headers, &project, &envelope(invalid, invalid)).is_err());
        }
        let renamed = envelope("rename-website", "website");
        assert!(apply(&mut wb, &headers, &project, &renamed).is_ok());
        assert_eq!(wb.library.work_targets[&target_id].name, "website");
        assert_eq!(
            wb.main_target_name(&project, &target_id).as_deref(),
            Some("website")
        );
        // A replay applies nothing twice.
        assert!(apply(&mut wb, &headers, &project, &renamed).is_ok());
    }

    #[test]
    fn project_commands_and_conversations_stay_in_their_exact_scope() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let headers = HeaderMap::new();
        let (first, second) = {
            let mut wb = shared.lock_unpoisoned();
            let first = crate::library_routes::create_named_project(&mut wb, "proj-first", "First")
                .unwrap();
            let second =
                crate::library_routes::create_named_project(&mut wb, "proj-second", "Second")
                    .unwrap();
            (
                first["id"].as_str().unwrap().to_owned(),
                second["id"].as_str().unwrap().to_owned(),
            )
        };
        let first_session = {
            let wb = shared.lock_unpoisoned();
            build(&wb, &headers, &first).unwrap().session
        };
        assert_eq!(
            first_session
                .pages
                .iter()
                .map(|page| page.id.as_str())
                .collect::<Vec<_>>(),
            ["overview", "people", "work-data", "agents", "model-access"]
        );
        let envelope = GaugeAppCommandEnvelope {
            session_id: first_session.id.clone(),
            generation: first_session.generation.clone(),
            app: APP,
            scope: first_session.scope.clone(),
            page_id: PAGE.into(),
            command_id: "project.network-isolation.set".into(),
            expected_basis: first_session.pages[0].resource_basis.clone(),
            idempotency_key: "isolate-first".into(),
            payload: json!({ "isolated": true }),
            client: GaugeAppClient::Web,
        };
        {
            let mut wb = shared.lock_unpoisoned();
            assert!(apply(&mut wb, &headers, &first, &envelope).is_ok());
            assert!(apply(&mut wb, &headers, &first, &envelope).is_ok());
            assert!(wb.library.projects[&first].network_isolated);
            assert!(!wb.library.projects[&second].network_isolated);
            assert!(apply(&mut wb, &headers, &second, &envelope).is_err());
        }
        append_gaugeapp_agent_exchange(
            &shared,
            &first_session,
            "turn-first",
            "Describe settings",
            &GaugeAppAgentTurn {
                message: "First project".into(),
                proposals: vec![],
            },
        )
        .unwrap();
        let wb = shared.lock_unpoisoned();
        let second_session = build(&wb, &headers, &second).unwrap().session;
        assert_eq!(
            gaugeapp_agent_transcript(wb.store_ref(), &first_session)
                .unwrap()
                .len(),
            2
        );
        assert!(gaugeapp_agent_transcript(wb.store_ref(), &second_session)
            .unwrap()
            .is_empty());
    }
}
