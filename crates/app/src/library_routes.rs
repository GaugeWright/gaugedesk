//! The library surface (ADR 0027): agents, projects, bindings, chats — and the
//! `/workspace` facet tree the nav renders. CRUD here writes durable records
//! (latest-wins / tombstone) and mutates the in-memory [`Library`] projection;
//! creating a chat creates a candidate workspace in the selected target and seeds its
//! `.agent-config.json` from the agent's config.
//!
//! Delete is a **cascade** with one hard ordering rule: retire a chat's runtime
//! session **before** touching its worktree on disk.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::library::{gen_id, ProjectRecord, RecordOp};
use crate::library_state::{
    AgentDeleteError, BindPlacementError, BoundaryAcceptError, BoundaryAttestationInput,
    CreateArchetypeChatError, CreateArchetypeError, ForkArchetypeError, ForkChatError,
    PublishArchetypeError, PullArchetypeError, UpgradePlacementError,
};
use crate::{LockUnpoisoned, SharedWorkbench, Workbench, DEFAULT_AGENT};
use gaugedesk_store::AdmitError;
use gaugedesk_workspace::MergeOutcome;

// ---- helpers -------------------------------------------------------------

// Every library mutation funnels through these four `write_*` helpers (creates,
// renames via upsert, removals via tombstone) — so each pushes a workspace-change
// REFERENCE (record kind + id + op) after recording the change, and every connected
// client resolves the affected projection live. (The few inline chat appends below
// do the same.) The reference never carries protected content (INV-10).
fn write_project(wb: &mut Workbench, r: ProjectRecord) {
    wb.write_project_record(r);
}
/// Create a chat under a logical placement/archetype root and exact target.
fn create_chat_in(
    wb: &mut Workbench,
    inst_id: &str,
    title: &str,
    target_id: Option<&str>,
) -> Result<serde_json::Value, String> {
    wb.create_chat_in_instance_on_target(inst_id, title, target_id)
}

// ---- GET /workspace ------------------------------------------------------

/// The nav facet tree (ADR 0035/0036), project-first vocabulary:
/// - `archetypes` — the reusable methods (each → its edit chats);
/// - `projects` — trust boundaries (each → its `placements` → work chats), including
///   the explicit default "Personal" project;
/// - `recent` — a flat current-first chat list.
///
/// Each chat carries a derived `kind` (`"edit"` | `"work"`), never a stored mode.
pub async fn get_workspace(
    State(wb): State<SharedWorkbench>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let vis = wb.project_visibility(crate::net_http::bearer(&headers));
    Json(scope_workspace_value(&wb, workspace_value(&wb), &vis)).into_response()
}

/// **ENTSEC-2** ([ADR 0065]): prune a workspace projection to what the caller may see — drop
/// projects that are not visible and any recent chat outside a visible project. Under
/// [`ProjectVisibility::All`] (solo / owner / admin / bootstrap) it is a no-op, so the
/// single-user shape is untouched. The archetype library is shared method truth (a placement
/// shows its archetype's name as lineage), so it is not project-scoped here.
pub fn scope_workspace_value(
    wb: &Workbench,
    mut value: serde_json::Value,
    vis: &crate::workbench_auth::ProjectVisibility,
) -> serde_json::Value {
    use crate::workbench_auth::ProjectVisibility;
    if matches!(vis, ProjectVisibility::All) {
        return value;
    }
    if let Some(projects) = value.get_mut("projects").and_then(|p| p.as_array_mut()) {
        projects.retain(|p| {
            p.get("id")
                .and_then(|i| i.as_str())
                .map(|id| vis.allows(id))
                .unwrap_or(false)
        });
    }
    if let Some(recent) = value.get_mut("recent").and_then(|r| r.as_array_mut()) {
        recent.retain(|c| {
            c.get("id")
                .and_then(|i| i.as_str())
                .map(|id| wb.chat_visible(id, vis))
                .unwrap_or(false)
        });
    }
    value
}

/// Build the workspace projection tree (archetypes → edit chats; projects →
/// placements → work chats; recent). Shared by the bare `GET /workspace` and the
/// freshness-carrying `GET /projections/library/workspace` carriage (ADR 0037), so
/// both serve the identical value — only the carriage adds the freshness stamp.
pub fn workspace_value(wb: &Workbench) -> serde_json::Value {
    wb.workspace_value()
}

/// Resolve one workspace-change reference into the smallest self-contained slice
/// of the workspace projection that can repair a client tree. The event stream
/// carries only `(record, id, op)` (INV-10); this resolver returns current
/// projection nodes, never mutable library records. Clients remove the referenced
/// record everywhere, then upsert these replacements and restore server order.
///
/// Parent nodes are intentionally complete: a chat or workstream is denormalized
/// into its rooted archetype/project tree and recent/search projection, so replacing
/// its current parents is both smaller and safer than teaching the client every
/// nested wire location.
pub fn workspace_delta_value(
    workspace: &serde_json::Value,
    record: &str,
    id: &str,
) -> Option<serde_json::Value> {
    if !matches!(
        record,
        "archetype" | "project" | "placement" | "chat" | "workstream" | "work_target"
    ) {
        return None;
    }

    let array = |key: &str| {
        workspace
            .get(key)
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let archetypes = array("archetypes");
    let projects = array("projects");
    let recent = array("recent");
    let workstreams = array("workstreams");
    let work_targets = array("work_targets");
    let has_id = |value: &serde_json::Value| value.get("id").and_then(|v| v.as_str()) == Some(id);
    let nested_has = |value: &serde_json::Value, collection: &str| {
        value
            .get(collection)
            .and_then(serde_json::Value::as_array)
            .is_some_and(|items| items.iter().any(&has_id))
    };
    let project_has = |project: &serde_json::Value| {
        if record == "work_target"
            && project
                .get("targets")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|targets| targets.iter().any(&has_id))
        {
            return true;
        }
        project
            .get("placements")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|placements| {
                placements.iter().any(|placement| match record {
                    "archetype" => {
                        placement.get("archetype_id").and_then(|v| v.as_str()) == Some(id)
                    }
                    "placement" => {
                        placement.get("placement_id").and_then(|v| v.as_str()) == Some(id)
                    }
                    "chat" => nested_has(placement, "chats"),
                    "workstream" => nested_has(placement, "workstreams"),
                    _ => false,
                })
            })
    };

    let selected_archetypes: Vec<_> = archetypes
        .iter()
        .filter(|value| match record {
            "archetype" => has_id(value),
            "chat" => nested_has(value, "chats"),
            "workstream" => nested_has(value, "workstreams"),
            "work_target" => value.get("authoring_target_id").and_then(|v| v.as_str()) == Some(id),
            _ => false,
        })
        .cloned()
        .collect();
    let selected_projects: Vec<_> = projects
        .iter()
        .filter(|value| (record == "project" && has_id(value)) || project_has(value))
        .cloned()
        .collect();
    let selected_recent: Vec<_> = recent
        .iter()
        .filter(|value| match record {
            "chat" => has_id(value),
            "placement" => value.get("placement").and_then(|v| v.as_str()) == Some(id),
            "workstream" => value.get("workstream").and_then(|v| v.as_str()) == Some(id),
            "work_target" => value.get("target_id").and_then(|v| v.as_str()) == Some(id),
            _ => false,
        })
        .cloned()
        .collect();
    let selected_workstreams: Vec<_> = workstreams
        .iter()
        .filter(|value| {
            (record == "workstream" && has_id(value))
                || (record == "work_target"
                    && value.get("target_id").and_then(|v| v.as_str()) == Some(id))
                || (record == "chat"
                    && value
                        .get("members")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|members| {
                            members.iter().any(|member| member.as_str() == Some(id))
                        }))
        })
        .cloned()
        .collect();
    let selected_work_targets: Vec<_> = work_targets
        .iter()
        .filter(|value| record == "work_target" && has_id(value))
        .cloned()
        .collect();
    let ids = |values: &[serde_json::Value], key: &str| {
        values
            .iter()
            .filter_map(|value| value.get(key).and_then(|v| v.as_str()).map(str::to_owned))
            .collect::<Vec<_>>()
    };

    Some(json!({
        "archetypes": selected_archetypes,
        "projects": selected_projects,
        "recent": selected_recent,
        "workstreams": selected_workstreams,
        "work_targets": selected_work_targets,
        "personal_placement": workspace.get("personal_placement").cloned().unwrap_or(serde_json::Value::Null),
        "order": {
            "archetypes": ids(&archetypes, "id"),
            "projects": ids(&projects, "id"),
            "recent": ids(&recent, "id"),
            "workstreams": ids(&workstreams, "id"),
            "work_targets": ids(&work_targets, "id"),
        },
    }))
}

// ---- GET /search : content search across chat log + worktree files (SEARCH-1/2) ----

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: String,
}

/// Search chat **content** — the chat-log tier (SEARCH-1) and the file-content tier
/// (SEARCH-2) of `navigation.md` "Search scope and relevance". A server projection
/// (`INV-5`, projection-first): for each chat we fold its `transcript` records
/// (user/assistant/admitted `text` and streamed `delta`) and — for the file tier —
/// run a **bounded walk** of the chat's worktree, case-insensitively substring-matching
/// the query and returning matching chat ids with a one-line snippet (and, for a file
/// hit, its path). Each hit carries a `tier` (`"log"` | `"file"`); log hits rank first,
/// then file hits, so with the client's title tier the order is title > log > file. The
/// client never folds transcripts nor walks worktrees; the title tier (label match) is a
/// separate pure client-side filter over the workspace projection. File search is a
/// per-query bounded walk, not an index — see [`Workbench::search_value`].
pub async fn search(
    State(wb): State<SharedWorkbench>,
    Query(sq): Query<SearchQuery>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    Json(wb.search_value(&sq.q)).into_response()
}

// ---- GET /tasks : the human task queue -----------------------------------

/// The human task queue (`navigation.md`: "a projection over review-needed /
/// approvals / follow-ups"). M0 sources it from our own merge lifecycle: a chat
/// whose finished turn left a clean diff (`MergePhase::Clean`) is **awaiting the
/// human's keep/reject** — that is a review task. Current-first (most recent).
pub async fn get_tasks(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    Json(wb.task_queue_value()).into_response()
}

/// Who exists and may be given work (`GATE-3f`).
///
/// A read-only projection of `Active` memberships (`INV-5`, `INV-20`): the same
/// list the `ask` tool offers an agent and the same one an assignment resolves
/// against, so no surface can believe in a person another does not.
pub async fn get_roster(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    Json(serde_json::json!({ "people": wb.roster() })).into_response()
}

#[derive(serde::Deserialize)]
pub struct AssignWorkItem {
    /// The tracker boundary the item lives in.
    pub boundary_id: String,
    /// An authority or display name from the roster. Absent or null clears the
    /// assignment, which means "whoever has access".
    #[serde(default)]
    pub to: Option<String>,
}

/// Direct an open issue at someone, or clear it.
///
/// Advisory by design (see [`crate::roster`]): it records who *should* act and
/// never restricts who may claim. An assignee who is away must not be able to
/// strand work in a queue whose premise is that anyone with access can pick it
/// up — exclusivity is what `claim` provides, and it is earned by taking the
/// work rather than granted by being named.
pub async fn assign_work_item(
    State(wb): State<SharedWorkbench>,
    Path(item_id): Path<String>,
    Json(request): Json<AssignWorkItem>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    match wb.assign_work_item(&request.boundary_id, &item_id, request.to.as_deref()) {
        Ok(assignee) => (
            StatusCode::OK,
            Json(serde_json::json!({ "item": item_id, "assigned_to": assignee })),
        )
            .into_response(),
        Err(error @ crate::roster::AssignError::NotOnRoster { .. }) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

// ---- agents --------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateAgent {
    pub name: String,
}

/// Create an agent + its authoring instance (a fresh repo).
pub async fn create_agent(
    State(wb): State<SharedWorkbench>,
    Json(body): Json<CreateAgent>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    match wb.create_archetype(body.name) {
        Ok(archetype) => (
            StatusCode::CREATED,
            Json(json!({ "id": archetype.id, "name": archetype.name })),
        )
            .into_response(),
        Err(CreateArchetypeError::Create(error)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": error })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct ForkArchetype {
    pub name: Option<String>,
}

/// Fork an archetype (ADR 0035/0038): copy its authored WhippleScript package
/// history and GaugeDesk runtime selection into a fresh, independent
/// archetype. Editing the fork never touches the source.
///
/// **Owner-only.** Solo, the user owns every archetype, so this is always allowed;
/// the guard is the seam that protects a vendor package's IP in distribution — a
/// placement of someone else's archetype cannot fork it (ADR 0035).
pub async fn fork_archetype(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    Json(body): Json<ForkArchetype>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    match wb.fork_archetype(&id, body.name) {
        Ok(archetype) => (
            StatusCode::CREATED,
            Json(json!({ "id": archetype.id, "name": archetype.name })),
        )
            .into_response(),
        Err(ForkArchetypeError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such archetype" })),
        )
            .into_response(),
        Err(ForkArchetypeError::SourceNotOpen) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "source archetype not open" })),
        )
            .into_response(),
        Err(ForkArchetypeError::Create(error)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": error })),
        )
            .into_response(),
    }
}

/// Pull the source archetype's improvements into this fork (ADR 0038): a real 3-way
/// merge of the source's current `main` over the shared fork point. Only an archetype
/// with `forked_from` can pull. A conflict aborts cleanly (the fork is never left
/// half-merged) and asks the owner to reconcile in an edit chat.
pub async fn post_pull_from_source(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    match wb.pull_archetype_from_source(&id) {
        Ok(MergeOutcome::Clean) => (StatusCode::OK, Json(json!({ "outcome": "clean" }))).into_response(),
        Ok(MergeOutcome::Conflict) => (
            StatusCode::CONFLICT,
            Json(json!({ "outcome": "conflict", "error": "pull hit a conflict with your fork's edits — reconcile it in an edit chat" })),
        )
            .into_response(),
        Err(PullArchetypeError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such archetype" })),
        )
            .into_response(),
        Err(PullArchetypeError::NotFork) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "not a fork — nothing to pull" })),
        )
            .into_response(),
        Err(PullArchetypeError::SourceMissing) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "the source archetype no longer exists" })),
        )
            .into_response(),
        Err(PullArchetypeError::SourceNotOpen) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "source archetype not open" })),
        )
            .into_response(),
        Err(PullArchetypeError::ForkNotOpen) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "fork not open" })),
        )
            .into_response(),
        Err(PullArchetypeError::Workspace(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// One agent's record (name + raw config) — what the settings editor loads.
pub async fn get_agent(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    match wb.agent_record(&id) {
        Some(a) => Json(json!({ "id": a.id, "name": a.name, "config": a.config })).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such agent" })),
        )
            .into_response(),
    }
}

pub async fn get_archetype_abilities(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    match wb.archetype_abilities(&id) {
        Ok(abilities) => Json(json!({ "abilities": abilities })).into_response(),
        Err(error) if error == "no such archetype" => {
            (StatusCode::NOT_FOUND, Json(json!({ "error": error }))).into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpdateArchetypeAbilities {
    pub abilities: Vec<String>,
}

pub async fn put_archetype_abilities(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    Json(body): Json<UpdateArchetypeAbilities>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    match wb.set_archetype_abilities(&id, body.abilities) {
        Ok(abilities) => Json(json!({ "abilities": abilities })).into_response(),
        Err(error) if error == "no such archetype" => {
            (StatusCode::NOT_FOUND, Json(json!({ "error": error }))).into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))).into_response(),
    }
}

pub async fn get_placement_abilities(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    match wb.placement_abilities(&id) {
        Ok(abilities) => Json(json!({ "abilities": abilities })).into_response(),
        Err(error) if error == "no such placement" => {
            (StatusCode::NOT_FOUND, Json(json!({ "error": error }))).into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpdateAgent {
    pub name: Option<String>,
    /// Raw `.agent-config.json` — validated before persisting.
    pub config: Option<String>,
}

/// Rename / re-configure an agent (append a newer record).
pub async fn update_agent(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    Json(body): Json<UpdateAgent>,
) -> impl IntoResponse {
    if let Some(cfg) = &body.config {
        if let Err(e) = gaugedesk_boundary::AgentConfig::runtime_settings_from_json(cfg) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("invalid agent config: {e}") })),
            )
                .into_response();
        }
    }
    let mut wb = wb.lock_unpoisoned();
    let Some(updated) = wb.update_agent_record(&id, body.name, body.config) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such agent" })),
        )
            .into_response();
    };
    (
        StatusCode::OK,
        Json(json!({ "id": updated.id, "name": updated.name })),
    )
        .into_response()
}

/// Delete an agent + its authoring instance (cascade its chats). Refuses the
/// default agent, and refuses while the agent is bound into any project (409).
pub async fn delete_agent(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    match wb.delete_agent_cascade(&id) {
        Ok(()) => (StatusCode::OK, Json(json!({ "deleted": id }))).into_response(),
        Err(AgentDeleteError::DefaultAgent) => (
            StatusCode::CONFLICT,
            Json(json!({ "rejected": "the default agent can't be deleted" })),
        )
            .into_response(),
        Err(AgentDeleteError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such agent" })),
        )
            .into_response(),
        Err(AgentDeleteError::BoundElsewhere) => (
            StatusCode::CONFLICT,
            Json(json!({ "rejected": "unbind this agent from its projects first" })),
        )
            .into_response(),
    }
}

// ---- projects ------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateProject {
    pub name: String,
    /// The Home selected by the client. Omitting it means the Home receiving
    /// this command; asserting another Home fails closed rather than creating a
    /// locally stored project with a remote ownership label.
    #[serde(default)]
    pub home_id: Option<gaugedesk_core::ids::HomeId>,
}

/// `GET /projects/:id/home` — the **project-home rollup** (`UX-2`, `mvp-workbench.md` "Project
/// Home"): the per-project summary derived **from data** (`INV-5`; never inferred from command
/// receipts). For each work chat across the project's placements it folds the chat's lifecycle
/// scopes (chat id = the run/merge scope) into:
/// - `recent_runs` — `{chat,title,phase,ran}` from each chat's `RunState`, most-recent-first;
/// - `outputs` — `{chat,title,phase}` from each chat's `MergeState` for chats with a **live**
///   (non-`Clean`/non-`Init`) output/review state — the review/output summaries;
/// - `audit` — `{placements,chats,events}`, the audit summary (event counts across the
///   project's chat scopes; references only, `INV-10`).
///
/// 404 on an unknown project. Read-only — placement version/upgrade display is the workspace
/// projection (`UX-9`), so this rollup is the remaining run/output/audit half.
pub async fn project_home(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    match wb.project_home_value(&id) {
        Some(value) => (StatusCode::OK, Json(value)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such project" })),
        )
            .into_response(),
    }
}

pub async fn create_project(
    State(wb): State<SharedWorkbench>,
    Json(body): Json<CreateProject>,
) -> axum::response::Response {
    let mut wb = wb.lock_unpoisoned();
    let home_id = body.home_id.unwrap_or_else(|| wb.home_id().clone());
    if &home_id != wb.home_id() {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "create the project through its selected Home",
                "selected_home": home_id.as_str(),
                "serving_home": wb.home_id().as_str(),
            })),
        )
            .into_response();
    }
    let id = gen_id("proj");
    write_project(
        &mut wb,
        ProjectRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: id.clone(),
            op: RecordOp::Upsert,
            name: body.name.clone(),
            is_default: false,
            home_id: home_id.clone(),
            network_isolated: false,
            run_purpose: None,
            deployment_mode: None,
        },
    );
    let target_id = match wb.create_managed_project_target(&id, format!("{} files", body.name)) {
        Ok(target_id) => target_id,
        Err(error) => {
            wb.delete_project_cascade(&id);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": error })),
            )
                .into_response();
        }
    };
    // Every project gets a built-in general placement at creation — the default
    // archetype installed on it under a deterministic id, mirroring the Personal
    // project. A project is therefore a real placement home the moment it exists: it
    // hosts plain work chats and workstreams with no manual "place an archetype" step,
    // and the nav shows those chats directly under the project (the general placement is
    // implementation detail, never a node). Deliberately placing other archetypes adds
    // visible placements alongside it.
    let placement =
        place_archetype_with_id(&mut wb, &id, DEFAULT_AGENT, &general_placement_id(&id)).ok();
    // Advance the onboarding checklist (ADR 0075 Phase 2): the user created their
    // first real project. Best-effort; the project already exists.
    wb.advance_onboarding("project", &json!({ "project": id }).to_string());
    (
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "name": body.name,
            "home_id": home_id.as_str(),
            "placement": placement,
            "target_id": target_id,
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct UpdateProject {
    /// Rename (omitted ⇒ name unchanged).
    #[serde(default)]
    pub name: Option<String>,
    /// Network egress posture (omitted ⇒ unchanged). `true` isolates the project's
    /// chats from the network (fail-closed); `false` opens egress (the app default).
    #[serde(default)]
    pub network_isolated: Option<bool>,
    /// The project's **deployment mode** (`DEPLOY-1`): the `(operator, attested)` placement
    /// the consultant declares as the engagement boundary ceiling. Omitted ⇒ unchanged.
    #[serde(default)]
    pub deployment_mode: Option<gaugedesk_core::boundary_lifecycle::Placement>,
    /// Business purpose admitted for runs in this project. Omitted means
    /// unchanged; `null` revokes it; purpose-tagged resources fail closed when
    /// none is set.
    #[serde(default, deserialize_with = "deserialize_present_run_purpose")]
    pub run_purpose: Option<Option<String>>,
}

fn deserialize_present_run_purpose<'de, D>(
    deserializer: D,
) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

pub async fn update_project(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    Json(body): Json<UpdateProject>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let Some(updated) = wb.update_project_record(
        &id,
        body.name,
        body.network_isolated,
        body.deployment_mode,
        body.run_purpose,
    ) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such project" })),
        )
            .into_response();
    };
    (
        StatusCode::OK,
        Json(json!({
            "id": id,
            "name": updated.name,
            "network_isolated": updated.network_isolated,
            "deployment_mode": updated.deployment_mode,
            "run_purpose": updated.run_purpose,
        })),
    )
        .into_response()
}

/// Delete a project: tear down every using-instance it holds, then tombstone it.
pub async fn delete_project(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if wb.delete_project_cascade(&id) {
        (StatusCode::OK, Json(json!({ "deleted": id }))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such project" })),
        )
            .into_response()
    }
}

// ---- binding: agent -> project (a using instance) ------------------------

#[derive(Deserialize)]
pub struct BindAgent {
    pub agent_id: String,
}

/// Create a **placement** (a Using instance) of `agent_id` on `project_id`, returning
/// the new instance id. Shared by explicit binding (a named project, [`bind_agent`])
/// and the **eager Personal placement** minted when an archetype is created
/// ([`create_agent`]/[`fork_archetype`]) so every archetype is immediately usable in
/// the explicit Personal project with no placement ceremony (ADR 0045/0036/0096).
/// The stable id of a project's **built-in general placement** — the auto-created
/// default-archetype placement every project gets (primitives/project.md). Deterministic
/// from the project id so the projection can flag it (and the nav hide it) without a
/// persisted marker; deliberately-placed archetypes get random `gen_id` ids instead.
pub fn general_placement_id(project_id: &str) -> String {
    format!("inst-general-{project_id}")
}

/// Place `agent_id` on `project_id` under a caller-chosen instance id — used to give a
/// project's built-in general placement its deterministic [`general_placement_id`].
fn place_archetype_with_id(
    wb: &mut Workbench,
    project_id: &str,
    agent_id: &str,
    inst_id: &str,
) -> Result<String, String> {
    // The built-in general placement is always active (APPROVE-1): a project is never
    // without something to chat with, so it is never approval-gated.
    wb.place_archetype_on_project_with_id(
        project_id,
        agent_id,
        inst_id,
        crate::library::Admission::Active,
    )
}

pub async fn bind_agent(
    State(wb): State<SharedWorkbench>,
    Path(pid): Path<String>,
    Json(body): Json<BindAgent>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    match wb.bind_agent_to_project(&pid, &body.agent_id) {
        Ok(inst_id) => {
            (StatusCode::CREATED, Json(json!({ "instance_id": inst_id }))).into_response()
        }
        Err(BindPlacementError::ProjectNotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such project" })),
        )
            .into_response(),
        Err(BindPlacementError::AgentNotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such agent" })),
        )
            .into_response(),
        Err(BindPlacementError::Create(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

// ---- versioning: publish a new archetype version, upgrade a placement (UX-9, ADR 0063) ----

#[derive(Deserialize)]
pub struct PublishArchetype {
    /// Optionally set the owner's auto-upgrade preference at publish time.
    #[serde(default)]
    pub auto_upgrade: Option<bool>,
}

/// Publish a new version of an archetype (`UX-9`): bump its `current_version`. Every placement
/// of this archetype then has an **upgrade available**; where the owner opted into auto-upgrade
/// **and** the hosting org allows it ([ADR 0063]), those placements advance automatically, else
/// they wait for a manual `/placements/:id/upgrade`.
pub async fn post_publish_archetype(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    Json(body): Json<PublishArchetype>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    match wb.publish_archetype_version(&id, body.auto_upgrade) {
        Ok((new_version, auto_upgraded)) => (
            StatusCode::OK,
            Json(json!({ "version": new_version, "auto_upgraded": auto_upgraded })),
        )
            .into_response(),
        Err(PublishArchetypeError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such archetype" })),
        )
            .into_response(),
        Err(PublishArchetypeError::InvalidPackage(error)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": format!("invalid archetype version: {error}") })),
        )
            .into_response(),
        Err(PublishArchetypeError::Workspace(error)) => {
            (StatusCode::CONFLICT, Json(json!({ "error": error }))).into_response()
        }
    }
}

/// Upgrade a placement to its archetype's current published version (`UX-9`, manual default).
/// Idempotent — a placement already current stays put. Diverged content is reconciled through
/// the workspace pull before the version pointer moves; conflicts fail closed.
/// Accept a pending placement (`APPROVE-1`, ADR 0064): the project owner's second
/// explicit act, flipping it `Pending → Active` so it can host work chats. Idempotent on
/// an already-active placement; 404 on an unknown one.
pub async fn post_accept_placement(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    match wb.accept_placement(&id) {
        Some(_) => (
            StatusCode::OK,
            Json(json!({ "placement": id, "admission": "active" })),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such placement" })),
        )
            .into_response(),
    }
}

pub async fn post_upgrade_placement(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    match wb.upgrade_placement_version(&id) {
        Ok(version) => (StatusCode::OK, Json(json!({ "version": version }))).into_response(),
        Err(UpgradePlacementError::PlacementNotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such placement" })),
        )
            .into_response(),
        Err(UpgradePlacementError::ArchetypeNotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such archetype" })),
        )
            .into_response(),
        Err(UpgradePlacementError::PackageUnavailable(error)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": error })),
        )
            .into_response(),
    }
}

/// Unbind: tear down a using instance (and its chats).
pub async fn unbind_agent(
    State(wb): State<SharedWorkbench>,
    Path((pid, iid)): Path<(String, String)>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if wb.placement_project_id(&iid) != Some(pid.as_str()) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such placement in project" })),
        )
            .into_response();
    }
    if wb.unbind_instance(&iid) {
        (StatusCode::OK, Json(json!({ "unbound": iid }))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such instance" })),
        )
            .into_response()
    }
}

// ---- chat creation -------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateChat {
    #[serde(default = "default_title")]
    pub title: String,
    /// Work chats may select any target explicitly eligible for the placement.
    /// Edit chats ignore this only when absent and use their archetype-owned
    /// managed authoring target.
    #[serde(default)]
    pub target_id: Option<String>,
}
fn default_title() -> String {
    "new chat".into()
}

/// New chat under an agent (its authoring instance).
pub async fn create_chat_under_agent(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    Json(body): Json<CreateChat>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    match wb.create_chat_under_agent(&id, &body.title) {
        Ok(v) => (StatusCode::CREATED, Json(v)).into_response(),
        Err(CreateArchetypeChatError::ArchetypeNotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such agent" })),
        )
            .into_response(),
        Err(CreateArchetypeChatError::Create(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

/// New chat under a project's using-instance.
pub async fn create_chat_under_instance(
    State(wb): State<SharedWorkbench>,
    Path((pid, iid)): Path<(String, String)>,
    Json(body): Json<CreateChat>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if wb.placement_project_id(&iid) != Some(pid.as_str()) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such placement in project" })),
        )
            .into_response();
    }
    let Some(target_id) = body.target_id.as_deref() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "target_id is required" })),
        )
            .into_response();
    };
    match create_chat_in(&mut wb, &iid, &body.title, Some(target_id)) {
        Ok(v) => (StatusCode::CREATED, Json(v)).into_response(),
        Err(e) => {
            let status = if e == "no such instance" {
                StatusCode::NOT_FOUND
            } else if e == "work target storage is not open" {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::BAD_REQUEST
            };
            (status, Json(json!({ "error": e }))).into_response()
        }
    }
}

/// **Use** an archetype with no placement ceremony (ADR 0045/0036): open a *work*
/// chat rooted on the archetype's placement in the explicit Personal project. The
/// placement is minted eagerly at creation; this finds it (and lazily creates it
/// for archetypes that predate eager placement), then roots a chat on it.
pub async fn use_archetype(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    Json(body): Json<CreateChat>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    match wb.use_archetype_chat(&id, &body.title) {
        Ok(v) => (StatusCode::CREATED, Json(v)).into_response(),
        Err(CreateArchetypeChatError::ArchetypeNotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such archetype" })),
        )
            .into_response(),
        Err(CreateArchetypeChatError::Create(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

/// Fork a chat (ADR 0038): **clone the whole thread** into a new chat rooted on the
/// **same** placement/archetype and kind, recording `forked_from`. The fork's worktree
/// inherits the parent's files, and WhippleScript seeds a distinct target instance
/// from the parent's exact durable thread position.
pub async fn fork_chat(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    match wb.fork_chat(&id) {
        Ok(forked) => (
            StatusCode::CREATED,
            Json(json!({ "id": forked.id, "title": forked.title, "forked_from": forked.forked_from, "forked_from_entry": forked.forked_from_entry })),
        )
            .into_response(),
        Err(ForkChatError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such chat" })),
        )
            .into_response(),
        Err(ForkChatError::SourceNotLive) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "source chat not live" })),
        )
            .into_response(),
        Err(ForkChatError::InstanceNotOpen) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "instance not open" })),
        )
            .into_response(),
        Err(ForkChatError::Create(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
        Err(ForkChatError::Continuity(e)) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": e })),
        )
            .into_response(),
        Err(ForkChatError::PointNotForkable) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "transcript entry is not a durable fork point" })),
        )
            .into_response(),
    }
}

/// Fork immediately before a durable user entry or immediately after a
/// durable assistant entry (ADR 0073).
pub async fn fork_chat_at(
    State(wb): State<SharedWorkbench>,
    Path((id, entry_id)): Path<(String, i64)>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    match wb.fork_chat_at(&id, entry_id) {
        Ok(forked) => (
            StatusCode::CREATED,
            Json(json!({
                "id": forked.id,
                "title": forked.title,
                "forked_from": forked.forked_from,
                "forked_from_entry": forked.forked_from_entry,
            })),
        )
            .into_response(),
        Err(ForkChatError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such chat" })),
        )
            .into_response(),
        Err(ForkChatError::PointNotForkable) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "transcript entry is not a durable fork point" })),
        )
            .into_response(),
        Err(ForkChatError::SourceNotLive) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "source chat not live" })),
        )
            .into_response(),
        Err(ForkChatError::InstanceNotOpen) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "instance not open" })),
        )
            .into_response(),
        Err(ForkChatError::Create(error)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": error })),
        )
            .into_response(),
        Err(ForkChatError::Continuity(error)) => {
            (StatusCode::CONFLICT, Json(json!({ "error": error }))).into_response()
        }
    }
}

// ---- chat delete / rename ------------------------------------------------

pub async fn delete_chat(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if wb.delete_chat_cascade(&id) {
        (StatusCode::OK, Json(json!({ "deleted": id }))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such chat" })),
        )
            .into_response()
    }
}

#[derive(Deserialize)]
pub struct RenameChat {
    pub title: String,
}

pub async fn rename_chat(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    Json(body): Json<RenameChat>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let Some(updated) = wb.rename_chat_record(&id, body.title) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such chat" })),
        )
            .into_response();
    };
    (
        StatusCode::OK,
        Json(json!({ "id": id, "title": updated.title })),
    )
        .into_response()
}

// ---- boundary acceptance (D-ATTEST / ADR 0040, ATTEST-7) -----------------

/// The optional attestation payload a participant presents when accepting an
/// *attested* boundary (ATTEST-2): the [`CodeMeasurement`] the host claims to run,
/// the freshness `nonce` the verifier issued, the opaque TEE report `quote_bytes`,
/// and — optionally — a `sealed_key_id` to release on the same verified evidence.
///
/// Absent entirely, the acceptance is *unattested*: the body carries only the
/// `participant` and the boundary admits an `Accept { evidence: None }` (ATTEST-2
/// requires no evidence on an unattested placement). Present, the route runs the
/// [`accept_boundary_attested`] gate so a bad quote never admits the acceptance.
#[derive(Deserialize)]
pub struct AttestationPayload {
    /// Lower-case hex of the reproducible-build image measurement the host proves.
    pub measurement: String,
    /// The freshness nonce the host echoed *inside* its quote report.
    pub nonce: String,
    /// The freshness challenge the verifier issued and requires the report to echo
    /// (anti-replay). Defaults to `nonce` when the caller does not separate them —
    /// a real flow carries a server-issued challenge from the attestation client; the
    /// loopback route lets a test supply a mismatching pair to exercise `StaleNonce`.
    #[serde(default)]
    pub expected_nonce: Option<String>,
    /// Opaque TEE-specific report bytes — parsed only behind the verifier seam.
    #[serde(default)]
    pub quote_bytes: Vec<u8>,
    /// The AMD **VCEK** (DER) endorsing the host chip/TCB, carried in the host's cert
    /// table alongside the report (ADR 0049). **Required** for the real SEV-SNP
    /// verifier path (`AttestationMode::RealRequired`); the built-in ARK/ASK roots
    /// chain to it. Ignored by the loopback verifier. Empty in `RealRequired` ⇒ `400`.
    #[serde(default)]
    pub vcek: Vec<u8>,
    /// A sealed key to release to the verified evidence, if one is requested.
    #[serde(default)]
    pub sealed_key_id: Option<String>,
}

#[derive(Deserialize)]
pub struct AcceptBoundary {
    /// The participant authority accepting the boundary (NO_GHOST_ACCEPT: it must
    /// be one of the proposed participants, or the reducer rejects).
    pub participant: String,
    /// Present iff this is an *attested* acceptance; absent ⇒ unattested.
    #[serde(default)]
    pub attestation: Option<AttestationPayload>,
}

fn boundary_accept_err(e: BoundaryAcceptError) -> axum::response::Response {
    match e {
        BoundaryAcceptError::PolicyRejected => (
            StatusCode::FORBIDDEN,
            Json(json!({
                "rejected": "org placement policy does not admit this boundary's declared deployment mode"
            })),
        )
            .into_response(),
        BoundaryAcceptError::Rejected(reason) => {
            (StatusCode::CONFLICT, Json(json!({ "rejected": reason }))).into_response()
        }
        BoundaryAcceptError::Store(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("{e:?}") })),
        )
            .into_response(),
        BoundaryAcceptError::QuoteRejected(reason) => {
            (StatusCode::BAD_REQUEST, Json(json!({ "rejected": reason }))).into_response()
        }
        BoundaryAcceptError::MissingVcek => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "rejected": "attested acceptance requires the host VCEK \
                             (DER) for SEV-SNP verification"
            })),
        )
            .into_response(),
        BoundaryAcceptError::RealVerifierUnavailable => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "rejected": "real attested acceptance is unavailable in this build"
            })),
        )
            .into_response(),
        BoundaryAcceptError::InvalidEndorsement(reason) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "rejected": format!("invalid endorsement material: {reason}") })),
        )
            .into_response(),
    }
}

fn boundary_attestation_input(att: AttestationPayload) -> BoundaryAttestationInput {
    BoundaryAttestationInput {
        measurement: att.measurement,
        nonce: att.nonce,
        expected_nonce: att.expected_nonce,
        quote_bytes: att.quote_bytes,
        vcek: att.vcek,
        sealed_key_id: att.sealed_key_id,
    }
}

pub async fn accept_boundary(
    State(wb): State<SharedWorkbench>,
    Path(bid): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<AcceptBoundary>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    // ITGOV-3(c): accepting a boundary admits a counterparty into this org's execution boundary
    // — in enterprise mode it must be an authenticated **active member** (ENTSEC-1); solo /
    // bootstrap is unchanged. Fail-closed (`INV-20`; ADR 0066 §C).
    if let Err((code, msg)) = wb.authenticate_request(crate::net_http::bearer(&headers)) {
        return (code, msg).into_response();
    }
    match wb.accept_boundary(
        &bid,
        body.participant,
        body.attestation.map(boundary_attestation_input),
    ) {
        Ok(out) => (StatusCode::OK, Json(out)).into_response(),
        Err(e) => boundary_accept_err(e),
    }
}

// A chat's kind (edit/work) is **fixed at creation** by what it is rooted on
// (ADR 0035): an edit chat is created under an archetype, a work chat under a
// placement. There is no mid-life toggle — the old `set_chat_mode` / `Use⇄Edit`
// control is removed.

// ---- device pairing (D-MOBILE / ADR 0009, MOB-027) -----------------------

/// `POST /pairing-requests` body: a paired device asks the owner to bind it to a
/// fresh boundary's bridge grant. The device presents its stable [`DeviceId`] and
/// the [`BridgeGrantId`] the grant was issued under — the typed `(device, grant)`
/// pair the boundary's `DeviceBinding` phase pins so a later federated delivery
/// must match exactly (MOB-001/MOB-004). The pairing scope (the boundary id) is
/// server-minted, so a request never names an existing boundary it could hijack.
#[derive(Deserialize)]
pub struct PairingRequest {
    /// The device asking to pair — its stable handle, presented by the client.
    pub device: String,
    /// The bridge grant the device pairs under. Defaults to a server-minted grant
    /// id when the caller does not supply one (the loopback flow mints both ends).
    #[serde(default)]
    pub bridge_grant: Option<String>,
}

/// `POST /pairing-requests` — open a device-pairing boundary and bind the device
/// to it in one step (MOB-027), driving the boundary lifecycle exactly as the rest
/// of the control plane does: `Propose` the owner authority as the sole required
/// participant, `DeclareCeiling` a local placement, then `BindDevice` the typed
/// `(DeviceId, BridgeGrantId)` so the boundary advances `Declared → DeviceBinding`.
///
/// The boundary id is the pairing id the client then polls via
/// `GET /pairing-status/:id`. A bind on a non-declared boundary, or a second bind
/// of a different device, is rejected by the reducer (no silent device swap) — the
/// route does not bypass `DEVICE_BINDS_DECLARED_BOUNDARY`.
pub async fn create_pairing_request(
    State(wb): State<SharedWorkbench>,
    Json(body): Json<PairingRequest>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    match wb.create_pairing_request(body.device, body.bridge_grant) {
        Ok(pairing) => (
            StatusCode::CREATED,
            Json(json!({
                "pairing_id": pairing.pairing_id,
                "device": pairing.device,
                "bridge_grant": pairing.bridge_grant,
                "status": pairing.status,
            })),
        )
            .into_response(),
        Err(e) => boundary_err(e),
    }
}

/// `GET /pairing-status/:id` — poll a pairing's progress (MOB-027). Reports the
/// boundary phase, whether the device has been bound, the typed `(device, grant)`
/// pinned by `DeviceBinding`, and whether the owner has accepted (the pairing is
/// `paired` once the boundary is active). A pairing id with no boundary is `404`.
pub async fn get_pairing_status(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    match wb.pairing_status_value(&id) {
        Ok(Some(status)) => (StatusCode::OK, Json(status)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such pairing" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("{e:?}") })),
        )
            .into_response(),
    }
}

/// Map an admission error from the pairing lifecycle to an HTTP response: a reducer
/// rejection (e.g. a second bind, a bind on a non-declared boundary) is a `409`, an
/// infrastructural error a `500`.
fn boundary_err(e: AdmitError) -> axum::response::Response {
    match e {
        AdmitError::Rejected(r) => {
            (StatusCode::CONFLICT, Json(json!({ "rejected": r.reason }))).into_response()
        }
        e => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("{e:?}") })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    //! `POST /boundaries/:bid/accept` (ATTEST-7): unattested and attested
    //! acceptance over the control-plane route, exercising the boundary keeper gate.
    //! These exercise only open routes (`/boundaries/*`, `/pairing-*`), so they
    //! compose the open control plane; the attested **operator** surface tests
    //! live with `gaugewright-cloud-attestation` (SPLIT-1).
    use super::UpdateProject;
    use crate::{open_control_plane, Workbench, LOCAL_AUTHORITY};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use gaugedesk_core::attestation::CodeMeasurement;
    use gaugedesk_core::boundary_lifecycle::{Operator, Placement};
    use http_body_util::BodyExt;
    use std::collections::BTreeSet;
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    };
    use tower::ServiceExt;

    const BID: &str = "boundary-chat-1";
    const PARTICIPANT_A: &str = "A";
    const PARTICIPANT_B: &str = "B";
    const MEASUREMENT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NONCE: &str = "challenge-1";

    #[test]
    fn project_run_purpose_distinguishes_omission_set_and_revocation() {
        let omitted: UpdateProject = serde_json::from_str("{}").unwrap();
        let set: UpdateProject = serde_json::from_str(r#"{"run_purpose":"support"}"#).unwrap();
        let revoked: UpdateProject = serde_json::from_str(r#"{"run_purpose":null}"#).unwrap();
        assert_eq!(omitted.run_purpose, None);
        assert_eq!(set.run_purpose, Some(Some("support".to_owned())));
        assert_eq!(revoked.run_purpose, Some(None));
    }

    /// A router whose store has a boundary at `BID` proposed for {A,B} and
    /// ceiling-declared with the given attestation posture. The operator has
    /// registered `MEASUREMENT` as a trusted reproducible build and sealed one key
    /// to it (ATTEST-13 wiring) — so an attested quote for `MEASUREMENT` verifies
    /// against the workbench's allow-list, and a quote for any other measurement does
    /// not.
    fn router_with_boundary(attested: bool) -> Router {
        // The loopback/dev shape (C-3): opt into the in-process quote verifier.
        router_with_boundary_mode(attested, crate::AttestationMode::Loopback)
    }

    fn router_with_boundary_mode(attested: bool, mode: crate::AttestationMode) -> Router {
        let store = gaugedesk_store::Store::open_in_memory().unwrap();
        // ADR 0065: these tests drive the attested operator surface (`/engagements/:eid/attested-*`),
        // which is now gated off by default — opt it in for the suite.
        let mut wb = Workbench::new(store)
            .with_attestation_mode(mode)
            .with_attestation_enabled(true);
        let parts = BTreeSet::from([PARTICIPANT_A.to_string(), PARTICIPANT_B.to_string()]);
        wb.seed_boundary_for_test(
            BID,
            parts,
            Placement {
                operator: Operator::Counterparty,
                attested,
            },
        )
        .unwrap();
        wb.seed_attested_boundary_release_for_test(
            "registry/gaugewright-host",
            "1.0.0",
            CodeMeasurement::new(MEASUREMENT),
            "sealed-1",
            vec![9, 8, 7],
        );
        open_control_plane(Arc::new(Mutex::new(wb)))
    }

    /// DEPLOY-3 / ITGOV-3: the same boundary, declared `(Counterparty, attested=false)`,
    /// but with a configured org placement policy in the `org` scope — so the client's
    /// accept consults it (the policy-gated pairing path). No attestation wiring is needed
    /// because these exercise the unattested accept.
    fn router_with_boundary_and_policy(
        policy: gaugedesk_core::boundary_lifecycle::PlacementPolicy,
    ) -> Router {
        let store = gaugedesk_store::Store::open_in_memory().unwrap();
        let mut wb = Workbench::new(store);
        let parts = BTreeSet::from([PARTICIPANT_A.to_string(), PARTICIPANT_B.to_string()]);
        wb.seed_boundary_for_test(
            BID,
            parts,
            Placement {
                operator: Operator::Counterparty,
                attested: false,
            },
        )
        .unwrap();
        let rec = crate::org::PlacementPolicyRecord {
            id: "pp".into(),
            op: crate::org::RecordOp::Upsert,
            policy,
        };
        wb.seed_org_placement_policy_for_test(rec).unwrap();
        open_control_plane(Arc::new(Mutex::new(wb)))
    }

    async fn post(app: &Router, uri: &str, body: &str) -> (StatusCode, String) {
        static KEY: AtomicU64 = AtomicU64::new(1);
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .header(
                "idempotency-key",
                format!("library-route-test-{}", KEY.fetch_add(1, Ordering::Relaxed)),
            )
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// Unattested boundary: a named participant accepts with no attestation payload,
    /// and the acceptance is admitted (ATTEST-2: no evidence on an unattested placement).
    #[tokio::test]
    async fn accept_boundary_unattested_admits_named_participant() {
        let app = router_with_boundary(false);
        let (s, b) = post(
            &app,
            "/boundaries/boundary-chat-1/accept",
            r#"{"participant":"A"}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "got {b}");
        assert!(b.contains(r#""accepted":true"#), "A accepted: {b}");
        assert!(b.contains(r#""active":false"#), "still pending B: {b}");
    }

    /// DEPLOY-3 / ITGOV-3: an org placement policy whose `allowed_operators` excludes the
    /// boundary's declared operator refuses the client's accept (`403`) — restrict-only,
    /// fail-closed (`INV-20`). Proves the policy-gated pairing gate is wired to the live route.
    #[tokio::test]
    async fn accept_boundary_refused_when_org_placement_policy_excludes_operator() {
        use gaugedesk_core::boundary_lifecycle::PlacementPolicy;
        let policy = PlacementPolicy {
            require_attested: false,
            allowed_operators: BTreeSet::from([Operator::Local]),
        };
        let app = router_with_boundary_and_policy(policy);
        let (s, b) = post(
            &app,
            "/boundaries/boundary-chat-1/accept",
            r#"{"participant":"A"}"#,
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "got {b}");
        assert!(b.contains("placement policy"), "policy refusal: {b}");
    }

    /// A policy that admits the declared (Counterparty) operator lets the accept through —
    /// the gate narrows, it does not block a compliant deployment mode.
    #[tokio::test]
    async fn accept_boundary_admitted_when_org_placement_policy_allows_operator() {
        use gaugedesk_core::boundary_lifecycle::PlacementPolicy;
        let policy = PlacementPolicy {
            require_attested: false,
            allowed_operators: BTreeSet::from([Operator::Counterparty]),
        };
        let app = router_with_boundary_and_policy(policy);
        let (s, b) = post(
            &app,
            "/boundaries/boundary-chat-1/accept",
            r#"{"participant":"A"}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "got {b}");
        assert!(b.contains(r#""accepted":true"#), "A accepted: {b}");
    }

    /// ITGOV-3(c): accepting a boundary admits a counterparty into this org's execution boundary.
    /// In enterprise mode (IdP + provisioned directory) an anonymous accept is `401`; a valid
    /// active member is let through. Solo mode is covered by the other accept tests (no bearer, OK).
    #[tokio::test]
    async fn accept_boundary_requires_member_auth_in_enterprise_mode() {
        use crate::identity::LoopbackIdentityProvider;
        use crate::org::{MembershipRecord, MembershipStatus, RecordOp, ORG_SCOPE};
        use gaugedesk_core::abac::AuthorityAttributes;
        use gaugedesk_core::ids::AuthorityId;

        let idp = LoopbackIdentityProvider::new().enroll(
            "member-token",
            AuthorityId::new("member-auth"),
            AuthorityAttributes::default(),
        );
        let mut wb = Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap())
            .with_identity_provider(Arc::new(idp));
        let parts = BTreeSet::from([PARTICIPANT_A.to_string(), PARTICIPANT_B.to_string()]);
        wb.seed_boundary_for_test(
            BID,
            parts,
            Placement {
                operator: Operator::Counterparty,
                attested: false,
            },
        )
        .unwrap();
        // Provision an active member so the gate engages (past bootstrap).
        let member = MembershipRecord {
            id: "member-auth".into(),
            op: RecordOp::Upsert,
            org_id: "org".into(),
            authority: "member-auth".into(),
            email: "m@e.com".into(),
            role: "member".into(),
            status: MembershipStatus::Active,
            managed_by_scim: false,
            team: None,
        };
        wb.store_mut()
            .append_record(
                ORG_SCOPE,
                "membership",
                &serde_json::to_string(&member).unwrap(),
            )
            .unwrap();
        let app = open_control_plane(Arc::new(Mutex::new(wb)));

        let accept = |bearer: Option<&str>| {
            let mut b = Request::builder()
                .method("POST")
                .uri("/boundaries/boundary-chat-1/accept")
                .header("content-type", "application/json")
                .header("idempotency-key", "enterprise-boundary-accept");
            if let Some(t) = bearer {
                b = b.header("authorization", format!("Bearer {t}"));
            }
            b.body(Body::from(r#"{"participant":"A"}"#)).unwrap()
        };

        let resp = app.clone().oneshot(accept(None)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "an anonymous boundary-accept is refused in enterprise mode"
        );
        let resp = app.oneshot(accept(Some("member-token"))).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a valid member is let through the auth gate"
        );
    }

    /// Both participants accepting an unattested boundary brings it active — the route
    /// drives the conjunctive activation end to end.
    #[tokio::test]
    async fn accept_boundary_unattested_both_participants_activates() {
        let app = router_with_boundary(false);
        post(
            &app,
            "/boundaries/boundary-chat-1/accept",
            r#"{"participant":"A"}"#,
        )
        .await;
        let (s, b) = post(
            &app,
            "/boundaries/boundary-chat-1/accept",
            r#"{"participant":"B"}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "got {b}");
        assert!(b.contains(r#""active":true"#), "boundary active: {b}");
    }

    /// A ghost participant (not proposed) is rejected by the reducer — the route does
    /// not bypass NO_GHOST_ACCEPT.
    #[tokio::test]
    async fn accept_boundary_rejects_ghost_participant() {
        let app = router_with_boundary(false);
        let (s, b) = post(
            &app,
            "/boundaries/boundary-chat-1/accept",
            r#"{"participant":"ghost"}"#,
        )
        .await;
        assert_eq!(s, StatusCode::CONFLICT, "got {b}");
    }

    /// Attested boundary: a fresh quote for the trusted measurement verifies, and the
    /// acceptance is admitted with evidence (the keeper gate, ATTEST-5).
    #[tokio::test]
    async fn accept_boundary_attested_verified_quote_admits() {
        let app = router_with_boundary(true);
        let body = serde_json::json!({
            "participant": PARTICIPANT_A,
            "attestation": { "measurement": MEASUREMENT, "nonce": NONCE, "quote_bytes": [1, 2, 3, 4] }
        })
        .to_string();
        let (s, b) = post(&app, "/boundaries/boundary-chat-1/accept", &body).await;
        assert_eq!(s, StatusCode::OK, "got {b}");
        assert!(b.contains(r#""accepted":true"#), "A attested-accepted: {b}");
        assert!(
            b.contains(r#""ceiling""#),
            "ceiling projection present: {b}"
        );
    }

    /// C-3 fail-closed default (ADR 0049): in `RealRequired` mode (the default for any
    /// real deployment) the attested-accept route routes to the real SEV-SNP verifier,
    /// never the loopback stand-in. With no host VCEK on the request it cannot build the
    /// AMD chain, so it refuses with `400` rather than fall back to loopback or release
    /// a key — the loopback verifier can never gate a live key release.
    #[tokio::test]
    async fn accept_boundary_attested_real_required_needs_vcek() {
        let app = router_with_boundary_mode(true, crate::AttestationMode::RealRequired);
        let body = serde_json::json!({
            "participant": PARTICIPANT_A,
            // No `vcek` ⇒ the SEV-SNP path cannot verify; fail-closed.
            "attestation": { "measurement": MEASUREMENT, "nonce": NONCE, "quote_bytes": [1, 2, 3, 4] }
        })
        .to_string();
        let (s, b) = post(&app, "/boundaries/boundary-chat-1/accept", &body).await;
        assert_eq!(
            s,
            StatusCode::BAD_REQUEST,
            "real-required mode must refuse without a VCEK, not fall back to loopback: {b}"
        );
        assert!(
            b.contains("VCEK"),
            "structured VCEK-required rejection: {b}"
        );
        // The boundary did not advance — nothing was accepted, no key released.
        assert!(!b.contains(r#""accepted":true"#), "must not accept: {b}");
    }

    /// The ATTEST-13 wiring tooth: the verifier trusts the *operator-registered*
    /// allow-list, not the measurement the caller claims. A quote for a measurement
    /// the operator never registered is `UnknownMeasurement` → 400, even though it is
    /// a well-formed quote echoing the right nonce — the caller cannot self-assert a
    /// host into the trusted set.
    #[tokio::test]
    async fn accept_boundary_attested_unregistered_measurement_is_rejected() {
        let app = router_with_boundary(true);
        let untrusted = "b".repeat(64);
        let body = serde_json::json!({
            "participant": PARTICIPANT_A,
            "attestation": { "measurement": untrusted, "nonce": NONCE, "quote_bytes": [1, 2, 3, 4] }
        })
        .to_string();
        let (s, b) = post(&app, "/boundaries/boundary-chat-1/accept", &body).await;
        assert_eq!(
            s,
            StatusCode::BAD_REQUEST,
            "unregistered measurement rejects: {b}"
        );
        assert!(
            b.contains("UnknownMeasurement"),
            "structured rejection: {b}"
        );
    }

    /// ADR 0048 — the gate, end to end through the route: the *same* attested request
    /// that releases a key when the engagement is entitled releases **nothing** when it
    /// is not. Acceptance still admits (attestation is sound); only the key is gated.
    #[tokio::test]
    async fn accept_boundary_attested_without_entitlement_releases_no_key() {
        let app = router_with_boundary(true);
        // No entitlement activated for this engagement.
        let body = serde_json::json!({
            "participant": PARTICIPANT_A,
            "attestation": {
                "measurement": MEASUREMENT,
                "nonce": NONCE,
                "quote_bytes": [1, 2, 3, 4],
                "sealed_key_id": "sealed-1"
            }
        })
        .to_string();
        let (s, b) = post(&app, "/boundaries/boundary-chat-1/accept", &body).await;
        assert_eq!(s, StatusCode::OK, "acceptance still admits: {b}");
        assert!(
            b.contains(r#""accepted":true"#),
            "participant accepted: {b}"
        );
        assert!(
            b.contains(r#""released":false"#),
            "unentitled engagement releases no key: {b}"
        );
    }

    /// Attested boundary, stale nonce: the verifier rejects the quote, the route
    /// returns 400, and the acceptance is never admitted.
    #[tokio::test]
    async fn accept_boundary_attested_stale_nonce_is_rejected() {
        let app = router_with_boundary(true);
        let body = serde_json::json!({
            "participant": PARTICIPANT_A,
            "attestation": {
                "measurement": MEASUREMENT,
                "nonce": "stale",
                "expected_nonce": NONCE,
                "quote_bytes": [1, 2, 3, 4]
            }
        })
        .to_string();
        let (s, b) = post(&app, "/boundaries/boundary-chat-1/accept", &body).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "stale nonce rejects: {b}");
        assert!(b.contains("StaleNonce"), "structured rejection: {b}");
    }

    /// An attested placement refuses an *unattested* acceptance: posting with no
    /// attestation payload drives `Accept { evidence: None }`, which the reducer
    /// rejects (ATTEST-2 requires evidence on an attested placement) → 409.
    #[tokio::test]
    async fn accept_boundary_attested_requires_evidence() {
        let app = router_with_boundary(true);
        let (s, b) = post(
            &app,
            "/boundaries/boundary-chat-1/accept",
            r#"{"participant":"A"}"#,
        )
        .await;
        assert_eq!(
            s,
            StatusCode::CONFLICT,
            "attested placement needs evidence: {b}"
        );
    }

    // ---- device pairing (MOB-027) ----------------------------------------

    /// A bare control plane over an empty in-memory workbench — the pairing routes
    /// mint their own boundary scope, so they need no pre-seeded boundary.
    fn bare_router() -> Router {
        let wb = Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap());
        open_control_plane(Arc::new(Mutex::new(wb)))
    }

    async fn get(app: &Router, uri: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// `POST /pairing-requests` opens a boundary, declares its ceiling, and binds
    /// the device in one step (MOB-027): the response carries the server-minted
    /// pairing id and the typed `(device, grant)` the `DeviceBinding` phase pinned,
    /// and the boundary sits in `DeviceBinding` awaiting the owner's acceptance.
    #[tokio::test]
    async fn pairing_request_binds_device_and_reports_status() {
        let app = bare_router();
        let (s, b) = post(
            &app,
            "/pairing-requests",
            r#"{"device":"device:pixel-9","bridge_grant":"grant-7"}"#,
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "got {b}");
        let v: serde_json::Value = serde_json::from_str(&b).unwrap();
        let pairing_id = v["pairing_id"].as_str().unwrap().to_string();
        assert!(
            pairing_id.starts_with("pairing-"),
            "server-minted pairing id: {b}"
        );
        assert_eq!(
            v["status"]["phase"], "DeviceBinding",
            "device bound, not yet accepted: {b}"
        );
        assert_eq!(
            v["status"]["bound"]["device"], "device:pixel-9",
            "typed device pinned: {b}"
        );
        assert_eq!(
            v["status"]["bound"]["bridge_grant"], "grant-7",
            "typed grant pinned: {b}"
        );
        assert_eq!(
            v["status"]["paired"], false,
            "not paired until the owner accepts: {b}"
        );

        // The status endpoint reports the same pinned binding for the minted id.
        let (s, b) = get(&app, &format!("/pairing-status/{pairing_id}")).await;
        assert_eq!(s, StatusCode::OK, "got {b}");
        let v: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(
            v["bound"]["device"], "device:pixel-9",
            "status reflects binding: {b}"
        );
        assert_eq!(v["paired"], false, "still pending the owner's accept: {b}");
    }

    /// The owner accepting the pairing boundary drives it active — at which point
    /// the pairing status flips to `paired` (MOB-027 ties the pairing handshake to
    /// the same boundary lifecycle the rest of the control plane rides).
    #[tokio::test]
    async fn pairing_completes_when_owner_accepts() {
        let app = bare_router();
        let (_, b) = post(
            &app,
            "/pairing-requests",
            r#"{"device":"device:pixel-9","bridge_grant":"grant-7"}"#,
        )
        .await;
        let v: serde_json::Value = serde_json::from_str(&b).unwrap();
        let pairing_id = v["pairing_id"].as_str().unwrap().to_string();

        // The owner authority accepts the pairing boundary (unattested, no evidence).
        let accept_body = serde_json::json!({ "participant": LOCAL_AUTHORITY }).to_string();
        let (s, b) = post(
            &app,
            &format!("/boundaries/{pairing_id}/accept"),
            &accept_body,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "owner accepts: {b}");

        let (s, b) = get(&app, &format!("/pairing-status/{pairing_id}")).await;
        assert_eq!(s, StatusCode::OK, "got {b}");
        let v: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(v["paired"], true, "active boundary ⇒ paired: {b}");
        assert_eq!(v["phase"], "Active", "boundary went active: {b}");
    }

    /// Status for a pairing id that was never opened is `404`, not a ghost `Init`
    /// pairing — a never-proposed boundary scope folds to the default state, which
    /// the route must not report as a real pairing.
    #[tokio::test]
    async fn pairing_status_unknown_id_is_not_found() {
        let app = bare_router();
        let (s, b) = get(&app, "/pairing-status/pairing-nope").await;
        assert_eq!(s, StatusCode::NOT_FOUND, "no such pairing: {b}");
    }

    /// A pairing request with no `bridge_grant` mints one server-side — the loopback
    /// flow provisions both ends, and the response surfaces the minted grant id so
    /// the client can present it on the later federated delivery (MOB-004).
    #[tokio::test]
    async fn pairing_request_mints_grant_when_absent() {
        let app = bare_router();
        let (s, b) = post(&app, "/pairing-requests", r#"{"device":"device:pixel-9"}"#).await;
        assert_eq!(s, StatusCode::CREATED, "got {b}");
        let v: serde_json::Value = serde_json::from_str(&b).unwrap();
        let grant = v["bridge_grant"].as_str().unwrap();
        assert!(grant.starts_with("grant-"), "server-minted grant id: {b}");
        assert_eq!(
            v["status"]["bound"]["bridge_grant"], grant,
            "bound under the minted grant: {b}"
        );
    }
}

#[cfg(test)]
mod search_tests {
    //! Content search: `GET /search?q=` folds chat transcripts (SEARCH-1, the
    //! chat-log tier) and runs a bounded walk of each chat's worktree files
    //! (SEARCH-2, the file-content tier) — tiers 2 and 3 of `navigation.md`
    //! "Search scope and relevance", each hit tagged with its `tier`.
    use crate::library::ChatRecord;
    use crate::stream::ServerEvent;
    use crate::{open_control_plane, Workbench};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use gaugedesk_store::Store;
    use gaugedesk_workspace::Instance;
    use http_body_util::BodyExt;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    async fn get(app: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    fn chat(id: &str, title: &str, pos: i64) -> ChatRecord {
        ChatRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: id.into(),
            op: Default::default(),
            instance_id: "i1".into(),
            title: title.into(),
            created_position: pos,
            forked_from: None,
            forked_from_entry: None,
            forked_from_cut: None,
        }
    }

    /// Two chats: chat-1's *log* mentions "bridge"/"deadline"; chat-2 only has
    /// "deadline" in its *title* (its log is unrelated).
    fn seed() -> axum::Router {
        let store = gaugedesk_store::Store::open_in_memory().unwrap();
        let mut wb = Workbench::new(store);
        wb.write_chat_record(chat("chat-1", "weekly sync", 0));
        wb.write_chat_transcript_event(
            "chat-1",
            ServerEvent::User {
                text: "please review the deadline for the bridge".into(),
            },
        )
        .unwrap();
        wb.write_chat_record(chat("chat-2", "deadline planning", 1));
        wb.write_chat_transcript_event(
            "chat-2",
            ServerEvent::Assistant {
                text: "nothing relevant in this log".into(),
            },
        )
        .unwrap();
        open_control_plane(Arc::new(Mutex::new(wb)))
    }

    #[tokio::test]
    async fn content_match_surfaces_chat_with_snippet() {
        let (status, v) = get(&seed(), "/search?q=bridge").await;
        assert_eq!(status, StatusCode::OK);
        let hits = v["hits"].as_array().unwrap();
        assert_eq!(hits.len(), 1, "only chat-1's log mentions bridge");
        assert_eq!(hits[0]["id"], "chat-1");
        assert!(hits[0]["snippet"].as_str().unwrap().contains("bridge"));
    }

    #[tokio::test]
    async fn search_is_case_insensitive_and_log_only() {
        // "DEADLINE" is in chat-1's log and chat-2's *title*; content search is
        // the log tier, so it returns chat-1 only (the title tier is client-side).
        let (_, v) = get(&seed(), "/search?q=DEADLINE").await;
        let ids: Vec<&str> = v["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["chat-1"]);
    }

    #[tokio::test]
    async fn empty_query_returns_no_hits() {
        let (status, v) = get(&seed(), "/search?q=").await;
        assert_eq!(status, StatusCode::OK);
        assert!(v["hits"].as_array().unwrap().is_empty());
    }

    // ---- SEARCH-2: the file-content tier (bounded worktree walk) --------------

    /// A router with one real chat on a live instance, holding the given worktree
    /// files. The chat's log is empty (nothing tasked), so a hit here can only come
    /// from the file tier. The `TempDir` must outlive the router (it owns the repo).
    fn router_with_worktree_files(files: &[(&str, &str)]) -> (tempfile::TempDir, axum::Router) {
        let dir = tempfile::tempdir().unwrap();
        let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let store = Store::open_in_memory().unwrap();
        let mut wb = Workbench::with_target("inst-test", instance, store);
        wb.create_default_engagement("chat-f".into(), "files chat".into())
            .unwrap_or_else(|_| panic!("create default engagement"));
        {
            // Write via the same path-confined worktree API the walk reads back through.
            let eng = wb.engagements.get("chat-f").unwrap();
            for (path, content) in files {
                eng.write_file(path, content).unwrap();
            }
        }
        (dir, open_control_plane(Arc::new(Mutex::new(wb))))
    }

    /// SEARCH-2: a term present only in a worktree file (not the title, not the log)
    /// surfaces the chat as a `file`-tier hit, carrying the file path and a snippet.
    #[tokio::test]
    async fn file_content_match_surfaces_chat_with_snippet() {
        let (_dir, app) =
            router_with_worktree_files(&[("notes/spec.md", "the WIDGETRON schematic lives here")]);
        let (status, v) = get(&app, "/search?q=widgetron").await;
        assert_eq!(status, StatusCode::OK);
        let hits = v["hits"].as_array().unwrap();
        assert_eq!(
            hits.len(),
            1,
            "only the worktree file mentions widgetron: {v}"
        );
        assert_eq!(hits[0]["id"], "chat-f");
        assert_eq!(hits[0]["tier"], "file");
        assert_eq!(hits[0]["path"], "notes/spec.md");
        let snippet = hits[0]["snippet"].as_str().unwrap();
        assert!(
            snippet.contains("WIDGETRON"),
            "snippet shows the hit: {snippet}"
        );
        assert!(
            snippet.contains("notes/spec.md"),
            "snippet leads with path: {snippet}"
        );
    }

    /// The walk skips **binary** files (null-byte sniff): a match inside a file with a
    /// NUL byte is not a content hit, so binary blobs never surface as noise.
    #[tokio::test]
    async fn binary_file_is_skipped_in_content_search() {
        let (_dir, app) =
            router_with_worktree_files(&[("blob.bin", "WIDGETRON\u{0}\u{1}\u{2}binary")]);
        let (status, v) = get(&app, "/search?q=widgetron").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            v["hits"].as_array().unwrap().is_empty(),
            "a NUL-bearing file is treated as binary and skipped: {v}"
        );
    }

    /// The per-file byte cap bounds the walk: a term past `FILE_SEARCH_MAX_BYTES` is
    /// never read, so it does not match — the walk stays no heavier than the log fold.
    #[tokio::test]
    async fn content_search_respects_per_file_byte_cap() {
        let mut big = "x".repeat(Workbench::FILE_SEARCH_MAX_BYTES);
        big.push_str("WIDGETRON"); // past the cap — outside the scanned prefix
        let (_dir, app) = router_with_worktree_files(&[("big.txt", &big)]);
        let (_status, v) = get(&app, "/search?q=widgetron").await;
        assert!(
            v["hits"].as_array().unwrap().is_empty(),
            "a term beyond the byte cap is not read, so not matched: {v}"
        );
    }

    /// The per-chat file cap bounds the walk: with more than `FILE_SEARCH_MAX_FILES`
    /// files, one whose (sorted) path falls past the cap is never scanned.
    #[tokio::test]
    async fn content_search_stops_after_per_chat_file_cap() {
        // FILE_SEARCH_MAX_FILES filler files sort before `zzz-last.txt`, which alone
        // carries the term — so the term-bearing file is beyond the scan cap.
        let mut files: Vec<(String, String)> = (0..Workbench::FILE_SEARCH_MAX_FILES)
            .map(|i| (format!("f{i:04}.txt"), "nothing to see".to_string()))
            .collect();
        files.push(("zzz-last.txt".into(), "the WIDGETRON is here".into()));
        let refs: Vec<(&str, &str)> = files
            .iter()
            .map(|(p, c)| (p.as_str(), c.as_str()))
            .collect();
        let (_dir, app) = router_with_worktree_files(&refs);
        let (_status, v) = get(&app, "/search?q=widgetron").await;
        assert!(
            v["hits"].as_array().unwrap().is_empty(),
            "the term-bearing file past the file cap is not scanned: {v}"
        );
    }

    /// Ordering (title > log > file): a chat whose **log** matches surfaces as a `log`
    /// hit and is not repeated as a `file` hit even when a worktree file also carries the
    /// term — the stronger tier wins per chat, so the row shows the log snippet once.
    #[tokio::test]
    async fn log_hit_suppresses_file_hit_for_same_chat() {
        let dir = tempfile::tempdir().unwrap();
        let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
        let store = Store::open_in_memory().unwrap();
        let mut wb = Workbench::with_target("inst-test", instance, store);
        wb.create_default_engagement("chat-both".into(), "both tiers".into())
            .unwrap_or_else(|_| panic!("create default engagement"));
        wb.engagements
            .get("chat-both")
            .unwrap()
            .write_file("note.txt", "the SENTINEL token in a file")
            .unwrap();
        // The same term also in the chat's log.
        wb.write_chat_transcript_event(
            "chat-both",
            ServerEvent::User {
                text: "please check the SENTINEL".into(),
            },
        )
        .unwrap();
        let app = open_control_plane(Arc::new(Mutex::new(wb)));
        let (status, v) = get(&app, "/search?q=sentinel").await;
        assert_eq!(status, StatusCode::OK);
        let hits = v["hits"].as_array().unwrap();
        assert_eq!(hits.len(), 1, "one hit per chat, log tier wins: {v}");
        assert_eq!(hits[0]["tier"], "log");
        assert!(
            hits[0]["path"].is_null(),
            "a log hit carries no file path: {v}"
        );
    }
}
