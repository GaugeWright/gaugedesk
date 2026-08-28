//! The workstream surface (`WS-E`): create / list / join / leave / archive / promote
//! the shared auto-sync lines within a placement.
//!
//! A workstream's *existence* is a durable library [`WorkstreamRecord`] (name + which
//! placement); its authoritative status + membership live in the per-workstream
//! [`WorkstreamState`] reducer (scope = the workstream id), folded on demand. Joining
//! re-homes a chat's worktree onto the stream main (`workstream/<id>/main`) so its turns
//! greedily auto-sync there (the engine hook, `WS-D`); leaving / archiving re-homes back
//! to the placement mainline. Promotion runs the boundary-gated `advanced → integrated`
//! merge hop into the mainline (`MAINLINE_INTEGRATION_REQUIRES_BOUNDARY`).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::library::{gen_id, RecordOp, WorkstreamRecord, WorkstreamRootRecord};
use crate::target_adapter::TargetActKind;
use crate::target_settlement::RequestedSettlementMember;
use crate::{LockUnpoisoned, SharedWorkbench, Workbench};
use gaugedesk_core::merge::{MergePhase, MergeState};
use gaugedesk_core::run::{RunPhase, RunState};
use gaugedesk_core::target_settlement::{
    SettlementMemberPhase, SettlementPhase, TargetSettlementState,
};
use gaugedesk_workspace::{MergeOutcome, WorkstreamTransferOutcome};
use whipplescript_store::workstreams::StreamStatus;

const PROMOTION_CONFLICT_PATHS: &str = "promotion_conflict_paths";

fn collaboration_projection(rec: &WorkstreamRecord, status: Option<StreamStatus>) -> &'static str {
    match status {
        Some(StreamStatus::Archived) => "promoted",
        Some(StreamStatus::BoundaryReserved | StreamStatus::RefAdvanced) => "promoting",
        Some(StreamStatus::Active) if rec.extra.contains_key(PROMOTION_CONFLICT_PATHS) => {
            "conflicted"
        }
        Some(StreamStatus::Active) => "active",
        None => "conflicted",
    }
}

fn target_settlement_projection(phase: Option<SettlementPhase>) -> &'static str {
    match phase {
        None
        | Some(
            SettlementPhase::Undeclared
            | SettlementPhase::Refused
            | SettlementPhase::Cancelled
            | SettlementPhase::Expired,
        ) => "not-requested",
        Some(
            SettlementPhase::Declared | SettlementPhase::Preflighting | SettlementPhase::Ready,
        ) => "preflighting",
        Some(SettlementPhase::Applying) => "applying",
        Some(SettlementPhase::Completed) => "completed",
        Some(SettlementPhase::PartiallyApplied) => "partially-applied",
        Some(SettlementPhase::ReconciliationRequired) => "reconciliation-required",
        Some(SettlementPhase::Compensated) => "compensated",
        Some(SettlementPhase::AbandonedPartial) => "abandoned-partial",
    }
}

fn settlement_member_projection(phase: SettlementMemberPhase) -> &'static str {
    match phase {
        SettlementMemberPhase::Pending => "pending",
        SettlementMemberPhase::PreflightPassed => "preflight-passed",
        SettlementMemberPhase::Started => "started",
        SettlementMemberPhase::Succeeded => "succeeded",
        SettlementMemberPhase::Failed => "failed",
        SettlementMemberPhase::Unknown => "unknown",
        SettlementMemberPhase::CancelledBeforeStart => "cancelled-before-start",
        SettlementMemberPhase::SupersededBeforeStart => "superseded-before-start",
    }
}

fn clear_promotion_conflict(wb: &mut Workbench, workstream_id: &str) {
    let Some(mut record) = wb.library.workstreams.get(workstream_id).cloned() else {
        return;
    };
    if record.extra.remove(PROMOTION_CONFLICT_PATHS).is_some() {
        wb.write_workstream_record(record);
    }
}

fn record_promotion_conflict(wb: &mut Workbench, workstream_id: &str, paths: &[String]) {
    let Some(mut record) = wb.library.workstreams.get(workstream_id).cloned() else {
        return;
    };
    record
        .extra
        .insert(PROMOTION_CONFLICT_PATHS.to_owned(), json!(paths));
    wb.write_workstream_record(record);
}

/// Whether a rendered provider diff contains collaborative workspace changes.
/// `.agent-config.json` is a host-owned per-chat overlay, preserved across re-home;
/// it is not a candidate against the shared line.
fn diff_has_shared_line_changes(diff: &str) -> bool {
    diff.lines()
        .filter_map(|line| line.strip_prefix("diff --git a/"))
        .filter_map(|line| line.split_once(" b/").map(|(path, _)| path))
        .any(|path| path != gaugedesk_boundary::definition::CONFIG_PATH)
}

#[derive(Deserialize)]
pub struct CreateWorkstreamBody {
    pub name: String,
    /// Accepted only as a compatibility hint. Project workstreams are rooted in
    /// the collaboration workspace, never in one selected target.
    #[serde(default)]
    pub target_id: Option<String>,
}

#[derive(Deserialize)]
pub struct MemberBody {
    pub chat: String,
}

#[derive(Default, Deserialize)]
pub struct PromoteWorkstreamBody {
    #[serde(default)]
    pub settlement_members: Vec<WorkstreamSettlementMemberBody>,
}

#[derive(Deserialize)]
pub struct WorkstreamSettlementMemberBody {
    pub target_id: String,
    pub act: TargetActKind,
}

#[derive(Deserialize)]
pub struct CreateWorkstreamSettlementBody {
    #[serde(default)]
    pub promotion_manifest_ref: Option<String>,
    pub members: Vec<WorkstreamSettlementMemberBody>,
}

impl Workbench {
    /// Rebuild the in-memory chat target tokens from WhippleScript's durable
    /// branch-home receipts. GaugeDesk reducers are not a second membership
    /// authority.
    pub fn restore_workstream_homing(&mut self) {
        let chats = self.engagement_index.keys().cloned().collect::<Vec<_>>();
        for chat in chats {
            let Some(storage_id) = self.engagement_index.get(&chat).cloned() else {
                continue;
            };
            let Some(workspace) = self.workspace_by_storage_id(&storage_id) else {
                continue;
            };
            let Ok(home) = workspace.engagement_home_receipt(&chat) else {
                continue;
            };
            let target = home
                .line_branch_id
                .unwrap_or_else(|| workspace.mainline().to_owned());
            self.set_engagement_target(&chat, target);
        }
    }

    /// Re-home a chat's engagement onto a shared ref — joining a workstream
    /// (`workstream/<id>/main`) or leaving it back to `main` (`WS-E`). The membership
    /// authority is the [`WorkstreamState`] reducer; this updates the in-memory
    /// worktree target the auto-sync hook and the merge surface read. A no-op if the
    /// chat has no live engagement.
    pub fn set_engagement_target(&mut self, chat_id: &str, target: impl Into<String>) {
        self.set_live_engagement_target(chat_id, target);
    }

    /// Re-home a settled chat onto another line in its immutable workspace root.
    /// The provider refuses a live candidate and rematerializes the destination cut,
    /// so changing membership cannot smuggle the old line's files into the new one.
    fn rehome_engagement(&mut self, chat_id: &str, target: &str) -> Result<(), String> {
        if self.engagement_rehome_blocked(chat_id) {
            return Err(
                "chat has active or unsettled workspace changes; settle or discard them before moving"
                    .into(),
            );
        }
        self.engagements
            .get_mut(chat_id)
            .ok_or_else(|| "chat has no live workspace".to_string())?
            .rehome(target)
            .map_err(|error| error.to_string())
    }

    /// Fail-closed transfer eligibility shared by admission and the navigation
    /// projection. The provider diff catches manual edits; lifecycle folds catch the
    /// pre-write part of a running turn and explicit review/conflict candidates.
    pub(crate) fn engagement_rehome_blocked(&self, chat_id: &str) -> bool {
        let run_active = self
            .store_ref()
            .fold::<RunState>(chat_id)
            .map(|run| {
                matches!(
                    run.phase,
                    RunPhase::Requested | RunPhase::Admitted | RunPhase::Running
                )
            })
            // A freshly created chat has no run events yet; that is the lifecycle's
            // default Idle state, not an unknown active turn.
            .unwrap_or(false);
        let candidate_active = self
            .store_ref()
            .fold::<MergeState>(chat_id)
            .map(|merge| {
                matches!(
                    merge.phase,
                    MergePhase::Merging
                        | MergePhase::Clean
                        | MergePhase::Rejected
                        | MergePhase::Repairing
                )
            })
            // Likewise, no merge events means the default Idle candidate state.
            .unwrap_or(false);
        let workspace_dirty = self
            .engagement_diff(chat_id)
            .and_then(Result::ok)
            .map(|diff| diff_has_shared_line_changes(&diff))
            .unwrap_or(true);
        run_active || candidate_active || workspace_dirty
    }

    /// Create the native shared workstream line under an open managed target.
    pub fn create_workstream_ref(
        &self,
        storage_id: &str,
        workstream_id: &str,
    ) -> std::io::Result<()> {
        self.workspace_by_storage_id(storage_id)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "workspace missing"))?
            .create_named_workstream(workstream_id, None)
            .map_err(crate::io)
    }

    /// Append a workstream declaration to the library log, apply it to the in-memory
    /// projection, and publish the workspace-change reference (`INV-10`).
    pub fn write_workstream(&mut self, record: WorkstreamRecord) -> i64 {
        self.write_workstream_record(record)
    }

    pub fn write_workstream_root(&mut self, record: WorkstreamRootRecord) {
        self.write_workstream_root_record(record);
    }

    /// Re-stamp the just-written workstream record with its durable library
    /// position so navigation ordering is stable.
    pub fn restamp_workstream_position(&mut self, workstream_id: &str, position: i64) {
        self.library_restamp_workstream_position(workstream_id, position);
    }

    /// Live workstream records for a placement.
    pub fn workstreams_in(&self, instance_id: &str) -> Vec<&WorkstreamRecord> {
        self.library_workstreams_in(instance_id)
    }

    /// A cloned workstream declaration, if this workbench knows it.
    pub fn workstream(&self, workstream_id: &str) -> Option<WorkstreamRecord> {
        self.library_workstream(workstream_id)
    }

    pub fn workstream_root(&self, workstream_id: &str) -> Option<WorkstreamRootRecord> {
        self.library_workstream_root(workstream_id)
    }

    /// Whether this workbench knows a workstream declaration.
    pub fn has_workstream(&self, workstream_id: &str) -> bool {
        self.library_has_workstream(workstream_id)
    }

    fn workstream_workspace(
        &self,
        workstream_id: &str,
    ) -> Option<&dyn gaugedesk_workspace::Workspace> {
        let root = self.library_workstream_root(workstream_id)?;
        self.workspace_by_storage_id(&root.workspace_id)
    }

    /// WhippleScript-authoritative member chat ids.
    pub fn workstream_members(&self, workstream_id: &str) -> Vec<String> {
        self.workstream_workspace(workstream_id)
            .and_then(|workspace| workspace.workstream_members(workstream_id).ok())
            .unwrap_or_default()
    }

    /// The managed target id that owns a chat's live candidate workspace.
    pub fn engagement_target_id(&self, chat_id: &str) -> Option<&str> {
        self.live_engagement_target_id(chat_id)
    }

    /// The placement that admitted this live engagement. The work target is a
    /// separate boundary and is available through [`engagement_target_id`].
    pub fn engagement_placement_id(&self, chat_id: &str) -> Option<&str> {
        self.library_chat_placement(chat_id)
    }

    pub fn chat_placement_id(&self, chat_id: &str) -> Option<&str> {
        self.library_chat_placement(chat_id)
    }

    /// Promote a workstream ref into project collaboration Main.
    pub fn promote_workstream_ref_to_main(
        &self,
        workstream_id: &str,
        storage_id: &str,
    ) -> std::io::Result<MergeOutcome> {
        self.workspace_by_storage_id(storage_id)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "workspace missing"))?
            .promote_workstream_to_main(workstream_id)
            .map_err(crate::io)
    }

    /// Refresh every live chat still homed to a target's implicit Main after that
    /// mainline advances. Promotion updates the managed target store; without this
    /// reconciliation, existing Main chat worktrees keep their old cut and make a
    /// successful promotion look like a no-op in the workbench.
    fn sync_mainline_members(&self, storage_id: &str) -> Vec<String> {
        let Some(mainline) = self
            .workspace_by_storage_id(storage_id)
            .map(|workspace| workspace.mainline())
        else {
            return Vec::new();
        };
        self.engagements
            .iter()
            .filter(|(chat_id, engagement)| {
                self.engagement_target_id(chat_id) == Some(storage_id)
                    && engagement.target() == mainline
            })
            .map(|(chat_id, engagement)| {
                let _ = engagement.sync_from_main();
                chat_id.clone()
            })
            .collect()
    }
}

// ---- POST /placements/:iid/workstreams -----------------------------------

/// Create a named workstream in a placement (a user **or** an agent may call this).
/// Branches `workstream/<id>/main` off the placement mainline, admits `CreateWorkstream`
/// on the new workstream scope, and records the nav declaration.
pub async fn create_workstream(
    State(wb): State<SharedWorkbench>,
    Path(iid): Path<String>,
    Json(body): Json<CreateWorkstreamBody>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let Some(project_id) = wb.placement_project_id(&iid).map(str::to_owned) else {
        return (
            StatusCode::BAD_REQUEST,
            "workstream creator is not a project placement",
        )
            .into_response();
    };
    if let Some(target_id) = body.target_id.as_deref() {
        if let Err(error) = wb.resolve_placement_target(&iid, Some(target_id)) {
            return (StatusCode::BAD_REQUEST, error).into_response();
        }
    }
    let Some(collaboration) = wb
        .library
        .project_collaboration_workspaces
        .get(&project_id)
        .cloned()
    else {
        return (
            StatusCode::CONFLICT,
            "project collaboration workspace is unavailable",
        )
            .into_response();
    };
    let ws_id = gen_id("ws");
    let Some(workspace) = wb.workspace_by_storage_id(&collaboration.workspace_id) else {
        return (
            StatusCode::CONFLICT,
            "project collaboration workspace is not open",
        )
            .into_response();
    };
    if let Err(e) = workspace.create_named_workstream(&ws_id, Some(&body.name)) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response();
    }
    let record = WorkstreamRecord {
        schema: crate::library::LIBRARY_RECORD_SCHEMA,
        extra: Default::default(),
        id: ws_id.clone(),
        op: RecordOp::Upsert,
        instance_id: iid.clone(),
        name: body.name.clone(),
        created_position: 0,
    };
    let pos = wb.write_workstream(record.clone());
    wb.write_workstream_root(WorkstreamRootRecord {
        schema: crate::library::LIBRARY_RECORD_SCHEMA,
        extra: Default::default(),
        workstream_id: ws_id.clone(),
        op: RecordOp::Upsert,
        placement_id: iid,
        project_id,
        workspace_id: collaboration.workspace_id,
        target_id: String::new(),
        adapter_family: String::new(),
    });
    // Re-stamp the record's position so nav ordering is stable (mirrors create_chat_in).
    wb.restamp_workstream_position(&ws_id, pos);
    (StatusCode::CREATED, Json(workstream_json(&wb, &record))).into_response()
}

// ---- GET /placements/:iid/workstreams ------------------------------------

/// List a placement's workstreams with folded status + members.
pub async fn list_workstreams(
    State(wb): State<SharedWorkbench>,
    Path(iid): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let out: Vec<_> = wb
        .workstreams_in(&iid)
        .iter()
        .map(|w| workstream_json(&wb, w))
        .collect();
    Json(json!({ "workstreams": out })).into_response()
}

/// One workstream's projection: name + status + member chat ids (folded from the
/// reducer). Shared by the list route and the workspace tree.
pub fn workstream_json(wb: &Workbench, rec: &WorkstreamRecord) -> serde_json::Value {
    let root = wb
        .workstream_root(&rec.id)
        .expect("validated workstream has a collaboration root");
    let topology = wb
        .workspace_by_storage_id(&root.workspace_id)
        .and_then(|workspace| workspace.workstream(&rec.id).ok().flatten());
    let status = collaboration_projection(rec, topology.as_ref().map(|row| row.status));
    let members = wb.workstream_members(&rec.id);
    let promotion_manifest = wb
        .workstream_promotion_manifests(&rec.id)
        .ok()
        .and_then(|manifests| manifests.last().cloned());
    let target_settlement = wb.latest_workstream_target_settlement(&rec.id);
    let settlement_members = target_settlement
        .as_ref()
        .and_then(|state| {
            state.declaration.as_ref().map(|declaration| {
                declaration.members.iter().map(|member| json!({
                "member_id": member.member_id,
                "target_id": member.target_id,
                "act": member.act,
                "phase": state.members.get(&member.member_id).map(|member| settlement_member_projection(member.phase)),
            })).collect::<Vec<_>>()
            })
        })
        .unwrap_or_default();
    json!({
        "id": rec.id,
        "name": rec.name,
        "placement_id": rec.instance_id,
        "project_id": root.project_id,
        "workspace_root": root.workspace_id,
        "target_id": serde_json::Value::Null,
        "adapter_family": "whipplescript-project-v1",
        "status": status,
        "collaboration": status,
        "members": members,
        "expected_stream_cut": topology.as_ref().and_then(|row| row.expected_line_cut.clone()),
        "expected_main_cut": topology.as_ref().and_then(|row| row.expected_main_cut.clone()),
        "promotion_receipt": topology.and_then(|row| row.boundary_receipt(&root.workspace_id)),
        "promotion_manifest_ref": promotion_manifest.as_ref().map(|manifest| manifest.id.clone()),
        "promotion_targets": promotion_manifest.as_ref().map(|manifest| manifest.partitions.iter().map(|partition| partition.target_id.clone()).collect::<Vec<_>>()).unwrap_or_default(),
        "target_settlement": target_settlement_projection(target_settlement.as_ref().map(|state| state.phase)),
        "target_settlement_declaration": target_settlement
            .as_ref().and_then(|state| state.declaration.as_ref().map(|declaration| declaration.declaration_id.clone())),
        "target_settlement_members": settlement_members,
    })
}

// ---- POST /workstreams/:id/join ------------------------------------------

/// Transfer a chat onto a workstream's main — it now greedily auto-syncs there.
/// Membership is project topology: joining this line removes the branch from
/// its prior named line in the same collaboration workspace. Target selection
/// and placement do not participate in workstream identity.
pub async fn join_workstream(
    State(wb): State<SharedWorkbench>,
    Path(ws_id): Path<String>,
    Json(body): Json<MemberBody>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if !wb.has_workstream(&ws_id) {
        return (StatusCode::NOT_FOUND, "no such workstream").into_response();
    }
    let Some(root) = wb.workstream_root(&ws_id) else {
        return (StatusCode::CONFLICT, "workstream target root is unresolved").into_response();
    };
    if wb.library_project_of_chat(&body.chat).as_deref() != Some(root.project_id.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            "chat is not in this workstream's project",
        )
            .into_response();
    }
    let Some(workspace) = wb.workspace_by_storage_id(&root.workspace_id) else {
        return (
            StatusCode::CONFLICT,
            "project collaboration workspace is unavailable",
        )
            .into_response();
    };
    let Some(topology) = workspace.workstream(&ws_id).ok().flatten() else {
        return (StatusCode::CONFLICT, "workstream topology is unavailable").into_response();
    };
    if topology.status != StreamStatus::Active {
        return (StatusCode::CONFLICT, "workstream is not active").into_response();
    }
    if wb.engagement_rehome_blocked(&body.chat) {
        return (
            StatusCode::CONFLICT,
            "chat has active or unsettled workspace changes; settle or discard them before moving",
        )
            .into_response();
    }
    let transfer = match workspace.transfer_engagement_to_workstream(&body.chat, &ws_id) {
        Ok(outcome) => outcome,
        Err(error) => return (StatusCode::CONFLICT, error.to_string()).into_response(),
    };
    if !matches!(transfer, WorkstreamTransferOutcome::Joined { .. }) {
        return (
            StatusCode::CONFLICT,
            format!("WhippleScript workstream transfer refused: {transfer:?}"),
        )
            .into_response();
    }
    if let Err(error) = wb.rehome_engagement(&body.chat, &topology.line_branch_id) {
        if let Some(workspace) = wb.workspace_by_storage_id(&root.workspace_id) {
            let _ = workspace.leave_engagement_workstream(&body.chat);
        }
        return (StatusCode::CONFLICT, error).into_response();
    }
    if let WorkstreamTransferOutcome::Joined {
        left_stream_id: Some(prior),
    } = transfer
    {
        wb.notify_library_changed("workstream", &prior, "upsert");
    }
    wb.notify_library_changed("workstream", &ws_id, "upsert");
    wb.notify_library_changed("chat", &body.chat, "upsert");
    (StatusCode::OK, Json(json!({ "joined": body.chat }))).into_response()
}

// ---- POST /workstreams/:id/leave -----------------------------------------

/// Re-home a chat back to the placement mainline (leave the workstream). Clear every
/// active named membership for this chat, not merely the route's stream id, so a leave
/// repairs any stale duplicate state left by older clients (ADR 0087).
pub async fn leave_workstream(
    State(wb): State<SharedWorkbench>,
    Path(ws_id): Path<String>,
    Json(body): Json<MemberBody>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if !wb.has_workstream(&ws_id) {
        return (StatusCode::NOT_FOUND, "no such workstream").into_response();
    }
    let Some(root) = wb.workstream_root(&ws_id) else {
        return (
            StatusCode::CONFLICT,
            "workstream collaboration root is unresolved",
        )
            .into_response();
    };
    if wb.library_project_of_chat(&body.chat).as_deref() != Some(root.project_id.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            "chat is not in this workstream's project",
        )
            .into_response();
    }
    let Some(workspace) = wb.workspace_by_storage_id(&root.workspace_id) else {
        return (
            StatusCode::CONFLICT,
            "project collaboration workspace is unavailable",
        )
            .into_response();
    };
    let home = match workspace.engagement_home_receipt(&body.chat) {
        Ok(home) => home,
        Err(error) => return (StatusCode::CONFLICT, error.to_string()).into_response(),
    };
    if home.stream_id.as_deref() != Some(ws_id.as_str()) {
        return (
            StatusCode::CONFLICT,
            "chat is not a member of this active workstream",
        )
            .into_response();
    }
    if wb.engagement_rehome_blocked(&body.chat) {
        return (
            StatusCode::CONFLICT,
            "chat has active or unsettled workspace changes; settle or discard them before moving",
        )
            .into_response();
    }
    let mainline = workspace.mainline().to_owned();
    if let Err(error) = workspace.leave_engagement_workstream(&body.chat) {
        return (StatusCode::CONFLICT, error.to_string()).into_response();
    }
    if let Err(error) = wb.rehome_engagement(&body.chat, &mainline) {
        if let Some(workspace) = wb.workspace_by_storage_id(&root.workspace_id) {
            let _ = workspace.transfer_engagement_to_workstream(&body.chat, &ws_id);
        }
        return (StatusCode::CONFLICT, error).into_response();
    }
    wb.notify_library_changed("chat", &body.chat, "upsert");
    wb.notify_library_changed("workstream", &ws_id, "upsert");
    (StatusCode::OK, Json(json!({ "left": body.chat }))).into_response()
}

// ---- POST /workstreams/:id/archive ---------------------------------------

/// Archive a workstream: re-home every member back to the placement mainline, then
/// drive the reducer's terminal `archive` (which empties membership). The bounded
/// escape (`INV-23`) — no chat is left auto-syncing into a dead ref. Legacy duplicate
/// memberships are cleared from sibling streams too, so archive cannot reveal a stale
/// alternate target.
fn archive_active_workstream(
    wb: &mut Workbench,
    rec: &WorkstreamRecord,
) -> Result<Vec<String>, String> {
    let ws_id = &rec.id;
    let root = wb
        .workstream_root(ws_id)
        .ok_or_else(|| "workstream collaboration root is unresolved".to_owned())?;
    // The members to re-home, read from the reducer before it empties them. Refuse
    // the whole operation before changing membership when any chat still owns a
    // candidate; archive is not an implicit discard command.
    let members = wb.workstream_members(ws_id);
    for chat in &members {
        if wb.engagement_rehome_blocked(chat) {
            return Err(format!(
                "chat {chat} has active or unsettled workspace changes; settle or discard them before closing the workstream"
            ));
        }
    }
    let workspace = wb
        .workspace_by_storage_id(&root.workspace_id)
        .ok_or_else(|| "project collaboration workspace is unavailable".to_owned())?;
    let mainline = workspace.mainline().to_owned();
    workspace
        .archive_workstream(ws_id)
        .map_err(|error| error.to_string())?;
    // WhippleScript has already made archive terminal and atomically re-homed
    // topology. Materialization is forward-only recovery from that fact.
    for chat in &members {
        wb.rehome_engagement(chat, &mainline).map_err(|error| {
            format!("workstream archived; chat {chat} still needs Main rematerialization: {error}")
        })?;
    }
    wb.notify_library_changed("workstream", ws_id, "upsert");
    for chat in &members {
        wb.notify_library_changed("chat", chat, "upsert");
    }
    Ok(members)
}

pub async fn archive_workstream(
    State(wb): State<SharedWorkbench>,
    Path(ws_id): Path<String>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let Some(rec) = wb.workstream(&ws_id) else {
        return (StatusCode::NOT_FOUND, "no such workstream").into_response();
    };
    if let Err(error) = archive_active_workstream(&mut wb, &rec) {
        return (StatusCode::CONFLICT, error).into_response();
    }
    (StatusCode::OK, Json(json!({ "archived": ws_id }))).into_response()
}

// ---- POST /workstreams/:id/promote ---------------------------------------

/// Promote a workstream's main into the placement mainline — the explicit,
/// boundary-gated `advanced → integrated` hop. Performs the real workspace merge, then
/// records it through the verified merge reducer (the boundary command gates the
/// integrate, `MAINLINE_INTEGRATION_REQUIRES_BOUNDARY`). A workspace conflict leaves the
/// mainline untouched (`PARTIAL_MERGE_NOT_STANDING`) for repair.
pub async fn promote_workstream(
    State(wb): State<SharedWorkbench>,
    Path(ws_id): Path<String>,
    body: Option<Json<PromoteWorkstreamBody>>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if !wb.has_workstream(&ws_id) {
        return (StatusCode::NOT_FOUND, "no such workstream").into_response();
    }
    // A clean line may be promoted only when every member is settled. Otherwise the
    // subsequent retirement would have to discard or transplant a private candidate.
    let promotion_members = wb.workstream_members(&ws_id);
    for chat in &promotion_members {
        if wb.engagement_rehome_blocked(chat) {
            return (
                StatusCode::CONFLICT,
                format!("chat {chat} has active or unsettled workspace changes; settle or discard them before promoting"),
            )
                .into_response();
        }
    }
    // The real boundary is one exact project-collaboration Main CAS under
    // WhippleScript's durable reservation. Native targets are untouched.
    let Some(root) = wb.workstream_root(&ws_id) else {
        return (
            StatusCode::CONFLICT,
            "workstream collaboration root is unresolved",
        )
            .into_response();
    };
    let Some(workspace) = wb.workspace_by_storage_id(&root.workspace_id) else {
        return (
            StatusCode::CONFLICT,
            "project collaboration workspace is unavailable",
        )
            .into_response();
    };
    let topology_status = workspace
        .workstream(&ws_id)
        .ok()
        .flatten()
        .map(|workstream| workstream.status)
        .unwrap_or(StreamStatus::Archived);
    let recovering_after_cas = matches!(
        topology_status,
        StreamStatus::RefAdvanced | StreamStatus::Archived
    );
    let requested = body
        .map(|Json(body)| body.settlement_members)
        .unwrap_or_default()
        .into_iter()
        .map(|member| RequestedSettlementMember {
            target_id: member.target_id,
            act: member.act,
        })
        .collect::<Vec<_>>();
    let reservation_id = gen_id("promotion");
    let reservation = match workspace.reserve_workstream_promotion_boundary(&ws_id, &reservation_id)
    {
        Ok(reservation) => reservation,
        Err(error) => return (StatusCode::CONFLICT, error.to_string()).into_response(),
    };
    clear_promotion_conflict(&mut wb, &ws_id);
    let stored_reservation_id = reservation.reservation_id.clone();
    let manifest = match wb.build_workstream_promotion_manifest(&ws_id, &reservation) {
        Ok(manifest) => manifest,
        Err(error) => {
            if let Some(workspace) = wb.workspace_by_storage_id(&root.workspace_id) {
                let _ =
                    workspace.release_workstream_promotion_boundary(&ws_id, &stored_reservation_id);
            }
            return (StatusCode::CONFLICT, error).into_response();
        }
    };

    let existing_settlement = wb
        .latest_workstream_target_settlement(&ws_id)
        .filter(|state| {
            state
                .declaration
                .as_ref()
                .and_then(|declaration| declaration.promotion_manifest_ref.as_deref())
                == Some(manifest.id.as_str())
        });
    let mut settlement = if let Some(existing) = existing_settlement {
        Some(existing)
    } else if requested.is_empty() {
        None
    } else if recovering_after_cas {
        return (
            StatusCode::CONFLICT,
            "collaboration Main already advanced; create a later settlement from the accepted manifest",
        )
            .into_response();
    } else {
        let declared = match wb.create_workstream_target_settlement(&manifest, requested) {
            Ok(state) => state,
            Err(error) => {
                if let Some(workspace) = wb.workspace_by_storage_id(&root.workspace_id) {
                    let _ = workspace
                        .release_workstream_promotion_boundary(&ws_id, &stored_reservation_id);
                }
                return (StatusCode::CONFLICT, error).into_response();
            }
        };
        let declaration_id = declared
            .declaration
            .as_ref()
            .map(|declaration| declaration.declaration_id.clone())
            .expect("declared settlement has an identity");
        let preflight = match wb.preflight_target_settlement(&declaration_id) {
            Ok(state) => state,
            Err(error) => {
                if let Some(workspace) = wb.workspace_by_storage_id(&root.workspace_id) {
                    let _ = workspace
                        .release_workstream_promotion_boundary(&ws_id, &stored_reservation_id);
                }
                return (StatusCode::CONFLICT, error).into_response();
            }
        };
        if preflight.phase != SettlementPhase::Ready {
            if let Some(workspace) = wb.workspace_by_storage_id(&root.workspace_id) {
                let _ =
                    workspace.release_workstream_promotion_boundary(&ws_id, &stored_reservation_id);
            }
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "combined-preflight-refused",
                    "manifest": manifest,
                    "target_settlement": preflight,
                })),
            )
                .into_response();
        }
        Some(preflight)
    };

    let outcome = match wb
        .workspace_by_storage_id(&root.workspace_id)
        .expect("reserved workspace remains open")
        .promote_workstream_boundary(&ws_id, &root.workspace_id, &stored_reservation_id)
    {
        Ok(outcome) => outcome,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response(),
    };
    let (receipt, rehomed) = match outcome {
        gaugedesk_workspace::WorkstreamPromotionOutcome::Conflicted { paths } => {
            record_promotion_conflict(&mut wb, &ws_id, &paths);
            if let Some(state) = settlement.as_ref() {
                if let Some(declaration) = state.declaration.as_ref() {
                    let _ = wb.cancel_target_settlement(
                        &declaration.declaration_id,
                        "collaboration promotion conflicted before target effects",
                    );
                }
            }
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "workstream-conflict",
                    "message": "workstream conflicts with project collaboration Main",
                    "paths": paths,
                })),
            )
                .into_response();
        }
        gaugedesk_workspace::WorkstreamPromotionOutcome::Refused(reason) => {
            if let Some(state) = settlement.as_ref() {
                if let Some(declaration) = state.declaration.as_ref() {
                    let _ = wb.cancel_target_settlement(
                        &declaration.declaration_id,
                        "collaboration promotion was refused before target effects",
                    );
                }
            }
            return (StatusCode::CONFLICT, Json(json!({ "error": reason }))).into_response();
        }
        gaugedesk_workspace::WorkstreamPromotionOutcome::Promoted {
            receipt,
            rehomed_chat_ids,
        } => (receipt, rehomed_chat_ids),
    };
    let mainline = wb
        .workspace_by_storage_id(&root.workspace_id)
        .map(|workspace| workspace.mainline().to_owned())
        .unwrap_or_else(|| "main".to_owned());
    let members = if rehomed.is_empty() {
        promotion_members
    } else {
        rehomed
    };
    for chat in &members {
        if let Err(error) = wb.rehome_engagement(chat, &mainline) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "promotion-landed-close-incomplete",
                    "message": format!("project Main advanced; chat {chat} still needs re-home: {error}"),
                })),
            )
                .into_response();
        }
    }
    let _ = wb.store_mut().append_record(
        &ws_id,
        "workstream_promotion_receipt",
        &serde_json::to_string(&receipt).unwrap_or_default(),
    );
    let mainline_chats = wb.sync_mainline_members(&root.workspace_id);
    for chat_id in mainline_chats {
        wb.notify_library_changed("chat", &chat_id, "upsert");
    }
    wb.notify_library_changed("workstream", &ws_id, "upsert");
    if let Some(ready) = settlement.take() {
        let declaration = ready
            .declaration
            .as_ref()
            .expect("ready settlement has a declaration");
        let declaration_id = declaration.declaration_id.clone();
        let member_ids = declaration
            .members
            .iter()
            .filter(|member| {
                ready.members[&member.member_id].phase == SettlementMemberPhase::PreflightPassed
            })
            .map(|member| member.member_id.clone())
            .collect::<Vec<String>>();
        let mut latest = ready;
        for member_id in member_ids {
            match wb.execute_settlement_member(&declaration_id, &member_id) {
                Ok(state) => latest = state,
                Err(_) => {
                    latest = wb
                        .store_ref()
                        .fold::<TargetSettlementState>(&format!(
                            "target-settlement::{declaration_id}"
                        ))
                        .unwrap_or(latest);
                }
            }
        }
        settlement = Some(latest);
    }
    let target_settlement_projection =
        target_settlement_projection(settlement.as_ref().map(|state| state.phase));
    (
        StatusCode::OK,
        Json(json!({
            "promoted": ws_id,
            "collaboration": "promoted",
            "target_settlement": target_settlement_projection,
            "promotion_manifest": manifest,
            "receipt": receipt,
            "archived": true,
        })),
    )
        .into_response()
}

/// Create a fresh settlement declaration against an immutable manifest from an
/// already accepted collaboration promotion. This never rewrites the promotion
/// receipt and does not execute effects until the member action is invoked.
pub async fn create_workstream_settlement(
    State(wb): State<SharedWorkbench>,
    Path(ws_id): Path<String>,
    Json(body): Json<CreateWorkstreamSettlementBody>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let Some(root) = wb.workstream_root(&ws_id) else {
        return (StatusCode::NOT_FOUND, "no such workstream").into_response();
    };
    let promotion_receipt = wb
        .workspace_by_storage_id(&root.workspace_id)
        .and_then(|workspace| workspace.workstream(&ws_id).ok().flatten())
        .and_then(|workstream| {
            (workstream.status == StreamStatus::Archived)
                .then(|| workstream.boundary_receipt(&root.workspace_id))
                .flatten()
        });
    let Some(promotion_receipt) = promotion_receipt else {
        return (
            StatusCode::CONFLICT,
            "later settlement requires an archived promoted collaboration manifest",
        )
            .into_response();
    };
    let manifest =
        match wb.workstream_promotion_manifest(&ws_id, body.promotion_manifest_ref.as_deref()) {
            Ok(manifest) => manifest,
            Err(error) => return (StatusCode::NOT_FOUND, error).into_response(),
        };
    if manifest.reservation_id != promotion_receipt.reservation_id
        || manifest.expected_line_cut != promotion_receipt.expected_stream_cut
        || manifest.expected_main_cut != promotion_receipt.expected_main_cut
        || manifest.proposed_main_cut != promotion_receipt.proposed_main_cut
    {
        return (
            StatusCode::CONFLICT,
            "promotion manifest does not match the accepted collaboration receipt",
        )
            .into_response();
    }
    if body.members.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "settlement must request at least one target act",
        )
            .into_response();
    }
    let requested = body
        .members
        .into_iter()
        .map(|member| RequestedSettlementMember {
            target_id: member.target_id,
            act: member.act,
        })
        .collect();
    let declared = match wb.create_detached_workstream_target_settlement(&manifest, requested) {
        Ok(state) => state,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    let declaration_id = declared
        .declaration
        .as_ref()
        .map(|declaration| declaration.declaration_id.clone())
        .expect("declaration has identity");
    match wb.preflight_target_settlement(&declaration_id) {
        Ok(state) => (
            StatusCode::CREATED,
            Json(json!({
                "promotion_manifest": manifest,
                "target_settlement": state,
            })),
        )
            .into_response(),
        Err(error) => (StatusCode::CONFLICT, error).into_response(),
    }
}

pub async fn list_workstream_promotion_manifests(
    State(wb): State<SharedWorkbench>,
    Path(ws_id): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if !wb.has_workstream(&ws_id) {
        return (StatusCode::NOT_FOUND, "no such workstream").into_response();
    }
    match wb.workstream_promotion_manifests(&ws_id) {
        Ok(manifests) => Json(json!({ "manifests": manifests })).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    }
}
