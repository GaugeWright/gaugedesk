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
use crate::{LockUnpoisoned, SharedWorkbench, Workbench};
use gaugewright_core::merge::{MergeCommand, MergePhase, MergeState};
use gaugewright_core::run::{RunPhase, RunState};
use gaugewright_core::workstream::{WorkstreamCommand, WorkstreamPhase, WorkstreamState};
use gaugewright_store::AdmitError;
use gaugewright_workspace::MergeOutcome;

/// Whether a rendered provider diff contains collaborative workspace changes.
/// `.agent-config.json` is a host-owned per-chat overlay, preserved across re-home;
/// it is not a candidate against the shared line.
fn diff_has_shared_line_changes(diff: &str) -> bool {
    diff.lines()
        .filter_map(|line| line.strip_prefix("diff --git a/"))
        .filter_map(|line| line.split_once(" b/").map(|(path, _)| path))
        .any(|path| path != gaugewright_boundary::definition::CONFIG_PATH)
}

#[derive(Deserialize)]
pub struct CreateWorkstreamBody {
    pub name: String,
    pub target_id: String,
}

#[derive(Deserialize)]
pub struct MemberBody {
    pub chat: String,
}

impl Workbench {
    /// Ensure every durable managed-target workstream has a native shared line,
    /// then re-home its members from folded reducer membership (`WS-E`).
    pub fn restore_workstream_homing(&mut self) {
        let ws_ids = self.library_workstream_ids();
        for ws_id in ws_ids {
            if let Some(root) = self.library_workstream_root(&ws_id) {
                if let Some(storage) = self.managed_target_storage_id(&root.target_id) {
                    let _ = self.create_target_workstream_ref(storage, &ws_id);
                }
            }
            let members: Vec<String> = self
                .store_ref()
                .fold::<WorkstreamState>(&ws_id)
                .ok()
                .filter(|state| state.phase == WorkstreamPhase::Active)
                .map(|s| s.members.into_iter().collect())
                .unwrap_or_default();
            for chat in members {
                // The chat's owning placement mints the stream ref token — no
                // ref-format knowledge outside the workspace seam (W7).
                let Some(target) = self
                    .library_workstream_root(&ws_id)
                    .and_then(|root| {
                        self.managed_target_storage_id(&root.target_id)
                            .map(str::to_owned)
                    })
                    .and_then(|iid| self.workstream_target(&iid, &ws_id))
                else {
                    continue;
                };
                self.set_engagement_target(&chat, target);
            }
        }
    }

    /// The stream ref token for `ws_id`, minted by an open placement's
    /// workspace impl (`None` when the placement is not open).
    fn workstream_target(&self, instance_id: &str, ws_id: &str) -> Option<String> {
        self.targets
            .get(instance_id)
            .map(|inst| inst.workstream_ref(ws_id))
    }

    /// The mainline token of the placement owning `chat`'s live engagement.
    fn chat_mainline(&self, chat: &str) -> Option<String> {
        self.live_engagement_target_id(chat)
            .and_then(|iid| self.targets.get(iid))
            .map(|inst| inst.mainline().to_string())
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
        target_id: &str,
        workstream_id: &str,
    ) -> std::io::Result<()> {
        self.create_target_workstream_ref(target_id, workstream_id)
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

    /// Fold one workstream's state from the durable log.
    pub fn workstream_state(&self, workstream_id: &str) -> Option<WorkstreamState> {
        self.store_ref().fold::<WorkstreamState>(workstream_id).ok()
    }

    /// Fold one workstream's member chat ids.
    pub fn workstream_members(&self, workstream_id: &str) -> Vec<String> {
        self.workstream_state(workstream_id)
            .map(|state| state.members.into_iter().collect())
            .unwrap_or_default()
    }

    /// All active named streams in one placement that currently claim `chat`. The
    /// per-stream reducers own their own membership logs, so a placement-level move
    /// must inspect every sibling before it can preserve the one-target rule.
    fn active_workstream_memberships(&self, instance_id: &str, chat: &str) -> Vec<String> {
        self.workstreams_in(instance_id)
            .into_iter()
            .filter_map(|record| {
                self.workstream_state(&record.id).and_then(|state| {
                    (state.phase == WorkstreamPhase::Active && state.members.contains(chat))
                        .then(|| record.id.clone())
                })
            })
            .collect()
    }

    /// Admit a workstream reducer command.
    pub fn admit_workstream(
        &mut self,
        workstream_id: &str,
        command: WorkstreamCommand,
    ) -> Result<(), AdmitError> {
        self.store_mut()
            .admit::<WorkstreamState>(workstream_id, command)
            .map(|_| ())
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

    /// Promote a workstream ref into its managed target mainline.
    pub fn promote_workstream_ref_to_main(
        &self,
        workstream_id: &str,
        target_id: &str,
    ) -> std::io::Result<MergeOutcome> {
        self.promote_target_workstream_ref_to_main(workstream_id, target_id)
    }

    /// Refresh every live chat still homed to a target's implicit Main after that
    /// mainline advances. Promotion updates the managed target store; without this
    /// reconciliation, existing Main chat worktrees keep their old cut and make a
    /// successful promotion look like a no-op in the workbench.
    fn sync_mainline_members(&self, target_id: &str) -> Vec<String> {
        let Some(mainline) = self.targets.get(target_id).map(|target| target.mainline()) else {
            return Vec::new();
        };
        self.engagements
            .iter()
            .filter(|(chat_id, engagement)| {
                self.engagement_target_id(chat_id) == Some(target_id)
                    && engagement.target() == mainline
            })
            .map(|(chat_id, engagement)| {
                let _ = engagement.sync_from_main();
                chat_id.clone()
            })
            .collect()
    }

    /// Record the verified reducer path for a successful workstream promotion.
    pub fn admit_workstream_promotion(&mut self, workstream_id: &str) -> Result<(), AdmitError> {
        let scope = format!("ws-merge-{workstream_id}");
        for command in [
            MergeCommand::StartMerge,
            MergeCommand::WorkspaceClean,
            MergeCommand::PolicyAdmit,
            MergeCommand::AdvanceStandingRef,
            MergeCommand::AdmitBoundaryIntegration,
            MergeCommand::IntegrateToMainline,
        ] {
            self.store_mut().admit::<MergeState>(&scope, command)?;
        }
        Ok(())
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
    let target = match wb.resolve_placement_target(&iid, Some(&body.target_id)) {
        Ok(target) => target,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    if target.adapter_family != "whipplescript-v1" {
        return (
            StatusCode::CONFLICT,
            "this target adapter does not support shared managed lines",
        )
            .into_response();
    }
    let storage_target_id = target.id.as_str();
    let ws_id = gen_id("ws");
    if let Err(e) = wb.create_workstream_ref(storage_target_id, &ws_id) {
        let status = if e.kind() == std::io::ErrorKind::NotFound {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        return (status, format!("{e}")).into_response();
    }
    let home = wb.authority().as_str().to_string();
    if let Err(e) = wb.admit_workstream(
        &ws_id,
        WorkstreamCommand::CreateWorkstream {
            name: body.name.clone(),
            home: home.clone(),
            creator: home,
        },
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response();
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
        target_id: target.id.clone(),
        adapter_family: target.adapter_family,
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
    let state = wb.workstream_state(&rec.id);
    let status = match state.as_ref().map(|s| s.phase) {
        Some(WorkstreamPhase::Archived) => "archived",
        Some(WorkstreamPhase::Active) => "active",
        _ => "active",
    };
    let members: Vec<String> = state
        .map(|s| s.members.into_iter().collect())
        .unwrap_or_default();
    let root = wb
        .workstream_root(&rec.id)
        .expect("validated workstream has a target root");
    let workspace_root = format!(
        "{}::{}::{}",
        root.placement_id, root.target_id, root.adapter_family
    );
    json!({
        "id": rec.id,
        "name": rec.name,
        "placement_id": rec.instance_id,
        "workspace_root": workspace_root,
        "target_id": root.target_id,
        "adapter_family": root.adapter_family,
        "status": status,
        "members": members,
    })
}

// ---- POST /workstreams/:id/join ------------------------------------------

/// Transfer a chat onto a workstream's main — it now greedily auto-syncs there.
/// Membership is single-target: joining this line removes the chat from every other
/// active named line in the placement before its target is changed (ADR 0087).
pub async fn join_workstream(
    State(wb): State<SharedWorkbench>,
    Path(ws_id): Path<String>,
    Json(body): Json<MemberBody>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let Some(rec) = wb.workstream(&ws_id) else {
        return (StatusCode::NOT_FOUND, "no such workstream").into_response();
    };
    let Some(root) = wb.workstream_root(&ws_id) else {
        return (StatusCode::CONFLICT, "workstream target root is unresolved").into_response();
    };
    // Exact-root only: placement, target, and adapter family must all match.
    if wb.chat_placement_id(&body.chat) != Some(rec.instance_id.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            "chat is not in this workstream's placement",
        )
            .into_response();
    }
    let Some(binding) = wb.library_chat_target_binding(&body.chat) else {
        return (StatusCode::CONFLICT, "chat target is unresolved").into_response();
    };
    if binding.target_id != root.target_id {
        return (
            StatusCode::BAD_REQUEST,
            "chat is not on this workstream's target",
        )
            .into_response();
    }
    if wb
        .workstream_state(&ws_id)
        .map(|state| state.phase != WorkstreamPhase::Active)
        .unwrap_or(true)
    {
        return (StatusCode::CONFLICT, "workstream is not active").into_response();
    }
    let Some(storage_target_id) = wb
        .managed_target_storage_id(&root.target_id)
        .map(str::to_owned)
    else {
        return (StatusCode::CONFLICT, "work target storage is unavailable").into_response();
    };
    let Some(destination) = wb.workstream_target(&storage_target_id, &ws_id) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "workstream workspace is unavailable",
        )
            .into_response();
    };
    if let Err(error) = wb.rehome_engagement(&body.chat, &destination) {
        return (StatusCode::CONFLICT, error).into_response();
    }
    // Snapshot every old membership while holding the one workbench lock. Leaving the
    // prior lines first makes the requested join a placement-level transfer rather than
    // two independent memberships that happen to point at different refs.
    let prior: Vec<String> = wb
        .active_workstream_memberships(&rec.instance_id, &body.chat)
        .into_iter()
        .filter(|id| id != &ws_id)
        .collect();
    for prior_id in &prior {
        if let Err(e) = wb.admit_workstream(
            prior_id,
            WorkstreamCommand::LeaveWorkstream {
                chat: body.chat.clone(),
            },
        ) {
            return (StatusCode::CONFLICT, format!("{e:?}")).into_response();
        }
    }
    if let Err(e) = wb.admit_workstream(
        &ws_id,
        WorkstreamCommand::JoinWorkstream {
            chat: body.chat.clone(),
        },
    ) {
        return (StatusCode::CONFLICT, format!("{e:?}")).into_response();
    }
    for prior_id in prior {
        wb.notify_library_changed("workstream", &prior_id, "upsert");
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
    let Some(rec) = wb.workstream(&ws_id) else {
        return (StatusCode::NOT_FOUND, "no such workstream").into_response();
    };
    if wb.chat_placement_id(&body.chat) != Some(rec.instance_id.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            "chat is not in this workstream's placement",
        )
            .into_response();
    }
    let memberships = wb.active_workstream_memberships(&rec.instance_id, &body.chat);
    if !memberships.iter().any(|id| id == &ws_id) {
        return (
            StatusCode::CONFLICT,
            "chat is not a member of this active workstream",
        )
            .into_response();
    }
    let Some(mainline) = wb.chat_mainline(&body.chat) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "chat workspace is unavailable",
        )
            .into_response();
    };
    if let Err(error) = wb.rehome_engagement(&body.chat, &mainline) {
        return (StatusCode::CONFLICT, error).into_response();
    }
    for membership_id in &memberships {
        if let Err(e) = wb.admit_workstream(
            membership_id,
            WorkstreamCommand::LeaveWorkstream {
                chat: body.chat.clone(),
            },
        ) {
            return (StatusCode::CONFLICT, format!("{e:?}")).into_response();
        }
    }
    for membership_id in memberships {
        wb.notify_library_changed("workstream", &membership_id, "upsert");
    }
    wb.notify_library_changed("chat", &body.chat, "upsert");
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
    for chat in &members {
        let target = wb
            .chat_mainline(chat)
            .ok_or_else(|| format!("chat {chat} workspace is unavailable"))?;
        wb.rehome_engagement(chat, &target)?;
    }
    wb.admit_workstream(ws_id, WorkstreamCommand::ArchiveWorkstream)
        .map_err(|e| format!("{e:?}"))?;
    for chat in &members {
        let sibling_memberships: Vec<String> = wb
            .active_workstream_memberships(&rec.instance_id, chat)
            .into_iter()
            .filter(|id| id != ws_id)
            .collect();
        for sibling_id in &sibling_memberships {
            wb.admit_workstream(
                sibling_id,
                WorkstreamCommand::LeaveWorkstream { chat: chat.clone() },
            )
            .map_err(|e| format!("{e:?}"))?;
            wb.notify_library_changed("workstream", sibling_id, "upsert");
        }
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
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let Some(rec) = wb.workstream(&ws_id) else {
        return (StatusCode::NOT_FOUND, "no such workstream").into_response();
    };
    // A clean line may be promoted only when every member is settled. Otherwise the
    // subsequent retirement would have to discard or transplant a private candidate.
    for chat in wb.workstream_members(&ws_id) {
        if wb.engagement_rehome_blocked(&chat) {
            return (
                StatusCode::CONFLICT,
                format!("chat {chat} has active or unsettled workspace changes; settle or discard them before promoting"),
            )
                .into_response();
        }
    }
    // The real merge: workstream/<id>/main -> main, in the managed target store.
    let Some(root) = wb.workstream_root(&ws_id) else {
        return (StatusCode::CONFLICT, "workstream target root is unresolved").into_response();
    };
    let Some(storage_target_id) = wb
        .managed_target_storage_id(&root.target_id)
        .map(str::to_owned)
    else {
        return (StatusCode::CONFLICT, "work target storage is unavailable").into_response();
    };
    let outcome = match wb.promote_workstream_ref_to_main(&ws_id, &storage_target_id) {
        Ok(outcome) => outcome,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response(),
    };
    if outcome == MergeOutcome::Conflict {
        return (
            StatusCode::CONFLICT,
            "workstream conflicts with the mainline — resolve before promoting",
        )
            .into_response();
    }
    // Record the integration through the verified reducer on the workstream's own merge
    // scope: clean -> advanced, then the boundary-gated advanced -> integrated.
    if let Err(e) = wb.admit_workstream_promotion(&ws_id) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response();
    }
    // A clean integration completes this named line. Archive it only after the merge
    // and its boundary evidence both succeed, which re-homes every member to Main and
    // removes the retired line from the active navigation projection. A conflict above
    // returns before this point, leaving the line and all of its members intact.
    if let Err(error) = archive_active_workstream(&mut wb, &rec) {
        return (StatusCode::INTERNAL_SERVER_ERROR, error).into_response();
    }
    // Promotion advanced the target's mainline and archive re-homed its former
    // members. Reconcile every open Main chat so the result is visible immediately.
    let mainline_chats = wb.sync_mainline_members(&storage_target_id);
    for chat_id in mainline_chats {
        wb.refresh_work_target_basis_from_chat(&chat_id);
        wb.notify_library_changed("chat", &chat_id, "upsert");
    }
    (
        StatusCode::OK,
        Json(json!({ "promoted": ws_id, "phase": "Integrated", "archived": true })),
    )
        .into_response()
}
