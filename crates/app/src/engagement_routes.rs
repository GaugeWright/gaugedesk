//! Local chat/engagement route handlers.
//!
//! This is the local workbench surface for `/chats/*` APIs: target candidate
//! reads/writes, transcript/events, merge/revert/sync, task
//! turns, and e2e reset hooks.

use std::convert::Infallible;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::sse::{Event, Sse},
    response::IntoResponse,
    Json,
};
use futures::Stream;
use gaugedesk_core::instance::{InstanceCommand, InstanceState};
use gaugedesk_core::merge::{MergeCommand, MergeState};
#[cfg(debug_assertions)]
use gaugedesk_store::Store;
use gaugedesk_workspace::{
    ChatWorkspace, FileEntry, MergeOutcome, MergePreview, RegionResolution, SaveBase,
    SaveFileOutcome, WorkspaceError,
};
use serde::Deserialize;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

#[cfg(debug_assertions)]
use crate::build_workbench;
use crate::{
    engine, err_response,
    library::{ChatMode, ChatRecord, ChatTargetBindingRecord, RecordOp, LIBRARY_SCOPE},
    LockUnpoisoned, ServerEvent, SharedWorkbench, Workbench,
};

#[derive(Clone, Copy, Debug, serde::Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub(crate) enum EngagementMergeAction {
    Admit,
    Reject,
    Repair,
    Retry,
    Integrate,
}

pub(crate) enum EngagementCreateError {
    Exists,
    NoDefaultInstance,
    Git(String),
}

pub(crate) struct CreatedEngagement {
    pub id: String,
    pub branch: String,
    pub path: String,
}

pub struct EngagementTaskContext {
    /// Project-scoped chats carry their owning project. Archetype edit chats
    /// deliberately do not, but still use this context for immediate turns.
    pub project_id: Option<String>,
    pub work_target_basis: String,
    pub worktree: std::path::PathBuf,
    pub sender: broadcast::Sender<ServerEvent>,
    pub mode: ChatMode,
}

impl Workbench {
    pub(crate) fn create_default_engagement(
        &mut self,
        id: String,
        title: String,
    ) -> Result<CreatedEngagement, EngagementCreateError> {
        if self.engagements.contains_key(&id) {
            return Err(EngagementCreateError::Exists);
        }
        let root_id = self.default_instance.clone();
        let target = self
            .resolve_placement_target(&root_id, None)
            .map_err(EngagementCreateError::Git)?;
        let Some(workspace) = self.targets.get(&target.id) else {
            return Err(EngagementCreateError::NoDefaultInstance);
        };
        let eng = workspace
            .create_engagement(&id)
            .map_err(|e| EngagementCreateError::Git(e.to_string()))?;
        let basis = eng
            .boundary_cut()
            .map_err(|e| EngagementCreateError::Git(e.to_string()))?
            .0;
        let branch = eng.branch().to_string();
        let path = eng.path().to_string_lossy().to_string();
        self.write_created_chat_record(ChatRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: id.clone(),
            op: RecordOp::Upsert,
            instance_id: root_id,
            title,
            created_position: 0,
            forked_from: None,
            forked_from_entry: None,
        });
        self.write_chat_target_record(ChatTargetBindingRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            chat_id: id.clone(),
            op: RecordOp::Upsert,
            target_id: target.id.clone(),
            basis,
            path_scope: target.path_scope,
            capabilities: target.capabilities,
        });
        self.register_engagement(id.clone(), target.id, eng);
        Ok(CreatedEngagement { id, branch, path })
    }

    /// Register a live engagement handle under its owning instance.
    pub fn register_engagement(
        &mut self,
        chat_id: impl Into<String>,
        inst_id: impl Into<String>,
        eng: Box<dyn ChatWorkspace>,
    ) {
        let chat_id = chat_id.into();
        self.engagement_index
            .insert(chat_id.clone(), inst_id.into());
        self.engagements.insert(chat_id, eng);
    }

    /// Whether a live engagement handle is registered under this chat id.
    pub fn has_engagement(&self, chat_id: &str) -> bool {
        self.engagements.contains_key(chat_id)
    }

    pub(crate) fn set_live_engagement_target(&mut self, chat_id: &str, target: impl Into<String>) {
        if let Some(eng) = self.engagements.get_mut(chat_id) {
            // Re-home is fail-closed at the provider seam (AM-4).
            let _ = eng.set_target(&target.into());
        }
    }

    pub(crate) fn live_engagement_target_id(&self, chat_id: &str) -> Option<&str> {
        self.engagement_index.get(chat_id).map(String::as_str)
    }

    pub(crate) fn engagement_ids(&self) -> Vec<String> {
        self.engagements.keys().cloned().collect()
    }

    pub(crate) fn engagement_diff(&self, id: &str) -> Option<Result<String, WorkspaceError>> {
        self.engagements.get(id).map(|eng| eng.diff_against_main())
    }

    pub(crate) fn engagement_config_json(&self, id: &str) -> Option<Result<String, String>> {
        self.engagements.get(id)?;
        Some(self.effective_agent_config_for_chat(id))
    }

    pub(crate) fn write_engagement_config(
        &mut self,
        id: &str,
        body: &str,
    ) -> Option<Result<(), WorkspaceError>> {
        self.engagements.get(id)?;
        let instance_id = self.library.chats.get(id)?.instance_id.clone();
        let notes = self
            .store_ref()
            .fold::<InstanceState>(&instance_id)
            .ok()
            .and_then(|state| state.notes)
            .unwrap_or_default();
        let written = self
            .store_mut()
            .admit::<InstanceState>(
                &instance_id,
                InstanceCommand::SetLocalConfig {
                    config: body.to_owned(),
                    notes,
                },
            )
            .map(|_| ())
            .map_err(|error| WorkspaceError {
                message: format!("{error:?}"),
            });
        Some(written.map(|()| {
            self.publish(
                id,
                ServerEvent::Admitted {
                    kind: "authoring".into(),
                    text: "agent config updated".into(),
                },
            );
        }))
    }

    pub(crate) fn engagement_transcript_json(
        &self,
        id: &str,
    ) -> Result<String, gaugedesk_store::AdmitError> {
        let events = self.store_ref().events(id)?;
        let forkable: std::collections::BTreeSet<i64> = events
            .iter()
            .filter(|(_, kind, _)| kind == crate::engine::TURN_BOUNDARY_KIND)
            .filter_map(|(_, _, payload)| {
                serde_json::from_str::<crate::engine::TurnBoundaryRecord>(payload).ok()
            })
            .flat_map(|boundary| [boundary.user_entry_id, boundary.assistant_entry_id])
            .collect();
        let rows = events
            .into_iter()
            .filter(|(_, kind, _)| kind == "transcript")
            .filter_map(|(position, _, payload)| {
                let mut event = serde_json::from_str::<serde_json::Value>(&payload).ok()?;
                let object = event.as_object_mut()?;
                object.insert("entry_id".into(), position.into());
                if forkable.contains(&position) {
                    object.insert("forkable".into(), true.into());
                }
                Some(event)
            })
            .collect::<Vec<_>>();
        serde_json::to_string(&rows).map_err(Into::into)
    }

    /// The engagement's governance audit records (ADR 0082 §4: every
    /// auto-advance is durable evidence citing the rule it matched — audit,
    /// not conversation, so it reads from here rather than the transcript).
    pub(crate) fn engagement_audit_json(
        &self,
        id: &str,
    ) -> Result<String, gaugedesk_store::AdmitError> {
        self.store_ref()
            .records(id, "audit")
            .map(|rows| format!("[{}]", rows.join(",")))
    }

    /// Ingest context bytes into a live engagement and commit the worktree.
    pub fn ingest_context_into_engagement(
        &mut self,
        chat_id: &str,
        path: &std::path::Path,
    ) -> Option<Result<(usize, String), WorkspaceError>> {
        let eng = self.engagements.get(chat_id)?;
        let n = match eng.ingest(path) {
            Ok(n) => n,
            Err(e) => return Some(Err(e)),
        };
        let commit = match eng.commit_turn(&format!("ingest context: {}", path.display())) {
            Ok(commit) => commit.map(|c| c.0).unwrap_or_default(),
            Err(e) => return Some(Err(e)),
        };
        Some(Ok((n, commit)))
    }

    /// Ingest **uploaded** context bytes into a live engagement and commit (`ENTSEC-5`): the
    /// upload counterpart of [`ingest_context_into_engagement`](Self::ingest_context_into_engagement)
    /// for the enterprise thin-client, where the client's files are sent as an upload rather
    /// than a server-local path. `None` if the engagement is unknown.
    pub fn ingest_upload_into_engagement(
        &mut self,
        chat_id: &str,
        files: &[(String, String)],
    ) -> Option<Result<(usize, String), WorkspaceError>> {
        let eng = self.engagements.get(chat_id)?;
        let n = match eng.ingest_upload(files) {
            Ok(n) => n,
            Err(e) => return Some(Err(e)),
        };
        let commit = match eng.commit_turn(&format!("ingest uploaded context: {n} file(s)")) {
            Ok(commit) => commit.map(|c| c.0).unwrap_or_default(),
            Err(e) => return Some(Err(e)),
        };
        Some(Ok((n, commit)))
    }

    /// The current file manifest for a live engagement.
    pub fn engagement_tree(&self, chat_id: &str) -> Option<Result<Vec<FileEntry>, WorkspaceError>> {
        self.engagements.get(chat_id).map(|eng| eng.tree())
    }

    /// Read one file from a live engagement worktree.
    pub fn read_engagement_file(
        &self,
        chat_id: &str,
        path: &str,
    ) -> Option<Result<String, WorkspaceError>> {
        self.engagements.get(chat_id).map(|eng| eng.read_file(path))
    }

    /// The engagement's current cut — minted on demand so what the reader
    /// just saw is always an addressable save base (cut-on-read).
    pub fn engagement_current_cut(
        &self,
        chat_id: &str,
    ) -> Option<Result<Option<String>, WorkspaceError>> {
        self.engagements.get(chat_id).map(|eng| eng.current_cut())
    }

    /// Read-only preview of what a base-carrying save would do (the live
    /// fold): region memory applies exactly as it would on the save.
    pub fn engagement_merge_preview(
        &self,
        chat_id: &str,
        path: &str,
        draft: &str,
        base_cut: &str,
    ) -> Option<Result<Option<MergePreview>, WorkspaceError>> {
        self.engagements
            .get(chat_id)
            .map(|eng| eng.merge_preview(path, draft, base_cut))
    }

    pub(crate) fn write_engagement_file(
        &mut self,
        chat_id: &str,
        path: &str,
        body: &str,
    ) -> Option<Result<(), WorkspaceError>> {
        let eng = self.engagements.get(chat_id)?;
        let result = eng
            .write_file(path, body)
            .and_then(|_| eng.commit_turn(&format!("edit {path}")).map(|_| ()));
        if result.is_ok() {
            let ev = ServerEvent::Admitted {
                kind: "edit".into(),
                text: format!("edited {path}"),
            };
            let _ = self
                .store_mut()
                .append_record(chat_id, "transcript", &ev.to_json());
            self.publish(chat_id, ev);
        }
        Some(result)
    }

    /// Base-carrying editor save (SUB-6): the merge engine is whip's
    /// token-level three-way; this layer commits accepted outcomes and
    /// records the evidence. A merged save says so in the conversation
    /// (the fact), while the piece-level provenance lands on the AUDIT
    /// plane (ADR 0082 posture — rationale is evidence, not chat). A
    /// conflicted save commits nothing and returns the fold payload.
    pub(crate) fn save_engagement_file_with_base(
        &mut self,
        chat_id: &str,
        path: &str,
        draft: &str,
        base: SaveBase<'_>,
        resolutions: &[RegionResolution],
    ) -> Option<Result<SaveFileOutcome, WorkspaceError>> {
        let eng = self.engagements.get(chat_id)?;
        let outcome = match eng.save_file_with_base(path, draft, base, resolutions) {
            Ok(outcome) => outcome,
            Err(error) => return Some(Err(error)),
        };
        match &outcome {
            SaveFileOutcome::Written { .. } | SaveFileOutcome::Merged { .. } => {
                // The save IS the cut (whip minted it); no separate commit.
                let merged = matches!(&outcome, SaveFileOutcome::Merged { .. });
                let ev = ServerEvent::Admitted {
                    kind: "edit".into(),
                    text: if merged {
                        format!("edited {path} (merged with concurrent changes)")
                    } else {
                        format!("edited {path}")
                    },
                };
                let _ = self
                    .store_mut()
                    .append_record(chat_id, "transcript", &ev.to_json());
                self.publish(chat_id, ev);
                if let SaveFileOutcome::Merged { pieces, .. } = &outcome {
                    let _ = self.store_mut().append_record(
                        chat_id,
                        "audit",
                        &serde_json::json!({
                            "kind": "save_merged",
                            "path": path,
                            "algorithm": "text-merge/1",
                            "pieces": pieces,
                        })
                        .to_string(),
                    );
                }
                if !resolutions.is_empty() {
                    // Settled regions became durable resolution memory:
                    // that's rationale-grade evidence (ADR 0082 posture).
                    let _ = self.store_mut().append_record(
                        chat_id,
                        "audit",
                        &serde_json::json!({
                            "kind": "region_resolutions_recorded",
                            "path": path,
                            "count": resolutions.len(),
                        })
                        .to_string(),
                    );
                }
            }
            SaveFileOutcome::Conflicted { .. } => {}
        }
        Some(Ok(outcome))
    }

    fn authorize_file_edit(&self, chat_id: &str, path: &str) -> Result<(), &'static str> {
        let normalized = path.trim_start_matches("./");
        if gaugedesk_boundary::is_control_surface_path(normalized) {
            return Err("GaugeDesk runtime settings must be changed through Settings");
        }
        if normalized.starts_with(".whipple/versions/")
            || normalized.contains("/.whipple/versions/")
            || normalized.starts_with(".whipple/discipline/versions/")
            || normalized.contains("/.whipple/discipline/versions/")
        {
            return Err("published archetype versions are immutable");
        }
        if gaugedesk_boundary::is_method_surface_path(normalized) {
            let chat = self
                .library
                .chats
                .get(chat_id)
                .ok_or("no such engagement")?;
            let instance = self
                .library
                .instances
                .get(&chat.instance_id)
                .ok_or("chat instance is unavailable")?;
            if instance.kind != crate::library::InstanceKind::Authoring {
                return Err("work chats cannot edit their installed WhippleScript package");
            }
        }
        let binding = self
            .library_chat_target_binding(chat_id)
            .ok_or("chat target binding is unavailable")?;
        if !path_is_in_scope(normalized, &binding.path_scope) {
            return Err("path is outside the chat's admitted target scope");
        }
        Ok(())
    }

    fn candidate_within_target_scope(&self, chat_id: &str) -> Result<(), String> {
        let Some(binding) = self.library_chat_target_binding(chat_id) else {
            // Low-level in-memory workspace tests do not construct the durable
            // library. Production startup rejects every unbound chat.
            return Ok(());
        };
        let diff = self
            .engagements
            .get(chat_id)
            .ok_or_else(|| "chat candidate is unavailable".to_owned())?
            .diff_against_main()
            .map_err(|error| error.to_string())?;
        let escaped = diff
            .lines()
            .filter_map(|line| line.strip_prefix("diff --git a/"))
            .filter_map(|line| line.split_once(" b/").map(|(path, _)| path))
            .find(|path| !path_is_in_scope(path, &binding.path_scope));
        match escaped {
            Some(path) => Err(format!(
                "candidate path `{path}` is outside the admitted target scope"
            )),
            None => Ok(()),
        }
    }

    pub(crate) fn engagement_merge_state(
        &self,
        id: &str,
    ) -> Result<MergeState, gaugedesk_store::AdmitError> {
        self.store_ref().fold::<MergeState>(id)
    }

    pub(crate) fn revert_engagement(&mut self, id: &str) -> Option<Result<(), WorkspaceError>> {
        let eng = self.engagements.get(id)?;
        let result = eng.revert_to_main();
        if result.is_ok() {
            self.publish(
                id,
                ServerEvent::Admitted {
                    kind: "revert".into(),
                    text: "reverted to main — engagement work discarded".into(),
                },
            );
        }
        Some(result)
    }

    fn admit_merge_command(
        &mut self,
        id: &str,
        command: MergeCommand,
    ) -> Result<MergeState, String> {
        self.store_mut()
            .admit::<MergeState>(id, command)
            .map_err(|e| format!("{e:?}"))
    }

    pub(crate) fn apply_engagement_merge_action(
        &mut self,
        id: &str,
        action: EngagementMergeAction,
    ) -> Option<Result<MergeState, String>> {
        if !self.engagements.contains_key(id) {
            return None;
        }
        let result = match action {
            EngagementMergeAction::Reject => {
                self.admit_merge_command(id, MergeCommand::PolicyReject)
            }
            EngagementMergeAction::Repair => {
                self.admit_merge_command(id, MergeCommand::SubmitRepair)
            }
            EngagementMergeAction::Admit => self
                .candidate_within_target_scope(id)
                .and_then(|_| self.admit_merge_command(id, MergeCommand::PolicyAdmit))
                .and_then(
                    |_| match self.engagements.get(id).unwrap().merge_into_main() {
                        Ok(MergeOutcome::Clean) => {
                            let state =
                                self.admit_merge_command(id, MergeCommand::AdvanceStandingRef)?;
                            self.refresh_work_target_basis_from_chat(id);
                            if let Some(binding) = self.library_chat_target_binding(id) {
                                let candidate = self
                                    .engagements
                                    .get(id)
                                    .and_then(|engagement| engagement.current_cut().ok())
                                    .flatten();
                                let resulting_revision = self
                                    .library
                                    .work_targets
                                    .get(&binding.target_id)
                                    .and_then(|target| target.current_basis.clone());
                                self.record_target_act(
                                    Some(id),
                                    &binding.target_id,
                                    crate::target_adapter::TargetActKind::Apply,
                                    candidate,
                                    Vec::new(),
                                    resulting_revision,
                                    crate::target_adapter::TargetActStatus::Completed,
                                    None,
                                )?;
                            }
                            let target = self.engagements.get(id).unwrap().target().to_string();
                            let target_id = self.engagement_index.get(id).cloned();
                            for (sibling_id, sibling) in &self.engagements {
                                if sibling_id != id
                                    && sibling.target() == target
                                    && self.engagement_index.get(sibling_id) == target_id.as_ref()
                                {
                                    let _ = sibling.sync_from_main();
                                }
                            }
                            Ok(state)
                        }
                        // The line moved after review. Re-probe this candidate into the
                        // conflict state immediately so the incoming chat owns a durable
                        // repair task instead of returning an unmodeled 409 (ADR 0096).
                        Ok(MergeOutcome::Conflict) => {
                            if let Some(binding) = self.library_chat_target_binding(id) {
                                self.record_target_act(
                                    Some(id),
                                    &binding.target_id,
                                    crate::target_adapter::TargetActKind::Apply,
                                    None,
                                    Vec::new(),
                                    None,
                                    crate::target_adapter::TargetActStatus::Refused,
                                    Some("target basis changed before apply".to_owned()),
                                )?;
                            }
                            self.admit_merge_command(id, MergeCommand::StartMerge)
                                .and_then(|_| {
                                    self.admit_merge_command(id, MergeCommand::WorkspaceConflict)
                                })
                        }
                        Err(e) => Err(e.to_string()),
                    },
                ),
            EngagementMergeAction::Integrate => self
                .admit_merge_command(id, MergeCommand::AdmitBoundaryIntegration)
                .and_then(|_| self.admit_merge_command(id, MergeCommand::IntegrateToMainline)),
            EngagementMergeAction::Retry => {
                match self.engagements.get(id).unwrap().merge_into_main() {
                    Ok(MergeOutcome::Clean) => {
                        let n = self
                            .store_ref()
                            .fold::<MergeState>(id)
                            .map(|s| s.retry_keys_used.len())
                            .unwrap_or(0);
                        let state = self.admit_merge_command(
                            id,
                            MergeCommand::RetryRepair(format!("retry-{n}")),
                        );
                        if state.is_ok() {
                            self.refresh_work_target_basis_from_chat(id);
                        }
                        state
                    }
                    Ok(MergeOutcome::Conflict) => {
                        Err("still conflicting — resolve in the editor".into())
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
        };
        if let Ok(state) = &result {
            let line = format!("merge → {:?}", state.phase);
            let event = ServerEvent::Admitted {
                kind: "merge".into(),
                text: line,
            };
            let _ = self
                .store_mut()
                .append_record(id, "transcript", &event.to_json());
            self.publish(id, event);
        }
        Some(result)
    }

    pub fn engagement_task_context(&mut self, id: &str) -> Option<EngagementTaskContext> {
        let eng = self.engagements.get(id)?;
        let work_target_basis = eng.boundary_cut().ok()?.0;
        let worktree = eng.path().to_path_buf();
        let project_id = self.library_project_of_chat(id);
        let mode = self.library_chat_mode(id);
        let sender = self.sender(id);
        Some(EngagementTaskContext {
            project_id,
            work_target_basis,
            worktree,
            sender,
            mode,
        })
    }

    pub(crate) fn sync_engagement_from_main(
        &mut self,
        id: &str,
    ) -> Option<Result<MergeOutcome, WorkspaceError>> {
        let eng = self.engagements.get(id)?;
        let result = eng.sync_from_main();
        if matches!(result, Ok(MergeOutcome::Clean)) {
            let ev = ServerEvent::Admitted {
                kind: "sync".into(),
                text: "synced from main".into(),
            };
            let _ = self
                .store_mut()
                .append_record(id, "transcript", &ev.to_json());
            self.publish(id, ev);
        }
        Some(result)
    }

    pub(crate) fn workspace_sender(&mut self) -> broadcast::Sender<ServerEvent> {
        self.sender(LIBRARY_SCOPE)
    }
}

fn path_is_in_scope(path: &str, scopes: &[String]) -> bool {
    let path = path.trim_start_matches("./");
    scopes.iter().any(|scope| {
        let scope = scope.trim().trim_start_matches("./").trim_end_matches('/');
        scope.is_empty() || scope == "." || path == scope || path.starts_with(&format!("{scope}/"))
    })
}

#[derive(Deserialize)]
pub(crate) struct CreateEngagement {
    /// Optional. When absent, the server mints one (`gen_id("chat")`) — the path the
    /// All-chats "+ new chat" quick-start uses, since the UI never mints ids. An
    /// embedding host may supply its already-authorized durable chat id.
    #[serde(default)]
    id: Option<String>,
}

/// Quick-start a work chat under Personal's default placement and its exact managed
/// target. The placement owns context; the selected target owns the candidate files.
pub(crate) async fn create_engagement(
    State(wb): State<SharedWorkbench>,
    Json(body): Json<CreateEngagement>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    // An explicit embedding id keeps its raw value as the title; a minted id gets
    // the "new chat" placeholder so the nav renders it as "Untitled" until the first
    // message auto-titles it (state/chat-title) — never the raw `chat-…` token.
    let (id, title) = match body.id {
        Some(id) => (id.clone(), id),
        None => (crate::library::gen_id("chat"), "new chat".to_string()),
    };
    match wb.create_default_engagement(id, title) {
        Ok(created) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "id": created.id,
                "branch": created.branch,
                "path": created.path,
            })),
        )
            .into_response(),
        Err(EngagementCreateError::Exists) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "engagement exists" })),
        )
            .into_response(),
        Err(EngagementCreateError::NoDefaultInstance) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "no default instance" })),
        )
            .into_response(),
        Err(EngagementCreateError::Git(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// List open engagement ids (a projection).
pub(crate) async fn list_engagements(
    State(wb): State<SharedWorkbench>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    // ENTSEC-2: a scoped member sees only chats in their granted projects (a no-op for
    // solo/owner); a chat outside a visible project is dropped, not just access-denied.
    let vis = wb.project_visibility(crate::net_http::bearer(&headers));
    let ids: Vec<_> = wb
        .engagement_ids()
        .into_iter()
        .filter(|id| wb.chat_visible(id, &vis))
        .collect();
    Json(serde_json::json!({ "engagements": ids })).into_response()
}

/// The reviewer's diff: the engagement branch against `main`.
pub(crate) async fn engagement_diff(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let Some(diff) = wb.engagement_diff(&id) else {
        return (StatusCode::NOT_FOUND, "no such engagement").into_response();
    };
    match diff {
        Ok(diff) => (StatusCode::OK, Json(serde_json::json!({ "diff": diff }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response(),
    }
}

/// Agent authoring (edit mode): read the engagement's `.agent-config.json`
/// (the agent's policy + model). Returns `{}` if none is set yet.
pub(crate) async fn get_config(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let Some(body) = wb.engagement_config_json(&id) else {
        return (StatusCode::NOT_FOUND, "no such engagement").into_response();
    };
    // A corrupt stored config is an error, not `{}` — answering `{}` here
    // would let the next save persist the emptied config (DR-0054 Phase A).
    let body = match body {
        Ok(body) => body,
        Err(error) => return (StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    };
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// Write GaugeDesk-owned provider/model/thinking selection. Package capabilities
/// and IFC policy are rejected here; they live in the authored package/envelope.
pub(crate) async fn put_config(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    body: String,
) -> impl IntoResponse {
    // Validate the host-owned subset before writing.
    if let Err(e) = gaugedesk_boundary::AgentConfig::runtime_settings_from_json(&body) {
        return (
            StatusCode::BAD_REQUEST,
            format!("invalid agent config: {e}"),
        )
            .into_response();
    }
    let mut wb = wb.lock_unpoisoned();
    let Some(result) = wb.write_engagement_config(&id, &body) else {
        return (StatusCode::NOT_FOUND, "no such engagement").into_response();
    };
    match result {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "saved": true }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response(),
    }
}

/// The durable transcript snapshot (`app-stack.md`: the transcript is a client
/// reduction of the server stream, **repairable from a snapshot**). Returns the
/// engagement's admitted transcript records in order — the client reduces these,
/// then subscribes to live SSE for the in-progress turn.
pub(crate) async fn get_transcript(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    match wb.engagement_transcript_json(&id) {
        Ok(body) => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(e) => err_response(e),
    }
}

/// The governance audit trail (ADR 0082 §4): why `main` moved without a
/// human — rule citations that deliberately do NOT appear in the user's
/// transcript.
pub(crate) async fn get_audit(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    match wb.engagement_audit_json(&id) {
        Ok(body) => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(e) => err_response(e),
    }
}

/// The worktree file tree (the WORKSPACE panel, `navigation.md`).
pub(crate) async fn get_tree(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let Some(tree) = wb.engagement_tree(&id) else {
        return (StatusCode::NOT_FOUND, "no such engagement").into_response();
    };
    match tree {
        Ok(entries) => {
            let files: Vec<_> = entries
                .into_iter()
                .map(|e| serde_json::json!({ "path": e.path, "is_dir": e.is_dir }))
                .collect();
            (StatusCode::OK, Json(serde_json::json!({ "files": files }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response(),
    }
}

#[derive(Deserialize)]
pub(crate) struct FileQuery {
    path: String,
}

/// Read a worktree file (the content viewer's View mode).
pub(crate) async fn get_file(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    Query(q): Query<FileQuery>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let Some(content) = wb.read_engagement_file(&id, &q.path) else {
        return (StatusCode::NOT_FOUND, "no such engagement").into_response();
    };
    match content {
        Ok(content) => {
            // The cut the reader is looking at, minted on demand — the
            // addressable base a cut-carrying save sends back (§12).
            // Best-effort: an unreadable cut degrades to a plain body.
            let cut = wb
                .engagement_current_cut(&id)
                .and_then(|result| result.ok())
                .flatten();
            let mut response = (StatusCode::OK, content).into_response();
            if let Some(cut) = cut {
                if let Ok(value) = axum::http::HeaderValue::from_str(&cut) {
                    response.headers_mut().insert("x-workspace-cut", value);
                }
            }
            response.into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e}")).into_response(),
    }
}

/// The base-carrying save body (SUB-6). `base_cut` names the state the
/// editor loaded (the GET's `x-workspace-cut`); `base_content` is the
/// pre-cut client's fallback (the body it loaded, resolved server-side).
/// `resolutions` are fold-settled regions riding a resolve re-save —
/// they mint durable region memory. With neither base (or a non-JSON
/// plain-text body), the save is the legacy unconditional write.
#[derive(Deserialize)]
pub(crate) struct SaveFileBody {
    content: String,
    base_content: Option<String>,
    base_cut: Option<String>,
    #[serde(default)]
    resolutions: Vec<RegionResolution>,
}

/// Save a worktree file (the editor's Edit mode) and commit it — the human's edit
/// is a contribution to the engagement thread that rides the merge. Each save is a
/// cut on the engagement line, so the workspace is the file's durable version history
/// (surfaced via the Diff / promote-to-main surface), not a parallel store.
///
/// With `{content, base_content}` JSON, the save is base-carrying: concurrent
/// changes merge through whip's token-level engine; real divergence returns
/// 409 with the structured regions (`pieces`) and the file's `current` body
/// (the re-save base) — nothing is written. A plain-text body (or JSON
/// without `base_content`) keeps the legacy last-writer-wins behavior.
pub(crate) async fn put_file(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    Query(q): Query<FileQuery>,
    body: String,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Err(reason) = wb.authorize_file_edit(&id, &q.path) {
        return (StatusCode::FORBIDDEN, reason).into_response();
    }
    let parsed: Option<SaveFileBody> = serde_json::from_str(&body).ok();
    let Some(SaveFileBody {
        content,
        base_content,
        base_cut,
        resolutions,
    }) = parsed
    else {
        // Plain-text body: the legacy unconditional write.
        let Some(result) = wb.write_engagement_file(&id, &q.path, &body) else {
            return (StatusCode::NOT_FOUND, "no such engagement").into_response();
        };
        return match result {
            Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "saved": true }))).into_response(),
            Err(e) => (StatusCode::BAD_REQUEST, format!("{e}")).into_response(),
        };
    };
    let base = match (&base_cut, &base_content) {
        (Some(cut), _) => Some(SaveBase::Cut(cut)),
        (None, Some(body)) => Some(SaveBase::Content(body)),
        (None, None) => None,
    };
    let Some(base) = base else {
        let Some(result) = wb.write_engagement_file(&id, &q.path, &content) else {
            return (StatusCode::NOT_FOUND, "no such engagement").into_response();
        };
        return match result {
            Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "saved": true }))).into_response(),
            Err(e) => (StatusCode::BAD_REQUEST, format!("{e}")).into_response(),
        };
    };
    let Some(result) =
        wb.save_engagement_file_with_base(&id, &q.path, &content, base, &resolutions)
    else {
        return (StatusCode::NOT_FOUND, "no such engagement").into_response();
    };
    match result {
        Ok(SaveFileOutcome::Written { cut }) => (
            StatusCode::OK,
            Json(serde_json::json!({ "saved": true, "cut": cut })),
        )
            .into_response(),
        Ok(SaveFileOutcome::Merged {
            cut,
            content,
            pieces,
        }) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "saved": true,
                "merged": true,
                "cut": cut,
                "content": content,
                "pieces": pieces,
            })),
        )
            .into_response(),
        Ok(SaveFileOutcome::Conflicted {
            current,
            current_cut,
            pieces,
        }) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "conflict": true,
                "current": current,
                "current_cut": current_cut,
                "pieces": pieces,
            })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e}")).into_response(),
    }
}

/// The live fold's read-only twin (§12.3): what WOULD this draft do
/// against the file as it stands? Nothing moves; region memory applies
/// exactly as a save would apply it.
#[derive(Deserialize)]
pub(crate) struct MergePreviewBody {
    path: String,
    draft: String,
    base_cut: String,
}

pub(crate) async fn post_merge_preview(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    Json(body): Json<MergePreviewBody>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let Some(result) = wb.engagement_merge_preview(&id, &body.path, &body.draft, &body.base_cut)
    else {
        return (StatusCode::NOT_FOUND, "no such engagement").into_response();
    };
    match result {
        Ok(Some(preview)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "known_base": true,
                "clean": preview.clean,
                "merged": preview.merged,
                "current_cut": preview.current_cut,
                "pieces": preview.pieces,
            })),
        )
            .into_response(),
        // An unknown base cut is an honest miss (stale tab, foreign
        // history): the client reloads rather than trusting a fold.
        Ok(None) => (
            StatusCode::OK,
            Json(serde_json::json!({ "known_base": false })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e}")).into_response(),
    }
}

/// Merge state (the review surface): the turn's branch-vs-`main` merge lifecycle.
pub(crate) async fn get_merge(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    match wb.engagement_merge_state(&id) {
        Ok(state) => (StatusCode::OK, Json(state)).into_response(),
        Err(e) => err_response(e),
    }
}

/// Discard an engagement's work, restoring its worktree to `main` — the user-facing
/// **revert** (UX-5). `main` is untouched; the dropped work is recoverable only by redoing
/// it. Fail-closed: an unknown engagement 404s.
pub(crate) async fn post_revert(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let Some(result) = wb.revert_engagement(&id) else {
        return (StatusCode::NOT_FOUND, "no such engagement").into_response();
    };
    if let Err(e) = result {
        return (StatusCode::BAD_REQUEST, format!("{e}")).into_response();
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "reverted": true })),
    )
        .into_response()
}

pub(crate) async fn post_merge_command(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    Json(action): Json<EngagementMergeAction>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let Some(result) = wb.apply_engagement_merge_action(&id, action) else {
        return (StatusCode::NOT_FOUND, "no such engagement").into_response();
    };

    match result {
        Ok(state) => (StatusCode::OK, Json(state)).into_response(),
        Err(e) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "rejected": e })),
        )
            .into_response(),
    }
}

/// Live event stream (SSE): the engagement's operational + admitted events as
/// they happen. The client reduces this into its transcript.
pub(crate) async fn engagement_events(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = wb.lock_unpoisoned().sender(&id).subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| {
        msg.ok()
            .map(|ev: ServerEvent| Ok(Event::default().data(ev.to_json())))
    });
    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

/// Live **workspace** event stream (SSE): a "changed" ping whenever the library
/// mutates (a chat/project/archetype/placement created, renamed, or removed — on
/// THIS client or any other, e.g. a paired device). The client re-reads `/workspace`
/// on each ping, so every nav mirrors the node live (the push the system is built
/// on, not a poll). Subscribes to the reserved `library` stream key.
pub(crate) async fn workspace_events(
    State(wb): State<SharedWorkbench>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = wb.lock_unpoisoned().workspace_sender().subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| {
        msg.ok()
            .map(|ev: ServerEvent| Ok(Event::default().data(ev.to_json())))
    });
    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

#[derive(Deserialize)]
pub(crate) struct TaskBody {
    prompt: String,
    /// Native image content blocks attached to this message (UX-14). Resolved by
    /// WhippleScript as message-scoped model input; never recorded in the durable
    /// transcript. Absent ⇒ a text turn.
    #[serde(default)]
    images: Vec<gaugedesk_harness::ImageContent>,
}

/// The status a failed turn answers with.
///
/// A refusal is not a gateway failure. The runtime declining a turn on
/// information-flow policy is a decision the caller must read and act on, so it
/// answers `403`; only something actually breaking keeps `502`.
///
/// The distinction is not cosmetic, and getting it wrong is expensive twice
/// over: a 5xx invites a retry of something that will be refused identically
/// every time, and Cloudflare substitutes its own body for an origin 5xx — so
/// the runtime's explanation of *which* rule denied *which* read is replaced by
/// "the origin is overloaded or misconfigured" before the caller sees it. The
/// production wiring canary read that as an origin outage for days.
fn task_failure_status(error: &crate::engine::EngineError) -> StatusCode {
    if error.is_policy_denial() {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::BAD_GATEWAY
    }
}

/// Task an engagement: drive one governed WhippleScript turn in its worktree,
/// streaming operational events live (SSE) and returning the diff + output.
pub(crate) async fn post_task(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    actor: Option<axum::extract::Extension<crate::identity::AuthenticatedActor>>,
    Json(body): Json<TaskBody>,
) -> impl IntoResponse {
    // Brief lock: confirm the engagement and grab its worktree, live sender, mode.
    let (worktree, sender, mode) = {
        let mut g = wb.lock_unpoisoned();
        let Some(context) = g.engagement_task_context(&id) else {
            return (StatusCode::NOT_FOUND, "no such engagement").into_response();
        };
        (context.worktree, context.sender, context.mode)
    };

    let (account_scope, tenant_scope) = {
        let g = wb.lock_unpoisoned();
        (
            g.account_scope_for(crate::net_http::bearer(&headers)),
            crate::workbench_auth::req_scope(&headers),
        )
    };
    let wb2 = wb.clone();
    let task = body.prompt;
    let images = body.images;
    let actor = actor.map(|axum::extract::Extension(actor)| actor.0);
    let id2 = id.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        engine::run_engagement_turn(
            &wb2,
            &id2,
            &worktree,
            &sender,
            engine::EngagementTurnInput {
                task: &task,
                images: &images,
                mode,
                authenticated_actor: actor.as_ref(),
                contribution_by: None,
                account_scope: &account_scope,
                tenant_scope: &tenant_scope,
                runtime_command_id: None,
                harness_factory: None,
            },
        )
    })
    .await;

    match outcome {
        Ok(Ok(result)) => (StatusCode::OK, Json(result)).into_response(),
        Ok(Err(e)) => (
            task_failure_status(&e),
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "task panicked").into_response(),
    }
}

/// Sync settled `main` into this engagement (WC-1): pick up work other engagements
/// in the workstream promoted. Returns the outcome; a conflict leaves the worktree
/// for repair (the merge review surface).
pub(crate) async fn post_sync(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let Some(result) = wb.sync_engagement_from_main(&id) else {
        return (StatusCode::NOT_FOUND, "no such engagement").into_response();
    };
    match result {
        Ok(MergeOutcome::Clean) => (
            StatusCode::OK,
            Json(serde_json::json!({ "synced": true, "conflict": false })),
        )
            .into_response(),
        Ok(MergeOutcome::Conflict) => (
            StatusCode::OK,
            Json(serde_json::json!({ "synced": false, "conflict": true })),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response(),
    }
}

/// Stop a running turn (`run-chat.md`: Stop = abort the run). Fires the turn's
/// out-of-band interrupt handle so its blocking `recv` returns and the run fails;
/// the session is retired and the next turn respawns. A no-op if nothing is
/// running (or in fake-agent mode, where turns are instant).
pub(crate) async fn post_stop(
    State(_wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match engine::running_turn_interrupt(&id) {
        Some(interrupt) => {
            // The handle was captured at turn start. WhippleScript records a
            // cooperative cancellation request on an independent store
            // connection, so durable thread state survives the interrupted turn.
            interrupt();
            (StatusCode::OK, Json(serde_json::json!({ "stopped": true }))).into_response()
        }
        None => (
            StatusCode::OK,
            Json(serde_json::json!({ "stopped": false, "reason": "nothing running" })),
        )
            .into_response(),
    }
}

/// **Test-only** — reset the control plane to a freshly-seeded state. Gated behind
/// `GAUGEDESK_TEST_RESET` (set by the e2e launcher), so it is inert in a normal run.
///
/// The e2e suite shares one control plane across all scenarios, serially; with no
/// reset the append-only store accumulates every scenario's projects, archetypes
/// and chats, and later scenarios collide with the pile (stale `.first()` matches,
/// off-screen menus on a tall tree). This hands each scenario a clean slate: stop
/// every live agent process, wipe the on-disk state, and rebuild the seeded
/// workbench in place behind the shared mutex.
#[cfg(debug_assertions)]
#[derive(Default, serde::Deserialize)]
pub(crate) struct TestResetQuery {
    /// Seed one real tracker item after the reset so browser tests can exercise
    /// the production roster/assignment client. This remains behind the same
    /// test-only process guard as the reset itself.
    #[serde(default)]
    assignable_task: bool,
    /// Seed a real project chat with one context handle whose payload access is
    /// still Init, for production-client request/approval journeys.
    #[serde(default)]
    withheld_resource: bool,
    /// Seed a local chat whose export has all required source consent, so the
    /// desktop picker can supply target admission and perform the real crossing.
    #[serde(default)]
    exportable_output: bool,
    /// Seed an attestation-required org placement floor for the enrolled-client
    /// production journey. The test-only route remains guard- and build-gated.
    #[serde(default)]
    attested_placement_policy: bool,
}

/// Debug builds only (DR-0054 Phase A): a route that deletes the entire state
/// root must not exist in a release artifact, so the handler and its mounting
/// are both compiled out. The `GAUGEDESK_TEST_RESET` process guard below
/// remains as defense in depth where the route does exist.
#[cfg(debug_assertions)]
pub(crate) async fn post_test_reset(
    State(wb): State<SharedWorkbench>,
    Query(query): Query<TestResetQuery>,
) -> impl IntoResponse {
    if gaugedesk_env::var("TEST_RESET").is_none() {
        return (StatusCode::FORBIDDEN, "reset is disabled").into_response();
    }
    let mut guard = wb.lock_unpoisoned();
    let root = guard.root_path();
    if root.as_os_str().is_empty() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "no state root to reset").into_response();
    }
    guard.shutdown_sessions_for_reset();
    engine::clear_running_turns();
    // Drop the old workbench — closing the sqlite store and releasing the instance
    // worktrees — by swapping in a throwaway in-memory one, so the files unlink.
    match Store::open_in_memory() {
        Ok(scratch) => drop(std::mem::replace(&mut *guard, Workbench::new(scratch))),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("reset scratch store: {e}"),
            )
                .into_response()
        }
    }
    let _ = std::fs::remove_dir_all(&root);
    // Clear any armed test-only conflict injection (UX-7) so it can't leak across scenarios.
    engine::set_force_merge_conflict(false);
    match build_workbench(&root) {
        Ok(mut fresh) => {
            // The enterprise browser composition uses the same reset hook. Seed
            // its controlled identities and memberships here, behind the
            // test-only gate, rather than retaining a production `/admin/*`
            // write bypass solely for test setup. When the launcher supplies
            // credentials, the production enterprise middleware and cookie /
            // bearer parser remain active; absence and invalid credentials fail
            // closed exactly as they do outside the harness.
            let owner = crate::org::MembershipRecord {
                id: "local-user".to_owned(),
                op: crate::org::RecordOp::Upsert,
                org_id: crate::org::ORG_ID.to_owned(),
                authority: "local-user".to_owned(),
                email: String::new(),
                role: "owner".to_owned(),
                status: crate::org::MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            };
            let _ = fresh.store_mut().append_record(
                crate::org::ORG_SCOPE,
                "membership",
                &serde_json::to_string(&owner).expect("test owner serializes"),
            );
            if let Some(owner_token) = gaugedesk_env::var("TEST_IDENTITY_TOKEN") {
                use std::sync::Arc;

                use gaugedesk_core::abac::AuthorityAttributes;
                use gaugedesk_core::ids::AuthorityId;

                let member_token = gaugedesk_env::var("TEST_MEMBER_TOKEN")
                    .unwrap_or_else(|| "gw-e2e-member-token".to_owned());
                let member = crate::org::MembershipRecord {
                    id: "e2e-member".to_owned(),
                    op: crate::org::RecordOp::Upsert,
                    org_id: crate::org::ORG_ID.to_owned(),
                    authority: "e2e-member".to_owned(),
                    email: String::new(),
                    role: "member".to_owned(),
                    status: crate::org::MembershipStatus::Active,
                    managed_by_scim: false,
                    team: None,
                };
                let _ = fresh.store_mut().append_record(
                    crate::org::ORG_SCOPE,
                    "membership",
                    &serde_json::to_string(&member).expect("test member serializes"),
                );
                let idp = crate::identity::LoopbackIdentityProvider::new()
                    .enroll(
                        owner_token,
                        AuthorityId::new("local-user"),
                        AuthorityAttributes::default(),
                    )
                    .enroll(
                        member_token,
                        AuthorityId::new("e2e-member"),
                        AuthorityAttributes::default(),
                    );
                fresh.set_identity_provider(Some(Arc::new(idp)));
            }
            if query.attested_placement_policy {
                let record = crate::org::PlacementPolicyRecord {
                    id: crate::org::ORG_ID.to_owned(),
                    op: crate::org::RecordOp::Upsert,
                    policy: gaugedesk_core::boundary_lifecycle::PlacementPolicy {
                        require_attested: true,
                        allowed_operators: Default::default(),
                    },
                };
                let _ = fresh.store_mut().append_record(
                    crate::org::ORG_SCOPE,
                    "placement_policy",
                    &serde_json::to_string(&record).expect("test placement policy serializes"),
                );
            }
            if query.assignable_task {
                let tracker = match fresh.account_tracker() {
                    Ok(tracker) => tracker,
                    Err(error) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("test tracker: {error}"),
                        )
                            .into_response()
                    }
                };
                if let Err(error) = tracker.file_item(
                    crate::onboarding::ONBOARDING_QUEUE,
                    "Assign this onboarding step",
                    "Browser fixture for the production roster and assignment path.",
                    &[],
                    &serde_json::json!({ "step": "assignment-contract" }),
                    Some("test-system"),
                ) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("test tracker seed: {error}"),
                    )
                        .into_response();
                }
            }
            if query.withheld_resource {
                use gaugedesk_core::boundary::Authority;
                use gaugedesk_core::resource::{
                    ContentLocator, Resource, ResourceId, ResourceKind, ResourceRecord,
                };

                let chat = "access-contract";
                if fresh
                    .create_default_engagement(chat.to_owned(), "Access contract".to_owned())
                    .is_err()
                {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "test access chat could not be created",
                    )
                        .into_response();
                }
                let owner = Authority::from(fresh.authority().as_str());
                let record = ResourceRecord::new(
                    Resource::input(
                        ResourceId::new("withheld-context"),
                        ResourceKind::context(),
                        owner.clone(),
                    ),
                    ContentLocator::Workspace {
                        path: "withheld.txt".to_owned(),
                        commit: "test-fixture".to_owned(),
                    },
                    |_| owner.clone(),
                );
                if let Err(error) = crate::resource_store::put(fresh.store_mut(), chat, &record) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("test access resource: {error:?}"),
                    )
                        .into_response();
                }
            }
            if query.exportable_output {
                let chat = "export-contract";
                if fresh
                    .create_default_engagement(chat.to_owned(), "Export contract".to_owned())
                    .is_err()
                {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "test export chat could not be created",
                    )
                        .into_response();
                }
                match fresh.write_engagement_file(chat, "deliverable.txt", "desktop export proof\n")
                {
                    Some(Ok(())) => {}
                    Some(Err(error)) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("test export file: {error}"),
                        )
                            .into_response()
                    }
                    None => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "test export engagement disappeared",
                        )
                            .into_response()
                    }
                }
                let authority = fresh.authority().as_str().to_owned();
                let output = match crate::resource_store::mint_output(
                    fresh.store_mut(),
                    chat,
                    &authority,
                    "test-fixture",
                ) {
                    Ok(output) => output,
                    Err(error) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("test output resource: {error:?}"),
                        )
                            .into_response()
                    }
                };
                match fresh.admit_resource_export(chat, &output.resource.id) {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "test output resource disappeared",
                        )
                            .into_response()
                    }
                    Err(error) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("test output export proposal: {error:?}"),
                        )
                            .into_response()
                    }
                }
            }
            *guard = fresh;
            (StatusCode::OK, Json(serde_json::json!({ "reset": true }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("rebuild: {e}")).into_response(),
    }
}

#[cfg(debug_assertions)]
#[derive(serde::Deserialize)]
pub(crate) struct ForceConflictBody {
    #[serde(default)]
    on: bool,
}

/// Test-only (`UX-7`): arm/disarm merge-conflict injection so a browser BDD can drive the
/// `INV-24` conflict-repair path. Inert unless `GAUGEDESK_TEST_RESET` is set, like
/// [`post_test_reset`]; `POST /test/reset` also clears it. Debug builds only
/// (DR-0054 Phase A), like the reset route it accompanies.
#[cfg(debug_assertions)]
pub(crate) async fn post_test_force_conflict(
    Json(body): Json<ForceConflictBody>,
) -> impl IntoResponse {
    if gaugedesk_env::var("TEST_RESET").is_none() {
        return (StatusCode::FORBIDDEN, "conflict injection is disabled").into_response();
    }
    engine::set_force_merge_conflict(body.on);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "force_conflict": body.on })),
    )
        .into_response()
}

#[cfg(test)]
mod task_failure_status_tests {
    use super::task_failure_status;
    use crate::engine::EngineError;
    use axum::http::StatusCode;
    use std::io;

    /// The runtime refusing a turn on information-flow policy answers `403`.
    ///
    /// This is the case the wiring canary hit: `denied read in rule
    /// `converse`` is the policy speaking, not a broken upstream, and it must
    /// not be reported as one.
    #[test]
    fn a_policy_denial_is_forbidden_not_a_gateway_failure() {
        let denied = EngineError::Harness(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "package violates the admitted information-flow policy: denied read in rule `converse`",
        ));
        assert!(denied.is_policy_denial());
        assert_eq!(task_failure_status(&denied), StatusCode::FORBIDDEN);
    }

    /// A genuine transport death keeps `502`. The point of the change is to
    /// separate the two, not to move everything out of the 5xx range.
    #[test]
    fn a_transport_failure_is_still_a_gateway_failure() {
        let broken = EngineError::Harness(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "model transport died mid-turn",
        ));
        assert!(!broken.is_policy_denial());
        assert_eq!(task_failure_status(&broken), StatusCode::BAD_GATEWAY);
    }

    /// The runtime being wrong — a malformed package, an unknown instance —
    /// arrives as `InvalidData` and stays `502`. Only the two deliberate
    /// decision variants are reclassified upstream.
    #[test]
    fn a_runtime_fault_is_still_a_gateway_failure() {
        let invalid = EngineError::Harness(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown instance: inst-gone",
        ));
        assert!(!invalid.is_policy_denial());
        assert_eq!(task_failure_status(&invalid), StatusCode::BAD_GATEWAY);
    }

    /// The message-only leg carries no classification and must not be guessed
    /// at from its text — string-sniffing a denial is exactly what the typed
    /// path replaces.
    #[test]
    fn a_message_leg_is_never_read_as_a_denial() {
        let message = EngineError::Message(
            "package violates the admitted information-flow policy: denied read".to_string(),
        );
        assert!(!message.is_policy_denial());
        assert_eq!(task_failure_status(&message), StatusCode::BAD_GATEWAY);
    }
}
