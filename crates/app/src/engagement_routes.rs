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
use gaugedesk_core::instance::{InstanceCommand, InstanceState};
use gaugedesk_core::merge::{MergeCommand, MergeState};
#[cfg(debug_assertions)]
use gaugedesk_store::Store;
use gaugedesk_workspace::{
    ChatWorkspace, FileEntry, LineSync, MergeOutcome, MergePreview, RegionResolution, SaveBase,
    SaveFileOutcome, WorkspaceError,
};
use serde::Deserialize;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use whipplescript_kernel::harness_model::ModelWire;

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
    pub(crate) fn is_installed_method_path(&self, chat_id: &str, path: &str) -> bool {
        let Some(chat) = self.library.chats.get(chat_id) else {
            return false;
        };
        if !self
            .library
            .instances
            .get(&chat.instance_id)
            .is_some_and(|instance| instance.kind == crate::library::InstanceKind::Using)
        {
            return false;
        }
        let path = path.trim_start_matches("./");
        let runtime_agent = format!(
            "{}/agent",
            gaugedesk_boundary::definition::RUNTIME_MOUNT_ROOT
        );
        path == "agent"
            || path.starts_with("agent/")
            || path == runtime_agent
            || path.starts_with(&format!("{runtime_agent}/"))
    }

    /// A use chat's installed method is a package payload, even when the
    /// workspace also carries its runtime mount. Chat/project admission is
    /// not the separate resource grant needed by an account-backed reader.
    pub(crate) fn installed_method_read_requires_grant(&self, chat_id: &str, path: &str) -> bool {
        if self.idp.is_none()
            && !crate::workbench_auth::web_account_mode()
            && self
                .library
                .chats
                .get(chat_id)
                .is_none_or(|chat| chat.owner.is_none())
        {
            return false;
        }
        self.is_installed_method_path(chat_id, path)
    }

    /// A use chat reads its installed Agent definition from the frozen
    /// package. These files are a view, not part of any selected work target.
    fn installed_agent_view(
        &self,
        chat_id: &str,
    ) -> Option<(std::path::PathBuf, serde_json::Value)> {
        let chat = self.library.chats.get(chat_id)?;
        let instance = self.library.instances.get(&chat.instance_id)?;
        if instance.kind != crate::library::InstanceKind::Using {
            return None;
        }
        let agent = self.library.agents.get(&instance.agent_id)?;
        let target = self.library.authoring_target_for(&agent.id)?;
        let root = crate::library_state::published_package_root(
            &self.targets_dir(),
            &target.id,
            instance.version,
        );
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("package.json")).ok()?).ok()?;
        (manifest["schema"] == "whipplescript.agent_package.v1").then_some((root, manifest))
    }

    fn installed_agent_file(&self, chat_id: &str, path: &str) -> Option<Vec<u8>> {
        let (root, manifest) = self.installed_agent_view(chat_id)?;
        let source = manifest.get("source")?.as_str()?;
        let system = manifest.get("system_prompt")?.as_str()?;
        let file = match path {
            "agent/AGENTS.md" => "AGENTS.md",
            "agent/HUMANS.md" => "HUMANS.md",
            "agent/SYSTEM.md" => system,
            _ if path == format!("agent/{source}") => source,
            _ => return None,
        };
        let body = std::fs::read(root.join(file)).ok()?;
        if path == "agent/SYSTEM.md" && body.is_empty() {
            return None;
        }
        if path == format!("agent/{source}")
            && body == gaugedesk_boundary::definition::DEFAULT_METHOD_SOURCE.as_bytes()
        {
            return None;
        }
        Some(body)
    }

    fn engagement_single_target_root(&self, chat_id: &str) -> Option<String> {
        let chat = self.library.chats.get(chat_id)?;
        self.library
            .instances
            .get(&chat.instance_id)
            .is_some_and(|instance| instance.kind == crate::library::InstanceKind::Using)
            .then_some(())?;
        let set = self.library.current_target_set(chat_id)?;
        let [member] = set.members.as_slice() else {
            return None;
        };
        crate::library::target_id_path_v1(&member.target_id)
            .ok()
            .map(|root| format!("targets/{root}"))
    }

    pub(crate) fn engagement_context_target_root(
        &self,
        chat_id: &str,
        requested_target_id: Option<&str>,
    ) -> Result<Option<String>, String> {
        let chat = self
            .library
            .chats
            .get(chat_id)
            .ok_or_else(|| "no such engagement".to_owned())?;
        let Some(instance) = self.library.instances.get(&chat.instance_id) else {
            return Err("chat placement is unavailable".to_owned());
        };
        if instance.kind != crate::library::InstanceKind::Using {
            return if requested_target_id.is_some() {
                Err("edit-chat context does not select a work target".to_owned())
            } else {
                Ok(None)
            };
        }
        let set = self
            .library
            .current_target_set(chat_id)
            .ok_or_else(|| "chat target set is unavailable".to_owned())?;
        let member = match requested_target_id {
            Some(target_id) => set
                .members
                .iter()
                .find(|member| member.target_id == target_id)
                .ok_or_else(|| "context target is not selected by this chat".to_owned())?,
            None => match set.members.as_slice() {
                [member] => member,
                _ => return Err("select one writable target_id for context ingest".to_owned()),
            },
        };
        if member.participation != crate::library::TargetParticipationMode::Writable
            || !member.capability_ceiling.propose
        {
            return Err(format!(
                "context target {} is read-only in this chat",
                member.target_id
            ));
        }
        crate::library::target_id_path_v1(&member.target_id)
            .map(|root| Some(format!("targets/{root}")))
    }

    pub(crate) fn engagement_workspace_path(&self, chat_id: &str, path: &str) -> String {
        if (path == "agent" || path.starts_with("agent/"))
            && self.installed_agent_view(chat_id).is_some()
        {
            return format!(
                "{}/{path}",
                gaugedesk_boundary::definition::RUNTIME_MOUNT_ROOT
            );
        }
        if path == "artifacts"
            || path.starts_with("artifacts/")
            || path == "work"
            || path.starts_with("work/")
            || path == "targets"
            || path.starts_with("targets/")
            || path == gaugedesk_boundary::definition::RUNTIME_MOUNT_ROOT
            || path.starts_with(&format!(
                "{}/",
                gaugedesk_boundary::definition::RUNTIME_MOUNT_ROOT
            ))
        {
            return path.to_owned();
        }
        let Some(root) = self.engagement_single_target_root(chat_id) else {
            return path.to_owned();
        };
        format!("{root}/{path}")
    }

    pub(crate) fn create_default_engagement(
        &mut self,
        id: String,
        title: String,
    ) -> Result<CreatedEngagement, EngagementCreateError> {
        let root_id = self.default_instance.clone();
        self.create_personal_engagement(id, title, root_id)
    }

    /// Quick-start a chat on one Personal's general placement: the install's
    /// own, or a signed-in account's (DR-0268 §5).
    pub(crate) fn create_personal_engagement(
        &mut self,
        id: String,
        title: String,
        root_id: String,
    ) -> Result<CreatedEngagement, EngagementCreateError> {
        if self.engagements.contains_key(&id) {
            return Err(EngagementCreateError::Exists);
        }
        let target = self
            .resolve_placement_target(&root_id, None)
            .map_err(EngagementCreateError::Git)?;
        let project_id = self
            .library
            .instances
            .get(&root_id)
            .and_then(|instance| instance.project_id.clone())
            .ok_or_else(|| EngagementCreateError::Git("default placement has no project".into()))?;
        if self.project_moving(&project_id) {
            return Err(EngagementCreateError::Git(
                crate::federation::PAUSED_FOR_MOVE.into(),
            ));
        }
        self.ensure_collaboration_target_partition(&project_id, &target.id)
            .map_err(EngagementCreateError::Git)?;
        let collaboration_workspace_id = self
            .library
            .project_collaboration_workspaces
            .get(&project_id)
            .ok_or_else(|| {
                EngagementCreateError::Git(
                    "default project collaboration workspace is unavailable".into(),
                )
            })?
            .workspace_id
            .clone();
        let Some(workspace) = self
            .collaboration_workspaces
            .get(&collaboration_workspace_id)
        else {
            return Err(EngagementCreateError::NoDefaultInstance);
        };
        let roots = crate::target_names::chat_target_roots([target.id.as_str()])
            .map_err(EngagementCreateError::Git)?;
        let eng = workspace
            .create_engagement_subset(&id, workspace.mainline(), &roots)
            .map_err(|e| EngagementCreateError::Git(e.to_string()))?;
        let basis = target.current_basis.clone().ok_or_else(|| {
            EngagementCreateError::Git("default work target has no exact basis".into())
        })?;
        let branch = eng.branch().to_string();
        let path = eng.path().to_string_lossy().to_string();
        self.write_created_chat_record(ChatRecord {
            owner: None,
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: id.clone(),
            op: RecordOp::Upsert,
            instance_id: root_id,
            title,
            created_position: 0,
            forked_from: None,
            forked_from_entry: None,
            forked_from_cut: None,
        });
        self.write_chat_target_record(ChatTargetBindingRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            chat_id: id.clone(),
            op: RecordOp::Upsert,
            target_id: target.id.clone(),
            basis,
            path_scope: target.path_scope.clone(),
            capabilities: target.capabilities.clone(),
        });
        self.write_chat_target_set_record(crate::library::ChatTargetSetRevisionRecord {
            chat_id: id.clone(),
            revision: 0,
            members: vec![crate::library::ChatTargetSetMemberRecord {
                target_id: target.id,
                adapter_family: target.adapter_family,
                path_scope: target.path_scope,
                capability_ceiling: target.capabilities,
                participation: crate::library::TargetParticipationMode::Writable,
            }],
            created_position: 0,
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        })
        .map_err(EngagementCreateError::Git)?;
        self.register_engagement(id.clone(), collaboration_workspace_id, eng);
        if self.library.agents.contains_key(crate::DEFAULT_AGENT) {
            self.refresh_chat_discipline_mount(&id)
                .map_err(EngagementCreateError::Git)?;
        } else {
            self.refresh_chat_target_set_mount(&id)
                .map_err(EngagementCreateError::Git)?;
        }
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

    pub(crate) fn live_engagement_target_id(&self, chat_id: &str) -> Option<&str> {
        self.engagement_index.get(chat_id).map(String::as_str)
    }

    pub(crate) fn engagement_ids(&self) -> Vec<String> {
        self.engagements.keys().cloned().collect()
    }

    /// The chat's diff against its line. A pending target rename (DR-0248)
    /// stays in it as the change to that target's name file, which the client
    /// shows as the rename rather than as a file.
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
        if self.chat_project_moving(id) {
            return Some(Err(crate::federation::paused_for_move()));
        }
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
        // ADR 0141: the durable log is a rooted tree — fold the whole lineage,
        // root first. Inherited entries keep their authoring scope's identity
        // (`origin` + that scope's entry ids), so "Fork here" on an inherited
        // line forks the *origin* chat at its own entry; the vault decrypts
        // each scope's rows with that scope's own key.
        let mut rows = Vec::new();
        for (scope, bound) in self.effective_log_lineage(id) {
            let events = self.store_ref().events(&scope)?;
            let bound = bound.unwrap_or(i64::MAX);
            let forkable: std::collections::BTreeSet<i64> = events
                .iter()
                .filter(|(_, kind, _)| kind == crate::engine::TURN_BOUNDARY_KIND)
                .filter_map(|(_, _, payload)| {
                    serde_json::from_str::<crate::engine::TurnBoundaryRecord>(payload).ok()
                })
                .flat_map(|boundary| [boundary.user_entry_id, boundary.assistant_entry_id])
                .filter(|entry| *entry <= bound)
                .collect();
            // The settle receipt, rather than a successful read tool, proves a
            // workspace change. Pair it with the run immediately preceding it;
            // a later retry or a receipt beyond a fork cut cannot qualify it.
            let mut receipts = std::collections::BTreeMap::new();
            let mut preceding_run = None;
            for (position, kind, payload) in &events {
                if *position > bound {
                    continue;
                }
                if kind == "transcript" {
                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(payload) {
                        if event["type"] == "user" {
                            preceding_run = None;
                        } else if event["type"] == "admitted" && event["kind"] == "run" {
                            preceding_run =
                                (event["text"] == "run → Completed").then_some(*position);
                        }
                    }
                } else if kind == crate::turn_summary::TURN_SUMMARY_KIND {
                    if let (Some(run), Ok(summary)) = (
                        preceding_run.take(),
                        serde_json::from_str::<crate::turn_summary::TurnSummary>(payload),
                    ) {
                        if summary.receipt_status == crate::turn_summary::ReceiptStatus::Completed {
                            receipts.insert(
                                run,
                                serde_json::json!({
                                    "user_entry_id": summary.user_entry_id,
                                    "summary_entry_id": position,
                                    "changed_count": summary.changed_count,
                                }),
                            );
                        }
                    }
                }
            }
            let mut user_entry = None;
            let mut process = None;
            for (position, kind, payload) in events.into_iter().filter(|(p, _, _)| *p <= bound) {
                if kind == crate::target_change_set::TURN_PROCESS_DECLARATION_KIND {
                    process = serde_json::from_str::<
                        crate::target_change_set::TurnProcessDeclaration,
                    >(&payload)
                    .ok()
                    .filter(|declaration| {
                        Some(declaration.run_ref.as_str()) == user_entry.as_deref()
                    });
                    continue;
                }
                if kind != "transcript" {
                    continue;
                }
                let Ok(mut event) = serde_json::from_str::<serde_json::Value>(&payload) else {
                    continue;
                };
                let Some(object) = event.as_object_mut() else {
                    continue;
                };
                if object.get("type").and_then(|v| v.as_str()) == Some("user") {
                    user_entry = Some(format!("{scope}:{position}"));
                    process = None;
                }
                // The agent sees a presented folder name; the file viewer uses
                // its stable root. Resolve only against this turn's immutable
                // declaration, never today's names or model-supplied metadata.
                object.remove("canonical_target");
                if object.get("type").and_then(|v| v.as_str()) == Some("toolresult")
                    && matches!(
                        object.get("tool").and_then(|v| v.as_str()),
                        Some("write" | "edit")
                    )
                {
                    if let Some(target) = object
                        .get("target")
                        .and_then(|v| v.as_str())
                        .and_then(|target| process.as_ref()?.canonical_tool_target(target))
                    {
                        object.insert("canonical_target".into(), target.into());
                    }
                }
                object.insert("entry_id".into(), position.into());
                if let Some(receipt) = receipts.remove(&position) {
                    object.insert("workspace_change".into(), receipt);
                }
                if forkable.contains(&position) {
                    object.insert("forkable".into(), true.into());
                }
                if scope != id {
                    object.insert("origin".into(), scope.clone().into());
                }
                rows.push(event);
            }
        }
        serde_json::to_string(&rows).map_err(Into::into)
    }

    /// The chat's latest settled context-window reading (the composer's context
    /// meter), paired with the window of the model that read it — the runtime's
    /// own capability table, the same number its compaction trigger measures
    /// against. `null` when no turn has reported one: an Environment that
    /// cannot measure the window says so by showing nothing (ADR 0135's
    /// honesty rule), never by estimating.
    pub(crate) fn engagement_context_json(
        &self,
        id: &str,
    ) -> Result<String, gaugedesk_store::AdmitError> {
        let readings = self
            .store_ref()
            .records(id, crate::engine::CONTEXT_READING_KIND)?;
        let Some(latest) = readings.last() else {
            return Ok("null".to_owned());
        };
        let reading: gaugedesk_harness::ContextWindowReading = serde_json::from_str(latest)?;
        let window = whipplescript_kernel::harness_model::model_context_window(
            match reading.provider.as_str() {
                "anthropic" => ModelWire::AnthropicMessages,
                "openai" | "openai-codex" | "xai-grok" => ModelWire::OpenAiResponses,
                // The conservative family default; the function keys Claude
                // models off the model id regardless of this wire.
                _ => ModelWire::OpenAiChatCompat,
            },
            &reading.model,
        );
        Ok(serde_json::json!({
            "used_tokens": reading.last_input_tokens,
            "window_tokens": window,
            "provider": reading.provider,
            "model": reading.model,
        })
        .to_string())
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
        target_id: Option<&str>,
    ) -> Option<Result<(usize, String), String>> {
        if self.chat_project_moving(chat_id) {
            return Some(Err(crate::federation::PAUSED_FOR_MOVE.to_owned()));
        }
        let prefix = match self.engagement_context_target_root(chat_id, target_id) {
            Ok(prefix) => prefix,
            Err(error) => return Some(Err(error)),
        };
        let eng = self.engagements.get(chat_id)?;
        let result = match prefix {
            Some(prefix) => eng.ingest_into(&prefix, path),
            None => eng.ingest(path),
        };
        let n = match result {
            Ok(n) => n,
            Err(e) => return Some(Err(e.to_string())),
        };
        let commit = match eng.commit_turn(&format!("ingest context: {}", path.display())) {
            Ok(commit) => commit.map(|c| c.0).unwrap_or_default(),
            Err(e) => return Some(Err(e.to_string())),
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
        files: &[(String, Vec<u8>)],
        target_id: Option<&str>,
    ) -> Option<Result<(usize, String), String>> {
        if self.chat_project_moving(chat_id) {
            return Some(Err(crate::federation::PAUSED_FOR_MOVE.to_owned()));
        }
        let prefix = match self.engagement_context_target_root(chat_id, target_id) {
            Ok(prefix) => prefix,
            Err(error) => return Some(Err(error)),
        };
        let eng = self.engagements.get(chat_id)?;
        let result = match prefix {
            Some(prefix) => eng.ingest_upload_into(&prefix, files),
            None => eng.ingest_upload(files),
        };
        let n = match result {
            Ok(n) => n,
            Err(e) => return Some(Err(e.to_string())),
        };
        let commit = match eng.commit_turn(&format!("ingest uploaded context: {n} file(s)")) {
            Ok(commit) => commit.map(|c| c.0).unwrap_or_default(),
            Err(e) => return Some(Err(e.to_string())),
        };
        Some(Ok((n, commit)))
    }

    /// Where a streamed upload's bytes accumulate before they are admitted.
    ///
    /// Outside every worktree deliberately. `tree()` skips only `.git`, so a
    /// partial staged inside one would show in the Files panel and could be
    /// swept into a concurrent turn's commit — a half-written recording
    /// entering the work history as though it were work.
    pub fn staging_uploads_dir(&self) -> std::path::PathBuf {
        self.root.join("staging").join("uploads")
    }

    /// Admit one streamed file, already complete on disk at `source`.
    ///
    /// The bytes arrived without ever being held whole, but everything after
    /// they land is the buffered route's path exactly: the same target-root
    /// resolution, the same worktree write, the same `commit_turn`. A streamed
    /// upload and a posted one differ in transport and in nothing else, which
    /// is what keeps one admission story rather than two.
    pub fn ingest_streamed_file_into_engagement(
        &mut self,
        chat_id: &str,
        name: &str,
        source: &std::path::Path,
        target_id: Option<&str>,
    ) -> Option<Result<(usize, String), String>> {
        if self.chat_project_moving(chat_id) {
            return Some(Err(crate::federation::PAUSED_FOR_MOVE.to_owned()));
        }
        let prefix = match self.engagement_context_target_root(chat_id, target_id) {
            Ok(prefix) => prefix,
            Err(error) => return Some(Err(error)),
        };
        let eng = self.engagements.get(chat_id)?;
        // The basename only, like the buffered route: a client does not get to
        // choose a path in the worktree by naming its upload.
        let base = match std::path::Path::new(name).file_name() {
            Some(base) => base.to_string_lossy().into_owned(),
            None => return Some(Err(format!("uploaded file has no name: {name:?}"))),
        };
        let relative = match prefix {
            Some(prefix) => format!("{prefix}/{base}"),
            None => base.clone(),
        };
        if let Err(error) = eng.write_file_from_path(&relative, source) {
            return Some(Err(error.to_string()));
        }
        let commit = match eng.commit_turn(&format!("ingest uploaded context: {base}")) {
            Ok(commit) => commit.map(|c| c.0).unwrap_or_default(),
            Err(e) => return Some(Err(e.to_string())),
        };
        Some(Ok((1, commit)))
    }

    /// The current file manifest for a live engagement.
    pub fn engagement_tree(&self, chat_id: &str) -> Option<Result<Vec<FileEntry>, WorkspaceError>> {
        self.engagements.get(chat_id).map(|eng| {
            let mut entries = eng.tree()?;
            // A target's name is shown as its folder's name, never as a file.
            entries.retain(|entry| !crate::target_names::is_target_name_path(&entry.path));
            if self.installed_agent_view(chat_id).is_some() {
                let runtime_agent = format!(
                    "{}/agent/",
                    gaugedesk_boundary::definition::RUNTIME_MOUNT_ROOT
                );
                let visible = entries
                    .iter()
                    .filter_map(|entry| {
                        entry
                            .path
                            .strip_prefix(&runtime_agent)
                            .map(|suffix| FileEntry {
                                path: format!("agent/{suffix}"),
                                is_dir: entry.is_dir,
                            })
                    })
                    .collect::<Vec<_>>();
                entries.extend(visible);
                entries.push(FileEntry {
                    path: "agent".to_owned(),
                    is_dir: true,
                });
                entries.push(FileEntry {
                    path: "agent/skills".to_owned(),
                    is_dir: true,
                });
                for path in ["agent/AGENTS.md", "agent/HUMANS.md", "agent/SYSTEM.md"] {
                    if self.installed_agent_file(chat_id, path).is_some() {
                        entries.push(FileEntry {
                            path: path.to_owned(),
                            is_dir: false,
                        });
                    }
                }
                if let Some((_, manifest)) = self.installed_agent_view(chat_id) {
                    if let Some(source) = manifest.get("source").and_then(serde_json::Value::as_str)
                    {
                        let path = format!("agent/{source}");
                        if self.installed_agent_file(chat_id, &path).is_some() {
                            entries.push(FileEntry {
                                path,
                                is_dir: false,
                            });
                        }
                    }
                }
            }
            entries.sort_by(|a, b| a.path.cmp(&b.path));
            entries.dedup_by(|a, b| a.path == b.path);
            Ok(entries)
        })
    }

    /// Read one file from a live engagement worktree.
    pub fn read_engagement_file(
        &self,
        chat_id: &str,
        path: &str,
    ) -> Option<Result<String, WorkspaceError>> {
        // The method boundary below is a path comparison; it must see the
        // spelling the read resolves (WS-997).
        let path = match gaugedesk_workspace::canonical_relative_path(path) {
            Ok(path) => path,
            Err(error) => return Some(Err(error)),
        };
        let path = path.as_str();
        if self.installed_method_read_requires_grant(chat_id, path) {
            return Some(Err(WorkspaceError {
                message: "installed Agent method requires a current resource grant".to_owned(),
            }));
        }
        if let Some(bytes) = self.installed_agent_file(chat_id, path) {
            return Some(String::from_utf8(bytes).map_err(|error| WorkspaceError {
                message: error.to_string(),
            }));
        }
        let path = self.engagement_workspace_path(chat_id, path);
        self.engagements
            .get(chat_id)
            .map(|eng| eng.read_file(&path))
    }

    /// Read one file from a live engagement worktree as bytes, refusing
    /// anything past `max_bytes` (`Ok(None)`). A worktree holds whatever the
    /// work put in it, so the viewer's read cannot assume UTF-8: a PDF or a
    /// PNG is a file, not a failed text read.
    pub fn read_engagement_file_bytes(
        &self,
        chat_id: &str,
        path: &str,
        max_bytes: usize,
    ) -> Option<Result<Option<Vec<u8>>, WorkspaceError>> {
        self.read_engagement_file_bytes_for_viewer(chat_id, path, max_bytes, None, false)
    }

    pub(crate) fn read_engagement_file_bytes_for_viewer(
        &self,
        chat_id: &str,
        path: &str,
        max_bytes: usize,
        viewer: Option<&str>,
        account_backed_viewer: bool,
    ) -> Option<Result<Option<Vec<u8>>, WorkspaceError>> {
        // Every check below compares paths as strings: the method boundary,
        // the authoring surfaces, and the import claims a source grant
        // protects. The worktree read resolves `dir/./f`, `dir//f` and
        // `dir/f/` to `dir/f`, so each check and the read itself take the one
        // canonical spelling, computed here once. Otherwise a second spelling
        // of another person's upload reads as unclaimed (WS-997).
        let path = match gaugedesk_workspace::canonical_relative_path(path) {
            Ok(path) => path,
            Err(error) => return Some(Err(error)),
        };
        let path = path.as_str();
        let workspace_path = self.engagement_workspace_path(chat_id, path);
        if (self.installed_method_read_requires_grant(chat_id, path)
            || (account_backed_viewer && self.is_installed_method_path(chat_id, path)))
            && !viewer.is_some_and(|viewer| {
                self.package_selection_for_chat(chat_id)
                    .is_some_and(|(_, package_ref)| {
                        self.method_inspection_granted(chat_id, viewer, &package_ref)
                    })
            })
        {
            return Some(Err(WorkspaceError {
                message: "installed Agent method requires a current resource grant".to_owned(),
            }));
        }
        if account_backed_viewer
            && !self.is_installed_method_path(chat_id, path)
            && !self.authoring_draft_readable(chat_id, path, viewer)
            && !viewer.is_some_and(|viewer| {
                crate::context_inspection::worktree_file_readable(
                    self,
                    chat_id,
                    viewer,
                    &workspace_path,
                    None,
                )
            })
        {
            return Some(Err(WorkspaceError {
                message: "worktree file requires a current source inspection grant".to_owned(),
            }));
        }
        if let Some(bytes) = self.installed_agent_file(chat_id, path) {
            return Some(Ok((bytes.len() <= max_bytes).then_some(bytes)));
        }
        self.engagements
            .get(chat_id)
            .map(|eng| eng.read_file_bytes_capped(&workspace_path, max_bytes))
    }

    /// A retained immutable revision matching the exact bytes served. Reading
    /// a file never imports the worktree just to manufacture response metadata.
    pub fn engagement_recorded_file_cut(
        &self,
        chat_id: &str,
        path: &str,
        served: &[u8],
    ) -> Option<Result<Option<String>, WorkspaceError>> {
        let path = self.engagement_workspace_path(chat_id, path);
        self.engagements
            .get(chat_id)
            .map(|eng| eng.recorded_file_cut(&path, served))
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
        let path = self.engagement_workspace_path(chat_id, path);
        self.engagements
            .get(chat_id)
            .map(|eng| eng.merge_preview(&path, draft, base_cut))
    }

    pub(crate) fn write_engagement_file(
        &mut self,
        chat_id: &str,
        path: &str,
        body: &str,
    ) -> Option<Result<(), WorkspaceError>> {
        if self.chat_project_moving(chat_id) {
            return Some(Err(crate::federation::paused_for_move()));
        }
        let workspace_path = self.engagement_workspace_path(chat_id, path);
        let eng = self.engagements.get(chat_id)?;
        let result = eng
            .write_file(&workspace_path, body)
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

    fn apply_file_manager_command(
        &mut self,
        chat_id: &str,
        command: &FileManagerCommand,
    ) -> Result<(), (StatusCode, String)> {
        if self.chat_project_moving(chat_id) {
            return Err((
                StatusCode::CONFLICT,
                "project handoff is in progress".into(),
            ));
        }
        let source = command.path();
        if let FileManagerCommand::Rename { path, to } = command {
            if let Some(target_id) = self.chat_target_for_root(chat_id, path) {
                return self.rename_target_folder(chat_id, &target_id, to);
            }
        }
        if let FileManagerCommand::SettleTargetName { path, keep } = command {
            let target_id = self
                .chat_target_for_root(chat_id, path)
                .ok_or_else(|| (StatusCode::NOT_FOUND, "no such target folder".to_owned()))?;
            let keep_chat = match keep.as_str() {
                "chat" => true,
                "line" => false,
                _ => {
                    return Err((
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "keep must be `chat` or `line`".to_owned(),
                    ))
                }
            };
            let name = self
                .settle_target_name(chat_id, &target_id, keep_chat)
                .map_err(|error| (StatusCode::CONFLICT, error))?;
            let event = ServerEvent::Admitted {
                kind: "edit".into(),
                text: format!("settled the folder name {name}"),
            };
            let _ = self
                .store_mut()
                .append_record(chat_id, "transcript", &event.to_json());
            self.publish(chat_id, event);
            return Ok(());
        }
        let file_manager_protected = |path: &str| {
            path == "targets"
                || crate::target_names::is_target_name_path(path)
                || path == "artifacts"
                || path == "work"
                || path == ".whipple"
                || gaugedesk_boundary::is_method_surface_path(path)
                || gaugedesk_boundary::is_control_surface_path(path)
                || path.starts_with("builder_only/")
                || path.contains("/builder_only/")
                || path.split('/').any(|part| part == ".agent-config.json")
        };
        if file_manager_protected(source)
            || matches!(command, FileManagerCommand::Rename { to, .. } if file_manager_protected(to))
        {
            return Err((
                StatusCode::FORBIDDEN,
                "protected files are managed through their owning surface".into(),
            ));
        }
        let workspace_source = self.engagement_workspace_path(chat_id, source);
        let workspace_destination = match command {
            FileManagerCommand::Rename { to, .. } => {
                Some(self.engagement_workspace_path(chat_id, to))
            }
            _ => None,
        };
        let authorize = |path: &str| {
            self.authorize_file_edit(chat_id, path)
                .map_err(|reason| (StatusCode::FORBIDDEN, reason.to_owned()))
        };
        authorize(source)?;
        if let FileManagerCommand::Rename { to, .. } = command {
            authorize(to)?;
        }
        let eng = self
            .engagements
            .get(chat_id)
            .ok_or_else(|| (StatusCode::NOT_FOUND, "no such chat".to_owned()))?;
        if matches!(
            command,
            FileManagerCommand::Rename { .. } | FileManagerCommand::Delete { .. }
        ) {
            let prefix = format!("{workspace_source}/");
            let descendants = eng
                .tree()
                .map_err(|error| (StatusCode::CONFLICT, error.to_string()))?;
            for entry in descendants
                .into_iter()
                .filter(|entry| entry.path.starts_with(&prefix))
            {
                authorize(&entry.path)?;
                if let Some(destination) = &workspace_destination {
                    let suffix = &entry.path[workspace_source.len()..];
                    authorize(&format!("{destination}{suffix}"))?;
                }
            }
        }
        match command {
            FileManagerCommand::CreateFile { .. } => eng.create_file_if_absent(&workspace_source),
            FileManagerCommand::CreateFolder { .. } => eng.create_folder(&workspace_source),
            FileManagerCommand::Rename { .. } => eng.rename_entry(
                &workspace_source,
                workspace_destination.as_deref().unwrap_or_default(),
            ),
            FileManagerCommand::Delete { .. } => eng.delete_entry(&workspace_source),
            // Handled before any path authorization, above.
            FileManagerCommand::SettleTargetName { .. } => Err(WorkspaceError {
                message: "a target name is settled only for one of this chat's target folders"
                    .to_owned(),
            }),
        }
        .and_then(|_| {
            eng.commit_turn(&format!("{} {source}", command.verb()))
                .map(|_| ())
        })
        .map_err(|error| (StatusCode::CONFLICT, error.to_string()))?;
        let event = ServerEvent::Admitted {
            kind: "edit".into(),
            text: format!("{} {source}", command.verb()),
        };
        let _ = self
            .store_mut()
            .append_record(chat_id, "transcript", &event.to_json());
        self.publish(chat_id, event);
        Ok(())
    }

    /// The member target whose stored root a chat's Files pane shows at
    /// `path`, `targets/<target-id-path-v1>`.
    fn chat_target_for_root(&self, chat_id: &str, path: &str) -> Option<String> {
        self.library
            .current_target_set(chat_id)?
            .members
            .iter()
            .find_map(|member| {
                let encoded = crate::library::target_id_path_v1(&member.target_id).ok()?;
                (path == format!("targets/{encoded}")).then(|| member.target_id.clone())
            })
    }

    /// Renaming a target's folder in the Files pane renames the target on the
    /// chat's line, as the agent's `mv` does (DR-0248). The folder's storage
    /// does not move; `to` is the folder as it would be shown, beside the
    /// others.
    fn rename_target_folder(
        &mut self,
        chat_id: &str,
        target_id: &str,
        to: &str,
    ) -> Result<(), (StatusCode, String)> {
        let name = to.strip_prefix("targets/").unwrap_or(to);
        let from = self.chat_target_name(chat_id, target_id);
        self.rename_chat_target(chat_id, target_id, name)
            .map_err(|error| (StatusCode::CONFLICT, error))?;
        if name == from {
            return Ok(());
        }
        let text = format!("renamed {from} to {name}");
        self.engagements
            .get(chat_id)
            .ok_or_else(|| (StatusCode::NOT_FOUND, "no such chat".to_owned()))?
            .commit_turn(&text)
            .map_err(|error| (StatusCode::CONFLICT, error.to_string()))?;
        let event = ServerEvent::Admitted {
            kind: "edit".into(),
            text,
        };
        let _ = self
            .store_mut()
            .append_record(chat_id, "transcript", &event.to_json());
        self.publish(chat_id, event);
        Ok(())
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
        if self.chat_project_moving(chat_id) {
            return Some(Err(crate::federation::paused_for_move()));
        }
        let workspace_path = self.engagement_workspace_path(chat_id, path);
        let eng = self.engagements.get(chat_id)?;
        let outcome = match eng.save_file_with_base(&workspace_path, draft, base, resolutions) {
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

    fn resolve_file_edit_target(
        &self,
        chat_id: &str,
        path: &str,
    ) -> Result<(crate::library::ChatTargetSetMemberRecord, String), &'static str> {
        let Some(target_set) = self.library.current_target_set(chat_id) else {
            let binding = self
                .library_chat_target_binding(chat_id)
                .ok_or("chat target binding is unavailable")?;
            return Ok((
                crate::library::ChatTargetSetMemberRecord {
                    target_id: binding.target_id,
                    adapter_family: String::new(),
                    path_scope: binding.path_scope,
                    capability_ceiling: binding.capabilities,
                    participation: crate::library::TargetParticipationMode::Writable,
                },
                path.to_owned(),
            ));
        };
        let normalized = path.trim_start_matches("./");
        let (member, relative) = if let Some(rooted) = normalized.strip_prefix("targets/") {
            let (encoded_target, relative) = rooted
                .split_once('/')
                .ok_or("a target-rooted edit must name a target-relative path")?;
            let member = target_set
                .members
                .iter()
                .find(|member| {
                    crate::library::target_id_path_v1(&member.target_id)
                        .is_ok_and(|encoded| encoded == encoded_target)
                })
                .ok_or("path does not resolve to a selected chat target")?;
            (member, relative)
        } else if let [member] = target_set.members.as_slice() {
            // One-member pre-cutover worktrees used target-relative editor paths.
            // Keep that exact compatibility seam without making an unrooted path
            // ambiguous once a chat selects more than one target.
            (member, normalized)
        } else {
            return Err("a multi-target edit must name one selected target root");
        };
        if member.participation != crate::library::TargetParticipationMode::Writable
            || !member.capability_ceiling.propose
        {
            return Err("the selected chat target is read-only");
        }
        if !path_is_in_scope(relative, &member.path_scope) {
            return Err("path is outside the chat's admitted target scope");
        }
        Ok((member.clone(), relative.to_owned()))
    }

    fn authorize_file_edit(&self, chat_id: &str, path: &str) -> Result<(), &'static str> {
        let normalized = path.trim_start_matches("./");
        if normalized == "agent" || normalized.starts_with("agent/") {
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
            if instance.kind == crate::library::InstanceKind::Using {
                return Err("installed Agent files are read-only; edit the Agent draft and publish a version");
            }
        }
        let run_file = normalized.starts_with("artifacts/") || normalized.starts_with("work/");
        if run_file {
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
            if instance.kind == crate::library::InstanceKind::Using {
                return Ok(());
            }
        }
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
        self.resolve_file_edit_target(chat_id, normalized)?;
        Ok(())
    }

    fn candidate_within_target_scope(&self, chat_id: &str) -> Result<(), String> {
        if self.library.current_target_set(chat_id).is_none()
            && self.library_chat_target_binding(chat_id).is_none()
        {
            // Low-level in-memory workspace tests do not construct the durable
            // library. Production startup rejects every unbound chat.
            return Ok(());
        }
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
            .filter(|path| !crate::target_names::is_target_name_path(path))
            .find_map(|path| {
                self.resolve_file_edit_target(chat_id, path)
                    .err()
                    .map(|reason| (path, reason))
            });
        match escaped {
            Some((path, reason)) => Err(format!("candidate path `{path}` is refused: {reason}")),
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
        if self.chat_project_moving(id) {
            return Some(Err(crate::federation::paused_for_move()));
        }
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
        if self.chat_project_moving(id) {
            return Some(Err(crate::federation::PAUSED_FOR_MOVE.to_owned()));
        }
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
                            let siblings: Vec<String> = self
                                .engagements
                                .iter()
                                .filter(|(sibling_id, sibling)| {
                                    sibling_id.as_str() != id
                                        && sibling.target() == target
                                        && self.engagement_index.get(sibling_id.as_str())
                                            == target_id.as_ref()
                                })
                                .map(|(sibling_id, _)| sibling_id.clone())
                                .collect();
                            for sibling_id in siblings {
                                let _ = self.pull_line_into_chat(&sibling_id);
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

    /// Coordinates for a foreground turn, with no native history import.
    /// Current task admission owns its original base and all durable startup.
    pub(crate) fn engagement_turn_location(
        &mut self,
        id: &str,
    ) -> Option<(std::path::PathBuf, broadcast::Sender<ServerEvent>, ChatMode)> {
        let worktree = self.engagements.get(id)?.path().to_path_buf();
        let mode = self.library_chat_mode(id);
        let sender = self.sender(id);
        Some((worktree, sender, mode))
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
        if self.chat_project_moving(id) {
            return Some(Err(crate::federation::paused_for_move()));
        }
        Some(self.pull_line_into_chat(id)?.map(LineSync::merge_outcome))
    }

    /// Fold a chat's collaboration line into it. When the line's advance
    /// actually arrives, the chat's transcript gains one plain operational line;
    /// a sync that found nothing to fold says nothing, and a conflict is shown
    /// by the chat's navigation row and Changes view rather than here
    /// (`run-chat.md`, shared line & auto-sync; WS-H).
    pub(crate) fn pull_line_into_chat(
        &mut self,
        id: &str,
    ) -> Option<Result<LineSync, WorkspaceError>> {
        let result = self.engagements.get(id)?.pull_from_line();
        if matches!(result, Ok(LineSync::Pulled)) {
            let ev = ServerEvent::Admitted {
                kind: "sync".into(),
                text: "pulled in the latest from the shared line".into(),
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

pub(crate) fn path_is_in_scope(path: &str, scopes: &[String]) -> bool {
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
    headers: axum::http::HeaderMap,
    authenticated: Option<axum::Extension<crate::identity::AuthenticatedActionContext>>,
    Json(body): Json<CreateEngagement>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let creator = crate::project_tracker_routes::context(&mut wb, &headers, authenticated)
        .map(|context| context.actor().as_str().to_owned());
    // An explicit embedding id keeps its raw value as the title; a minted id gets
    // the "new chat" placeholder so the nav renders it as "Untitled" until the first
    // completed turn names it through the engine — never the raw `chat-…` token.
    let (id, title) = match body.id {
        Some(id) => (id.clone(), id),
        None => (crate::library::gen_id("chat"), "new chat".to_string()),
    };
    // A desktop's signed-in account starts chats in its own Personal, never
    // in another account's (DR-0268 §5). The local channel, a phone and a
    // hosted Home keep the install's Personal.
    let personal = match wb.request_personal(&headers).and_then(|project| {
        project
            .map(|project| {
                wb.personal_placement_of(&project)
                    .ok_or_else(|| "this Personal has no placement to start a chat on".to_owned())
            })
            .transpose()
    }) {
        Ok(placement) => placement,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": error })),
            )
                .into_response()
        }
    };
    let created = match personal {
        Some(placement) => wb.create_personal_engagement(id, title, placement),
        None => wb.create_default_engagement(id, title),
    };
    match created {
        Ok(created) => {
            if let Some(creator) = &creator {
                wb.claim_chat_owner(&created.id, creator);
            }
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "id": created.id,
                    "branch": created.branch,
                    "path": created.path,
                })),
            )
                .into_response()
        }
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
    let vis = wb.project_visibility_in(
        crate::net_http::bearer(&headers),
        &crate::workbench_auth::req_scope(&headers),
    );
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

/// A live, privileged view of the actual provider request bodies. Source
/// labels alone do not grant access: every label must pass current read and
/// erasure checks before the provider body leaves this route. Nothing here is
/// appended to the transcript.
pub(crate) async fn get_model_context(
    State(shared): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    fn no_store(status: StatusCode, body: serde_json::Value) -> axum::response::Response {
        (
            status,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(body),
        )
            .into_response()
    }
    let authorize = |wb: &Workbench| -> Result<String, (StatusCode, &'static str)> {
        crate::method_access::chat_reader(wb, &id, &headers)
    };
    let (handle, live) = {
        let wb = shared.lock_unpoisoned();
        if let Err((status, message)) = authorize(&wb) {
            return no_store(status, serde_json::json!({"error": message}));
        }
        (
            crate::engine::running_turn_model_context(&id),
            crate::engine::turn_is_live(&id),
        )
    };
    let Some(handle) = handle else {
        return no_store(
            StatusCode::OK,
            serde_json::json!({
                "available": false,
                "reason": if live {
                    "This runtime does not support raw context."
                } else {
                    "No live provider request is available for this chat."
                }
            }),
        );
    };
    let captured = tokio::task::spawn_blocking(move || handle()).await;
    let Ok(Ok(raw)) = captured else {
        return no_store(
            StatusCode::OK,
            serde_json::json!({
                "available": false, "reason": "No exact provider request is available yet."
            }),
        );
    };
    let Ok(view) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return no_store(
            StatusCode::BAD_GATEWAY,
            serde_json::json!({"error": "invalid runtime capture"}),
        );
    };
    // Keep the workbench locked from the final admission through projection:
    // a revocation cannot race between the source check and the response.
    let wb = shared.lock_unpoisoned();
    let viewer = match authorize(&wb) {
        Ok(viewer) => viewer,
        Err((status, message)) => {
            return no_store(status, serde_json::json!({"error": message}));
        }
    };
    let workspace_contexts_current = std::cell::OnceCell::new();
    let account_backed = crate::method_access::account_backed_chat(&wb, &id, &headers);
    let projection = project_model_context(&view, |source| {
        if source == "runtime" || source == format!("chat:{id}") {
            return true;
        }
        if source.starts_with("question-answer:") {
            return crate::agent_question::current_answer_source(wb.store_ref(), &id, source);
        }
        if source.starts_with("turn-image:") {
            // The exact image stays bound to this live turn. Account-backed
            // readers also have to be its verified submitter: chat ownership
            // alone does not grant another person's submitted media.
            let account_backed = wb.idp.is_some()
                || crate::workbench_auth::web_account_mode()
                || crate::net_http::bearer(&headers)
                    .is_some_and(|token| wb.resolve_account_session(token).is_some());
            return crate::engine::running_turn_has_image_source(
                &id,
                source,
                account_backed.then_some(viewer.as_str()),
            );
        }
        if source.starts_with("workspace-file:") {
            let contexts_current = account_backed
                || *workspace_contexts_current
                    .get_or_init(|| current_workspace_context_grants(&wb, &id));
            return current_workspace_file_source_with_grants(
                &wb,
                &id,
                source,
                contexts_current,
                Some(&viewer),
                account_backed,
            );
        }
        if source.starts_with("workspace-dir:") {
            let contexts_current = account_backed
                || *workspace_contexts_current
                    .get_or_init(|| current_workspace_context_grants(&wb, &id));
            return current_workspace_directory_source_with_grants(
                &wb,
                &id,
                source,
                contexts_current,
                Some(&viewer),
                account_backed,
            );
        }
        if source.starts_with("workspace:") {
            // A chat-level handle cannot establish whether one file read into
            // this call was erased after capture. Until the handle names the
            // exact source cut and its current erasure state, redact the call.
            return false;
        }
        if source.starts_with("discipline-skill:") {
            return current_discipline_skill_source(
                &wb,
                &id,
                &viewer,
                source,
                crate::method_access::account_backed_chat(&wb, &id, &headers),
            );
        }
        let Some(package_ref) = source.strip_prefix("package:") else {
            return false;
        };
        // A work package can include method bytes outside the chat's grant.
        // Recheck the selected version and the current reader-specific basis.
        if crate::method_access::account_backed_chat(&wb, &id, &headers) {
            return wb.method_inspection_granted(&id, &viewer, package_ref);
        }
        let Some((version, selected_ref)) = wb.package_selection_for_chat(&id) else {
            return false;
        };
        if selected_ref != package_ref {
            return false;
        }
        wb.package_root_for_chat(&id, version)
            .and_then(|root| gaugedesk_whip_runtime::AuthoredAgentPackage::load(&root).ok())
            .is_some_and(|package| package.version_ref() == package_ref)
    });
    match projection {
        Ok(body) => no_store(StatusCode::OK, body),
        Err(()) => no_store(
            StatusCode::BAD_GATEWAY,
            serde_json::json!({"error": "invalid runtime capture"}),
        ),
    }
}

/// An installed skill is frozen in the discipline beside the method package.
/// Its registry hash names exactly the body injected into the model prompt;
/// the current reader must still hold method access and the frozen discipline
/// must still carry those same bytes.
fn current_discipline_skill_source(
    wb: &Workbench,
    chat_id: &str,
    viewer: &str,
    source: &str,
    account_backed: bool,
) -> bool {
    let prefix = format!("discipline-skill:{chat_id}:");
    let Some((digest, name)) = source
        .strip_prefix(&prefix)
        .and_then(|rest| rest.split_once(':'))
    else {
        return false;
    };
    if digest.len() != 32
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return false;
    }
    let Some(chat) = wb.library.chats.get(chat_id) else {
        return false;
    };
    let Some(instance) = wb.library.instances.get(&chat.instance_id) else {
        return false;
    };
    if instance.kind != crate::library::InstanceKind::Using {
        return false;
    }
    let Some(agent) = wb.library.agents.get(&instance.agent_id) else {
        return false;
    };
    let Some(version) = agent.versions.get(&instance.version) else {
        return false;
    };
    if account_backed && !wb.method_inspection_granted(chat_id, viewer, &version.package_ref) {
        return false;
    }
    let Some(target) = wb.library.authoring_target_for(&agent.id) else {
        return false;
    };
    let package_root = crate::library_state::published_package_root(
        &wb.targets_dir(),
        &target.id,
        instance.version,
    );
    let Ok(package) = gaugedesk_whip_runtime::AuthoredAgentPackage::load(package_root) else {
        return false;
    };
    if package.version_ref() != version.package_ref {
        return false;
    }
    let discipline_root = crate::library_state::published_discipline_root(
        &wb.targets_dir(),
        &target.id,
        instance.version,
    );
    let Ok(discipline) =
        crate::discipline::load(&discipline_root, package.capabilities().iter().cloned())
    else {
        return false;
    };
    if discipline.reference != version.discipline_ref {
        return false;
    }
    let path = format!("agent-skills/{name}/SKILL.md");
    discipline.files.iter().any(|(candidate, body)| {
        candidate == &path && digest == whipplescript_store::stable_hash_hex(body)
    })
}

/// A native `read` witness names the full bytes read, even when the model saw
/// only selected lines. A viewer read must find those same bytes in the chat's
/// current worktree and its retained head cut. This is deliberately stricter
/// than access to an old digest: erasure or replacement must close the view.
#[cfg(test)]
fn current_workspace_file_source(wb: &Workbench, chat_id: &str, source: &str) -> bool {
    current_workspace_file_source_with_grants(
        wb,
        chat_id,
        source,
        current_workspace_context_grants(wb, chat_id),
        None,
        false,
    )
}

/// The Raw context projection's answer for one file source, as an
/// account-backed viewer asks it.
#[cfg(test)]
pub(crate) fn viewer_workspace_file_source(
    wb: &Workbench,
    chat_id: &str,
    source: &str,
    viewer: &str,
) -> bool {
    current_workspace_file_source_with_grants(wb, chat_id, source, true, Some(viewer), true)
}

fn current_workspace_file_source_with_grants(
    wb: &Workbench,
    chat_id: &str,
    source: &str,
    contexts_current: bool,
    viewer: Option<&str>,
    account_backed: bool,
) -> bool {
    let prefix = format!("workspace-file:{chat_id}:");
    let Some((digest, path)) = source
        .strip_prefix(&prefix)
        .and_then(|rest| rest.split_once(':'))
    else {
        return false;
    };
    // The witness carries whatever spelling the read used. Scope, claims and
    // the bytes are all judged under its one canonical spelling (WS-997).
    let Ok(path) = gaugedesk_workspace::canonical_relative_path(path) else {
        return false;
    };
    let path = path.as_str();
    if !current_workspace_source_scope(wb, chat_id, path, contexts_current) {
        return false;
    }
    if digest.len() != 32 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return false;
    }
    if account_backed
        && !viewer.is_some_and(|viewer| {
            crate::context_inspection::worktree_file_readable(
                wb,
                chat_id,
                viewer,
                path,
                Some(digest),
            )
        })
    {
        return false;
    }
    let Some(Ok(Some(bytes))) = wb.read_engagement_file_bytes(chat_id, path, 8 * 1024 * 1024)
    else {
        return false;
    };
    digest == whipplescript_store::stable_hash_bytes_hex(&bytes)
        && wb
            .engagement_recorded_file_cut(chat_id, path, &bytes)
            .and_then(Result::ok)
            .flatten()
            .is_some()
}

/// A directory scan's root must still be a readable directory inside the
/// current selected target. Its companion file handles prove every searched
/// file, including negative matches, against current retained bytes.
#[cfg(test)]
fn current_workspace_directory_source(wb: &Workbench, chat_id: &str, source: &str) -> bool {
    current_workspace_directory_source_with_grants(
        wb,
        chat_id,
        source,
        current_workspace_context_grants(wb, chat_id),
        None,
        false,
    )
}

fn current_workspace_directory_source_with_grants(
    wb: &Workbench,
    chat_id: &str,
    source: &str,
    contexts_current: bool,
    viewer: Option<&str>,
    account_backed: bool,
) -> bool {
    let prefix = format!("workspace-dir:{chat_id}:");
    let Some(path) = source.strip_prefix(&prefix) else {
        return false;
    };
    let Ok(path) = gaugedesk_workspace::canonical_relative_path(path) else {
        return false;
    };
    let path = path.as_str();
    current_workspace_source_scope(wb, chat_id, path, contexts_current)
        && (!account_backed
            || viewer.is_some_and(|viewer| {
                crate::context_inspection::directory_readable(wb, chat_id, viewer, path)
            }))
        && wb.engagement_tree(chat_id).is_some_and(|tree| {
            tree.is_ok_and(|entries| {
                entries
                    .iter()
                    .any(|entry| entry.path == path && entry.is_dir)
            })
        })
}

fn current_workspace_context_grants(wb: &Workbench, chat_id: &str) -> bool {
    wb.list_resource_contexts(chat_id).is_ok_and(|resources| {
        resources.into_iter().all(|(record, phase)| {
            !record.tombstoned
                && (record.resource.kind != gaugedesk_core::resource::ResourceKind::context()
                    || phase == gaugedesk_core::resource_access::AccessPhase::Granted)
        })
    })
}

pub(crate) fn current_workspace_source_scope(
    wb: &Workbench,
    chat_id: &str,
    path: &str,
    contexts_current: bool,
) -> bool {
    // Solo worktrees without per-import bindings must treat an uncertain
    // revoked context as capable of supplying any worktree path. Account-backed
    // reads check the exact import and reader in context_inspection first.
    if !contexts_current {
        return false;
    }
    let Some(chat) = wb.library.chats.get(chat_id) else {
        return false;
    };
    let Some(instance) = wb.library.instances.get(&chat.instance_id) else {
        return false;
    };
    if instance.kind == crate::library::InstanceKind::Authoring {
        // Edit chats import into the root of their authoring workspace. The
        // imported file still needs its own exact reader grant; keep the
        // method and runtime surfaces on their separate authorities.
        if path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
            || path == "agent"
            || path.starts_with("agent/")
            || path == "artifacts"
            || path.starts_with("artifacts/")
            || path == "work"
            || path.starts_with("work/")
            || path == "targets"
            || path.starts_with("targets/")
            || path == ".whipple"
            || gaugedesk_boundary::is_method_surface_path(path)
            || gaugedesk_boundary::is_control_surface_path(path)
        {
            return false;
        }
        let Some(set) = wb.library.current_target_set(chat_id) else {
            return false;
        };
        let [member] = set.members.as_slice() else {
            return false;
        };
        let Some(target) = wb.library.authoring_target_for(&instance.agent_id) else {
            return false;
        };
        return target.id == member.target_id
            && target.status == crate::library::WorkTargetStatus::Available
            && member.capability_ceiling.read
            && target.capabilities.read
            && path_is_in_scope(path, &member.path_scope)
            && path_is_in_scope(path, &target.path_scope);
    }
    let Some(rest) = path.strip_prefix("targets/") else {
        return false;
    };
    let (encoded_target, relative) = rest.split_once('/').unwrap_or((rest, ""));
    if encoded_target.is_empty() {
        return false;
    }
    let Some(member) = wb.library.current_target_set(chat_id).and_then(|set| {
        set.members.iter().find(|member| {
            crate::library::target_id_path_v1(&member.target_id)
                .is_ok_and(|encoded| encoded == encoded_target)
        })
    }) else {
        return false;
    };
    let Ok(target) = wb.resolve_placement_target(&chat.instance_id, Some(&member.target_id)) else {
        return false;
    };
    member.capability_ceiling.read
        && target.capabilities.read
        && path_is_in_scope(relative, &member.path_scope)
        && path_is_in_scope(relative, &target.path_scope)
}

fn project_model_context(
    view: &serde_json::Value,
    authorized_source: impl Fn(&str) -> bool,
) -> Result<serde_json::Value, ()> {
    // One provider call often repeats earlier source labels across messages.
    // Authorize each distinct source once for this response while the caller
    // holds its workbench lock; the next viewer poll rechecks current access.
    let source_cache = std::cell::RefCell::new(std::collections::HashMap::<String, bool>::new());
    let authorize_cached = |source: &str| {
        if let Some(allowed) = source_cache.borrow().get(source).copied() {
            return allowed;
        }
        let allowed = authorized_source(source);
        source_cache.borrow_mut().insert(source.to_owned(), allowed);
        allowed
    };
    let calls = view
        .get("calls")
        .and_then(serde_json::Value::as_array)
        .ok_or(())?;
    let incomplete = view
        .get("incomplete")
        .and_then(serde_json::Value::as_bool)
        .ok_or(())?;
    let mut projected = Vec::with_capacity(calls.len());
    for call in calls {
        let ordinal = call
            .get("ordinal")
            .and_then(serde_json::Value::as_u64)
            .ok_or(())?;
        let body = call.get("body").ok_or(())?;
        let labels = call
            .get("ordered_provenance")
            .and_then(serde_json::Value::as_object)
            .filter(|object| {
                object.len() == 2 || (object.len() == 3 && object.contains_key("wire"))
            });
        let messages = labels
            .and_then(|object| object.get("messages"))
            .and_then(serde_json::Value::as_array)
            .filter(|messages| !messages.is_empty());
        let tools = labels.and_then(|object| object.get("tools"));
        let fully_authorized = call.get("provenance_complete")
            == Some(&serde_json::Value::Bool(true))
            && messages.is_some_and(|messages| {
                messages
                    .iter()
                    .all(|label| authorized_model_source_label(label, &authorize_cached))
            })
            && tools.is_some_and(|label| authorized_model_source_label(label, &authorize_cached));
        let wire = labels.and_then(|object| object.get("wire"));
        let partial = messages.and_then(|messages| {
            wire.and_then(|wire| {
                tools.and_then(|tools| {
                    project_wire_model_context(body, wire, messages, tools, &authorize_cached)
                })
            })
        });
        // Logical labels do not prove that a custom provider put only those
        // inputs in its request. Release the whole body only after the exact
        // wire planes have also been matched to those labels.
        if fully_authorized && partial.as_ref().is_some_and(|(_, redacted)| !redacted) {
            projected.push(serde_json::json!({ "ordinal": ordinal, "body": body }));
        } else if let Some((body, true)) = partial {
            projected.push(serde_json::json!({
                "ordinal": ordinal,
                "body": body,
                "redacted": true,
                "reason": "Some model input sources are unavailable to this reader."
            }));
        } else {
            projected.push(serde_json::json!({
                "ordinal": ordinal,
                "redacted": true,
                "reason": "Current access to every model input source could not be proven."
            }));
        }
    }
    Ok(serde_json::json!({
        "available": true,
        "calls": projected,
        "incomplete": incomplete
    }))
}

/// Return only input planes whose wire positions the kernel mapped to exact
/// logical sources. A partial view copies no unrecognized provider fields.
fn project_wire_model_context(
    body: &serde_json::Value,
    wire: &serde_json::Value,
    messages: &[serde_json::Value],
    tools: &serde_json::Value,
    authorized_source: &impl Fn(&str) -> bool,
) -> Option<(serde_json::Value, bool)> {
    let body = body.as_object()?;
    let wire = wire.as_object()?;
    if wire.len() != 3 {
        return None;
    }
    let format = wire.get("format")?.as_str()?;
    let input_key = if format == "open-ai-responses" {
        "input"
    } else if matches!(
        format,
        "anthropic-messages" | "open-ai-chat-compat" | "coerced-tools"
    ) {
        "messages"
    } else {
        return None;
    };
    if body.contains_key(if input_key == "input" {
        "messages"
    } else {
        "input"
    }) {
        return None;
    }
    if format != "anthropic-messages" && body.contains_key("system") {
        return None;
    }
    if format != "coerced-tools" && body.contains_key("response_format") {
        return None;
    }
    let inputs = body.get(input_key)?.as_array()?;
    let labels = wire.get("items")?.as_array()?;
    if inputs.len() != labels.len() || inputs.is_empty() {
        return None;
    }
    // A wire map may repeat a source for expanded items, but may not silently
    // omit a source from the logical conversation it claims to represent.
    let mut logical_sources = model_source_handles(tools)?;
    for label in messages {
        logical_sources.extend(model_source_handles(label)?);
    }
    let mut wire_sources = model_source_handles(tools)?;
    for label in labels {
        wire_sources.extend(model_source_handles(label)?);
    }
    if !wire.get("system")?.is_null() {
        wire_sources.extend(model_source_handles(wire.get("system")?)?);
    }
    if logical_sources != wire_sources {
        return None;
    }
    let mut redacted = false;
    let items = inputs
        .iter()
        .zip(labels)
        .map(|(item, label)| {
            if authorized_model_source_label(label, authorized_source) {
                item.clone()
            } else {
                redacted = true;
                redacted_model_input_item(item)
            }
        })
        .collect::<Vec<_>>();
    let mut output = serde_json::Map::new();
    if let Some(model) = body.get("model").and_then(serde_json::Value::as_str) {
        output.insert("model".into(), serde_json::json!(model));
    }
    output.insert(input_key.into(), serde_json::Value::Array(items));
    let system_label = wire.get("system")?;
    if format == "anthropic-messages" {
        match (body.get("system"), system_label.is_null()) {
            (None, true) => {}
            (Some(system), false)
                if system
                    .as_array()
                    .is_some_and(|blocks| blocks.len() == 1 && blocks[0]["type"] == "text") =>
            {
                if authorized_model_source_label(system_label, authorized_source) {
                    output.insert("system".into(), system.clone());
                } else {
                    redacted = true;
                    output.insert(
                        "system".into(),
                        serde_json::json!([{"redacted": true, "type": "text"}]),
                    );
                }
            }
            _ => return None,
        }
    } else if !system_label.is_null() {
        return None;
    }
    if let Some(definitions) = body.get("tools") {
        let definitions = definitions.as_array()?;
        if authorized_model_source_label(tools, authorized_source) {
            output.insert(
                "tools".into(),
                serde_json::Value::Array(definitions.clone()),
            );
        } else {
            redacted = true;
            output.insert(
                "tools".into(),
                serde_json::Value::Array(
                    definitions
                        .iter()
                        .map(|_| serde_json::json!({"redacted": true}))
                        .collect(),
                ),
            );
        }
    }
    if let Some(schema) = body.get("response_format") {
        if format != "coerced-tools" {
            return None;
        }
        if authorized_model_source_label(tools, authorized_source) {
            output.insert("response_format".into(), schema.clone());
        } else {
            redacted = true;
            output.insert(
                "response_format".into(),
                serde_json::json!({"redacted": true}),
            );
        }
    }
    for key in ["max_tokens", "stream", "store", "parallel_tool_calls"] {
        if let Some(value) = body.get(key) {
            let valid = if key == "max_tokens" {
                value.as_u64().is_some()
            } else {
                value.as_bool().is_some()
            };
            if !valid {
                return None;
            }
            output.insert(key.into(), value.clone());
        }
    }
    if let Some(options) = body.get("stream_options") {
        let options = options.as_object()?;
        if options.len() != 1 || !options.get("include_usage")?.is_boolean() {
            return None;
        }
        output.insert(
            "stream_options".into(),
            serde_json::Value::Object(options.clone()),
        );
    }
    let unmapped_field = body
        .keys()
        .any(|key| key != "prompt_cache_key" && !output.contains_key(key));
    if !redacted && !unmapped_field {
        if let Some(cache_key) = body.get("prompt_cache_key") {
            output.insert(
                "prompt_cache_key".into(),
                serde_json::json!(cache_key.as_str()?),
            );
        }
    }
    // A new provider field may carry model input without a source label.
    // Preserve the mapped input planes but never release an unmapped field.
    redacted |= unmapped_field;
    Some((serde_json::Value::Object(output), redacted))
}

fn model_source_handles(label: &serde_json::Value) -> Option<std::collections::BTreeSet<&str>> {
    let label = label.as_object()?;
    if label.len() != 2 || !label.get("complete")?.is_boolean() {
        return None;
    }
    label
        .get("source_handles")?
        .as_array()?
        .iter()
        .map(serde_json::Value::as_str)
        .collect()
}

fn redacted_model_input_item(item: &serde_json::Value) -> serde_json::Value {
    let role = item
        .get("role")
        .and_then(serde_json::Value::as_str)
        .filter(|role| matches!(*role, "system" | "user" | "assistant" | "tool"));
    let kind = item
        .get("type")
        .and_then(serde_json::Value::as_str)
        .filter(|kind| matches!(*kind, "function_call" | "function_call_output"));
    let mut output = serde_json::Map::new();
    output.insert("redacted".into(), serde_json::Value::Bool(true));
    if let Some(role) = role {
        output.insert("role".into(), serde_json::json!(role));
    }
    if let Some(kind) = kind {
        output.insert("type".into(), serde_json::json!(kind));
    }
    serde_json::Value::Object(output)
}

fn authorized_model_source_label(
    label: &serde_json::Value,
    authorized_source: &impl Fn(&str) -> bool,
) -> bool {
    let Some(object) = label.as_object() else {
        return false;
    };
    if object.len() != 2 || object.get("complete") != Some(&serde_json::Value::Bool(true)) {
        return false;
    }
    object
        .get("source_handles")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|handles| {
            handles
                .iter()
                .all(|handle| handle.as_str().is_some_and(authorized_source))
        })
}

#[cfg(test)]
mod raw_model_context_tests {
    use super::current_discipline_skill_source;
    use super::{
        current_workspace_directory_source, current_workspace_file_source,
        current_workspace_source_scope, project_model_context,
    };
    use crate::{
        library::{ChatRecord, RecordOp, LIBRARY_RECORD_SCHEMA},
        LockUnpoisoned, Workbench,
    };
    use axum::{
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
    };

    fn mapped_chat_request(mut view: serde_json::Value) -> serde_json::Value {
        for call in view["calls"].as_array_mut().expect("calls") {
            let labels = call["ordered_provenance"]["messages"]
                .as_array()
                .expect("logical labels")
                .clone();
            assert_eq!(
                call["body"]["messages"]
                    .as_array()
                    .expect("wire inputs")
                    .len(),
                labels.len()
            );
            assert!(call["ordered_provenance"].get("wire").is_none());
            call["ordered_provenance"]["wire"] = serde_json::json!({
                "format": "open-ai-chat-compat", "items": labels, "system": null
            });
        }
        view
    }

    #[tokio::test]
    async fn frozen_skill_requires_exact_body_and_current_method_access() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let path = "agent-skills/triage/SKILL.md";
        let (chat_id, discipline_root, source) = {
            let mut wb = shared.lock_unpoisoned();
            let chat = wb
                .create_default_engagement("skill-source-chat".into(), "Skill source".into())
                .unwrap_or_else(|_| panic!("create work chat"));
            let instance = wb
                .library
                .instances
                .get(&wb.library.chats.get(&chat.id).unwrap().instance_id)
                .unwrap()
                .clone();
            let target_id = wb
                .library
                .authoring_target_for(&instance.agent_id)
                .unwrap()
                .id
                .clone();
            let discipline_root = crate::library_state::published_discipline_root(
                &wb.targets_dir(),
                &target_id,
                instance.version,
            );
            let manifest_path = discipline_root.join(crate::discipline::DISCIPLINE_MANIFEST);
            let mut manifest: crate::discipline::DisciplineManifest =
                serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
            manifest.assets.push(crate::discipline::DisciplineAsset {
                path: path.into(),
                treatment: crate::discipline::DisciplineTreatment::Runtime,
            });
            let skill_body =
                "---\nname: triage\ndescription: Inspect reports\n---\nRead the report.\n";
            std::fs::create_dir_all(discipline_root.join("agent-skills/triage")).unwrap();
            std::fs::write(discipline_root.join(path), skill_body).unwrap();
            std::fs::write(
                &manifest_path,
                serde_json::to_string_pretty(&manifest).unwrap(),
            )
            .unwrap();
            let package = gaugedesk_whip_runtime::AuthoredAgentPackage::load(
                crate::library_state::published_package_root(
                    &wb.targets_dir(),
                    &target_id,
                    instance.version,
                ),
            )
            .unwrap();
            let discipline =
                crate::discipline::load(&discipline_root, package.capabilities().iter().cloned())
                    .unwrap();
            let mut agent = wb.library.agents.get(&instance.agent_id).unwrap().clone();
            agent
                .versions
                .get_mut(&instance.version)
                .unwrap()
                .discipline_ref = discipline.reference;
            wb.write_agent_record(agent);
            let source = format!(
                "discipline-skill:{}:{}:triage",
                chat.id,
                whipplescript_store::stable_hash_hex(skill_body)
            );
            assert!(current_discipline_skill_source(
                &wb, &chat.id, "solo", &source, false
            ));
            assert!(!current_discipline_skill_source(
                &wb, &chat.id, "reader", &source, true
            ));
            assert!(!current_discipline_skill_source(
                &wb,
                &chat.id,
                "solo",
                &format!("{source}/other"),
                false,
            ));
            (chat.id, discipline_root, source)
        };
        let turn_claim = crate::engine::claim_turn(&chat_id).unwrap();
        let raw = mapped_chat_request(serde_json::json!({
            "calls": [{
                "ordinal": 0,
                "body": {"messages": ["skill body entered the model"]},
                "ordered_provenance": {
                    "messages": [{"source_handles": ["runtime", source], "complete": true}],
                    "tools": {"source_handles": ["runtime"], "complete": true}
                },
                "provenance_complete": true
            }],
            "incomplete": false
        }));
        crate::engine::bind_turn_model_context(
            &chat_id,
            std::sync::Arc::new(move || Ok(raw.to_string())),
        );
        let read_raw = |shared: crate::SharedWorkbench| {
            let chat_id = chat_id.clone();
            async move {
                let response =
                    super::get_model_context(State(shared), Path(chat_id), HeaderMap::new())
                        .await
                        .into_response();
                assert_eq!(response.status(), StatusCode::OK);
                let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            }
        };
        assert_eq!(
            read_raw(shared.clone()).await["calls"][0]["body"]["messages"][0],
            "skill body entered the model"
        );
        std::fs::write(discipline_root.join(path), "erased").unwrap();
        assert_eq!(read_raw(shared).await["calls"][0]["redacted"], true);
        drop(turn_claim);
    }

    #[test]
    fn unknown_provenance_releases_no_prompt_or_source_handle() {
        let view = serde_json::json!({
            "calls": [{
                "ordinal": 0,
                "body": {"input": "private prompt"},
                "source_handles": ["private source"],
                "provenance_complete": false
            }],
            "incomplete": false,
            "future_private_field": "private metadata"
        });
        let projection = project_model_context(&view, |_| true).unwrap();
        let output = projection.to_string();
        assert!(!output.contains("private prompt"));
        assert!(!output.contains("private source"));
        assert!(!output.contains("private metadata"));
        assert_eq!(projection["calls"][0]["redacted"], true);
    }

    #[test]
    fn logical_labels_without_a_wire_map_cannot_release_a_custom_provider_body() {
        let view = serde_json::json!({
            "calls": [{
                "ordinal": 0,
                "body": {
                    "messages": [{"role": "user", "content": "visible question"}],
                    "future_input": "unclassified private instruction"
                },
                "ordered_provenance": {
                    "messages": [{"source_handles": ["chat:one"], "complete": true}],
                    "tools": {"source_handles": ["runtime"], "complete": true}
                },
                "provenance_complete": true
            }],
            "incomplete": false
        });
        let projected = project_model_context(&view, |_| true).unwrap();
        assert_eq!(projected["calls"][0]["redacted"], true);
        assert!(projected["calls"][0].get("body").is_none());
        assert!(!projected
            .to_string()
            .contains("unclassified private instruction"));
    }

    #[test]
    fn malformed_capture_is_refused() {
        let view = serde_json::json!({"calls": [{"body": "secret"}], "incomplete": false});
        assert!(project_model_context(&view, |_| true).is_err());
    }

    #[test]
    fn release_requires_current_access_to_every_labeled_source() {
        let view = mapped_chat_request(serde_json::json!({
            "calls": [{
                "ordinal": 0,
                "body": {"messages": ["private method", "user prompt"]},
                "ordered_provenance": {
                    "messages": [
                        {"source_handles": ["package:pinned"], "complete": true},
                        {"source_handles": ["chat:one"], "complete": true}
                    ],
                    "tools": {"source_handles": ["package:pinned"], "complete": true}
                },
                "provenance_complete": true,
                "secret_metadata": "must not leave"
            }],
            "incomplete": false
        }));
        let visible = project_model_context(&view, |_| true).unwrap();
        assert_eq!(visible["calls"][0]["body"], view["calls"][0]["body"]);

        assert!(!visible.to_string().contains("package:pinned"));
        assert!(!visible.to_string().contains("secret_metadata"));

        let revoked = project_model_context(&view, |source| source == "chat:one").unwrap();
        assert_eq!(revoked["calls"][0]["redacted"], true);
        assert!(!revoked.to_string().contains("private method"));

        let mut unknown = view;
        unknown["calls"][0]["ordered_provenance"]["tools"]["complete"] = false.into();
        let redacted = project_model_context(&unknown, |_| true).unwrap();
        assert_eq!(redacted["calls"][0]["redacted"], true);

        unknown["calls"][0]["ordered_provenance"]["tools"]["complete"] = true.into();
        unknown["calls"][0]["ordered_provenance"]["future_input_plane"] =
            serde_json::json!({"source_handles": ["private"], "complete": true});
        let redacted = project_model_context(&unknown, |_| true).unwrap();
        assert_eq!(redacted["calls"][0]["redacted"], true);
    }

    #[test]
    fn wire_map_redacts_only_hidden_provider_items_and_tool_definitions() {
        let view = serde_json::json!({
            "calls": [{
                "ordinal": 0,
                "body": {
                    "model": "test-model",
                    "messages": [
                        {"role": "system", "content": "private method"},
                        {"role": "user", "content": "public question"},
                        {"role": "tool", "tool_call_id": "private-id", "content": "private result"}
                    ],
                    "tools": [{"type": "function", "function": {"name": "private_tool"}}],
                    "prompt_cache_key": "private-cache-key"
                },
                "ordered_provenance": {
                    "messages": [
                        {"source_handles": ["method"], "complete": true},
                        {"source_handles": ["chat"], "complete": true},
                        {"source_handles": ["result"], "complete": true}
                    ],
                    "tools": {"source_handles": ["method"], "complete": true},
                    "wire": {
                        "format": "open-ai-chat-compat",
                        "items": [
                            {"source_handles": ["method"], "complete": true},
                            {"source_handles": ["chat"], "complete": true},
                            {"source_handles": ["result"], "complete": true}
                        ],
                        "system": null
                    }
                },
                "provenance_complete": true
            }],
            "incomplete": false
        });
        let projected = project_model_context(&view, |source| source == "chat").unwrap();
        let call = &projected["calls"][0];
        assert_eq!(call["redacted"], true);
        assert_eq!(
            call["body"]["messages"][0],
            serde_json::json!({"redacted": true, "role": "system"})
        );
        assert_eq!(
            call["body"]["messages"][1],
            view["calls"][0]["body"]["messages"][1]
        );
        assert_eq!(
            call["body"]["messages"][2],
            serde_json::json!({"redacted": true, "role": "tool"})
        );
        assert_eq!(
            call["body"]["tools"][0],
            serde_json::json!({"redacted": true})
        );
        for secret in [
            "private method",
            "private result",
            "private_tool",
            "private-id",
            "private-cache-key",
            "method",
            "result",
        ] {
            assert!(!projected.to_string().contains(secret), "{secret}");
        }
        let visible = project_model_context(&view, |_| true).unwrap();
        assert_eq!(visible["calls"][0]["body"], view["calls"][0]["body"]);

        let mut extra_field = view.clone();
        extra_field["calls"][0]["body"]["unmapped_input"] =
            serde_json::json!("private unclassified instruction");
        let projected = project_model_context(&extra_field, |_| true).unwrap();
        assert_eq!(projected["calls"][0]["redacted"], true);
        assert_eq!(
            projected["calls"][0]["body"]["messages"],
            view["calls"][0]["body"]["messages"]
        );
        assert!(!projected
            .to_string()
            .contains("private unclassified instruction"));
        assert!(!projected.to_string().contains("private-cache-key"));

        let mut unknown = view;
        unknown["calls"][0]["provenance_complete"] = serde_json::json!(false);
        unknown["calls"][0]["ordered_provenance"]["messages"][2]["complete"] =
            serde_json::json!(false);
        unknown["calls"][0]["ordered_provenance"]["wire"]["items"][2]["complete"] =
            serde_json::json!(false);
        let projected = project_model_context(&unknown, |source| source == "chat").unwrap();
        assert_eq!(
            projected["calls"][0]["body"]["messages"][1]["content"],
            "public question"
        );
        assert_eq!(
            projected["calls"][0]["body"]["messages"][2]["redacted"],
            true
        );
        assert!(!projected.to_string().contains("private result"));
    }

    #[test]
    fn joined_system_and_unmapped_provider_inputs_fail_closed() {
        let mut view = serde_json::json!({
            "calls": [{
                "ordinal": 0,
                "body": {
                    "model": "test-model",
                    "system": [{"type": "text", "text": "hidden system"}],
                    "messages": [
                        {"role": "user", "content": [{"type": "text", "text": "visible"}]},
                        {"role": "assistant", "content": [{"type": "tool_use", "name": "secret tool"}]}
                    ],
                    "tools": []
                },
                "ordered_provenance": {
                    "messages": [
                        {"source_handles": ["hidden"], "complete": true},
                        {"source_handles": ["chat"], "complete": true},
                        {"source_handles": ["hidden"], "complete": true}
                    ],
                    "tools": {"source_handles": [], "complete": true},
                    "wire": {
                        "format": "anthropic-messages",
                        "items": [
                            {"source_handles": ["chat"], "complete": true},
                            {"source_handles": ["hidden"], "complete": true}
                        ],
                        "system": {"source_handles": ["hidden"], "complete": true}
                    }
                },
                "provenance_complete": true
            }],
            "incomplete": false
        });
        let projected = project_model_context(&view, |source| source == "chat").unwrap();
        assert_eq!(projected["calls"][0]["body"]["system"][0]["redacted"], true);
        assert_eq!(projected["calls"][0]["body"]["messages"][0]["role"], "user");
        assert_eq!(
            projected["calls"][0]["body"]["messages"][1],
            serde_json::json!({"redacted": true, "role": "assistant"})
        );
        assert!(!projected.to_string().contains("hidden system"));
        assert!(!projected.to_string().contains("secret tool"));

        view["calls"][0]["ordered_provenance"]["wire"]["system"] =
            serde_json::json!({"source_handles": ["chat"], "complete": true});
        view["calls"][0]["ordered_provenance"]["wire"]["items"][1] =
            serde_json::json!({"source_handles": ["chat"], "complete": true});
        let omitted_source = project_model_context(&view, |source| source == "chat").unwrap();
        assert_eq!(omitted_source["calls"][0]["redacted"], true);
        assert!(omitted_source["calls"][0].get("body").is_none());

        view["calls"][0]["ordered_provenance"]["wire"]["items"] = serde_json::json!([]);
        let malformed = project_model_context(&view, |source| source == "chat").unwrap();
        assert_eq!(malformed["calls"][0]["redacted"], true);
        assert!(malformed["calls"][0].get("body").is_none());
    }

    #[test]
    fn responses_and_coerced_tool_items_keep_only_safe_structure() {
        let responses = serde_json::json!({
            "calls": [{
                "ordinal": 0,
                "body": {
                    "input": [
                        {"role": "user", "content": "visible question"},
                        {"type": "function_call_output", "call_id": "secret-id", "output": "secret result"}
                    ],
                    "tools": []
                },
                "ordered_provenance": {
                    "messages": [
                        {"source_handles": ["chat"], "complete": true},
                        {"source_handles": ["hidden"], "complete": true}
                    ],
                    "tools": {"source_handles": [], "complete": true},
                    "wire": {
                        "format": "open-ai-responses",
                        "items": [
                            {"source_handles": ["chat"], "complete": true},
                            {"source_handles": ["hidden"], "complete": true}
                        ],
                        "system": null
                    }
                },
                "provenance_complete": true
            }],
            "incomplete": false
        });
        let projected = project_model_context(&responses, |source| source == "chat").unwrap();
        assert_eq!(
            projected["calls"][0]["body"]["input"][1],
            serde_json::json!({
                "redacted": true, "type": "function_call_output"
            })
        );
        assert!(!projected.to_string().contains("secret-id"));
        assert!(!projected.to_string().contains("secret result"));

        let coerced = serde_json::json!({
            "calls": [{
                "ordinal": 0,
                "body": {
                    "messages": [
                        {"role": "user", "content": "visible question"},
                        {"role": "system", "content": "private tool vocabulary"}
                    ],
                    "response_format": {"private_schema": "secret schema"}
                },
                "ordered_provenance": {
                    "messages": [{"source_handles": ["chat"], "complete": true}],
                    "tools": {"source_handles": ["hidden"], "complete": true},
                    "wire": {
                        "format": "coerced-tools",
                        "items": [
                            {"source_handles": ["chat"], "complete": true},
                            {"source_handles": ["hidden"], "complete": true}
                        ],
                        "system": null
                    }
                },
                "provenance_complete": true
            }],
            "incomplete": false
        });
        let projected = project_model_context(&coerced, |source| source == "chat").unwrap();
        assert_eq!(
            projected["calls"][0]["body"]["messages"][1],
            serde_json::json!({
                "redacted": true, "role": "system"
            })
        );
        assert_eq!(
            projected["calls"][0]["body"]["response_format"],
            serde_json::json!({"redacted": true})
        );
        assert!(!projected.to_string().contains("private tool vocabulary"));
        assert!(!projected.to_string().contains("secret schema"));
    }

    #[test]
    fn workspace_result_redacts_only_its_call_after_an_authorized_world_state() {
        let view = mapped_chat_request(serde_json::json!({
            "calls": [
                {
                    "ordinal": 0,
                    "body": {"messages": ["generated world state", "user request"]},
                    "ordered_provenance": {
                        "messages": [
                            {"source_handles": ["package:pinned", "chat:one"], "complete": true},
                            {"source_handles": ["chat:one"], "complete": true}
                        ],
                        "tools": {"source_handles": ["package:pinned"], "complete": true}
                    },
                    "provenance_complete": true
                },
                {
                    "ordinal": 1,
                    "body": {"messages": ["generated world state", "erased file bytes"]},
                    "ordered_provenance": {
                        "messages": [
                            {"source_handles": ["package:pinned", "chat:one"], "complete": true},
                            {"source_handles": ["workspace:one"], "complete": true}
                        ],
                        "tools": {"source_handles": ["package:pinned"], "complete": true}
                    },
                    "provenance_complete": true
                }
            ],
            "incomplete": false
        }));
        let projected = project_model_context(&view, |source| source != "workspace:one").unwrap();
        assert_eq!(projected["calls"][0]["body"], view["calls"][0]["body"]);
        assert_eq!(projected["calls"][1]["ordinal"], 1);
        assert_eq!(projected["calls"][1]["redacted"], true);
        assert!(!projected.to_string().contains("erased file bytes"));
    }

    #[test]
    fn authoring_context_scope_admits_imported_files_but_not_method_files() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let mut wb = wb.lock_unpoisoned();
        let chat = wb
            .create_chat_under_agent(crate::DEFAULT_AGENT, "Edit context")
            .unwrap_or_else(|_| panic!("create edit chat"));
        let chat_id = chat["id"].as_str().unwrap();
        assert!(current_workspace_source_scope(
            &wb,
            chat_id,
            "context.txt",
            true
        ));
        for path in [
            "agent/SYSTEM.md",
            "./agent/SYSTEM.md",
            "notes/../agent/SYSTEM.md",
            ".whipple/draft/source.md",
            ".agent-config.json",
            "work/output.txt",
        ] {
            assert!(!current_workspace_source_scope(&wb, chat_id, path, true));
        }
        assert!(!current_workspace_source_scope(
            &wb,
            chat_id,
            "context.txt",
            false
        ));
    }

    #[test]
    fn file_witness_requires_current_bytes_and_a_retained_cut() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let mut wb = wb.lock_unpoisoned();
        let chat = wb
            .create_default_engagement("file-witness-chat".into(), "File witness".into())
            .unwrap_or_else(|_| panic!("create file witness chat"));
        let path = wb.engagement_workspace_path(&chat.id, "notes.txt");
        let bytes = b"private notes\n";
        let source = format!(
            "workspace-file:{}:{}:{path}",
            chat.id,
            whipplescript_store::stable_hash_bytes_hex(bytes)
        );
        wb.engagements
            .get(&chat.id)
            .unwrap()
            .write_file(&path, "private notes\n")
            .unwrap();
        assert!(!current_workspace_file_source(&wb, &chat.id, &source));
        wb.engagements
            .get(&chat.id)
            .unwrap()
            .commit_turn("retain notes")
            .unwrap();
        assert!(current_workspace_file_source(&wb, &chat.id, &source));
        let target_id = wb.library.current_target_set(&chat.id).unwrap().members[0]
            .target_id
            .clone();
        wb.library
            .work_targets
            .get_mut(&target_id)
            .unwrap()
            .capabilities
            .read = false;
        assert!(!current_workspace_file_source(&wb, &chat.id, &source));
        wb.library
            .work_targets
            .get_mut(&target_id)
            .unwrap()
            .capabilities
            .read = true;
        assert!(current_workspace_file_source(&wb, &chat.id, &source));
        assert!(!current_workspace_file_source(&wb, "another-chat", &source));
        assert!(!current_workspace_file_source(
            &wb,
            &chat.id,
            "workspace-file:file-witness-chat:bad:work/notes.txt"
        ));
        wb.engagements
            .get(&chat.id)
            .unwrap()
            .write_file(&path, "replaced notes\n")
            .unwrap();
        assert!(!current_workspace_file_source(&wb, &chat.id, &source));
        wb.engagements
            .get(&chat.id)
            .unwrap()
            .delete_entry(&path)
            .unwrap();
        wb.engagements
            .get(&chat.id)
            .unwrap()
            .commit_turn("remove notes")
            .unwrap();
        assert!(!current_workspace_file_source(&wb, &chat.id, &source));
    }

    #[test]
    fn directory_search_checks_its_root_and_negative_match_files() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let mut wb = wb.lock_unpoisoned();
        let chat = wb
            .create_default_engagement("scan-witness-chat".into(), "Scan witness".into())
            .unwrap_or_else(|_| panic!("create scan chat"));
        let matched = wb.engagement_workspace_path(&chat.id, "matched.txt");
        let negative = wb.engagement_workspace_path(&chat.id, "negative.txt");
        let directory = matched.strip_suffix("/matched.txt").unwrap();
        let dir_source = format!("workspace-dir:{}:{directory}", chat.id);
        let matched_source = format!(
            "workspace-file:{}:{}:{matched}",
            chat.id,
            whipplescript_store::stable_hash_bytes_hex(b"found\n")
        );
        let negative_source = format!(
            "workspace-file:{}:{}:{negative}",
            chat.id,
            whipplescript_store::stable_hash_bytes_hex(b"no match\n")
        );
        let engagement = wb.engagements.get(&chat.id).unwrap();
        engagement.write_file(&matched, "found\n").unwrap();
        engagement.write_file(&negative, "no match\n").unwrap();
        engagement.commit_turn("retain scan files").unwrap();
        assert!(current_workspace_directory_source(
            &wb,
            &chat.id,
            &dir_source
        ));
        assert!(current_workspace_file_source(
            &wb,
            &chat.id,
            &matched_source
        ));
        assert!(current_workspace_file_source(
            &wb,
            &chat.id,
            &negative_source
        ));
        let view = mapped_chat_request(serde_json::json!({
            "calls": [{
                "ordinal": 0,
                "body": {"messages": ["matched.txt:1:found"]},
                "ordered_provenance": {
                    "messages": [{"source_handles": [dir_source, matched_source, negative_source], "complete": true}],
                    "tools": {"source_handles": ["runtime"], "complete": true}
                },
                "provenance_complete": true
            }],
            "incomplete": false
        }));
        let project = |wb: &Workbench| {
            project_model_context(&view, |source| {
                source == "runtime"
                    || current_workspace_directory_source(wb, &chat.id, source)
                    || current_workspace_file_source(wb, &chat.id, source)
            })
            .unwrap()
        };
        assert_eq!(project(&wb)["calls"][0]["body"], view["calls"][0]["body"]);
        wb.engagements
            .get(&chat.id)
            .unwrap()
            .delete_entry(&negative)
            .unwrap();
        assert_eq!(project(&wb)["calls"][0]["redacted"], true);
    }

    #[test]
    fn directory_listing_checks_each_listed_child_directory() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let mut wb = wb.lock_unpoisoned();
        let chat = wb
            .create_default_engagement("listing-witness-chat".into(), "Listing witness".into())
            .unwrap_or_else(|_| panic!("create listing chat"));
        let nested = wb.engagement_workspace_path(&chat.id, "child/nested.txt");
        let child = nested.strip_suffix("/nested.txt").unwrap();
        let directory = child.strip_suffix("/child").unwrap();
        let dir_source = format!("workspace-dir:{}:{directory}", chat.id);
        let child_source = format!("workspace-dir:{}:{child}", chat.id);
        let engagement = wb.engagements.get(&chat.id).unwrap();
        engagement.write_file(&nested, "nested\n").unwrap();
        engagement.commit_turn("retain listed child").unwrap();
        assert!(current_workspace_directory_source(
            &wb,
            &chat.id,
            &dir_source
        ));
        assert!(current_workspace_directory_source(
            &wb,
            &chat.id,
            &child_source
        ));
        let view = mapped_chat_request(serde_json::json!({
            "calls": [{
                "ordinal": 0,
                "body": {"messages": ["child/"]},
                "ordered_provenance": {
                    "messages": [{"source_handles": [dir_source, child_source], "complete": true}],
                    "tools": {"source_handles": ["runtime"], "complete": true}
                },
                "provenance_complete": true
            }],
            "incomplete": false
        }));
        let project = |wb: &Workbench| {
            project_model_context(&view, |source| {
                source == "runtime" || current_workspace_directory_source(wb, &chat.id, source)
            })
            .unwrap()
        };
        assert_eq!(project(&wb)["calls"][0]["body"], view["calls"][0]["body"]);
        wb.engagements
            .get(&chat.id)
            .unwrap()
            .delete_entry(child)
            .unwrap();
        wb.engagements
            .get(&chat.id)
            .unwrap()
            .commit_turn("remove listed child")
            .unwrap();
        assert_eq!(project(&wb)["calls"][0]["redacted"], true);
    }

    #[test]
    fn file_witness_closes_when_an_unmapped_context_is_revoked_or_erased() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let mut wb = wb.lock_unpoisoned();
        for (name, erase) in [("revoked", false), ("erased", true)] {
            let chat = wb
                .create_default_engagement(format!("{name}-file-chat"), name.to_owned())
                .unwrap_or_else(|_| panic!("create file witness chat"));
            let project = wb.library.project_of_chat(&chat.id).unwrap().to_owned();
            wb.hold_session_for_tests(&project);
            let path = wb.engagement_workspace_path(&chat.id, "notes.txt");
            let bytes = b"retained context\n";
            let source = format!(
                "workspace-file:{}:{}:{path}",
                chat.id,
                whipplescript_store::stable_hash_bytes_hex(bytes)
            );
            let engagement = wb.engagements.get(&chat.id).unwrap();
            engagement.write_file(&path, "retained context\n").unwrap();
            engagement.commit_turn("retain context").unwrap();
            assert!(current_workspace_file_source(&wb, &chat.id, &source));

            let owner = wb.authority().as_str().to_owned();
            let resource = wb
                .mint_resource_context(
                    &chat.id,
                    &owner,
                    &format!("uploaded: {name}"),
                    "test-cut",
                    Default::default(),
                )
                .unwrap();
            assert!(current_workspace_file_source(&wb, &chat.id, &source));
            if erase {
                wb.tombstone_resource_context(&chat.id, &resource.resource.id)
                    .unwrap();
            } else {
                wb.revoke_resource_access(&chat.id, &resource.resource.id)
                    .unwrap();
            }
            assert!(!current_workspace_file_source(&wb, &chat.id, &source));
        }
    }

    #[tokio::test]
    async fn live_route_refuses_another_chats_owner_and_never_caches() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        {
            let mut guard = wb.lock_unpoisoned();
            let instance_id = guard.default_instance.clone();
            guard.write_chat_record(ChatRecord {
                id: "private-chat".into(),
                op: RecordOp::Upsert,
                instance_id,
                title: "Private".into(),
                created_position: 0,
                forked_from: None,
                forked_from_entry: None,
                forked_from_cut: None,
                owner: Some("another-person".into()),
                schema: LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
            });
        }
        let denied = super::get_model_context(
            State(wb.clone()),
            Path("private-chat".into()),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert_eq!(denied.headers()["cache-control"], "no-store");

        let unavailable =
            super::get_model_context(State(wb), Path("missing-chat".into()), HeaderMap::new())
                .await
                .into_response();
        assert_eq!(unavailable.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn live_route_rechecks_sources_and_discards_settled_capture() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let set_owner = |owner: Option<&str>| {
            let mut guard = wb.lock_unpoisoned();
            let instance_id = guard.default_instance.clone();
            guard.write_chat_record(ChatRecord {
                id: "raw-context-chat".into(),
                op: RecordOp::Upsert,
                instance_id,
                title: "Raw context".into(),
                created_position: 0,
                forked_from: None,
                forked_from_entry: None,
                forked_from_cut: None,
                owner: owner.map(str::to_owned),
                schema: LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
            });
        };
        set_owner(None);
        let claim = crate::engine::claim_turn("raw-context-chat").unwrap();
        let image = gaugedesk_harness::ImageContent {
            kind: gaugedesk_harness::ImageKind::Image,
            data: "aW1hZ2U=".to_owned(),
            mime_type: "image/png".to_owned(),
        };
        let image_source =
            gaugedesk_whip_runtime::live_turn_image_source("raw-context-chat", &image).unwrap();
        let raw = mapped_chat_request(serde_json::json!({
            "calls": [
                {
                    "ordinal": 0,
                    "body": {"messages": ["visible runtime framing"]},
                    "ordered_provenance": {
                        "messages": [{"source_handles": ["runtime", "chat:raw-context-chat"], "complete": true}],
                        "tools": {"source_handles": ["runtime"], "complete": true}
                    },
                    "provenance_complete": true
                },
                {
                    "ordinal": 1,
                    "body": {"messages": ["erased workspace bytes"]},
                    "ordered_provenance": {
                        "messages": [{"source_handles": ["workspace:raw-context-chat"], "complete": true}],
                        "tools": {"source_handles": ["runtime"], "complete": true}
                    },
                    "provenance_complete": true
                },
                {
                    "ordinal": 2,
                    "body": {"messages": [{"type": "image", "data": "aW1hZ2U="}]},
                    "ordered_provenance": {
                        "messages": [{"source_handles": ["chat:raw-context-chat", image_source], "complete": true}],
                        "tools": {"source_handles": ["runtime"], "complete": true}
                    },
                    "provenance_complete": true
                }
            ],
            "incomplete": false
        }));
        crate::engine::bind_turn_model_context(
            "raw-context-chat",
            std::sync::Arc::new(move || Ok(raw.to_string())),
        );
        let response = super::get_model_context(
            State(wb.clone()),
            Path("raw-context-chat".into()),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let view: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            view["calls"][0]["body"]["messages"][0],
            "visible runtime framing"
        );
        assert_eq!(view["calls"][1]["redacted"], true);
        assert_eq!(view["calls"][2]["redacted"], true);
        assert!(!view.to_string().contains("erased workspace bytes"));
        assert!(!view.to_string().contains("aW1hZ2U="));

        crate::engine::bind_turn_image_sources("raw-context-chat", &[image]);
        let response = super::get_model_context(
            State(wb.clone()),
            Path("raw-context-chat".into()),
            HeaderMap::new(),
        )
        .await
        .into_response();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let visible: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            visible["calls"][2]["body"]["messages"][0]["data"],
            "aW1hZ2U="
        );

        set_owner(Some("another-person"));
        let revoked = super::get_model_context(
            State(wb.clone()),
            Path("raw-context-chat".into()),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(revoked.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(revoked.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("visible runtime framing"));

        drop(claim);
        set_owner(None);
        let settled =
            super::get_model_context(State(wb), Path("raw-context-chat".into()), HeaderMap::new())
                .await
                .into_response();
        let bytes = axum::body::to_bytes(settled.into_body(), usize::MAX)
            .await
            .unwrap();
        let view: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(view["available"], false);
    }

    #[tokio::test]
    async fn account_image_requires_the_verified_live_submitter() {
        use gaugedesk_core::abac::AuthorityAttributes;
        use gaugedesk_core::ids::AuthorityId;

        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let chat_id = "account-image-chat";
        {
            let mut guard = wb.lock_unpoisoned();
            let instance_id = guard.default_instance.clone();
            guard.write_chat_record(ChatRecord {
                id: chat_id.into(),
                op: RecordOp::Upsert,
                instance_id,
                title: "Image".into(),
                created_position: 0,
                forked_from: None,
                forked_from_entry: None,
                forked_from_cut: None,
                owner: Some("alice".into()),
                schema: LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
            });
            let idp = crate::identity::LoopbackIdentityProvider::new().enroll(
                "alice-token",
                AuthorityId::new("alice"),
                AuthorityAttributes::default(),
            );
            guard.set_identity_provider(Some(std::sync::Arc::new(idp)));
        }
        let claim = crate::engine::claim_turn(chat_id).unwrap();
        let image = gaugedesk_harness::ImageContent {
            kind: gaugedesk_harness::ImageKind::Image,
            data: "aW1hZ2U=".into(),
            mime_type: "image/png".into(),
        };
        let source = gaugedesk_whip_runtime::live_turn_image_source(chat_id, &image).unwrap();
        crate::engine::bind_turn_image_sources(chat_id, &[image]);
        let raw = mapped_chat_request(serde_json::json!({
            "calls": [{
                "ordinal": 0,
                "body": {"messages": [{"role": "user", "content": [{"type": "image", "data": "aW1hZ2U="}]}]},
                "ordered_provenance": {
                    "messages": [{"source_handles": [format!("chat:{chat_id}"), source], "complete": true}],
                    "tools": {"source_handles": ["runtime"], "complete": true}
                },
                "provenance_complete": true
            }],
            "incomplete": false
        }));
        crate::engine::bind_turn_model_context(
            chat_id,
            std::sync::Arc::new(move || Ok(raw.to_string())),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer alice-token".parse().unwrap(),
        );
        let read = |wb: crate::SharedWorkbench, headers: HeaderMap| async move {
            let response = super::get_model_context(State(wb), Path(chat_id.into()), headers)
                .await
                .into_response();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        };
        assert_eq!(
            read(wb.clone(), headers.clone()).await["calls"][0]["redacted"],
            true
        );
        crate::engine::bind_turn_image_submitter(chat_id, Some(&AuthorityId::new("bob")));
        assert_eq!(
            read(wb.clone(), headers.clone()).await["calls"][0]["redacted"],
            true
        );
        crate::engine::bind_turn_image_submitter(chat_id, Some(&AuthorityId::new("alice")));
        assert_eq!(
            read(wb.clone(), headers).await["calls"][0]["body"]["messages"][0]["content"][0]
                ["data"],
            "aW1hZ2U="
        );
        drop(claim);
    }

    #[tokio::test]
    async fn live_route_redacts_a_file_after_its_current_cut_is_removed() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let (chat_id, path) = {
            let mut guard = wb.lock_unpoisoned();
            let chat = guard
                .create_default_engagement("file-context-chat".into(), "File context".into())
                .unwrap_or_else(|_| panic!("create file context chat"));
            let path = guard.engagement_workspace_path(&chat.id, "notes.txt");
            let engagement = guard.engagements.get(&chat.id).unwrap();
            engagement
                .write_file(&path, "retained private notes\n")
                .unwrap();
            engagement.commit_turn("retain notes").unwrap();
            (chat.id, path)
        };
        let source = format!(
            "workspace-file:{chat_id}:{}:{path}",
            whipplescript_store::stable_hash_bytes_hex(b"retained private notes\n")
        );
        let claim = crate::engine::claim_turn(&chat_id).unwrap();
        let raw = mapped_chat_request(serde_json::json!({
            "calls": [{
                "ordinal": 0,
                "body": {"messages": ["retained private notes"]},
                "ordered_provenance": {
                    "messages": [{"source_handles": [source], "complete": true}],
                    "tools": {"source_handles": ["runtime"], "complete": true}
                },
                "provenance_complete": true
            }],
            "incomplete": false
        }));
        crate::engine::bind_turn_model_context(
            &chat_id,
            std::sync::Arc::new(move || Ok(raw.to_string())),
        );
        let read = |wb: crate::workbench_state::SharedWorkbench, id: String| async move {
            let response = super::get_model_context(State(wb), Path(id), HeaderMap::new())
                .await
                .into_response();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        };
        let visible = read(wb.clone(), chat_id.clone()).await;
        assert_eq!(
            visible["calls"][0]["body"]["messages"][0],
            "retained private notes"
        );

        {
            let guard = wb.lock_unpoisoned();
            let engagement = guard.engagements.get(&chat_id).unwrap();
            engagement.delete_entry(&path).unwrap();
            engagement.commit_turn("remove notes").unwrap();
        }
        let redacted = read(wb, chat_id).await;
        assert_eq!(redacted["calls"][0]["redacted"], true);
        assert!(!redacted.to_string().contains("retained private notes"));
        drop(claim);
    }
}

pub(crate) async fn get_choice_cards(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if !wb.library.chats.contains_key(&id) {
        return (StatusCode::NOT_FOUND, "no such chat").into_response();
    }
    match crate::choice_prompt::list(wb.store_ref(), &id) {
        Ok(cards) => (StatusCode::OK, Json(cards)).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{error:?}")).into_response(),
    }
}

pub(crate) async fn post_choice_answer(
    State(wb): State<SharedWorkbench>,
    Path((id, card_id)): Path<(String, String)>,
    headers: HeaderMap,
    actor: Option<axum::extract::Extension<crate::identity::AuthenticatedActor>>,
    authenticated: Option<axum::extract::Extension<crate::identity::AuthenticatedActionContext>>,
    Json(body): Json<crate::choice_prompt::AnswerRequest>,
) -> impl IntoResponse {
    let actor = actor.map(|axum::extract::Extension(actor)| actor.0);
    let authenticated = authenticated.map(|axum::extract::Extension(context)| context);
    let (card, inserted, context, respondent) = {
        let mut g = wb.lock_unpoisoned();
        let Some(context) = g.engagement_task_context(&id) else {
            return (StatusCode::NOT_FOUND, "no such chat").into_response();
        };
        if context.mode != ChatMode::Use {
            return (StatusCode::FORBIDDEN, "choice answers require a work chat").into_response();
        }
        let respondent = actor
            .as_ref()
            .cloned()
            .unwrap_or_else(|| g.authority().clone());
        if !g
            .roster()
            .iter()
            .any(|person| person.authority == respondent.as_str())
        {
            return (StatusCode::FORBIDDEN, "respondent has no chat standing").into_response();
        }
        let Some(existing) = (match crate::choice_prompt::get(g.store_ref(), &id, &card_id) {
            Ok(card) => card,
            Err(error) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{error:?}")).into_response();
            }
        }) else {
            return (StatusCode::NOT_FOUND, "choice card not found").into_response();
        };
        if existing.recipient != respondent.as_str() {
            return (
                StatusCode::FORBIDDEN,
                "choice card belongs to another recipient",
            )
                .into_response();
        }
        let result =
            crate::choice_prompt::answer(g.store_mut(), &id, &card_id, respondent.as_str(), &body);
        let (card, inserted) = match result {
            Ok(result) => result,
            Err(error) => {
                let status = if error.contains("already answered") {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::BAD_REQUEST
                };
                return (status, error).into_response();
            }
        };
        g.notify_library_changed("question", &id, "upsert");
        (card, inserted, context, respondent)
    };
    if !inserted
        && card
            .continuation
            .as_ref()
            .is_some_and(|state| state.status == "completed")
    {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"card": card, "replayed": true})),
        )
            .into_response();
    }
    if !inserted
        && card
            .continuation
            .as_ref()
            .is_some_and(|state| state.status == "refused")
    {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"card": card, "continuation_error": card.continuation.as_ref().and_then(|state| state.error.clone())})),
        )
            .into_response();
    }
    let account_bearer = crate::net_http::bearer(&headers).map(str::to_owned);
    let (account_scope, tenant_scope) = {
        let g = wb.lock_unpoisoned();
        (
            g.credential_scope_for(account_bearer.as_deref()),
            crate::workbench_auth::req_scope(&headers),
        )
    };
    let client_build = crate::client_admission::ClientBuild::from_headers(&headers);
    let wb2 = wb.clone();
    let id2 = id.clone();
    let prompt = crate::choice_prompt::continuation_text(&card);
    let command_id = format!("choice-answer:{}", card.id);
    let outcome = tokio::task::spawn_blocking(move || {
        engine::run_engagement_turn(
            &wb2,
            &id2,
            &context.worktree,
            &context.sender,
            engine::EngagementTurnInput {
                task: &prompt,
                images: &[],
                mode: context.mode,
                authenticated_actor: Some(&respondent),
                authenticated_context: authenticated.as_ref(),
                client_build: Some(&client_build),
                local_operator: false,
                contribution_by: None,
                account_scope: &account_scope,
                tenant_scope: &tenant_scope,
                account_bearer: account_bearer.as_deref(),
                client_request_id: None,
                client_author: None,
                client_attempt: None,
                runtime_command_id: Some(&command_id),
                original_http_command: None,
                harness_factory: None,
            },
        )
    })
    .await;
    let (status, continuation_status, error) = match &outcome {
        Ok(Ok(_)) => (StatusCode::OK, "completed", None),
        Ok(Err(error)) => (
            task_failure_status(error),
            if matches!(error, engine::EngineError::Admit(_)) {
                "refused"
            } else {
                "pending"
            },
            Some(error.to_string()),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "pending",
            Some("turn panicked".to_owned()),
        ),
    };
    {
        let mut g = wb.lock_unpoisoned();
        if let Err(error) = crate::choice_prompt::record_continuation(
            g.store_mut(),
            &id,
            &card.id,
            continuation_status,
            error.as_deref(),
        ) {
            return (StatusCode::INTERNAL_SERVER_ERROR, error).into_response();
        }
        g.notify_library_changed("question", &id, "upsert");
    }
    match outcome {
        Ok(Ok(result)) => (
            status,
            Json(serde_json::json!({"card": card, "turn": result})),
        )
            .into_response(),
        Ok(Err(error)) => (
            task_failure_status(&error),
            Json(serde_json::json!({"card": card, "continuation_error": error.to_string()})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"card": card, "continuation_error": "turn panicked"})),
        )
            .into_response(),
    }
}

/// The chat's context-window reading for the composer's meter. `null` until a
/// turn on a reporting runtime settles.
pub(crate) async fn get_context_usage(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    match wb.engagement_context_json(&id) {
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
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let viewer = match crate::method_access::chat_reader(&wb, &id, &headers) {
        Ok(viewer) => viewer,
        Err(error) => return error.into_response(),
    };
    let Some(tree) = wb.engagement_tree(&id) else {
        return (StatusCode::NOT_FOUND, "no such engagement").into_response();
    };
    match tree {
        Ok(entries) => {
            let files: Vec<_> = entries
                .into_iter()
                .filter(|e| {
                    !(wb.installed_method_read_requires_grant(&id, &e.path)
                        || (crate::method_access::account_backed_chat(&wb, &id, &headers)
                            && wb.is_installed_method_path(&id, &e.path)))
                        || wb
                            .package_selection_for_chat(&id)
                            .is_some_and(|(_, package_ref)| {
                                wb.method_inspection_granted(&id, &viewer, &package_ref)
                            })
                })
                .filter(|e| {
                    !crate::method_access::account_backed_chat(&wb, &id, &headers)
                        || wb.is_installed_method_path(&id, &e.path)
                        || wb.authoring_draft_readable(&id, &e.path, Some(&viewer))
                        || if e.is_dir {
                            crate::context_inspection::directory_visible(&wb, &id, &viewer, &e.path)
                        } else {
                            crate::context_inspection::worktree_file_readable(
                                &wb, &id, &viewer, &e.path, None,
                            )
                        }
                })
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

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub(crate) enum FileManagerCommand {
    CreateFile {
        path: String,
    },
    CreateFolder {
        path: String,
    },
    Rename {
        path: String,
        to: String,
    },
    Delete {
        path: String,
    },
    /// Settle a target name the chat and its line disagree on (DR-0248):
    /// `keep` is `chat` or `line`. `path` is the target's folder.
    SettleTargetName {
        path: String,
        keep: String,
    },
}

impl FileManagerCommand {
    fn path(&self) -> &str {
        match self {
            Self::CreateFile { path }
            | Self::CreateFolder { path }
            | Self::Rename { path, .. }
            | Self::Delete { path }
            | Self::SettleTargetName { path, .. } => path,
        }
    }

    fn verb(&self) -> &'static str {
        match self {
            Self::CreateFile { .. } => "created file",
            Self::CreateFolder { .. } => "created folder",
            Self::Rename { .. } => "renamed",
            Self::Delete { .. } => "deleted",
            Self::SettleTargetName { .. } => "settled the name of",
        }
    }
}

pub(crate) async fn post_file_manager_command(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(command): Json<FileManagerCommand>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Err(error) = crate::method_access::chat_reader(&wb, &id, &headers) {
        return error.into_response();
    }
    match wb.apply_file_manager_command(&id, &command) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "updated": true }))).into_response(),
        Err((status, reason)) => {
            (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

/// The largest file this read serves. A worktree holds whatever the work put
/// in it, up to and including multi-gigabyte artifacts; buffering one into a
/// response to paint it in a browser pane helps nobody, so the read refuses
/// past this and the viewer says so rather than hanging.
pub(crate) const MAX_VIEWABLE_FILE_BYTES: usize = 32 * 1024 * 1024;

/// Read a worktree file (the content viewer's View mode).
///
/// UTF-8 content keeps the `text/plain` body every existing reader expects.
/// Anything else is served as opaque bytes — a PDF or an image is a file the
/// viewer renders, and reading it as text was never a failure of the file.
pub(crate) async fn get_file(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    Query(q): Query<FileQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let viewer = match crate::method_access::chat_reader(&wb, &id, &headers) {
        Ok(viewer) => viewer,
        Err(error) => return error.into_response(),
    };
    let account_backed = crate::method_access::account_backed_chat(&wb, &id, &headers);
    // One spelling for the guarded read and for the cut it names (WS-997).
    let path = match gaugedesk_workspace::canonical_relative_path(&q.path) {
        Ok(path) => path,
        Err(error) => return (StatusCode::BAD_REQUEST, format!("{error}")).into_response(),
    };
    let Some(content) = wb.read_engagement_file_bytes_for_viewer(
        &id,
        &path,
        MAX_VIEWABLE_FILE_BYTES,
        Some(&viewer),
        account_backed,
    ) else {
        return (StatusCode::NOT_FOUND, "no such engagement").into_response();
    };
    let bytes = match content {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "{path} is larger than the {} MiB this viewer opens",
                    MAX_VIEWABLE_FILE_BYTES / (1024 * 1024)
                ),
            )
                .into_response();
        }
        Err(e) => return (StatusCode::BAD_REQUEST, format!("{e}")).into_response(),
    };
    // Name a cut only if retained history contains the exact served body.
    // A transient working-copy edit remains viewable without becoming history;
    // unavailable evidence omits the cut instead of importing or repairing it.
    let cut = wb
        .engagement_recorded_file_cut(&id, &path, &bytes)
        .and_then(|result| result.ok())
        .flatten();
    let mut response = match String::from_utf8(bytes) {
        Ok(text) => (StatusCode::OK, text).into_response(),
        Err(not_utf8) => {
            let mut response = (StatusCode::OK, not_utf8.into_bytes()).into_response();
            let headers = response.headers_mut();
            // Worktree bytes are never rendered in the Home's own origin: a
            // direct navigation to this URL downloads them. The viewer reads
            // them through `fetch` and paints them from a blob either way, so
            // nothing legitimate needs the browser to interpret this body.
            headers.insert(
                axum::http::header::CONTENT_DISPOSITION,
                axum::http::HeaderValue::from_static("attachment"),
            );
            headers.insert(
                axum::http::header::X_CONTENT_TYPE_OPTIONS,
                axum::http::HeaderValue::from_static("nosniff"),
            );
            response
        }
    };
    if let Some(cut) = cut {
        if let Ok(value) = axum::http::HeaderValue::from_str(&cut) {
            response.headers_mut().insert("x-workspace-cut", value);
        }
    }
    response
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
    headers: HeaderMap,
    Query(q): Query<FileQuery>,
    body: String,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if let Err(error) = crate::method_access::chat_reader(&wb, &id, &headers) {
        return error.into_response();
    }
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
    headers: HeaderMap,
    Json(body): Json<MergePreviewBody>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if let Err(error) = crate::method_access::chat_reader(&wb, &id, &headers) {
        return error.into_response();
    }
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
    headers: HeaderMap,
    context: Option<axum::Extension<crate::identity::AuthenticatedActionContext>>,
) -> axum::response::Response {
    if let Some(axum::Extension(context)) = context {
        if matches!(
            context.authentication(),
            crate::identity::ActorAuthentication::OfficeStaff { .. }
        ) {
            return crate::office_home_admission::chat_stream::response(
                wb,
                &context,
                id,
                crate::client_admission::ClientBuild::from_headers(&headers),
            );
        }
    }
    let rx = wb.lock_unpoisoned().sender(&id).subscribe();
    // A lagged subscriber's stream ends; the client reopens and reloads the
    // durable transcript (SCALE-4).
    let stream = crate::stream::until_lagged(rx)
        .map(|ev: ServerEvent| Ok::<_, Infallible>(Event::default().data(ev.to_json())));
    Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response()
}

/// Live **workspace** event stream (SSE): a "changed" ping whenever the library
/// mutates (a chat/project/archetype/placement created, renamed, or removed — on
/// THIS client or any other, e.g. a paired device). The client re-reads `/workspace`
/// on each ping, so every nav mirrors the node live (the push the system is built
/// on, not a poll). Subscribes to the reserved `library` stream key.
pub(crate) async fn workspace_events(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    context: Option<axum::Extension<crate::identity::AuthenticatedActionContext>>,
) -> axum::response::Response {
    if let Some(axum::Extension(context)) = context {
        if matches!(
            context.authentication(),
            crate::identity::ActorAuthentication::OfficeStaff { .. }
        ) {
            return crate::office_home_admission::workspace_stream::response(
                wb,
                &context,
                crate::client_admission::ClientBuild::from_headers(&headers),
            );
        }
    }
    let rx = wb.lock_unpoisoned().workspace_sender().subscribe();
    // Each subscriber hears only of what it can see (DR-0268 §5).
    let bearer = crate::net_http::bearer(&headers).map(str::to_owned);
    let shared = wb.clone();
    // A lagged subscriber's stream ends; the client reopens and re-reads the
    // workspace (SCALE-4).
    let stream = crate::stream::until_lagged(rx)
        .filter(move |ev: &ServerEvent| {
            shared
                .lock_unpoisoned()
                .workspace_event_visible(bearer.as_deref(), ev)
        })
        .map(|ev: ServerEvent| Ok::<_, Infallible>(Event::default().data(ev.to_json())));
    Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response()
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
/// answers `403`; a chat that is already running answers `409`, because the
/// caller's message is fine and only its timing was wrong (ADR 0138 §2); only
/// something actually breaking keeps `502`.
///
/// The distinction is not cosmetic, and getting it wrong is expensive twice
/// over: a 5xx invites a retry of something that will be refused identically
/// every time, and Cloudflare substitutes its own body for an origin 5xx — so
/// the runtime's explanation of *which* rule denied *which* read is replaced by
/// "the origin is overloaded or misconfigured" before the caller sees it. The
/// production wiring canary read that as an origin outage for days.
fn task_failure_status(error: &crate::engine::EngineError) -> StatusCode {
    match error {
        // Conflict, not failure: the chat is busy and the same message will be
        // accepted once it is not. `409` is what tells the composer to hold it as
        // a follow-up rather than surface a broken turn (ADR 0138 §4).
        crate::engine::EngineError::AlreadyRunning => StatusCode::CONFLICT,
        // Asked for, not broken: this turn ended because someone stopped it.
        // `499` is nginx's "client closed the request" and reads the same way —
        // the caller withdrew, so nothing here failed. A 502 would tell the
        // composer to keep the cancelled message for a retry nobody wanted.
        crate::engine::EngineError::Interrupted => StatusCode::from_u16(499).unwrap(),
        error if error.is_policy_denial() => StatusCode::FORBIDDEN,
        _ => StatusCode::BAD_GATEWAY,
    }
}

/// Task an engagement: drive one governed WhippleScript turn in its worktree,
/// streaming operational events live (SSE) and returning the diff + output.
#[allow(clippy::too_many_arguments)] // Independent request authority and original command extractors.
pub(crate) async fn post_task(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    actor: Option<axum::extract::Extension<crate::identity::AuthenticatedActor>>,
    authenticated: Option<axum::extract::Extension<crate::identity::AuthenticatedActionContext>>,
    operator: Option<axum::extract::Extension<crate::account_signin::DesktopOperatorPlane>>,
    original: Option<axum::extract::Extension<crate::command_idempotency::ClaimedHttpCommand>>,
    attempt: Option<axum::extract::Extension<crate::command_idempotency::TaskAttempt>>,
    Json(body): Json<TaskBody>,
) -> impl IntoResponse {
    let original = original.map(|axum::extract::Extension(original)| original);
    if authenticated.as_ref().is_some_and(|context| {
        matches!(
            context.authentication(),
            crate::identity::ActorAuthentication::OfficeStaff { .. }
        )
    }) && original.is_none()
    {
        return (
            StatusCode::BAD_REQUEST,
            "office task requires its original HTTP command claim",
        )
            .into_response();
    }
    let client_request_id = match crate::command_idempotency::caller_idempotency_key(&headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let author = {
        let mut guard = wb.lock_unpoisoned();
        engine::verified_task_author(
            &mut guard,
            &headers,
            &axum::http::Method::POST,
            &format!("/chats/{id}/task"),
        )
    };
    // An original Office HTTP request needs its independently verified
    // requester. A staff/runtime extension is not a substitute for that proof.
    if authenticated.as_ref().is_some_and(|context| {
        matches!(
            context.authentication(),
            crate::identity::ActorAuthentication::OfficeStaff { .. }
        )
    }) && author.is_none()
    {
        return (
            StatusCode::FORBIDDEN,
            "office task requires verified HTTP requester",
        )
            .into_response();
    }
    let attempt = attempt.map(|axum::extract::Extension(attempt)| attempt);
    let refused = || {
        author
            .as_ref()
            .map(|author| crate::stream::TaskCorrelation {
                home_id: author.home_id.clone(),
                actor_id: author.actor_id.clone(),
                client_request_id: client_request_id.clone(),
                chat_id: id.clone(),
                outcome: crate::stream::TaskCorrelationOutcome::Refused,
            })
    };
    // Brief lock: confirm the engagement and grab its worktree, live sender, mode.
    let (worktree, sender, mode) = {
        let mut g = wb.lock_unpoisoned();
        let Some(location) = g.engagement_turn_location(&id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "no such engagement", "correlation": refused(),
                })),
            )
                .into_response();
        };
        location
    };

    let account_bearer = crate::net_http::bearer(&headers).map(str::to_owned);
    let (account_scope, tenant_scope) = {
        let g = wb.lock_unpoisoned();
        (
            g.credential_scope_for(account_bearer.as_deref()),
            crate::workbench_auth::req_scope(&headers),
        )
    };
    let client_build = crate::client_admission::ClientBuild::from_headers(&headers);
    let wb2 = wb.clone();
    let task = body.prompt;
    let images = body.images;
    let actor = actor.map(|axum::extract::Extension(actor)| actor.0);
    let authenticated = authenticated.map(|axum::extract::Extension(context)| context);
    let local_operator = operator.is_some();
    let id2 = id.clone();
    let client_request_id2 = client_request_id.clone();
    let author2 = author.clone();
    let attempt2 = attempt.clone();
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
                authenticated_context: authenticated.as_ref(),
                client_build: Some(&client_build),
                local_operator,
                contribution_by: None,
                account_scope: &account_scope,
                tenant_scope: &tenant_scope,
                account_bearer: account_bearer.as_deref(),
                client_request_id: Some(&client_request_id2),
                client_author: author2.as_ref(),
                client_attempt: attempt2.as_ref(),
                runtime_command_id: None,
                original_http_command: original.as_ref(),
                harness_factory: None,
            },
        )
    })
    .await;

    let correlation = author
        .as_ref()
        .zip(attempt.as_ref())
        .and_then(|(author, attempt)| {
            engine::task_correlation(
                wb.lock_unpoisoned().store_ref(),
                &id,
                &client_request_id,
                author,
                Some(attempt),
            )
        });
    match outcome {
        Ok(Ok(result)) => {
            let mut body = serde_json::to_value(result).expect("serialize TaskResult");
            if let Some(correlation) = correlation {
                body["correlation"] =
                    serde_json::to_value(correlation).expect("serialize task correlation");
            }
            (StatusCode::OK, Json(body)).into_response()
        }
        Ok(Err(e)) => {
            let status = task_failure_status(&e);
            let mut body = serde_json::json!({ "error": e.to_string() });
            let correlation = if matches!(e, engine::EngineError::AlreadyRunning) {
                refused()
            } else {
                correlation
            };
            if let Some(correlation) = correlation {
                body["correlation"] =
                    serde_json::to_value(correlation).expect("serialize task correlation");
            }
            // A 409 is read as a refusal by the browser transport, which looks for
            // `rejected` and reports "unknown" without it. Carrying the reason is
            // the difference between the composer saying why a message is waiting
            // and saying nothing (`INV-2`; ADR 0138 §2).
            if status == StatusCode::CONFLICT {
                body["rejected"] = serde_json::Value::String(e.to_string());
            }
            (status, Json(body)).into_response()
        }
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
/// the session is retired and the next turn respawns.
///
/// Stop is a standing intent recorded against the turn's claim, not a call on a
/// handle that must already exist. It used to be the latter, and so its answer
/// described how far turn startup had got rather than anything true about the
/// turn: for the 124-222ms before a handle was bound it refused a plainly
/// running turn as `"not interruptible"`, and in the moment after, while the
/// handle's own cancellation surface was still empty, it reported success and
/// did nothing at all — the turn ran to completion behind a composer that had
/// been told it was stopping.
///
/// Recording the intent removes both. A claimed turn is always stoppable, so
/// `"nothing running"` is the only refusal left: the turn is ended by whichever
/// mechanism reaches the intent first — a startup checkpoint, the bind that
/// fires a newly-arrived handle, or this call firing one that is already there.
pub(crate) async fn post_stop(
    State(_wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match engine::request_turn_stop(&id) {
        Some(interrupt) => {
            // A handle already bound is fired now, out of band, so a turn
            // blocked in provider I/O does not have to reach a checkpoint to
            // notice. WhippleScript records the cancellation on an independent
            // store connection, so durable thread state survives it.
            if let Some(interrupt) = interrupt {
                interrupt();
            }
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
    /// Match the synthetic account Hub only for Administration admission.
    /// The ordinary local-user fixture remains the default.
    #[serde(default)]
    administration_account: bool,
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
    /// Seed one recoverable person account. The plaintext fixture code exists
    /// only in the browser test; the store receives its verifier and encrypted
    /// custody envelope through the production account-auth decisions.
    #[serde(default)]
    account_recovery: bool,
}

/// Debug builds only (DR-0054 Phase A): a route that deletes the entire state
/// root must not exist in a release artifact, so the handler and its mounting
/// are both compiled out. The `GAUGEDESK_TEST_RESET` process guard below
/// remains as defense in depth where the route does exist.
#[cfg(debug_assertions)]
pub(crate) async fn post_test_reset(
    State(wb): State<SharedWorkbench>,
    Query(query): Query<TestResetQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if gaugedesk_env::var("TEST_RESET").is_none() {
        return (StatusCode::FORBIDDEN, "reset is disabled").into_response();
    }
    if query.administration_account && gaugedesk_env::var("TEST_IDENTITY_TOKEN").is_none() {
        return (
            StatusCode::BAD_REQUEST,
            "Administration account fixture requires test identity",
        )
            .into_response();
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
        Ok(scratch) => {
            let mut recovery = Workbench::new(scratch);
            // A failed debug reset must keep its recovery root so the next
            // guarded request can retry; this is never a successful reset.
            recovery.root = root.clone();
            drop(std::mem::replace(&mut *guard, recovery));
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("reset scratch store: {e}"),
            )
                .into_response()
        }
    }
    if let Err(error) = wipe_state_root(&root) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("reset wipe: {error}"),
        )
            .into_response();
    }
    // Clear any armed test-only conflict injection (UX-7) so it can't leak across scenarios.
    engine::set_force_merge_conflict(false);
    match build_workbench(&root) {
        Ok(fresh) => {
            // Keep the rebuilt root on every fixture error. The mutex excludes
            // observers while seeding; refusal stays failure, never reset success
            // or an old-state rollback claim, and the next reset can retry.
            *guard = fresh;
            let fresh = &mut *guard;
            // The enterprise browser composition uses the same reset hook. Seed
            // its controlled identities and memberships here, behind the
            // test-only gate, rather than retaining a production `/admin/*`
            // write bypass solely for test setup. When the launcher supplies
            // credentials, the production enterprise middleware and cookie /
            // bearer parser remain active; absence and invalid credentials fail
            // closed exactly as they do outside the harness.
            let owner_authority = if query.administration_account {
                "e2e-account-root"
            } else {
                "local-user"
            };
            let owner = crate::org::MembershipRecord {
                id: owner_authority.to_owned(),
                op: crate::org::RecordOp::Upsert,
                org_id: crate::org::ORG_ID.to_owned(),
                authority: owner_authority.to_owned(),
                email: String::new(),
                role: "owner".to_owned(),
                status: crate::org::MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            };
            if let Err(error) = fresh.store_mut().append_record(
                crate::org::ORG_SCOPE,
                "membership",
                &serde_json::to_string(&owner).expect("test owner serializes"),
            ) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("test owner: {error:?}"),
                )
                    .into_response();
            }
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
                if let Err(error) = fresh.store_mut().append_record(
                    crate::org::ORG_SCOPE,
                    "membership",
                    &serde_json::to_string(&member).expect("test member serializes"),
                ) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("test member: {error:?}"),
                    )
                        .into_response();
                }
                let idp = crate::identity::LoopbackIdentityProvider::new()
                    .enroll(
                        owner_token,
                        AuthorityId::new(owner_authority),
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
            if query.account_recovery {
                use crate::account_auth::{
                    append_facts, create_custodied_account_root, decide_replace_recovery_codes,
                    decide_verify_email, AccountAuth, RecoveryCodeRecord, VerifiedEmailRecord,
                };

                let now = crate::account_session::unix_now();
                let (account_id, root) = match create_custodied_account_root(fresh, now) {
                    Ok(value) => value,
                    Err(error) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("test recovery custody: {error:?}"),
                        )
                            .into_response()
                    }
                };
                let state = match AccountAuth::rebuild(fresh.store_ref()) {
                    Ok(state) => state,
                    Err(error) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("test recovery projection: {error:?}"),
                        )
                            .into_response()
                    }
                };
                let email = match VerifiedEmailRecord::new(
                    &account_id,
                    "recovery-fixture@gaugewright.test",
                    now,
                ) {
                    Ok(record) => record,
                    Err(error) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("test recovery email: {error:?}"),
                        )
                            .into_response()
                    }
                };
                let code = match RecoveryCodeRecord::prepare(
                    &account_id,
                    "browser-recovery-fixture",
                    "browser-recovery-salt",
                    "GW-E2E-RECOVERY",
                ) {
                    Ok(record) => record,
                    Err(error) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("test recovery code: {error:?}"),
                        )
                            .into_response()
                    }
                };
                let mut facts = vec![root];
                match decide_verify_email(&state, email) {
                    Ok(records) => facts.extend(records),
                    Err(error) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("test recovery email decision: {error:?}"),
                        )
                            .into_response()
                    }
                }
                match decide_replace_recovery_codes(
                    &state,
                    &account_id,
                    "browser-recovery-fixture",
                    now,
                    vec![code],
                ) {
                    Ok(records) => facts.extend(records),
                    Err(error) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("test recovery code decision: {error:?}"),
                        )
                            .into_response()
                    }
                }
                if let Err(error) = append_facts(fresh.store_mut(), &facts) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("test recovery seed: {error:?}"),
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
                let project = match fresh.library.project_of_chat(chat) {
                    Some(project) => project.to_owned(),
                    None => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "test access project missing",
                        )
                            .into_response()
                    }
                };
                let _session = match reset_fixture_session(fresh, &headers, &project) {
                    Ok(session) => session,
                    Err(error) => return error.into_response(),
                };
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
                if let Err(error) = seed_exportable_output(fresh, &headers) {
                    return *error;
                }
            }
            (StatusCode::OK, Json(serde_json::json!({ "reset": true }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("rebuild: {e}")).into_response(),
    }
}

/// Fixture content is written only for the proven resource owner while that
/// request holds its admitted project, exactly as other non-project-path
/// request handlers use `hold_for_session`. No unattended/test key grant.
///
/// A local Project Host without an identity provider admits its
/// credential-free channel as the computer's own account, as its composition
/// does for every other request; anywhere else the caller must present a
/// credential that names the current owner.
#[cfg(debug_assertions)]
fn reset_fixture_session(
    wb: &Workbench,
    headers: &HeaderMap,
    project: &str,
) -> Result<crate::content_vault::SessionHold, (StatusCode, &'static str)> {
    let live = wb
        .library
        .projects
        .get(project)
        .is_some_and(|record| record.op == RecordOp::Upsert);
    let Some(bearer) = crate::net_http::bearer(headers) else {
        if !wb.desktop_account_mode() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "authenticate the fixture resource owner",
            ));
        }
        if !live || !wb.project_visibility(None).allows(project) {
            return Err((
                StatusCode::FORBIDDEN,
                "fixture caller does not own this project",
            ));
        }
        return wb.hold_for_session(project).ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "fixture project custody unavailable",
        ));
    };
    let context = wb.authenticate_action_context(bearer).ok_or((
        StatusCode::UNAUTHORIZED,
        "authenticate the fixture resource owner",
    ))?;
    crate::identity::revalidate_workflow_context(wb.store_ref(), wb.home_id(), &context)
        .map_err(|_| (StatusCode::FORBIDDEN, "fixture owner standing unavailable"))?;
    let org = crate::org::Org::rebuild(wb.store_ref())
        .map_err(|_| (StatusCode::FORBIDDEN, "fixture owner standing unavailable"))?;
    if context.actor() != wb.authority()
        || org.role_of(context.actor().as_str()) != Some(gaugedesk_core::abac::Role::new("owner"))
        || !live
        || !wb.project_visibility(Some(bearer)).allows(project)
    {
        return Err((
            StatusCode::FORBIDDEN,
            "fixture caller does not own this project",
        ));
    }
    wb.hold_for_session(project).ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "fixture project custody unavailable",
    ))
}

/// Seed `export-contract`: a local chat whose `deliverable.txt` is minted as an
/// output resource with its export proposed, so the desktop picker can supply
/// target admission and perform the real crossing. The deliverable's edit
/// record, the output resource and its export proposal are protected chat
/// content (SECAUD-9), so they are written only under
/// [`reset_fixture_session`]'s hold, as a request that produced them would be.
#[cfg(debug_assertions)]
fn seed_exportable_output(
    fresh: &mut Workbench,
    headers: &HeaderMap,
) -> Result<(), Box<axum::response::Response>> {
    fn refuse(message: impl Into<String>) -> Box<axum::response::Response> {
        Box::new((StatusCode::INTERNAL_SERVER_ERROR, message.into()).into_response())
    }
    let chat = "export-contract";
    fresh
        .create_default_engagement(chat.to_owned(), "Export contract".to_owned())
        .map_err(|_| refuse("test export chat could not be created"))?;
    let project = fresh
        .library
        .project_of_chat(chat)
        .map(str::to_owned)
        .ok_or_else(|| refuse("test export project missing"))?;
    let _session = reset_fixture_session(fresh, headers, &project)
        .map_err(|refusal| Box::new(refusal.into_response()))?;
    fresh
        .write_engagement_file(chat, "deliverable.txt", "desktop export proof\n")
        .ok_or_else(|| refuse("test export engagement disappeared"))?
        .map_err(|error| refuse(format!("test export file: {error}")))?;
    let authority = fresh.authority().as_str().to_owned();
    let output =
        crate::resource_store::mint_output(fresh.store_mut(), chat, &authority, "test-fixture")
            .map_err(|error| refuse(format!("test output resource: {error:?}")))?;
    fresh
        .admit_resource_export(chat, &output.resource.id)
        .map_err(|error| refuse(format!("test output export proposal: {error:?}")))?
        .ok_or_else(|| refuse("test output resource disappeared"))?;
    Ok(())
}

#[cfg(test)]
mod reset_fixture_session_tests {
    use super::*;
    use gaugedesk_core::abac::AuthorityAttributes;
    use gaugedesk_core::ids::AuthorityId;

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {token}").parse().expect("test bearer"),
        );
        headers
    }

    #[test]
    fn fixture_session_requires_current_resource_owner_and_live_project() {
        let root = tempfile::tempdir().expect("fixture root");
        let shared = crate::open_workbench(root.path()).expect("open fixture workbench");
        let mut wb = shared.lock_unpoisoned();
        let owner = wb.authority().clone();
        let idp = crate::identity::LoopbackIdentityProvider::new()
            .enroll("owner-token", owner.clone(), AuthorityAttributes::default())
            .enroll(
                "other-token",
                AuthorityId::new("other"),
                AuthorityAttributes::default(),
            );
        wb.set_identity_provider(Some(std::sync::Arc::new(idp)));
        let project = crate::DEFAULT_PROJECT;
        assert_eq!(
            reset_fixture_session(&wb, &HeaderMap::new(), project)
                .map(|_| ())
                .expect_err("anonymous refusal")
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            reset_fixture_session(&wb, &bearer("unknown"), project)
                .map(|_| ())
                .expect_err("unknown bearer refusal")
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            reset_fixture_session(&wb, &bearer("other-token"), project)
                .map(|_| ())
                .expect_err("wrong owner refusal")
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            reset_fixture_session(&wb, &bearer("owner-token"), project)
                .map(|_| ())
                .expect_err("missing active standing refusal")
                .0,
            StatusCode::FORBIDDEN
        );
        let member = crate::org::MembershipRecord {
            id: owner.to_string(),
            op: crate::org::RecordOp::Upsert,
            org_id: crate::org::ORG_ID.to_owned(),
            authority: owner.to_string(),
            email: String::new(),
            role: "owner".to_owned(),
            status: crate::org::MembershipStatus::Active,
            managed_by_scim: false,
            team: None,
        };
        wb.store_mut()
            .append_record(
                crate::org::ORG_SCOPE,
                "membership",
                &serde_json::to_string(&member).expect("owner record"),
            )
            .expect("admit fixture owner");
        assert_eq!(
            reset_fixture_session(&wb, &bearer("owner-token"), "missing-project")
                .map(|_| ())
                .expect_err("missing project refusal")
                .0,
            StatusCode::FORBIDDEN
        );
        let session = reset_fixture_session(&wb, &bearer("owner-token"), project)
            .expect("current owner project session");
        drop(session);
    }

    #[test]
    fn local_channel_holds_only_its_own_live_project() {
        let root = tempfile::tempdir().expect("fixture root");
        let shared = crate::open_workbench(root.path()).expect("open fixture workbench");
        let wb = shared.lock_unpoisoned();
        assert!(wb.desktop_account_mode(), "fixture is a local Project Host");
        assert_eq!(
            reset_fixture_session(&wb, &HeaderMap::new(), "missing-project")
                .map(|_| ())
                .expect_err("missing project refusal")
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            reset_fixture_session(&wb, &bearer("unknown"), crate::DEFAULT_PROJECT)
                .map(|_| ())
                .expect_err("a presented credential is never the local channel")
                .0,
            StatusCode::UNAUTHORIZED
        );
        let session = reset_fixture_session(&wb, &HeaderMap::new(), crate::DEFAULT_PROJECT)
            .expect("local operator project session");
        drop(session);
    }

    #[test]
    fn exportable_output_seed_writes_its_protected_content_under_the_owner_session() {
        use gaugedesk_core::resource::ResourceId;
        use gaugedesk_core::resource_export::ExportPhase;

        let root = tempfile::tempdir().expect("fixture root");
        let shared = crate::open_workbench(root.path()).expect("open fixture workbench");
        let mut wb = shared.lock_unpoisoned();
        let refused = seed_exportable_output(&mut wb, &bearer("unknown"))
            .expect_err("a presented credential that names no owner writes nothing");
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        assert!(
            crate::resource_store::get(
                wb.store_ref(),
                "export-contract",
                &ResourceId::new("out-export-contract"),
            )
            .expect("read refused seed")
            .is_none(),
            "a refused seed mints no output"
        );

        let root = tempfile::tempdir().expect("fixture root");
        let shared = crate::open_workbench(root.path()).expect("open fixture workbench");
        let mut wb = shared.lock_unpoisoned();
        seed_exportable_output(&mut wb, &HeaderMap::new())
            .expect("the local operator seeds the export contract under its session");
        let output = ResourceId::new("out-export-contract");
        assert!(
            crate::resource_store::get(wb.store_ref(), "export-contract", &output)
                .expect("read seeded output")
                .is_some()
        );
        assert_eq!(
            wb.resource_export_state("export-contract", &output)
                .expect("fold seeded export")
                .phase,
            ExportPhase::Requested
        );
    }
}

#[cfg(debug_assertions)]
#[derive(serde::Deserialize)]
pub(crate) struct ForceConflictBody {
    #[serde(default)]
    on: bool,
}

/// Remove the debug harness's state root for a reset.
///
/// A thread the previous scenario started can still be finishing a write
/// into the root while it is removed — on Linux the browser suite met
/// `Directory not empty` here about once a run (WS-871) — so a removal that
/// loses that race is retried briefly before the reset is refused.
#[cfg(debug_assertions)]
fn wipe_state_root(root: &std::path::Path) -> std::io::Result<()> {
    let mut attempt = 0;
    loop {
        match std::fs::remove_dir_all(root) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty && attempt < 20 => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => return Err(error),
        }
    }
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

/// `POST /test/desktop-home-session`: the Home session the desktop shell hands
/// its own window over IPC once someone is signed in (DR-0188), for the browser
/// BDD that stands in for the shell. The real handover never crosses HTTP; this
/// exists only in debug builds, behind `GAUGEDESK_TEST_RESET`, so the suite can
/// drive the window a signed-in desktop actually has — one presenting an
/// account session to its control plane from another origin. That window's
/// preflights were refused in 0.8.7 and its first chat never started, while the
/// suite drove only the signed-out window, whose preflights pass (WS-871).
pub(crate) async fn post_test_desktop_home_session(
    State(wb): State<SharedWorkbench>,
) -> impl IntoResponse {
    if gaugedesk_env::var("TEST_RESET").is_none() {
        return (
            StatusCode::FORBIDDEN,
            "desktop home session fixture is disabled",
        )
            .into_response();
    }
    let token = tokio::task::spawn_blocking(move || crate::desktop_session::home_session(&wb))
        .await
        .ok()
        .flatten();
    (StatusCode::OK, Json(serde_json::json!({ "token": token }))).into_response()
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

    /// A turn someone stopped is not a turn that broke. It answers `499` so the
    /// composer can tell the two apart — as a `502` it reported the reader's own
    /// Stop back to them as a failure and kept the cancelled message to retry.
    #[test]
    fn a_stopped_turn_is_not_a_gateway_failure() {
        assert_eq!(
            task_failure_status(&EngineError::Interrupted).as_u16(),
            499,
            "a deliberate stop must not answer in the 5xx range"
        );
        assert_eq!(format!("{}", EngineError::Interrupted), "stopped");
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

#[cfg(test)]
mod multi_target_edit_authorization_tests {
    use crate::{open_workbench, LockUnpoisoned, DEFAULT_PLACEMENT, DEFAULT_PROJECT};
    use axum::{
        extract::{Path, State},
        response::IntoResponse,
    };

    #[test]
    fn use_chat_shows_the_frozen_agent_entry_point_as_read_only() {
        let root = tempfile::tempdir().unwrap();
        let workbench = open_workbench(root.path()).unwrap();
        let mut workbench = workbench.lock_unpoisoned();
        let chat = workbench
            .create_default_engagement("agent-view-chat".to_owned(), "Agent view".to_owned())
            .unwrap_or_else(|_| panic!("create Agent work chat"));
        let entries = workbench.engagement_tree(&chat.id).unwrap().unwrap();
        assert!(entries.iter().any(|entry| entry.path == "agent/AGENTS.md"));
        assert!(entries.iter().any(|entry| entry.path == "agent/HUMANS.md"));
        assert!(entries
            .iter()
            .any(|entry| entry.path == "agent/skills" && entry.is_dir));
        assert!(!entries
            .iter()
            .any(|entry| entry.path == "agent/method.whip"));
        assert!(workbench
            .read_engagement_file(&chat.id, "agent/AGENTS.md")
            .unwrap()
            .unwrap()
            .contains("Agent conventions"));
        assert!(workbench
            .authorize_file_edit(&chat.id, "agent/AGENTS.md")
            .is_err());
    }

    #[test]
    fn account_backed_use_chat_cannot_read_installed_method_through_file_aliases() {
        let root = tempfile::tempdir().unwrap();
        let workbench = open_workbench(root.path()).unwrap();
        let mut workbench = workbench.lock_unpoisoned();
        let chat = workbench
            .create_default_engagement("method-read-chat".to_owned(), "Method read".to_owned())
            .unwrap_or_else(|_| panic!("create Agent work chat"));
        assert!(workbench
            .read_engagement_file_bytes(&chat.id, "agent/AGENTS.md", 1024 * 1024)
            .unwrap()
            .unwrap()
            .is_some());

        workbench.set_identity_provider(Some(std::sync::Arc::new(
            crate::identity::LoopbackIdentityProvider::new(),
        )));
        for path in [
            "agent/AGENTS.md",
            "./agent/AGENTS.md",
            ".gaugedesk-runtime/agent/AGENTS.md",
            "./.gaugedesk-runtime/agent/AGENTS.md",
            "agent/skills",
        ] {
            assert!(workbench.installed_method_read_requires_grant(&chat.id, path));
            assert!(workbench
                .read_engagement_file_bytes(&chat.id, path, 1024 * 1024)
                .unwrap()
                .is_err());
            assert!(workbench
                .read_engagement_file(&chat.id, path)
                .unwrap()
                .is_err());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let worktree = workbench.engagements.get(&chat.id).unwrap().path();
            let method = worktree.join(".gaugedesk-runtime/agent/AGENTS.md");
            let agent_dir = worktree.join(".gaugedesk-runtime/agent");
            symlink(&method, worktree.join("work/method-link.md")).unwrap();
            symlink(&agent_dir, worktree.join("work/agent-link")).unwrap();
            for path in ["work/method-link.md", "work/agent-link/AGENTS.md"] {
                assert!(workbench
                    .read_engagement_file_bytes(&chat.id, path, 1024 * 1024)
                    .unwrap()
                    .is_err());
                assert!(workbench
                    .read_engagement_file(&chat.id, path)
                    .unwrap()
                    .is_err());
            }
        }
        assert!(!workbench.installed_method_read_requires_grant(&chat.id, "work/notes.md"));
    }

    #[tokio::test]
    async fn account_backed_tree_omits_installed_method_paths() {
        use gaugedesk_core::{abac::AuthorityAttributes, ids::AuthorityId};
        let root = tempfile::tempdir().unwrap();
        let workbench = open_workbench(root.path()).unwrap();
        let chat_id = {
            let mut workbench = workbench.lock_unpoisoned();
            let chat = workbench
                .create_default_engagement("method-tree-chat".to_owned(), "Method tree".to_owned())
                .unwrap_or_else(|_| panic!("create Agent work chat"));
            let mut owned = workbench.library.chats.get(&chat.id).unwrap().clone();
            owned.owner = Some("alice".into());
            workbench.write_chat_record(owned);
            let idp = crate::identity::LoopbackIdentityProvider::new().enroll(
                "alice-token",
                AuthorityId::new("alice"),
                AuthorityAttributes::default(),
            );
            workbench.set_identity_provider(Some(std::sync::Arc::new(idp)));
            chat.id
        };
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer alice-token".parse().unwrap(),
        );
        let response = super::get_tree(State(workbench), Path(chat_id), headers)
            .await
            .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["files"].as_array().unwrap().iter().all(|entry| {
            let path = entry["path"].as_str().unwrap();
            !path.starts_with("agent/") && !path.starts_with(".gaugedesk-runtime/agent/")
        }));
    }

    #[test]
    fn editor_resolves_one_target_root_and_refuses_read_only_members() {
        let root = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        std::fs::write(external.path().join("reference.txt"), "reference\n").unwrap();
        let workbench = open_workbench(root.path()).unwrap();
        let mut workbench = workbench.lock_unpoisoned();
        let default_target =
            workbench.library.placement_targets[DEFAULT_PLACEMENT].target_ids[0].clone();
        let reference = workbench
            .attach_external_target(
                DEFAULT_PROJECT,
                crate::target_adapter::AttachTargetBody {
                    name: "Reference".to_owned(),
                    kind: crate::library::WorkTargetKind::ExternalFolder,
                    path: external.path().to_path_buf(),
                    path_scope: vec![".".to_owned()],
                },
            )
            .unwrap();
        let chat = workbench
            .create_chat_in_instance_on_targets(
                DEFAULT_PLACEMENT,
                "two roots",
                &[default_target.clone(), reference.id.clone()],
            )
            .unwrap();
        let chat_id = chat["id"].as_str().unwrap();
        workbench
            .revise_chat_targets(
                chat_id,
                &[
                    (
                        default_target.clone(),
                        crate::library::TargetParticipationMode::Writable,
                    ),
                    (
                        reference.id.clone(),
                        crate::library::TargetParticipationMode::ReadOnly,
                    ),
                ],
            )
            .unwrap();
        let default_root = crate::library::target_id_path_v1(&default_target).unwrap();
        let reference_root = crate::library::target_id_path_v1(&reference.id).unwrap();
        assert!(workbench
            .authorize_file_edit(chat_id, &format!("targets/{default_root}/new.txt"))
            .is_ok());
        assert_eq!(
            workbench
                .authorize_file_edit(chat_id, &format!("targets/{reference_root}/reference.txt")),
            Err("the selected chat target is read-only")
        );
        assert_eq!(
            workbench.authorize_file_edit(chat_id, "unrooted.txt"),
            Err("a multi-target edit must name one selected target root")
        );
        assert!(workbench
            .authorize_file_edit(chat_id, "artifacts/report.md")
            .is_ok());
        assert!(workbench
            .authorize_file_edit(chat_id, "work/notes.md")
            .is_ok());
        assert_eq!(
            workbench.engagement_workspace_path(chat_id, "artifacts/report.md"),
            "artifacts/report.md"
        );
        workbench
            .write_engagement_file(chat_id, "artifacts/report.md", "report")
            .unwrap()
            .unwrap();
        assert!(workbench.engagements[chat_id]
            .diff_against_main()
            .unwrap()
            .is_empty());
    }
}

#[cfg(test)]
mod live_stream_backpressure_tests {
    //! SCALE-4: a subscriber that falls more than `LIVE_STREAM_SLOTS` events
    //! behind has its stream closed, so the client reconnects and refetches
    //! its snapshot instead of rendering a transcript with a hole in it.
    use crate::stream::{ServerEvent, LIVE_STREAM_SLOTS};
    use crate::{open_workbench, LockUnpoisoned};
    use axum::{
        body::Body,
        extract::{Path, State},
        http::HeaderMap,
    };
    use http_body_util::BodyExt;
    use std::time::Duration;

    fn user(n: usize) -> ServerEvent {
        ServerEvent::User {
            text: format!("event {n}"),
            client_request_id: None,
            chat_id: None,
            home_id: None,
            actor_id: None,
        }
    }

    fn workspace(n: usize) -> ServerEvent {
        ServerEvent::WorkspaceChanged {
            record: "chat".into(),
            id: format!("chat-{n}"),
            op: "upsert".into(),
        }
    }

    /// The next data frame, `None` when the stream has ended, or a panic when
    /// nothing arrives (an open stream with nothing to say).
    async fn next(body: &mut Body) -> Option<String> {
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(3), body.frame())
                .await
                .expect("stream neither delivered nor closed")?;
            let data = frame.unwrap().into_data().unwrap();
            let text = String::from_utf8(data.to_vec()).unwrap();
            if text.contains("data:") {
                return Some(text);
            }
        }
    }

    async fn still_open(body: &mut Body) -> bool {
        tokio::time::timeout(Duration::from_millis(200), body.frame())
            .await
            .is_err()
    }

    #[tokio::test]
    async fn a_slow_engagement_subscriber_is_closed_on_overflow() {
        let root = tempfile::tempdir().unwrap();
        let wb = open_workbench(root.path()).unwrap();
        let response = super::engagement_events(
            State(wb.clone()),
            Path("chat-slow".to_owned()),
            HeaderMap::new(),
            None,
        )
        .await;
        let mut body = response.into_body();
        let sender = wb.lock_unpoisoned().sender("chat-slow");
        for n in 0..LIVE_STREAM_SLOTS + 8 {
            sender.send(user(n)).unwrap();
        }
        assert_eq!(
            next(&mut body).await,
            None,
            "an overflowed subscriber must be closed, not continued with a gap"
        );
    }

    #[tokio::test]
    async fn an_engagement_subscriber_within_the_bound_keeps_its_stream() {
        let root = tempfile::tempdir().unwrap();
        let wb = open_workbench(root.path()).unwrap();
        let response = super::engagement_events(
            State(wb.clone()),
            Path("chat-ok".to_owned()),
            HeaderMap::new(),
            None,
        )
        .await;
        let mut body = response.into_body();
        let sender = wb.lock_unpoisoned().sender("chat-ok");
        for n in 0..LIVE_STREAM_SLOTS {
            sender.send(user(n)).unwrap();
        }
        for n in 0..LIVE_STREAM_SLOTS {
            let frame = next(&mut body).await.expect("event delivered");
            assert!(frame.contains(&format!("event {n}\"")), "{frame}");
        }
        assert!(still_open(&mut body).await);
    }

    #[tokio::test]
    async fn a_slow_workspace_subscriber_is_closed_on_overflow() {
        let root = tempfile::tempdir().unwrap();
        let wb = open_workbench(root.path()).unwrap();
        let response = super::workspace_events(State(wb.clone()), HeaderMap::new(), None).await;
        let mut body = response.into_body();
        let sender = wb.lock_unpoisoned().workspace_sender();
        sender.send(workspace(0)).unwrap();
        assert!(next(&mut body)
            .await
            .expect("change delivered")
            .contains("chat-0"));
        for n in 0..LIVE_STREAM_SLOTS + 8 {
            sender.send(workspace(n)).unwrap();
        }
        assert_eq!(next(&mut body).await, None);
    }
}
