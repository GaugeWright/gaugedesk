//! The runs of a chat's `.whip` files: what the Run button's status, a file's
//! status dot and its Runs history show (WHIP-3).
//!
//! A run is found by its retained launch command, whose source binding names
//! the target and path it was launched from, and its state is read from the
//! native instance without stepping it. A run of a project's Home-owned files
//! is the project's, so everyone with access to the project sees it
//! (DR-0199); a run of a person's own files is shown only to whoever launched
//! it.
use super::*;
use crate::library::InstanceKind;
use gaugedesk_whip_runtime::host_actions::RuntimeStore;
use std::num::NonZeroUsize;

/// One run of one file, as a chat shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChatWhipRun {
    /// The file, as the chat names it: `targets/<target>/<path>`.
    pub path: String,
    pub request_id: String,
    pub launched_by: String,
    /// Whether the person asking launched it.
    pub by_you: bool,
    /// `running`, `waiting` (running, and parked until a task it filed is
    /// closed), `completed`, `failed`, `cancelled`, or `unknown` when the
    /// native instance cannot be read.
    pub state: String,
    /// Whether the person asking may stop it: whoever launched it, or an owner
    /// or admin of this Home — and only while it has not finished.
    pub can_stop: bool,
    /// When the native instance was created, as the runtime records it.
    pub started_at: Option<String>,
    /// The kept revision it runs; later edits to the file never reach it.
    pub cut: String,
    /// Its firings, projected as the Instances view projects any run — only
    /// when one file's runs were asked for, since it reads each run's history.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view: Option<serde_json::Value>,
}

const DISCOVERY_PAGE: NonZeroUsize = match NonZeroUsize::new(256) {
    Some(size) => size,
    None => unreachable!(),
};

impl Workbench {
    /// Every run launched from a `.whip` file this chat can see, newest first,
    /// optionally only those of `path`. Reads; steps and grants nothing.
    pub(crate) fn chat_whip_runs(
        &self,
        context: &AuthenticatedActionContext,
        chat_id: &str,
        path: Option<&str>,
    ) -> Result<Vec<ChatWhipRun>, String> {
        if matches!(
            context.authentication(),
            crate::identity::ActorAuthentication::ProjectWorkflowInvocation { .. }
        ) {
            return Err("workflow authority cannot list runs".into());
        }
        crate::identity::revalidate_workflow_context(self.store_ref(), self.home_id(), context)
            .map_err(debug_error)?;
        let chat = self
            .library
            .chats
            .get(chat_id)
            .ok_or("chat is unavailable")?;
        let project = self
            .library
            .instances
            .get(&chat.instance_id)
            .filter(|instance| instance.kind == InstanceKind::Using)
            .and_then(|instance| instance.project_id.clone())
            .ok_or("only a project chat has runs")?;
        let actor = context.actor().as_str();
        let org = crate::org::Org::rebuild(self.store_ref()).map_err(debug_error)?;
        if !org.can_access_project(actor, &project) {
            return Err("runs exceed current project authority".into());
        }
        let only = path
            .map(|path| {
                self.chat_workflow_source(chat_id, path)
                    .map(|source| (source.target, source.path))
            })
            .transpose()?;
        let targets: BTreeMap<String, String> = self
            .library
            .current_target_set(chat_id)
            .ok_or("chat has no committed target selection")?
            .members
            .iter()
            .filter_map(|member| {
                crate::library::target_id_path_v1(&member.target_id)
                    .ok()
                    .map(|encoded| (member.target_id.clone(), encoded))
            })
            .collect();
        let workspace = self
            .library
            .project_collaboration_workspaces
            .get(&project)
            .map(|workspace| workspace.workspace_id.clone());
        let runtime = workspace.as_deref().and_then(|workspace| {
            let key = self.workflow_key(&project, workspace, false).ok()?;
            let protection = gaugedesk_workspace::WorkflowProtection::new(workspace, key).ok()?;
            self.workflow_storage(workspace)
                .ok()?
                .open_existing_protected(&protection)
                .ok()
                .map(|stores| stores.runtime.into_parts().0)
        });

        let mut runs = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = self
                .store_ref()
                .scope_ids_with_kind(
                    super::supervisor::ADMISSION_KIND,
                    after.as_deref(),
                    DISCOVERY_PAGE,
                )
                .map_err(debug_error)?;
            let Some(last) = page.last().cloned() else {
                break;
            };
            for scope in page {
                let Some((owner, launcher, request_id)) = launch_scope_parts(&scope) else {
                    continue;
                };
                if owner != project {
                    continue;
                }
                let Some(command) = self
                    .store_ref()
                    .fold::<ProductActionAdmission>(&scope)
                    .map_err(debug_error)?
                    .command
                else {
                    continue;
                };
                let Ok(binding) = super::launch::source_binding(&command) else {
                    continue;
                };
                let Some(encoded) = targets.get(&binding.target) else {
                    continue;
                };
                if only.as_ref().is_some_and(|(target, path)| {
                    target != &binding.target || path != &binding.path
                }) {
                    continue;
                }
                let shared = self
                    .library
                    .work_targets
                    .get(&binding.target)
                    .is_some_and(|target| target.authority == self.home_id().as_str());
                if launcher != actor && !shared {
                    continue;
                }
                let instance_ref = command.instance_ref().ok();
                let instance = runtime.as_ref().zip(instance_ref.as_deref()).and_then(
                    |(runtime, instance_ref)| runtime.get_instance(instance_ref).ok().flatten(),
                );
                let state = match instance.as_ref().map(|instance| instance.status.as_str()) {
                    Some("running")
                        if runtime.as_ref().zip(instance_ref.as_deref()).is_some_and(
                            |(runtime, instance_ref)| waiting_on_a_task(runtime, instance_ref),
                        ) =>
                    {
                        "waiting".to_owned()
                    }
                    Some(status) => status.to_owned(),
                    None => "unknown".to_owned(),
                };
                let live = matches!(state.as_str(), "running" | "waiting");
                runs.push(ChatWhipRun {
                    can_stop: live && may_stop(&org, actor, &launcher),
                    path: format!("targets/{encoded}/{}", binding.path),
                    request_id,
                    by_you: launcher == actor,
                    launched_by: launcher,
                    state,
                    started_at: instance.map(|instance| instance.created_at),
                    cut: binding.cut,
                    view: only.as_ref().and_then(|_| {
                        runtime.as_ref().zip(instance_ref.as_deref()).and_then(
                            |(runtime, instance_ref)| {
                                gaugedesk_whip_runtime::instance_view_in(runtime, instance_ref)
                            },
                        )
                    }),
                });
            }
            after = Some(last);
        }
        runs.sort_by(|left, right| right.started_at.cmp(&left.started_at));
        Ok(runs)
    }
}

/// A run is parked on a task when its pending effect is the closure wait a
/// `tracker.wait_closed` call leaves queued until the issue closes.
fn waiting_on_a_task(runtime: &impl RuntimeStore, instance: &str) -> bool {
    runtime.list_effects(instance).is_ok_and(|effects| {
        effects.iter().any(|effect| {
            effect.kind == "capability.call"
                && effect.target.as_deref() == Some("tracker.wait_closed")
                && !matches!(effect.status.as_str(), "completed" | "failed" | "cancelled")
        })
    })
}

/// Who may stop a run: whoever launched it, or an owner or admin of this Home.
fn may_stop(org: &crate::org::Org, actor: &str, launcher: &str) -> bool {
    actor == launcher
        || org.role_of(actor).is_some_and(|role| {
            role == gaugedesk_core::abac::Role::owner()
                || role == gaugedesk_core::abac::Role::admin()
        })
}

impl Workbench {
    /// Stop one run of a chat's `.whip` file (WHIP-3). The run must be one this
    /// person can see from this chat and may stop; stopping cancels its native
    /// instance, which releases what it holds. Tasks it already filed stay in
    /// their tracker. Stopping a run that already finished changes nothing.
    pub(crate) fn stop_chat_whip_run(
        &mut self,
        context: &AuthenticatedActionContext,
        chat_id: &str,
        path: &str,
        launched_by: &str,
        request_id: &str,
        key: &str,
    ) -> Result<ChatWhipRun, String> {
        let find = |wb: &Self| -> Result<ChatWhipRun, String> {
            wb.chat_whip_runs(context, chat_id, Some(path))?
                .into_iter()
                .find(|run| run.launched_by == launched_by && run.request_id == request_id)
                .ok_or_else(|| "no such run of this file".to_owned())
        };
        let run = find(self)?;
        if !matches!(run.state.as_str(), "running" | "waiting") {
            return Ok(run);
        }
        if !run.can_stop {
            return Err("only its launcher or a Home admin may stop a run".into());
        }
        let project = self.chat_workflow_source(chat_id, path)?.project;
        crate::federation::require_project_writes_available(self.store_ref(), &project)
            .map_err(debug_error)?;
        let scope = request_scope(&project, launched_by, request_id)?;
        let command = self
            .store_ref()
            .fold::<ProductActionAdmission>(&scope)
            .map_err(debug_error)?
            .command
            .ok_or("workflow invocation is unavailable")?;
        let instance = command.instance_ref().map_err(debug_error)?;
        let workspace = self
            .library
            .project_collaboration_workspaces
            .get(&project)
            .map(|workspace| workspace.workspace_id.clone())
            .ok_or("workflow workspace is unavailable")?;
        let key_ref = self.workflow_key(&project, &workspace, false)?;
        let protection = gaugedesk_workspace::WorkflowProtection::new(&workspace, key_ref.clone())
            .map_err(debug_error)?;
        let storage = self.workflow_storage(&workspace)?;
        let reason = format!("stopped by {}", context.actor().as_str());
        key_ref
            .retain(|| -> std::io::Result<_> {
                let stores = storage
                    .open_existing_protected(&protection)
                    .map_err(|error| std::io::Error::other(debug_error(error)))?;
                let mut kernel = whipplescript_kernel::RuntimeKernel::new(stores.runtime);
                kernel
                    .cancel_instance(&instance, Some(&reason), Some(key))
                    .map(|_| ())
                    .map_err(|error| std::io::Error::other(debug_error(error)))
            })
            .map_err(debug_error)?;
        self.hint_project_workflows(scope);
        self.notify_library_changed("project_tracker", &project, "upsert");
        find(self)
    }
}
