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
    /// `running`, `completed`, `failed`, `cancelled`, or `unknown` when the
    /// native instance cannot be read.
    pub state: String,
    /// When the native instance was created, as the runtime records it.
    pub started_at: Option<String>,
    /// The kept revision it runs; later edits to the file never reach it.
    pub cut: String,
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
                .map(|stores| stores.runtime)
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
                let instance = runtime.as_ref().and_then(|runtime| {
                    runtime
                        .get_instance(&command.instance_ref().ok()?)
                        .ok()
                        .flatten()
                });
                runs.push(ChatWhipRun {
                    path: format!("targets/{encoded}/{}", binding.path),
                    request_id,
                    by_you: launcher == actor,
                    launched_by: launcher,
                    state: instance
                        .as_ref()
                        .map(|instance| instance.status.clone())
                        .unwrap_or_else(|| "unknown".into()),
                    started_at: instance.map(|instance| instance.created_at),
                    cut: binding.cut,
                });
            }
            after = Some(last);
        }
        runs.sort_by(|left, right| right.started_at.cmp(&left.started_at));
        Ok(runs)
    }
}
