//! Running a `.whip` file from the chat it is open in (WHIP-3's Run control).
//!
//! A chat sees files through its target selection; a launch needs a project,
//! a target, a path inside that target and a revision on the target's Main.
//! This resolves the first into the second the way native file actions do,
//! and always at Main: the workspace admits only a revision in Main's history,
//! so what runs is the file as kept, never a chat's unkept edit. Describing
//! and launching then go through the ordinary launch authority unchanged.
use super::*;
use crate::library::InstanceKind;

/// Where a chat's `.whip` file lives, as a launch names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChatWorkflowSource {
    pub project: String,
    pub target: String,
    pub path: String,
    /// Main's head on that target: the revision a Run from this chat launches.
    pub cut: String,
}

impl Workbench {
    /// Resolve a chat-relative `.whip` path to its project, target, in-target
    /// path and Main head. Grants nothing; the launch re-checks all of it.
    pub(crate) fn chat_workflow_source(
        &self,
        chat_id: &str,
        path: &str,
    ) -> Result<ChatWorkflowSource, String> {
        if !path.ends_with(".whip") {
            return Err("only a .whip file can be run".into());
        }
        let chat = self
            .library
            .chats
            .get(chat_id)
            .ok_or("chat is unavailable")?;
        let instance = self
            .library
            .instances
            .get(&chat.instance_id)
            .ok_or("chat placement is unavailable")?;
        let project = instance
            .project_id
            .clone()
            .filter(|_| instance.kind == InstanceKind::Using)
            .ok_or("only a project chat can run a workflow")?;
        let set = self
            .library
            .current_target_set(chat_id)
            .ok_or("chat has no committed target selection")?;
        let (target, relative) = if let Some(rooted) = path.strip_prefix("targets/") {
            let (encoded, relative) = rooted
                .split_once('/')
                .ok_or("target-relative file path is missing")?;
            let member = set
                .members
                .iter()
                .find(|member| {
                    crate::library::target_id_path_v1(&member.target_id)
                        .is_ok_and(|id| id == encoded)
                })
                .ok_or("file target is not selected")?;
            (member.target_id.clone(), relative.to_owned())
        } else if let [member] = set.members.as_slice() {
            (member.target_id.clone(), path.to_owned())
        } else {
            return Err("a multi-target chat must name the file's target".into());
        };
        let cut = self
            .targets
            .get(&target)
            .ok_or("file target is unavailable")?
            .current_main_cut()
            .map_err(debug_error)?
            .ok_or("the file's target has no kept revision yet")?;
        Ok(ChatWorkflowSource {
            project,
            target,
            path: relative,
            cut,
        })
    }

    /// The inputs the kept version of a workflow declares, under the same
    /// authority a launch of it would need: whoever may not run it may not
    /// read its declaration through here either.
    pub(crate) fn describe_project_workflow(
        &self,
        context: &AuthenticatedActionContext,
        source: &ChatWorkflowSource,
        limits: ProjectWorkflowLimits,
    ) -> Result<serde_json::Value, String> {
        let request = ProjectWorkflowLaunch {
            project: source.project.clone(),
            target: source.target.clone(),
            path: source.path.clone(),
            cut: source.cut.clone(),
            request_id: "describe".into(),
            inputs: BTreeMap::new(),
        };
        self.prepare_workflow_authority(context, &request)?;
        let text = self
            .targets
            .get(&source.target)
            .ok_or("file target is unavailable")?
            .workflow_source(&source.path, &source.cut, limits.source_bytes)
            .map_err(debug_error)?
            .content;
        gaugedesk_whip_runtime::workflow_inputs(&text)
            .ok_or_else(|| "the kept version of this file does not compile".into())
    }
}
