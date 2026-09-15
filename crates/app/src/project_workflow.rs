//! Project-owned workflow custody shared by launch and authority relocation.

/// The native runtime/tracker/coordination/input plane uses one project-owned
/// key. Workspace identity remains authenticated separately by its owner API.
pub(crate) fn content_scope(project: &str) -> std::io::Result<String> {
    if project.is_empty() || project.contains("::") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid workflow project identity",
        ));
    }
    Ok(format!("project::{project}::workflow"))
}

use crate::{
    action_inputs::NativeActionInputCustody, identity::AuthenticatedActionContext, Workbench,
};
use gaugedesk_whip_runtime::host_actions::{action::*, CompiledHostAction, ProductActionAdmission};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[path = "project_workflow_authority.rs"]
mod authority;
#[path = "project_workflow_launch.rs"]
mod launch;

fn debug_error(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

/// Caller intent only. The Home derives authority, storage and resource labels.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectWorkflowLaunch {
    pub project: String,
    pub target: String,
    pub path: String,
    pub cut: String,
    pub request_id: String,
    pub inputs: BTreeMap<String, serde_json::Value>,
}

/// Trusted host budgets; the public request cannot increase these limits.
#[derive(Clone, Copy)]
pub struct ProjectWorkflowLimits {
    pub source_bytes: usize,
    pub input_bytes: usize,
}

/// Admission evidence, not completion or an authority grant.
#[derive(Clone, Debug, Serialize)]
pub struct ProjectWorkflowInvocation {
    pub project: String,
    pub workspace: String,
    pub product_scope: String,
    pub command: HostActionCommand,
    pub admission: ActionAdmissionReceipt,
}

fn request_scope(project: &str, actor: &str, request: &str) -> Result<String, String> {
    content_scope(project).map_err(debug_error)?;
    if actor.trim().is_empty() || request.trim().is_empty() {
        return Err("workflow request identity is empty".into());
    }
    Ok(format!(
        "project::{project}::workflow-launch::{}::{}",
        hex::encode(actor),
        hex::encode(request)
    ))
}

#[cfg(test)]
#[path = "project_workflow_tests.rs"]
mod tests;

/// One bounded execution result; workflow status and evidence remain native.
#[derive(Clone, Debug, Serialize)]
pub struct ProjectWorkflowStep {
    pub executed_effect: Option<String>,
    pub recovered_effect: Option<String>,
    pub snapshot: gaugedesk_whip_runtime::host_actions::action_result::ActionResultSnapshot,
}
