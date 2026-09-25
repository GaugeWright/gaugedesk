//! Release-maintained tutorials in a separate project for each learner (DR-0225).
//! The release is the publisher; the serving Home still orders project facts.

use crate::{
    home_owner::{HomeOwnerClaim, CLAIM_KIND},
    library::{
        ProjectCollaborationWorkspaceRecord, ProjectRecord, RecordOp, TargetCapabilities,
        WorkTargetOwner, LIBRARY_RECORD_SCHEMA,
    },
    org::{MemberGrantRecord, MembershipStatus, Org, ORG_SCOPE},
    Workbench, DEFAULT_PROJECT,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// The old Personal attachment is retained for runs pinned before DR-0225.
pub const TUTORIALS_TARGET: &str = "target-tutorials";
pub const SHIPPED: &[(&str, &str)] = &[("basics.whip", include_str!("tutorials/basics.whip"))];
const RELEASE_KIND: &str = "shipped_tutorials_release";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShippedRelease {
    target: String,
    cut: String,
    version: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ShippedTutorials {
    NoOwner,
    Current(String),
    Updated(String),
}

/// Stable identities separate learners' workspaces without putting an account
/// authority (which may contain personal data) into a path or projection.
pub fn tutorial_project_id(learner: &str) -> String {
    let digest = sha2::Sha256::digest(learner.as_bytes());
    format!("tutorials-{}", hex::encode(&digest[..16]))
}

pub fn tutorial_target_id(learner: &str) -> String {
    format!("target-{}", tutorial_project_id(learner))
}

pub fn is_tutorial_project(project: &ProjectRecord) -> bool {
    project
        .extra
        .get("product")
        .and_then(|p| p.get("kind"))
        .and_then(|k| k.as_str())
        == Some("tutorials")
}

impl Workbench {
    fn tutorial_learner_admitted(&self, actor: &str, org: &Org) -> bool {
        if org
            .members
            .values()
            .any(|member| member.status == MembershipStatus::Active)
        {
            org.role_of(actor).is_some()
        } else {
            self.home_owner_account().as_deref() == Some(actor)
        }
    }

    pub(crate) fn home_owner_account(&self) -> Option<String> {
        let claimed = self
            .store_ref()
            .records(ORG_SCOPE, CLAIM_KIND)
            .ok()?
            .iter()
            .filter_map(|raw| serde_json::from_str::<HomeOwnerClaim>(raw).ok())
            .find_map(|claim| claim.account);
        if claimed.is_some() {
            return claimed;
        }
        let org = Org::rebuild(self.store_ref()).ok()?;
        let mut owners = org
            .members
            .values()
            .filter(|member| member.status == MembershipStatus::Active && member.role == "owner");
        let owner = owners.next()?;
        owners.next().is_none().then(|| owner.authority.clone())
    }

    /// Install or reconcile one product project for each active learner. An
    /// unclaimed Home creates none. Reconcile is idempotent on every wake.
    pub fn ensure_shipped_tutorials(&mut self) -> Result<ShippedTutorials, String> {
        let org = Org::rebuild(self.store_ref()).map_err(|e| format!("{e:?}"))?;
        let mut learners = org
            .members
            .values()
            .filter(|member| member.status == MembershipStatus::Active)
            .map(|member| member.authority.clone())
            .collect::<Vec<_>>();
        if let Some(owner) = self.home_owner_account() {
            if !learners.contains(&owner) {
                learners.push(owner);
            }
        }
        if learners.is_empty() {
            return Ok(ShippedTutorials::NoOwner);
        }
        let mut result = ShippedTutorials::NoOwner;
        for learner in learners {
            let next = self.ensure_tutorial_project(&learner, &org)?;
            if matches!(next, ShippedTutorials::Updated(_))
                || matches!(result, ShippedTutorials::NoOwner)
            {
                result = next;
            }
        }
        Ok(result)
    }

    fn ensure_tutorial_project(
        &mut self,
        learner: &str,
        org: &Org,
    ) -> Result<ShippedTutorials, String> {
        let project_id = tutorial_project_id(learner);
        let target_id = tutorial_target_id(learner);
        if self.project_moving(&project_id) {
            return Err(crate::federation::PAUSED_FOR_MOVE.into());
        }
        if let Some(existing) = self.library.projects.get(&project_id) {
            if !is_tutorial_project(existing)
                || existing
                    .extra
                    .get("product")
                    .and_then(|p| p.get("learner"))
                    .and_then(|v| v.as_str())
                    != Some(learner)
            {
                return Err("Tutorials project identity is occupied".into());
            }
        } else {
            let mut extra = std::collections::BTreeMap::new();
            extra.insert("product".into(), serde_json::json!({"kind":"tutorials", "publisher":"GaugeWright", "learner":learner}));
            self.write_project_record(ProjectRecord {
                id: project_id.clone(),
                op: RecordOp::Upsert,
                name: "Tutorials".into(),
                is_default: false,
                home_id: self.home_id().clone(),
                network_isolated: false,
                run_purpose: None,
                deployment_mode: None,
                schema: LIBRARY_RECORD_SCHEMA,
                extra,
            });
        }
        if !self.has_project_collaboration_workspace(&project_id) {
            self.write_project_collaboration_workspace_record(
                ProjectCollaborationWorkspaceRecord {
                    project_id: project_id.clone(),
                    workspace_id: format!("project-workspace-{project_id}"),
                    home_id: self.home_id().clone(),
                    substrate: "whipplescript".into(),
                    host_contract_revision: crate::workstream_host_contract::REVISION.into(),
                    host_contract_digest: crate::workstream_host_contract::DIGEST.into(),
                    op: RecordOp::Upsert,
                    schema: LIBRARY_RECORD_SCHEMA,
                    extra: Default::default(),
                },
            );
        }
        self.ensure_project_collaboration_workspace(&project_id)?;
        if org.role_of(learner).is_some()
            && !org
                .grants
                .contains_key(&MemberGrantRecord::make_id(learner, &project_id))
        {
            let grant = MemberGrantRecord {
                id: MemberGrantRecord::make_id(learner, &project_id),
                op: RecordOp::Upsert,
                authority: learner.into(),
                project_id: project_id.clone(),
            };
            self.store_mut()
                .append_record(
                    ORG_SCOPE,
                    "member_grant",
                    &serde_json::to_string(&grant).map_err(|e| e.to_string())?,
                )
                .map_err(|e| format!("{e:?}"))?;
        }
        if !self.targets.contains_key(&target_id) {
            let workspace = self
                .workspace_provider(&target_id)
                .init_at(&self.targets_dir().join(&target_id))
                .map_err(|e| e.to_string())?;
            self.targets.insert(target_id.clone(), workspace);
        }
        let before = self.targets[&target_id]
            .current_main_cut()
            .map_err(|e| e.to_string())?;
        let head = self.targets[&target_id]
            .seed_main_exactly(SHIPPED, "whip")
            .map_err(|e| e.to_string())?
            .0;
        let current = self
            .library
            .work_targets
            .get(&target_id)
            .is_some_and(|target| {
                target.current_basis.as_deref() == Some(head.as_str())
                    && target.owner
                        == WorkTargetOwner::Project {
                            project_id: project_id.clone(),
                        }
                    && target.authority == learner
                    && target.capabilities.read
                    && !target.capabilities.propose
                    && !target.capabilities.apply
            })
            && before.as_deref() == Some(head.as_str());
        if current {
            return Ok(ShippedTutorials::Current(head));
        }
        let mut record = crate::library_state::managed_target_record(
            target_id.clone(),
            "Tutorials files".into(),
            WorkTargetOwner::Project { project_id },
            self.home_id(),
            head.clone(),
        );
        // The learner is the information-flow principal for their tracker;
        // GaugeWright is the source's release publisher, not a Home principal.
        record.authority = learner.into();
        record.parties = vec![learner.into()];
        record.capabilities = TargetCapabilities {
            read: true,
            propose: false,
            apply: false,
            publish: false,
            release: false,
        };
        self.write_work_target_record(record);
        self.store_mut()
            .append_record(
                crate::library::LIBRARY_SCOPE,
                RELEASE_KIND,
                &serde_json::to_string(&ShippedRelease {
                    target: target_id,
                    cut: head.clone(),
                    version: env!("CARGO_PKG_VERSION").into(),
                })
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| format!("{e:?}"))?;
        Ok(ShippedTutorials::Updated(head))
    }
}

pub fn tutorial_request_id(name: &str) -> String {
    format!("shipped-tutorial:{name}")
}

impl Workbench {
    /// Read-only view for the project surface. Source comes from the installed
    /// target head, while progress is derived from the ordinary run and tracker.
    pub fn shipped_tutorial_info(
        &self,
        context: &crate::identity::AuthenticatedActionContext,
        name: &str,
    ) -> Result<serde_json::Value, String> {
        let file = format!("{name}.whip");
        if !SHIPPED.iter().any(|(shipped, _)| *shipped == file) {
            return Err("no such shipped tutorial".into());
        }
        crate::identity::revalidate_workflow_context(self.store_ref(), self.home_id(), context)
            .map_err(|e| format!("{e:?}"))?;
        let actor = context.actor().as_str();
        let org = Org::rebuild(self.store_ref()).map_err(|e| format!("{e:?}"))?;
        if !self.tutorial_learner_admitted(actor, &org) {
            return Err("Tutorials are unavailable to this account".into());
        }
        let project = tutorial_project_id(actor);
        let record = self
            .library
            .projects
            .get(&project)
            .ok_or("Tutorials project is unavailable")?;
        if !is_tutorial_project(record)
            || record
                .extra
                .get("product")
                .and_then(|p| p.get("learner"))
                .and_then(|v| v.as_str())
                != Some(actor)
        {
            return Err("Tutorials project is unavailable".into());
        }
        let target = self
            .targets
            .get(&tutorial_target_id(actor))
            .ok_or("Tutorials source is unavailable")?;
        let source = target
            .read_main_file(&file)
            .map_err(|e| e.to_string())?
            .ok_or("Tutorial source is unavailable")?;
        let request_id = tutorial_request_id(name);
        let legacy = self.project_workflow_launched(DEFAULT_PROJECT, actor, &request_id)?;
        let launched = legacy || self.project_workflow_launched(&project, actor, &request_id)?;
        let run_project = if legacy { DEFAULT_PROJECT } else { &project };
        let open_tasks = if launched {
            self.read_project_tracker_tasks(context, run_project, "tutorials")
                .map(|tasks| tasks.backlog.issues.len())
                .unwrap_or(0)
        } else {
            0
        };
        let completed = launched
            && open_tasks == 0
            && self
                .read_project_tracker_backlog(context, run_project, "tutorials")
                .is_ok_and(|backlog| {
                    !backlog.issues.is_empty()
                        && backlog.issues.iter().all(|issue| issue.status == "closed")
                });
        Ok(serde_json::json!({
            "project": project, "run_project": run_project, "publisher": "GaugeWright",
            "file": file, "source": source,
            "status": if completed { "complete" } else if launched { "continue" } else { "ready" },
            "open_tasks": open_tasks,
        }))
    }

    pub fn start_shipped_tutorial(
        &mut self,
        context: &crate::identity::AuthenticatedActionContext,
        name: &str,
    ) -> Result<crate::project_workflow::ProjectWorkflowInvocation, String> {
        use crate::project_workflow::{ProjectWorkflowLaunch, ProjectWorkflowLimits};
        let file = format!("{name}.whip");
        if !SHIPPED.iter().any(|(shipped, _)| *shipped == file) {
            return Err("no such shipped tutorial".into());
        }
        let actor = context.actor().as_str().to_owned();
        let request_id = tutorial_request_id(name);
        let limits = ProjectWorkflowLimits::PRODUCT;
        // Runs already admitted in Personal retain their pinned source and tasks.
        if self.project_workflow_launched(DEFAULT_PROJECT, &actor, &request_id)? {
            return self.resume_project_workflow(context, DEFAULT_PROJECT, &request_id, limits);
        }
        let project = tutorial_project_id(&actor);
        if self.project_workflow_launched(&project, &actor, &request_id)? {
            return self.resume_project_workflow(context, &project, &request_id, limits);
        }
        let org = Org::rebuild(self.store_ref()).map_err(|e| format!("{e:?}"))?;
        if !self.tutorial_learner_admitted(&actor, &org) {
            return Err("this Home has no owner yet".into());
        }
        let cut = match self.ensure_tutorial_project(&actor, &org)? {
            ShippedTutorials::NoOwner => return Err("this Home has no owner yet".into()),
            ShippedTutorials::Current(cut) | ShippedTutorials::Updated(cut) => cut,
        };
        if self
            .prepare_project_tracker_read(
                context,
                &project,
                "tutorials",
                crate::project_tracker::TrackerPermission::Contribute,
            )
            .is_err()
        {
            self.declare_project_tracker(
                context,
                &project,
                "tutorials",
                "shipped-tutorials",
                gaugedesk_core::abac::ResourceAttributes::default(),
            )
            .map_err(|e| format!("{e:?}"))?;
        }
        self.launch_project_workflow(
            context,
            &ProjectWorkflowLaunch {
                project,
                target: tutorial_target_id(&actor),
                path: file,
                cut,
                request_id,
                inputs: std::collections::BTreeMap::from([(
                    "learner".into(),
                    serde_json::json!({"authority":actor}),
                )]),
            },
            limits,
        )
    }
}

#[cfg(test)]
#[path = "shipped_tutorials_tests.rs"]
mod tests;
