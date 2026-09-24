//! The tutorials GaugeDesk ships, and the folder they live in (DR-0192).
//!
//! Shipped tutorials are product content: GaugeDesk installs and updates them,
//! and they are neither the person's own files nor the Home's. They live in a
//! Tutorials folder in Personal — a managed work target beside Personal's files
//! — owned by the Home's owner so their text may flow into that person's
//! `tutorials` tracker, and read-only to people and agents so a release never
//! has to reconcile anyone's edits. Its head is exactly what this release ships.

use crate::{
    home_owner::{HomeOwnerClaim, CLAIM_KIND},
    library::{TargetCapabilities, WorkTargetOwner},
    org::ORG_SCOPE,
    Workbench, DEFAULT_PROJECT,
};
use serde::{Deserialize, Serialize};

/// The Tutorials folder's work-target id. One per Home: it hangs off Personal.
pub const TUTORIALS_TARGET: &str = "target-tutorials";

/// Every tutorial this release ships, as `(file, source)`. Each is an ordinary
/// `.whip` file; nothing about a tutorial is known to the product beyond this.
pub const SHIPPED: &[(&str, &str)] = &[("basics.whip", include_str!("tutorials/basics.whip"))];

/// Library record noting which release put the folder at which revision.
const RELEASE_KIND: &str = "shipped_tutorials_release";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShippedRelease {
    target: String,
    cut: String,
    version: String,
}

/// What [`Workbench::ensure_shipped_tutorials`] found or did.
#[derive(Debug, PartialEq, Eq)]
pub enum ShippedTutorials {
    /// Nobody owns this Home yet, so there is no one for the folder to belong to.
    NoOwner,
    /// The folder already held exactly this release's tutorials.
    Current(String),
    /// The folder was created or brought to this release; its new head.
    Updated(String),
}

impl Workbench {
    /// The account that owns this Home: the one that claimed it (DR-0187), or,
    /// for a Home governed by a directory of its own — a Cloud Home is
    /// provisioned with its tenant's owner — that directory's one active owner.
    /// A directory with several owners names nobody here: whose the tutorials
    /// are is not something to guess.
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
        let org = crate::org::Org::rebuild(self.store_ref()).ok()?;
        let mut owners = org.members.values().filter(|member| {
            member.status == crate::org::MembershipStatus::Active && member.role == "owner"
        });
        let owner = owners.next()?;
        owners.next().is_none().then(|| owner.authority.clone())
    }

    /// Ensure the owner's Tutorials folder exists in Personal and holds exactly
    /// this release's tutorials (DR-0192 §1–§3). Asked wherever the Home's owner
    /// is established, and on every reconcile; once current it changes nothing.
    pub fn ensure_shipped_tutorials(&mut self) -> Result<ShippedTutorials, String> {
        let Some(owner) = self.home_owner_account() else {
            return Ok(ShippedTutorials::NoOwner);
        };
        if !self.library.projects.contains_key(DEFAULT_PROJECT) {
            return Ok(ShippedTutorials::NoOwner);
        }
        // Personal mid-move takes no writes; the next reconcile catches up.
        if self.project_moving(DEFAULT_PROJECT) {
            return Err(crate::federation::PAUSED_FOR_MOVE.into());
        }
        if !self.targets.contains_key(TUTORIALS_TARGET) {
            let workspace = self
                .workspace_provider(TUTORIALS_TARGET)
                .init_at(&self.targets_dir().join(TUTORIALS_TARGET))
                .map_err(|error| error.to_string())?;
            self.targets.insert(TUTORIALS_TARGET.to_owned(), workspace);
        }
        let before = self
            .targets
            .get(TUTORIALS_TARGET)
            .and_then(|target| target.current_main_cut().ok().flatten());
        let head = self.targets[TUTORIALS_TARGET]
            .seed_main_exactly(SHIPPED, "whip")
            .map_err(|error| error.to_string())?
            .0;
        let recorded = self.library.work_targets.get(TUTORIALS_TARGET);
        let current = recorded.is_some_and(|target| {
            target.authority == owner && target.current_basis.as_deref() == Some(head.as_str())
        }) && before.as_deref() == Some(head.as_str());
        if current {
            return Ok(ShippedTutorials::Current(head));
        }
        let mut record = crate::library_state::managed_target_record(
            TUTORIALS_TARGET.to_owned(),
            "Tutorials".to_owned(),
            WorkTargetOwner::Project {
                project_id: DEFAULT_PROJECT.to_owned(),
            },
            self.home_id(),
            head.clone(),
        );
        // The owner's, so its text may flow into their tutorial tracker; and
        // read-only, so a release never meets an edit (DR-0192 §2, §4).
        record.authority = owner.clone();
        record.parties = vec![owner];
        record.capabilities = TargetCapabilities {
            read: true,
            propose: false,
            apply: false,
            publish: false,
            release: false,
        };
        self.write_work_target_record(record);
        let release = ShippedRelease {
            target: TUTORIALS_TARGET.to_owned(),
            cut: head.clone(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        };
        self.store_mut()
            .append_record(
                crate::library::LIBRARY_SCOPE,
                RELEASE_KIND,
                &serde_json::to_string(&release).map_err(|e| e.to_string())?,
            )
            .map_err(|error| format!("{error:?}"))?;
        Ok(ShippedTutorials::Updated(head))
    }
}

/// The request id a shipped tutorial is launched under: fixed per tutorial, so
/// a second window, a retry or a restart finds the run that exists instead of
/// starting another (`experience/onboarding.md`).
pub fn tutorial_request_id(name: &str) -> String {
    format!("shipped-tutorial:{name}")
}

impl Workbench {
    /// Start, or find, the signed-in owner's run of a shipped tutorial (WHIP-5).
    /// Ensures the Tutorials folder and the owner's `tutorials` tracker, then
    /// launches the tutorial from the folder's current revision — or, when it
    /// was launched before, resumes that run on the revision it pinned.
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
        if self.project_workflow_launched(DEFAULT_PROJECT, &actor, &request_id)? {
            return self.resume_project_workflow(context, DEFAULT_PROJECT, &request_id, limits);
        }
        let cut = match self.ensure_shipped_tutorials()? {
            ShippedTutorials::NoOwner => return Err("this Home has no owner yet".into()),
            ShippedTutorials::Current(cut) | ShippedTutorials::Updated(cut) => cut,
        };
        if self
            .prepare_project_tracker_read(
                context,
                DEFAULT_PROJECT,
                "tutorials",
                crate::project_tracker::TrackerPermission::Contribute,
            )
            .is_err()
        {
            self.declare_project_tracker(
                context,
                DEFAULT_PROJECT,
                "tutorials",
                "shipped-tutorials",
                gaugedesk_core::abac::ResourceAttributes::default(),
            )
            .map_err(|error| format!("{error:?}"))?;
        }
        let request = ProjectWorkflowLaunch {
            project: DEFAULT_PROJECT.to_owned(),
            target: TUTORIALS_TARGET.to_owned(),
            path: file,
            cut,
            request_id,
            inputs: std::collections::BTreeMap::from([(
                "learner".to_owned(),
                serde_json::json!({ "authority": actor }),
            )]),
        };
        self.launch_project_workflow(context, &request, limits)
    }
}

#[cfg(test)]
#[path = "shipped_tutorials_tests.rs"]
mod tests;
