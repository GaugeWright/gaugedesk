//! Who owns a project ([DR-0268](../../../specs/decisions/0268-the-project-is-the-unit-of-trust.md) §6,
//! [DR-0309](../../../specs/decisions/0309-a-project-records-its-owner.md)).
//!
//! Every project has exactly one owner: an account or an organization. A
//! project created on this build records its creating account in
//! `extra.owner`. Older records carry none, and their owner is derived the way
//! the founder settled on 2026-10-01: the account that claimed this computer,
//! whose claim was the explicit act that gave it the computer's projects, or
//! the computer's local account where nobody claimed it.
//!
//! On a desktop this is what admits a signed-in account to a project, beside
//! an explicit grant; an organization role no longer reaches every project.

use std::collections::{BTreeMap, BTreeSet};

use crate::library::ProjectRecord;
use crate::org::Org;
use crate::Workbench;

/// The `ProjectRecord.extra` key holding the owning account.
pub const PROJECT_OWNER_EXTRA: &str = "owner";

/// A project's one owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectOwner {
    Account(String),
    Organization(String),
}

/// Record `account` as the owner on a project record about to be written.
/// An empty or anonymous actor records nothing, so the legacy rule applies.
pub fn record_owner(extra: &mut BTreeMap<String, serde_json::Value>, account: &str) {
    if account.is_empty() || account == "anonymous" {
        return;
    }
    extra.insert(
        PROJECT_OWNER_EXTRA.to_owned(),
        serde_json::Value::String(account.to_owned()),
    );
}

fn recorded_owner(project: &ProjectRecord) -> Option<&str> {
    project
        .extra
        .get(PROJECT_OWNER_EXTRA)
        .and_then(serde_json::Value::as_str)
        .filter(|owner| !owner.is_empty())
}

impl Workbench {
    /// The owner of a project with no recorded one: the account that claimed
    /// this computer, else the computer's local account.
    pub(crate) fn legacy_project_owner(&self) -> String {
        self.home_owner_account()
            .unwrap_or_else(|| self.authority().as_str().to_owned())
    }

    /// The owner of `project`. `legacy` is [`Self::legacy_project_owner`],
    /// passed in so a caller folding every project reads it once.
    pub(crate) fn project_owner_with(&self, project: &ProjectRecord, legacy: &str) -> ProjectOwner {
        if let Some(owner) = recorded_owner(project) {
            return ProjectOwner::Account(owner.to_owned());
        }
        if let Some(organization) = project
            .extra
            .get("organization")
            .and_then(serde_json::Value::as_str)
        {
            return ProjectOwner::Organization(organization.to_owned());
        }
        if crate::shipped_tutorials::is_tutorial_project(project) {
            if let Some(learner) = project
                .extra
                .get("product")
                .and_then(|product| product.get("learner"))
                .and_then(serde_json::Value::as_str)
            {
                return ProjectOwner::Account(learner.to_owned());
            }
        }
        // A Panel agent's preview project is hidden plumbing: it belongs to
        // whoever owns what it previews.
        if let Some(marker) = crate::panel_preview::preview_marker(project) {
            let previewed = marker
                .placement_id
                .as_deref()
                .and_then(|placement| self.library.project_of_instance(placement))
                .and_then(|id| self.library.projects.get(id))
                .filter(|previewed| !crate::panel_preview::is_panel_preview_project(previewed));
            if let Some(previewed) = previewed {
                return self.project_owner_with(previewed, legacy);
            }
            if let Some(author) = self.agent_authoring_owner(&marker.agent_id) {
                return ProjectOwner::Account(author.to_owned());
            }
        }
        ProjectOwner::Account(legacy.to_owned())
    }

    /// The projects `account` reaches as itself: those it owns and those it
    /// holds a grant to in `org`.
    pub(crate) fn account_project_ids(&self, account: &str, org: &Org) -> BTreeSet<String> {
        let legacy = self.legacy_project_owner();
        let mut ids: BTreeSet<String> = self
            .library
            .projects
            .values()
            .filter(|project| {
                self.project_owner_with(project, &legacy)
                    == ProjectOwner::Account(account.to_owned())
            })
            .map(|project| project.id.clone())
            .collect();
        ids.extend(org.granted_project_ids(account));
        ids
    }
}

/// Refuse a request carrying an account session that names a project the
/// account neither owns nor holds a grant to. Layered on the desktop's own
/// channel and its relay leg, which otherwise serve whoever reaches them.
///
/// Only a project the path resolves to is checked here. A credential-free
/// request is the local channel and keeps its view until the local account
/// has a Personal of its own (WS-588); a route naming no project is the
/// next step's (WS-655).
pub(crate) async fn account_project_gate(
    axum::extract::State(wb): axum::extract::State<crate::SharedWorkbench>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use crate::LockUnpoisoned;
    use axum::response::IntoResponse;
    let refused = crate::net_http::bearer(request.headers()).is_some_and(|bearer| {
        let wb = wb.lock_unpoisoned();
        if !wb.desktop_account_mode() {
            return false;
        }
        wb.scope_project_of_path(request.uri().path())
            .is_some_and(|project| {
                !wb.project_visibility_in(
                    Some(bearer),
                    &crate::workbench_auth::req_scope(request.headers()),
                )
                .allows(&project)
            })
    });
    if refused {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({ "error": "not in scope for this project" })),
        )
            .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
#[path = "project_owner_tests.rs"]
mod tests;
