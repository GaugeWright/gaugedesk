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
//! This is what admits a signed-in account to a project, beside
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

pub(crate) fn recorded_owner(project: &ProjectRecord) -> Option<&str> {
    project
        .extra
        .get(PROJECT_OWNER_EXTRA)
        .and_then(serde_json::Value::as_str)
        .filter(|owner| !owner.is_empty())
}

/// The id of `account`'s own Personal on this host. Hashed, so no account id
/// reaches a path or a directory name.
pub fn personal_project_id(account: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(format!("gaugedesk-personal:{account}").as_bytes());
    format!("personal-{}", hex::encode(&digest[..16]))
}

impl Workbench {
    /// The owner of a project with no recorded one: the account that claimed
    /// this computer, else the computer's local account.
    pub(crate) fn legacy_project_owner(&self) -> String {
        // DR-0309 names the earlier explicit claim, never an organization
        // role. home_owner_account also recognizes a sole directory owner,
        // which is host-era compatibility and cannot establish project data
        // ownership. Unreadable or ambiguous claim evidence supplies no owner.
        let Ok(claims) = self
            .store_ref()
            .records(crate::org::ORG_SCOPE, crate::home_owner::CLAIM_KIND)
        else {
            return String::new();
        };
        match claims.as_slice() {
            [] => self.authority().as_str().to_owned(),
            [claim] => match serde_json::from_str::<crate::home_owner::HomeOwnerClaim>(claim) {
                Ok(claim) => claim
                    .account
                    .unwrap_or_else(|| self.authority().as_str().to_owned()),
                Err(_) => String::new(),
            },
            _ => String::new(),
        }
    }

    /// The owner of `project`. `legacy` is [`Self::legacy_project_owner`],
    /// passed in so a caller folding every project reads it once.
    pub(crate) fn project_owner_with(&self, project: &ProjectRecord, legacy: &str) -> ProjectOwner {
        self.project_owner_in(&self.library, project, legacy)
    }

    fn project_owner_in(
        &self,
        library: &crate::library::Library,
        project: &ProjectRecord,
        legacy: &str,
    ) -> ProjectOwner {
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
                .and_then(|placement| library.project_of_instance(placement))
                .and_then(|id| library.projects.get(id))
                .filter(|previewed| !crate::panel_preview::is_panel_preview_project(previewed));
            if let Some(previewed) = previewed {
                return self.project_owner_in(library, previewed, legacy);
            }
            if let Some(author) = self.agent_authoring_owner_in(library, &marker.agent_id) {
                return ProjectOwner::Account(author);
            }
        }
        ProjectOwner::Account(legacy.to_owned())
    }

    /// `account`'s Personal on this host, if it has one: the install's own
    /// Personal for the account DR-0309 gave it to, else one made for it.
    pub(crate) fn account_personal(&self, account: &str) -> Option<String> {
        let legacy = self.legacy_project_owner();
        let owned = |project: &&ProjectRecord| {
            project.is_default
                && self.project_owner_with(project, &legacy)
                    == ProjectOwner::Account(account.to_owned())
        };
        let mut personals = self.library.projects.values().filter(owned);
        let first = personals.next()?;
        // The install's Personal wins if an account somehow holds two.
        if first.id == crate::DEFAULT_PROJECT {
            return Some(first.id.clone());
        }
        Some(
            personals
                .find(|project| project.id == crate::DEFAULT_PROJECT)
                .unwrap_or(first)
                .id
                .clone(),
        )
    }

    /// Make sure `account` has a Personal of its own on this host, and name it
    /// (DR-0268 §5). Idempotent; an account DR-0309 gave the install's
    /// Personal keeps it.
    pub(crate) fn ensure_account_personal(&mut self, account: &str) -> Result<String, String> {
        if account.is_empty() || account == "anonymous" {
            return Err("an account is needed for a Personal project".to_owned());
        }
        if let Some(project) = self.account_personal(account) {
            return Ok(project);
        }
        let id = personal_project_id(account);
        crate::library_routes::create_personal_project(self, &id, account)?;
        Ok(id)
    }

    /// The Personal a new Agent is placed on: its owner's, else the
    /// install's.
    pub(crate) fn agent_owner_personal(&self, agent: &str) -> String {
        self.agent_authoring_owner(agent)
            .and_then(|owner| self.account_personal(&owner))
            .unwrap_or_else(|| crate::DEFAULT_PROJECT.to_owned())
    }

    /// The Personal a request works in when it is not the install's: a
    /// desktop account session's own, made if it has none (DR-0268 §5).
    /// `None` for the local channel, a phone and a hosted Home, which keep the
    /// install's until WS-588, and for the account DR-0309 gave it to.
    pub(crate) fn request_personal(
        &mut self,
        headers: &axum::http::HeaderMap,
    ) -> Result<Option<String>, String> {
        let Some((account, _)) = crate::net_http::bearer(headers)
            .filter(|_| self.desktop_account_mode())
            .and_then(|token| self.resolve_account_session(token))
        else {
            return Ok(None);
        };
        let personal = self.ensure_account_personal(&account)?;
        Ok((personal != crate::DEFAULT_PROJECT).then_some(personal))
    }

    /// The placement a quick-start chat in Personal `project` starts on.
    pub(crate) fn personal_placement_of(&self, project: &str) -> Option<String> {
        if project == crate::DEFAULT_PROJECT {
            return Some(crate::app_support::DEFAULT_PLACEMENT.to_owned())
                .filter(|placement| self.library.instances.contains_key(placement));
        }
        Some(crate::library_routes::general_placement_id(project))
            .filter(|placement| self.library.instances.contains_key(placement))
    }

    /// The projects `account` reaches as itself: those it owns and those it
    /// holds a grant to in `org`.
    pub(crate) fn account_project_ids(&self, account: &str, org: &Org) -> BTreeSet<String> {
        // Admission consumes durable ownership, including a preview's source,
        // rather than a Workbench projection that another writer may have left
        // stale. Unreadable ownership evidence grants no project visibility.
        let Ok(library) = crate::library::Library::rebuild(self.store_ref()) else {
            return BTreeSet::new();
        };
        let legacy = self.legacy_project_owner();
        let mut ids: BTreeSet<String> = library
            .projects
            .values()
            .filter(|project| {
                self.project_owner_in(&library, project, &legacy)
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
