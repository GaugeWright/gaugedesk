//! Move signed-out work to a signed-in account
//! ([DR-0268](../../../specs/decisions/0268-the-project-is-the-unit-of-trust.md) §4,
//! [DR-0328](../../../specs/decisions/0328-removing-the-desktop-claim.md) §7).
//!
//! Work done on a desktop without signing in belongs to the computer's local
//! account. It reaches a signed-in account only by this explicit transfer of
//! ownership, never by merging the two identities: the window names the
//! projects and the receiving account, and the account it is signed in as
//! becomes the recorded owner of each named project and of their chats. The
//! local account keeps no standing in them. Personal is never transferred,
//! and neither is anything whose owner is not the local account — an
//! organization's project, Tutorials, a Panel preview, or a project someone
//! else owns.
//!
//! It is a command of this computer's own window, never of the relay or of a
//! hosted Home: only the window holds the local account's work, and only the
//! person at it may give that work away.

use std::collections::BTreeSet;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::account_signin::DesktopOperatorPlane;
use crate::library::{ProjectRecord, RecordOp};
use crate::project_owner::{record_owner, ProjectOwner};
use crate::{net_http, LockUnpoisoned, SharedWorkbench, Workbench};

fn problem(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// Why a transfer did not happen, or did not finish.
#[derive(Debug, PartialEq, Eq)]
pub enum TransferRefused {
    /// A named project is not the local account's to give; nothing moved.
    NotMovable,
    /// The store refused a grant's revocation after the projects moved.
    Failed(String),
    /// This Home holds the office-controlled profile, whose work never becomes
    /// an account's (WS-424); nothing moved.
    OfficeProfile(&'static str),
}

impl IntoResponse for TransferRefused {
    fn into_response(self) -> Response {
        match self {
            TransferRefused::NotMovable => problem(
                StatusCode::CONFLICT,
                "only this computer's signed-out projects can move to an account; \
                 nothing was moved",
            ),
            TransferRefused::OfficeProfile(message) => problem(StatusCode::CONFLICT, message),
            TransferRefused::Failed(message) => {
                problem(StatusCode::INTERNAL_SERVER_ERROR, &message)
            }
        }
    }
}

impl Workbench {
    /// Whether `project` belongs to this computer's local account and may
    /// move to an account: owned by the local account, recorded or derived,
    /// and neither a Personal, an organization's, Tutorials, a Panel
    /// preview, nor paused for a handoff.
    fn movable_local_project(&self, project: &ProjectRecord, legacy: &str) -> bool {
        !project.is_default
            && !project.extra.contains_key("organization")
            && !crate::shipped_tutorials::is_tutorial_project(project)
            && crate::panel_preview::preview_marker(project).is_none()
            && self.project_owner_with(project, legacy)
                == ProjectOwner::Account(self.authority().as_str().to_owned())
            && !self.project_moving(&project.id)
    }

    /// The projects the computer's local account owns that may move to an
    /// account, by name.
    pub(crate) fn movable_local_projects(&self) -> Vec<(String, String)> {
        if self.office_profile_exit_refusal().is_some() {
            return Vec::new();
        }
        let legacy = self.legacy_project_owner();
        let mut projects: Vec<(String, String)> = self
            .library
            .projects
            .values()
            .filter(|project| self.movable_local_project(project, &legacy))
            .map(|project| (project.id.clone(), project.name.clone()))
            .collect();
        projects.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        projects
    }

    /// Give each of `projects`, and the chats in it the local account holds,
    /// to `account`. Refuses the whole request, writing nothing, when any of
    /// them is not the local account's to give.
    pub(crate) fn transfer_local_projects(
        &mut self,
        projects: &BTreeSet<String>,
        account: &str,
    ) -> Result<Vec<String>, TransferRefused> {
        if let Some(refusal) = self.office_profile_exit_refusal() {
            return Err(TransferRefused::OfficeProfile(refusal));
        }
        let legacy = self.legacy_project_owner();
        let mut records = Vec::with_capacity(projects.len());
        for id in projects {
            match self.library.projects.get(id) {
                Some(project) if self.movable_local_project(project, &legacy) => {
                    records.push(project.clone());
                }
                _ => return Err(TransferRefused::NotMovable),
            }
        }
        let local = self.authority().as_str().to_owned();
        let chats: Vec<crate::library::ChatRecord> = self
            .library
            .chats
            .values()
            .filter(|chat| {
                chat.owner.as_deref().is_none_or(|owner| owner == local)
                    && self
                        .library
                        .project_of_chat(&chat.id)
                        .is_some_and(|project| projects.contains(project))
            })
            .cloned()
            .collect();
        let granted: Vec<String> = crate::org::Org::rebuild(self.store_ref())
            .map(|org| {
                org.granted_project_ids(&local)
                    .into_iter()
                    .filter(|project| projects.contains(project))
                    .collect()
            })
            .unwrap_or_default();

        let mut moved = Vec::with_capacity(records.len());
        for mut record in records {
            record_owner(&mut record.extra, account);
            record.op = RecordOp::Upsert;
            moved.push(record.id.clone());
            self.write_project_record(record);
        }
        for mut chat in chats {
            chat.owner = Some(account.to_owned());
            chat.op = RecordOp::Upsert;
            self.write_chat_record(chat);
        }
        // Owning a project is the local account's only standing in it, but a
        // grant would outlive the move.
        for project in granted {
            let revoked = crate::org::MemberGrantRecord {
                id: crate::org::MemberGrantRecord::make_id(&local, &project),
                op: RecordOp::Tombstone,
                authority: local.clone(),
                project_id: project,
            };
            let raw = serde_json::to_string(&revoked)
                .map_err(|error| TransferRefused::Failed(error.to_string()))?;
            self.store_mut()
                .append_record(crate::org::ORG_SCOPE, "member_grant", &raw)
                .map_err(|error| TransferRefused::Failed(format!("{error:?}")))?;
        }
        Ok(moved)
    }
}

/// The signed-in account a transfer gives the local account's work to: the
/// account session this window presents. Off a desktop there is no local
/// account's work; off the window, nobody may give it away.
#[allow(clippy::result_large_err)]
fn receiving_account(
    wb: &Workbench,
    headers: &HeaderMap,
    window: bool,
) -> Result<String, Response> {
    if !wb.desktop_account_mode() {
        return Err(problem(
            StatusCode::NOT_FOUND,
            "signed-out work exists only on a desktop",
        ));
    }
    if !window {
        return Err(problem(
            StatusCode::FORBIDDEN,
            "only this computer's own window can move its signed-out work",
        ));
    }
    net_http::bearer(headers)
        .and_then(|token| wb.resolve_account_session(token))
        .map(|(account, _)| account)
        .filter(|account| account != wb.authority().as_str())
        .ok_or_else(|| {
            problem(
                StatusCode::UNAUTHORIZED,
                "sign in to the account that should receive this computer's signed-out work",
            )
        })
}

/// `GET /local-projects`: what the signed-in account could receive.
pub async fn list_local_projects(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    window: Option<Extension<DesktopOperatorPlane>>,
) -> Response {
    let wb = wb.lock_unpoisoned();
    let account = match receiving_account(&wb, &headers, window.is_some()) {
        Ok(account) => account,
        Err(response) => return response,
    };
    let projects: Vec<serde_json::Value> = wb
        .movable_local_projects()
        .into_iter()
        .map(|(id, name)| json!({ "id": id, "name": name }))
        .collect();
    Json(json!({ "account": account, "projects": projects })).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferLocalProjects {
    /// The projects to move, each named by the window that confirmed them.
    pub projects: Vec<String>,
}

/// `POST /local-projects/transfer`: move the named signed-out projects to
/// the signed-in account.
pub async fn transfer_local_projects(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    window: Option<Extension<DesktopOperatorPlane>>,
    Json(body): Json<TransferLocalProjects>,
) -> Response {
    let mut wb = wb.lock_unpoisoned();
    let account = match receiving_account(&wb, &headers, window.is_some()) {
        Ok(account) => account,
        Err(response) => return response,
    };
    let projects: BTreeSet<String> = body.projects.into_iter().collect();
    if projects.is_empty() {
        return problem(StatusCode::BAD_REQUEST, "name at least one project to move");
    }
    match wb.transfer_local_projects(&projects, &account) {
        Ok(moved) => Json(json!({ "account": account, "moved": moved })).into_response(),
        Err(refused) => refused.into_response(),
    }
}

#[cfg(test)]
#[path = "project_transfer_tests.rs"]
mod tests;
