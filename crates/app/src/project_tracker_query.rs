//! Current-recipient discovery and reads of project-owned native trackers.
use super::*;
use gaugedesk_workspace::WorkflowProtection;
use whipplescript_store::tracker_filing::{TrackerFiling, TrackerFilings};
fn query_error(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

/// An affordance projection, never a grant that can authorize a later command.
#[derive(Clone, Debug, Serialize)]
pub struct ReadableProjectTracker {
    pub project_id: String,
    pub workspace_id: String,
    pub queue: String,
    pub resource_id: String,
    pub can_complete: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProjectTrackerIssue {
    pub subject_id: String,
    pub id: String,
    pub title: String,
    pub body: String,
    pub status: String,
    pub assigned_to: Option<String>,
    pub claimed_by: Option<String>,
    /// When the current claim's lease runs out, if one is held (WHIP-4).
    pub claim_expires_at: Option<String>,
    /// Who closed it and what they reported, while it is closed: completion
    /// attribution that survives the claim being released.
    pub closed_by: Option<String>,
    pub closing_summary: Option<String>,
    pub filed_by: Option<String>,
    pub labels: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// The lease and closure one issue's own events establish.
#[derive(Default)]
struct IssueHistory {
    lease: Option<(String, Option<String>)>,
    closed: Option<(Option<String>, Option<String>)>,
}

/// Fold the tracker's event log into each issue's current lease and latest
/// closure, keyed by the issue's permanent subject.
fn issue_histories(
    events: &[whipplescript_store::items::TrackerEvent],
) -> BTreeMap<String, IssueHistory> {
    let mut histories: BTreeMap<String, IssueHistory> = BTreeMap::new();
    for event in events {
        let Some(subject) = &event.issue_id else {
            continue;
        };
        let payload: serde_json::Value =
            serde_json::from_str(&event.payload_json).unwrap_or_default();
        let text = |name: &str| payload[name].as_str().map(str::to_owned);
        let history = histories.entry(subject.clone()).or_default();
        match event.kind.as_str() {
            "claim.acquired" => {
                history.lease = Some((event.event_id.clone(), text("expires_at")));
            }
            "claim.renewed" => {
                if let Some((lease, expires)) = &mut history.lease {
                    if text("lease_id").as_deref() == Some(lease.as_str()) {
                        *expires = text("expires_at");
                    }
                }
            }
            "claim.released" | "claim.expired"
                if history.lease.as_ref().map(|(lease, _)| lease.as_str())
                    == text("lease_id").as_deref() =>
            {
                history.lease = None;
            }
            "issue.closed" => {
                history.closed = Some((event.actor.clone(), text("summary")));
            }
            _ => {}
        }
    }
    histories
}

#[derive(Clone, Debug, Serialize)]
pub struct ProjectTrackerBacklog {
    pub tracker: ReadableProjectTracker,
    pub issues: Vec<ProjectTrackerIssue>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProjectTrackerTasks {
    pub actor: String,
    #[serde(flatten)]
    pub backlog: ProjectTrackerBacklog,
}

fn visible(snapshot: &Snapshot, actor: &str) -> Result<Option<ReadableProjectTracker>, AdmitError> {
    let tracker = snapshot
        .registry
        .tracker
        .as_ref()
        .ok_or_else(|| refused("tracker is unavailable"))?;
    if !permitted(snapshot, actor, TrackerPermission::Read)
        || check_policy(snapshot, &tracker.resource, Action::Access).is_err()
    {
        return Ok(None);
    }
    Ok(Some(ReadableProjectTracker {
        project_id: tracker.project_id.clone(),
        workspace_id: tracker.workspace_id.clone(),
        queue: tracker.queue.clone(),
        resource_id: tracker.resource.resource.id.as_str().into(),
        can_complete: permitted(snapshot, actor, TrackerPermission::Contribute)
            && check_policy(snapshot, &tracker.resource, Action::Run).is_ok(),
    }))
}

impl Workbench {
    /// File a real issue in the current project's Home-owned tasks tracker.
    /// The package tool is only an intent: this path rechecks the actor,
    /// project, resource policy, handoff state, and protected store at use.
    pub(crate) fn file_agent_project_task(
        &mut self,
        context: &AuthenticatedActionContext,
        project: &str,
        chat_id: &str,
        operation_id: &str,
        content: &str,
        assigned_to: Option<&str>,
    ) -> Result<String, String> {
        let content = content.trim();
        if content.is_empty()
            || content.len() > 16 * 1024
            || chat_id.trim().is_empty()
            || operation_id.trim().is_empty()
        {
            return Err("task content or operation identity is invalid".to_owned());
        }
        if self.library_project_of_chat(chat_id).as_deref() != Some(project) {
            return Err("task chat no longer belongs to this project".to_owned());
        }
        let (tracker, recipients, choices, basis) = self
            .prepare_project_tracker_recipients(
                context,
                project,
                crate::project_tracker::PROJECT_TASKS,
            )
            .map_err(query_error)?;
        let recipient = match assigned_to.map(str::trim) {
            None | Some("me" | "myself") => context.actor().as_str().to_owned(),
            Some("") => return Err("task assignee is empty".to_owned()),
            Some(requested) if recipients.contains(requested) => requested.to_owned(),
            Some(requested) => {
                let mut matches = choices
                    .iter()
                    .filter(|(_, display)| display.as_str() == requested);
                let recipient = matches
                    .next()
                    .ok_or("task assignee is not an eligible project recipient")?
                    .0;
                if matches.next().is_some() {
                    return Err("task assignee is ambiguous".to_owned());
                }
                recipient.clone()
            }
        };
        if !recipients.contains(&recipient) {
            return Err("task assignee cannot currently read this project tracker".to_owned());
        }
        crate::federation::require_project_writes_available(self.store_ref(), project)
            .map_err(query_error)?;
        let key = self.workflow_key(project, &tracker.workspace_id, true)?;
        let protection =
            WorkflowProtection::new(&tracker.workspace_id, key.clone()).map_err(query_error)?;
        let storage = self.workflow_storage(&tracker.workspace_id)?;
        let (title, body) = content
            .split_once('\n')
            .map_or((content, ""), |(title, body)| (title.trim(), body.trim()));
        if title.is_empty() || title.len() > 512 {
            return Err("task title must be 1–512 bytes".to_owned());
        }
        let filing = TrackerFiling {
            operation_id: operation_id.to_owned(),
            instance_id: format!("project-agent-chat:{chat_id}"),
            effect_id: operation_id.to_owned(),
            actor: context.actor().as_str().to_owned(),
            queue: tracker.queue,
            title: title.to_owned(),
            body: body.to_owned(),
            labels: Vec::new(),
            metadata: serde_json::json!({"source": "agent"}),
            assigned_to: Some(recipient),
        };
        let mut writer = self.store_ref().sibling().map_err(query_error)?;
        let item_id = writer
            .with_dispatch_basis(&basis, || {
                key.retain(|| {
                    let mut stores = storage
                        .initialize_protected(&protection)
                        .map_err(|error| std::io::Error::other(query_error(error)))?;
                    stores
                        .runtime
                        .items
                        .file_issue_once(&filing)
                        .map(|receipt| receipt.item_id)
                        .map_err(|error| std::io::Error::other(query_error(error)))
                })
            })
            .map_err(query_error)?
            .map_err(query_error)?;
        self.notify_library_changed("project_tracker", project, "upsert");
        Ok(item_id)
    }

    /// The person's queue is a projection of a currently readable native tracker.
    /// Assignment is a filter, never admission and never inferred from a claim.
    pub fn read_project_tracker_tasks(
        &self,
        context: &AuthenticatedActionContext,
        project: &str,
        queue: &str,
    ) -> Result<ProjectTrackerTasks, String> {
        let actor = context.actor().as_str().to_owned();
        let mut backlog = self.read_project_tracker_backlog(context, project, queue)?;
        backlog.issues.retain(|issue| {
            issue.assigned_to.as_deref() == Some(actor.as_str())
                && matches!(issue.status.as_str(), "open" | "in_progress")
        });
        Ok(ProjectTrackerTasks { actor, backlog })
    }

    /// List only the project's readable tracker resources; no issue body is read.
    pub fn list_project_trackers(
        &self,
        context: &AuthenticatedActionContext,
        project: &str,
    ) -> Result<Vec<ReadableProjectTracker>, String> {
        let (authority, mut basis) = self
            .store_ref()
            .read_for_dispatch(
                &[
                    LIBRARY_SCOPE,
                    ORG_SCOPE,
                    crate::account_auth::ACCOUNT_AUTH_SCOPE,
                    crate::mobile_machine_session::SCOPE,
                    &crate::federation::handoff_scope(project),
                ],
                |store| current_project(store, self.home_id(), context, project),
            )
            .map_err(query_error)?;
        if let Some(ms) = authority.deadline_ms {
            basis = basis.with_deadline(
                std::time::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_millis(ms))
                    .ok_or("tracker authentication deadline is invalid")?,
            );
        }
        let prefix = format!("project::{project}::tracker::");
        let scopes = self
            .store_ref()
            .scope_high_water_marks()
            .map_err(query_error)?;
        let mut result = Vec::new();
        for scope in scopes.keys() {
            let Some(encoded) = scope
                .strip_prefix(&prefix)
                .filter(|suffix| !suffix.contains("::"))
            else {
                continue;
            };
            let queue = String::from_utf8(hex::decode(encoded).map_err(query_error)?)
                .map_err(query_error)?;
            if registry_scope(project, &queue).map_err(query_error)? != *scope {
                return Err("tracker declaration has noncanonical coordinates".into());
            }
            let (snapshot, observed) = capture(
                self.store_ref(),
                self.home_id(),
                context,
                project,
                &queue,
                None,
            )
            .map_err(query_error)?;
            if let Some(mut tracker) =
                visible(&snapshot, context.actor().as_str()).map_err(query_error)?
            {
                tracker.can_complete &=
                    crate::federation::require_project_writes_available(self.store_ref(), project)
                        .is_ok();
                result.push(tracker);
            }
            basis = basis.combine(observed).map_err(query_error)?;
        }
        // Discovery is only a projection. Reject a changed authority observation
        // before returning even when every tracker was filtered out.
        let mut writer = self.store_ref().sibling().map_err(query_error)?;
        writer
            .with_dispatch_basis(&basis, || result)
            .map_err(query_error)
    }

    /// Read one actual queue under its original current grants and project key.
    /// It deliberately cannot create or replace missing native storage.
    pub fn read_project_tracker_backlog(
        &self,
        context: &AuthenticatedActionContext,
        project: &str,
        queue: &str,
    ) -> Result<ProjectTrackerBacklog, String> {
        let (snapshot, basis) = capture(
            self.store_ref(),
            self.home_id(),
            context,
            project,
            queue,
            None,
        )
        .map_err(query_error)?;
        let mut tracker = visible(&snapshot, context.actor().as_str())
            .map_err(query_error)?
            .ok_or("tracker requires a current recipient-specific read grant")?;
        tracker.can_complete &=
            crate::federation::require_project_writes_available(self.store_ref(), project).is_ok();
        let key = self.workflow_key(project, &tracker.workspace_id, false)?;
        let protection =
            WorkflowProtection::new(&tracker.workspace_id, key.clone()).map_err(query_error)?;
        let storage = self.workflow_storage(&tracker.workspace_id)?;
        let mut writer = self.store_ref().sibling().map_err(query_error)?;
        let issues = writer
            .with_dispatch_basis(&basis, || {
                key.retain(|| {
                    let stores = storage
                        .open_existing_protected(&protection)
                        .map_err(|error| std::io::Error::other(query_error(error)))?;
                    // The owner filters the queue in SQL before materializing payloads.
                    // Product writers are excluded through the item/subject resolution.
                    stores
                        .runtime
                        .items
                        .list_items(Some(queue), None)
                        .and_then(|items| {
                            let histories = issue_histories(&stores.runtime.items.export_events()?);
                            items
                                .into_iter()
                                .map(|item| {
                                    let subject_id = stores
                                        .runtime
                                        .items
                                        .subject_content_id(&item.id)?
                                        .ok_or_else(|| {
                                            whipplescript_store::StoreError::Conflict(
                                                "tracker issue has no permanent subject".into(),
                                            )
                                        })?;
                                    let history = histories.get(&subject_id);
                                    let claim_expires_at = item
                                        .claimed_by
                                        .as_ref()
                                        .and(history.and_then(|h| h.lease.as_ref()))
                                        .and_then(|(_, expires)| expires.clone());
                                    let (closed_by, closing_summary) = history
                                        .and_then(|h| h.closed.clone())
                                        .filter(|_| item.status == "closed")
                                        .unwrap_or_default();
                                    Ok(ProjectTrackerIssue {
                                        subject_id,
                                        id: item.id,
                                        title: item.title,
                                        body: item.body,
                                        status: item.status,
                                        assigned_to: item.assigned_to,
                                        claimed_by: item.claimed_by,
                                        claim_expires_at,
                                        closed_by,
                                        closing_summary,
                                        filed_by: item.filed_by,
                                        labels: item.labels,
                                        created_at: item.created_at,
                                        updated_at: item.updated_at,
                                    })
                                })
                                .collect::<whipplescript_store::StoreResult<Vec<_>>>()
                        })
                        .map_err(|error| std::io::Error::other(query_error(error)))
                })
            })
            .map_err(query_error)?
            .map_err(query_error)?;
        Ok(ProjectTrackerBacklog { tracker, issues })
    }
}
