//! Delegations derived from current work (DR-0312 phase 2, WS-672).
//!
//! A host holds a project's keys only for work that needs them. A member who
//! starts background work — today a folder workflow, the only work that runs
//! with nobody present — hands the host the keys its declaration names, and
//! nothing else. Nobody grants anything and nothing asks: the delegation is
//! derived from the work when it is launched, and read back from that work's
//! committed declaration if it was launched before delegations existed.
//!
//! - **Out of scope fails.** An unattended step runs inside
//!   [`crate::content_vault::act_for`], so the vault refuses any project scope
//!   the delegation does not name, and the run reports what it could not reach.
//! - **Lapse and renewal.** A background delegation lapses 30 days after the
//!   last time a member used the project, and renews whenever one does. A
//!   member uses a project when a request naming it succeeds; see
//!   [`record_member_use`]. Lapsed work pauses, members are told in their task
//!   queue, and it resumes by itself once a member is back.
//! - **The record.** Each project keeps an append-only ledger of what
//!   background work holds which keys, from whose work, when it lapses, every
//!   step that acted unattended, and every refusal. It is plaintext metadata,
//!   because lapse must be decided while nobody who could open the project's
//!   keys is present. Nothing waits on it: writing it is never a gate.
//!
//! A member who is present holds keys through a session instead
//! ([`crate::content_vault::SessionHold`], WS-740): the request middleware
//! here takes the holds, and the vault drops a project's keys once nothing
//! holds it. Until account keys replace the install's custody
//! (WS-674), what a delegation governs is which keys the host opens, not
//! which keys it could open.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{LockUnpoisoned, SharedWorkbench, Workbench};

/// How long a background delegation lasts after the last member use.
pub const LAPSE_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// How finely member use is recorded. A day's use writes at most this many
/// records per project, and a lapse is never early by more than this.
pub const MEMBER_USE_GRANULARITY_MS: u64 = 60 * 60 * 1000;
/// How finely a step that finds its run still waiting is recorded. The
/// supervisor revisits every waiting run each minute; each visit opens the
/// work's keys, and the record says so without a line per minute.
pub const CHECK_GRANULARITY_MS: u64 = 60 * 60 * 1000;
/// How many of a delegation's latest uses and refusals the view returns.
const VIEW_RECENT: usize = 20;
/// How many ended delegations the view returns.
const VIEW_ENDED: usize = 50;

const RECORD_KIND: &str = "key_delegation";

/// The scope holding `project`'s delegation ledger.
pub(crate) fn ledger_scope(project: &str) -> String {
    format!("project::{project}::key-delegations")
}

/// Wall-clock milliseconds, the time every ledger event carries.
pub(crate) fn now_ms() -> u64 {
    crate::account::session_now_ms()
}

/// The work a delegation was derived from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DelegatedWork {
    /// A folder workflow launch: its retained launch scope and its source.
    Workflow {
        launch: String,
        target: String,
        path: String,
    },
}

/// The keys one piece of background work holds, and where they came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDelegation {
    pub id: String,
    pub project: String,
    pub work: DelegatedWork,
    /// The project scopes whose keys the work's declaration names.
    pub scopes: BTreeSet<String>,
    /// The member whose work this was derived from.
    pub granted_from: String,
    pub granted_at_ms: u64,
}

/// One ledger event. Lapse is decided from these and the clock, so a lapse
/// event records that a step found the work lapsed, not that it lapsed then.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Event {
    Derived(KeyDelegation),
    MemberUsed {
        at_ms: u64,
    },
    Used {
        delegation: String,
        at_ms: u64,
        effect: String,
    },
    /// A step found the run still waiting. It opened the work's keys to look,
    /// so it is a use, recorded at most once per [`CHECK_GRANULARITY_MS`].
    Checked {
        delegation: String,
        at_ms: u64,
    },
    Refused {
        delegation: String,
        at_ms: u64,
        scope: String,
    },
    Lapsed {
        delegation: String,
        at_ms: u64,
    },
    Ended {
        delegation: String,
        at_ms: u64,
        outcome: String,
    },
}

/// What a delegation's ledger says about it.
#[derive(Clone, Debug)]
pub struct DelegationRecord {
    pub delegation: KeyDelegation,
    pub ended: Option<(u64, String)>,
    pub lapses: Vec<u64>,
    pub uses: Vec<(u64, String)>,
    pub checks: Vec<u64>,
    pub refusals: Vec<(u64, String)>,
}

/// Whether a delegation still hands the host its keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DelegationState {
    Held { expires_at_ms: u64 },
    Lapsed { since_ms: u64 },
    Ended,
}

impl DelegationRecord {
    /// When the delegation lapses without another member use.
    pub fn expires_at_ms(&self, last_member_use_ms: Option<u64>) -> u64 {
        last_member_use_ms
            .unwrap_or(0)
            .max(self.delegation.granted_at_ms)
            .saturating_add(LAPSE_MS)
    }

    pub fn state(&self, last_member_use_ms: Option<u64>, now_ms: u64) -> DelegationState {
        if self.ended.is_some() {
            return DelegationState::Ended;
        }
        let expires_at_ms = self.expires_at_ms(last_member_use_ms);
        if now_ms >= expires_at_ms {
            DelegationState::Lapsed {
                since_ms: expires_at_ms,
            }
        } else {
            DelegationState::Held { expires_at_ms }
        }
    }
}

/// A project's delegation ledger, folded.
#[derive(Clone, Debug, Default)]
pub struct ProjectDelegations {
    pub last_member_use_ms: Option<u64>,
    pub delegations: BTreeMap<String, DelegationRecord>,
}

impl ProjectDelegations {
    fn fold(records: &[String]) -> Self {
        let mut folded = Self::default();
        for record in records {
            let Ok(event) = serde_json::from_str::<Event>(record) else {
                // A newer build's event: what this build understands still stands.
                tracing::debug!("key delegation ledger: skipped an event this build cannot read");
                continue;
            };
            match event {
                Event::Derived(delegation) => {
                    folded
                        .delegations
                        .entry(delegation.id.clone())
                        .or_insert(DelegationRecord {
                            delegation,
                            ended: None,
                            lapses: Vec::new(),
                            uses: Vec::new(),
                            checks: Vec::new(),
                            refusals: Vec::new(),
                        });
                }
                Event::MemberUsed { at_ms } => {
                    folded.last_member_use_ms =
                        Some(folded.last_member_use_ms.unwrap_or(0).max(at_ms));
                }
                Event::Used {
                    delegation,
                    at_ms,
                    effect,
                } => {
                    if let Some(record) = folded.delegations.get_mut(&delegation) {
                        record.uses.push((at_ms, effect));
                    }
                }
                Event::Checked { delegation, at_ms } => {
                    if let Some(record) = folded.delegations.get_mut(&delegation) {
                        record.checks.push(at_ms);
                    }
                }
                Event::Refused {
                    delegation,
                    at_ms,
                    scope,
                } => {
                    if let Some(record) = folded.delegations.get_mut(&delegation) {
                        record.refusals.push((at_ms, scope));
                    }
                }
                Event::Lapsed { delegation, at_ms } => {
                    if let Some(record) = folded.delegations.get_mut(&delegation) {
                        record.lapses.push(at_ms);
                    }
                }
                Event::Ended {
                    delegation,
                    at_ms,
                    outcome,
                } => {
                    if let Some(record) = folded.delegations.get_mut(&delegation) {
                        record.ended.get_or_insert((at_ms, outcome));
                    }
                }
            }
        }
        folded
    }
}

/// Whether background work may act now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Standing {
    Held(KeyDelegation),
    /// Paused until a member uses the project.
    Lapsed(String),
    /// Finished, with its outcome. It holds nothing.
    Ended(String),
}

/// The delegation id of a folder workflow launch: one launch, one delegation.
pub(crate) fn workflow_delegation_id(launch: &str) -> String {
    crate::org::sha256_hex(&format!("workflow-delegation:{launch}"))
}

impl Workbench {
    /// Hold `project` for the session running this code, lingering after it:
    /// for a request whose path names no project but whose work uses one,
    /// such as starting a tutorial (WS-740). Public so a composition's own
    /// handler, and its tests, can hold a project the way this crate's
    /// handlers do; it is never a way to act with nobody present.
    pub fn hold_for_session(&self, project: &str) -> Option<crate::content_vault::SessionHold> {
        let hold = self.content_vault.as_ref()?.hold(project);
        hold.linger();
        Some(hold)
    }

    /// Open a member's session on `project` for the rest of a test that
    /// drives the workbench directly, as a request handler would within one.
    #[cfg(test)]
    pub(crate) fn hold_session_for_tests(&mut self, project: &str) {
        if let Some(hold) = self.content_vault.as_ref().map(|vault| vault.hold(project)) {
            self.test_session_holds.push(hold);
        }
    }

    /// The member-use throttle every composition of this workbench shares.
    pub fn member_use(&self) -> MemberUse {
        self.member_use.clone()
    }

    /// `project`'s delegation ledger.
    pub(crate) fn project_delegations(&self, project: &str) -> Result<ProjectDelegations, String> {
        let records = self
            .store_ref()
            .records(&ledger_scope(project), RECORD_KIND)
            .map_err(|error| format!("{error:?}"))?;
        Ok(ProjectDelegations::fold(&records))
    }

    fn append_delegation_event(&mut self, project: &str, event: &Event) -> Result<(), String> {
        let payload = serde_json::to_string(event).map_err(|error| error.to_string())?;
        self.store_mut()
            .append_record(&ledger_scope(project), RECORD_KIND, &payload)
            .map(|_| ())
            .map_err(|error| format!("{error:?}"))
    }

    /// The delegation a retained workflow launch holds, derived from its
    /// committed declaration. Deriving it again returns the one recorded.
    pub(crate) fn derive_workflow_delegation(
        &mut self,
        launch: &str,
        now_ms: u64,
    ) -> Result<KeyDelegation, String> {
        let declaration = self.workflow_launch_declaration(launch)?;
        let id = workflow_delegation_id(launch);
        if let Some(record) = self
            .project_delegations(&declaration.project)?
            .delegations
            .remove(&id)
        {
            return Ok(record.delegation);
        }
        let delegation = KeyDelegation {
            id,
            project: declaration.project,
            work: DelegatedWork::Workflow {
                launch: launch.to_owned(),
                target: declaration.target,
                path: declaration.path,
            },
            scopes: declaration.scopes,
            granted_from: declaration.launcher,
            granted_at_ms: now_ms,
        };
        self.append_delegation_event(&delegation.project, &Event::Derived(delegation.clone()))?;
        Ok(delegation)
    }

    /// Whether the background work of `launch` holds its keys at `now_ms`,
    /// deriving its delegation if it has none yet. A lapse is recorded once
    /// per lapse, so the record shows when each was found.
    pub(crate) fn workflow_standing(
        &mut self,
        launch: &str,
        now_ms: u64,
    ) -> Result<Standing, String> {
        let delegation = self.derive_workflow_delegation(launch, now_ms)?;
        let ledger = self.project_delegations(&delegation.project)?;
        let record = ledger
            .delegations
            .get(&delegation.id)
            .ok_or("the work's delegation was not recorded")?;
        match record.state(ledger.last_member_use_ms, now_ms) {
            DelegationState::Held { .. } => Ok(Standing::Held(delegation)),
            DelegationState::Ended => Ok(Standing::Ended(
                record
                    .ended
                    .clone()
                    .map(|(_, outcome)| outcome)
                    .unwrap_or_default(),
            )),
            DelegationState::Lapsed { since_ms } => {
                if !record.lapses.iter().any(|&at| at >= since_ms) {
                    self.append_delegation_event(
                        &delegation.project,
                        &Event::Lapsed {
                            delegation: delegation.id.clone(),
                            at_ms: now_ms,
                        },
                    )?;
                }
                Ok(Standing::Lapsed(delegation.project))
            }
        }
    }

    /// The delegation an unattended step of `launch` may act under, or why it
    /// may not act: the work ended, or it lapsed.
    pub(crate) fn held_workflow_delegation(
        &mut self,
        launch: &str,
        now_ms: u64,
    ) -> Result<KeyDelegation, String> {
        match self.workflow_standing(launch, now_ms)? {
            Standing::Held(delegation) => Ok(delegation),
            Standing::Ended(_) => Err("this work has ended and holds no keys".into()),
            Standing::Lapsed(project) => Err(format!(
                "background work paused: no member has used project {project} in 30 days; \
                 it resumes when one does"
            )),
        }
    }

    /// Record that background work acted unattended.
    pub(crate) fn record_unattended_use(
        &mut self,
        delegation: &KeyDelegation,
        effect: &str,
        now_ms: u64,
    ) {
        let event = Event::Used {
            delegation: delegation.id.clone(),
            at_ms: now_ms,
            effect: effect.to_owned(),
        };
        if let Err(error) = self.append_delegation_event(&delegation.project, &event) {
            tracing::warn!(%error, project = %delegation.project, "could not record an unattended use");
        }
    }

    /// Record that background work looked at its run and found it waiting,
    /// at most once per [`CHECK_GRANULARITY_MS`].
    pub(crate) fn record_unattended_check(&mut self, delegation: &KeyDelegation, now_ms: u64) {
        let last = self
            .project_delegations(&delegation.project)
            .ok()
            .and_then(|ledger| {
                ledger
                    .delegations
                    .get(&delegation.id)
                    .and_then(|record| record.checks.last().copied())
            });
        if last.is_some_and(|last| now_ms < last.saturating_add(CHECK_GRANULARITY_MS)) {
            return;
        }
        let event = Event::Checked {
            delegation: delegation.id.clone(),
            at_ms: now_ms,
        };
        if let Err(error) = self.append_delegation_event(&delegation.project, &event) {
            tracing::warn!(%error, project = %delegation.project, "could not record an unattended check");
        }
    }

    /// Record every scope the vault refused background work.
    pub(crate) fn record_delegation_refusals(
        &mut self,
        delegation: &KeyDelegation,
        scopes: &BTreeSet<String>,
        now_ms: u64,
    ) {
        for scope in scopes {
            let event = Event::Refused {
                delegation: delegation.id.clone(),
                at_ms: now_ms,
                scope: scope.clone(),
            };
            if let Err(error) = self.append_delegation_event(&delegation.project, &event) {
                tracing::warn!(%error, project = %delegation.project, "could not record a refusal");
            }
        }
    }

    /// The work finished: its delegation hands the host nothing more.
    pub(crate) fn end_delegation(
        &mut self,
        delegation: &KeyDelegation,
        outcome: &str,
        now_ms: u64,
    ) {
        let ended = self
            .project_delegations(&delegation.project)
            .ok()
            .and_then(|ledger| {
                ledger
                    .delegations
                    .get(&delegation.id)
                    .map(|r| r.ended.is_some())
            })
            .unwrap_or(false);
        if ended {
            return;
        }
        let event = Event::Ended {
            delegation: delegation.id.clone(),
            at_ms: now_ms,
            outcome: outcome.to_owned(),
        };
        if let Err(error) = self.append_delegation_event(&delegation.project, &event) {
            tracing::warn!(%error, project = %delegation.project, "could not record that work ended");
        }
    }

    /// A member used `project`: every background delegation in it renews.
    /// Recorded at most once per [`MEMBER_USE_GRANULARITY_MS`].
    pub(crate) fn note_member_use(&mut self, project: &str, now_ms: u64) {
        let last = self
            .project_delegations(project)
            .ok()
            .and_then(|ledger| ledger.last_member_use_ms);
        if last.is_some_and(|last| now_ms < last.saturating_add(MEMBER_USE_GRANULARITY_MS)) {
            return;
        }
        let paused = self.lapsed_background_work(project, now_ms);
        if let Err(error) =
            self.append_delegation_event(project, &Event::MemberUsed { at_ms: now_ms })
        {
            tracing::warn!(%error, %project, "could not record member use");
            return;
        }
        if paused > 0 {
            // Paused work resumes now rather than at the next sweep.
            self.hint_project_workflows(crate::project_workflow::project_hint(project));
        }
    }

    /// How much of `project`'s background work is paused because it lapsed.
    pub(crate) fn lapsed_background_work(&self, project: &str, now_ms: u64) -> usize {
        let Ok(ledger) = self.project_delegations(project) else {
            return 0;
        };
        ledger
            .delegations
            .values()
            .filter(|record| {
                matches!(
                    record.state(ledger.last_member_use_ms, now_ms),
                    DelegationState::Lapsed { .. }
                )
            })
            .count()
    }

    /// What a project scope is, in words a member reads.
    fn scope_label(&self, project: &str, scope: &str) -> String {
        if let Some(chat) = self.library.chats.get(scope) {
            return if crate::chat_title::is_system_title(&chat.title) {
                "an untitled chat".into()
            } else {
                format!("chat “{}”", chat.title)
            };
        }
        if crate::project_workflow::content_scope(project).is_ok_and(|workflow| workflow == scope) {
            return "workflow storage".into();
        }
        if scope == crate::account::project_scope(project) {
            return "project credentials".into();
        }
        scope.to_owned()
    }

    /// The project's record of what background work holds which keys.
    pub(crate) fn project_delegations_value(
        &self,
        project: &str,
        now_ms: u64,
    ) -> Result<serde_json::Value, String> {
        let ledger = self.project_delegations(project)?;
        let mut held = Vec::new();
        let mut ended = Vec::new();
        for record in ledger.delegations.values() {
            let state = record.state(ledger.last_member_use_ms, now_ms);
            let delegation = &record.delegation;
            let DelegatedWork::Workflow { target, path, .. } = &delegation.work;
            let target_name = self
                .library
                .work_targets
                .get(target)
                .map(|target| target.name.clone());
            let recent = |items: &[(u64, String)]| -> Vec<(u64, String)> {
                items.iter().rev().take(VIEW_RECENT).cloned().collect()
            };
            let mut value = serde_json::json!({
                "id": delegation.id,
                "work": {
                    "kind": "workflow",
                    "target": target,
                    "target_name": target_name,
                    "path": path,
                },
                "keys": delegation.scopes.iter().map(|scope| serde_json::json!({
                    "scope": scope,
                    "label": self.scope_label(project, scope),
                })).collect::<Vec<_>>(),
                "granted_from": delegation.granted_from,
                "granted_at_ms": delegation.granted_at_ms,
                "use_count": record.uses.len(),
                "last_checked_ms": record.checks.last(),
                "uses": recent(&record.uses).into_iter().map(|(at_ms, effect)| serde_json::json!({
                    "at_ms": at_ms, "effect": effect,
                })).collect::<Vec<_>>(),
                "refusals": recent(&record.refusals).into_iter().map(|(at_ms, scope)| serde_json::json!({
                    "at_ms": at_ms,
                    "label": self.scope_label(project, &scope),
                    "scope": scope,
                })).collect::<Vec<_>>(),
                "lapsed_at_ms": record.lapses.last(),
            });
            match state {
                DelegationState::Held { expires_at_ms } => {
                    value["state"] = "held".into();
                    value["expires_at_ms"] = expires_at_ms.into();
                    held.push((delegation.granted_at_ms, value));
                }
                DelegationState::Lapsed { since_ms } => {
                    value["state"] = "lapsed".into();
                    value["lapsed_since_ms"] = since_ms.into();
                    held.push((delegation.granted_at_ms, value));
                }
                DelegationState::Ended => {
                    let (at_ms, outcome) = record.ended.clone().unwrap_or_default();
                    value["state"] = "ended".into();
                    value["ended"] = serde_json::json!({ "at_ms": at_ms, "outcome": outcome });
                    ended.push((at_ms, value));
                }
            }
        }
        held.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
        ended.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
        Ok(serde_json::json!({
            "project": project,
            "lapse_after_ms": LAPSE_MS,
            "last_member_use_ms": ledger.last_member_use_ms,
            "delegations": held.into_iter().map(|(_, value)| value).collect::<Vec<_>>(),
            "ended": ended.into_iter().take(VIEW_ENDED).map(|(_, value)| value).collect::<Vec<_>>(),
        }))
    }
}

/// `GET /projects/{project}/key-delegations` — what background work holds
/// which of the project's keys, granted from whose work, and when it lapses.
/// Any member of the project may read it.
pub async fn project_key_delegations(
    State(wb): State<SharedWorkbench>,
    Path(project): Path<String>,
    headers: HeaderMap,
) -> Response {
    let wb = wb.lock_unpoisoned();
    if let Err(response) = crate::project_settings_gaugeapp::admit_project(&wb, &headers, &project)
    {
        return *response;
    }
    match wb.project_delegations_value(&project, now_ms()) {
        Ok(value) => Json(value).into_response(),
        Err(error) => {
            tracing::warn!(%project, %error, "key delegation record unavailable");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "The record could not be read" })),
            )
                .into_response()
        }
    }
}

/// Throttles member use before the workbench is locked: a path prefix seen
/// within the granularity has already been counted.
#[derive(Clone, Default)]
pub struct MemberUse {
    recent: Arc<Mutex<HashMap<String, u64>>>,
}

impl MemberUse {
    /// Whether `prefix` is due to be counted at `now_ms`, marking it counted.
    fn due(&self, prefix: &str, now_ms: u64) -> bool {
        let mut recent = self
            .recent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if recent
            .get(prefix)
            .is_some_and(|&seen| now_ms < seen.saturating_add(MEMBER_USE_GRANULARITY_MS))
        {
            return false;
        }
        recent.retain(|_, seen| now_ms < seen.saturating_add(MEMBER_USE_GRANULARITY_MS));
        recent.insert(prefix.to_owned(), now_ms);
        true
    }
}

/// The part of a path that names one thing: `/chats/<id>` of
/// `/chats/<id>/events`. Two requests with one prefix name one project.
fn path_prefix(path: &str) -> String {
    path.split('/').take(3).collect::<Vec<_>>().join("/")
}

/// Whether a request is a member using the project its path names. Every
/// write is. A read is, except the two a personal task queue makes of every
/// project at once to find the caller's own tasks: that is someone looking at
/// their queue, not using any one project, and counting it would renew every
/// project's background work for as long as GaugeDesk is open.
fn counts_as_use(method: &axum::http::Method, path: &str) -> bool {
    if method == axum::http::Method::OPTIONS {
        // A browser's preflight, before anyone has done anything.
        return false;
    }
    if method != axum::http::Method::GET && method != axum::http::Method::HEAD {
        return true;
    }
    let parts: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    !matches!(
        parts.as_slice(),
        ["", "projects", _, "trackers"] | ["", "projects", _, "trackers", _, "tasks"]
    )
}

/// Count a successful request that names a project as a member using it.
/// Called after the response, so a refused request renews nothing.
pub(crate) async fn count_member_use(
    wb: &SharedWorkbench,
    throttle: &MemberUse,
    method: &axum::http::Method,
    path: &str,
    status: StatusCode,
) {
    if !status.is_success() || !counts_as_use(method, path) {
        return;
    }
    let now = now_ms();
    if !throttle.due(&path_prefix(path), now) {
        return;
    }
    let wb = wb.clone();
    let path = path.to_owned();
    let counted = tokio::task::spawn_blocking(move || {
        let mut wb = wb.lock_unpoisoned();
        if let Some(project) = wb.scope_project_of_path(&path) {
            wb.note_member_use(&project, now);
        }
    })
    .await;
    if let Err(error) = counted {
        tracing::warn!(%error, "member use was not counted");
    }
}

/// Middleware that counts member use (DR-0312): a request naming a project
/// that its composition admitted and answered successfully renews every
/// background delegation in that project.
pub async fn record_member_use(
    State((wb, throttle)): State<(SharedWorkbench, MemberUse)>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let (method, path) = (request.method().clone(), request.uri().path().to_owned());
    let holds = session_holds(&wb, request.headers(), &method, &path);
    let response = next.run(request).await;
    count_member_use(&wb, &throttle, &method, &path, response.status()).await;
    hold_while_sent(response, holds)
}

/// The reads that read across every project their caller can see — search,
/// the task queue, notices — and so use each of those projects' keys.
fn reads_across_projects(method: &axum::http::Method, path: &str) -> bool {
    method == axum::http::Method::GET
        && (matches!(
            path,
            "/search" | "/tasks" | "/notices" | "/console/review-count"
        ) || path.starts_with("/tutorials/"))
}

/// The session holds a request takes (WS-740): the project its path names,
/// or, for a read across projects, every project its caller can see. Taken
/// inside a composition's own admission, so a request that reaches here has
/// been authenticated by it.
pub(crate) fn session_holds(
    wb: &SharedWorkbench,
    headers: &HeaderMap,
    method: &axum::http::Method,
    path: &str,
) -> Vec<crate::content_vault::SessionHold> {
    if method == axum::http::Method::OPTIONS {
        return Vec::new();
    }
    let wb = wb.lock_unpoisoned();
    let Some(vault) = wb.content_vault.clone() else {
        return Vec::new();
    };
    // A member's authoring of an Agent placed in a shared project — its edit
    // chats, previews and settings assistant — uses that project's keys, for
    // the project's credentials it runs on (DR-0453).
    let authoring = crate::net_http::bearer(headers)
        .and_then(|token| wb.resolve_account_session(token))
        .and_then(|(account, _)| wb.member_authoring_project_of_path(path, &account));
    let mut holds: Vec<_> = wb
        .scope_project_of_path(path)
        .into_iter()
        .chain(authoring)
        .map(|project| vault.hold(&project))
        .collect();
    if !holds.is_empty() || !reads_across_projects(method, path) {
        holds.dedup_by(|a, b| a.project() == b.project());
        return holds;
    }
    let visibility = wb.project_visibility_in(
        crate::net_http::bearer(headers),
        &crate::workbench_auth::req_scope(headers),
    );
    wb.library
        .projects
        .values()
        .filter(|project| project.op == crate::library::RecordOp::Upsert)
        .filter(|project| visibility.allows(&project.id))
        .map(|project| vault.hold(&project.id))
        .collect()
}

/// Hold the project `chat` belongs to for work a member started in it, such
/// as a turn: held while the returned holds live and lingering after them.
/// A member's edit chat or preview of an Agent placed in a shared project
/// also holds that project, whose credentials it runs on (DR-0453).
pub(crate) fn hold_chat_project(
    wb: &SharedWorkbench,
    chat: &str,
) -> Vec<crate::content_vault::SessionHold> {
    let wb = wb.lock_unpoisoned();
    let Some(vault) = wb.content_vault.clone() else {
        return Vec::new();
    };
    let authoring = wb
        .chat_member_author(chat)
        .and_then(|author| wb.member_authoring_project_of_chat(chat, &author));
    vault
        .scope_index()
        .project_of(chat)
        .into_iter()
        .chain(authoring)
        .map(|project| {
            let hold = vault.hold(&project);
            hold.linger();
            hold
        })
        .collect()
}

/// Keep `holds` for as long as `response` is being sent, and for the linger
/// after it if it succeeded: the member is connected and using these
/// projects. A stream therefore holds its project while it is connected.
pub(crate) fn hold_while_sent(
    response: Response,
    holds: Vec<crate::content_vault::SessionHold>,
) -> Response {
    if holds.is_empty() {
        return response;
    }
    if response.status().is_success() {
        for hold in &holds {
            hold.linger();
        }
    }
    response.map(|body| crate::content_vault::held_body(body, holds))
}

#[cfg(test)]
#[path = "key_delegation_tests.rs"]
mod tests;
