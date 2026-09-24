//! The Home's folder-whip supervisor (DR-0191). Retained launch commands own
//! the work; wake hints and notices are disposable process-local signals. It
//! steps a run with the same native step a caller would, under its launcher's
//! standing, and adds no workflow semantics of its own.
use super::*;
use crate::{identity::AuthenticatedActionContext, LockUnpoisoned, SharedWorkbench};
use gaugedesk_core::ids::AuthorityId;
use gaugedesk_whip_runtime::host_actions::action_result::ActionInstanceStatus;
use std::{
    collections::BTreeSet,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{broadcast, mpsc, watch};

/// The event kind every product action admission is committed under. Launch
/// scopes are the ones [`launch_scope_parts`] recognises.
pub(super) const ADMISSION_KIND: &str = "host_action_admission_v1";

/// Trusted host limits. No HTTP handler chooses them.
#[derive(Clone, Copy)]
pub struct ProjectWorkflowSupervisorConfig {
    pub limits: ProjectWorkflowLimits,
    pub discovery_page_size: NonZeroUsize,
    /// Steps one wake may take for one run. A run that is still executing
    /// effects when this is spent is picked up again by the next wake.
    pub steps_per_wake: usize,
    /// How often every live run is revisited without a hint, so an expired
    /// wait takes its native failure path and restored standing resumes.
    pub sweep: Duration,
}

/// Internal wake/result hint, never a disclosure or a substitute for an
/// authenticated read of the run.
#[derive(Debug)]
pub struct ProjectWorkflowNotice {
    pub scope: String,
    pub outcome: ProjectWorkflowOutcome,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProjectWorkflowOutcome {
    /// Waiting on something outside the run, such as an issue closing.
    Parked,
    /// Completed, failed or cancelled; it will not be stepped again.
    Finished(String),
    /// Refused or failed this time: lost standing, a pending handoff, or a
    /// fault. It is retried on the next wake and never treated as finished.
    NeedsAttention { detail: String },
}

/// Hint that something every launch in `project` might be waiting on changed.
pub(crate) fn project_hint(project: &str) -> String {
    format!("project::{project}")
}

impl Workbench {
    /// Advance one retained launch under its launcher's standing (DR-0191).
    /// The authority is built here from the committed scope, never from a
    /// request, and every step still revalidates it in full.
    pub(crate) fn step_project_workflow_unattended(
        &mut self,
        scope: &str,
        limits: ProjectWorkflowLimits,
    ) -> Result<ProjectWorkflowStep, String> {
        let (project, actor, request) =
            launch_scope_parts(scope).ok_or("not a workflow launch scope")?;
        let context = AuthenticatedActionContext::project_workflow_invocation(
            AuthorityId::new(actor),
            scope.to_owned(),
        );
        self.step_project_workflow(&context, &project, &request, limits)
    }

    /// Wake the supervisor for one launch or a whole project. Best effort: a
    /// missed hint is covered by the next sweep.
    pub(crate) fn hint_project_workflows(&self, hint: String) {
        let _ = self.project_workflow_changed.send(hint);
    }
}

struct Lease(Arc<AtomicBool>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn stopping(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow() || shutdown.has_changed().is_err()
}

fn finished(status: &ActionInstanceStatus) -> Option<String> {
    match status {
        ActionInstanceStatus::Completed => Some("completed".into()),
        ActionInstanceStatus::Failed => Some("failed".into()),
        ActionInstanceStatus::Cancelled => Some("cancelled".into()),
        ActionInstanceStatus::Running | ActionInstanceStatus::Paused => None,
    }
}

/// Step one run until it waits, finishes or spends its wake budget.
fn drive(
    wb: &SharedWorkbench,
    scope: &str,
    config: ProjectWorkflowSupervisorConfig,
    shutdown: &watch::Receiver<bool>,
) -> Option<ProjectWorkflowOutcome> {
    for _ in 0..config.steps_per_wake.max(1) {
        if stopping(shutdown) {
            return None;
        }
        let step = wb
            .lock_unpoisoned()
            .step_project_workflow_unattended(scope, config.limits);
        let step = match step {
            Ok(step) => step,
            Err(detail) => return Some(ProjectWorkflowOutcome::NeedsAttention { detail }),
        };
        if step.executed_effect.is_some() || step.recovered_effect.is_some() {
            // A reference wakes clients; the issue itself stays behind its own
            // authenticated read, as it does after a human completion.
            if let Some((project, _, _)) = launch_scope_parts(scope) {
                wb.lock_unpoisoned()
                    .notify_library_changed("project_tracker", &project, "upsert");
            }
        }
        if let Some(status) = finished(&step.snapshot.instance_status) {
            return Some(ProjectWorkflowOutcome::Finished(status));
        }
        if step.executed_effect.is_none() && step.recovered_effect.is_none() {
            return Some(ProjectWorkflowOutcome::Parked);
        }
    }
    // Still executing: the next wake continues it rather than this one spinning.
    Some(ProjectWorkflowOutcome::Parked)
}

/// Every retained launch scope, optionally limited to one project.
fn discover(
    wb: &SharedWorkbench,
    project: Option<&str>,
    page_size: NonZeroUsize,
) -> Result<Vec<String>, String> {
    let mut scopes = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let page = wb
            .lock_unpoisoned()
            .store_ref()
            .scope_ids_with_kind(ADMISSION_KIND, after.as_deref(), page_size)
            .map_err(|e| format!("{e:?}"))?;
        let Some(last) = page.last().cloned() else {
            return Ok(scopes);
        };
        scopes.extend(page.into_iter().filter(|scope| {
            launch_scope_parts(scope)
                .is_some_and(|(owner, _, _)| project.is_none_or(|p| p == owner))
        }));
        after = Some(last);
    }
}

/// Run this Home's folder-whip supervisor until shutdown. Startup and every
/// sweep rediscover retained launches; hints only narrow what to look at next.
/// A run that finished is remembered for this process and not stepped again.
pub async fn supervise_project_workflows(
    wb: SharedWorkbench,
    config: ProjectWorkflowSupervisorConfig,
    mut shutdown: watch::Receiver<bool>,
    notices: mpsc::Sender<ProjectWorkflowNotice>,
) -> Result<(), String> {
    let (mut changed, running) = {
        let wb = wb.lock_unpoisoned();
        (
            wb.project_workflow_changed.subscribe(),
            Arc::clone(&wb.project_workflow_running),
        )
    };
    running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "project workflow supervisor is already running")?;
    let _lease = Lease(running);
    let mut done: BTreeSet<String> = BTreeSet::new();
    let mut sweep = tokio::time::interval(config.sweep);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // `None` is a full sweep; the first tick fires immediately, which is the
    // startup rediscovery.
    let mut next: Option<String> = None;
    let mut due = false;
    loop {
        if due {
            due = false;
            let worker_wb = Arc::clone(&wb);
            let hint = next.take();
            let scopes = tokio::task::spawn_blocking(move || match hint {
                Some(hint) if launch_scope_parts(&hint).is_some() => Ok(vec![hint]),
                Some(hint) => discover(
                    &worker_wb,
                    hint.strip_prefix("project::"),
                    config.discovery_page_size,
                ),
                None => discover(&worker_wb, None, config.discovery_page_size),
            })
            .await
            .map_err(|_| "project workflow discovery worker failed")??;
            for scope in scopes {
                if stopping(&shutdown) {
                    return Ok(());
                }
                if done.contains(&scope) {
                    continue;
                }
                let worker_wb = Arc::clone(&wb);
                let worker_shutdown = shutdown.clone();
                let worker_scope = scope.clone();
                let outcome = tokio::task::spawn_blocking(move || {
                    drive(&worker_wb, &worker_scope, config, &worker_shutdown)
                })
                .await
                .map_err(|_| "project workflow worker failed; inspect retained evidence")?;
                let Some(outcome) = outcome else {
                    return Ok(());
                };
                if matches!(outcome, ProjectWorkflowOutcome::Finished(_)) {
                    done.insert(scope.clone());
                }
                // No receiver or a full channel cannot withhold execution.
                let _ = notices.try_send(ProjectWorkflowNotice { scope, outcome });
            }
        }
        tokio::select! {
            _ = sweep.tick() => { next = None; due = true; }
            hint = changed.recv() => match hint {
                Ok(hint) => { next = Some(hint); due = true; }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // Hints were lost; a full sweep covers every launch.
                    changed = changed.resubscribe();
                    next = None;
                    due = true;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    // The workbench value was replaced in place (the debug
                    // reset route does this), taking its hint channel with it.
                    // Listen to the one now there and sweep, since hints sent
                    // in between are gone; retained launches are the truth.
                    changed = wb.lock_unpoisoned().project_workflow_changed.subscribe();
                    next = None;
                    due = true;
                }
            },
            _ = shutdown.changed() => {
                if stopping(&shutdown) { return Ok(()); }
            }
        }
    }
}
