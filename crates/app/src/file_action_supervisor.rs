//! Event-driven native dispatch discovery. Durable grants/outbox facts own the
//! work; wakeups and notices are disposable process-local hints.
use super::*;
use crate::{LockUnpoisoned, SharedWorkbench};
use std::{
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::{mpsc, watch};

/// Trusted host limits. No HTTP handler chooses storage or discovery limits.
#[derive(Clone, Copy)]
pub struct NativeEditorSupervisorConfig {
    pub storage: NativeActionStorageConfig,
    pub discovery_page_size: NonZeroUsize,
}

/// Internal wake/result hint, never a public disclosure or replacement for an
/// authenticated read of retained product/runtime evidence.
#[derive(Debug, PartialEq, Eq)]
pub struct NativeEditorDispatchNotice {
    pub grant_ref: String,
    pub outcome: NativeEditorDispatchOutcome,
}

#[derive(Debug, PartialEq, Eq)]
pub enum NativeEditorDispatchOutcome {
    Saved {
        product_command_id: String,
        cut_id: String,
        replayed: bool,
    },
    Inactive,
    Unresolved,
    /// May follow a committed write. It does not assert that nothing happened.
    NeedsAttention {
        detail: String,
    },
}

struct SupervisorLease {
    running: Arc<AtomicBool>,
    cancelled: AtomicBool,
}
impl Drop for SupervisorLease {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
    }
}

struct SupervisorGuard(Arc<SupervisorLease>);
impl Drop for SupervisorGuard {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Release);
    }
}

fn stopping(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow() || shutdown.has_changed().is_err()
}

fn drive_candidate(
    wb: &SharedWorkbench,
    grant_ref: &str,
    config: NativeEditorSupervisorConfig,
    shutdown: &watch::Receiver<bool>,
    lease: &SupervisorLease,
) -> Result<Option<NativeEditorDispatchOutcome>, String> {
    let stopped = || stopping(shutdown) || lease.cancelled.load(Ordering::Acquire);
    if stopped() {
        return Ok(None);
    }
    let (storage, mut driver) = {
        let mut wb = wb.lock_unpoisoned();
        let Some(command) = wb.discover_editor_file_save_dispatch(grant_ref)? else {
            return Ok(Some(NativeEditorDispatchOutcome::Inactive));
        };
        if stopped() {
            return Ok(None);
        }
        let storage = wb.open_native_action_storage(config.storage)?;
        let driver = wb.start_editor_file_save_driver(&storage, &command, grant_ref)?;
        (storage, driver)
    };
    // The fixed v1 save performs one input read, one target write and one result
    // step. A changed workflow must qualify a new bound, never spin indefinitely.
    for _ in 0..3 {
        let progress = {
            let mut wb = wb.lock_unpoisoned();
            if stopped() {
                return Ok(None);
            }
            wb.step_editor_file_save_driver(&storage, &mut driver)?
        };
        match progress {
            NativeEditorSaveProgress::Advanced => {}
            NativeEditorSaveProgress::Saved(result) => {
                return Ok(Some(NativeEditorDispatchOutcome::Saved {
                    product_command_id: result.result.product_command_id,
                    cut_id: result.result.cut_id,
                    replayed: result.replayed,
                }));
            }
            NativeEditorSaveProgress::Unresolved(_) => {
                return Ok(Some(NativeEditorDispatchOutcome::Unresolved));
            }
        }
    }
    Err("native save exceeded its fixed workflow step bound; inspect retained evidence".into())
}

/// Run one Home's supervisor until shutdown or a discovery/storage failure.
/// Startup always discovers retained grants. Grant commits wake another pass;
/// notifications cannot select commands or confer authority. Production callers
/// must qualify rollout budgets before activating this host service.
///
/// An explicit shutdown waits for the current bounded step. If this future is
/// dropped, its blocking job still retains the process-local exclusion until
/// that job exits. Runtime ownership fencing remains the cross-process boundary.
pub async fn supervise_native_editor_dispatch(
    wb: SharedWorkbench,
    config: NativeEditorSupervisorConfig,
    mut shutdown: watch::Receiver<bool>,
    notices: mpsc::Sender<NativeEditorDispatchNotice>,
) -> Result<(), String> {
    let (changed, running) = {
        let wb = wb.lock_unpoisoned();
        (
            Arc::clone(&wb.native_editor_dispatch_changed),
            Arc::clone(&wb.native_editor_dispatch_running),
        )
    };
    running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "native editor supervisor is already running")?;
    let lease = Arc::new(SupervisorLease {
        running,
        cancelled: AtomicBool::new(false),
    });
    let _guard = SupervisorGuard(Arc::clone(&lease));
    loop {
        let mut after: Option<String> = None;
        loop {
            if stopping(&shutdown) {
                return Ok(());
            }
            let worker_wb = Arc::clone(&wb);
            let worker_lease = Arc::clone(&lease);
            let page = tokio::task::spawn_blocking(move || {
                let _lease = worker_lease;
                worker_wb
                    .lock_unpoisoned()
                    .store_ref()
                    .scope_ids_with_kind(
                        dispatch_grant::GRANT_KIND,
                        after.as_deref(),
                        config.discovery_page_size,
                    )
                    .map_err(|e| format!("{e:?}"))
            })
            .await
            .map_err(|_| "native dispatch discovery worker failed")??;
            if page.is_empty() {
                break;
            }
            after = page.last().cloned();
            for grant_ref in page {
                if stopping(&shutdown) {
                    return Ok(());
                }
                let worker_wb = Arc::clone(&wb);
                let worker_lease = Arc::clone(&lease);
                let worker_shutdown = shutdown.clone();
                let worker_grant = grant_ref.clone();
                let outcome = tokio::task::spawn_blocking(move || {
                    drive_candidate(
                        &worker_wb,
                        &worker_grant,
                        config,
                        &worker_shutdown,
                        &worker_lease,
                    )
                })
                .await
                .map_err(|_| "native dispatch worker failed; inspect retained evidence")?;
                let outcome = match outcome {
                    Ok(Some(outcome)) => outcome,
                    Ok(None) => return Ok(()),
                    Err(detail) => NativeEditorDispatchOutcome::NeedsAttention { detail },
                };
                // No receiver or a full channel cannot withhold durable saving.
                let _ = notices.try_send(NativeEditorDispatchNotice { grant_ref, outcome });
            }
        }
        tokio::select! {
            _ = changed.notified() => {}
            _ = shutdown.changed() => {
                if stopping(&shutdown) { return Ok(()); }
            }
        }
    }
}

#[cfg(test)]
#[path = "file_action_supervisor_tests.rs"]
mod tests;
