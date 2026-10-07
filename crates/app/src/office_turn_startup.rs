//! Production office startup under the original task's product/native writers.
//! A startup receipt keeps the original command pending; it grants no execution.
use super::{EngineError, RunCommand, RunPhase, RunState, ServerEvent, TurnForkSnapshot};
use crate::{command_idempotency::ClaimedHttpCommand, LockUnpoisoned, SharedWorkbench};
use gaugedesk_store::{command_dispatch::LifecycleBatch, AdmitError, CommandRecordFact, Store};
use gaugedesk_workspace::{ChatWorkspace, NativeWitnessedTurnTarget, WorkspaceError};
use serde::{Deserialize, Serialize};

pub(crate) struct OfficeTurnContext<'a> {
    pub(crate) wb: &'a SharedWorkbench,
    pub(crate) authority: &'a super::office_authority::OfficeTaskAuthority,
    pub(crate) original: &'a ClaimedHttpCommand,
}

/// Each native saved-result read retains the original staff and HTTP parent.
pub(crate) struct OfficeRecordedRuntimeAccess<'a, 'b> {
    office: &'a OfficeTurnContext<'b>,
    ended: std::sync::atomic::AtomicBool,
}
impl OfficeTurnContext<'_> {
    pub(crate) fn recorded_access(&self) -> OfficeRecordedRuntimeAccess<'_, '_> {
        OfficeRecordedRuntimeAccess {
            office: self,
            ended: std::sync::atomic::AtomicBool::new(false),
        }
    }
}
impl OfficeRecordedRuntimeAccess<'_, '_> {
    fn current(&self) -> Result<(), EngineError> {
        let mut wb = self.office.wb.lock_unpoisoned();
        let authority = self.office.authority.prepare_basis(&wb)?;
        let phase =
            Store::claimed_lifecycle_prefix_scope(self.office.original.command_id(), STARTUP_PHASE);
        let (startup, observed) = wb
            .store_ref()
            .read_for_dispatch(&[self.office.authority.chat(), &phase], |store| {
                require_original_standing(store, self.office)
            })?;
        let basis = authority.combine(observed)?;
        let original = self.office.original;
        wb.store_mut()
            .with_dispatch_record_admission(&basis, |writer| {
                writer.require_pending_claim(
                    original.command_id(),
                    original.scope(),
                    original.key(),
                    original.snapshot(),
                )?;
                startup.require_phase(&writer, original)
            })??;
        Ok(())
    }
}
impl gaugedesk_harness::TurnAccess for OfficeRecordedRuntimeAccess<'_, '_> {
    fn check_current(&self) -> Result<(), String> {
        use std::sync::atomic::Ordering;
        if self.ended.load(Ordering::Acquire) || self.current().is_err() {
            self.ended.store(true, Ordering::Release);
            return Err("original office runtime access ended".into());
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct OfficeTurnStartup {
    pub(crate) native_base: NativeWitnessedTurnTarget,
    pub(crate) user_entry_id: i64,
    pub(crate) reads_before: Vec<String>,
    pub(crate) recovered: bool,
}

pub(crate) const SNAPSHOT_KIND: &str = "office_turn_startup";
const STARTUP_PHASE: &str = "startup";
const PROCESS_PHASE: &str = "startup-process-declaration";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartupSnapshot {
    revision: String,
    command: String,
    actor: String,
    standing: super::office_authority::OriginalOfficeTaskBinding,
    chat: String,
    task: String,
    base_cut: String,
    lineage: whipplescript_store::branches::BranchRow,
    phase: RunPhase,
    reads_before: Vec<String>,
    fork: Option<TurnForkSnapshot>,
}

impl StartupSnapshot {
    fn facts(&self) -> Result<[CommandRecordFact; 3], AdmitError> {
        Ok([
            CommandRecordFact {
                scope_id: self.chat.clone(),
                kind: "office_turn_base".into(),
                payload: self.base_cut.clone(),
            },
            CommandRecordFact {
                scope_id: self.chat.clone(),
                kind: SNAPSHOT_KIND.into(),
                payload: serde_json::to_string(self).map_err(AdmitError::Json)?,
            },
            // Keep the input last: its original assigned position binds the process.
            CommandRecordFact {
                scope_id: self.chat.clone(),
                kind: "transcript".into(),
                payload: ServerEvent::User {
                    text: self.task.clone(),
                    client_request_id: None,
                    chat_id: None,
                    home_id: None,
                    actor_id: None,
                }
                .to_json(),
            },
        ])
    }

    fn require_phase(
        &self,
        writer: &gaugedesk_store::command_dispatch::DispatchRecordAdmission<'_>,
        original: &ClaimedHttpCommand,
    ) -> Result<(), AdmitError> {
        writer.require_claimed_lifecycle_prefix(
            original.command_id(),
            original.scope(),
            original.key(),
            original.snapshot(),
            STARTUP_PHASE,
            &LifecycleBatch::<RunState> {
                scope: self.chat.clone(),
                commands: commands(self.phase),
            },
            &self.facts()?,
        )?;
        Ok(())
    }

    fn validate(
        &self,
        authority: &super::office_authority::OfficeTaskAuthority,
        chat: &str,
        task: &str,
    ) -> Result<(), AdmitError> {
        if self.revision != "office-turn-startup/v3"
            || self.actor != authority.actor()
            || self.standing != authority.original_binding()?
            || self.chat != chat
            || self.task != task
            || self.base_cut.is_empty()
            || self
                .fork
                .as_ref()
                .and_then(|fork| fork.process_declaration.as_ref())
                .is_some_and(|process| {
                    process.chat_id != chat || !process.id.is_empty() || !process.run_ref.is_empty()
                })
        {
            return Err(snapshot_refused());
        }
        Ok(())
    }
}

fn require_original_standing(
    store: &Store,
    office: &OfficeTurnContext<'_>,
) -> Result<StartupSnapshot, AdmitError> {
    let original = office.original;
    let scope = office.authority.chat();
    store.retained_events(scope)?;
    let phase = Store::claimed_lifecycle_prefix_scope(original.command_id(), STARTUP_PHASE);
    store.retained_events(&phase)?;
    if !store.claimed_lifecycle_prefix_recorded(original.command_id(), STARTUP_PHASE)? {
        return Err(snapshot_refused());
    }
    let snapshots = store
        .records(scope, SNAPSHOT_KIND)?
        .into_iter()
        .map(|row| serde_json::from_str::<StartupSnapshot>(&row).map_err(AdmitError::Json))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|row| row.command == original.command_id())
        .collect::<Vec<_>>();
    match snapshots.as_slice() {
        [snapshot] => {
            snapshot.validate(office.authority, scope, &snapshot.task)?;
            Ok(snapshot.clone())
        }
        _ => Err(snapshot_refused()),
    }
}

fn snapshot_refused() -> AdmitError {
    AdmitError::Rejected(gaugedesk_core::Rejection {
        reason: "office startup has no exact retained original snapshot or phase",
    })
}

/// A transport failure has no qualified runtime result to import. Record the
/// failed attempt and explicit evidence gap against the original recorded base;
/// pending mutable files remain unadmitted. Revoked authority refuses this too.
pub(crate) fn admit_failed_attempt(
    office: &OfficeTurnContext<'_>,
    startup: &OfficeTurnStartup,
    scope: &str,
    reason: &str,
) -> Result<(), EngineError> {
    if scope != office.authority.chat() {
        return Err(EngineError::Message(
            "office failure differs from original chat".into(),
        ));
    }
    let summary = crate::turn_summary::TurnSummary {
        user_entry_id: startup.user_entry_id,
        receipt_status: crate::turn_summary::ReceiptStatus::Failed,
        error: Some(reason.to_owned()),
        // No qualified result paths or certified output reads are available.
        // The gap fact below distinguishes this from a witnessed empty result.
        ..Default::default()
    };
    let facts = [
        CommandRecordFact {
            scope_id: scope.into(),
            kind: "transcript".into(),
            payload: ServerEvent::Error {
                reason: reason.to_owned(),
                code: None,
            }
            .to_json(),
        },
        CommandRecordFact {
            scope_id: scope.into(),
            kind: "office_turn_result_gap".into(),
            payload: serde_json::to_string(&serde_json::json!({
                "revision": "office-turn-result-gap/v1", "base_cut": startup.native_base.base_cut(),
                "user_entry_id": startup.user_entry_id,
                "reason": "transport_failed_without_qualified_runtime_outcome",
            }))
            .map_err(gaugedesk_store::AdmitError::Json)?,
        },
        CommandRecordFact {
            scope_id: scope.into(),
            kind: crate::turn_summary::TURN_SUMMARY_KIND.into(),
            payload: serde_json::to_string(&summary).map_err(gaugedesk_store::AdmitError::Json)?,
        },
    ];
    let mut wb = office.wb.lock_unpoisoned();
    let authority = office.authority.prepare_basis(&wb)?;
    let startup_phase =
        Store::claimed_lifecycle_prefix_scope(office.original.command_id(), STARTUP_PHASE);
    let (original_startup, observed) = wb
        .store_ref()
        .read_for_dispatch(&[scope, &startup_phase], |store| {
            require_original_standing(store, office)
        })?;
    let basis = authority.combine(observed)?;
    let original = office.original;
    wb.store_mut()
        .with_dispatch_record_admission(&basis, |writer| {
            writer.require_pending_claim(
                original.command_id(),
                original.scope(),
                original.key(),
                original.snapshot(),
            )?;
            original_startup.require_phase(&writer, original)?;
            startup
                .native_base
                .publish_base_retained(|| {
                    writer
                        .commit_claimed_lifecycle(
                            original.command_id(),
                            original.scope(),
                            original.key(),
                            original.snapshot(),
                            LifecycleBatch::<RunState> {
                                scope: scope.into(),
                                commands: vec![RunCommand::FailRun],
                            },
                            &facts,
                        )
                        .map_err(retention_error)
                })
                .map_err(WorkspaceError::from)
                .map_err(EngineError::Workspace)
        })??;
    Ok(())
}

fn commands(phase: RunPhase) -> Vec<RunCommand> {
    match phase {
        RunPhase::Init => vec![
            RunCommand::RequestRun,
            RunCommand::AdmitRun,
            RunCommand::StartRun,
        ],
        RunPhase::Requested => vec![RunCommand::AdmitRun, RunCommand::StartRun],
        RunPhase::Admitted => vec![RunCommand::StartRun],
        // A fresh task may resume a run whose process died. This does not
        // re-execute the crashed task's original pending command.
        RunPhase::Running => Vec::new(),
        RunPhase::Completed | RunPhase::Failed | RunPhase::Canceled => {
            vec![
                RunCommand::RetryRun,
                RunCommand::AdmitRun,
                RunCommand::StartRun,
            ]
        }
    }
}

fn retention_error(error: gaugedesk_store::AdmitError) -> whipplescript_store::StoreError {
    whipplescript_store::StoreError::Conflict(format!("office startup refused: {error:?}"))
}

pub(crate) fn admit_startup(
    office: &OfficeTurnContext<'_>,
    engagement: &dyn ChatWorkspace,
    scope: &str,
    task: &str,
    fork_snapshot: &mut Option<TurnForkSnapshot>,
) -> Result<OfficeTurnStartup, EngineError> {
    startup(office, engagement, scope, task, fork_snapshot, false)
}

pub(crate) fn admit_retained_startup(
    office: &OfficeTurnContext<'_>,
    engagement: &dyn ChatWorkspace,
    scope: &str,
    task: &str,
    fork_snapshot: &mut Option<TurnForkSnapshot>,
) -> Result<OfficeTurnStartup, EngineError> {
    startup(office, engagement, scope, task, fork_snapshot, true)
}

fn startup(
    office: &OfficeTurnContext<'_>,
    engagement: &dyn ChatWorkspace,
    scope: &str,
    task: &str,
    fork_snapshot: &mut Option<TurnForkSnapshot>,
    require_retained: bool,
) -> Result<OfficeTurnStartup, EngineError> {
    if office.authority.chat() != scope {
        return Err(EngineError::Message(
            "office startup differs from original chat".into(),
        ));
    }
    let mut wb = office.wb.lock_unpoisoned();
    let authority = office.authority.prepare_basis(&wb)?;
    let original = office.original;
    let phase_scope = Store::claimed_lifecycle_prefix_scope(original.command_id(), STARTUP_PHASE);
    // Original phase presence and snapshot are observed under the same product
    // basis. Neither locator nor snapshot is an execution grant.
    let ((retained, phase, reads_before), observed) =
        wb.store_ref()
            .read_for_dispatch(&[scope, &phase_scope], |store| {
                store.retained_events(scope)?;
                store.retained_events(&phase_scope)?;
                let recorded = store
                    .claimed_lifecycle_prefix_recorded(original.command_id(), STARTUP_PHASE)?;
                let snapshots = store
                    .records(scope, SNAPSHOT_KIND)?
                    .into_iter()
                    .map(|row| {
                        serde_json::from_str::<StartupSnapshot>(&row).map_err(AdmitError::Json)
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter(|snapshot| snapshot.command == original.command_id())
                    .collect::<Vec<_>>();
                let retained = match (recorded, snapshots.len()) {
                    (false, 0) => None,
                    (true, 1) => Some(snapshots.into_iter().next().ok_or_else(snapshot_refused)?),
                    _ => return Err(snapshot_refused()),
                };
                if let Some(snapshot) = &retained {
                    snapshot.validate(office.authority, scope, task)?;
                }
                Ok((
                    retained,
                    store.fold::<RunState>(scope)?.phase,
                    crate::resource_store::engagement_reads(store, scope)?
                        .items()
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>(),
                ))
            })?;
    if require_retained && retained.is_none() {
        return Err(snapshot_refused().into());
    }
    let basis = authority.combine(observed)?;
    let recovered = retained.is_some();
    let (native_base, prefix, snapshot) =
        wb.store_mut()
            .with_dispatch_record_admission(&basis, |writer| {
                writer.require_pending_claim(
                    original.command_id(),
                    original.scope(),
                    original.key(),
                    original.snapshot(),
                )?;
                let native_base = writer.with_native_check(|check| {
                    let mut current = || {
                        check.check_current().map_err(|error| WorkspaceError {
                            message: format!("{error:?}"),
                        })
                    };
                    current()?;
                    let base = if let Some(snapshot) = &retained {
                        engagement
                            .witnessed_turn_target_at(&snapshot.base_cut)?
                            .with_retained_lineage(snapshot.lineage.clone())?
                    } else {
                        engagement
                            .witnessed_turn_start_guarded(
                                office.authority.actor(),
                                original.command_id(),
                                &mut current,
                            )?
                            .capture_original_lineage()?
                    };
                    current()?;
                    Ok::<_, WorkspaceError>(base)
                })??;
                let original_binding = office.authority.original_binding()?;
                let snapshot = retained.unwrap_or_else(|| StartupSnapshot {
                    revision: "office-turn-startup/v3".into(),
                    command: original.command_id().into(),
                    actor: office.authority.actor().into(),
                    standing: original_binding,
                    chat: scope.into(),
                    task: task.into(),
                    base_cut: native_base.base_cut().into(),
                    lineage: native_base
                        .original_lineage()
                        .expect("captured or retained lineage")
                        .clone(),
                    phase,
                    reads_before,
                    fork: fork_snapshot.clone(),
                });
                snapshot.validate(office.authority, scope, task)?;
                let facts = snapshot.facts()?;
                let publish = || {
                    writer
                        .commit_claimed_lifecycle_prefix(
                            original.command_id(),
                            original.scope(),
                            original.key(),
                            original.snapshot(),
                            STARTUP_PHASE,
                            LifecycleBatch::<RunState> {
                                scope: scope.into(),
                                commands: commands(snapshot.phase),
                            },
                            &facts,
                        )
                        .map_err(retention_error)
                };
                let prefix = if recovered {
                    native_base.publish_base_retained(publish)
                } else {
                    native_base.publish_startup_lineage_retained(publish)
                }
                .map_err(WorkspaceError::from)?;
                Ok::<_, EngineError>((native_base, prefix, snapshot))
            })??;
    let reads_before = snapshot.reads_before;
    *fork_snapshot = snapshot.fork;
    let user_entry_id = *prefix.positions.last().ok_or_else(|| {
        EngineError::Message("office startup has no retained input position".into())
    })?;

    // The process refers to the position assigned above. Publish its exact
    // meaning in a second phase under fresh checks of the SAME original task.
    // No model may run until both phases succeed. Never finish the parent here.
    if let Some(process) = fork_snapshot
        .as_mut()
        .and_then(|snapshot| snapshot.process_declaration.as_mut())
    {
        process
            .bind_run(user_entry_id)
            .map_err(EngineError::Message)?;
        let fact = CommandRecordFact {
            scope_id: scope.into(),
            kind: crate::target_change_set::TURN_PROCESS_DECLARATION_KIND.into(),
            payload: serde_json::to_string(process).map_err(gaugedesk_store::AdmitError::Json)?,
        };
        let authority = office.authority.prepare_basis(&wb)?;
        let process_scope =
            Store::claimed_lifecycle_prefix_scope(original.command_id(), PROCESS_PHASE);
        let (_, observed) =
            wb.store_ref()
                .read_for_dispatch(&[scope, &process_scope, &phase_scope], |store| {
                    require_original_standing(store, office)?;
                    store.retained_events(scope)?;
                    store.retained_events(&process_scope)?;
                    let recorded = store
                        .claimed_lifecycle_prefix_recorded(original.command_id(), PROCESS_PHASE)?;
                    let declarations = store
                        .records(
                            scope,
                            crate::target_change_set::TURN_PROCESS_DECLARATION_KIND,
                        )?
                        .into_iter()
                        .map(|row| {
                            serde_json::from_str::<
                                    crate::target_change_set::TurnProcessDeclaration,
                                >(&row)
                                .map_err(AdmitError::Json)
                        })
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .filter(|declared| declared.run_ref == process.run_ref)
                        .collect::<Vec<_>>();
                    match (recorded, declarations.as_slice()) {
                        (false, []) => {}
                        (true, [declared]) if declared == process => {}
                        _ => return Err(snapshot_refused()),
                    }

                    if store.fold::<RunState>(scope)?.phase != RunPhase::Running {
                        return Err(gaugedesk_store::AdmitError::Rejected(
                            gaugedesk_core::Rejection {
                                reason: "office startup run ended before process declaration",
                            },
                        ));
                    }
                    Ok(())
                })?;
        let basis = authority.combine(observed)?;
        wb.store_mut()
            .with_dispatch_record_admission(&basis, |writer| {
                writer.require_pending_claim(
                    original.command_id(),
                    original.scope(),
                    original.key(),
                    original.snapshot(),
                )?;
                native_base
                    .publish_base_retained(|| {
                        writer
                            .commit_claimed_lifecycle_prefix(
                                original.command_id(),
                                original.scope(),
                                original.key(),
                                original.snapshot(),
                                PROCESS_PHASE,
                                LifecycleBatch::<RunState> {
                                    scope: scope.into(),
                                    commands: Vec::new(),
                                },
                                &[fact],
                            )
                            .map_err(retention_error)
                    })
                    .map_err(WorkspaceError::from)
                    .map_err(EngineError::Workspace)
            })??;
    }
    Ok(OfficeTurnStartup {
        native_base,
        user_entry_id,
        reads_before,
        recovered,
    })
}

/// Retain prepared intent under the original task writer. Preparation runs
/// before this call, without the Workbench lock that its access check needs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeSnapshot {
    revision: String,
    command: String,
    actor: String,
    chat: String,
    input_position: i64,
    process: Option<crate::target_change_set::TurnProcessDeclaration>,
    preparation: gaugedesk_harness::RuntimeTurnPreparation,
}

pub(crate) const RUNTIME_SNAPSHOT_KIND: &str = "office_turn_runtime";
const RUNTIME_PHASE: &str = "runtime-preparation";

pub(crate) fn retain_runtime(
    office: &OfficeTurnContext<'_>,
    startup: &OfficeTurnStartup,
    fork: Option<&TurnForkSnapshot>,
    preparation: gaugedesk_harness::RuntimeTurnPreparation,
) -> Result<(), EngineError> {
    let scope = office.authority.chat();
    let original = office.original;
    let snapshot = RuntimeSnapshot {
        revision: "office-turn-runtime/v2".into(),
        command: original.command_id().into(),
        actor: office.authority.actor().into(),
        chat: scope.into(),
        input_position: startup.user_entry_id,
        process: fork.and_then(|fork| fork.process_declaration.clone()),
        preparation,
    };
    if snapshot.input_position <= 0
        || snapshot.preparation.input_digest.is_empty()
        || snapshot.preparation.command_json.is_empty()
        || snapshot.preparation.start_position.instance_ref.is_empty()
        || snapshot.preparation.start_head_digest.is_empty()
    {
        return Err(snapshot_refused().into());
    }
    let mut wb = office.wb.lock_unpoisoned();
    let authority = office.authority.prepare_basis(&wb)?;
    let phase_scope = Store::claimed_lifecycle_prefix_scope(original.command_id(), RUNTIME_PHASE);
    let startup_phase = Store::claimed_lifecycle_prefix_scope(original.command_id(), STARTUP_PHASE);
    let (original_startup, observed) =
        wb.store_ref()
            .read_for_dispatch(&[scope, &phase_scope, &startup_phase], |store| {
                let original_startup = require_original_standing(store, office)?;
                store.retained_events(scope)?;
                store.retained_events(&phase_scope)?;
                let recorded = store
                    .claimed_lifecycle_prefix_recorded(original.command_id(), RUNTIME_PHASE)?;
                let snapshots = store
                    .records(scope, RUNTIME_SNAPSHOT_KIND)?
                    .into_iter()
                    .map(|row| {
                        serde_json::from_str::<RuntimeSnapshot>(&row).map_err(AdmitError::Json)
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter(|row| row.command == original.command_id())
                    .collect::<Vec<_>>();
                match (recorded, snapshots.as_slice()) {
                    (false, []) => {}
                    (true, [retained]) if retained == &snapshot => {}
                    _ => return Err(snapshot_refused()),
                }
                let declarations = store
                    .records(
                        scope,
                        crate::target_change_set::TURN_PROCESS_DECLARATION_KIND,
                    )?
                    .into_iter()
                    .map(|row| {
                        serde_json::from_str::<crate::target_change_set::TurnProcessDeclaration>(
                            &row,
                        )
                        .map_err(AdmitError::Json)
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter(|row| row.run_ref == format!("{scope}:{}", snapshot.input_position))
                    .collect::<Vec<_>>();
                if declarations != snapshot.process.clone().into_iter().collect::<Vec<_>>() {
                    return Err(snapshot_refused());
                }
                Ok(original_startup)
            })?;
    let basis = authority.combine(observed)?;
    let facts = [CommandRecordFact {
        scope_id: scope.into(),
        kind: RUNTIME_SNAPSHOT_KIND.into(),
        payload: serde_json::to_string(&snapshot).map_err(AdmitError::Json)?,
    }];
    wb.store_mut()
        .with_dispatch_record_admission(&basis, |writer| {
            writer.require_pending_claim(
                original.command_id(),
                original.scope(),
                original.key(),
                original.snapshot(),
            )?;
            original_startup.require_phase(&writer, original)?;
            startup
                .native_base
                .publish_base_retained(|| {
                    writer
                        .commit_claimed_lifecycle_prefix(
                            original.command_id(),
                            original.scope(),
                            original.key(),
                            original.snapshot(),
                            RUNTIME_PHASE,
                            LifecycleBatch::<RunState> {
                                scope: scope.into(),
                                commands: Vec::new(),
                            },
                            &facts,
                        )
                        .map_err(retention_error)
                })
                .map_err(WorkspaceError::from)
                .map_err(EngineError::Workspace)
        })??;
    Ok(())
}

/// Read the sealed original preparation under its pending task writer.
/// This observation supplies no execution, recovery or publication grant.
pub(crate) fn recorded_runtime(
    office: &OfficeTurnContext<'_>,
    startup: &OfficeTurnStartup,
    fork: Option<&TurnForkSnapshot>,
) -> Result<gaugedesk_harness::RuntimeTurnPreparation, EngineError> {
    let scope = office.authority.chat();
    let original = office.original;
    let mut wb = office.wb.lock_unpoisoned();
    let authority = office.authority.prepare_basis(&wb)?;
    let phase = Store::claimed_lifecycle_prefix_scope(original.command_id(), RUNTIME_PHASE);
    let startup_phase = Store::claimed_lifecycle_prefix_scope(original.command_id(), STARTUP_PHASE);
    let ((preparation, original_startup), observed) =
        wb.store_ref()
            .read_for_dispatch(&[scope, &phase, &startup_phase], |store| {
                let original_startup = require_original_standing(store, office)?;
                store.retained_events(scope)?;
                store.retained_events(&phase)?;
                let recorded = store
                    .claimed_lifecycle_prefix_recorded(original.command_id(), RUNTIME_PHASE)?;
                let snapshots = store
                    .records(scope, RUNTIME_SNAPSHOT_KIND)?
                    .into_iter()
                    .map(|row| {
                        serde_json::from_str::<RuntimeSnapshot>(&row).map_err(AdmitError::Json)
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter(|row| row.command == original.command_id())
                    .collect::<Vec<_>>();
                let snapshot = match (recorded, snapshots.as_slice()) {
                    (true, [snapshot]) => snapshot,
                    _ => return Err(snapshot_refused()),
                };
                if snapshot.revision != "office-turn-runtime/v2"
                    || snapshot.actor != office.authority.actor()
                    || snapshot.chat != scope
                    || snapshot.input_position != startup.user_entry_id
                    || snapshot.input_position <= 0
                    || snapshot.process != fork.and_then(|fork| fork.process_declaration.clone())
                    || snapshot.preparation.input_digest.is_empty()
                    || snapshot.preparation.command_json.is_empty()
                    || snapshot.preparation.start_position.instance_ref.is_empty()
                    || snapshot.preparation.start_head_digest.is_empty()
                {
                    return Err(snapshot_refused());
                }
                let declarations = store
                    .records(
                        scope,
                        crate::target_change_set::TURN_PROCESS_DECLARATION_KIND,
                    )?
                    .into_iter()
                    .map(|row| {
                        serde_json::from_str::<crate::target_change_set::TurnProcessDeclaration>(
                            &row,
                        )
                        .map_err(AdmitError::Json)
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter(|row| row.run_ref == format!("{scope}:{}", snapshot.input_position))
                    .collect::<Vec<_>>();
                if declarations != snapshot.process.clone().into_iter().collect::<Vec<_>>() {
                    return Err(snapshot_refused());
                }
                Ok((snapshot.preparation.clone(), original_startup))
            })?;
    let basis = authority.combine(observed)?;
    let preparation = wb
        .store_mut()
        .with_dispatch_record_admission(&basis, |writer| {
            writer.require_pending_claim(
                original.command_id(),
                original.scope(),
                original.key(),
                original.snapshot(),
            )?;
            original_startup.require_phase(&writer, original)?;
            startup
                .native_base
                .publish_base_retained(|| Ok(preparation))
                .map_err(WorkspaceError::from)
                .map_err(EngineError::Workspace)
        })??;
    office.authority.prepare_basis(&wb)?;
    original.verify_pending(wb.store_ref())?;
    Ok(preparation)
}

/// Observe an exact historical policy under the original pending task. Native
/// envelope/command verification remains the recorded-runtime owner's job.
pub(crate) fn recorded_policy(
    office: &OfficeTurnContext<'_>,
    startup: &OfficeTurnStartup,
    epoch: u64,
) -> Result<(String, gaugedesk_whip_runtime::GovernanceRootVerifier), EngineError> {
    let scope = office.authority.chat();
    let original = office.original;
    let mut wb = office.wb.lock_unpoisoned();
    let authority = office.authority.prepare_basis(&wb)?;
    let startup_phase = Store::claimed_lifecycle_prefix_scope(original.command_id(), STARTUP_PHASE);
    let ((policy, original_startup), observed) =
        wb.store_ref()
            .read_for_dispatch(&[scope, &startup_phase], |store| {
                let original_startup = require_original_standing(store, office)?;
                store.retained_events(scope)?;
                let policy = crate::policy_compiler::recorded_policy_envelope(store, scope, epoch)
                    .map_err(|_| snapshot_refused())?;
                Ok((policy, original_startup))
            })?;
    let (root, root_basis) = wb
        .recorded_chat_policy_root(scope, office.authority.project(), epoch)
        .map_err(|_| snapshot_refused())?;
    let basis = authority.combine(observed)?.combine(root_basis)?;
    let policy = wb
        .store_mut()
        .with_dispatch_record_admission(&basis, |writer| {
            writer.require_pending_claim(
                original.command_id(),
                original.scope(),
                original.key(),
                original.snapshot(),
            )?;
            original_startup.require_phase(&writer, original)?;
            startup
                .native_base
                .publish_base_retained(|| Ok((policy, root)))
                .map_err(WorkspaceError::from)
                .map_err(EngineError::Workspace)
        })??;
    office.authority.prepare_basis(&wb)?;
    original.verify_pending(wb.store_ref())?;
    Ok(policy)
}

/// Observe only whether an exact original startup already exists. This routing
/// fact permits no work. The original pending writer fences the observation.
pub(crate) fn recorded_startup(
    office: &OfficeTurnContext<'_>,
    task: &str,
) -> Result<bool, EngineError> {
    let mut wb = office.wb.lock_unpoisoned();
    let original = office.original;
    let scope = office.authority.chat();
    let authority = office.authority.prepare_basis(&wb)?;
    let phase = Store::claimed_lifecycle_prefix_scope(original.command_id(), STARTUP_PHASE);
    let (recorded, observed) = wb
        .store_ref()
        .read_for_dispatch(&[scope, &phase], |store| {
            store.retained_events(scope)?;
            store.retained_events(&phase)?;
            let recorded =
                store.claimed_lifecycle_prefix_recorded(original.command_id(), STARTUP_PHASE)?;
            let snapshots = store
                .records(scope, SNAPSHOT_KIND)?
                .into_iter()
                .map(|row| serde_json::from_str::<StartupSnapshot>(&row).map_err(AdmitError::Json))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|row| row.command == original.command_id())
                .collect::<Vec<_>>();
            match (recorded, snapshots.as_slice()) {
                (false, []) => {}
                (true, [snapshot]) => snapshot.validate(office.authority, scope, task)?,
                _ => return Err(snapshot_refused()),
            }
            Ok(recorded)
        })?;
    let basis = authority.combine(observed)?;
    wb.store_mut()
        .with_dispatch_record_admission(&basis, |writer| {
            writer.require_pending_claim(
                original.command_id(),
                original.scope(),
                original.key(),
                original.snapshot(),
            )
        })??;
    Ok(recorded)
}
