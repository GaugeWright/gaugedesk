//! Bounded execution and recovery of one admitted native save. The scheduler
//! owns when to call this driver; it cannot supply actor, paths or lease clocks.
use super::*;
use crate::host_action_delivery::{RuntimeAcknowledgment, ACKNOWLEDGMENT_KIND};
use gaugedesk_whip_runtime::host_actions::action_result::{
    ActionInstanceStatus, ActionResultSnapshot,
};
use whipplescript_store::{effect_recovery::ExternalDisposition, vcs_file_save::SaveResult};

/// One explicitly acquired owner and one exact, revocable product grant.
/// No facade/context accessor: a scheduler uses the bounded step boundary.
pub struct NativeEditorSaveDriver {
    command: HostActionCommand,
    authority: NativeEditorDispatchAuthority,
    owner: NativeEditorActionRuntime,
}

pub enum NativeEditorSaveProgress {
    /// One ordinary step completed; a scheduler may arrange the next step.
    Advanced,
    /// Exact target result admitted by the product. Runtime failure/uncertainty
    /// is not rewritten, and this does not materialize or publish the file.
    Saved(Box<AdmittedEditorSavedResult>),
    /// The recorded state needs separate recovery/continuation authority or
    /// retained evidence. Repeating the step never retries an uncertain write.
    Unresolved(Box<ActionResultSnapshot>),
}

impl Workbench {
    pub fn start_editor_file_save_driver(
        &mut self,
        storage: &NativeActionStorage,
        command: &HostActionCommand,
        grant_ref: &str,
    ) -> Result<NativeEditorSaveDriver, String> {
        storage.require_home(self)?;
        let authority =
            self.load_editor_file_save_dispatch_authority(storage.inputs(), command, grant_ref)?;
        let mut runtime =
            self.open_editor_file_save_runtime(&authority.context, storage, command)?;
        let prepared = self.prepare_native_editor_action(
            &authority.context,
            storage.inputs(),
            command,
            &command.policy,
        )?;
        let receipt_scope = format!("host-action-runtime-ack:{}", prepared.scope);
        let snapshot = self
            .store_ref()
            .committed_record_snapshot(&receipt_scope, "admitted")
            .map_err(|e| format!("{e:?}"))?;
        let history = self
            .store_ref()
            .retained_events(&prepared.scope)
            .map_err(|e| format!("{e:?}"))?;
        let acknowledgments: Vec<_> = history
            .iter()
            .filter(|(_, kind, _)| kind == ACKNOWLEDGMENT_KIND)
            .collect();
        let admission = if let Some(snapshot) = snapshot {
            let acknowledgment: RuntimeAcknowledgment =
                serde_json::from_str(&snapshot).map_err(|e| e.to_string())?;
            if acknowledgments.len() != 1
                || acknowledgments[0].2 != snapshot
                || acknowledgment.product_command_id != prepared.delivery.command_id
                || acknowledgment.runtime_ref != prepared.delivery.dispatch.runtime_ref
            {
                return Err(
                    "native driver acknowledgment differs from its committed command".into(),
                );
            }
            acknowledgment
                .receipt
                .validate_for(command)
                .map_err(|e| format!("{e:?}"))?;
            acknowledgment.receipt
        } else {
            if !acknowledgments.is_empty() {
                return Err("native driver acknowledgment has no committed receipt".into());
            }
            self.deliver_editor_file_save(
                &authority.context,
                storage.inputs(),
                command,
                &mut runtime,
            )?
            .receipt
        };
        // This revalidates the exact runtime admission under current product
        // standing before acquiring ownership, including after reading the ack.
        let owner = self.claim_editor_file_save_runtime(
            &authority.context,
            storage.inputs(),
            command,
            &admission,
            runtime,
        )?;
        Ok(NativeEditorSaveDriver {
            command: command.clone(),
            authority,
            owner,
        })
    }

    /// Execute at most one file effect. An error can follow a committed target
    /// write; callers must resume this driver, never infer non-application.
    pub fn step_editor_file_save_driver(
        &mut self,
        storage: &NativeActionStorage,
        driver: &mut NativeEditorSaveDriver,
    ) -> Result<NativeEditorSaveProgress, String> {
        storage.require_home(self)?;
        let command = &driver.command;
        let context = &driver.authority.context;
        let admission = driver.owner.admission.clone();
        let prepared =
            self.prepare_native_editor_action(context, storage.inputs(), command, &command.policy)?;
        let snapshot = self
            .store_mut()
            .with_dispatch_basis(&prepared.basis, || {
                driver.owner.require_current(&admission)?;
                execution::read_evidence(driver.owner.runtime(), command, &admission, &prepared.key)
            })
            .map_err(|e| format!("{e:?}"))?
            .map_err(|e| format!("{e:?}"))?;
        let writes: Vec<_> = snapshot
            .effects
            .iter()
            .flat_map(|effect| {
                effect.attempts.iter().filter_map(move |attempt| {
                    attempt
                        .dispatch
                        .as_ref()
                        .filter(|dispatch| dispatch.frame.kind == "file.write")
                        .map(|_| (effect.effect_id.clone(), attempt.clone()))
                })
            })
            .collect();
        if let [(effect_id, observed)] = writes.as_slice() {
            if observed.disputed || observed.disposition == ExternalDisposition::NotApplied {
                return Ok(NativeEditorSaveProgress::Unresolved(Box::new(snapshot)));
            }
            let attempt = EditorFileSaveAttempt {
                effect_id,
                run_id: &observed.run_id,
            };
            let Some(saved) = self.inspect_editor_file_save_attempt(
                context,
                storage.inputs(),
                command,
                &admission,
                attempt,
                driver.owner.runtime(),
            )?
            else {
                return Ok(NativeEditorSaveProgress::Unresolved(Box::new(snapshot)));
            };
            if matches!(saved.receipt.result, SaveResult::Conflicted { .. }) {
                return Ok(NativeEditorSaveProgress::Unresolved(Box::new(snapshot)));
            }
            // Only ordinary successful completion may drive its final rule.
            // Applied target evidence alone cannot continue an interrupted run.
            if observed.terminal_status.as_deref() == Some("completed")
                && snapshot.instance_status == ActionInstanceStatus::Running
                && snapshot.terminal.is_none()
            {
                let pending = self.advance_editor_file_save_fenced(
                    context,
                    storage.inputs(),
                    command,
                    &admission,
                    &mut driver.owner.runtime,
                    Some(driver.owner.epoch),
                )?;
                if !pending.is_empty() {
                    return Err("native save final rule produced unexpected effects".into());
                }
            }
            let request_id = serde_json::to_string(&(
                "gaugedesk.native-editor-driver.reconcile.v1",
                effect_id,
                &observed.run_id,
            ))
            .map_err(|e| e.to_string())?;
            self.reconcile_editor_file_save_attempt(
                context,
                storage.inputs(),
                command,
                &admission,
                EditorFileSaveReconciliation {
                    request_id: &request_id,
                    attempt,
                },
                &mut driver.owner,
            )?
            .ok_or("native save evidence became unavailable during reconciliation")?;
            return self
                .admit_editor_file_save_result_fenced(
                    context,
                    storage.inputs(),
                    command,
                    &admission,
                    attempt,
                    driver.owner.runtime(),
                    Some(driver.owner.epoch),
                )?
                .map(|result| NativeEditorSaveProgress::Saved(Box::new(result)))
                .ok_or("native save evidence became unavailable during result admission".into());
        }
        if !writes.is_empty()
            || snapshot.instance_status != ActionInstanceStatus::Running
            || snapshot.terminal.is_some()
            || snapshot
                .effects
                .iter()
                .flat_map(|effect| &effect.attempts)
                .any(|attempt| {
                    attempt.disputed || attempt.terminal_status.as_deref() != Some("completed")
                })
        {
            return Ok(NativeEditorSaveProgress::Unresolved(Box::new(snapshot)));
        }
        let pending = self.advance_editor_file_save_fenced(
            context,
            storage.inputs(),
            command,
            &admission,
            &mut driver.owner.runtime,
            Some(driver.owner.epoch),
        )?;
        match pending.as_slice() {
            [effect_id] => {
                self.execute_editor_file_save_effect_fenced(
                    context,
                    storage.inputs(),
                    command,
                    &admission,
                    effect_id,
                    &mut driver.owner.runtime,
                    Some(driver.owner.epoch),
                )?;
                Ok(NativeEditorSaveProgress::Advanced)
            }
            [] => Ok(NativeEditorSaveProgress::Unresolved(Box::new(
                self.read_editor_file_save_result(
                    context,
                    storage.inputs(),
                    command,
                    &admission,
                    driver.owner.runtime(),
                )?,
            ))),
            _ => Err("native save workflow produced multiple claimable effects".into()),
        }
    }
}

#[cfg(test)]
#[path = "file_action_driver_tests.rs"]
mod tests;
