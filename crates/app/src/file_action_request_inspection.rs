//! Resolve a lost save response using its original identity, without admission.
use super::*;

/// Exact original identity, including the original scope even after a move.
/// These coordinates grant no access and contain no execution input.
#[derive(Clone, Copy)]
pub struct EditorFileSaveRequest<'a> {
    pub issuer: &'a str,
    pub scope: &'a str,
    pub request_id: &'a str,
}

/// Currently authorized original command metadata. This is neither an outcome
/// nor a capability for later reads; those reads recheck current authority.
pub struct EditorFileSaveRequestObservation {
    command: HostActionCommand,
    restrictions: ResourcePolicy,
    observer: String,
}
impl EditorFileSaveRequestObservation {
    pub fn command(&self) -> &HostActionCommand {
        &self.command
    }
    pub fn restrictions(&self) -> &ResourcePolicy {
        &self.restrictions
    }
    pub fn observer(&self) -> &str {
        &self.observer
    }
}

fn unavailable() -> String {
    "original native save request is unavailable".into()
}

/// Exact historical Saved bytes, not today's file or permission to reuse them.
pub struct EditorFileSavedContentObservation {
    result: NativeEditorSavedResult,
    content: String,
    restrictions: ResourcePolicy,
    observer: String,
}
impl EditorFileSavedContentObservation {
    pub fn result(&self) -> &NativeEditorSavedResult {
        &self.result
    }
    pub fn content(&self) -> &str {
        &self.content
    }
    pub fn restrictions(&self) -> &ResourcePolicy {
        &self.restrictions
    }
    pub fn observer(&self) -> &str {
        &self.observer
    }
}

impl Workbench {
    /// Resolve admitted Saved content without importing or materializing a file.
    /// Metadata and bytes are separate observations: a retained fact alone
    /// cannot reconstruct erased or unavailable content.
    pub fn observe_editor_file_saved_content_by_request(
        &mut self,
        context: &AuthenticatedActionContext,
        request: EditorFileSaveRequest<'_>,
        cut: &str,
    ) -> Result<EditorFileSavedContentObservation, String> {
        if cut.trim().is_empty() {
            return Err(unavailable());
        }
        let original = self.observe_editor_file_save_request(context, request)?;
        let facts = self.observe_editor_file_saved_results(context, original.command())?;
        let fact = facts
            .results()
            .iter()
            .find(|fact| fact.result.cut_id == cut)
            .ok_or_else(unavailable)?;
        self.with_editor_file_save_observation(
            context,
            original.command(),
            &fact.result.admission,
            EditorFileSaveAttempt {
                effect_id: &fact.effect_id,
                run_id: &fact.run_id,
            },
            SavedObservationOptions {
                retained: Some(facts.restrictions()),
                ..Default::default()
            },
            |observed, _, _, _| {
                let saved = observed.saved().ok_or_else(refused)?;
                let (cut_id, operation, hash, merged) = match &saved.receipt.result {
                    whipplescript_store::vcs_file_save::SaveResult::Written {
                        cut_id,
                        operation_id,
                        accepted_content_hash,
                        ..
                    } => (cut_id, operation_id, accepted_content_hash, false),
                    whipplescript_store::vcs_file_save::SaveResult::Merged {
                        cut_id,
                        operation_id,
                        accepted_content_hash,
                        ..
                    } => (cut_id, operation_id, accepted_content_hash, true),
                    whipplescript_store::vcs_file_save::SaveResult::Conflicted { .. } => {
                        return Err(refused())
                    }
                };
                if saved.reference != fact.result.result_reference
                    || cut_id != &fact.result.cut_id
                    || operation != &fact.result.operation_id
                    || hash != &fact.result.content_hash
                    || merged != fact.result.merged
                {
                    return Err(refused());
                }
                Ok(EditorFileSavedContentObservation {
                    result: fact.result.clone(),
                    content: saved.accepted_content.clone(),
                    restrictions: observed.restrictions().clone(),
                    observer: observed.observer().into(),
                })
            },
        )
    }

    /// Recover the exact admitted command without reissuing intent. Missing
    /// evidence and refused access return the same unavailable error.
    /// No runtime, input, target or coordination storage is opened or created.
    pub fn observe_editor_file_save_request(
        &mut self,
        context: &AuthenticatedActionContext,
        request: EditorFileSaveRequest<'_>,
    ) -> Result<EditorFileSaveRequestObservation, String> {
        let scope = HostActionCommand::instance_ref_for_request(
            request.issuer,
            request.scope,
            request.request_id,
        )
        .map_err(|_| unavailable())?;
        let original = self
            .store_mut()
            .committed_dispatch::<ProductActionAdmission>(&scope, request.request_id)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let command = original.command;
        if command.issuer != request.issuer
            || command.scope != request.scope
            || command.request_id != request.request_id
        {
            return Err(unavailable());
        }
        let prepared = self
            .prepare_editor_file_save_inspection(context, &command, &[], None)
            .map_err(|_| unavailable())?;
        self.store_mut()
            .with_dispatch_basis(&prepared.basis, || EditorFileSaveRequestObservation {
                command,
                restrictions: prepared.restrictions,
                observer: context.actor().as_str().into(),
            })
            .map_err(|_| unavailable())
    }

    /// Execution evidence by original request identity. A missing response or
    /// acknowledgment never authorizes redelivery and never proves no effect.
    pub fn observe_editor_file_save_execution_by_request(
        &mut self,
        context: &AuthenticatedActionContext,
        request: EditorFileSaveRequest<'_>,
    ) -> Result<EditorFileSaveExecutionObservation, String> {
        let original = self.observe_editor_file_save_request(context, request)?;
        self.observe_editor_file_save_execution(context, original.command())
    }

    /// Product Saved facts remain independently readable when runtime/content
    /// evidence is erased. Their original authority and evidence ceiling hold.
    pub fn observe_editor_file_saved_results_by_request(
        &mut self,
        context: &AuthenticatedActionContext,
        request: EditorFileSaveRequest<'_>,
    ) -> Result<EditorFileSavedResultObservation, String> {
        let original = self.observe_editor_file_save_request(context, request)?;
        self.observe_editor_file_saved_results(context, original.command())
    }
}

#[cfg(test)]
#[path = "file_action_request_inspection_tests.rs"]
mod tests;
