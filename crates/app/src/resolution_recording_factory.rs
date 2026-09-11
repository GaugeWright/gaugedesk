//! Home admission for independently authored correction assertions (ACTION-4).
//! Delivery, governed execution and result admission remain separate. This
//! input path cannot discard retained observations or agent read taint.
use super::*;
use whipplescript_kernel::resolution_recording::{ResolutionRecordingAction, RECORDING_OPERATION};
use whipplescript_store::vcs_resolution_recording::ResolutionRecordingInput;

/// New authoring only: these region texts assert no verified earlier history.
/// Derived corrections need their retained inputs and causal evidence path.
/// The caller cannot select a policy, namespace, executable, actor or file base.
pub struct EditorCorrections<'a> {
    pub chat_id: &'a str,
    pub request_id: &'a str,
    pub path: &'a str,
    pub corrections: &'a ResolutionRecordingInput,
}

pub struct AdmittedEditorCorrections {
    pub command: HostActionCommand,
    pub replayed: bool,
}

impl Workbench {
    /// Admit a distinct correction command using the current Home's authority
    /// and input custody. This does not record any knowledge or activate a route.
    pub fn admit_editor_corrections(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        request: &EditorCorrections<'_>,
    ) -> Result<AdmittedEditorCorrections, String> {
        if inputs.authority_scope() != self.home_id().as_str() {
            return Err("correction input custody belongs to another Home".into());
        }
        let home = self.home_id().clone();
        let intent = NativeTargetIntent {
            chat_id: request.chat_id,
            request_id: request.request_id,
            path: request.path,
        };
        let read = |store: &Store| {
            current_target_authority(
                store,
                &home,
                context,
                &intent,
                NativeActionKind::RecordCorrections,
            )
        };
        let authority_scopes = [
            LIBRARY_SCOPE,
            ORG_SCOPE,
            crate::account_auth::ACCOUNT_AUTH_SCOPE,
            crate::mobile_machine_session::SCOPE,
        ];
        let (authority, _) = self
            .store_ref()
            .read_for_dispatch(&authority_scopes, read)
            .map_err(|error| format!("correction authorization refused: {error:?}"))?;
        let target = self
            .engagements
            .get(request.chat_id)
            .ok_or("chat workspace is unavailable")?
            .native_resolution_recording_target(
                &authority.workspace_path,
                authority.resolution_scope.clone(),
            )
            .map_err(|error| format!("{error:?}"))?;
        let recording = ResolutionRecordingAction::compile()?;
        let action = recording.action();
        let identity = ActionPolicyIdentity {
            issuer: self.authority().as_str().into(),
            // Retain the exact target path used for admission without claiming a
            // file version or exposing a caller-chosen physical store locator.
            scope: serde_json::to_string(&(
                "gaugedesk.editor-corrections.v1",
                &authority.project_id,
                request.chat_id,
                target.path(),
            ))
            .map_err(|error| error.to_string())?,
            request_id: request.request_id.into(),
        };
        let signing_key =
            SigningKey::from_seed(&self.governance_seed()).map_err(|error| error.reason)?;
        let root = GovernanceRootVerifier::new(self.authority().clone(), signing_key.public_key());
        let policy =
            prepare_action_policy(self.store_mut(), &identity, &authority.policy, &signing_key)?;
        let envelope =
            ifc::VerifiedEnvelope::verify_signed_text_with(policy.signed_envelope(), &root)?;
        if !ifc::check_with_envelope(action.program(), &envelope).is_empty() {
            return Err("correction workflow violates the admitted policy".into());
        }
        let body = serde_json::to_string(request.corrections).map_err(|error| error.to_string())?;
        let input = inputs
            .prepare(
                "admitted_corrections",
                &format!(
                    "policy:{}:admitted_corrections",
                    policy.policy_ref().envelope_hash
                ),
                &body,
            )
            .map_err(|error| format!("{error:?}"))?;
        crate::action_input_binding::retain_input_binding(
            self.store_mut(),
            inputs,
            &identity.issuer,
            home.as_str(),
            &input,
            &signing_key,
        )
        .map_err(|error| format!("correction input mapping refused: {error:?}"))?;
        let mapping_scope =
            crate::action_input_binding::input_binding_scope(&identity.issuer, &input)
                .map_err(|error| format!("correction input mapping refused: {error:?}"))?;
        let resolutions = recording_resource(
            &authority.resolution_scope,
            &policy.policy_ref().envelope_hash,
        )?;
        let command = HostActionCommand {
            protocol: HOST_ACTION_PROTOCOL.into(),
            issuer: identity.issuer,
            scope: identity.scope,
            request_id: identity.request_id,
            operation: RECORDING_OPERATION.into(),
            program_version_ref: action.version_ref().into(),
            input_schema_ref: action.input_schema_ref().into(),
            policy: policy.policy_ref().clone(),
            provenance: ActionProvenance {
                initiator: context.actor().as_str().into(),
                executor: context.actor().as_str().into(),
                delegation: vec![],
                origin: "editor.corrections".into(),
                causes: vec![],
            },
            inputs: BTreeMap::from([("corrections".into(), input.clone())]),
            resources: BTreeMap::from([("resolutions".into(), resolutions)]),
        };
        let scope = command
            .instance_ref()
            .map_err(|error| format!("invalid correction action: {error:?}"))?;
        let dispatch = CommandDispatch {
            runtime_ref: format!("{}:native", self.home_id()),
            command_ref: command
                .fingerprint()
                .map_err(|error| format!("invalid correction action: {error:?}"))?,
        };
        let mut final_scopes = authority_scopes.to_vec();
        final_scopes.push(&mapping_scope);
        let (current, basis) = self
            .store_ref()
            .read_for_dispatch(&final_scopes, read)
            .map_err(|error| format!("correction authorization refused: {error:?}"))?;
        if current != authority {
            return Err("correction authority changed during preparation".into());
        }
        let basis = current
            .bind_deadline(basis)
            .map_err(|error| format!("correction authority deadline refused: {error:?}"))?;
        let admitted = inputs
            .publish(std::slice::from_ref(&input), || {
                self.store_mut()
                    .admit_with_dispatch_against::<ProductActionAdmission>(
                        &scope,
                        &command.request_id,
                        command.clone(),
                        &dispatch,
                        &basis,
                    )
                    .map_err(|error| {
                        whipplescript_store::StoreError::Conflict(format!(
                            "correction admission refused: {error:?}"
                        ))
                    })
            })
            .map_err(|error| format!("{error:?}"))?;
        Ok(AdmittedEditorCorrections {
            command,
            replayed: admitted.replayed,
        })
    }
}

fn recording_resource(
    scope: &whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope,
    policy_hash: &str,
) -> Result<ActionResource, String> {
    let mut resource = resolution_scope::resource(scope, policy_hash)?;
    resource.resource.writable = Some(true);
    Ok(resource)
}

#[path = "resolution_recording_delivery.rs"]
mod delivery;

#[path = "resolution_recording_execution.rs"]
mod execution;

#[path = "resolution_recording_inspection.rs"]
mod inspection;
pub use inspection::{
    AdmittedEditorCorrectionReconciliation, AdmittedEditorCorrectionResult,
    CorrectionReconciliationAcknowledgment, EditorCorrectionObservation,
    EditorCorrectionReconciliation, EditorCorrectionResultRequest,
    NativeCorrectionReconciliationRuntime, NativeEditorCorrectionResult,
};
