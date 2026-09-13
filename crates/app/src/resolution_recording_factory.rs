//! Home admission for independently authored correction assertions (ACTION-4).
//! Delivery, governed execution and result admission remain separate. This
//! input path cannot discard retained observations or agent read taint.
use super::*;
use whipplescript_kernel::resolution_recording::{ResolutionRecordingAction, RECORDING_OPERATION};
use whipplescript_store::vcs_resolution_recording::ResolutionRecordingInput;

/// Region texts alone assert no verified earlier history. Derived corrections
/// use the saved-source admission method to bind retained evidence separately.
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

struct PreparedCorrections {
    command: HostActionCommand,
    input: ActionInput,
    scope: String,
    dispatch: CommandDispatch,
    basis: gaugedesk_store::command_dispatch::DispatchReadBasis,
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
        let prepared = self.prepare_editor_corrections(context, inputs, request, None)?;
        let admitted = inputs
            .publish(std::slice::from_ref(&prepared.input), || {
                self.store_mut()
                    .admit_with_dispatch_against::<ProductActionAdmission>(
                        &prepared.scope,
                        &prepared.command.request_id,
                        prepared.command.clone(),
                        &prepared.dispatch,
                        &prepared.basis,
                    )
                    .map_err(|e| {
                        whipplescript_store::StoreError::Conflict(format!(
                            "correction admission refused: {e:?}"
                        ))
                    })
            })
            .map_err(|e| format!("{e:?}"))?;
        Ok(AdmittedEditorCorrections {
            command: prepared.command,
            replayed: admitted.replayed,
        })
    }

    /// Admit a distinct correction derived from one exact saved source. The
    /// source cause is verified under this actor's current reading authority;
    /// its attribution and restrictions are retained independently of this act.
    pub fn admit_saved_source_corrections(
        &mut self,
        context: &AuthenticatedActionContext,
        storage: &NativeActionStorage,
        request: &EditorCorrections<'_>,
        cause: &ActionCause,
    ) -> Result<AdmittedEditorCorrections, String> {
        let source = self.prepare_editor_saved_source(context, storage, cause)?;
        let inputs = storage.inputs();
        let prepared = self.prepare_editor_corrections(
            context,
            inputs,
            request,
            Some((source.restrictions(), source.cause())),
        )?;
        let held = [source.input().clone(), prepared.input.clone()];
        let admitted = inputs
            .publish(&held, || {
                self.with_editor_saved_source(context, &source, |writer| {
                    writer
                        .admit_with_dispatch_against::<ProductActionAdmission>(
                            &prepared.scope,
                            &prepared.command.request_id,
                            prepared.command.clone(),
                            &prepared.dispatch,
                            &prepared.basis,
                        )
                        .map_err(|e| {
                            whipplescript_store::StoreError::Conflict(format!(
                                "derived correction admission refused: {e:?}"
                            ))
                        })
                })
                .map_err(whipplescript_store::StoreError::Conflict)
            })
            .map_err(|e| format!("{e:?}"))?;
        Ok(AdmittedEditorCorrections {
            command: prepared.command,
            replayed: admitted.replayed,
        })
    }

    fn prepare_editor_corrections(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        request: &EditorCorrections<'_>,
        source: Option<(&gaugedesk_whip_runtime::ResourcePolicy, &ActionCause)>,
    ) -> Result<PreparedCorrections, String> {
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
            current_target_authority_with_source(
                store,
                &home,
                context,
                &intent,
                NativeActionKind::RecordCorrections,
                source.map(|(restrictions, _)| restrictions),
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
        crate::resolution_recording_policy::validate_resolution_recording_flows(&envelope)?;
        if !ifc::check_with_envelope(action.program(), &envelope).is_empty() {
            return Err("correction workflow violates the admitted policy".into());
        }
        let body = serde_json::to_string(request.corrections).map_err(|error| error.to_string())?;
        let prepare_input = if source.is_some() {
            NativeActionInputCustody::prepare_unerased
        } else {
            NativeActionInputCustody::prepare
        };
        let input = prepare_input(
            inputs,
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
                origin: if source.is_some() {
                    "editor.corrections.derived"
                } else {
                    "editor.corrections"
                }
                .into(),
                causes: source
                    .map(|(_, cause)| vec![cause.clone()])
                    .unwrap_or_default(),
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
        Ok(PreparedCorrections {
            command,
            input,
            scope,
            dispatch,
            basis,
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
