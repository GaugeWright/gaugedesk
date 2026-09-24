//! Recover original launch delivery without reading a mutable source file.
use super::*;

impl Workbench {
    /// Resume the actor's original request. The caller supplies no new source.
    pub fn resume_project_workflow(
        &mut self,
        context: &AuthenticatedActionContext,
        project: &str,
        request_id: &str,
        limits: ProjectWorkflowLimits,
    ) -> Result<ProjectWorkflowInvocation, String> {
        let scope = request_scope(project, context.actor().as_str(), request_id)?;
        if let crate::identity::ActorAuthentication::ProjectWorkflowInvocation { scope: bound } =
            context.authentication()
        {
            if bound != &scope {
                return Err("workflow authority serves only its own invocation".into());
            }
        }
        crate::identity::revalidate_workflow_context(self.store_ref(), self.home_id(), context)
            .map_err(debug_error)?;
        let command = self
            .store_ref()
            .fold::<ProductActionAdmission>(&scope)
            .map_err(debug_error)?
            .command
            .ok_or("workflow invocation is unavailable")?;
        self.deliver_project_workflow(context, &scope, command, limits, None)
    }

    pub(super) fn deliver_project_workflow(
        &mut self,
        context: &AuthenticatedActionContext,
        scope: &str,
        command: HostActionCommand,
        limits: ProjectWorkflowLimits,
        expected_inputs: Option<&BTreeMap<String, serde_json::Value>>,
    ) -> Result<ProjectWorkflowInvocation, String> {
        let preparation::PreparedWorkflow {
            project,
            authority,
            trackers: _,
            key,
            protection,
            storage,
            root,
            policy,
            input,
            action,
            delivery,
        } = self.prepare_project_workflow(context, scope, command, limits)?;
        let command = delivery.command.clone();
        let basis = authority.basis;
        let mut writer = self.store_ref().sibling().map_err(debug_error)?;
        let signing_key = SigningKey::from_seed(&self.governance_seed()).map_err(debug_error)?;
        let proof = signing_key
            .sign(&command.signing_bytes().map_err(debug_error)?)
            .as_bytes()
            .to_vec();
        let receipt = writer
            .with_dispatch_record_admission(&basis, |admission| {
                key.retain(|| -> std::io::Result<_> {
                    let stores = storage
                        .open_existing_protected(&protection)
                        .map_err(|error| std::io::Error::other(debug_error(error)))?;
                    let inputs = NativeActionInputCustody::new(
                        stores.inputs,
                        &authority.workspace,
                        limits.source_bytes.max(limits.input_bytes),
                    )
                    .map_err(|error| std::io::Error::other(debug_error(error)))?;
                    let retained: Vec<_> = command
                        .inputs
                        .values()
                        .cloned()
                        .chain(std::iter::once(input.clone()))
                        .collect();
                    inputs
                        .with_resolved_many(&retained, |resolved| {
                            let mut total = 0usize;
                            let values = command
                                .inputs
                                .keys()
                                .zip(&resolved)
                                .map(|(name, value)| {
                                    total = total.checked_add(value.content.len()).ok_or_else(
                                        || {
                                            whipplescript_store::StoreError::Conflict(
                                                "workflow inputs exceed budget".into(),
                                            )
                                        },
                                    )?;
                                    if total > limits.input_bytes {
                                        return Err(whipplescript_store::StoreError::Conflict(
                                            "workflow inputs exceed budget".into(),
                                        ));
                                    }
                                    Ok((
                                        name.clone(),
                                        serde_json::from_str::<serde_json::Value>(&value.content)
                                            .map_err(|error| {
                                            whipplescript_store::StoreError::Conflict(
                                                error.to_string(),
                                            )
                                        })?,
                                    ))
                                })
                                .collect::<whipplescript_store::StoreResult<BTreeMap<_, _>>>()?;
                            if expected_inputs.is_some_and(|expected| expected != &values) {
                                return Err(whipplescript_store::StoreError::Conflict(
                                    "workflow request key has different input intent".into(),
                                ));
                            }
                            gaugedesk_whip_runtime::host_actions::register_native_tracker_package(
                                &stores.runtime.runtime,
                            )?;
                            let mut runtime = GovernedHostFacade::from_signed_store_with_verifier(
                                stores.runtime,
                                1,
                                policy.signed_envelope(),
                                &root,
                            )
                            .map_err(|error| {
                                whipplescript_store::StoreError::Conflict(debug_error(error))
                            })?;
                            let verifier = ExactAdmission {
                                command: &command,
                                key: signing_key.public_key(),
                            };
                            let receipt = runtime
                                .admit_action_with_inputs(
                                    command.clone(),
                                    &action,
                                    &verifier,
                                    &proof,
                                    &Inputs {
                                        command: &command,
                                        values,
                                    },
                                )
                                .map_err(|error| {
                                    whipplescript_store::StoreError::Conflict(debug_error(error))
                                })?;
                            let acknowledgment =
                                crate::host_action_delivery::RuntimeAcknowledgment {
                                    product_command_id: delivery.command_id,
                                    runtime_ref: delivery.dispatch.runtime_ref,
                                    receipt: receipt.clone(),
                                };
                            let payload =
                                serde_json::to_string(&acknowledgment).map_err(|error| {
                                    whipplescript_store::StoreError::Conflict(error.to_string())
                                })?;
                            admission
                                .commit(
                                    &format!("{scope}::runtime-admission"),
                                    "admitted",
                                    &payload,
                                    &[CommandRecordFact {
                                        scope_id: scope.into(),
                                        kind: crate::host_action_delivery::ACKNOWLEDGMENT_KIND
                                            .into(),
                                        payload: payload.clone(),
                                    }],
                                )
                                .map_err(|error| {
                                    whipplescript_store::StoreError::Conflict(debug_error(error))
                                })?;
                            Ok(receipt)
                        })
                        .map_err(|error| std::io::Error::other(debug_error(error)))
                })
            })
            .map_err(debug_error)?
            .map_err(debug_error)?;
        Ok(ProjectWorkflowInvocation {
            project,
            workspace: authority.workspace,
            product_scope: scope.into(),
            command,
            admission: receipt,
        })
    }
}
