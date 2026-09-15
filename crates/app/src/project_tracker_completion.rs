//! Human closure is an independent admitted action in the project's native stores.
use super::*;
use crate::project_tracker::{
    CompleteTrackerIssue, ProjectTracker, TrackerCompletionClaim, TrackerPermission,
};
use gaugedesk_store::command_dispatch::DispatchReadBasis;
use gaugedesk_whip_runtime::{HostGovernancePolicy, ResourcePolicy};
use whipplescript_kernel::{
    tracker_closure::TrackerClosureBinding, tracker_filing::TrackerBinding,
};
use whipplescript_store::{StoreError, StoreResult};

const COMPLETE: &str = "tracker.complete.v1";
const SUBJECT: &str = "@issue";
fn native_error(error: impl std::fmt::Debug) -> StoreError {
    StoreError::Conflict(debug_error(error))
}
fn io_error(error: impl std::fmt::Debug) -> std::io::Error {
    std::io::Error::other(debug_error(error))
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Subject {
    item_id: String,
    subject_id: String,
    expected_holder: Option<String>,
}
fn completion_scope(request: &CompleteTrackerIssue, actor: &str) -> Result<String, String> {
    content_scope(&request.project).map_err(debug_error)?;
    if request.request_id.trim().is_empty()
        || request.item_id.trim().is_empty()
        || request.subject_id.trim().is_empty()
        || actor.trim().is_empty()
    {
        return Err("completion identity is empty".into());
    }
    Ok(format!(
        "project::{}::tracker-completion::{}::{}",
        request.project,
        hex::encode(actor),
        hex::encode(&request.request_id)
    ))
}
fn expected_holder(request: &CompleteTrackerIssue) -> Result<Option<String>, String> {
    match &request.claim {
        TrackerCompletionClaim::Override => Ok(None),
        TrackerCompletionClaim::Holder { holder } if !holder.trim().is_empty() => {
            Ok(Some(holder.clone()))
        }
        _ => Err("completion claim holder is empty".into()),
    }
}
fn completion_action(queue: &str) -> Result<CompiledHostAction, String> {
    // Names are identifiers in the existing language; never interpolate arbitrary source.
    if queue.is_empty()
        || queue.len() > 128
        || !queue
            .bytes()
            .enumerate()
            .all(|(i, c)| c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()))
    {
        return Err("completion tracker name is not a Whip identifier".into());
    }
    let action = CompiledHostAction::compile_materialized_inputs(COMPLETE, &format!(
        "workflow CompleteIssue(issue: Completion) -> bool\nclass Completion {{ queue string id string summary string }}\ntracker {queue}\nrule close\n  when Completion as issue\n=> {{\n  then closed <- finish issue {{ summary issue.summary }}\n  complete result true\n}}\n"
    ), None)?;
    if action.program().trackers.len() != 1 || action.program().trackers[0].name != queue {
        return Err("completion tracker declaration differs from its binding".into());
    }
    Ok(action)
}
fn completion_policy(
    tracker: &ProjectTracker,
    actor: &str,
) -> Result<HostGovernancePolicy, String> {
    let readers = crate::policy_compiler::resource_reader_roles(&tracker.resource);
    let role = crate::policy_compiler::authority_role(actor);
    let label = ResourcePolicy {
        reader: readers.clone(),
        ..Default::default()
    };
    let handle = tracker.resource.resource.id.as_str();
    let mut policy = HostGovernancePolicy {
        parties: BTreeMap::from([(actor.into(), role.clone())]),
        delegations: readers
            .into_iter()
            .filter(|reader| reader != &role)
            .map(|reader| [role.clone(), reader])
            .collect(),
        capabilities: std::collections::BTreeSet::from(["tracker.finish".into()]),
        ..Default::default()
    };
    for (binding, resource) in [
        (tracker.queue.as_str(), handle),
        (SUBJECT, SUBJECT),
        ("input:issue", "input:issue"),
        ("result", "result"),
        ("error", "error"),
    ] {
        policy.resources.insert(resource.into(), label.clone());
        policy.bindings.insert(binding.into(), resource.into());
    }
    policy.resources.insert("fact:Completion".into(), label);
    policy.validate()?;
    Ok(policy)
}
fn resources(
    tracker: &ProjectTracker,
    subject: &Subject,
    hash: &str,
) -> Result<BTreeMap<String, ActionResource>, String> {
    let subject = serde_json::to_string(subject).map_err(debug_error)?;
    Ok(BTreeMap::from([
        (
            tracker.queue.clone(),
            ActionResource {
                resource: ResourceRef {
                    handle: tracker.resource.resource.id.as_str().into(),
                    kind: "tracker".into(),
                    selector: Some(tracker.queue.clone()),
                    writable: Some(true),
                },
                basis: ActionBasis::Version {
                    version_ref: whipplescript_store::stable_hash_hex(
                        &serde_json::to_string(tracker).map_err(debug_error)?,
                    ),
                },
                label_ref: format!("policy:{hash}:{}", tracker.queue),
            },
        ),
        (
            SUBJECT.into(),
            ActionResource {
                resource: ResourceRef {
                    handle: SUBJECT.into(),
                    kind: "tracker_issue".into(),
                    selector: Some(subject.clone()),
                    writable: Some(true),
                },
                basis: ActionBasis::Version {
                    version_ref: whipplescript_store::stable_hash_hex(&subject),
                },
                label_ref: format!("policy:{hash}:{SUBJECT}"),
            },
        ),
    ]))
}
struct Completion {
    tracker: ProjectTracker,
    basis: DispatchReadBasis,
    key: Arc<PreparedScopeKey>,
    storage: NativeWorkflowStorage,
    protection: WorkflowProtection,
    root: GovernanceRootVerifier,
    policy: crate::action_policy::RetainedActionPolicy,
    action: CompiledHostAction,
    command: HostActionCommand,
    binding: TrackerClosureBinding,
    delivery: CommittedDispatch<HostActionCommand>,
}
impl Workbench {
    /// Close one task as the authenticated person; repeated intent keeps one native root.
    pub fn complete_project_tracker_issue(
        &mut self,
        context: &AuthenticatedActionContext,
        request: &CompleteTrackerIssue,
        limits: ProjectWorkflowLimits,
    ) -> Result<super::super::ProjectWorkflowStep, String> {
        let scope = completion_scope(request, context.actor().as_str())?;
        let prepared = self.prepare_tracker_completion(context, request, limits, &scope)?;
        let invocation = self.deliver_tracker_completion(&prepared, request, limits, &scope)?;
        // Acknowledgment commits release the product writer. Re-capture current
        // authority before any effect, retaining the original command and inputs.
        let prepared = self.prepare_tracker_completion(context, request, limits, &scope)?;
        let signing_key = SigningKey::from_seed(&self.governance_seed()).map_err(debug_error)?;
        let mut writer = self.store_ref().sibling().map_err(debug_error)?;
        writer
            .with_dispatch_basis(&prepared.basis, || {
                prepared.key.retain(|| {
                    let stores = prepared
                        .storage
                        .open_existing_protected(&prepared.protection)
                        .map_err(io_error)?;
                    let inputs = NativeActionInputCustody::new(
                        stores.inputs,
                        &prepared.tracker.workspace_id,
                        limits.input_bytes,
                    )
                    .map_err(io_error)?;
                    inputs
                        .with_resolved_many(
                            &prepared
                                .command
                                .inputs
                                .values()
                                .cloned()
                                .collect::<Vec<_>>(),
                            |_| {
                                let mut runtime =
                                    GovernedHostFacade::from_signed_store_with_verifier(
                                        stores.runtime,
                                        1,
                                        prepared.policy.signed_envelope(),
                                        &prepared.root,
                                    )
                                    .map_err(native_error)?;
                                execute::advance(
                                    &mut runtime,
                                    &prepared.action,
                                    &invocation,
                                    &prepared.binding,
                                    &request.summary,
                                    &signing_key,
                                )
                            },
                        )
                        .map_err(io_error)
                })
            })
            .map_err(debug_error)?
            .map_err(debug_error)
    }

    fn prepare_tracker_completion(
        &mut self,
        context: &AuthenticatedActionContext,
        request: &CompleteTrackerIssue,
        limits: ProjectWorkflowLimits,
        scope: &str,
    ) -> Result<Completion, String> {
        let (tracker, mut basis) = self
            .prepare_project_tracker_read(
                context,
                &request.project,
                &request.queue,
                TrackerPermission::Contribute,
            )
            .map_err(debug_error)?;
        let (_, command_basis) = self
            .store_ref()
            .read_for_dispatch(
                &[scope, &crate::federation::handoff_scope(&request.project)],
                |store| {
                    crate::federation::require_project_writes_available(store, &request.project)
                },
            )
            .map_err(debug_error)?;
        basis = basis.combine(command_basis).map_err(debug_error)?;
        let original = self
            .store_ref()
            .fold::<ProductActionAdmission>(scope)
            .map_err(debug_error)?
            .command;
        let action = completion_action(&request.queue)?;
        let holder = expected_holder(request)?;
        let value = serde_json::json!({"queue": request.queue, "id": request.item_id, "summary": request.summary});
        let content = serde_json::to_string(&value).map_err(debug_error)?;
        if content.len() > limits.input_bytes {
            return Err("completion input exceeds budget".into());
        }
        let current_policy = completion_policy(&tracker, context.actor().as_str())?;
        let signing_key = SigningKey::from_seed(&self.governance_seed()).map_err(debug_error)?;
        let identity = ActionPolicyIdentity {
            issuer: original.as_ref().map_or_else(
                || self.authority().as_str().into(),
                |command| command.issuer.clone(),
            ),
            scope: format!(
                "project::{}::tracker-action::{}",
                request.project,
                hex::encode(context.actor().as_str())
            ),
            request_id: request.request_id.clone(),
        };
        let (root, trust_basis) = self.workflow_policy_root(&identity.issuer)?;
        basis = basis.combine(trust_basis).map_err(debug_error)?;
        let policy = if let Some(command) = &original {
            load_project_action_policy(
                self.store_ref(),
                &request.project,
                &identity,
                &command.policy,
                &root,
            )?
        } else {
            prepare_project_action_policy(
                self.store_mut(),
                &request.project,
                &identity,
                &current_policy,
                &signing_key,
            )?
        };
        if whipplescript_kernel::gov::canonicalize(policy.signed_envelope())?
            != whipplescript_kernel::gov::canonicalize(&current_policy.to_json()?)?
        {
            return Err("completion policy differs from its original ceiling".into());
        }
        let envelope =
            ifc::VerifiedEnvelope::verify_signed_text_with(policy.signed_envelope(), &root)?;
        if !ifc::check_with_envelope(action.program(), &envelope).is_empty() {
            return Err("completion violates tracker resource policy".into());
        }
        let key = self.workflow_key(&request.project, &tracker.workspace_id, false)?;
        let storage = self.workflow_storage(&tracker.workspace_id)?;
        let protection =
            WorkflowProtection::new(&tracker.workspace_id, key.clone()).map_err(debug_error)?;
        let mut writer = self.store_ref().sibling().map_err(debug_error)?;
        let (command, subject) = writer
            .with_dispatch_record_admission(&basis, |admission| {
                key.retain(|| {
                    let stores = storage
                        .open_existing_protected(&protection)
                        .map_err(io_error)?;
                    let inputs = NativeActionInputCustody::new(
                        stores.inputs,
                        &tracker.workspace_id,
                        limits.input_bytes,
                    )
                    .map_err(io_error)?;
                    let subject = if let Some(command) = &original {
                        // Replay keeps the original permanent subject and claim precondition,
                        // including after a successful closure releases that claim.
                        let selector = command
                            .resources
                            .get(SUBJECT)
                            .and_then(|r| r.resource.selector.as_deref())
                            .ok_or_else(|| io_error("completion has no original subject"))?;
                        let subject: Subject = serde_json::from_str(selector).map_err(io_error)?;
                        if subject.item_id != request.item_id
                            || subject.subject_id != request.subject_id
                            || subject.expected_holder != holder
                        {
                            return Err(io_error(
                                "completion request key has different target intent",
                            ));
                        }
                        subject
                    } else {
                        // Filter in the owning store before materializing issue payloads.
                        let found = stores
                            .runtime
                            .items
                            .list_items(Some(&request.queue), None)
                            .map_err(io_error)?
                            .into_iter()
                            .any(|item| item.id == request.item_id);
                        if !found {
                            return Err(io_error(
                                "completion issue is unavailable in this tracker",
                            ));
                        }
                        Subject {
                            item_id: request.item_id.clone(),
                            subject_id: stores
                                .runtime
                                .items
                                .subject_content_id(&request.item_id)
                                .map_err(io_error)?
                                .ok_or_else(|| {
                                    io_error("completion issue has no permanent subject")
                                })?,
                            expected_holder: holder.clone(),
                        }
                    };
                    if subject.subject_id != request.subject_id {
                        return Err(io_error(
                            "completion issue differs from the observed subject",
                        ));
                    }
                    let input = if let Some(command) = &original {
                        let input = command
                            .inputs
                            .get("issue")
                            .ok_or_else(|| io_error("completion input is unavailable"))?;
                        let resolved = inputs.resolve(input).map_err(io_error)?;
                        if resolved.content != content {
                            return Err(io_error(
                                "completion request key has different input intent",
                            ));
                        }
                        input.clone()
                    } else {
                        inputs
                            .prepare(
                                "input:issue",
                                &format!(
                                    "policy:{}:input:issue",
                                    policy.policy_ref().envelope_hash
                                ),
                                &content,
                            )
                            .map_err(io_error)?
                    };
                    let command = HostActionCommand {
                        protocol: HOST_ACTION_PROTOCOL.into(),
                        issuer: identity.issuer.clone(),
                        scope: identity.scope.clone(),
                        request_id: request.request_id.clone(),
                        operation: COMPLETE.into(),
                        program_version_ref: action.version_ref().into(),
                        input_schema_ref: action.input_schema_ref().into(),
                        policy: policy.policy_ref().clone(),
                        provenance: ActionProvenance {
                            initiator: context.actor().as_str().into(),
                            executor: context.actor().as_str().into(),
                            origin: "tracker.complete".into(),
                            delegation: vec![],
                            causes: vec![],
                        },
                        inputs: BTreeMap::from([("issue".into(), input.clone())]),
                        resources: resources(
                            &tracker,
                            &subject,
                            &policy.policy_ref().envelope_hash,
                        )
                        .map_err(io_error)?,
                    };
                    if original
                        .as_ref()
                        .is_some_and(|original| original != &command)
                    {
                        return Err(io_error("completion differs from its original command"));
                    }
                    if original.is_none() {
                        let dispatch = CommandDispatch {
                            runtime_ref: format!("workspace:{}", tracker.workspace_id),
                            command_ref: command.fingerprint().map_err(io_error)?,
                        };
                        inputs
                            .publish(&[input], || {
                                admission
                                    .commit_dispatch::<ProductActionAdmission>(
                                        scope,
                                        &request.request_id,
                                        command.clone(),
                                        &dispatch,
                                    )
                                    .map_err(native_error)
                            })
                            .map_err(io_error)?;
                    }
                    Ok((command, subject))
                })
            })
            .map_err(debug_error)?
            .map_err(debug_error)?;
        // A new command changed this scope. Capture its committed dispatch at the
        // new head, then combine it with the still-current resource authority.
        let (tracker_now, current_basis) = self
            .prepare_project_tracker_read(
                context,
                &request.project,
                &request.queue,
                TrackerPermission::Contribute,
            )
            .map_err(debug_error)?;
        if tracker_now != tracker {
            return Err("completion tracker changed during admission".into());
        }
        let (_, receipt_basis) = self
            .store_ref()
            .read_for_dispatch(
                &[scope, &crate::federation::handoff_scope(&request.project)],
                |store| {
                    crate::federation::require_project_writes_available(store, &request.project)
                },
            )
            .map_err(debug_error)?;
        let (root, trust_basis) = self.workflow_policy_root(&identity.issuer)?;
        // The command commit changed the product head. Re-verify the retained
        // signature against this fresh trust observation rather than carrying a
        // verifier derived from an earlier pairing into its new basis.
        let policy = load_project_action_policy(
            self.store_ref(),
            &request.project,
            &identity,
            &command.policy,
            &root,
        )?;
        let basis = current_basis
            .combine(receipt_basis)
            .map_err(debug_error)?
            .combine(trust_basis)
            .map_err(debug_error)?;
        let delivery = self
            .store_mut()
            .committed_dispatch::<ProductActionAdmission>(scope, &request.request_id)
            .map_err(debug_error)?
            .ok_or("completion has no original dispatch")?;
        if delivery.command != command
            || delivery.dispatch.runtime_ref != format!("workspace:{}", tracker.workspace_id)
            || delivery.dispatch.command_ref != command.fingerprint().map_err(debug_error)?
        {
            return Err("completion dispatch differs from its command".into());
        }
        let binding = TrackerClosureBinding {
            tracker: TrackerBinding {
                scope: command.scope.clone(),
                queue: request.queue.clone(),
                resource: command.resources[&request.queue].clone(),
            },
            item_id: subject.item_id,
            subject_id: subject.subject_id,
            expected_holder: subject.expected_holder,
        };
        Ok(Completion {
            tracker,
            basis,
            key,
            storage,
            protection,
            root,
            policy,
            action,
            command,
            binding,
            delivery,
        })
    }

    fn deliver_tracker_completion(
        &self,
        prepared: &Completion,
        request: &CompleteTrackerIssue,
        limits: ProjectWorkflowLimits,
        scope: &str,
    ) -> Result<ProjectWorkflowInvocation, String> {
        let signing_key = SigningKey::from_seed(&self.governance_seed()).map_err(debug_error)?;
        let command = &prepared.command;
        let proof = signing_key.sign(&command.signing_bytes().map_err(debug_error)?);
        let mut writer = self.store_ref().sibling().map_err(debug_error)?;
        let receipt = writer
            .with_dispatch_record_admission(&prepared.basis, |admission| {
                prepared.key.retain(|| {
                    let stores = prepared
                        .storage
                        .open_existing_protected(&prepared.protection)
                        .map_err(io_error)?;
                    let inputs = NativeActionInputCustody::new(
                        stores.inputs,
                        &prepared.tracker.workspace_id,
                        limits.input_bytes,
                    )
                    .map_err(io_error)?;
                    inputs
                        .with_resolved_many(
                            &command.inputs.values().cloned().collect::<Vec<_>>(),
                            |resolved| {
                                let values = BTreeMap::from([(
                                    "issue".into(),
                                    serde_json::from_str(&resolved[0].content)?,
                                )]);
                                let mut runtime =
                                    GovernedHostFacade::from_signed_store_with_verifier(
                                        stores.runtime,
                                        1,
                                        prepared.policy.signed_envelope(),
                                        &prepared.root,
                                    )
                                    .map_err(native_error)?;
                                let receipt = runtime
                                    .admit_action_with_inputs(
                                        command.clone(),
                                        &prepared.action,
                                        &ExactAdmission {
                                            command,
                                            key: signing_key.public_key(),
                                        },
                                        proof.as_bytes(),
                                        &Inputs { command, values },
                                    )
                                    .map_err(native_error)?;
                                let acknowledgment =
                                    crate::host_action_delivery::RuntimeAcknowledgment {
                                        product_command_id: prepared.delivery.command_id.clone(),
                                        runtime_ref: prepared.delivery.dispatch.runtime_ref.clone(),
                                        receipt: receipt.clone(),
                                    };
                                let payload = serde_json::to_string(&acknowledgment)?;
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
                                    .map_err(native_error)?;
                                Ok(receipt)
                            },
                        )
                        .map_err(io_error)
                })
            })
            .map_err(debug_error)?
            .map_err(debug_error)?;
        Ok(ProjectWorkflowInvocation {
            project: request.project.clone(),
            workspace: prepared.tracker.workspace_id.clone(),
            product_scope: scope.into(),
            command: command.clone(),
            admission: receipt,
        })
    }
}

#[path = "project_tracker_completion_execution.rs"]
mod execute;
