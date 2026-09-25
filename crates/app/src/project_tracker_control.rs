//! A person's claim, renewal, release or reassignment of one native issue
//! (WHIP-4), admitted and executed exactly as a human completion is: an
//! independent action in the project's native stores, under the actor's current
//! tracker grants, replayed from its original command by its request key.
use super::*;
use crate::project_tracker::{
    ControlTrackerIssue, ProjectTracker, TrackerIssueControl, TrackerPermission,
};
use gaugedesk_store::command_dispatch::DispatchReadBasis;
use gaugedesk_whip_runtime::{HostGovernancePolicy, ResourcePolicy};
use whipplescript_kernel::{
    tracker_control::TrackerControlBinding, tracker_filing::TrackerBinding,
};
use whipplescript_store::{StoreError, StoreResult};

const CONTROL: &str = "tracker.control.v1";
/// Why a control did not take: the task changed since it was read.
pub(crate) const TRACKER_CONTROL_REFUSED: &str =
    "the task changed since it was read: it is claimed, released or assigned differently now";
const SUBJECT: &str = "@issue";
/// The longest lease a person may take or renew in one act.
pub(crate) const MAX_LEASE_SECONDS: u32 = 7 * 24 * 60 * 60;

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
}

fn control_scope(request: &ControlTrackerIssue, actor: &str) -> Result<String, String> {
    content_scope(&request.project).map_err(debug_error)?;
    if request.request_id.trim().is_empty()
        || request.item_id.trim().is_empty()
        || request.subject_id.trim().is_empty()
        || actor.trim().is_empty()
    {
        return Err("tracker control identity is empty".into());
    }
    Ok(format!(
        "project::{}::tracker-control::{}::{}",
        request.project,
        hex::encode(actor),
        hex::encode(&request.request_id)
    ))
}

/// The capability, the input class's own fields, and whether a lease is taken.
fn control_shape(control: &TrackerIssueControl) -> (&'static str, &'static str) {
    match control {
        TrackerIssueControl::Claim { .. } => ("tracker.claim", "expires_at string"),
        TrackerIssueControl::Renew { .. } => ("tracker.renew", "expires_at string"),
        TrackerIssueControl::Release { .. } => ("tracker.release", "expected_holder string?"),
        TrackerIssueControl::Assign { .. } => (
            "tracker.assign",
            "expected_assignee string?\n  assigned_to string?",
        ),
    }
}

fn control_action(
    queue: &str,
    control: &TrackerIssueControl,
) -> Result<CompiledHostAction, String> {
    // Names are identifiers in the existing language; never interpolate arbitrary source.
    if queue.is_empty()
        || queue.len() > 128
        || !queue
            .bytes()
            .enumerate()
            .all(|(i, c)| c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()))
    {
        return Err("tracker control name is not a Whip identifier".into());
    }
    let (capability, fields) = control_shape(control);
    let action = CompiledHostAction::compile_materialized_inputs(
        CONTROL,
        &format!(
            "use std.tracker\nworkflow ControlIssue(issue: Control) -> bool\nclass Control {{\n  queue string\n  id string\n  {fields}\n}}\ntracker {queue}\nrule control\n  when Control as issue\n=> {{\n  then outcome <- call {capability} for issue timeout 1m\n  complete result true\n}}\n"
        ),
        None,
    )?;
    if action.program().trackers.len() != 1 || action.program().trackers[0].name != queue {
        return Err("tracker control declaration differs from its binding".into());
    }
    Ok(action)
}

/// The recipient an assignment names, if it names one: a reader of the tracker
/// the Home has already confirmed, so the signed policy may name them.
fn control_policy(
    tracker: &ProjectTracker,
    actor: &str,
    control: &TrackerIssueControl,
) -> Result<HostGovernancePolicy, String> {
    let readers = crate::policy_compiler::resource_reader_roles(&tracker.resource);
    let role = crate::policy_compiler::authority_role(actor);
    let label = ResourcePolicy {
        reader: readers.clone(),
        ..Default::default()
    };
    let handle = tracker.resource.resource.id.as_str();
    let (capability, _) = control_shape(control);
    let mut parties = BTreeMap::from([(actor.to_owned(), role.clone())]);
    let mut delegations: Vec<[String; 2]> = readers
        .iter()
        .filter(|reader| *reader != &role)
        .map(|reader| [role.clone(), reader.clone()])
        .collect();
    if let TrackerIssueControl::Assign {
        assigned_to: Some(recipient),
        ..
    } = control
    {
        let recipient_role = crate::policy_compiler::authority_role(recipient);
        parties.insert(recipient.clone(), recipient_role.clone());
        delegations.extend(
            readers
                .iter()
                .filter(|reader| *reader != &recipient_role)
                .map(|reader| [recipient_role.clone(), reader.clone()]),
        );
    }
    delegations.sort();
    delegations.dedup();
    let mut policy = HostGovernancePolicy {
        parties,
        delegations,
        capabilities: std::collections::BTreeSet::from([capability.into()]),
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
    policy.resources.insert("fact:Control".into(), label);
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

/// The lease a claim or renewal asks for, as the tracker compares it: UTC
/// `YYYY-MM-DD HH:MM:SS`, the form SQLite's `datetime('now')` produces.
fn lease_expiry(lease_seconds: u32) -> Result<String, String> {
    if lease_seconds == 0 || lease_seconds > MAX_LEASE_SECONDS {
        return Err("claim lease is outside its allowed length".into());
    }
    let expires = std::time::SystemTime::now()
        .checked_add(std::time::Duration::from_secs(lease_seconds.into()))
        .ok_or("claim lease is out of range")?;
    let seconds = expires
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(debug_error)?
        .as_secs();
    let days = (seconds / 86_400) as i64;
    let rem = seconds % 86_400;
    // Civil date from days since the epoch (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    Ok(format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    ))
}

/// The input the effect is called with. A claim or renewal's expiry is fixed at
/// first admission; a replay reads it back rather than recomputing it.
fn control_input(
    request: &ControlTrackerIssue,
    original_expiry: Option<String>,
) -> Result<serde_json::Value, String> {
    let (queue, id) = (&request.queue, &request.item_id);
    Ok(match &request.control {
        TrackerIssueControl::Claim { lease_seconds }
        | TrackerIssueControl::Renew { lease_seconds } => {
            let expires_at = match original_expiry {
                Some(expires_at) => expires_at,
                None => lease_expiry(*lease_seconds)?,
            };
            serde_json::json!({"queue": queue, "id": id, "expires_at": expires_at})
        }
        TrackerIssueControl::Release { expected_holder } => {
            serde_json::json!({"queue": queue, "id": id, "expected_holder": expected_holder})
        }
        TrackerIssueControl::Assign {
            expected_assignee,
            assigned_to,
        } => serde_json::json!({
            "queue": queue, "id": id,
            "expected_assignee": expected_assignee, "assigned_to": assigned_to,
        }),
    })
}

struct Control {
    tracker: ProjectTracker,
    basis: DispatchReadBasis,
    key: Arc<PreparedScopeKey>,
    storage: NativeWorkflowStorage,
    protection: WorkflowProtection,
    root: GovernanceRootVerifier,
    policy: crate::action_policy::RetainedActionPolicy,
    action: CompiledHostAction,
    command: HostActionCommand,
    binding: TrackerControlBinding,
    delivery: CommittedDispatch<HostActionCommand>,
    /// The exact input the effect is called with, for authorizing it.
    input: serde_json::Value,
}

impl Workbench {
    /// Claim, renew, release or reassign one task as the authenticated person;
    /// repeated intent keeps one native root (WHIP-4).
    pub fn control_project_tracker_issue(
        &mut self,
        context: &AuthenticatedActionContext,
        request: &ControlTrackerIssue,
        limits: ProjectWorkflowLimits,
    ) -> Result<super::super::ProjectWorkflowStep, String> {
        let (step, outcome) =
            self.control_project_tracker_issue_admitted(context, request, limits)?;
        self.hint_project_workflows(crate::project_workflow::project_hint(&request.project));
        // The tracker answers a stale or contested act with a negative outcome
        // — someone else holds it, it was reassigned since it was read — which
        // is the answer rather than a fault, and a retry returns the same one.
        use whipplescript_store::tracker_control::TrackerControlOutcome as O;
        match outcome {
            Some(O::Claimed { .. } | O::Renewed { .. } | O::Released | O::Assigned) => Ok(step),
            Some(O::AlreadyClaimed { holder } | O::HeldByOther { holder }) => {
                Err(format!("{TRACKER_CONTROL_REFUSED}: {holder} holds it"))
            }
            Some(O::AssignmentChanged { assignee }) => Err(format!(
                "{TRACKER_CONTROL_REFUSED}: it is assigned to {}",
                assignee.as_deref().unwrap_or("nobody")
            )),
            Some(O::NotHeld) => Err(format!("{TRACKER_CONTROL_REFUSED}: it is not claimed")),
            Some(O::NotOpen) => Err(format!("{TRACKER_CONTROL_REFUSED}: it is not open")),
            Some(O::NotReady { reasons }) => {
                Err(format!("{TRACKER_CONTROL_REFUSED}: {}", reasons.join("; ")))
            }
            Some(O::NotMonotonic | O::DeadlineElapsed) => Err(format!(
                "{TRACKER_CONTROL_REFUSED}: its lease cannot be moved that way"
            )),
            None => Err("the task change did not settle; retry to recover it".into()),
        }
    }

    fn control_project_tracker_issue_admitted(
        &mut self,
        context: &AuthenticatedActionContext,
        request: &ControlTrackerIssue,
        limits: ProjectWorkflowLimits,
    ) -> Result<
        (
            super::super::ProjectWorkflowStep,
            Option<whipplescript_store::tracker_control::TrackerControlOutcome>,
        ),
        String,
    > {
        if let TrackerIssueControl::Assign {
            assigned_to: Some(recipient),
            ..
        } = &request.control
        {
            // Assignment never grants access: the recipient must already read
            // this tracker, as the Home's roster and grants say now.
            let (_, recipients, _, _) = self
                .prepare_project_tracker_recipients(context, &request.project, &request.queue)
                .map_err(debug_error)?;
            if !recipients.contains(recipient) {
                return Err("tracker assignment names someone who cannot read this tracker".into());
            }
        }
        let scope = control_scope(request, context.actor().as_str())?;
        let prepared = self.prepare_tracker_control(context, request, limits, &scope)?;
        let invocation = self.deliver_tracker_control(&prepared, request, limits, &scope)?;
        // Acknowledgment commits release the product writer. Re-capture current
        // authority before any effect, retaining the original command and inputs.
        let prepared = self.prepare_tracker_control(context, request, limits, &scope)?;
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
                                let step = execute::advance(
                                    &mut runtime,
                                    &prepared.action,
                                    &invocation,
                                    &prepared.binding,
                                    &prepared.input,
                                    &signing_key,
                                )?;
                                // What the tracker actually did, from its own receipt.
                                let outcome = match step.snapshot.effects.first() {
                                    Some(effect) => {
                                        use whipplescript_store::tracker_control::TrackerControls;
                                        runtime
                                            .kernel()
                                            .store()
                                            .control_receipt(
                                                &whipplescript_kernel::tracker_control::control_operation_id(
                                                    &invocation.admission.instance_ref,
                                                    &effect.effect_id,
                                                ),
                                            )?
                                            .map(|receipt| receipt.outcome)
                                    }
                                    None => None,
                                };
                                Ok((step, outcome))
                            },
                        )
                        .map_err(io_error)
                })
            })
            .map_err(debug_error)?
            .map_err(debug_error)
    }

    fn prepare_tracker_control(
        &mut self,
        context: &AuthenticatedActionContext,
        request: &ControlTrackerIssue,
        limits: ProjectWorkflowLimits,
        scope: &str,
    ) -> Result<Control, String> {
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
        let action = control_action(&request.queue, &request.control)?;
        let current_policy = control_policy(&tracker, context.actor().as_str(), &request.control)?;
        let signing_key = SigningKey::from_seed(&self.governance_seed()).map_err(debug_error)?;
        let identity = ActionPolicyIdentity {
            issuer: original.as_ref().map_or_else(
                || self.authority().as_str().into(),
                |command| command.issuer.clone(),
            ),
            scope: format!(
                "project::{}::tracker-control::{}",
                request.project,
                hex::encode(context.actor().as_str())
            ),
            request_id: request.request_id.clone(),
        };
        let (root, trust_basis) = self.workflow_policy_root(&request.project, &identity.issuer)?;
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
            return Err("tracker control policy differs from its original ceiling".into());
        }
        let envelope =
            ifc::VerifiedEnvelope::verify_signed_text_with(policy.signed_envelope(), &root)?;
        if !ifc::check_with_envelope(action.program(), &envelope).is_empty() {
            return Err("tracker control violates tracker resource policy".into());
        }
        let key = self.workflow_key(&request.project, &tracker.workspace_id, false)?;
        let storage = self.workflow_storage(&tracker.workspace_id)?;
        let protection =
            WorkflowProtection::new(&tracker.workspace_id, key.clone()).map_err(debug_error)?;
        let mut writer = self.store_ref().sibling().map_err(debug_error)?;
        let (command, subject, input_value) = writer
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
                        let selector = command
                            .resources
                            .get(SUBJECT)
                            .and_then(|r| r.resource.selector.as_deref())
                            .ok_or_else(|| io_error("tracker control has no original subject"))?;
                        let subject: Subject = serde_json::from_str(selector).map_err(io_error)?;
                        if subject.item_id != request.item_id
                            || subject.subject_id != request.subject_id
                        {
                            return Err(io_error(
                                "tracker control request key has different target intent",
                            ));
                        }
                        subject
                    } else {
                        let found = stores
                            .runtime
                            .items
                            .list_items(Some(&request.queue), None)
                            .map_err(io_error)?
                            .into_iter()
                            .any(|item| item.id == request.item_id);
                        if !found {
                            return Err(io_error(
                                "tracker control issue is unavailable in this tracker",
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
                                    io_error("tracker control issue has no permanent subject")
                                })?,
                        }
                    };
                    if subject.subject_id != request.subject_id {
                        return Err(io_error(
                            "tracker control issue differs from the observed subject",
                        ));
                    }
                    let (input, value) = if let Some(command) = &original {
                        let input = command
                            .inputs
                            .get("issue")
                            .ok_or_else(|| io_error("tracker control input is unavailable"))?;
                        let resolved = inputs.resolve(input).map_err(io_error)?;
                        let retained: serde_json::Value =
                            serde_json::from_str(&resolved.content).map_err(io_error)?;
                        let expected = control_input(
                            request,
                            retained["expires_at"].as_str().map(str::to_owned),
                        )
                        .map_err(io_error)?;
                        if retained != expected {
                            return Err(io_error(
                                "tracker control request key has different input intent",
                            ));
                        }
                        (input.clone(), retained)
                    } else {
                        let value = control_input(request, None).map_err(io_error)?;
                        let content = serde_json::to_string(&value).map_err(io_error)?;
                        if content.len() > limits.input_bytes {
                            return Err(io_error("tracker control input exceeds budget"));
                        }
                        let input = inputs
                            .prepare(
                                "input:issue",
                                &format!(
                                    "policy:{}:input:issue",
                                    policy.policy_ref().envelope_hash
                                ),
                                &content,
                            )
                            .map_err(io_error)?;
                        (input, value)
                    };
                    let command = HostActionCommand {
                        protocol: HOST_ACTION_PROTOCOL.into(),
                        issuer: identity.issuer.clone(),
                        scope: identity.scope.clone(),
                        request_id: request.request_id.clone(),
                        operation: CONTROL.into(),
                        program_version_ref: action.version_ref().into(),
                        input_schema_ref: action.input_schema_ref().into(),
                        policy: policy.policy_ref().clone(),
                        provenance: ActionProvenance {
                            initiator: context.actor().as_str().into(),
                            executor: context.actor().as_str().into(),
                            origin: "tracker.control".into(),
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
                        return Err(io_error(
                            "tracker control differs from its original command",
                        ));
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
                    Ok((command, subject, value))
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
            return Err("tracker changed during control admission".into());
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
        let (root, trust_basis) = self.workflow_policy_root(&request.project, &identity.issuer)?;
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
            .ok_or("tracker control has no original dispatch")?;
        if delivery.command != command
            || delivery.dispatch.runtime_ref != format!("workspace:{}", tracker.workspace_id)
            || delivery.dispatch.command_ref != command.fingerprint().map_err(debug_error)?
        {
            return Err("tracker control dispatch differs from its command".into());
        }
        let binding = TrackerControlBinding {
            tracker: TrackerBinding {
                scope: command.scope.clone(),
                queue: request.queue.clone(),
                resource: command.resources[&request.queue].clone(),
            },
            item_id: subject.item_id,
            subject_id: subject.subject_id,
        };
        Ok(Control {
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
            input: input_value,
        })
    }

    fn deliver_tracker_control(
        &self,
        prepared: &Control,
        request: &ControlTrackerIssue,
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

#[path = "project_tracker_control_execution.rs"]
mod execute;
