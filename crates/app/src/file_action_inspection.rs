//! Independent current-authority observation of an original native save.
//! The returned bytes retain their restrictions; this is neither a retention
//! lease nor permission to derive, reconcile, replay or execute another action.
use super::*;
use crate::action_policy::load_action_policy;
use gaugedesk_whip_runtime::{
    host_actions::action_result::{ReadActionResult, ACTION_RESULT_PROTOCOL},
    sign_hosted_policy_envelope, ResourcePolicy,
};
use whipplescript_kernel::{gov::canonicalize, host_protocol::PinnedPosition};

#[derive(Default)]
struct SavedObservationOptions<'a> {
    through: Option<PinnedPosition>,
    retained: Option<&'a ResourcePolicy>,
}

/// Constructed only by a currently authorized read of original runtime/target
/// evidence. Its saved bytes are historical and unendorsed, never today's file.
/// A subsequent action must re-admit access and retain its exact source.
pub struct EditorFileSaveObservation {
    evidence: ActionResultSnapshot,
    saved: Option<RecoveredSave<ScopedSaveReceipt>>,
    restrictions: ResourcePolicy,
    observer: String,
}
impl EditorFileSaveObservation {
    pub fn evidence(&self) -> &ActionResultSnapshot {
        &self.evidence
    }
    pub fn saved(&self) -> Option<&RecoveredSave<ScopedSaveReceipt>> {
        self.saved.as_ref()
    }
    pub fn restrictions(&self) -> &ResourcePolicy {
        &self.restrictions
    }
    pub fn observer(&self) -> &str {
        &self.observer
    }
}

fn read_policy(
    current: &FileAuthority,
    original_scope: &whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope,
    original: &HostGovernancePolicy,
) -> Result<(HostGovernancePolicy, ResourcePolicy), String> {
    let memory = original
        .resources
        .get("memory:/action/resolutions")
        .ok_or("original save policy has no memory compartment")?;
    resolution_scope::original_ceiling_is_covered(
        original_scope,
        &current.resolution_scope,
        memory,
    )?;
    let readers: BTreeSet<_> = original
        .resources
        .values()
        .chain(current.policy.resources.values())
        .flat_map(|resource| resource.reader.iter().cloned())
        .collect();
    if !readers.is_subset(&current.read_clearances) {
        return Err("reader does not clear original and current saved-input restrictions".into());
    }
    let restrictions = ResourcePolicy {
        reader: readers,
        writer: BTreeSet::new(),
        principal: false,
        internal: false,
    };
    let bindings = BTreeMap::from([
        ("admitted_input".into(), "file:/action/input".into()),
        ("admitted_target".into(), "file:/action/output".into()),
        (
            "admitted_resolutions".into(),
            "memory:/action/resolutions".into(),
        ),
        ("result".into(), "result".into()),
        ("error".into(), "error".into()),
    ]);
    let mut resources = BTreeMap::new();
    for address in [
        "file:/action/input",
        "file:/action/output",
        "memory:/action/resolutions",
        "result",
        "error",
    ] {
        if !original.resources.contains_key(address) {
            return Err("original saved-input policy is incomplete".into());
        }
        resources.insert(address.into(), restrictions.clone());
    }
    let policy = HostGovernancePolicy {
        resources,
        bindings,
        parties: current.policy.parties.clone(),
        delegations: current.policy.delegations.clone(),
        ..HostGovernancePolicy::default()
    };
    policy.validate()?;
    Ok((policy, restrictions))
}

impl Workbench {
    /// Inspect one original attempt with this reader's current Home standing.
    /// Opens only existing read-only runtime and target stores; neither input
    /// custody, coordination storage nor the former writer's grant is required.
    /// An absent result remains absent even after a failed/unknown attempt.
    pub fn observe_editor_file_save(
        &mut self,
        context: &AuthenticatedActionContext,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        attempt: EditorFileSaveAttempt<'_>,
    ) -> Result<EditorFileSaveObservation, String> {
        self.with_editor_file_save_observation(
            context,
            command,
            admission,
            attempt,
            SavedObservationOptions::default(),
            |observation, _, _, _| Ok(observation),
        )
    }

    // The one-use writer is consumed only by retained source publication. An
    // ordinary observation drops it without committing any product fact.
    fn with_editor_file_save_observation<T>(
        &mut self,
        context: &AuthenticatedActionContext,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        attempt: EditorFileSaveAttempt<'_>,
        options: SavedObservationOptions<'_>,
        publish: impl for<'tx> FnOnce(
            EditorFileSaveObservation,
            &OriginalSave,
            &gaugedesk_workspace::NativeFileActionEvidenceTarget,
            gaugedesk_store::command_dispatch::DispatchRecordAdmission<'tx>,
        ) -> StoreResult<T>,
    ) -> Result<T, String> {
        let invalid_profile = || "saved input is outside the registered native profile".to_owned();
        if command.issuer != self.authority().as_str()
            || command.provenance.initiator != command.provenance.executor
            || !command.provenance.delegation.is_empty()
            || !command.provenance.causes.is_empty()
            || command.provenance.origin != "editor.save"
            || command.inputs.len() != 1
            || command.resources.len() != 2
        {
            return Err(invalid_profile());
        }
        delivery::registered_editor_workflow(command)?;
        command.signing_bytes().map_err(|_| invalid_profile())?;
        admission
            .validate_for(command)
            .map_err(|_| invalid_profile())?;
        let (format, project, chat): (String, String, String) =
            serde_json::from_str(&command.scope).map_err(|_| invalid_profile())?;
        if format != "gaugedesk.editor-file.v1" {
            return Err(invalid_profile());
        }
        let original_scope = resolution_scope::original(command)?;
        let input = command.inputs.get("content").ok_or_else(invalid_profile)?;
        let resource = command
            .resources
            .get("target")
            .ok_or_else(invalid_profile)?;
        let (target_id, branch, path): (String, String, String) = serde_json::from_str(
            resource
                .resource
                .selector
                .as_deref()
                .ok_or_else(invalid_profile)?,
        )
        .map_err(|_| invalid_profile())?;
        let ActionBasis::Version { version_ref: base } = &resource.basis else {
            return Err(invalid_profile());
        };
        let label = |binding| format!("policy:{}:{binding}", command.policy.envelope_hash);
        if input.handle != "admitted_input"
            || input.label_ref != label("admitted_input")
            || resource.label_ref != label("admitted_target")
            || resource.resource.handle != "admitted_target"
            || resource.resource.kind != "file_store"
            || resource.resource.writable != Some(true)
        {
            return Err(invalid_profile());
        }
        let home = self.home_id().clone();
        let scope = command.instance_ref().map_err(|_| invalid_profile())?;
        let identity = ActionPolicyIdentity {
            issuer: command.issuer.clone(),
            scope: command.scope.clone(),
            request_id: command.request_id.clone(),
        };
        let policy_scope = identity.storage_scope()?;
        let key = SigningKey::from_seed(&self.governance_seed()).map_err(|e| e.reason)?;
        let root = GovernanceRootVerifier::new(self.authority().clone(), key.public_key());
        let ((current, admitted, retained), basis) = self
            .store_ref()
            .read_for_dispatch(
                &[
                    LIBRARY_SCOPE,
                    ORG_SCOPE,
                    crate::account_auth::ACCOUNT_AUTH_SCOPE,
                    crate::mobile_machine_session::SCOPE,
                    &scope,
                    &policy_scope,
                ],
                |store| {
                    let current = current_target_authority(
                        store,
                        &home,
                        context,
                        &NativeTargetIntent {
                            chat_id: &chat,
                            request_id: &command.request_id,
                            path: &path,
                        },
                        NativeActionKind::InspectHistory,
                    )?;
                    Ok((
                        current,
                        store.fold::<ProductActionAdmission>(&scope)?,
                        load_action_policy(store, &identity, &command.policy, &root),
                    ))
                },
            )
            .map_err(|e| format!("current saved-input authority refused: {e:?}"))?;
        if admitted.command.as_ref() != Some(command)
            || current.project_id != project
            || current.target_id != target_id
            || current.workspace_path != path
        {
            return Err("saved input differs from original admission or current target".into());
        }
        let dispatch = self
            .store_mut()
            .committed_dispatch::<ProductActionAdmission>(&scope, &command.request_id)
            .map_err(|e| format!("original saved-input receipt refused: {e:?}"))?
            .ok_or("original saved input has no Home outbox")?;
        if dispatch.command != *command
            || dispatch.dispatch.runtime_ref != format!("{home}:native")
            || dispatch.dispatch.command_ref
                != command.fingerprint().map_err(|_| invalid_profile())?
        {
            return Err("saved input has no original Home outbox binding".into());
        }
        let retained = retained?;
        let original: HostGovernancePolicy =
            serde_json::from_str(retained.signed_envelope()).map_err(|e| e.to_string())?;
        if canonicalize(&original.to_json()?)? != canonicalize(retained.signed_envelope())? {
            return Err("original saved-input policy cannot be represented losslessly".into());
        }
        let (mut policy, mut restrictions) = read_policy(&current, &original_scope, &original)?;
        if let Some(retained) = options.retained {
            if retained.principal
                || retained.internal
                || !retained.writer.is_empty()
                || !retained.reader.is_subset(&current.read_clearances)
            {
                return Err("reader does not clear the retained saved-source restrictions".into());
            }
            restrictions.reader.extend(retained.reader.iter().cloned());
            for resource in policy.resources.values_mut() {
                *resource = restrictions.clone();
            }
        }
        let signed = sign_hosted_policy_envelope(&policy.to_json()?, self.authority(), &key, 1)?;
        let target = self
            .engagements
            .get(&chat)
            .ok_or("saved-input workspace is unavailable")?
            .native_file_action_evidence_target(&path, base)
            .map_err(|e| format!("{e:?}"))?;
        if target.branch() != branch || target.path() != path || target.base() != base {
            return Err("saved input differs from its actual target".into());
        }
        let source = self.native_action_observation_source()?;
        let history = dispatch_grant::NativeDispatchHistory::open(self, key.public_key())?;
        let basis = current.bind_deadline(basis).map_err(|e| format!("{e:?}"))?;
        self.store_mut()
            .with_dispatch_record_admission(&basis, |writer| {
                let runtime = GovernedHostFacade::from_signed_store_with_verifier(
                    source.open()?,
                    1,
                    &signed,
                    &root,
                )
                .map_err(|e| StoreError::Conflict(format!("saved-input reader refused: {e:?}")))?;
                let request = ReadActionResult {
                    protocol: ACTION_RESULT_PROTOCOL.into(),
                    issuer: command.issuer.clone(),
                    scope: command.scope.clone(),
                    policy: runtime.policy_ref().clone(),
                    provenance: ActionProvenance {
                        initiator: context.actor().as_str().into(),
                        executor: context.actor().as_str().into(),
                        delegation: vec![],
                        origin: "editor.save.observe".into(),
                        causes: vec![],
                    },
                    admission: admission.clone(),
                    evidence_handle: "result".into(),
                    evidence_label_ref: format!(
                        "policy:{}:result",
                        runtime.policy_ref().envelope_hash
                    ),
                    through: options.through,
                };
                let bytes = request.signing_bytes().map_err(|_| refused())?;
                let verifier = super::super::execution::NativeResultVerifier {
                    request: &request,
                    key: key.public_key(),
                };
                let evidence = runtime
                    .read_action_result(request.clone(), &verifier, key.sign(&bytes).as_bytes())
                    .map_err(|_| refused())?;
                if &evidence.command != command || &evidence.admission != admission {
                    return Err(refused());
                }
                let store = runtime.kernel().store();
                let effect = store
                    .list_effects(&admission.instance_ref)?
                    .into_iter()
                    .find(|effect| effect.effect_id == attempt.effect_id)
                    .ok_or_else(refused)?;
                let original = original_save(
                    &evidence,
                    store.chain_prefix(&admission.instance_ref)?,
                    effect,
                    attempt.run_id,
                    &history,
                )?;
                let saved = target.read_committed_scoped_result(
                    &original.binding,
                    &original.resolution_scope,
                    &original.attempt,
                )?;
                publish(
                    EditorFileSaveObservation {
                        evidence,
                        saved,
                        restrictions,
                        observer: context.actor().as_str().into(),
                    },
                    &original,
                    &target,
                    writer,
                )
            })
            .map_err(|e| format!("{e:?}"))?
            .map_err(|e| format!("{e:?}"))
    }
}

#[cfg(test)]
#[path = "file_action_inspection_tests.rs"]
mod tests;

#[path = "file_action_source.rs"]
mod source;
pub use source::RetainedEditorFileSaveSource;
