//! Current native execution of the fixed editor workflow. The runtime owns
//! rule evaluation, dispatch/attempts, versioned writes and result evidence.

use super::*;
use crate::file_action_factory::delivery::{registered_editor_workflow, NativeEditorPreparation};
use gaugedesk_core::{
    ids::PublicKey,
    signature::{verify_signature, Signature},
};
use gaugedesk_whip_runtime::{
    host_actions::{
        action_result::{
            ActionResultSnapshot, ActionResultVerifier, ReadActionResult, ACTION_RESULT_PROTOCOL,
        },
        execution::{
            effect_observation_fingerprint, ActionExecutionVerifier, ExecuteActionEffect,
            ACTION_EXECUTION_PROTOCOL,
        },
        facade::GovernedHostFacade,
        NativeStores,
    },
    ProtocolError,
};
use whipplescript_kernel::host_facade::ScopedSaveExecutionAuthority;
use whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope;
use whipplescript_store::vcs_file_save::VersionedSaveBinding;
use whipplescript_store::{ClaimableEffect, StoreError, StoreResult, StoredEvent};

fn runtime_error(error: impl std::fmt::Debug) -> StoreError {
    StoreError::Conflict(format!("native editor operation failed: {error:?}"))
}

pub(super) struct NativeResultVerifier<'a> {
    pub(super) request: &'a ReadActionResult,
    pub(super) key: PublicKey,
}
impl ActionResultVerifier for NativeResultVerifier<'_> {
    fn verify(
        &self,
        request: &ReadActionResult,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if request != self.request
            || bytes != request.signing_bytes()?
            || !verify_signature(bytes, &Signature::new(proof), &self.key).unwrap_or(false)
        {
            return Err(ProtocolError::Mismatch("current editor evidence read"));
        }
        Ok(())
    }
}

pub(super) fn read_evidence(
    runtime: &GovernedHostFacade<NativeStores>,
    command: &HostActionCommand,
    admission: &ActionAdmissionReceipt,
    key: &SigningKey,
) -> StoreResult<ActionResultSnapshot> {
    admission.validate_for(command).map_err(runtime_error)?;
    let request = ReadActionResult {
        protocol: ACTION_RESULT_PROTOCOL.into(),
        issuer: command.issuer.clone(),
        scope: command.scope.clone(),
        policy: command.policy.clone(),
        provenance: command.provenance.clone(),
        admission: admission.clone(),
        evidence_handle: "result".into(),
        evidence_label_ref: format!("policy:{}:result", command.policy.envelope_hash),
        through: None,
    };
    let bytes = request.signing_bytes().map_err(runtime_error)?;
    let verifier = NativeResultVerifier {
        request: &request,
        key: key.public_key(),
    };
    let snapshot = runtime
        .read_action_result(request.clone(), &verifier, key.sign(&bytes).as_bytes())
        .map_err(runtime_error)?;
    if &snapshot.command != command {
        return Err(runtime_error(
            "runtime admission differs from original editor command",
        ));
    }
    Ok(snapshot)
}

/// Exists only inside a current product fence. The actual handler is constructed
/// from this very binding after all retained references have been resolved.
struct NativeExecutionVerifier<'a> {
    command: &'a HostActionCommand,
    request: &'a ExecuteActionEffect,
    provenance: &'a ActionProvenance,
    binding: &'a VersionedSaveBinding,
    target_id: &'a str,
    resolved_hash: &'a str,
    resolution_scope: &'a ResolutionMemoryScope,
    key: PublicKey,
}
impl ActionExecutionVerifier for NativeExecutionVerifier<'_> {
    fn authenticate(
        &self,
        request: &ExecuteActionEffect,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if request != self.request
            || bytes != request.signing_bytes()?
            || !verify_signature(bytes, &Signature::new(proof), &self.key).unwrap_or(false)
        {
            return Err(ProtocolError::Mismatch("current native editor execution"));
        }
        Ok(())
    }
    fn authorize(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        effect: &ClaimableEffect,
    ) -> Result<(), ProtocolError> {
        let mismatch = || ProtocolError::Mismatch("exact native editor effect binding");
        if request != self.request
            || original != self.command
            || &request.provenance != self.provenance
            || request.provenance.executor != self.binding.executing_principal
        {
            return Err(mismatch());
        }
        let target = original.resources.get("target").ok_or_else(mismatch)?;
        let input = original.inputs.get("content").ok_or_else(mismatch)?;
        let selector =
            serde_json::to_string(&(self.target_id, &self.binding.branch_id, &self.binding.path))
                .map_err(|_| mismatch())?;
        if target.resource.selector.as_deref() != Some(selector.as_str())
            || target.basis
                != (ActionBasis::Version {
                    version_ref: self.binding.base_cut_id.clone(),
                })
            || target.label_ref != self.binding.evidence_label
            || input.label_ref != self.binding.input_label
            || self.binding.draft_hash != self.resolved_hash
            || self.binding.draft_hash != whipplescript_store::stable_hash_hex(&self.binding.draft)
        {
            return Err(mismatch());
        }
        // The input's version identifies the retained labeled envelope. Its
        // resolved bytes, not that envelope hash, bind the handler and write.
        let json: serde_json::Value =
            serde_json::from_str(&effect.input_json).map_err(|_| mismatch())?;
        let (handle, root, path) = match effect.kind.as_str() {
            "file.read" => ("admitted_input", "/action/input", "content"),
            "file.write" => ("admitted_target", "/action/output", "target"),
            _ => return Err(mismatch()),
        };
        if effect
            .target
            .as_deref()
            .is_some_and(|target| target != handle)
            || json["store"] != handle
            || json["root"] != root
            || json["path"] != path
            || json["format"] != "reference"
        {
            return Err(mismatch());
        }
        if effect.kind == "file.write"
            && (json["mode"] != "upsert"
                || json["body_ref"]["content_hash"] != self.binding.draft_hash
                || json["body_ref"]["label_ref"] != self.binding.input_label
                || json.get("body").is_some()
                || json.get("body_expr").is_some())
        {
            return Err(mismatch());
        }
        Ok(())
    }
}

impl ScopedSaveExecutionAuthority for NativeExecutionVerifier<'_> {
    fn authorize_scoped_save(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        effect: &ClaimableEffect,
        binding: &VersionedSaveBinding,
        scope: &ResolutionMemoryScope,
    ) -> Result<(), ProtocolError> {
        self.authorize(request, original, effect)?;
        if whipplescript_store::vcs_file_save::SaveResultBinding::from(binding)
            != whipplescript_store::vcs_file_save::SaveResultBinding::from(self.binding)
            || binding.draft != self.binding.draft
            || binding.input_label != self.binding.input_label
            || binding.recorded_at != self.binding.recorded_at
            || scope != self.resolution_scope
            || resolution_scope::original(original).as_ref() != Ok(scope)
        {
            return Err(ProtocolError::Mismatch("current native resolution scope"));
        }
        Ok(())
    }
}

impl Workbench {
    /// Current authorized metadata read; it never steps rules, resumes a saved
    /// workflow or dereferences result bodies. Other readers need their own
    /// standing; this editor boundary serves only the original current actor.
    pub fn read_editor_file_save_result(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        runtime: &GovernedHostFacade<NativeStores>,
    ) -> Result<ActionResultSnapshot, String> {
        let prepared =
            self.prepare_native_editor_action(context, inputs, command, runtime.policy_ref())?;
        self.store_mut()
            .with_dispatch_basis(&prepared.basis, || {
                read_evidence(runtime, command, admission, &prepared.key)
            })
            .map_err(|error| format!("{error:?}"))?
            .map_err(|error| format!("{error:?}"))
    }

    /// Evaluate the fixed owner's rule pass under current action authority.
    /// Returned IDs only locate pending effects; each effect needs a fresh call
    /// to the governed execution boundary. This is not a background scheduler.
    pub fn advance_editor_file_save(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        runtime: &mut GovernedHostFacade<NativeStores>,
    ) -> Result<Vec<String>, String> {
        self.advance_editor_file_save_fenced(context, inputs, command, admission, runtime, None)
    }

    pub(super) fn advance_editor_file_save_fenced(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        runtime: &mut GovernedHostFacade<NativeStores>,
        epoch: Option<i64>,
    ) -> Result<Vec<String>, String> {
        let prepared =
            self.prepare_native_editor_action(context, inputs, command, runtime.policy_ref())?;
        let action = registered_editor_workflow(command)?;
        self.store_mut()
            .with_dispatch_basis(&prepared.basis, || {
                ownership::require_epoch(runtime, admission, epoch)?;
                read_evidence(runtime, command, admission, &prepared.key)?;
                whipplescript_kernel::rule_pass::step_instance_generic(
                    runtime.kernel_mut(),
                    &prepared.scope,
                    action.program(),
                    None,
                    None,
                )?;
                Ok::<_, StoreError>(
                    runtime
                        .kernel()
                        .claimable_effects(&prepared.scope)?
                        .into_iter()
                        .map(|effect| effect.effect_id)
                        .collect(),
                )
            })
            .map_err(|error| format!("{error:?}"))?
            .map_err(|error| format!("{error:?}"))
    }

    /// Execute one actual claimable file effect using current Home authority.
    /// The returned event records the runtime's attempt, not a product promise
    /// of success. Result admission, reconciliation and materialization are
    /// separate; an uncertain or conflicted effect is never retried blindly.
    pub fn execute_editor_file_save_effect(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        effect_id: &str,
        runtime: &mut GovernedHostFacade<NativeStores>,
    ) -> Result<StoredEvent, String> {
        self.execute_editor_file_save_effect_fenced(
            context, inputs, command, admission, effect_id, runtime, None,
        )
    }

    #[allow(clippy::too_many_arguments)] // Retain the direct boundary plus its acquired owner epoch.
    pub(super) fn execute_editor_file_save_effect_fenced(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        admission: &ActionAdmissionReceipt,
        effect_id: &str,
        runtime: &mut GovernedHostFacade<NativeStores>,
        epoch: Option<i64>,
    ) -> Result<StoredEvent, String> {
        let NativeEditorPreparation {
            chat_id,
            key,
            basis,
            scope,
            grant_cause,
            resolution_scope,
            ..
        } = self.prepare_native_editor_action(context, inputs, command, runtime.policy_ref())?;
        let provenance =
            dispatch_grant::with_grant_cause(command.provenance.clone(), grant_cause.as_ref());
        let action = registered_editor_workflow(command)?;
        let target = self.bind_native_editor_target(&chat_id, command)?;
        inputs
            .with_resolved(&command.inputs["content"], |resolved| {
                self.store_mut()
                    .with_dispatch_basis(&basis, || {
                        ownership::require_epoch(runtime, admission, epoch)?;
                        read_evidence(runtime, command, admission, &key)?;
                        let effect = runtime
                            .kernel()
                            .claimable_effects(&scope)?
                            .into_iter()
                            .find(|effect| effect.effect_id == effect_id)
                            .ok_or_else(|| runtime_error("editor effect is not claimable"))?;
                        let resolved_hash = resolved.content_hash.clone();
                        let binding = VersionedSaveBinding {
                            branch_id: target.branch().into(),
                            path: target.path().into(),
                            base_cut_id: target.base().into(),
                            draft: resolved.content,
                            draft_hash: resolved.content_hash,
                            input_label: command.inputs["content"].label_ref.clone(),
                            executing_principal: context.actor().as_str().into(),
                            evidence_label: command.resources["target"].label_ref.clone(),
                            recorded_at: crate::account::session_now_ms().to_string(),
                        };
                        let request = ExecuteActionEffect {
                            protocol: ACTION_EXECUTION_PROTOCOL.into(),
                            issuer: command.issuer.clone(),
                            scope: command.scope.clone(),
                            admission: admission.clone(),
                            policy: command.policy.clone(),
                            provenance: provenance.clone(),
                            effect_id: effect.effect_id.clone(),
                            effect_fingerprint: effect_observation_fingerprint(&effect)
                                .map_err(runtime_error)?,
                        };
                        let (target_id, _, _): (String, String, String) = serde_json::from_str(
                            command.resources["target"]
                                .resource
                                .selector
                                .as_deref()
                                .ok_or_else(|| runtime_error("missing target"))?,
                        )
                        .map_err(runtime_error)?;
                        let verifier = NativeExecutionVerifier {
                            command,
                            request: &request,
                            provenance: &provenance,
                            binding: &binding,
                            target_id: &target_id,
                            resolved_hash: &resolved_hash,
                            resolution_scope: &resolution_scope,
                            key: key.public_key(),
                        };
                        // Authenticate and compare before opening a writer as well as
                        // at the runtime's own dispatch boundary.
                        let bytes = request.signing_bytes().map_err(runtime_error)?;
                        let proof = key.sign(&bytes);
                        verifier
                            .authenticate(&request, &bytes, proof.as_bytes())
                            .map_err(runtime_error)?;
                        verifier
                            .authorize(&request, command, &effect)
                            .map_err(runtime_error)?;
                        verifier
                            .authorize_scoped_save(
                                &request,
                                command,
                                &effect,
                                &binding,
                                &resolution_scope,
                            )
                            .map_err(runtime_error)?;
                        let files = target.open_scoped_versioned_save(
                            binding.clone(),
                            resolution_scope.clone(),
                        )?;
                        runtime
                            .execute_scoped_save_file_effect(
                                request.clone(),
                                &action,
                                &verifier,
                                proof.as_bytes(),
                                &files,
                            )
                            .map_err(runtime_error)
                    })
                    .map_err(runtime_error)?
            })
            .map_err(|error| format!("{error:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{admitted_fixture, configure_native_files, editor_runtime};
    use super::*;
    use crate::LockUnpoisoned;

    #[test]
    fn execution_proof_and_actual_handler_binding_refuse_substitution() {
        let dir = tempfile::tempdir().unwrap();
        let (wb, command, inputs, token) = admitted_fixture(dir.path());
        let mut wb = wb.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let mut runtime = editor_runtime(&wb, &command, dir.path());
        configure_native_files(runtime.kernel().store());
        let admission = wb
            .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
            .unwrap()
            .receipt;
        wb.advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
            .unwrap();
        let effect = runtime
            .kernel()
            .claimable_effects(&admission.instance_ref)
            .unwrap()
            .remove(0);
        let prepared = wb
            .prepare_native_editor_action(&context, &inputs, &command, runtime.policy_ref())
            .unwrap();
        let target = wb
            .bind_native_editor_target(&prepared.chat_id, &command)
            .unwrap();
        let resolved = inputs.resolve(&command.inputs["content"]).unwrap();
        let binding = VersionedSaveBinding {
            branch_id: target.branch().into(),
            path: target.path().into(),
            base_cut_id: target.base().into(),
            draft: resolved.content,
            draft_hash: resolved.content_hash.clone(),
            input_label: command.inputs["content"].label_ref.clone(),
            executing_principal: context.actor().as_str().into(),
            evidence_label: command.resources["target"].label_ref.clone(),
            recorded_at: "fixture".into(),
        };
        let request = ExecuteActionEffect {
            protocol: ACTION_EXECUTION_PROTOCOL.into(),
            issuer: command.issuer.clone(),
            scope: command.scope.clone(),
            admission,
            policy: command.policy.clone(),
            provenance: command.provenance.clone(),
            effect_id: effect.effect_id.clone(),
            effect_fingerprint: effect_observation_fingerprint(&effect).unwrap(),
        };
        let (target_id, _, _): (String, String, String) = serde_json::from_str(
            command.resources["target"]
                .resource
                .selector
                .as_deref()
                .unwrap(),
        )
        .unwrap();
        macro_rules! verifier {
            ($binding:expr) => {
                NativeExecutionVerifier {
                    command: &command,
                    request: &request,
                    provenance: &command.provenance,
                    binding: $binding,
                    target_id: &target_id,
                    resolved_hash: &resolved.content_hash,
                    resolution_scope: &prepared.resolution_scope,
                    key: prepared.key.public_key(),
                }
            };
        }
        let bytes = request.signing_bytes().unwrap();
        let proof = prepared.key.sign(&bytes);
        assert!(verifier!(&binding)
            .authenticate(&request, &bytes, proof.as_bytes())
            .is_ok());
        assert!(verifier!(&binding)
            .authenticate(
                &request,
                &bytes,
                SigningKey::from_seed(&[95; 32])
                    .unwrap()
                    .sign(&bytes)
                    .as_bytes()
            )
            .is_err());
        assert!(verifier!(&binding)
            .authorize(&request, &command, &effect)
            .is_ok());
        for field in [
            "branch",
            "path",
            "base",
            "input label",
            "evidence label",
            "actor",
            "content",
        ] {
            let mut changed = binding.clone();
            match field {
                "branch" => changed.branch_id.push_str("-foreign"),
                "path" => changed.path.push_str(".other"),
                "base" => changed.base_cut_id.push_str("-other"),
                "input label" => changed.input_label = "public".into(),
                "evidence label" => changed.evidence_label = "public".into(),
                "actor" => changed.executing_principal = "other".into(),
                _ => {
                    changed.draft = "different bytes with a valid hash".into();
                    changed.draft_hash = whipplescript_store::stable_hash_hex(&changed.draft);
                }
            }
            assert!(
                verifier!(&changed)
                    .authorize(&request, &command, &effect)
                    .is_err(),
                "{field}"
            );
        }
        assert!(verifier!(&binding)
            .authorize_scoped_save(
                &request,
                &command,
                &effect,
                &binding,
                &prepared.resolution_scope
            )
            .is_ok());
        for field in ["authority", "resource", "compartment"] {
            let mut scope = serde_json::to_value(&prepared.resolution_scope).unwrap();
            scope[field] = "foreign".into();
            let scope = serde_json::from_value(scope).unwrap();
            assert!(
                verifier!(&binding)
                    .authorize_scoped_save(&request, &command, &effect, &binding, &scope)
                    .is_err(),
                "{field}"
            );
        }
        let mut actual = binding.clone();
        actual.recorded_at = "substituted actual adapter".into();
        assert!(verifier!(&binding)
            .authorize_scoped_save(
                &request,
                &command,
                &effect,
                &actual,
                &prepared.resolution_scope
            )
            .is_err());
        let mut changed = effect.clone();
        let mut json: serde_json::Value = serde_json::from_str(&effect.input_json).unwrap();
        json["format"] = "text".into();
        changed.input_json = json.to_string();
        assert!(verifier!(&binding)
            .authorize(&request, &command, &changed)
            .is_err());
    }
}
