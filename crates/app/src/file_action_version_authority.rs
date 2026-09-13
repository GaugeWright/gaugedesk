//! Per-version read admission inside the native execution fence (ACTION-3).
//! A verified historical label contributes restrictions, never authorship or
//! the Home's independently admitted Saved outcome.

use super::*;
use gaugedesk_whip_runtime::{sign_hosted_policy_envelope, ResourcePolicy};
use std::sync::Mutex;
use whipplescript_store::vcs::{FileVersionSource, SaveVersionReadAuthority};
use whipplescript_store::{StoreError, StoreResult};

pub(super) struct NativeSaveVersionAuthority {
    target: gaugedesk_workspace::NativeFileActionTarget,
    product: Mutex<Store>,
    current: FileAuthority,
    issuer: gaugedesk_core::ids::AuthorityId,
    key: SigningKey,
}

impl NativeSaveVersionAuthority {
    /// The caller must keep construction and every use inside the dispatch
    /// fence for `current`; this observer does not acquire current standing.
    pub(super) fn new(
        target: gaugedesk_workspace::NativeFileActionTarget,
        product: Store,
        current: FileAuthority,
        issuer: gaugedesk_core::ids::AuthorityId,
        key: SigningKey,
    ) -> Self {
        Self {
            target,
            product: Mutex::new(product),
            current,
            issuer,
            key,
        }
    }
}

pub(super) fn authorize_reader(
    current: &FileAuthority,
    source: &ResourcePolicy,
) -> Result<(), String> {
    if source.principal
        || source.internal
        || !source.writer.is_empty()
        || !source.reader.is_subset(&current.read_clearances)
    {
        return Err("current actor does not clear an unendorsed retained file version".into());
    }
    Ok(())
}

fn authorize_source(
    current: &FileAuthority,
    source: &ResourcePolicy,
    issuer: &gaugedesk_core::ids::AuthorityId,
    key: &SigningKey,
) -> Result<(), String> {
    authorize_reader(current, source)?;
    // Ask the owner to evaluate the historical source against the actual
    // admitted sinks. Do not widen those sinks or replace the execution policy.
    let mut observation = current.policy.clone();
    let address = "file:/action/retained-version";
    let binding = "retained_version";
    if observation.resources.contains_key(address) || observation.bindings.contains_key(binding) {
        return Err("retained version observation binding is already occupied".into());
    }
    observation.resources.insert(address.into(), source.clone());
    observation.bindings.insert(binding.into(), address.into());
    let signed = sign_hosted_policy_envelope(&observation.to_json()?, issuer, key, 1)?;
    let root = GovernanceRootVerifier::new(issuer.clone(), key.public_key());
    let verified = ifc::VerifiedEnvelope::verify_signed_text_with(&signed, &root)?;
    for sink in ["admitted_target", "result", "error"] {
        verified.check_resource_flow(binding, sink)?;
    }
    Ok(())
}

/// Original restrictions only; neither a read grant nor a Saved acknowledgment.
pub(super) fn original_policy(
    target: &gaugedesk_workspace::NativeFileActionTarget,
    product: &Store,
    cut: &str,
    root: &GovernanceRootVerifier,
) -> StoreResult<Option<ResourcePolicy>> {
    let refuse = |reason: String| StoreError::Conflict(reason);
    let version = target.version_origin(
        cut,
        std::num::NonZeroUsize::new(512).expect("positive history budget"),
    )?;
    let evidence = match version.source {
        FileVersionSource::Absent => return Ok(None),
        FileVersionSource::Write {
            evidence: Some(evidence),
            ..
        } if evidence.schema_ref
            == whipplescript_store::vcs_file_save::SCOPED_SAVE_RECEIPT_SCHEMA =>
        {
            evidence
        }
        _ => {
            return Err(refuse(
                "retained file version requires explicit provenance migration".into(),
            ))
        }
    };
    if !evidence.label_ref.ends_with(":admitted_target") {
        return Err(refuse(
            "retained file version has no supported target label".into(),
        ));
    }
    crate::action_policy::load_action_label(product, &evidence.label_ref, root)
        .map(Some)
        .map_err(refuse)
}

impl SaveVersionReadAuthority for NativeSaveVersionAuthority {
    fn authorize_read(&self, branch: &str, path: &str, cut: &str) -> StoreResult<()> {
        let refuse = |reason: String| StoreError::Conflict(reason);
        if branch != self.target.branch() || path != self.target.path() {
            return Err(refuse(
                "retained file read differs from the admitted target".into(),
            ));
        }
        let product = self
            .product
            .lock()
            .map_err(|_| refuse("retained policy observer is unavailable".into()))?;
        let root = GovernanceRootVerifier::new(self.issuer.clone(), self.key.public_key());
        let Some(source) = original_policy(&self.target, &product, cut, &root)? else {
            return Ok(());
        };
        authorize_source(&self.current, &source, &self.issuer, &self.key).map_err(refuse)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::admitted_fixture;
    use super::*;
    use crate::LockUnpoisoned;

    #[test]
    fn recorded_version_resolves_its_original_signed_restrictions() {
        use whipplescript_store::files::{FileStore, FileWriteContext};
        use whipplescript_store::vcs_file_save::{
            save_cut_id, VersionedSaveBinding, SAVE_OUTPUT_PATH,
        };
        let dir = tempfile::tempdir().unwrap();
        let (wb, command, inputs, token) = admitted_fixture(dir.path());
        let mut wb = wb.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let prepared = wb
            .prepare_native_editor_action(&context, &inputs, &command, &command.policy)
            .unwrap();
        let target = wb
            .bind_native_editor_target(&prepared.chat_id, &command)
            .unwrap();
        let mut source_policy = prepared.authority.policy.clone();
        source_policy
            .resources
            .get_mut("file:/action/output")
            .unwrap()
            .reader
            .insert("historical:restricted".into());
        let original = prepare_action_policy(
            wb.store_mut(),
            &ActionPolicyIdentity {
                issuer: command.issuer.clone(),
                scope: command.scope.clone(),
                request_id: "recorded-source".into(),
            },
            &source_policy,
            &prepared.key,
        )
        .unwrap();
        let binding = VersionedSaveBinding {
            branch_id: target.branch().into(),
            path: target.path().into(),
            base_cut_id: target.base().into(),
            draft: "retained source".into(),
            draft_hash: whipplescript_store::stable_hash_hex("retained source"),
            input_label: command.inputs["content"].label_ref.clone(),
            executing_principal: context.actor().as_str().into(),
            evidence_label: format!(
                "policy:{}:admitted_target",
                original.policy_ref().envelope_hash
            ),
            recorded_at: "fixture".into(),
        };
        // Construct owner evidence directly to test its provenance consumer.
        // This fixture is not product dispatch or a claimed Home Saved result.
        let files = target
            .open_scoped_versioned_save(
                binding.clone(),
                prepared.resolution_scope,
                std::sync::Arc::new(|_: &str, _: &str, _: &str| Ok(())),
            )
            .unwrap();
        files
            .write_text_with_context(
                std::path::Path::new(SAVE_OUTPUT_PATH),
                &binding.draft,
                FileWriteContext {
                    instance_id: "source-fixture",
                    effect_id: "save",
                    run_id: "attempt",
                    started_event_id: "started",
                },
            )
            .unwrap();
        drop(files);
        let cut = save_cut_id("source-fixture", "save");
        let mut current = prepared.authority;
        current
            .read_clearances
            .insert("historical:restricted".into());
        for sink in ["file:/action/output", "result", "error"] {
            current
                .policy
                .resources
                .get_mut(sink)
                .unwrap()
                .reader
                .insert("historical:restricted".into());
        }
        let mut guard = NativeSaveVersionAuthority::new(
            target.clone(),
            wb.store_ref().read_only_sibling().unwrap(),
            current,
            wb.authority().clone(),
            prepared.key,
        );
        guard
            .authorize_read(target.branch(), target.path(), &cut)
            .unwrap();
        guard
            .current
            .policy
            .resources
            .get_mut("file:/action/output")
            .unwrap()
            .reader
            .remove("historical:restricted");
        assert!(guard
            .authorize_read(target.branch(), target.path(), &cut)
            .is_err());
        guard
            .current
            .policy
            .resources
            .get_mut("file:/action/output")
            .unwrap()
            .reader
            .insert("historical:restricted".into());
        guard.key = SigningKey::from_seed(&[97; 32]).unwrap();
        assert!(guard
            .authorize_read(target.branch(), target.path(), &cut)
            .is_err());
    }

    #[test]
    fn historical_source_must_clear_the_reader_and_every_admitted_sink() {
        let dir = tempfile::tempdir().unwrap();
        let (wb, command, inputs, token) = admitted_fixture(dir.path());
        let mut wb = wb.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let prepared = wb
            .prepare_native_editor_action(&context, &inputs, &command, &command.policy)
            .unwrap();
        let mut current = prepared.authority;
        let key = prepared.key;
        let issuer = wb.authority().clone();
        let mut source = current.policy.resources["file:/action/output"].clone();
        source.reader.insert("historical:restricted".into());
        current
            .read_clearances
            .extend(source.reader.iter().cloned());
        for sink in ["file:/action/output", "result", "error"] {
            current
                .policy
                .resources
                .get_mut(sink)
                .unwrap()
                .reader
                .extend(source.reader.iter().cloned());
        }
        authorize_source(&current, &source, &issuer, &key).unwrap();
        for sink in ["file:/action/output", "result", "error"] {
            let mut relaxed = current.clone();
            relaxed
                .policy
                .resources
                .get_mut(sink)
                .unwrap()
                .reader
                .remove("historical:restricted");
            assert!(
                authorize_source(&relaxed, &source, &issuer, &key).is_err(),
                "{sink}"
            );
        }
        let mut uncleared = current.clone();
        uncleared.read_clearances.remove("historical:restricted");
        assert!(authorize_source(&uncleared, &source, &issuer, &key).is_err());
        for field in ["principal", "internal", "writer"] {
            let mut endorsed = source.clone();
            match field {
                "principal" => endorsed.principal = true,
                "internal" => endorsed.internal = true,
                _ => {
                    endorsed.writer.insert("trusted".into());
                }
            }
            assert!(
                authorize_source(&current, &endorsed, &issuer, &key).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn legacy_history_does_not_acquire_a_label_from_current_target_policy() {
        let dir = tempfile::tempdir().unwrap();
        let (wb, command, inputs, token) = admitted_fixture(dir.path());
        let mut wb = wb.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let prepared = wb
            .prepare_native_editor_action(&context, &inputs, &command, &command.policy)
            .unwrap();
        let target = wb
            .bind_native_editor_target(&prepared.chat_id, &command)
            .unwrap();
        wb.engagements[&prepared.chat_id]
            .write_file(target.path(), "unlabeled external edit")
            .unwrap();
        let opaque = wb.engagements[&prepared.chat_id]
            .commit_turn("legacy import")
            .unwrap()
            .unwrap()
            .0;
        let guard = NativeSaveVersionAuthority::new(
            target.clone(),
            wb.store_ref().read_only_sibling().unwrap(),
            prepared.authority,
            wb.authority().clone(),
            prepared.key,
        );
        let error = guard
            .authorize_read(target.branch(), target.path(), &opaque)
            .unwrap_err();
        assert!(format!("{error:?}").contains("requires explicit provenance migration"));
        assert!(guard
            .authorize_read("other-line", target.path(), target.base())
            .is_err());
        assert!(guard
            .authorize_read(target.branch(), "other-file", target.base())
            .is_err());
    }
}
