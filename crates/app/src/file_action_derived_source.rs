//! Verify saved-source custody at publication and causal metadata at continuation.
use super::*;

pub(in crate::file_action_factory) struct PreparedSavedSource {
    source: SignedSource,
    command: HostActionCommand,
    restrictions: ResourcePolicy,
    cause: ActionCause,
}
impl PreparedSavedSource {
    pub(in crate::file_action_factory) fn input(&self) -> &ActionInput {
        &self.source.statement.input
    }
    pub(in crate::file_action_factory) fn restrictions(&self) -> &ResourcePolicy {
        &self.restrictions
    }
    pub(in crate::file_action_factory) fn cause(&self) -> &ActionCause {
        &self.cause
    }
}

fn cause_scope(cause: &ActionCause) -> StoreResult<String> {
    let (scope, key): (String, String) = serde_json::from_str(&cause.record_ref)?;
    if key != KEY || serde_json::to_string(&(&scope, KEY))? != cause.record_ref {
        return Err(refused());
    }
    Ok(scope)
}

fn source_for_cause(
    product: &Store,
    home: &str,
    issuer: &str,
    key: &PublicKey,
    cause: &ActionCause,
) -> StoreResult<SignedSource> {
    if cause.authority != issuer {
        return Err(refused());
    }
    let scope = cause_scope(cause)?;
    let source = load_source(product, &scope, key)?.ok_or_else(refused)?;
    let s = &source.statement;
    if s.protocol != PROTOCOL
        || s.home != home
        || s.issuer != issuer
        || s.observer.trim().is_empty()
        || source_scope(home, &s.observer, &s.request_id)? != scope
        || s.input.handle != "saved_source"
        || s.input.label_ref != label(&s.restrictions)?
        || s.restrictions.principal
        || s.restrictions.internal
        || !s.restrictions.writer.is_empty()
        || digest(s.snapshot()?.as_bytes()) != cause.digest
    {
        return Err(refused());
    }
    Ok(source)
}

fn same_saved_evidence(
    source: &SourceStatement,
    observed: &EditorFileSaveObservation,
) -> StoreResult<()> {
    let mut actual = statement(
        &source.home,
        &source.request_id,
        source.input.clone(),
        observed,
        EditorFileSaveAttempt {
            effect_id: &source.effect_id,
            run_id: &source.attempt.run_id,
        },
    )?;
    // These two fields describe the historical preparer. Today's observer and
    // combined restrictions are checked separately; the original fact is never
    // modified or republished when another principal derives from it.
    actual.observer = source.observer.clone();
    actual.restrictions = source.restrictions.clone();
    if actual != *source {
        return Err(refused());
    }
    Ok(())
}

impl Workbench {
    /// Closed native profiles, with the source scope included in every later
    /// authorization snapshot. This parses coordinates, not a source grant.
    pub(in crate::file_action_factory) fn correction_source_scope(
        command: &HostActionCommand,
    ) -> Result<Option<String>, String> {
        match (
            command.provenance.origin.as_str(),
            command.provenance.causes.as_slice(),
        ) {
            ("editor.corrections", []) => Ok(None),
            ("editor.corrections.derived", [cause]) => cause_scope(cause)
                .map(Some)
                .map_err(|e| format!("correction source coordinates refused: {e:?}")),
            _ => Err("correction provenance is outside the registered native profiles".into()),
        }
    }

    /// Verify historical causal metadata without resolving an earlier body.
    /// The returned ceiling is the correction's complete admitted input policy,
    /// including restrictions added between source preparation and admission.
    pub(in crate::file_action_factory) fn correction_source_policy(
        store: &Store,
        home: &str,
        key: &PublicKey,
        command: &HostActionCommand,
        policy: &HostGovernancePolicy,
    ) -> StoreResult<Option<ResourcePolicy>> {
        if Self::correction_source_scope(command)
            .map_err(StoreError::Conflict)?
            .is_none()
        {
            return Ok(None);
        }
        let source = source_for_cause(
            store,
            home,
            &command.issuer,
            key,
            &command.provenance.causes[0],
        )?;
        for address in ["memory:/action/corrections", "result", "error"] {
            let retained = policy.resources.get(address).ok_or_else(refused)?;
            if retained.principal
                || retained.internal
                || !retained.writer.is_empty()
                || !source
                    .statement
                    .restrictions
                    .reader
                    .is_subset(&retained.reader)
            {
                return Err(refused());
            }
        }
        Ok(Some(policy.resources["memory:/action/corrections"].clone()))
    }

    pub(in crate::file_action_factory) fn prepare_editor_saved_source(
        &mut self,
        context: &AuthenticatedActionContext,
        storage: &NativeActionStorage,
        cause: &ActionCause,
    ) -> Result<PreparedSavedSource, String> {
        storage.require_home(self)?;
        let key = SigningKey::from_seed(&self.governance_seed()).map_err(|e| e.reason)?;
        let source = source_for_cause(
            self.store_ref(),
            self.home_id().as_str(),
            self.authority().as_str(),
            &key.public_key(),
            cause,
        )
        .map_err(|e| format!("saved source cause refused: {e:?}"))?;
        let command = self
            .store_ref()
            .fold::<ProductActionAdmission>(&source.statement.admission.instance_ref)
            .map_err(|e| format!("original source command unavailable: {e:?}"))?
            .command
            .ok_or("original source command unavailable")?;
        if command.fingerprint().map_err(|e| format!("{e:?}"))?
            != source.statement.command_fingerprint
        {
            return Err("saved source command identity changed".into());
        }
        let observed = self.with_editor_file_save_observation(
            context,
            &command,
            &source.statement.admission,
            EditorFileSaveAttempt {
                effect_id: &source.statement.effect_id,
                run_id: &source.statement.attempt.run_id,
            },
            SavedObservationOptions {
                through: Some(source.statement.observed_at.clone()),
                retained: Some(&source.statement.restrictions),
            },
            |observed, _, _, _| Ok(observed),
        )?;
        same_saved_evidence(&source.statement, &observed).map_err(|e| format!("{e:?}"))?;
        let retained = storage
            .inputs()
            .resolve(&source.statement.input)
            .map_err(|e| format!("saved source custody refused: {e:?}"))?;
        if retained.content_hash != source.statement.content_hash
            || observed
                .saved
                .as_ref()
                .is_none_or(|saved| saved.accepted_content != retained.content)
        {
            return Err("saved source custody differs from original evidence".into());
        }
        Ok(PreparedSavedSource {
            source,
            command,
            restrictions: observed.restrictions,
            cause: cause.clone(),
        })
    }

    /// The caller already holds the source and derived-input custody exclusion.
    /// Recheck source authority, exact attestation and target retention before
    /// handing the one-use product writer to normal destination admission.
    pub(in crate::file_action_factory) fn with_editor_saved_source<T>(
        &mut self,
        context: &AuthenticatedActionContext,
        prepared: &PreparedSavedSource,
        publish: impl for<'tx> FnOnce(
            gaugedesk_store::command_dispatch::DispatchRecordAdmission<'tx>,
        ) -> StoreResult<T>,
    ) -> Result<T, String> {
        let key = SigningKey::from_seed(&self.governance_seed()).map_err(|e| e.reason)?;
        let history = dispatch_grant::NativeDispatchHistory::open(self, key.public_key())?;
        let home = self.home_id().as_str().to_owned();
        let issuer = self.authority().as_str().to_owned();
        let expected = &prepared.source.statement;
        self.with_editor_file_save_observation(
            context,
            &prepared.command,
            &expected.admission,
            EditorFileSaveAttempt {
                effect_id: &expected.effect_id,
                run_id: &expected.attempt.run_id,
            },
            SavedObservationOptions {
                through: Some(expected.observed_at.clone()),
                retained: Some(&expected.restrictions),
            },
            |observed, original, target, writer| {
                let source = source_for_cause(
                    &history.store,
                    &home,
                    &issuer,
                    &key.public_key(),
                    &prepared.cause,
                )?;
                if source.statement != *expected || observed.restrictions != prepared.restrictions {
                    return Err(refused());
                }
                same_saved_evidence(expected, &observed)?;
                target
                    .publish_committed_scoped_result(
                        &original.binding,
                        &original.resolution_scope,
                        &original.attempt,
                        |_, saved| {
                            if saved.reference != expected.receipt
                                || digest(saved.receipt_json.as_bytes()) != expected.receipt_digest
                                || whipplescript_store::stable_hash_hex(&saved.accepted_content)
                                    != expected.content_hash
                            {
                                return Err(refused());
                            }
                            publish(writer)
                        },
                    )?
                    .ok_or_else(refused)
            },
        )
    }
}
