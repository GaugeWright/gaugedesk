//! Encrypted prepared bytes under one original pending office task. A retained
//! copy is not evidence of a successful native write or publication permission.
use super::{
    office_turn_startup::{self, OfficeTurnContext, OfficeTurnStartup},
    EngineError, RunState, TurnForkSnapshot,
};
use crate::{content_vault::PreparedScopeKey, LockUnpoisoned};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use gaugedesk_store::{command_dispatch::LifecycleBatch, CommandRecordFact, Store};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const KIND: &str = "office_turn_payload";

/// Owned original locators for the native owner's static callback. Every call
/// rechecks the original staff/HTTP claim; copying these grants no authority.
struct OriginalPayloadRetention {
    wb: crate::SharedWorkbench,
    authority: super::office_authority::OfficeTaskAuthority,
    original: crate::command_idempotency::ClaimedHttpCommand,
    startup: OfficeTurnStartup,
    fork: Option<TurnForkSnapshot>,
}
impl gaugedesk_harness::WorkspacePayloadRetention for OriginalPayloadRetention {
    fn retain(
        &self,
        file: &gaugedesk_harness::PreparedWorkspaceFile,
        body: &[u8],
    ) -> Result<(), String> {
        let office = OfficeTurnContext {
            wb: &self.wb,
            authority: &self.authority,
            original: &self.original,
        };
        retain(
            &office,
            &self.startup,
            self.fork.as_ref(),
            &PreparedFile {
                path: file.path.clone(),
                kind: file.kind.clone(),
                sha256: file.sha256.clone(),
                bytes: file.bytes,
            },
            body,
        )
        .map_err(|_| "original office file payload refused".into())
    }
}
pub(crate) fn callback(
    office: &OfficeTurnContext<'_>,
    startup: &OfficeTurnStartup,
    fork: Option<&TurnForkSnapshot>,
) -> std::sync::Arc<dyn gaugedesk_harness::WorkspacePayloadRetention> {
    std::sync::Arc::new(OriginalPayloadRetention {
        wb: office.wb.clone(),
        authority: office.authority.clone(),
        original: office.original.clone(),
        startup: startup.clone(),
        fork: fork.cloned(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedFile {
    pub(crate) path: String,
    pub(crate) kind: String,
    pub(crate) sha256: String,
    pub(crate) bytes: u64,
}
impl PreparedFile {
    fn validate(&self) -> Result<(), EngineError> {
        if self.path.is_empty()
            || self.path.contains('\\')
            || self.path.chars().any(char::is_control)
            || self
                .path
                .split('/')
                .any(|p| matches!(p, "" | "." | ".." | ".git" | ".gaugedesk-folder"))
            || !matches!(self.kind.as_str(), "add" | "modify" | "delete")
            || self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || (self.kind == "delete"
                && (self.bytes != 0 || self.sha256 != hex::encode(Sha256::digest([]))))
        {
            return Err(refused());
        }
        Ok(())
    }
    fn matches(&self, body: &[u8]) -> Result<(), EngineError> {
        self.validate()?;
        if self.bytes != body.len() as u64 || self.sha256 != hex::encode(Sha256::digest(body)) {
            return Err(refused());
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    command: String,
    actor: String,
    chat: String,
    base: String,
    lineage: String,
    input: i64,
    runtime: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    binding: Binding,
    file: PreparedFile,
    body: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    revision: String,
    command: String,
    phase: String,
    sealed: String,
}
fn refused() -> EngineError {
    EngineError::Message("original office file payload refused".into())
}
fn json<T: Serialize>(value: &T) -> Result<Vec<u8>, EngineError> {
    serde_json::to_vec(value).map_err(|_| refused())
}
fn binding(
    office: &OfficeTurnContext<'_>,
    startup: &OfficeTurnStartup,
    preparation: &gaugedesk_harness::RuntimeTurnPreparation,
) -> Result<Binding, EngineError> {
    Ok(Binding {
        command: office.original.command_id().into(),
        actor: office.authority.actor().into(),
        chat: office.authority.chat().into(),
        base: startup.native_base.base_cut().into(),
        lineage: hex::encode(Sha256::digest(json(
            startup
                .native_base
                .original_lineage()
                .map_err(|_| refused())?,
        )?)),
        input: startup.user_entry_id,
        runtime: hex::encode(Sha256::digest(json(preparation)?)),
    })
}
fn phase(binding: &Binding, file: &PreparedFile) -> Result<String, EngineError> {
    Ok(format!(
        "file-payload-{}",
        hex::encode(Sha256::digest(json(&(
            "office-file-phase/v2",
            binding,
            file,
        ))?))
    ))
}

/// Only encrypted original locators cross the read/writer boundary. The final
/// ordered owner witness selects the phases; preparation alone proves no write.
pub(crate) struct ResultPayloadPlan {
    binding: Binding,
    files: std::collections::BTreeMap<String, (PreparedFile, String)>,
}
impl ResultPayloadPlan {
    pub(crate) fn new(
        office: &OfficeTurnContext<'_>,
        startup: &OfficeTurnStartup,
        preparation: &gaugedesk_harness::RuntimeTurnPreparation,
        witness: &[PreparedFile],
    ) -> Result<Self, EngineError> {
        let binding = binding(office, startup, preparation)?;
        let mut files = std::collections::BTreeMap::new();
        for file in witness {
            file.validate()?;
            files.insert(file.path.clone(), (file.clone(), phase(&binding, file)?));
        }
        Ok(Self { binding, files })
    }
    pub(crate) fn scopes(&self) -> Vec<String> {
        std::iter::once(self.binding.chat.clone())
            .chain(self.files.values().map(|(_, phase)| {
                Store::claimed_lifecycle_prefix_scope(&self.binding.command, phase)
            }))
            .collect()
    }
    pub(crate) fn observe(
        self,
        store: &Store,
    ) -> Result<ObservedResultPayloads, gaugedesk_store::AdmitError> {
        for scope in self.scopes() {
            store.retained_events(&scope)?;
        }
        let envelopes = store
            .records(&self.binding.chat, KIND)?
            .into_iter()
            .map(|raw| {
                serde_json::from_str::<Envelope>(&raw)
                    .map(|envelope| (raw, envelope))
                    .map_err(gaugedesk_store::AdmitError::Json)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut selected = Vec::new();
        for (file, phase) in self.files.into_values() {
            let matching: Vec<_> = envelopes
                .iter()
                .filter(|(_, row)| row.command == self.binding.command && row.phase == phase)
                .collect();
            let [(raw, _)] = matching.as_slice() else {
                return Err(gaugedesk_store::AdmitError::Rejected(
                    gaugedesk_core::Rejection {
                        reason: "original saved file envelope unavailable or ambiguous",
                    },
                ));
            };
            selected.push((file, phase, raw.clone()));
        }
        Ok(ObservedResultPayloads {
            binding: self.binding,
            selected,
        })
    }
}
pub(crate) struct ObservedResultPayloads {
    binding: Binding,
    selected: Vec<(PreparedFile, String, String)>,
}
impl ObservedResultPayloads {
    /// The writer is consumed here, including on every decoding/key refusal.
    /// Existing key custody spans exact phase verification, decryption, native
    /// preparation/publication and the caller's original product completion.
    pub(crate) fn consume<T>(
        self,
        writer: gaugedesk_store::command_dispatch::DispatchRecordAdmission<'_>,
        key: &PreparedScopeKey,
        original: &crate::command_idempotency::ClaimedHttpCommand,
        publish: impl FnOnce(
            gaugedesk_store::command_dispatch::DispatchRecordAdmission<'_>,
            std::collections::BTreeMap<String, Vec<u8>>,
        ) -> Result<T, EngineError>,
    ) -> Result<T, EngineError> {
        let consume = || {
            if key.scope() != self.binding.chat || original.command_id() != self.binding.command {
                return Err(refused());
            }
            writer.require_pending_claim(
                original.command_id(),
                original.scope(),
                original.key(),
                original.snapshot(),
            )?;
            let mut bodies = std::collections::BTreeMap::new();
            for (file, phase, raw) in self.selected {
                writer.require_claimed_lifecycle_prefix(
                    original.command_id(),
                    original.scope(),
                    original.key(),
                    original.snapshot(),
                    &phase,
                    &LifecycleBatch::<RunState> {
                        scope: self.binding.chat.clone(),
                        commands: vec![],
                    },
                    &[CommandRecordFact {
                        scope_id: self.binding.chat.clone(),
                        kind: KIND.into(),
                        payload: raw.clone(),
                    }],
                )?;
                let envelope: Envelope = serde_json::from_str(&raw).map_err(|_| refused())?;
                let body = envelope.open(key, &self.binding, &phase, &file)?;
                bodies.insert(file.path, body);
            }
            writer.with_native_check(|check| check.check_current())??;
            publish(writer, bodies)
        };
        key.retain(|| Ok::<_, std::io::Error>(consume()))
            .map_err(|_| refused())?
    }
}
fn aad(binding: &Binding, phase: &str) -> Result<Vec<u8>, EngineError> {
    json(&(
        "gaugedesk.office-file-payload/v2",
        &binding.chat,
        &binding.command,
        phase,
    ))
}
impl Envelope {
    fn open(
        &self,
        key: &PreparedScopeKey,
        binding: &Binding,
        phase: &str,
        file: &PreparedFile,
    ) -> Result<Vec<u8>, EngineError> {
        if self.revision != "office-file-envelope/v2"
            || self.command != binding.command
            || self.phase != phase
            || key.scope() != binding.chat
        {
            return Err(refused());
        }
        let sealed = STANDARD.decode(&self.sealed).map_err(|_| refused())?;
        let decoded = key
            .open(&aad(binding, phase)?, &sealed)
            .map_err(|_| refused())?;
        let payload: Payload = serde_json::from_slice(&decoded).map_err(|_| refused())?;
        if payload.binding != *binding || payload.file != *file {
            return Err(refused());
        }
        let body = STANDARD.decode(payload.body).map_err(|_| refused())?;
        file.matches(&body)?;
        Ok(body)
    }
}

pub(crate) fn retain(
    office: &OfficeTurnContext<'_>,
    startup: &OfficeTurnStartup,
    fork: Option<&TurnForkSnapshot>,
    file: &PreparedFile,
    body: &[u8],
) -> Result<(), EngineError> {
    file.matches(body)?;
    operate(office, startup, fork, file, Some(body)).map(|_| ())
}
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "saved native witness consumer pending")
)]
pub(crate) fn recorded(
    office: &OfficeTurnContext<'_>,
    startup: &OfficeTurnStartup,
    fork: Option<&TurnForkSnapshot>,
    file: &PreparedFile,
) -> Result<Vec<u8>, EngineError> {
    file.validate()?;
    operate(office, startup, fork, file, None)
}
fn operate(
    office: &OfficeTurnContext<'_>,
    startup: &OfficeTurnStartup,
    fork: Option<&TurnForkSnapshot>,
    file: &PreparedFile,
    offered: Option<&[u8]>,
) -> Result<Vec<u8>, EngineError> {
    let preparation = office_turn_startup::recorded_runtime(office, startup, fork)?;
    let original = office.original;
    let scope = office.authority.chat();
    let binding = binding(office, startup, &preparation)?;
    let phase = phase(&binding, file)?;
    let phase_scope = Store::claimed_lifecycle_prefix_scope(original.command_id(), &phase);
    let mut wb = office.wb.lock_unpoisoned();
    let authority = office.authority.prepare_basis(&wb)?;
    original.verify_pending(wb.store_ref())?;
    // Existing custody only, outside the product transaction. No key creation,
    // codec opt-out or legacy plaintext is a substitute for this inner envelope.
    let key = wb
        .content_vault
        .as_ref()
        .ok_or_else(refused)?
        .prepare_scope_key(scope)
        .map_err(|_| refused())?;
    let ((body, retained), observed) =
        wb.store_ref()
            .read_for_dispatch(&[scope, &phase_scope], |store| {
                store.retained_events(scope)?;
                store.retained_events(&phase_scope)?;
                let recorded =
                    store.claimed_lifecycle_prefix_recorded(original.command_id(), &phase)?;
                let envelopes = store
                    .records(scope, KIND)?
                    .into_iter()
                    .map(|row| {
                        serde_json::from_str::<Envelope>(&row)
                            .map(|envelope| (row, envelope))
                            .map_err(gaugedesk_store::AdmitError::Json)
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter(|(_, row)| row.command == binding.command && row.phase == phase)
                    .collect::<Vec<_>>();
                Ok::<_, gaugedesk_store::AdmitError>((recorded, envelopes))
            })
            .map(|((recorded, envelopes), basis)| {
                let selected = match (recorded, envelopes.as_slice()) {
                    (false, []) => offered
                        .map(|body| (body.to_vec(), None))
                        .ok_or_else(refused),
                    (true, [(raw, envelope)]) => envelope
                        .open(&key, &binding, &phase, file)
                        .and_then(|body| {
                            if offered.is_some_and(|offered| offered != body) {
                                Err(refused())
                            } else {
                                Ok((body, Some(raw.clone())))
                            }
                        }),
                    _ => Err(refused()),
                };
                selected.map(|selected| (selected, basis))
            })??;
    let basis = authority.combine(observed)?;
    let envelope = match retained {
        Some(raw) => raw,
        None => {
            let payload = Payload {
                binding: binding.clone(),
                file: file.clone(),
                body: STANDARD.encode(&body),
            };
            let sealed = key
                .seal(&aad(&binding, &phase)?, &json(&payload)?)
                .map_err(|_| refused())?;
            serde_json::to_string(&Envelope {
                revision: "office-file-envelope/v2".into(),
                command: binding.command.clone(),
                phase: phase.clone(),
                sealed: STANDARD.encode(sealed),
            })
            .map_err(|_| refused())?
        }
    };
    let facts = [CommandRecordFact {
        scope_id: scope.into(),
        kind: KIND.into(),
        payload: envelope,
    }];
    wb.store_mut()
        .with_dispatch_record_admission(&basis, |writer| {
            writer.require_pending_claim(
                original.command_id(),
                original.scope(),
                original.key(),
                original.snapshot(),
            )?;
            key.retain(|| {
                startup
                    .native_base
                    .publish_base_retained(|| {
                        // Presence alone grants no release. Verify the exact original
                        // phase meaning and retained rows under the same writer;
                        // recovery reuses its old ciphertext, without appending.
                        writer
                            .commit_claimed_lifecycle_prefix(
                                original.command_id(),
                                original.scope(),
                                original.key(),
                                original.snapshot(),
                                &phase,
                                LifecycleBatch::<RunState> {
                                    scope: scope.into(),
                                    commands: vec![],
                                },
                                &facts,
                            )
                            .map_err(|_| {
                                whipplescript_store::StoreError::Conflict(
                                    "original file payload phase refused".into(),
                                )
                            })?;
                        Ok(())
                    })
                    .map_err(|_| std::io::Error::other("original payload native custody refused"))
            })
            .map_err(|_| refused())?;
            Ok::<_, EngineError>(())
        })??;
    office.authority.prepare_basis(&wb)?;
    original.verify_pending(wb.store_ref())?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn office_prepared_payload_envelope_authenticates_phase_binding_and_bytes() {
        let root = tempfile::tempdir().unwrap();
        let vault = crate::content_vault::ContentVault::new(
            root.path(),
            Box::new(crate::at_rest::LoopbackKeyWrap::new([6; 32])),
        )
        .with_ledger(Box::new(crate::content_vault::LocalFileErasureLedger::new(
            root.path().join("erasures"),
        )));
        let key = vault.initialize_scope_key("chat").unwrap();
        let binding = Binding {
            command: "original-command".into(),
            actor: "original-actor".into(),
            chat: "chat".into(),
            base: "original-base".into(),
            lineage: "original-lineage".into(),
            input: 1,
            runtime: "original-runtime".into(),
        };
        let body = b"synthetic original\0binary\xff";
        let file = PreparedFile {
            path: "original.txt".into(),
            kind: "add".into(),
            sha256: hex::encode(Sha256::digest(body)),
            bytes: body.len() as u64,
        };
        let phase = "original-phase";
        let seal = |payload| Envelope {
            revision: "office-file-envelope/v2".into(),
            command: binding.command.clone(),
            phase: phase.into(),
            sealed: STANDARD.encode(
                key.seal(&aad(&binding, phase).unwrap(), &json(&payload).unwrap())
                    .unwrap(),
            ),
        };
        let mut envelope = seal(Payload {
            binding: binding.clone(),
            file: file.clone(),
            body: STANDARD.encode(body),
        });
        assert_eq!(envelope.open(&key, &binding, phase, &file).unwrap(), body);
        // Header and caller agree on the relocated phase, so authenticated
        // associated data must independently prevent ciphertext relocation.
        envelope.phase = "relocated-phase".into();
        assert!(envelope
            .open(&key, &binding, "relocated-phase", &file)
            .is_err());
        envelope.phase = phase.into();
        let mut changed = binding.clone();
        changed.runtime = "later runtime".into();
        assert!(envelope.open(&key, &changed, phase, &file).is_err());
        let substituted = seal(Payload {
            binding: binding.clone(),
            file: file.clone(),
            body: STANDARD.encode(b"substituted"),
        });
        assert!(substituted.open(&key, &binding, phase, &file).is_err());
        vault.erase_scope_key("chat").unwrap();
        assert!(envelope.open(&key, &binding, phase, &file).is_err());
    }
}
