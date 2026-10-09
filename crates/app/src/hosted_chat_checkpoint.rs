//! Chat-lifetime custody for a verified hosted runtime thread (GaugeWright DR-0263).
//!
//! The private Home obtains the export from its exact signed command route. This
//! module owns storage and erasure, not the WhippleScript source attestation or
//! the target handoff. An export is never accepted from a browser request.

use crate::workbench_state::Workbench;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const KIND: &str = "hosted_chat_checkpoint";
pub const HANDOFF_KIND: &str = "hosted_chat_handoff";
const MAX_EXPORT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedChatCheckpoint {
    pub version: u8,
    pub chat_id: String,
    pub source_command_id: String,
    pub export_sha256: String,
    pub export: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedCheckpoint {
    version: u8,
    ciphertext: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostedChatHandoff {
    version: u8,
    chat_id: String,
    source_pin: String,
    target_command_id: String,
    target_request_id: String,
    target_package: String,
    target_policy: Value,
    target_instance_ref: Option<String>,
    fork_sequence: Option<u64>,
}

fn refused() -> String {
    "hosted chat checkpoint is unavailable or invalid".into()
}

fn export_bytes(export: &Value) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(export).map_err(|_| refused())?;
    if bytes.len() > MAX_EXPORT_BYTES {
        return Err("hosted chat checkpoint exceeds the supported size".into());
    }
    Ok(bytes)
}

fn aad(chat_id: &str) -> Vec<u8> {
    serde_json::to_vec(&("gaugedesk.hosted-chat-checkpoint/v1", chat_id))
        .expect("string tuple serialization")
}

impl HostedChatCheckpoint {
    pub fn new(chat_id: &str, source_command_id: &str, export: Value) -> Result<Self, String> {
        if chat_id.is_empty() || source_command_id.is_empty() {
            return Err(refused());
        }
        let bytes = export_bytes(&export)?;
        let source = export.get("source").ok_or_else(refused)?;
        if source
            .get("instance_ref")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            || source
                .get("sequence")
                .and_then(Value::as_u64)
                .is_none_or(|n| n == 0)
            || export.get("policy").is_none()
            || export
                .get("package_version_ref")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || export.get("messages").and_then(Value::as_array).is_none()
        {
            return Err(refused());
        }
        Ok(Self {
            version: 1,
            chat_id: chat_id.into(),
            source_command_id: source_command_id.into(),
            export_sha256: hex::encode(Sha256::digest(&bytes)),
            export,
        })
    }

    fn validate(&self, chat_id: &str) -> Result<(), String> {
        if self.version != 1 || self.chat_id != chat_id {
            return Err(refused());
        }
        let rebuilt = Self::new(&self.chat_id, &self.source_command_id, self.export.clone())?;
        if self.export_sha256 != rebuilt.export_sha256 {
            return Err(refused());
        }
        Ok(())
    }
}

impl Workbench {
    fn handoff_for(
        &self,
        chat_id: &str,
        command_id: &str,
    ) -> Result<Option<HostedChatHandoff>, String> {
        self.store.retained_events(chat_id).map_err(|_| refused())?;
        let rows = self
            .store
            .records(chat_id, HANDOFF_KIND)
            .map_err(|_| refused())?;
        let mut selected = None;
        for row in rows {
            let sealed: SealedCheckpoint = serde_json::from_str(&row).map_err(|_| refused())?;
            if sealed.version != 1 {
                return Err(refused());
            }
            let key = self
                .content_vault
                .as_ref()
                .ok_or_else(refused)?
                .prepare_scope_key(chat_id)
                .map_err(|_| refused())?;
            let ciphertext = STANDARD.decode(sealed.ciphertext).map_err(|_| refused())?;
            let plaintext = key
                .open(
                    &serde_json::to_vec(&("gaugedesk.hosted-chat-handoff/v1", chat_id))
                        .map_err(|_| refused())?,
                    &ciphertext,
                )
                .map_err(|_| refused())?;
            let handoff: HostedChatHandoff =
                serde_json::from_slice(&plaintext).map_err(|_| refused())?;
            if handoff.version != 1 || handoff.chat_id != chat_id {
                return Err(refused());
            }
            if handoff.target_command_id == command_id {
                selected = Some(handoff);
            }
        }
        Ok(selected)
    }

    fn append_handoff(&mut self, handoff: &HostedChatHandoff) -> Result<(), String> {
        let key = self
            .content_vault
            .as_ref()
            .ok_or_else(refused)?
            .prepare_scope_key(&handoff.chat_id)
            .map_err(|_| refused())?;
        let aad = serde_json::to_vec(&("gaugedesk.hosted-chat-handoff/v1", &handoff.chat_id))
            .map_err(|_| refused())?;
        let plaintext = serde_json::to_vec(handoff).map_err(|_| refused())?;
        let ciphertext = key.seal(&aad, &plaintext).map_err(|_| refused())?;
        let payload = serde_json::to_string(&SealedCheckpoint {
            version: 1,
            ciphertext: STANDARD.encode(ciphertext),
        })
        .map_err(|_| refused())?;
        key.retain(|| {
            self.store
                .append_record(&handoff.chat_id, HANDOFF_KIND, &payload)
                .map(|_| ())
                .map_err(|error| std::io::Error::other(format!("{error:?}")))
        })
        .map_err(|_| refused())
    }

    /// Register the exact source and target before any target runtime write.
    pub fn register_hosted_chat_handoff(
        &mut self,
        chat_id: &str,
        source_pin: &str,
        target_command_id: &str,
        target_request_id: &str,
        target_package: &str,
        target_policy: Value,
    ) -> Result<(), String> {
        let checkpoint = self
            .latest_hosted_chat_checkpoint(chat_id)?
            .ok_or_else(refused)?;
        if checkpoint.export_sha256 != source_pin
            || checkpoint.source_command_id == target_command_id
            || target_command_id.is_empty()
            || target_request_id.is_empty()
            || target_package.is_empty()
        {
            return Err(refused());
        }
        let expected = HostedChatHandoff {
            version: 1,
            chat_id: chat_id.into(),
            source_pin: source_pin.into(),
            target_command_id: target_command_id.into(),
            target_request_id: target_request_id.into(),
            target_package: target_package.into(),
            target_policy,
            target_instance_ref: None,
            fork_sequence: None,
        };
        if let Some(prior) = self.handoff_for(chat_id, target_command_id)? {
            let mut comparison = prior;
            comparison.target_instance_ref = None;
            comparison.fork_sequence = None;
            return if comparison == expected {
                Ok(())
            } else {
                Err(refused())
            };
        }
        self.append_handoff(&expected)
    }

    /// Complete only after the target returns its exact fork receipt.
    pub fn complete_hosted_chat_handoff(
        &mut self,
        chat_id: &str,
        source_pin: &str,
        target_command_id: &str,
        target_request_id: &str,
        receipt: &Value,
    ) -> Result<(), String> {
        let mut pending = self
            .handoff_for(chat_id, target_command_id)?
            .ok_or_else(refused)?;
        let checkpoint = self
            .latest_hosted_chat_checkpoint(chat_id)?
            .ok_or_else(refused)?;
        let target = receipt.get("target").ok_or_else(refused)?;
        let instance_ref = target
            .get("instance_ref")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(refused)?;
        let sequence = receipt
            .get("forked_at")
            .and_then(|value| value.get("sequence"))
            .and_then(Value::as_u64)
            .filter(|value| *value > 0)
            .ok_or_else(refused)?;
        if pending.source_pin != source_pin
            || pending.target_request_id != target_request_id
            || checkpoint.export_sha256 != source_pin
            || receipt.get("source") != checkpoint.export.get("source")
            || target.get("request_id").and_then(Value::as_str) != Some(target_request_id)
            || target.get("package_version_ref").and_then(Value::as_str)
                != Some(&pending.target_package)
            || target.get("policy") != Some(&pending.target_policy)
            || receipt
                .get("forked_at")
                .and_then(|value| value.get("instance_ref"))
                .and_then(Value::as_str)
                != Some(instance_ref)
        {
            return Err(refused());
        }
        if pending.target_instance_ref.is_some() || pending.fork_sequence.is_some() {
            return if pending.target_instance_ref.as_deref() == Some(instance_ref)
                && pending.fork_sequence == Some(sequence)
            {
                Ok(())
            } else {
                Err(refused())
            };
        }
        pending.target_instance_ref = Some(instance_ref.into());
        pending.fork_sequence = Some(sequence);
        self.append_handoff(&pending)
    }

    pub fn hosted_chat_handoff_complete(
        &self,
        chat_id: &str,
        target_command_id: &str,
    ) -> Result<bool, String> {
        Ok(self
            .handoff_for(chat_id, target_command_id)?
            .is_some_and(|handoff| {
                handoff.target_instance_ref.is_some() && handoff.fork_sequence.is_some()
            }))
    }

    /// Append one exact source checkpoint under the chat's key. A retry for
    /// the same command must present the same bytes; it cannot rewrite a pin.
    pub fn retain_hosted_chat_checkpoint(
        &mut self,
        checkpoint: HostedChatCheckpoint,
    ) -> Result<(), String> {
        checkpoint.validate(&checkpoint.chat_id)?;
        if !self.library.chats.contains_key(&checkpoint.chat_id) {
            return Err(refused());
        }
        if let Some(previous) = self.latest_hosted_chat_checkpoint(&checkpoint.chat_id)? {
            if previous.source_command_id == checkpoint.source_command_id {
                return if previous.export_sha256 == checkpoint.export_sha256 {
                    Ok(())
                } else {
                    Err("hosted command changed its retained source checkpoint".into())
                };
            }
        }
        let vault = self.content_vault.as_ref().ok_or_else(refused)?;
        let key = vault
            .prepare_scope_key(&checkpoint.chat_id)
            .map_err(|_| refused())?;
        let plaintext = serde_json::to_vec(&checkpoint).map_err(|_| refused())?;
        let ciphertext = key
            .seal(&aad(&checkpoint.chat_id), &plaintext)
            .map_err(|_| refused())?;
        let payload = serde_json::to_string(&SealedCheckpoint {
            version: 1,
            ciphertext: STANDARD.encode(ciphertext),
        })
        .map_err(|_| refused())?;
        key.retain(|| {
            self.store
                .append_record(&checkpoint.chat_id, KIND, &payload)
                .map(|_| ())
                .map_err(|error| std::io::Error::other(format!("{error:?}")))
        })
        .map_err(|_| refused())
    }

    /// Read the newest retained source. An unreadable row refuses the whole
    /// history; it is never skipped in favor of an older or empty checkpoint.
    pub fn latest_hosted_chat_checkpoint(
        &self,
        chat_id: &str,
    ) -> Result<Option<HostedChatCheckpoint>, String> {
        if !self.library.chats.contains_key(chat_id) {
            return Err(refused());
        }
        self.store.retained_events(chat_id).map_err(|_| refused())?;
        let rows = self.store.records(chat_id, KIND).map_err(|_| refused())?;
        let Some(row) = rows.last() else {
            return Ok(None);
        };
        let sealed: SealedCheckpoint = serde_json::from_str(row).map_err(|_| refused())?;
        if sealed.version != 1 {
            return Err(refused());
        }
        let key = self
            .content_vault
            .as_ref()
            .ok_or_else(refused)?
            .prepare_scope_key(chat_id)
            .map_err(|_| refused())?;
        let ciphertext = STANDARD.decode(sealed.ciphertext).map_err(|_| refused())?;
        let plaintext = key
            .open(&aad(chat_id), &ciphertext)
            .map_err(|_| refused())?;
        let checkpoint: HostedChatCheckpoint =
            serde_json::from_slice(&plaintext).map_err(|_| refused())?;
        checkpoint.validate(chat_id)?;
        Ok(Some(checkpoint))
    }

    /// A hosted command without a checkpoint may open only at the start of a
    /// chat. Older hosted runs had no checkpoint; their visible transcript is
    /// not sufficient to reconstruct the runtime's tool and policy history.
    pub fn hosted_chat_has_prior_turn(&self, chat_id: &str) -> Result<bool, String> {
        if !self.library.chats.contains_key(chat_id) {
            return Err(refused());
        }
        self.store.retained_events(chat_id).map_err(|_| refused())?;
        let rows = self
            .store
            .records(chat_id, "transcript")
            .map_err(|_| refused())?;
        let mut users = 0;
        for row in rows {
            let event: serde_json::Value = serde_json::from_str(&row).map_err(|_| refused())?;
            match event["type"].as_str() {
                Some("user") => {
                    users += 1;
                    if users > 1 {
                        return Ok(true);
                    }
                }
                Some("assistant" | "tool" | "toolresult" | "blocked" | "error") => return Ok(true),
                _ => {}
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn hosted_history_is_chat_sealed_and_handoff_requires_exact_receipt() {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("home.sqlite");
        let vault = Arc::new(
            crate::content_vault::ContentVault::new(
                root.path().join("keys"),
                Box::new(crate::at_rest::LoopbackKeyWrap::new([8; 32])),
            )
            .with_ledger(Box::new(crate::content_vault::LocalFileErasureLedger::new(
                root.path().join("erasures"),
            ))),
        );
        let store = gaugedesk_store::Store::open(db.to_str().unwrap())
            .unwrap()
            .with_codec(vault.clone());
        let mut wb = Workbench::new(store).with_content_vault(vault.clone());
        vault.initialize_scope_key("chat-one").unwrap();
        wb.library.chats.insert(
            "chat-one".into(),
            serde_json::from_value(serde_json::json!({
                "id": "chat-one", "instance_id": "placement-one", "title": "History",
            }))
            .unwrap(),
        );
        assert!(!wb.hosted_chat_has_prior_turn("chat-one").unwrap());
        wb.store
            .append_record(
                "chat-one",
                "transcript",
                r#"{"type":"user","text":"hello"}"#,
            )
            .unwrap();
        assert!(!wb.hosted_chat_has_prior_turn("chat-one").unwrap());
        wb.store
            .append_record(
                "chat-one",
                "transcript",
                r#"{"type":"assistant","text":"reply"}"#,
            )
            .unwrap();
        assert!(wb.hosted_chat_has_prior_turn("chat-one").unwrap());
        let export = serde_json::json!({
            "protocol": "whip-host/v1",
            "source": {"instance_ref": "source-one", "sequence": 9},
            "policy": {"epoch": 1},
            "package_version_ref": "package-one",
            "messages": [{"role": "user", "content": "private prompt"}],
        });
        let checkpoint =
            HostedChatCheckpoint::new("chat-one", "command-one", export.clone()).unwrap();
        wb.retain_hosted_chat_checkpoint(checkpoint.clone())
            .unwrap();
        assert_eq!(
            wb.latest_hosted_chat_checkpoint("chat-one")
                .unwrap()
                .unwrap()
                .export,
            export
        );
        let raw: String = rusqlite::Connection::open(&db).unwrap().query_row(
            "SELECT payload FROM events WHERE scope_id='chat-one' AND kind='hosted_chat_checkpoint'",
            [], |row| row.get(0),
        ).unwrap();
        assert!(!raw.contains("private prompt"));
        assert!(raw.starts_with("gwenc:"));

        let policy = serde_json::json!({"epoch": 2, "envelope_hash": "target-policy"});
        wb.register_hosted_chat_handoff(
            "chat-one",
            &checkpoint.export_sha256,
            "command-two",
            "target-open",
            "package-two",
            policy.clone(),
        )
        .unwrap();
        let receipt = serde_json::json!({
            "source": export["source"],
            "target": {"request_id": "target-open", "instance_ref": "target-one",
                "package_version_ref": "package-two", "policy": policy},
            "forked_at": {"instance_ref": "target-one", "sequence": 4},
        });
        let mut wrong = receipt.clone();
        wrong["source"]["sequence"] = serde_json::json!(8);
        assert!(wb
            .complete_hosted_chat_handoff(
                "chat-one",
                &checkpoint.export_sha256,
                "command-two",
                "target-open",
                &wrong
            )
            .is_err());
        assert!(!wb
            .hosted_chat_handoff_complete("chat-one", "command-two")
            .unwrap());
        wb.complete_hosted_chat_handoff(
            "chat-one",
            &checkpoint.export_sha256,
            "command-two",
            "target-open",
            &receipt,
        )
        .unwrap();
        assert!(wb
            .hosted_chat_handoff_complete("chat-one", "command-two")
            .unwrap());
        assert!(vault.crypto_erase("chat-one"));
        assert!(wb.latest_hosted_chat_checkpoint("chat-one").is_err());
        assert!(wb
            .hosted_chat_handoff_complete("chat-one", "command-two")
            .is_err());
    }
}
