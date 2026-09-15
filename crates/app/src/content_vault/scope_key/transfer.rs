//! Recipient-bound content-key custody. No product authority is granted here.
use super::*;
use crate::device_enroll::{open_sealed, seal_to_subkey, SealedKey};
use gaugedesk_core::{ids::PublicKey, signature::SigningKey};
use serde::{Deserialize, Serialize};

const PROTOCOL: &str = "gaugedesk.scope-key-transfer.v1";

/// Only sealed key bytes and their public binding may enter handoff custody.
/// The expected scope and recipient come from the receiving admission context.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeKeyCapsule {
    protocol: String,
    scope: String,
    recipient: PublicKey,
    sealed: SealedKey,
}

// Never Debug or expose the unsealed payload through a product-facing API.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyPayload {
    protocol: String,
    scope: String,
    recipient: PublicKey,
    data_key: [u8; 32],
}

/// Remote ledger/KMS preparation has finished. Publish the capsule only inside
/// retained product admission, after taking the product writer. The receiver's
/// later consent and network delivery run outside that transaction.
pub struct PreparedScopeTransfer {
    key: Arc<PreparedScopeKey>,
    capsule: ScopeKeyCapsule,
}
impl PreparedScopeTransfer {
    pub fn with_retained<T, E: From<std::io::Error>>(
        &self,
        operation: impl FnOnce(&Arc<PreparedScopeKey>, &ScopeKeyCapsule) -> Result<T, E>,
    ) -> Result<T, E> {
        self.key.retain(|| operation(&self.key, &self.capsule))
    }
}

fn invalid_transfer() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "scope key transfer binding is invalid",
    )
}

impl ContentVault {
    /// Prepare existing source custody; never mint a missing transfer key.
    /// Ledger confirmation and key unwrap belong outside product transactions.
    pub fn prepare_scope_transfer(
        &self,
        scope: &str,
        recipient: &PublicKey,
    ) -> std::io::Result<PreparedScopeTransfer> {
        let key_id = self.confirmed_scope(scope)?;
        let root = std::fs::canonicalize(&self.dir)?;
        let _lease = shared(&root, &key_id)?;
        available(&root, &key_id)?;
        let wrapped = std::fs::read(key_path(&root, &key_id))?;
        let data_key = self.wrap.unwrap(&wrapped).map_err(custody_error)?;
        let payload = KeyPayload {
            protocol: PROTOCOL.into(),
            scope: scope.into(),
            recipient: recipient.clone(),
            data_key,
        };
        let bytes = serde_json::to_vec(&payload).map_err(|_| invalid_transfer())?;
        let sealed = seal_to_subkey(recipient, &bytes).ok_or_else(invalid_transfer)?;
        Ok(PreparedScopeTransfer {
            key: Arc::new(PreparedScopeKey {
                root,
                scope: scope.into(),
                key_id,
                wrapped_fingerprint: fingerprint(&wrapped),
                cipher: LocalAeadEncryptor::new(data_key),
            }),
            capsule: ScopeKeyCapsule {
                protocol: PROTOCOL.into(),
                scope: scope.into(),
                recipient: recipient.clone(),
                sealed,
            },
        })
    }

    /// Receive key custody for an already authenticated recipient. Receiving a key
    /// grants no project authority and does not delete the source. The caller
    /// must prepare outside product/store transactions, then retain the returned
    /// key through product publication. Matching custody is idempotent; conflicting
    /// or erased custody is never overwritten. An installed key may be retained
    /// for retry if later product import fails; it does not make that Home current.
    pub fn receive_scope_key(
        &self,
        expected_scope: &str,
        recipient: &SigningKey,
        capsule: &ScopeKeyCapsule,
    ) -> std::io::Result<PreparedScopeKey> {
        let recipient_public = recipient.public_key();
        if capsule.protocol != PROTOCOL
            || capsule.scope != expected_scope
            || capsule.recipient != recipient_public
        {
            return Err(invalid_transfer());
        }
        let key_id = self.confirmed_scope(expected_scope)?;
        let bytes = open_sealed(recipient, &capsule.sealed).ok_or_else(invalid_transfer)?;
        let payload: KeyPayload = serde_json::from_slice(&bytes).map_err(|_| invalid_transfer())?;
        if payload.protocol != PROTOCOL
            || payload.scope != expected_scope
            || payload.recipient != recipient_public
        {
            return Err(invalid_transfer());
        }
        std::fs::create_dir_all(&self.dir)?;
        let root = std::fs::canonicalize(&self.dir)?;
        let _lease = exclusive(&root, &key_id)?;
        available(&root, &key_id)?;
        let path = key_path(&root, &key_id);
        let wrapped = match std::fs::read(&path) {
            Ok(wrapped) => {
                if self.wrap.unwrap(&wrapped).map_err(custody_error)? != payload.data_key {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "receiving scope has conflicting content-key custody",
                    ));
                }
                wrapped
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let wrapped = self.wrap.wrap(&payload.data_key).map_err(custody_error)?;
                persist_new(&root, &path, &wrapped)?;
                wrapped
            }
            Err(error) => return Err(error),
        };
        // A prior attempt may have published the wrapped file but failed its
        // final sync. Matching replay must finish that durability step too.
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)?
            .sync_all()?;
        sync_directory(&root)?;
        self.key_state.lock().unwrap().cache.remove(expected_scope);
        Ok(PreparedScopeKey {
            root,
            scope: expected_scope.into(),
            key_id,
            wrapped_fingerprint: fingerprint(&wrapped),
            cipher: LocalAeadEncryptor::new(payload.data_key),
        })
    }
}

#[cfg(test)]
mod tests;
