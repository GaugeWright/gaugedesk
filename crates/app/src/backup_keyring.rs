//! Tenant-held recovery key material for B17 backups (ADR 0102).
//!
//! This is deliberately separate from account/device enrollment keys and from a
//! Home's content-key envelope. A backup recipient owns a P-256 private key
//! locally; the Hub receives only its public half and opaque ECIES wraps. A
//! fenced point is encrypted locally under a fresh data key, then that data key
//! is wrapped independently to each current recipient. The Hub has no operation
//! here that opens a point key or performs a recipient-to-receiver re-wrap.
//!
//! The managed-service shell persists/publicly routes only
//! [`BackupRecipientPublicKey`], [`BackupKeyWrap`], and point ciphertext. The
//! private type is intentionally neither serializable nor cloneable.

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{ecdh::diffie_hellman, PublicKey as P256PublicKey, SecretKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::at_rest::{Encryptor, LocalAeadEncryptor};

const RECIPIENT_KDF_DOMAIN: &[u8] = b"gaugewright/b17/backup-keyring/ecies/v1";

/// Why backup recipient material or a sealed point key was refused. All failures
/// remain deliberately non-specific at the cryptographic boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupKeyringError {
    InvalidRecipient,
    InvalidContext,
    Rng,
    Encrypt,
    Decrypt,
}

/// The public half of one tenant-held backup recipient. It is a hex-encoded,
/// uncompressed SEC1 P-256 point. Public recipients may be stored at the Hub;
/// this type contains no private material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BackupRecipientPublicKey(String);

impl BackupRecipientPublicKey {
    /// Parse untrusted public-key input at the service boundary.
    pub fn parse(encoded: impl Into<String>) -> Result<Self, BackupKeyringError> {
        let encoded = encoded.into();
        let bytes = hex::decode(&encoded).map_err(|_| BackupKeyringError::InvalidRecipient)?;
        P256PublicKey::from_sec1_bytes(&bytes).map_err(|_| BackupKeyringError::InvalidRecipient)?;
        Ok(Self(encoded))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn p256(&self) -> Result<P256PublicKey, BackupKeyringError> {
        let bytes = hex::decode(&self.0).map_err(|_| BackupKeyringError::InvalidRecipient)?;
        P256PublicKey::from_sec1_bytes(&bytes).map_err(|_| BackupKeyringError::InvalidRecipient)
    }
}

/// A locally held backup recipient private key. The caller owns its persistence
/// boundary (browser/device secure storage, recovery hardware, etc.); it cannot
/// be serialized or sent to a service through this API.
pub struct BackupRecipientPrivateKey(SecretKey);

impl BackupRecipientPrivateKey {
    /// Generate a new independent backup-recipient key. It must not reuse an
    /// account/session, governance-signing, or Home content key.
    pub fn generate() -> Result<Self, BackupKeyringError> {
        let mut seed = [0u8; 32];
        SystemRandom::new()
            .fill(&mut seed)
            .map_err(|_| BackupKeyringError::Rng)?;
        Self::from_seed(seed)
    }

    /// Reopen private material supplied by a local secure-storage adapter. This
    /// accepts no Hub data and is useful to a client that already holds the key.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, BackupKeyringError> {
        SecretKey::from_slice(&seed)
            .map(Self)
            .map_err(|_| BackupKeyringError::InvalidRecipient)
    }

    pub fn public_key(&self) -> BackupRecipientPublicKey {
        BackupRecipientPublicKey(hex::encode(
            self.0.public_key().to_encoded_point(false).as_bytes(),
        ))
    }

    /// Export private material only to a local secure-storage adapter. This is
    /// the counterpart to [`Self::from_seed`], not a wire representation: callers
    /// must never send these bytes to the Hub or include them in backup records.
    pub fn to_seed_bytes(&self) -> [u8; 32] {
        let bytes = self.0.to_bytes();
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&bytes);
        seed
    }
}

/// A tenant-selected recipient, named by an opaque stable id. The id is not a
/// membership or role: adding/removing it is an explicit key-distribution act.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRecipient {
    pub id: String,
    pub public_key: BackupRecipientPublicKey,
}

impl BackupRecipient {
    pub fn new(
        id: impl Into<String>,
        public_key: BackupRecipientPublicKey,
    ) -> Result<Self, BackupKeyringError> {
        let id = id.into();
        valid_component(&id)
            .then_some(Self { id, public_key })
            .ok_or(BackupKeyringError::InvalidRecipient)
    }
}

/// Context bound into a wrap's ECDH-derived key. A wrap cannot be replayed to a
/// point in another tenant, another point, or a one-time receiving-Home handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupKeyContext {
    tenant_id: String,
    key_id: String,
}

impl BackupKeyContext {
    /// `key_id` is a fenced point id for point wraps or an exact one-time receiver
    /// id for restore delivery.
    pub fn new(
        tenant_id: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Result<Self, BackupKeyringError> {
        let tenant_id = tenant_id.into();
        let key_id = key_id.into();
        (valid_component(&tenant_id) && valid_component(&key_id))
            .then_some(Self { tenant_id, key_id })
            .ok_or(BackupKeyringError::InvalidContext)
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// A fresh per-point symmetric key. It has no serializer or byte accessor: callers
/// can only use it to encrypt/decrypt a point or to create/open a recipient wrap.
pub struct BackupDataKey([u8; 32]);

impl BackupDataKey {
    pub fn generate() -> Result<Self, BackupKeyringError> {
        let mut key = [0u8; 32];
        SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| BackupKeyringError::Rng)?;
        Ok(Self(key))
    }
}

/// Opaque ciphertext of a fenced backup cut. This is safe to persist at the Hub
/// alongside [`BackupKeyWrap`] records; it cannot be opened without a local data
/// key recovered by an admitted recipient.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupCiphertext {
    pub bytes: Vec<u8>,
}

/// One ECIES wrapping of a point data key to a named public recipient. Both fields
/// are opaque and safe for Hub storage; the ephemeral public key is not a recipient
/// private key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupKeyWrap {
    pub recipient_id: String,
    pub ephemeral_pubkey: String,
    pub ciphertext: String,
}

/// Encrypt a fenced point locally under a fresh [`BackupDataKey`].
pub fn encrypt_point(
    key: &BackupDataKey,
    plaintext: &[u8],
) -> Result<BackupCiphertext, BackupKeyringError> {
    LocalAeadEncryptor::new(key.0)
        .encrypt(plaintext)
        .map(|bytes| BackupCiphertext { bytes })
        .map_err(|_| BackupKeyringError::Encrypt)
}

/// Decrypt a point locally after a recipient has recovered its data key.
pub fn decrypt_point(
    key: &BackupDataKey,
    ciphertext: &BackupCiphertext,
) -> Result<Vec<u8>, BackupKeyringError> {
    LocalAeadEncryptor::new(key.0)
        .decrypt(&ciphertext.bytes)
        .map_err(|_| BackupKeyringError::Decrypt)
}

/// Wrap a fresh point data key to one current tenant recipient. The context binds
/// the wrap to the exact tenant and fenced point/receiver id.
pub fn wrap_data_key(
    context: &BackupKeyContext,
    key: &BackupDataKey,
    recipient: &BackupRecipient,
) -> Result<BackupKeyWrap, BackupKeyringError> {
    let peer = recipient.public_key.p256()?;
    let mut seed = [0u8; 32];
    SystemRandom::new()
        .fill(&mut seed)
        .map_err(|_| BackupKeyringError::Rng)?;
    let ephemeral = SecretKey::from_slice(&seed).map_err(|_| BackupKeyringError::Rng)?;
    let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), peer.as_affine());
    let wrapping_key =
        derive_wrapping_key(shared.raw_secret_bytes().as_ref(), context, &recipient.id);
    let ciphertext = LocalAeadEncryptor::new(wrapping_key)
        .encrypt(&key.0)
        .map_err(|_| BackupKeyringError::Encrypt)?;
    Ok(BackupKeyWrap {
        recipient_id: recipient.id.clone(),
        ephemeral_pubkey: hex::encode(ephemeral.public_key().to_encoded_point(false).as_bytes()),
        ciphertext: hex::encode(ciphertext),
    })
}

/// Open one opaque wrap locally. A wrong private key, changed tenant/point context,
/// malformed record, or tampering all fail closed with the same refusal.
pub fn unwrap_data_key(
    context: &BackupKeyContext,
    private_key: &BackupRecipientPrivateKey,
    wrap: &BackupKeyWrap,
) -> Result<BackupDataKey, BackupKeyringError> {
    if !valid_component(&wrap.recipient_id) {
        return Err(BackupKeyringError::InvalidRecipient);
    }
    let ephemeral = P256PublicKey::from_sec1_bytes(
        &hex::decode(&wrap.ephemeral_pubkey).map_err(|_| BackupKeyringError::InvalidRecipient)?,
    )
    .map_err(|_| BackupKeyringError::InvalidRecipient)?;
    let ciphertext = hex::decode(&wrap.ciphertext).map_err(|_| BackupKeyringError::Decrypt)?;
    let shared = diffie_hellman(private_key.0.to_nonzero_scalar(), ephemeral.as_affine());
    let wrapping_key = derive_wrapping_key(
        shared.raw_secret_bytes().as_ref(),
        context,
        &wrap.recipient_id,
    );
    let bytes = LocalAeadEncryptor::new(wrapping_key)
        .decrypt(&ciphertext)
        .map_err(|_| BackupKeyringError::Decrypt)?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| BackupKeyringError::Decrypt)?;
    Ok(BackupDataKey(key))
}

fn derive_wrapping_key(
    shared_secret: &[u8],
    context: &BackupKeyContext,
    recipient_id: &str,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RECIPIENT_KDF_DOMAIN);
    add_component(&mut digest, context.tenant_id());
    add_component(&mut digest, context.key_id());
    add_component(&mut digest, recipient_id);
    digest.update(shared_secret);
    digest.finalize().into()
}

fn add_component(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

fn valid_component(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private(seed: u8) -> BackupRecipientPrivateKey {
        BackupRecipientPrivateKey::from_seed([seed; 32]).unwrap()
    }

    fn recipient(id: &str, private: &BackupRecipientPrivateKey) -> BackupRecipient {
        BackupRecipient::new(id, private.public_key()).unwrap()
    }

    fn point_context() -> BackupKeyContext {
        BackupKeyContext::new("tenant:acme", "point:cut-42").unwrap()
    }

    #[test]
    fn point_is_openable_only_by_the_wrapped_recipient() {
        let holder = private(7);
        let wrong = private(8);
        let key = BackupDataKey::generate().unwrap();
        let ciphertext = encrypt_point(&key, b"fenced backup cut").unwrap();
        let wrap =
            wrap_data_key(&point_context(), &key, &recipient("recovery-a", &holder)).unwrap();

        let recovered = unwrap_data_key(&point_context(), &holder, &wrap).unwrap();
        assert_eq!(
            decrypt_point(&recovered, &ciphertext).unwrap(),
            b"fenced backup cut"
        );
        assert!(matches!(
            unwrap_data_key(&point_context(), &wrong, &wrap),
            Err(BackupKeyringError::Decrypt)
        ));
    }

    #[test]
    fn wrap_is_bound_to_exact_tenant_and_fenced_point() {
        let holder = private(9);
        let key = BackupDataKey::generate().unwrap();
        let wrap = wrap_data_key(&point_context(), &key, &recipient("device-a", &holder)).unwrap();

        assert!(unwrap_data_key(&point_context(), &holder, &wrap).is_ok());
        let other_tenant = BackupKeyContext::new("tenant:beta", "point:cut-42").unwrap();
        let other_point = BackupKeyContext::new("tenant:acme", "point:cut-43").unwrap();
        assert!(matches!(
            unwrap_data_key(&other_tenant, &holder, &wrap),
            Err(BackupKeyringError::Decrypt)
        ));
        assert!(matches!(
            unwrap_data_key(&other_point, &holder, &wrap),
            Err(BackupKeyringError::Decrypt)
        ));
    }

    #[test]
    fn retained_recovery_holder_rewraps_to_exact_receiver_locally() {
        let recovery = private(11);
        let receiver = private(12);
        let point = point_context();
        let receiver_context = BackupKeyContext::new("tenant:acme", "receiver:home-new:1").unwrap();
        let key = BackupDataKey::generate().unwrap();
        let ciphertext = encrypt_point(&key, b"restore after lost home").unwrap();
        let old_wrap = wrap_data_key(&point, &key, &recipient("recovery-a", &recovery)).unwrap();

        let recovered = unwrap_data_key(&point, &recovery, &old_wrap).unwrap();
        let receiver_wrap = wrap_data_key(
            &receiver_context,
            &recovered,
            &recipient("home-new-receiver", &receiver),
        )
        .unwrap();
        let delivered = unwrap_data_key(&receiver_context, &receiver, &receiver_wrap).unwrap();
        assert_eq!(
            decrypt_point(&delivered, &ciphertext).unwrap(),
            b"restore after lost home"
        );
        assert!(matches!(
            unwrap_data_key(&point, &receiver, &receiver_wrap),
            Err(BackupKeyringError::Decrypt)
        ));
    }

    #[test]
    fn public_key_input_is_validated() {
        assert_eq!(
            BackupRecipientPublicKey::parse("not-a-p256-key"),
            Err(BackupKeyringError::InvalidRecipient)
        );
    }
}
