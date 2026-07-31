//! Encryption at rest (M3 `SEC-4`) — the seam that lets the durable store / content
//! be encrypted, with the data key managed by a cloud KMS in production.
//!
//! The split follows the [`DEFERRED.md`](../../../DEFERRED.md) doctrine: the
//! **cipher is local and real** (AES-256-GCM via `ring`), so the loopback
//! [`LocalAeadEncryptor`] genuinely encrypts/decrypts; the **infra half** is *key
//! management* — a `KmsEncryptor` that seals/unseals the data key through Azure Key
//! Vault / AWS KMS / GCP KMS attaches behind the same [`Encryptor`] trait with no
//! change to callers (mirrors the `SealedKeyReleaseService` pattern). Until then the
//! local key is supplied/derived in-process (a dev double, not a managed key).

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};

/// Why an encrypt/decrypt failed. `Decrypt` covers both a wrong key and a tampered
/// ciphertext (AEAD does not distinguish — both fail the tag check, fail-closed).
#[derive(Debug, PartialEq, Eq)]
pub enum AtRestError {
    Rng,
    BadKey,
    Encrypt,
    /// Ciphertext shorter than the nonce prefix.
    Malformed,
    /// Authentication failed: wrong key or tampered ciphertext.
    Decrypt,
}

/// Encrypt/decrypt opaque bytes for storage. Implementations are AEAD: a tampered or
/// wrong-key ciphertext fails to decrypt (never silently returns garbage).
pub trait Encryptor: Send + Sync {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AtRestError>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, AtRestError>;
}

/// The loopback encryptor: AES-256-GCM under a **process-local** 256-bit key. Real
/// crypto; the dev shortcut is only that the key lives here rather than being sealed
/// by a KMS. The wire format is `nonce(12) || ciphertext || tag(16)`, a fresh random
/// nonce per call.
pub struct LocalAeadEncryptor {
    key: [u8; 32],
}

impl LocalAeadEncryptor {
    /// Use a caller-supplied 256-bit key (e.g. one a KMS unwrapped into memory).
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Generate a fresh random key — the dev/test default when no KMS-managed key is
    /// available. (In production the key comes from the KMS, not from here.)
    pub fn generate() -> Result<Self, AtRestError> {
        let mut key = [0u8; 32];
        SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| AtRestError::Rng)?;
        Ok(Self { key })
    }

    fn sealing_key(&self) -> Result<LessSafeKey, AtRestError> {
        let unbound = UnboundKey::new(&AES_256_GCM, &self.key).map_err(|_| AtRestError::BadKey)?;
        Ok(LessSafeKey::new(unbound))
    }
}

impl Encryptor for LocalAeadEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AtRestError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| AtRestError::Rng)?;
        let key = self.sealing_key()?;
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::empty(),
            &mut in_out,
        )
        .map_err(|_| AtRestError::Encrypt)?;
        let mut out = Vec::with_capacity(NONCE_LEN + in_out.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&in_out);
        Ok(out)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, AtRestError> {
        if ciphertext.len() < NONCE_LEN {
            return Err(AtRestError::Malformed);
        }
        let (nonce_bytes, ct) = ciphertext.split_at(NONCE_LEN);
        let nonce_arr: [u8; NONCE_LEN] =
            nonce_bytes.try_into().map_err(|_| AtRestError::Malformed)?;
        let key = self.sealing_key()?;
        let mut in_out = ct.to_vec();
        let plaintext = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_arr),
                Aad::empty(),
                &mut in_out,
            )
            .map_err(|_| AtRestError::Decrypt)?;
        Ok(plaintext.to_vec())
    }
}

/// Wrap/unwrap a 256-bit data key (DEK) with a key-encryption key (KEK) held by a KMS —
/// the seam the real Azure Key Vault / AWS KMS / GCP KMS client attaches behind. This is
/// the *only* outside-world piece SEC-4 needs, and a **standard, software-protected Key
/// Vault is sufficient** for it (per-operation, cheap) — the hardware Managed HSM is a
/// `D-ATTEST` requirement (attestation-bound Secure Key Release), not an at-rest one.
pub trait KeyWrap: Send + Sync {
    fn wrap(&self, dek: &[u8; 32]) -> Result<Vec<u8>, AtRestError>;
    fn unwrap(&self, wrapped: &[u8]) -> Result<[u8; 32], AtRestError>;
}

/// The loopback KEK: AES-256-GCM wrap of the DEK under a **process-local** KEK. Real
/// crypto; the dev shortcut is the KEK living here rather than in a KMS. The Azure
/// adapter replaces this with a Key Vault `wrapKey`/`unwrapKey` call, behind the same
/// [`KeyWrap`] trait, with no change to [`EnvelopeEncryptor`].
pub struct LoopbackKeyWrap {
    kek: LocalAeadEncryptor,
}

impl LoopbackKeyWrap {
    pub fn new(kek: [u8; 32]) -> Self {
        Self {
            kek: LocalAeadEncryptor::new(kek),
        }
    }
    pub fn generate() -> Result<Self, AtRestError> {
        Ok(Self {
            kek: LocalAeadEncryptor::generate()?,
        })
    }
}

impl KeyWrap for LoopbackKeyWrap {
    fn wrap(&self, dek: &[u8; 32]) -> Result<Vec<u8>, AtRestError> {
        self.kek.encrypt(dek)
    }
    fn unwrap(&self, wrapped: &[u8]) -> Result<[u8; 32], AtRestError> {
        self.kek
            .decrypt(wrapped)?
            .try_into()
            .map_err(|_| AtRestError::Malformed)
    }
}

/// Build the local persisted loopback content-key wrapper used by open/local
/// workbench startup when content encryption is enabled.
pub(crate) fn local_content_keywrap(root: &std::path::Path) -> std::io::Result<Box<dyn KeyWrap>> {
    Ok(Box::new(LoopbackKeyWrap::new(local_content_kek(root)?)))
}

/// Load the persisted content KEK, minting one only when the file is genuinely
/// absent. Any other read outcome — a permission error, a truncated or
/// wrong-length file — fails closed (DR-0054 Phase A): silently minting a
/// replacement here would overwrite the only key that can unwrap every
/// persisted `content-keys/*.dek`, permanently orphaning the encrypted
/// content. Mirrors the fail-loud contract of
/// [`crate::key_store::FileKeyStore`].
fn local_content_kek(root: &std::path::Path) -> std::io::Result<[u8; 32]> {
    let dir = root.join("keys");
    let path = dir.join("content-kek");
    match std::fs::read(&path) {
        Ok(bytes) => <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "content KEK at {} has invalid length {} (expected 32 bytes); \
                     refusing to regenerate over key material that still wraps stored content",
                    path.display(),
                    bytes.len()
                ),
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut kek = [0u8; 32];
            SystemRandom::new()
                .fill(&mut kek)
                .map_err(|_| std::io::Error::other("OS CSPRNG for the content KEK"))?;
            std::fs::create_dir_all(&dir)?;
            // Persist durably: stage in the same directory, fsync, then rename
            // into place, so a crash never leaves a partial KEK on disk.
            let staged = dir.join(format!("content-kek.tmp-{}", std::process::id()));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let written = options.open(&staged).and_then(|mut file| {
                use std::io::Write;
                file.write_all(&kek)?;
                file.sync_all()
            });
            if let Err(error) = written {
                let _ = std::fs::remove_file(&staged);
                return Err(error);
            }
            std::fs::rename(&staged, &path)?;
            Ok(kek)
        }
        Err(error) => Err(error),
    }
}

/// Envelope encryption (`SEC-4`): data is sealed under a random per-instance **DEK**, and
/// the DEK is persisted only **wrapped by the KMS-held KEK**. So nothing usable sits in
/// plaintext at rest — a disk/store compromise yields ciphertext plus a wrapped DEK that
/// only the KMS can unwrap, and key access is centrally controlled/revocable at the KMS.
/// Composed from the local AES-256-GCM cipher + a [`KeyWrap`] seam; the plaintext DEK
/// never leaves memory.
pub struct EnvelopeEncryptor {
    cipher: LocalAeadEncryptor, // the DEK, in memory only
    wrapped_dek: Vec<u8>,       // the DEK wrapped by the KEK — this is what gets persisted
}

impl EnvelopeEncryptor {
    /// Create a fresh envelope: generate a random DEK and wrap it with the KMS KEK. The
    /// wrapped DEK ([`wrapped_dek`](Self::wrapped_dek)) is persisted alongside ciphertext.
    pub fn create(wrap: &impl KeyWrap) -> Result<Self, AtRestError> {
        let mut dek = [0u8; 32];
        SystemRandom::new()
            .fill(&mut dek)
            .map_err(|_| AtRestError::Rng)?;
        let wrapped_dek = wrap.wrap(&dek)?;
        Ok(Self {
            cipher: LocalAeadEncryptor::new(dek),
            wrapped_dek,
        })
    }

    /// Reopen a persisted envelope: unwrap the stored DEK via the KMS KEK. Fails closed if
    /// the KEK cannot unwrap it (wrong/rotated KEK, tampered wrapped DEK).
    pub fn open(wrapped_dek: Vec<u8>, wrap: &impl KeyWrap) -> Result<Self, AtRestError> {
        let dek = wrap.unwrap(&wrapped_dek)?;
        Ok(Self {
            cipher: LocalAeadEncryptor::new(dek),
            wrapped_dek,
        })
    }

    /// The wrapped DEK to persist next to the ciphertext. Safe at rest: only the KMS KEK
    /// unwraps it.
    pub fn wrapped_dek(&self) -> &[u8] {
        &self.wrapped_dek
    }
}

impl Encryptor for EnvelopeEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AtRestError> {
        self.cipher.encrypt(plaintext)
    }
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, AtRestError> {
        self.cipher.decrypt(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let enc = LocalAeadEncryptor::generate().unwrap();
        let msg = b"sealed-key material and chat content";
        let ct = enc.encrypt(msg).unwrap();
        assert_ne!(&ct[..], &msg[..], "ciphertext is not the plaintext");
        assert_eq!(enc.decrypt(&ct).unwrap(), msg);
    }

    #[test]
    fn fresh_nonce_per_call_so_ciphertexts_differ() {
        let enc = LocalAeadEncryptor::generate().unwrap();
        let a = enc.encrypt(b"same").unwrap();
        let b = enc.encrypt(b"same").unwrap();
        assert_ne!(a, b, "a random nonce makes repeated encryptions differ");
        assert_eq!(enc.decrypt(&a).unwrap(), b"same");
        assert_eq!(enc.decrypt(&b).unwrap(), b"same");
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let enc = LocalAeadEncryptor::generate().unwrap();
        let mut ct = enc.encrypt(b"protected").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01; // flip a bit in the tag
        assert_eq!(enc.decrypt(&ct), Err(AtRestError::Decrypt));
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let a = LocalAeadEncryptor::generate().unwrap();
        let b = LocalAeadEncryptor::generate().unwrap();
        let ct = a.encrypt(b"secret").unwrap();
        assert_eq!(b.decrypt(&ct), Err(AtRestError::Decrypt));
    }

    #[test]
    fn truncated_ciphertext_is_malformed() {
        let enc = LocalAeadEncryptor::generate().unwrap();
        assert_eq!(enc.decrypt(b"short"), Err(AtRestError::Malformed));
    }

    #[test]
    fn key_round_trips_across_instances() {
        // The same key (as a KMS would unwrap) decrypts what another instance sealed.
        let key = [7u8; 32];
        let sealed = LocalAeadEncryptor::new(key).encrypt(b"payload").unwrap();
        assert_eq!(
            LocalAeadEncryptor::new(key).decrypt(&sealed).unwrap(),
            b"payload"
        );
    }

    #[test]
    fn envelope_round_trips_and_persists_via_the_wrapped_dek() {
        let kek = LoopbackKeyWrap::new([9u8; 32]);
        // Seal under a fresh wrapped DEK.
        let env = EnvelopeEncryptor::create(&kek).unwrap();
        let ct = env.encrypt(b"account settings + chat index").unwrap();
        let wrapped = env.wrapped_dek().to_vec();
        // The wrapped DEK is what's stored — never the plaintext DEK.
        assert!(
            wrapped.len() > 32,
            "wrapped DEK carries nonce+tag, not a bare key"
        );

        // Reopen from the persisted wrapped DEK (as a fresh process would) and decrypt.
        let reopened = EnvelopeEncryptor::open(wrapped, &kek).unwrap();
        assert_eq!(
            reopened.decrypt(&ct).unwrap(),
            b"account settings + chat index"
        );
    }

    #[test]
    fn a_different_kek_cannot_unwrap_the_dek() {
        // The KMS KEK gates access: the wrapped DEK is useless without the right KEK.
        let env = EnvelopeEncryptor::create(&LoopbackKeyWrap::new([1u8; 32])).unwrap();
        let wrapped = env.wrapped_dek().to_vec();
        assert_eq!(
            EnvelopeEncryptor::open(wrapped, &LoopbackKeyWrap::new([2u8; 32])).err(),
            Some(AtRestError::Decrypt),
            "a wrong/rotated KEK fails closed — only the KMS KEK can unwrap the DEK"
        );
    }

    #[test]
    fn a_tampered_wrapped_dek_fails_closed() {
        let kek = LoopbackKeyWrap::new([3u8; 32]);
        let env = EnvelopeEncryptor::create(&kek).unwrap();
        let mut wrapped = env.wrapped_dek().to_vec();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0x01;
        assert_eq!(
            EnvelopeEncryptor::open(wrapped, &kek).err(),
            Some(AtRestError::Decrypt)
        );
    }

    #[test]
    fn content_kek_mints_once_and_reloads_the_same_key() {
        let root = tempfile::tempdir().unwrap();
        let first = local_content_kek(root.path()).unwrap();
        let second = local_content_kek(root.path()).unwrap();
        assert_eq!(first, second, "restart reloads the persisted KEK");
        assert_eq!(
            std::fs::read(root.path().join("keys").join("content-kek")).unwrap(),
            first,
            "the persisted bytes are the key itself"
        );
    }

    #[test]
    fn a_truncated_content_kek_fails_closed_and_is_left_untouched() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("keys");
        let path = dir.join("content-kek");
        std::fs::create_dir_all(&dir).unwrap();
        // A truncated key file — e.g. a crash mid-write or disk corruption.
        std::fs::write(&path, [7u8; 5]).unwrap();

        let error = local_content_kek(root.path())
            .expect_err("an unreadable KEK must never be silently replaced");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            [7u8; 5],
            "the original file bytes survive for recovery"
        );
        assert!(
            local_content_keywrap(root.path()).is_err(),
            "the keywrap seam propagates the failure to startup"
        );
    }
}
