//! Signatures over federation messages — an opaque [`Signature`] newtype, the
//! pure [`verify_signature`] predicate, and a pure [`SigningKey`] signing path
//! (D-REMOTE / ADR 0009).
//!
//! **Real P-256 ECDSA over SHA-256** (D-CRYPTO / ADR 0042) — this replaced the
//! `SIGN-1` length-check stub. The crypto is pure (no I/O, deterministic):
//! signing is RFC-6979 deterministic and verification borrows the public key,
//! message, and signature and decides true/false. Key *storage* — where the
//! private half lives — is the imperative shell's `KeyStore` seam (file today, a
//! secure enclave / TPM later), not the core's concern.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature as P256Sig, SigningKey as P256SigningKey, VerifyingKey};

use crate::ids::PublicKey;

/// An opaque signature — raw P-256 ECDSA signature bytes (`r ‖ s`, 64 bytes)
/// carried through the log and over the wire (D-REMOTE). The inner bytes are
/// private so callers construct via [`Signature::new`] (from wire bytes) or
/// [`SigningKey::sign`], and observe only [`Signature::len`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Construct from already-collected signature bytes (e.g. parsed off the
    /// wire). Real signatures are produced by [`SigningKey::sign`].
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Number of raw signature bytes. A well-formed P-256 signature is 64 bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no signature bytes at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow the canonical raw `r ‖ s` bytes for a cryptographic protocol
    /// adapter. This does not expose key material; it avoids making external
    /// attestation formats depend on this crate's serde representation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Why a signature could not be verified (as opposed to verifying to `false`).
/// Returned only when the **public key** itself is unparseable; a malformed or
/// non-verifying signature is a plain `Ok(false)` rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureError {
    pub reason: &'static str,
}

/// The P-256 ECDSA signature size in bytes (two 32-byte scalars, `r ‖ s`).
const P256_SIG_LEN: usize = 64;

/// A P-256 governance signing key — the **private** half of an authority/device
/// identity. The core uses it only for the pure [`SigningKey::sign`]; it is held
/// (and persisted) by the shell's `KeyStore`, never serialized through the log.
#[derive(Clone)]
pub struct SigningKey(P256SigningKey);

impl SigningKey {
    /// Derive a signing key **deterministically** from a 32-byte seed — no RNG,
    /// so enrollment is reproducible and tests are hermetic. `Err` if the seed is
    /// not a valid P-256 scalar (e.g. all-zero).
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, SignatureError> {
        P256SigningKey::from_slice(seed)
            .map(SigningKey)
            .map_err(|_| SignatureError {
                reason: "seed is not a valid P-256 scalar",
            })
    }

    /// The matching [`PublicKey`] — SEC1-compressed, hex-encoded. This is the
    /// value pinned in a `BridgeGrant` at pairing and carried as an envelope's
    /// `source_pubkey`.
    pub fn public_key(&self) -> PublicKey {
        let sec1 = self.0.verifying_key().to_sec1_bytes();
        PublicKey::new(hex::encode(sec1))
    }

    /// The matching public point in uncompressed SEC1 form (`04 || x || y`).
    /// Protocol adapters that must publish JWK coordinates can use this without
    /// gaining access to private key material.
    pub fn public_key_uncompressed_bytes(&self) -> [u8; 65] {
        let encoded = self.0.verifying_key().to_encoded_point(false);
        encoded
            .as_bytes()
            .try_into()
            .expect("a P-256 uncompressed point is always 65 bytes")
    }

    /// Sign `msg` (real P-256 ECDSA over SHA-256, deterministic).
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let sig: P256Sig = self.0.sign(msg);
        Signature(sig.to_bytes().to_vec())
    }

    /// The 32-byte scalar — for a `KeyStore` to persist (the inverse of
    /// [`SigningKey::from_seed`]). The private half; never serialized through the
    /// event log, only held by the shell's key storage.
    pub fn to_seed_bytes(&self) -> [u8; 32] {
        let bytes = self.0.to_bytes();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        seed
    }
}

/// Verify `sig` over `msg` under `pubkey` (D-REMOTE).
///
/// Pure and **fail-closed**: `Ok(true)` accepted; `Ok(false)` rejected (wrong
/// length, unparseable signature, or a good signature that does not verify);
/// `Err` only when `pubkey` itself cannot be decoded into a P-256 point. The
/// federation reducers reject on anything but `Ok(true)`.
pub fn verify_signature(
    msg: &[u8],
    sig: &Signature,
    pubkey: &PublicKey,
) -> Result<bool, SignatureError> {
    let key_bytes = hex::decode(pubkey.as_str()).map_err(|_| SignatureError {
        reason: "public key is not valid hex",
    })?;
    let verifying = VerifyingKey::from_sec1_bytes(&key_bytes).map_err(|_| SignatureError {
        reason: "public key is not a valid P-256 point",
    })?;
    if sig.len() != P256_SIG_LEN {
        return Ok(false);
    }
    match P256Sig::from_slice(&sig.0) {
        Ok(parsed) => Ok(verifying.verify(msg, &parsed).is_ok()),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed, deterministic signer for tests across the crate.
    pub(crate) fn signer() -> SigningKey {
        SigningKey::from_seed(&[7u8; 32]).expect("valid seed")
    }

    fn cbor_round_trip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).unwrap();
        ciborium::from_reader(bytes.as_slice()).unwrap()
    }

    /// A real signature over a message verifies under the matching public key.
    #[test]
    fn real_signature_round_trips() {
        let sk = signer();
        let pk = sk.public_key();
        let sig = sk.sign(b"hello");
        assert_eq!(sig.len(), P256_SIG_LEN);
        assert_eq!(verify_signature(b"hello", &sig, &pk), Ok(true));
        let uncompressed = sk.public_key_uncompressed_bytes();
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 4);
    }

    /// The same signature over a *different* message does not verify (INV-21).
    #[test]
    fn signature_is_message_bound() {
        let sk = signer();
        let pk = sk.public_key();
        let sig = sk.sign(b"hello");
        assert_eq!(verify_signature(b"goodbye", &sig, &pk), Ok(false));
    }

    /// A signature does not verify under a *different* key (INV-21).
    #[test]
    fn signature_is_key_bound() {
        let sig = signer().sign(b"hello");
        let other = SigningKey::from_seed(&[9u8; 32]).unwrap().public_key();
        assert_eq!(verify_signature(b"hello", &sig, &other), Ok(false));
    }

    /// A wrong-length signature is rejected (fail-closed), not an error.
    #[test]
    fn signature_wrong_length_rejected() {
        let pk = signer().public_key();
        assert_eq!(
            verify_signature(b"hello", &Signature::new(vec![0u8; 32]), &pk),
            Ok(false)
        );
        assert_eq!(
            verify_signature(b"hello", &Signature::new(vec![0u8; 65]), &pk),
            Ok(false)
        );
    }

    /// A correct-length but bogus signature is rejected, not accepted by length.
    #[test]
    fn signature_bogus_bytes_rejected() {
        let pk = signer().public_key();
        assert_eq!(
            verify_signature(b"hello", &Signature::new(vec![0u8; 64]), &pk),
            Ok(false)
        );
    }

    /// A public key that is not a valid P-256 point is an error (cannot decide).
    #[test]
    fn malformed_public_key_errors() {
        let sig = signer().sign(b"hello");
        assert!(verify_signature(b"hello", &sig, &PublicKey::new("04a1b2c3")).is_err());
    }

    /// The opaque signature round-trips through serde unchanged (D-REMOTE / `INV-8`).
    #[test]
    fn signature_serde_round_trip() {
        let sig = signer().sign(b"payload");
        assert_eq!(cbor_round_trip(&sig), sig);
    }
}
