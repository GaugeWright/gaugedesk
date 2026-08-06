//! Crypto-erasure for content behind handles (`SECAUD-6`, GDPR right-to-erasure /
//! SOC 2 Confidentiality C1.2 & Privacy).
//!
//! The event log is **append-only and immutable** (`INV-6`), and the content-erasure
//! lifecycle deliberately *preserves history* (`HISTORY_PRESERVED`,
//! [`content_erasure`](gaugedesk_core::content_erasure)) — so a tombstone makes a
//! payload *unresolvable for future use* but does **not** shred the bytes. For a true
//! right-to-erasure ("the data is gone, unrecoverable"), shredding bytes in the
//! immutable log is not an option.
//!
//! **Crypto-erasure** reconciles the two. Each erasable unit's content is sealed under
//! its **own** data key. Erasing destroys that key, so the ciphertext that remains in
//! the immutable log becomes **permanently unrecoverable** — the payload is gone, yet
//! history (the handle, the sealed bytes, the audit metadata) is intact. The keys live
//! in **mutable** storage (a keyring — KMS-sealed in production via `SEC-4`); the
//! content lives in the immutable log. Deleting a key never touches the log, so `INV-6`
//! holds *and* the payload is unrecoverable. This is the concrete realization of the
//! model's `TOMBSTONE_BLOCKS_FUTURE_RESOLUTION` for the case where unrecoverability —
//! not merely non-resolution — is required.

use std::collections::BTreeMap;

use ring::rand::{SecureRandom, SystemRandom};

use crate::at_rest::{AtRestError, Encryptor, LocalAeadEncryptor};

/// A content unit sealed under a per-unit data key. `key_id` references the key in the
/// [`CryptoEraser`] keyring; `ciphertext` is what lands in durable (immutable) storage.
/// After the key is erased the ciphertext remains but cannot be opened (`SECAUD-6`).
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SealedContent {
    pub key_id: String,
    pub ciphertext: Vec<u8>,
}

/// A per-unit-key store enabling crypto-erasure. Sealing mints a fresh data key per
/// unit; erasing destroys it. In production the keyring is the set of KMS-sealed
/// wrapped-DEK records (`SEC-4`) and erasure deletes the wrapped-DEK row; here it is an
/// in-memory keyring that realizes the same mechanism, fail-closed (a missing key never
/// decrypts).
#[derive(Default)]
pub struct CryptoEraser {
    keys: BTreeMap<String, [u8; 32]>,
}

impl CryptoEraser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seal `content` under a fresh per-unit key identified by `key_id`, returning the
    /// ciphertext to persist. The key is retained in the keyring until erased.
    pub fn seal(
        &mut self,
        key_id: impl Into<String>,
        content: &[u8],
    ) -> Result<SealedContent, AtRestError> {
        let key_id = key_id.into();
        let mut key = [0u8; 32];
        SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| AtRestError::Rng)?;
        let ciphertext = LocalAeadEncryptor::new(key).encrypt(content)?;
        self.keys.insert(key_id.clone(), key);
        Ok(SealedContent { key_id, ciphertext })
    }

    /// Open a sealed unit. `None` if the unit's key was erased (fail-closed) — the
    /// content is gone even though the ciphertext is still present.
    pub fn open(&self, sealed: &SealedContent) -> Option<Vec<u8>> {
        let key = self.keys.get(&sealed.key_id)?;
        LocalAeadEncryptor::new(*key)
            .decrypt(&sealed.ciphertext)
            .ok()
    }

    /// **Crypto-erase** a unit: destroy its data key. The ciphertext (history) remains
    /// in the immutable log but is now permanently unrecoverable (`SECAUD-6`). The key
    /// bytes are overwritten before being dropped (best-effort zeroization; production
    /// uses a zeroizing key type / KMS key deletion). Idempotent — returns whether a
    /// key was present.
    pub fn erase(&mut self, key_id: &str) -> bool {
        match self.keys.remove(key_id) {
            Some(mut key) => {
                for b in key.iter_mut() {
                    // Volatile write so the overwrite is not optimized away.
                    unsafe { std::ptr::write_volatile(b, 0) };
                }
                true
            }
            None => false,
        }
    }

    /// Whether a unit has been erased (its key is gone) — true also for an unknown id.
    pub fn is_erased(&self, key_id: &str) -> bool {
        !self.keys.contains_key(key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_then_open_round_trips() {
        let mut e = CryptoEraser::new();
        let sealed = e.seal("chat-1", b"a private transcript").unwrap();
        assert_eq!(
            e.open(&sealed).as_deref(),
            Some(&b"a private transcript"[..])
        );
    }

    #[test]
    fn erase_makes_content_permanently_unrecoverable_but_keeps_history() {
        // SECAUD-6: destroying the key crypto-erases the payload; the ciphertext (the
        // historical record, INV-6) is untouched, but it can never be opened again.
        let mut e = CryptoEraser::new();
        let sealed = e.seal("chat-1", b"erase me").unwrap();
        assert!(e.open(&sealed).is_some(), "readable before erasure");

        assert!(
            e.erase("chat-1"),
            "the key was present and is now destroyed"
        );
        assert!(e.is_erased("chat-1"));
        // History intact: the sealed ciphertext still exists...
        assert!(!sealed.ciphertext.is_empty());
        // ...but the payload is gone — unrecoverable, fail-closed.
        assert_eq!(
            e.open(&sealed),
            None,
            "content unrecoverable after key destruction"
        );
        // Idempotent: erasing again is a no-op.
        assert!(!e.erase("chat-1"));
    }

    #[test]
    fn erasing_one_unit_does_not_affect_another() {
        // Per-unit keys: erasing one client's content leaves every other unit readable.
        let mut e = CryptoEraser::new();
        let a = e.seal("chat-a", b"alice data").unwrap();
        let b = e.seal("chat-b", b"bob data").unwrap();
        e.erase("chat-a");
        assert_eq!(e.open(&a), None);
        assert_eq!(
            e.open(&b).as_deref(),
            Some(&b"bob data"[..]),
            "untouched unit still opens"
        );
    }

    #[test]
    fn the_ciphertext_does_not_contain_the_plaintext() {
        let mut e = CryptoEraser::new();
        let sealed = e.seal("c", b"SECRET-MARKER-1234").unwrap();
        assert!(
            !sealed
                .ciphertext
                .windows(b"SECRET-MARKER-1234".len())
                .any(|w| w == b"SECRET-MARKER-1234"),
            "the plaintext must not appear in the sealed bytes",
        );
    }
}
