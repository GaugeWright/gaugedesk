//! Content-only, per-unit at-rest encryption + crypto-erasure (`SECAUD-9` / `SECAUD-6`).
//!
//! A [`ContentVault`] implements the store's [`ContentCodec`] seam to transparently
//! encrypt **content** record kinds (e.g. `transcript` — the client's conversation) at
//! rest, under a **per-scope** data key, leaving lifecycle/metadata records plaintext.
//! Each scope (engagement) gets its own DEK, persisted only **wrapped by a KEK**
//! (`SEC-4` [`KeyWrap`] — `LoopbackKeyWrap` in dev, the Azure Key Vault adapter in
//! prod). Two properties fall out:
//!
//! - **Encryption at rest** (`SECAUD-9`): the payload column holds ciphertext; a disk /
//!   store compromise yields only ciphertext + a KMS-wrapped DEK.
//! - **Crypto-erasure** (`SECAUD-6`, GDPR right-to-erasure): [`crypto_erase`] destroys a
//!   scope's wrapped DEK, so that scope's retained ciphertext is permanently
//!   unrecoverable — the content is gone, the append-only log (`INV-6`) untouched.
//!
//! The keyring is **file-backed, outside the event store** (one wrapped-DEK file per
//! scope), so it never re-enters the store while the store is mid-write, and a key can
//! be deleted (erasure) without touching the immutable log.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use ring::rand::{SecureRandom, SystemRandom};

use gaugedesk_store::{ContentCodec, Store};

use crate::at_rest::{Encryptor, KeyWrap, LocalAeadEncryptor};
use crate::workbench_state::Workbench;

/// Marks an encrypted payload so [`ContentVault::decode`] can tell ciphertext from a
/// legacy/plaintext row (mixed logs and the pre-encryption history stay readable).
const MARKER: &str = "gwenc:1:";

/// The default content kind to encrypt: the durable conversation transcript.
pub const DEFAULT_CONTENT_KINDS: &[&str] = &["transcript"];

pub(crate) fn configured_content_vault(
    root: &Path,
    content_keywrap: impl Fn(&Path) -> std::io::Result<Box<dyn KeyWrap>>,
) -> std::io::Result<Option<Arc<ContentVault>>> {
    if gaugedesk_env::var("ENCRYPT_CONTENT").as_deref() != Some("1") {
        return Ok(None);
    }
    // KEK selection is creds-only: a hosted deployment sets GAUGEDESK_CONTENT_KEK_ID
    // + the AZURE_* Crypto User SP creds to use the KMS; dev uses the local KEK.
    Ok(Some(Arc::new(ContentVault::new(
        root.join("content-keys"),
        content_keywrap(root)?,
    ))))
}

pub(crate) fn open_startup_store(
    root: &Path,
    content_keywrap: impl Fn(&Path) -> std::io::Result<Box<dyn KeyWrap>>,
) -> std::io::Result<(Store, Option<Arc<ContentVault>>)> {
    let mut store =
        Store::open(root.join("gaugewright.db").to_str().expect("utf8 path")).map_err(crate::io)?;
    let content_vault = configured_content_vault(root, content_keywrap)?;
    if let Some(vault) = &content_vault {
        store = store.with_codec(vault.clone());
    }
    Ok((store, content_vault))
}

impl Workbench {
    pub(crate) fn apply_startup_content_vault(&mut self, content_vault: Option<Arc<ContentVault>>) {
        self.content_vault = content_vault;
    }
}

/// Per-scope content encryption + crypto-erasure. Held by the [`Store`](gaugedesk_store::Store)
/// as its [`ContentCodec`]; `Send + Sync` so it can ride the shared workbench.
pub struct ContentVault {
    /// Directory holding the per-scope wrapped-DEK files.
    dir: PathBuf,
    /// The KEK seam (`SEC-4`) wrapping each per-scope DEK.
    wrap: Box<dyn KeyWrap>,
    /// The record kinds treated as content (everything else passes through plaintext).
    kinds: BTreeSet<String>,
    /// In-memory DEK cache (scope → 32-byte key), so the KEK is touched once per scope.
    cache: Mutex<HashMap<String, [u8; 32]>>,
}

impl ContentVault {
    /// A vault rooted at `dir` (the wrapped-DEK keyring), wrapping DEKs with `wrap`,
    /// encrypting [`DEFAULT_CONTENT_KINDS`].
    pub fn new(dir: impl Into<PathBuf>, wrap: Box<dyn KeyWrap>) -> Self {
        Self {
            dir: dir.into(),
            wrap,
            kinds: DEFAULT_CONTENT_KINDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Override which record kinds are treated as content (builder).
    pub fn with_kinds<I, S>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.kinds = kinds.into_iter().map(Into::into).collect();
        self
    }

    fn key_path(&self, scope: &str) -> PathBuf {
        self.dir
            .join(format!("{}.dek", crate::org::sha256_hex(scope)))
    }

    /// The per-scope DEK. `create` mints + persists one on a miss (the write path);
    /// the read path passes `false`, so a scope whose key file is gone (crypto-erased)
    /// resolves to `None` — its content is unrecoverable.
    fn dek_for(&self, scope: &str, create: bool) -> Option<[u8; 32]> {
        if let Some(dek) = self.cache.lock().unwrap().get(scope) {
            return Some(*dek);
        }
        let path = self.key_path(scope);
        if let Ok(wrapped) = std::fs::read(&path) {
            if let Ok(dek) = self.wrap.unwrap(&wrapped) {
                self.cache.lock().unwrap().insert(scope.to_string(), dek);
                return Some(dek);
            }
            return None; // a key file we cannot unwrap is unrecoverable, fail-closed
        }
        if !create {
            return None;
        }
        // Mint a fresh DEK, persist it wrapped, cache it.
        let mut dek = [0u8; 32];
        SystemRandom::new().fill(&mut dek).ok()?;
        let wrapped = self.wrap.wrap(&dek).ok()?;
        std::fs::create_dir_all(&self.dir).ok()?;
        std::fs::write(&path, &wrapped).ok()?;
        self.cache.lock().unwrap().insert(scope.to_string(), dek);
        Some(dek)
    }

    /// **Crypto-erase** a scope (`SECAUD-6`): destroy its wrapped DEK (file + cache).
    /// Its retained ciphertext can never be opened again. Idempotent; returns whether a
    /// key was present.
    pub fn crypto_erase(&self, scope: &str) -> bool {
        self.cache.lock().unwrap().remove(scope);
        std::fs::remove_file(self.key_path(scope)).is_ok()
    }

    fn is_content(&self, kind: &str) -> bool {
        self.kinds.contains(kind)
    }
}

impl ContentCodec for ContentVault {
    fn encode(&self, scope: &str, kind: &str, payload: &str) -> Result<String, String> {
        if !self.is_content(kind) {
            return Ok(payload.to_string());
        }
        match self.dek_for(scope, true).and_then(|dek| {
            LocalAeadEncryptor::new(dek)
                .encrypt(payload.as_bytes())
                .ok()
        }) {
            Some(ct) => Ok(format!("{MARKER}{}", hex::encode(ct))),
            None => Err(format!(
                "content encryption unavailable for scope {scope}; append refused (SECAUD-9)"
            )),
        }
    }

    fn decode(&self, scope: &str, kind: &str, payload: &str) -> Option<String> {
        if !self.is_content(kind) {
            return Some(payload.to_string());
        }
        let Some(hexct) = payload.strip_prefix(MARKER) else {
            return Some(payload.to_string()); // legacy / pre-encryption plaintext
        };
        if hexct == "UNENCRYPTABLE" {
            return None;
        }
        let dek = self.dek_for(scope, false)?; // erased / missing key ⇒ unrecoverable
        let ct = hex::decode(hexct).ok()?;
        let plain = LocalAeadEncryptor::new(dek).decrypt(&ct).ok()?;
        String::from_utf8(plain).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::at_rest::LoopbackKeyWrap;

    fn vault(dir: &std::path::Path) -> ContentVault {
        ContentVault::new(dir, Box::new(LoopbackKeyWrap::new([7u8; 32])))
    }

    #[test]
    fn content_is_encrypted_at_rest_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        let stored = v
            .encode("eng-1", "transcript", "a private question")
            .unwrap();
        // The stored form is ciphertext, not the plaintext.
        assert!(stored.starts_with(MARKER));
        assert!(!stored.contains("a private question"));
        // ...and decodes back.
        assert_eq!(
            v.decode("eng-1", "transcript", &stored).as_deref(),
            Some("a private question")
        );
    }

    #[test]
    fn non_content_kinds_pass_through() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        assert_eq!(
            v.encode("eng-1", "membership", "role=admin").unwrap(),
            "role=admin"
        );
        assert_eq!(
            v.decode("eng-1", "membership", "role=admin").as_deref(),
            Some("role=admin")
        );
    }

    #[test]
    fn crypto_erase_makes_a_scopes_content_unrecoverable_others_intact() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        let a = v.encode("eng-a", "transcript", "alice data").unwrap();
        let b = v.encode("eng-b", "transcript", "bob data").unwrap();
        assert!(v.decode("eng-a", "transcript", &a).is_some());

        assert!(v.crypto_erase("eng-a"), "the key existed and is destroyed");
        // eng-a's ciphertext can never be opened again...
        assert_eq!(v.decode("eng-a", "transcript", &a), None);
        // ...while eng-b (a different unit) is untouched.
        assert_eq!(
            v.decode("eng-b", "transcript", &b).as_deref(),
            Some("bob data")
        );
        // Idempotent.
        assert!(!v.crypto_erase("eng-a"));
    }

    #[test]
    fn legacy_plaintext_rows_still_read() {
        // A row written before encryption (no marker) is returned as-is.
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        assert_eq!(
            v.decode("eng-1", "transcript", "old plaintext line")
                .as_deref(),
            Some("old plaintext line")
        );
    }

    #[test]
    fn keys_persist_across_vault_instances() {
        // A fresh vault over the same keyring dir decrypts what the first wrote
        // (keys survive a restart — the wrapped DEK is on disk).
        let dir = tempfile::tempdir().unwrap();
        let stored = vault(dir.path())
            .encode("eng-1", "transcript", "persisted")
            .unwrap();
        let reopened = vault(dir.path());
        assert_eq!(
            reopened.decode("eng-1", "transcript", &stored).as_deref(),
            Some("persisted")
        );
    }
}
