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

/// The content record kinds sealed at rest by default.
///
/// The set covers the durable conversation transcript plus every record kind that
/// carries personal data an erasure request must be able to destroy (SOC 2 finding
/// 2.6, authorized by DR-0086). `audit` is deliberately **excluded**: it lives on a
/// separate store, is hash-chained for keyless external verification, and holds
/// pseudonymous references rather than the PII erasure targets. Library/lifecycle
/// metadata kinds (`chat`, `project`, `target`, `engagement`, …) are also left
/// cleartext for a follow-on, so their titles are the remaining residual.
pub const DEFAULT_CONTENT_KINDS: &[&str] = &[
    // The durable conversation transcript (the client's own words).
    "transcript",
    // Org-scope personal-data records (SOC 2 finding 2.6 / DR-0086).
    "membership",
    "org",
    "billing",
    "sso",
    "scim_token",
    "member_grant",
    "group_mapping",
    "policy",
    "placement_policy",
    "security",
    "software_policy",
    "archetype_approval",
    // Account-scope personal-data records.
    "setting",
    "device",
    "home",
    "home_route",
    "credential",
];

pub(crate) fn configured_content_vault(
    root: &Path,
    content_keywrap: impl Fn(&Path) -> std::io::Result<Box<dyn KeyWrap>>,
) -> std::io::Result<Option<Arc<ContentVault>>> {
    // Fail-closed posture (SOC 2 finding 2.6 / DR-0086): content encryption is ON by
    // default so a deployment that forgets a flag still seals personal data at rest.
    // It is disabled only by an explicit opt-out. The local KEK works with no config,
    // so defaulting on is safe on the desktop path; the hosted path supplies its own
    // keywrap closure and is likewise unaffected by the default.
    if content_encryption_opted_out() {
        return Ok(None);
    }
    // KEK selection is creds-only: a hosted deployment sets GAUGEDESK_CONTENT_KEK_ID
    // + the AZURE_* Crypto User SP creds to use the KMS; dev uses the local KEK.
    Ok(Some(Arc::new(ContentVault::new(
        root.join("content-keys"),
        content_keywrap(root)?,
    ))))
}

/// Whether an operator has explicitly opted out of at-rest content encryption.
/// Any other value (including the flag being unset) keeps encryption on.
fn content_encryption_opted_out() -> bool {
    matches!(
        gaugedesk_env::var("ENCRYPT_CONTENT")
            .as_deref()
            .map(str::trim),
        Some("0") | Some("false") | Some("off") | Some("no")
    )
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
        // `audit` is deliberately excluded from the sealed set (it verifies without
        // keys), so it must round-trip untouched — cleartext in, cleartext out.
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        assert_eq!(
            v.encode("eng-1", "audit", "advanced by rule R7").unwrap(),
            "advanced by rule R7"
        );
        assert_eq!(
            v.decode("eng-1", "audit", "advanced by rule R7").as_deref(),
            Some("advanced by rule R7")
        );
    }

    #[test]
    fn every_pii_kind_is_treated_as_content() {
        // Guards SOC 2 finding 2.6 (DR-0086): the whole personal-data set is sealed.
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        for kind in [
            "transcript",
            "membership",
            "org",
            "billing",
            "sso",
            "scim_token",
            "member_grant",
            "group_mapping",
            "policy",
            "placement_policy",
            "security",
            "software_policy",
            "archetype_approval",
            "setting",
            "device",
            "home",
            "home_route",
            "credential",
        ] {
            assert!(v.is_content(kind), "{kind} must be sealed at rest");
        }
        // Excluded kinds stay cleartext.
        for kind in ["audit", "chat", "project", "target", "engagement"] {
            assert!(!v.is_content(kind), "{kind} must remain cleartext");
        }
    }

    #[test]
    fn membership_is_sealed_through_the_store_and_erasable_audit_stays_cleartext() {
        // The full seam as the app runs it: a Store with the vault as its codec.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("s.db");
        let db_path = db.to_str().unwrap();
        let vault = Arc::new(vault(&dir.path().join("content-keys")));
        let mut store = Store::open(db_path).unwrap().with_codec(vault.clone());

        store
            .append_record("org", "membership", "role=admin;email=alice@example.com")
            .unwrap();
        // (d) an excluded `audit` record is written cleartext.
        store
            .append_record("eng-1", "audit", "advanced by rule R7")
            .unwrap();

        // (a) the raw stored membership payload is ciphertext (MARKER-prefixed), not
        //     the plaintext — read it back through a codec-less store to see the row.
        let raw = Store::open(db_path).unwrap();
        let stored_membership = raw.records("org", "membership").unwrap();
        assert!(
            stored_membership[0].starts_with(MARKER),
            "membership is sealed at rest: {}",
            stored_membership[0]
        );
        assert!(!stored_membership[0].contains("alice@example.com"));
        // (d, cont.) the audit row is stored verbatim, no marker.
        let stored_audit = raw.records("eng-1", "audit").unwrap();
        assert_eq!(stored_audit, vec!["advanced by rule R7".to_string()]);

        // (b) it round-trips: reading through the vault's decode seam yields plaintext.
        assert_eq!(
            store.records("org", "membership").unwrap(),
            vec!["role=admin;email=alice@example.com".to_string()]
        );

        // (c) after crypto-erasing the scope, the record is unreadable — the decode
        //     seam drops the now-unrecoverable row.
        assert!(vault.crypto_erase("org"), "the scope key existed");
        assert!(
            store.records("org", "membership").unwrap().is_empty(),
            "crypto-erased membership is gone from every reader"
        );
        // The audit row, on a different scope with no key, is untouched by erasure.
        assert_eq!(
            store.records("eng-1", "audit").unwrap(),
            vec!["advanced by rule R7".to_string()]
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
