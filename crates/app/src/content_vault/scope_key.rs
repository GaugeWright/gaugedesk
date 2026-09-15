//! Prepared scope keys keep remote custody work out of store transactions.
use super::*;
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::rc::{Rc, Weak};

mod transfer;
pub use transfer::{PreparedScopeTransfer, ScopeKeyCapsule};

const TOMBSTONE: &[u8] = b"gaugedesk.content-key-erased.v1\n";

thread_local! {
    // Share locks, never decrypted keys. Two vaults with different KEKs must
    // independently unwrap their keys even when their filesystem is the same.
    static RETAINED: RefCell<HashMap<PathBuf, Weak<File>>> = RefCell::new(HashMap::new());
}

fn lock_path(root: &Path, key_id: &str) -> std::io::Result<PathBuf> {
    require_erasure_key_id(key_id)?;
    let directory = std::fs::canonicalize(root)?.join("scope-locks");
    std::fs::create_dir_all(&directory)?;
    Ok(directory.join(format!("{key_id}.lock")))
}

fn open_lock(path: &Path) -> std::io::Result<File> {
    // The inode is permanent: deleting/replacing it would split exclusion.
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

fn shared(root: &Path, key_id: &str) -> std::io::Result<Rc<File>> {
    let path = lock_path(root, key_id)?;
    if let Some(lease) =
        RETAINED.with(|retained| retained.borrow().get(&path).and_then(Weak::upgrade))
    {
        return Ok(lease);
    }
    let file = open_lock(&path)?;
    file.lock_shared()?;
    let lease = Rc::new(file);
    RETAINED.with(|retained| {
        let mut retained = retained.borrow_mut();
        retained.retain(|_, lease| lease.strong_count() != 0);
        retained.insert(path, Rc::downgrade(&lease));
    });
    Ok(lease)
}

fn exclusive(root: &Path, key_id: &str) -> std::io::Result<File> {
    let path = lock_path(root, key_id)?;
    if RETAINED.with(|retained| {
        retained
            .borrow()
            .get(&path)
            .and_then(Weak::upgrade)
            .is_some()
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "scope is retained by this publication",
        ));
    }
    let file = open_lock(&path)?;
    file.lock()?;
    Ok(file)
}

fn key_path(root: &Path, key_id: &str) -> PathBuf {
    root.join(format!("{key_id}.dek"))
}

fn tombstone_path(root: &Path, key_id: &str) -> PathBuf {
    root.join(format!("{key_id}.erased"))
}

fn available(root: &Path, key_id: &str) -> std::io::Result<()> {
    match std::fs::symlink_metadata(tombstone_path(root, key_id)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "scope content key is erased",
        )),
    }
}

fn sync_directory(root: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    File::open(root)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = root;
    Ok(())
}

fn persist_new(root: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut staged = tempfile::NamedTempFile::new_in(root)?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    staged
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    sync_directory(root)
}

fn mark_erased(root: &Path, key_id: &str) -> std::io::Result<()> {
    let path = tombstone_path(root, key_id);
    match std::fs::read(&path) {
        Ok(bytes) if bytes == TOMBSTONE => Ok(()),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "scope erasure marker is malformed",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            persist_new(root, &path, TOMBSTONE)
        }
        Err(error) => Err(error),
    }
}

fn fingerprint(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

fn custody_error(_: crate::at_rest::AtRestError) -> std::io::Error {
    std::io::Error::other("scope content-key custody is unavailable")
}

/// A confirmed, unwrapped scope key prepared outside store transactions. It
/// grants no product permission, and every use still checks local availability.
/// Keys are not shared across vaults or silently replaced after preparation.
pub struct PreparedScopeKey {
    root: PathBuf,
    scope: String,
    key_id: String,
    wrapped_fingerprint: Vec<u8>,
    cipher: LocalAeadEncryptor,
}

impl PreparedScopeKey {
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Retain through the callback's commit/rollback. Nested same-thread calls
    /// reuse the file lease and cannot deadlock behind a waiting eraser.
    pub fn retain<T, E: From<std::io::Error>>(
        &self,
        publish: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let _lease = shared(&self.root, &self.key_id)?;
        available(&self.root, &self.key_id)?;
        let wrapped = std::fs::read(key_path(&self.root, &self.key_id))?;
        if fingerprint(&wrapped) != self.wrapped_fingerprint {
            return Err(
                std::io::Error::other("scope content key changed after preparation").into(),
            );
        }
        publish()
    }

    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        self.retain(|| {
            self.cipher
                .encrypt_with_aad(plaintext, aad)
                .map_err(custody_error)
        })
    }

    pub fn open(&self, aad: &[u8], ciphertext: &[u8]) -> std::io::Result<Vec<u8>> {
        self.retain(|| {
            self.cipher
                .decrypt_with_aad(ciphertext, aad)
                .map_err(custody_error)
        })
    }
}

impl whipplescript_store::payload_protection::PayloadCodec for PreparedScopeKey {
    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> whipplescript_store::StoreResult<Vec<u8>> {
        PreparedScopeKey::seal(self, aad, plaintext).map_err(Into::into)
    }

    fn open(&self, aad: &[u8], ciphertext: &[u8]) -> whipplescript_store::StoreResult<Vec<u8>> {
        PreparedScopeKey::open(self, aad, ciphertext).map_err(Into::into)
    }

    fn retain(
        &self,
        publish: &mut dyn FnMut() -> whipplescript_store::StoreResult<()>,
    ) -> whipplescript_store::StoreResult<()> {
        PreparedScopeKey::retain(self, publish)
    }
}

impl ContentVault {
    fn confirmed_scope(&self, scope: &str) -> std::io::Result<String> {
        if scope.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "scope identity is empty",
            ));
        }
        let key_id = crate::org::sha256_hex(scope);
        let ledger = self.ledger.as_ref().ok_or_else(|| {
            std::io::Error::other("scope key preparation requires an erasure ledger")
        })?;
        if ledger.recorded_confirmed()?.iter().any(|id| id == &key_id) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "scope content key is erased",
            ));
        }
        Ok(key_id)
    }

    fn prepared(
        &self,
        root: PathBuf,
        scope: &str,
        key_id: String,
        wrapped: &[u8],
    ) -> std::io::Result<PreparedScopeKey> {
        Ok(PreparedScopeKey {
            root,
            scope: scope.to_owned(),
            key_id,
            wrapped_fingerprint: fingerprint(wrapped),
            cipher: LocalAeadEncryptor::new(self.wrap.unwrap(wrapped).map_err(custody_error)?),
        })
    }

    /// Prepare only an existing scope. Ledger confirmation and KMS unwrapping
    /// may block; call before product/store transactions, never from a codec.
    pub fn prepare_scope_key(&self, scope: &str) -> std::io::Result<PreparedScopeKey> {
        let key_id = self.confirmed_scope(scope)?;
        let root = std::fs::canonicalize(&self.dir)?;
        let _lease = shared(&root, &key_id)?;
        available(&root, &key_id)?;
        let wrapped = std::fs::read(key_path(&root, &key_id))?;
        self.prepared(root, scope, key_id, &wrapped)
    }

    /// Explicit admitted initialization. Reuses a valid existing key; never
    /// replaces it or revives a tombstoned scope. Store reopening uses prepare.
    pub fn initialize_scope_key(&self, scope: &str) -> std::io::Result<PreparedScopeKey> {
        let key_id = self.confirmed_scope(scope)?;
        std::fs::create_dir_all(&self.dir)?;
        let root = std::fs::canonicalize(&self.dir)?;
        let _lease = exclusive(&root, &key_id)?;
        available(&root, &key_id)?;
        let wrapped = self.existing_or_new_key(&root, &key_id, true)?;
        self.prepared(root, scope, key_id, &wrapped)
    }

    fn existing_or_new_key(
        &self,
        root: &Path,
        key_id: &str,
        create: bool,
    ) -> std::io::Result<Vec<u8>> {
        let path = key_path(root, key_id);
        match std::fs::read(&path) {
            Ok(wrapped) => Ok(wrapped),
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                let mut dek = [0; 32];
                SystemRandom::new()
                    .fill(&mut dek)
                    .map_err(|_| std::io::Error::other("scope key generation failed"))?;
                let wrapped = self.wrap.wrap(&dek).map_err(custody_error)?;
                persist_new(root, &path, &wrapped)?;
                Ok(wrapped)
            }
            Err(error) => Err(error),
        }
    }

    /// Preserve the legacy empty-AAD format while retaining its key through
    /// encryption/decryption. Native publication uses PreparedScopeKey::retain.
    pub(super) fn with_legacy_key<T>(
        &self,
        scope: &str,
        create: bool,
        use_key: impl FnOnce([u8; 32]) -> Option<T>,
    ) -> Option<T> {
        if create {
            std::fs::create_dir_all(&self.dir).ok()?;
        }
        let root = std::fs::canonicalize(&self.dir).ok()?;
        let key_id = crate::org::sha256_hex(scope);
        let lease = shared(&root, &key_id).ok()?;
        available(&root, &key_id).ok()?;
        if key_path(&root, &key_id).is_file() {
            let cached = self.key_state.lock().unwrap().cache.get(scope).copied();
            if let Some(key) = cached {
                return use_key(key);
            }
        }
        let wrapped = match self.existing_or_new_key(&root, &key_id, false) {
            Ok(wrapped) => wrapped,
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                drop(lease);
                let _exclusive = exclusive(&root, &key_id).ok()?;
                available(&root, &key_id).ok()?;
                let wrapped = self.existing_or_new_key(&root, &key_id, true).ok()?;
                let key = self.wrap.unwrap(&wrapped).ok()?;
                {
                    // The fence and the cache share a lock so a writer either
                    // completes before erasure or observes the fence; minting a
                    // replacement key after erasure would resurrect the scope.
                    let mut state = self.key_state.lock().unwrap();
                    if state.erased_key_ids.contains(&key_id) {
                        return None;
                    }
                    state.cache.insert(scope.to_owned(), key);
                }
                return use_key(key);
            }
            Err(_) => return None,
        };
        let key = self.wrap.unwrap(&wrapped).ok()?;
        {
            let mut state = self.key_state.lock().unwrap();
            if state.erased_key_ids.contains(&key_id) {
                return None;
            }
            state.cache.insert(scope.to_owned(), key);
        }
        use_key(key)
    }

    pub(super) fn erase_local_scope(&self, key_id: &str) -> std::io::Result<bool> {
        std::fs::create_dir_all(&self.dir)?;
        let root = std::fs::canonicalize(&self.dir)?;
        let _exclusive = exclusive(&root, key_id)?;
        mark_erased(&root, key_id)?;
        {
            // Raise the in-process fence under the same lock that drops the live
            // key, so a writer racing this erasure cannot mint a replacement:
            // main's durable tombstone survives restart, this stops the window
            // inside one.
            let mut state = self.key_state.lock().unwrap();
            state.erased_key_ids.insert(key_id.to_owned());
            state
                .cache
                .retain(|scope, _| crate::org::sha256_hex(scope) != key_id);
        }
        let existed = match std::fs::remove_file(key_path(&root, key_id)) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        sync_directory(&root)?;
        Ok(existed)
    }

    /// Local destruction can succeed even when remote confirmation fails. Retry
    /// confirms the same tombstone; it never recreates a key. Blocking authority
    /// work runs after local exclusion is released, outside store transactions.
    pub fn erase_scope_key(&self, scope: &str) -> std::io::Result<bool> {
        if scope.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "scope identity is empty",
            ));
        }
        let ledger = self
            .ledger
            .as_ref()
            .ok_or_else(|| std::io::Error::other("confirmed erasure requires an erasure ledger"))?;
        let key_id = crate::org::sha256_hex(scope);
        let existed = self.erase_local_scope(&key_id)?;
        ledger.record_confirmed(&key_id)?;
        Ok(existed)
    }
}

#[cfg(test)]
mod tests;
