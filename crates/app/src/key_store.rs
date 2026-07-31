//! `KeyStore` — where an authority's / device's P-256 **governance signing key**
//! lives (D-CRYPTO / ADR 0042). The pure core does the crypto
//! ([`gaugewright_core::signature`]); *storage* is impure and lives here behind a trait,
//! so the loopback double, a file-backed dev impl, and a future secure-enclave /
//! TPM impl are interchangeable with no change to the signing path.

use std::io::{self, Write};
use std::path::PathBuf;

use gaugewright_core::ids::{AuthorityId, PublicKey};
use gaugewright_core::signature::{Signature, SigningKey};
use sha2::{Digest, Sha256};

use crate::workbench_state::Workbench;

/// Resolve the signing key for an authority. Real signing paths (the relay
/// constructing a federated envelope, the challenge/response handshake) take a
/// `&dyn KeyStore` and never see raw key material beyond the `SigningKey`.
pub trait KeyStore {
    /// The authority's signing key, deriving + persisting one on first use.
    fn signing_key(&self, authority: &AuthorityId) -> SigningKey;
}

/// Loopback/dev double: derive a deterministic key from the authority id (SHA-256
/// → seed), with **no storage**. This makes the loopback bridge sign and verify
/// with real P-256 — but it is **not secure** (the key is derivable from the
/// public id). Real deployments enroll keys in [`FileKeyStore`] (or a secure
/// enclave) instead of deriving them.
#[derive(Default, Clone, Copy)]
pub struct LoopbackKeyStore;

impl KeyStore for LoopbackKeyStore {
    fn signing_key(&self, authority: &AuthorityId) -> SigningKey {
        SigningKey::from_seed(&seed_from(authority.as_str()))
            .expect("a SHA-256 digest is a valid P-256 scalar")
    }
}

/// File-backed store: persists each authority's unguessable 32-byte seed under
/// `dir/<authority>.key`, generating it from the operating-system CSPRNG on first
/// use. The on-disk format is the bare seed; production packaging can replace
/// this boundary with secure-enclave custody without changing signing callers.
#[derive(Clone)]
pub struct FileKeyStore {
    dir: PathBuf,
}

impl FileKeyStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, authority: &AuthorityId) -> PathBuf {
        // authority ids are scope segments (no path separators); hex-namespace to
        // be safe against odd characters.
        self.dir
            .join(format!("{}.key", hex::encode(authority.as_str())))
    }

    /// Enroll a specific key for an authority (overwrites). Used by tests and by
    /// out-of-band key import.
    pub fn enroll(&self, authority: &AuthorityId, key: &SigningKey) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(self.path(authority))?;
        file.write_all(&key.to_seed_bytes())?;
        file.sync_all()
    }

    /// Load or create an unguessable key for a real external authority.
    ///
    /// Unlike [`KeyStore::signing_key`], this never derives private material
    /// from the public authority id and never falls back after an I/O failure.
    pub fn random_signing_key(&self, authority: &AuthorityId) -> io::Result<SigningKey> {
        let path = self.path(authority);
        if path.exists() {
            return read_signing_key(&path);
        }
        std::fs::create_dir_all(&self.dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let key = loop {
            let mut seed = [0_u8; 32];
            getrandom::getrandom(&mut seed).map_err(io::Error::other)?;
            if let Ok(key) = SigningKey::from_seed(&seed) {
                break key;
            }
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                file.write_all(&key.to_seed_bytes())?;
                file.sync_all()?;
                Ok(key)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => read_signing_key(&path),
            Err(error) => Err(error),
        }
    }
}

fn read_signing_key(path: &std::path::Path) -> io::Result<SigningKey> {
    let bytes = std::fs::read(path)?;
    let seed = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "signing key has invalid length")
    })?;
    SigningKey::from_seed(&seed)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.reason))
}

impl KeyStore for FileKeyStore {
    fn signing_key(&self, authority: &AuthorityId) -> SigningKey {
        self.random_signing_key(authority)
            .expect("file-backed signing key must load or enroll securely")
    }
}

fn seed_from(s: &str) -> [u8; 32] {
    let digest = Sha256::digest(s.as_bytes());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

impl Workbench {
    fn governance_signing_key(&self) -> SigningKey {
        let root = self.root_path();
        if root.as_os_str().is_empty() {
            LoopbackKeyStore.signing_key(self.authority())
        } else {
            FileKeyStore::new(root.join("keys")).signing_key(self.authority())
        }
    }

    /// This authority's P-256 governance **public** key, resolved (deriving +
    /// persisting on first use) through the file-backed [`FileKeyStore`] under
    /// `root/keys`. This is the value pinned in a peer's bridge grant at pairing
    /// (`SERVE-1`/ADR 0042). The private half never leaves the key store.
    pub fn governance_public_key(&self) -> PublicKey {
        self.governance_signing_key().public_key()
    }

    /// Sign an already-canonical protocol payload with this Home authority's
    /// governance key. The private seed remains behind the key-store boundary.
    pub fn sign_governance_payload(&self, payload: &[u8]) -> Signature {
        self.governance_signing_key().sign(payload)
    }

    /// Public P-256 point for protocols that need JWK `x`/`y` coordinates.
    pub fn governance_public_key_uncompressed_bytes(&self) -> [u8; 65] {
        self.governance_signing_key()
            .public_key_uncompressed_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_keys_are_stable_per_authority_and_distinct_across() {
        let ks = LoopbackKeyStore;
        let a = ks.signing_key(&AuthorityId::new("acme"));
        let a2 = ks.signing_key(&AuthorityId::new("acme"));
        let b = ks.signing_key(&AuthorityId::new("other"));
        assert_eq!(
            a.to_seed_bytes(),
            a2.to_seed_bytes(),
            "stable per authority"
        );
        assert_ne!(
            a.to_seed_bytes(),
            b.to_seed_bytes(),
            "distinct across authorities"
        );
    }

    #[test]
    fn signed_then_verified_through_the_store() {
        use gaugewright_core::signature::verify_signature;
        let ks = LoopbackKeyStore;
        let key = ks.signing_key(&AuthorityId::new("acme"));
        let sig = key.sign(b"challenge");
        assert_eq!(
            verify_signature(b"challenge", &sig, &key.public_key()),
            Ok(true)
        );
    }

    #[test]
    fn file_store_persists_and_reloads_the_same_key() {
        let dir =
            std::env::temp_dir().join(format!("gaugewright-keystore-test-{}", std::process::id()));
        let ks = FileKeyStore::new(&dir);
        let authority = AuthorityId::new("acme");
        let first = ks.signing_key(&authority).to_seed_bytes();
        // a fresh store over the same dir reloads the persisted key, not a new one.
        let reloaded = FileKeyStore::new(&dir)
            .signing_key(&authority)
            .to_seed_bytes();
        assert_eq!(first, reloaded);
        assert_ne!(
            first,
            LoopbackKeyStore.signing_key(&authority).to_seed_bytes(),
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn random_file_keys_are_stable_per_root_and_unlinkable_across_roots() {
        let left = tempfile::tempdir().unwrap();
        let right = tempfile::tempdir().unwrap();
        let authority = AuthorityId::new("local-user::public-publisher");
        let first = FileKeyStore::new(left.path())
            .random_signing_key(&authority)
            .unwrap();
        let reloaded = FileKeyStore::new(left.path())
            .random_signing_key(&authority)
            .unwrap();
        let independent = FileKeyStore::new(right.path())
            .random_signing_key(&authority)
            .unwrap();
        assert_eq!(first.public_key(), reloaded.public_key());
        assert_ne!(first.public_key(), independent.public_key());
        assert_ne!(
            first.public_key(),
            LoopbackKeyStore.signing_key(&authority).public_key(),
        );
    }
}
