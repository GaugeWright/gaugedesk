//! Opening a sealed collection at the receiving Home (ADR 0109 §7/§8).
//!
//! The session host seals with tenant-held recipient public keys and never sees
//! a private half. This is the counterpart: it reconstructs the wrapping key
//! from the recipient's private key and the ephemeral public point, opens the
//! data key, and decrypts the artifact.
//!
//! The derivation deliberately matches [`crate::backup_keyring`] byte for byte —
//! SHA-256 over a domain, each context component length-prefixed as a big-endian
//! u64, then the raw ECDH secret — under a *different* domain so a backup
//! recipient key cannot silently serve as a collection recipient. A
//! cross-language vector in `tests/collection_seal_vector.rs` proves the
//! TypeScript sealer and this opener agree; without it, artifacts seal
//! successfully and never decrypt, and nothing surfaces until ingest.

use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{ecdh::diffie_hellman, PublicKey as P256PublicKey, SecretKey};
use std::io::{self, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::at_rest::{Encryptor, LocalAeadEncryptor};
use crate::key_store::{fitted_file_name, HASHED_FILE_NAME_PREFIX};

const COLLECTION_KDF_DOMAIN: &[u8] = b"gaugewright/collection/ecies/v1";

/// A recipient's seed file ends in this.
const SEED_SUFFIX: &str = ".recipient";

/// Appended to a hashed seed's file name to name the file holding its id.
const ID_SUFFIX: &str = ".id";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectionOpenError {
    InvalidRecipient,
    InvalidEncoding,
    NoWrapForRecipient,
    Decrypt,
}

impl std::fmt::Display for CollectionOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRecipient => write!(f, "collection recipient key is invalid"),
            Self::InvalidEncoding => write!(f, "sealed collection is not well formed"),
            Self::NoWrapForRecipient => write!(f, "no wrap addresses this recipient"),
            Self::Decrypt => write!(f, "sealed collection could not be opened"),
        }
    }
}

impl std::error::Error for CollectionOpenError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionEnvelope {
    pub schema_ref: String,
    pub session_id: String,
    pub release_id: String,
    pub revision: u64,
    pub produced_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionWrap {
    pub recipient_public_key: String,
    pub ephemeral_public_key: String,
    pub wrapped_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedCollection {
    pub envelope: CollectionEnvelope,
    pub ciphertext: String,
    pub wraps: Vec<CollectionWrap>,
    pub byte_len: u64,
}

fn add_component(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

fn derive_wrapping_key(shared_secret: &[u8], components: [&str; 3]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(COLLECTION_KDF_DOMAIN);
    for component in components {
        add_component(&mut digest, component);
    }
    digest.update(shared_secret);
    digest.finalize().into()
}

/// Open a sealed collection with a locally held recipient private key.
///
/// `admission_scope` is the opaque embedder scope the session sealed under; the
/// wrap is bound to it together with the exact session revision and recipient,
/// so a wrap cannot be replayed to another deployment, revision, or recipient.
pub fn open_sealed_collection(
    sealed: &SealedCollection,
    recipient_private_seed: &[u8; 32],
    admission_scope: &str,
) -> Result<Vec<u8>, CollectionOpenError> {
    let secret = SecretKey::from_slice(recipient_private_seed)
        .map_err(|_| CollectionOpenError::InvalidRecipient)?;
    let recipient_public = hex::encode(secret.public_key().to_sec1_point(false).as_bytes());
    let wrap = sealed
        .wraps
        .iter()
        .find(|wrap| wrap.recipient_public_key == recipient_public)
        .ok_or(CollectionOpenError::NoWrapForRecipient)?;

    let ephemeral_bytes = hex::decode(&wrap.ephemeral_public_key)
        .map_err(|_| CollectionOpenError::InvalidEncoding)?;
    let ephemeral = P256PublicKey::from_sec1_bytes(&ephemeral_bytes)
        .map_err(|_| CollectionOpenError::InvalidEncoding)?;
    let shared = diffie_hellman(secret.to_nonzero_scalar(), ephemeral.as_affine());
    let point_id = format!(
        "{}:{}",
        sealed.envelope.session_id, sealed.envelope.revision
    );
    let wrapping_key = derive_wrapping_key(
        shared.raw_secret_bytes().as_ref(),
        [admission_scope, &point_id, &recipient_public],
    );

    let wrapped =
        hex::decode(&wrap.wrapped_key).map_err(|_| CollectionOpenError::InvalidEncoding)?;
    let data_key_bytes = LocalAeadEncryptor::new(wrapping_key)
        .decrypt(&wrapped)
        .map_err(|_| CollectionOpenError::Decrypt)?;
    let data_key: [u8; 32] = data_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CollectionOpenError::Decrypt)?;

    let ciphertext =
        hex::decode(&sealed.ciphertext).map_err(|_| CollectionOpenError::InvalidEncoding)?;
    let plaintext = LocalAeadEncryptor::new(data_key)
        .decrypt(&ciphertext)
        .map_err(|_| CollectionOpenError::Decrypt)?;
    if plaintext.len() as u64 != sealed.byte_len {
        return Err(CollectionOpenError::Decrypt);
    }
    Ok(plaintext)
}

/// One artifact accepted at the receiving Home.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngestedCollection {
    pub session_id: String,
    pub release_id: String,
    pub revision: u64,
    pub plaintext: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectionIngestError {
    SchemaMismatch,
    Open(CollectionOpenError),
}

impl std::fmt::Display for CollectionIngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SchemaMismatch => {
                write!(
                    f,
                    "artifact schema does not match the expected release schema"
                )
            }
            Self::Open(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CollectionIngestError {}

/// Open one drained artifact and re-validate it here.
///
/// `expected_schema_ref` comes from this Home's own copy of the release. The
/// hosted side already checked the schema, but its verdict is not trusted: the
/// session object is the jurisdiction a visitor influences most, so the
/// receiving authority checks again against material it holds itself.
pub fn ingest_sealed_collection(
    sealed: &SealedCollection,
    recipient_private_seed: &[u8; 32],
    admission_scope: &str,
    expected_schema_ref: &str,
) -> Result<IngestedCollection, CollectionIngestError> {
    if sealed.envelope.schema_ref != expected_schema_ref {
        return Err(CollectionIngestError::SchemaMismatch);
    }
    let plaintext = open_sealed_collection(sealed, recipient_private_seed, admission_scope)
        .map_err(CollectionIngestError::Open)?;
    Ok(IngestedCollection {
        session_id: sealed.envelope.session_id.clone(),
        release_id: sealed.envelope.release_id.clone(),
        revision: sealed.envelope.revision,
        plaintext,
    })
}

/// Local custody for collection recipient keys.
///
/// The private half never leaves this boundary: publish carries only the public
/// point, the hosted side stores only ciphertext, and unsealing happens here.
/// Same on-disk discipline as the signing key store — 0700 directory, 0600 file,
/// raw 32-byte seed, load-or-create so a republish reuses the same recipient
/// rather than orphaning artifacts sealed to the previous one.
pub struct CollectionRecipientStore {
    dir: PathBuf,
}

/// The publishable half of a recipient, plus the exact reference that names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionRecipient {
    pub recipient_ref: String,
    pub public_key_hex: String,
}

fn valid_recipient_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl CollectionRecipientStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Where `recipient_id`'s seed lives: the id in hex, or its SHA-256 for an
    /// id of more than 122 characters, whose hex would pass the file-name limit.
    fn path(&self, recipient_id: &str) -> PathBuf {
        self.dir
            .join(fitted_file_name(recipient_id.as_bytes(), SEED_SUFFIX))
    }

    /// Where a hashed seed's id is written down, so [`Self::list`] can name a
    /// keyring whose file name does not spell it. A hex name spells its own id
    /// and has none.
    fn id_path(&self, recipient_id: &str) -> Option<PathBuf> {
        let name = fitted_file_name(recipient_id.as_bytes(), SEED_SUFFIX);
        name.starts_with(HASHED_FILE_NAME_PREFIX)
            .then(|| self.dir.join(format!("{name}{ID_SUFFIX}")))
    }

    /// Load or create the recipient for `recipient_id`, returning its public half.
    pub fn ensure(&self, recipient_id: &str) -> io::Result<CollectionRecipient> {
        let seed = self.ensure_seed(recipient_id)?;
        let secret = SecretKey::from_slice(&seed)
            .map_err(|_| io::Error::other("stored recipient key is invalid"))?;
        Ok(CollectionRecipient {
            recipient_ref: format!("recipient:collection:{recipient_id}"),
            public_key_hex: hex::encode(secret.public_key().to_sec1_point(false).as_bytes()),
        })
    }

    /// The recipient ids this Home holds a keyring for, in a stable order.
    ///
    /// Public halves only ever leave through [`Self::ensure`]; this is the index
    /// the Deploy Config surface offers so an owner picks an existing keyring
    /// instead of retyping an id and silently minting a second one. A missing
    /// directory is an empty list, not an error — a Home that has never collected
    /// has no keyring and that is not a fault.
    pub fn list(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut ids: Vec<String> = entries
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name();
                let name = name.to_str()?;
                let encoded = name.strip_suffix(SEED_SUFFIX)?;
                let id = if encoded.starts_with(HASHED_FILE_NAME_PREFIX) {
                    let id = std::fs::read_to_string(self.dir.join(format!("{name}{ID_SUFFIX}")))
                        .ok()?;
                    // An id that does not hash to this name names another keyring.
                    (fitted_file_name(id.as_bytes(), SEED_SUFFIX) == name).then_some(id)?
                } else {
                    String::from_utf8(hex::decode(encoded).ok()?).ok()?
                };
                valid_recipient_id(&id).then_some(id)
            })
            .collect();
        ids.sort();
        ids
    }

    /// Read the private seed. Only the local unseal path may call this.
    pub fn open_seed(&self, recipient_id: &str) -> io::Result<[u8; 32]> {
        if !valid_recipient_id(recipient_id) {
            return Err(io::Error::other("collection recipient id is invalid"));
        }
        let bytes = std::fs::read(self.path(recipient_id))?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| io::Error::other("stored recipient key is truncated"))
    }

    fn ensure_seed(&self, recipient_id: &str) -> io::Result<[u8; 32]> {
        if !valid_recipient_id(recipient_id) {
            return Err(io::Error::other("collection recipient id is invalid"));
        }
        let path = self.path(recipient_id);
        if path.exists() {
            return self.open_seed(recipient_id);
        }
        std::fs::create_dir_all(&self.dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        }
        if let Some(id_path) = self.id_path(recipient_id) {
            // Before the seed, so no hashed seed is ever missing from the list.
            // Every writer writes the same bytes, so a race needs no winner.
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&id_path)?;
            file.write_all(recipient_id.as_bytes())?;
            file.sync_all()?;
        }
        let seed = loop {
            let mut candidate = [0_u8; 32];
            getrandom::getrandom(&mut candidate)
                .map_err(|error| io::Error::other(error.to_string()))?;
            if SecretKey::from_slice(&candidate).is_ok() {
                break candidate;
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
                file.write_all(&seed)?;
                file.sync_all()?;
                Ok(seed)
            }
            // Lost a create race: whoever won holds the authoritative key.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                self.open_seed(recipient_id)
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recipient_is_created_once_and_reused_across_publishes() {
        let dir = std::env::temp_dir().join(format!("gw-recip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = CollectionRecipientStore::new(&dir);
        let first = store.ensure("theory-a").expect("recipient is created");
        let second = store.ensure("theory-a").expect("recipient is reused");
        assert_eq!(first, second);
        assert_eq!(first.recipient_ref, "recipient:collection:theory-a");
        assert!(first.public_key_hex.starts_with("04"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_stored_seed_opens_what_its_public_half_seals() {
        let dir = std::env::temp_dir().join(format!("gw-recip-open-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = CollectionRecipientStore::new(&dir);
        let recipient = store.ensure("theory-a").expect("recipient is created");
        let seed = store.open_seed("theory-a").expect("seed is readable");
        let secret = SecretKey::from_slice(&seed).expect("seed is a valid scalar");
        assert_eq!(
            hex::encode(secret.public_key().to_sec1_point(false).as_bytes()),
            recipient.public_key_hex,
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_recipient_id_too_long_for_a_hex_name_is_created_reused_and_listed() {
        let dir = tempfile::tempdir().unwrap();
        let store = CollectionRecipientStore::new(dir.path());
        // The longest id the store admits: hex of it plus the suffix is past
        // the 255-byte file-name limit.
        let long = format!("proj-{}", "a".repeat(123));
        assert!(valid_recipient_id(&long));
        let first = store.ensure(&long).expect("recipient is created");
        let second = CollectionRecipientStore::new(dir.path())
            .ensure(&long)
            .expect("recipient is reused");
        assert_eq!(first, second);
        let seed = store.open_seed(&long).expect("seed is readable");
        let secret = SecretKey::from_slice(&seed).expect("seed is a valid scalar");
        assert_eq!(
            hex::encode(secret.public_key().to_sec1_point(false).as_bytes()),
            first.public_key_hex,
        );
        let path = store.path(&long);
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(
            name.starts_with(HASHED_FILE_NAME_PREFIX)
                && name.len() <= crate::key_store::MAX_FILE_NAME_BYTES,
            "{name}"
        );
        // A short id keeps its hex name, so keyrings already held still open,
        // and both are listed by id.
        store.ensure("theory-a").expect("recipient is created");
        assert_eq!(
            store.path("theory-a").file_name().unwrap(),
            format!("{}.recipient", hex::encode("theory-a")).as_str()
        );
        assert_eq!(store.list(), vec![long, "theory-a".to_owned()]);
    }

    #[test]
    fn an_unsafe_recipient_id_is_refused() {
        let store = CollectionRecipientStore::new(std::env::temp_dir());
        assert!(store.ensure("../escape").is_err());
        assert!(store.ensure("").is_err());
    }
}
