//! A person's provider links, sealed once per trusted device (DR-0334).
//!
//! The account authority holds each link's non-secret record and, for every
//! trusted device of the account, one copy of the secret sealed to that
//! device's own public recipient key. The private half never leaves the device,
//! so the Hub stores ciphertext it cannot open, and revoking one device means
//! deleting its copies rather than rotating a key every device shares.
//!
//! A copy is P-256 ECIES straight over the secret: a fresh ephemeral key per
//! copy, a SHA-256 derivation that binds the account, the provider, the link's
//! version and the device, then AES-256-GCM. The binding is what stops a copy
//! being served to another device, another account, or as a different version
//! of the same link. The construction is the backup keyring's (ADR 0102) under
//! its own domain, and the browser's sealer in
//! `web/packages/control-plane-client/src/account-link-seal.ts` is a
//! byte-for-byte port, pinned by `tests/account-link-seal-vector.json`.
//!
//! The private type is neither serializable nor cloneable; a desktop keeps it
//! in [`LinkRecipientStore`].

use std::io::{self, Write as _};
use std::path::PathBuf;

use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{ecdh::diffie_hellman, PublicKey as P256PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::at_rest::{Encryptor, LocalAeadEncryptor};

const LINK_KDF_DOMAIN: &[u8] = b"gaugewright/account-link/ecies/v1";

/// Why a recipient, a context or a copy was refused. Failures stay
/// non-specific at the cryptographic boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountLinkSealError {
    InvalidRecipient,
    InvalidContext,
    Rng,
    Encrypt,
    Decrypt,
}

/// A device's public recipient key: hex, uncompressed SEC1 P-256. It may be
/// stored at the account authority; it contains no private material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LinkRecipientPublicKey(String);

impl LinkRecipientPublicKey {
    /// Parse untrusted public-key input at a service boundary.
    pub fn parse(encoded: impl Into<String>) -> Result<Self, AccountLinkSealError> {
        let encoded = encoded.into();
        let key = Self(encoded);
        key.p256()?;
        Ok(key)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn p256(&self) -> Result<P256PublicKey, AccountLinkSealError> {
        let bytes = hex::decode(&self.0).map_err(|_| AccountLinkSealError::InvalidRecipient)?;
        P256PublicKey::from_sec1_bytes(&bytes).map_err(|_| AccountLinkSealError::InvalidRecipient)
    }
}

/// A device's private recipient key. It opens copies sealed to this device and
/// nothing else; it is never serialized or sent anywhere.
pub struct LinkRecipientPrivateKey(SecretKey);

impl LinkRecipientPrivateKey {
    /// Reopen a seed held by the device's own key store.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, AccountLinkSealError> {
        SecretKey::from_slice(&seed)
            .map(Self)
            .map_err(|_| AccountLinkSealError::InvalidRecipient)
    }

    pub fn public_key(&self) -> LinkRecipientPublicKey {
        LinkRecipientPublicKey(hex::encode(
            self.0.public_key().to_sec1_point(false).as_bytes(),
        ))
    }
}

/// One trusted device that should hold a copy, named by its trusted-device id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkRecipient {
    pub device_id: String,
    pub public_key: LinkRecipientPublicKey,
}

impl LinkRecipient {
    pub fn new(
        device_id: impl Into<String>,
        public_key: LinkRecipientPublicKey,
    ) -> Result<Self, AccountLinkSealError> {
        let device_id = device_id.into();
        valid_component(&device_id)
            .then_some(Self {
                device_id,
                public_key,
            })
            .ok_or(AccountLinkSealError::InvalidRecipient)
    }
}

/// What a copy is a copy of: one version of one account's link to one
/// provider. Bound into every copy's key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkContext {
    account: String,
    provider: String,
    version: u64,
}

impl LinkContext {
    pub fn new(
        account: impl Into<String>,
        provider: impl Into<String>,
        version: u64,
    ) -> Result<Self, AccountLinkSealError> {
        let account = account.into();
        let provider = provider.into();
        (valid_component(&account) && valid_component(&provider) && version > 0)
            .then_some(Self {
                account,
                provider,
                version,
            })
            .ok_or(AccountLinkSealError::InvalidContext)
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn version(&self) -> u64 {
        self.version
    }
}

/// One device's copy of a link's secret. Opaque and safe to store at the
/// account authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedLinkCopy {
    pub device_id: String,
    pub ephemeral_pubkey: String,
    pub ciphertext: String,
}

/// Seal `secret` for one device.
pub fn seal_link_copy(
    context: &LinkContext,
    secret: &[u8],
    recipient: &LinkRecipient,
) -> Result<SealedLinkCopy, AccountLinkSealError> {
    let seed = loop {
        let mut candidate = [0_u8; 32];
        getrandom::getrandom(&mut candidate).map_err(|_| AccountLinkSealError::Rng)?;
        if SecretKey::from_slice(&candidate).is_ok() {
            break candidate;
        }
    };
    seal_with_ephemeral(context, secret, recipient, seed)
}

/// Seal `secret` for every device in `recipients`, in order.
pub fn seal_link_copies(
    context: &LinkContext,
    secret: &[u8],
    recipients: &[LinkRecipient],
) -> Result<Vec<SealedLinkCopy>, AccountLinkSealError> {
    recipients
        .iter()
        .map(|recipient| seal_link_copy(context, secret, recipient))
        .collect()
}

fn seal_with_ephemeral(
    context: &LinkContext,
    secret: &[u8],
    recipient: &LinkRecipient,
    ephemeral_seed: [u8; 32],
) -> Result<SealedLinkCopy, AccountLinkSealError> {
    let peer = recipient.public_key.p256()?;
    let ephemeral =
        SecretKey::from_slice(&ephemeral_seed).map_err(|_| AccountLinkSealError::Rng)?;
    let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), peer.as_affine());
    let key = derive_copy_key(
        shared.raw_secret_bytes().as_ref(),
        context,
        &recipient.device_id,
    );
    let ciphertext = LocalAeadEncryptor::new(key)
        .encrypt(secret)
        .map_err(|_| AccountLinkSealError::Encrypt)?;
    Ok(SealedLinkCopy {
        device_id: recipient.device_id.clone(),
        ephemeral_pubkey: hex::encode(ephemeral.public_key().to_sec1_point(false).as_bytes()),
        ciphertext: hex::encode(ciphertext),
    })
}

/// Open this device's copy. A copy for another device, another account,
/// provider or version, a wrong key, or tampering all fail the same way.
pub fn open_link_copy(
    context: &LinkContext,
    private_key: &LinkRecipientPrivateKey,
    copy: &SealedLinkCopy,
) -> Result<Vec<u8>, AccountLinkSealError> {
    if !valid_component(&copy.device_id) {
        return Err(AccountLinkSealError::InvalidRecipient);
    }
    let ephemeral = P256PublicKey::from_sec1_bytes(
        &hex::decode(&copy.ephemeral_pubkey).map_err(|_| AccountLinkSealError::Decrypt)?,
    )
    .map_err(|_| AccountLinkSealError::Decrypt)?;
    let ciphertext = hex::decode(&copy.ciphertext).map_err(|_| AccountLinkSealError::Decrypt)?;
    let shared = diffie_hellman(private_key.0.to_nonzero_scalar(), ephemeral.as_affine());
    let key = derive_copy_key(shared.raw_secret_bytes().as_ref(), context, &copy.device_id);
    LocalAeadEncryptor::new(key)
        .decrypt(&ciphertext)
        .map_err(|_| AccountLinkSealError::Decrypt)
}

fn derive_copy_key(shared_secret: &[u8], context: &LinkContext, device_id: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(LINK_KDF_DOMAIN);
    add_component(&mut digest, &context.account);
    add_component(&mut digest, &context.provider);
    add_component(&mut digest, &context.version.to_string());
    add_component(&mut digest, device_id);
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

/// A device's recipient keys, one per account signed in on it.
///
/// Each account gets its own key because each is a separate trusted device of
/// a separate account at the Hub; one account's copies must not open under
/// another's key. Same discipline as the signing key store: 0700 directory,
/// 0600 file, a raw 32-byte seed, load-or-create so registering again reuses
/// the key every existing copy was sealed to.
pub struct LinkRecipientStore {
    dir: PathBuf,
}

impl LinkRecipientStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, account: &str) -> PathBuf {
        self.dir.join(format!("{}.recipient", hex::encode(account)))
    }

    /// Load or create `account`'s recipient key on this device and return its
    /// public half, which is what the device registers with the account.
    pub fn ensure(&self, account: &str) -> io::Result<LinkRecipientPublicKey> {
        Ok(self.private_key(account, true)?.public_key())
    }

    /// Open `account`'s key to read a copy sealed to this device. An account
    /// that never registered has none, and that is an error rather than a
    /// fresh key no copy was sealed to.
    pub fn open(&self, account: &str) -> io::Result<LinkRecipientPrivateKey> {
        self.private_key(account, false)
    }

    fn private_key(&self, account: &str, create: bool) -> io::Result<LinkRecipientPrivateKey> {
        if !valid_component(account) {
            return Err(io::Error::other("account id is invalid"));
        }
        let path = self.path(account);
        let seed = if create && !path.exists() {
            self.create(account)?
        } else {
            read_seed(&path)?
        };
        LinkRecipientPrivateKey::from_seed(seed)
            .map_err(|_| io::Error::other("stored link recipient key is invalid"))
    }

    fn create(&self, account: &str) -> io::Result<[u8; 32]> {
        std::fs::create_dir_all(&self.dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let seed = loop {
            let mut candidate = [0_u8; 32];
            getrandom::getrandom(&mut candidate)
                .map_err(|error| io::Error::other(error.to_string()))?;
            if SecretKey::from_slice(&candidate).is_ok() {
                break candidate;
            }
        };
        let path = self.path(account);
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
            // Lost a create race: whoever won holds the key copies are sealed to.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => read_seed(&path),
            Err(error) => Err(error),
        }
    }
}

/// A hosted Home's own recipient key (DR-0380): one per Home, for every person
/// it serves, since each copy's derivation binds the person's account. The
/// seed is kept wrapped by the Home's content key-encryption key — Key Vault
/// in production — so the file alone opens nothing, and the Hub, which records
/// only the public half, never holds it.
pub struct HomeLinkRecipientKey {
    path: PathBuf,
    wrap: Box<dyn crate::at_rest::KeyWrap>,
}

impl HomeLinkRecipientKey {
    pub fn new(path: impl Into<PathBuf>, wrap: Box<dyn crate::at_rest::KeyWrap>) -> Self {
        Self {
            path: path.into(),
            wrap,
        }
    }

    /// Load or create the Home's key and return its public half, which is
    /// what the Hub records in the Home's tenant.
    pub fn ensure(&self) -> io::Result<LinkRecipientPublicKey> {
        Ok(self.private_key(true)?.public_key())
    }

    /// Open the key to read a copy sealed to this Home.
    pub fn open(&self) -> io::Result<LinkRecipientPrivateKey> {
        self.private_key(false)
    }

    fn private_key(&self, create: bool) -> io::Result<LinkRecipientPrivateKey> {
        let seed = if create && !self.path.exists() {
            self.create()?
        } else {
            self.read()?
        };
        LinkRecipientPrivateKey::from_seed(seed)
            .map_err(|_| io::Error::other("stored Home recipient key is invalid"))
    }

    fn read(&self) -> io::Result<[u8; 32]> {
        let wrapped = std::fs::read(&self.path)?;
        self.wrap
            .unwrap(&wrapped)
            .map_err(|_| io::Error::other("the Home recipient key did not unwrap"))
    }

    fn create(&self) -> io::Result<[u8; 32]> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let seed = loop {
            let mut candidate = [0_u8; 32];
            getrandom::getrandom(&mut candidate)
                .map_err(|error| io::Error::other(error.to_string()))?;
            if SecretKey::from_slice(&candidate).is_ok() {
                break candidate;
            }
        };
        let wrapped = self
            .wrap
            .wrap(&seed)
            .map_err(|_| io::Error::other("could not wrap the Home recipient key"))?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&self.path) {
            Ok(mut file) => {
                file.write_all(&wrapped)?;
                file.sync_all()?;
                Ok(seed)
            }
            // Lost a create race: whoever won holds the key copies are sealed to.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => self.read(),
            Err(error) => Err(error),
        }
    }
}

fn read_seed(path: &std::path::Path) -> io::Result<[u8; 32]> {
    std::fs::read(path)?
        .as_slice()
        .try_into()
        .map_err(|_| io::Error::other("stored link recipient key is truncated"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private(seed: u8) -> LinkRecipientPrivateKey {
        LinkRecipientPrivateKey::from_seed([seed; 32]).unwrap()
    }

    fn recipient(device: &str, key: &LinkRecipientPrivateKey) -> LinkRecipient {
        LinkRecipient::new(device, key.public_key()).unwrap()
    }

    fn context(version: u64) -> LinkContext {
        LinkContext::new("acct-person", "openai", version).unwrap()
    }

    #[test]
    fn each_device_opens_only_its_own_copy() {
        let (mac, phone) = (private(7), private(9));
        let copies = seal_link_copies(
            &context(3),
            b"sk-secret",
            &[
                recipient("device:mac", &mac),
                recipient("device:phone", &phone),
            ],
        )
        .unwrap();
        assert_eq!(
            open_link_copy(&context(3), &mac, &copies[0]).unwrap(),
            b"sk-secret"
        );
        assert_eq!(
            open_link_copy(&context(3), &phone, &copies[1]).unwrap(),
            b"sk-secret"
        );
        assert_eq!(
            open_link_copy(&context(3), &mac, &copies[1]),
            Err(AccountLinkSealError::Decrypt),
            "the phone's copy does not open under the Mac's key"
        );
    }

    #[test]
    fn a_copy_does_not_open_as_another_device_account_provider_or_version() {
        let mac = private(7);
        let copy =
            seal_link_copy(&context(3), b"sk-secret", &recipient("device:mac", &mac)).unwrap();
        let relabelled = SealedLinkCopy {
            device_id: "device:other".into(),
            ..copy.clone()
        };
        assert!(open_link_copy(&context(3), &mac, &relabelled).is_err());
        for other in [
            LinkContext::new("acct-other", "openai", 3).unwrap(),
            LinkContext::new("acct-person", "anthropic", 3).unwrap(),
            context(2),
        ] {
            assert!(open_link_copy(&other, &mac, &copy).is_err(), "{other:?}");
        }
        let mut tampered = copy;
        tampered.ciphertext.replace_range(0..2, "00");
        assert!(open_link_copy(&context(3), &mac, &tampered).is_err());
    }

    #[test]
    fn untrusted_input_is_refused_at_the_boundary() {
        assert!(LinkRecipientPublicKey::parse("not hex").is_err());
        assert!(LinkRecipientPublicKey::parse("04ab").is_err());
        assert!(LinkContext::new("acct", "openai", 0).is_err());
        assert!(LinkContext::new("", "openai", 1).is_err());
        assert!(LinkRecipient::new("bad\ndevice", private(1).public_key()).is_err());
    }

    #[test]
    fn a_device_keeps_one_key_per_account_and_reuses_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = LinkRecipientStore::new(dir.path().join("account-link"));
        assert!(
            store.open("acct-a").is_err(),
            "no key before the account registers"
        );
        let first = store.ensure("acct-a").unwrap();
        assert_eq!(store.ensure("acct-a").unwrap(), first);
        assert_eq!(store.open("acct-a").unwrap().public_key(), first);
        assert_ne!(store.ensure("acct-b").unwrap(), first);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode =
                |path: PathBuf| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(dir.path().join("account-link")), 0o700);
            assert_eq!(mode(store.path("acct-a")), 0o600);
        }
    }

    /// Writes the Rust half of the cross-language vector. Run with
    /// `cargo test -p gaugedesk-app --lib print_account_link_vector -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn print_account_link_vector() {
        let device = private(0x42);
        let copy = seal_with_ephemeral(
            &context(5),
            b"sk-vector-secret",
            &recipient("device:vector", &device),
            [0x24; 32],
        )
        .unwrap();
        println!("{}", serde_json::to_string_pretty(&copy).unwrap());
        println!("{}", device.public_key().as_str());
    }
}
