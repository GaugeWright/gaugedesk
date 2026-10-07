//! An account's own keys on this computer ([DR-0361](../../../specs/decisions/0361-account-and-project-key-custody.md) §1,
//! [DR-0359](../../../specs/decisions/0359-every-account-reaches-its-computers-under-its-own-keys.md) §1).
//!
//! Each account signed in on a computer holds three keys here, apart from every
//! other account's and from the install's own governance key:
//!
//! - its **root**, the identity its directory entries are signed under. One
//!   root serves the account on every computer it uses; the first computer
//!   mints it and every later one receives it through enrollment.
//! - its **account key**, which seals the account's own state. Like the root,
//!   it is the same on every computer.
//! - this computer's **device key**, with the root's delegation to it. That
//!   one is this computer's alone.
//!
//! The files sit under `<root>/keys/accounts/<hex(account)>/` (or
//! `sha256-<digest>/` when the hex name would pass the file-name limit), each written
//! once with owner-only permissions, as the install's own key store keeps its
//! keys. A computer holding the root can always delegate to its own device key
//! again, so a lapsed delegation is renewed here rather than by enrolling.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use gaugedesk_core::delegation::DeviceDelegation;
use gaugedesk_core::signature::SigningKey;

const ROOT_FILE: &str = "root.seed";
const ACCOUNT_KEY_FILE: &str = "account.key";
const DEVICE_FILE: &str = "device.seed";
const DELEGATION_FILE: &str = "delegation.json";

/// How long a delegation from the root to this computer's device key lasts
/// before it is issued again: the term enrollment gives one.
pub const DEVICE_DELEGATION_TTL_SECS: u64 = 400 * 24 * 60 * 60;

/// One account's keys on this computer.
pub struct AccountKeys {
    pub root: SigningKey,
    pub account_key: [u8; 32],
    pub device: SigningKey,
    pub delegation: DeviceDelegation,
}

/// Where this computer keeps each account's keys.
pub struct AccountKeyStore {
    dir: PathBuf,
}

impl AccountKeyStore {
    /// `keys_dir` is the workbench's `<root>/keys`.
    pub fn new(keys_dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: keys_dir.into().join("accounts"),
        }
    }

    fn account_dir(&self, account: &str) -> PathBuf {
        self.dir
            .join(crate::key_store::fitted_file_name(account.as_bytes(), ""))
    }

    /// The account's keys, if this computer holds them. A delegation that has
    /// lapsed by `now` is issued again under the root and kept.
    pub fn held(&self, account: &str, now: u64) -> io::Result<Option<AccountKeys>> {
        let dir = self.account_dir(account);
        if !dir.join(ROOT_FILE).exists() {
            return Ok(None);
        }
        let root = read_signing_key(&dir.join(ROOT_FILE))?;
        let account_key = read_secret(&dir.join(ACCOUNT_KEY_FILE))?;
        let device = read_signing_key(&dir.join(DEVICE_FILE))?;
        let recorded: Option<DeviceDelegation> = std::fs::read(dir.join(DELEGATION_FILE))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        let delegation = match recorded.filter(|delegation| {
            delegation.verify(now).is_ok()
                && delegation.authority_root == root.public_key()
                && delegation.subkey == device.public_key()
        }) {
            Some(delegation) => delegation,
            None => {
                let renewed = DeviceDelegation::issue(
                    &root,
                    device.public_key(),
                    now + DEVICE_DELEGATION_TTL_SECS,
                );
                replace_file(&dir.join(DELEGATION_FILE), &serde_json::to_vec(&renewed)?)?;
                renewed
            }
        };
        Ok(Some(AccountKeys {
            root,
            account_key,
            device,
            delegation,
        }))
    }

    /// Mint fresh keys for an account no computer holds keys for yet: a new
    /// root, account key and device key, the root delegating to the device.
    /// Refuses when this computer already holds the account's keys.
    pub fn mint(&self, account: &str, now: u64) -> io::Result<AccountKeys> {
        let root = random_signing_key()?;
        let mut account_key = [0_u8; 32];
        getrandom::getrandom(&mut account_key)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let device = random_signing_key()?;
        let delegation =
            DeviceDelegation::issue(&root, device.public_key(), now + DEVICE_DELEGATION_TTL_SECS);
        let keys = AccountKeys {
            root,
            account_key,
            device,
            delegation,
        };
        self.write(account, &keys)?;
        Ok(keys)
    }

    /// Keep keys this computer received through enrollment. Refuses when it
    /// already holds the account's keys, so a later enrollment never replaces
    /// a root in place; a root changes only by a signed hand-over.
    pub fn adopt(&self, account: &str, keys: &AccountKeys) -> io::Result<()> {
        self.write(account, keys)
    }

    fn write(&self, account: &str, keys: &AccountKeys) -> io::Result<()> {
        let dir = self.account_dir(account);
        if dir.join(ROOT_FILE).exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "this computer already holds keys for the account",
            ));
        }
        create_private_dir(&self.dir)?;
        create_private_dir(&dir)?;
        // The root goes last: its presence is what marks the keys as held, so
        // an interrupted write leaves none.
        replace_file(&dir.join(ACCOUNT_KEY_FILE), &keys.account_key)?;
        replace_file(&dir.join(DEVICE_FILE), &keys.device.to_seed_bytes())?;
        replace_file(
            &dir.join(DELEGATION_FILE),
            &serde_json::to_vec(&keys.delegation)?,
        )?;
        replace_file(&dir.join(ROOT_FILE), &keys.root.to_seed_bytes())
    }
}

fn random_signing_key() -> io::Result<SigningKey> {
    loop {
        let mut seed = [0_u8; 32];
        getrandom::getrandom(&mut seed).map_err(|error| io::Error::other(error.to_string()))?;
        if let Ok(key) = SigningKey::from_seed(&seed) {
            return Ok(key);
        }
    }
}

fn read_secret(path: &Path) -> io::Result<[u8; 32]> {
    <[u8; 32]>::try_from(std::fs::read(path)?.as_slice())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "key file has invalid length"))
}

fn read_signing_key(path: &Path) -> io::Result<SigningKey> {
    SigningKey::from_seed(&read_secret(path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.reason))
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write `bytes` to `path` owner-only, through a temporary file renamed into
/// place, so a reader never sees half a key.
fn replace_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let staged = path.with_extension("staged");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&staged)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&staged, path)
}

#[cfg(test)]
#[path = "account_keys_tests.rs"]
mod tests;
