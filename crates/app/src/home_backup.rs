//! The Home-side B17 sealed backup cut format (ADR 0102).
//!
//! A caller supplies only the public recipients active for a tenant. This module
//! reads a closed Home root, creates one self-contained cut, encrypts it locally
//! under a fresh [`BackupDataKey`](crate::backup_keyring::BackupDataKey), and
//! returns only ciphertext plus public-recipient wraps. The key stays opaque: a
//! restore caller must present a locally held recipient private key to open a
//! wrap before it can reconstruct into an empty receiving-Home staging root.
//!
//! The archive is intentionally a small, fully validated internal format rather
//! than a generic archive extractor: it admits only regular files and directories
//! under relative paths, refuses links/special files, and rejects traversal or a
//! non-empty restore destination.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::backup_keyring::{
    decrypt_point, encrypt_point, unwrap_data_key, wrap_data_key, BackupCiphertext,
    BackupKeyContext, BackupKeyWrap, BackupRecipient, BackupRecipientPrivateKey,
};

const MAGIC: &[u8] = b"GW-B17-CUT-1\0";
const ENTRY_END: u8 = 0;
const ENTRY_DIRECTORY: u8 = 1;
const ENTRY_FILE: u8 = 2;

/// The only B17 point artifacts a Home may send to the Hub. The key is not part
/// of this type; it exists only within the local seal/unwrap operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedHomeBackupCut {
    pub ciphertext: BackupCiphertext,
    pub wraps: Vec<BackupKeyWrap>,
}

/// Fail-closed backup/restore result. Detailed filesystem paths and cryptographic
/// distinctions are intentionally not carried over a service boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HomeBackupError {
    NoRecipients,
    DuplicateRecipient,
    Source,
    Destination,
    Archive,
    Seal,
    Open,
}

/// Produce a sealed self-contained cut from a closed Home root. The result is
/// upload-safe: it has no plaintext archive or data key.
pub fn seal_home_root(
    root: &Path,
    context: &BackupKeyContext,
    recipients: &[BackupRecipient],
) -> Result<SealedHomeBackupCut, HomeBackupError> {
    if recipients.is_empty() {
        return Err(HomeBackupError::NoRecipients);
    }
    let mut ids = BTreeSet::new();
    if recipients
        .iter()
        .any(|recipient| !ids.insert(&recipient.id))
    {
        return Err(HomeBackupError::DuplicateRecipient);
    }
    let archive = encode_root(root)?;
    let key =
        crate::backup_keyring::BackupDataKey::generate().map_err(|_| HomeBackupError::Seal)?;
    let ciphertext = encrypt_point(&key, &archive).map_err(|_| HomeBackupError::Seal)?;
    let wraps = recipients
        .iter()
        .map(|recipient| wrap_data_key(context, &key, recipient).map_err(|_| HomeBackupError::Seal))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SealedHomeBackupCut { ciphertext, wraps })
}

/// Reconstruct a sealed cut into an empty receiving-Home staging directory. The
/// Hub cannot invoke this successfully: it must obtain the required private
/// recipient key from the receiving Home and provide the exact tenant/receiver
/// context that was bound into the wrap.
pub fn restore_home_root(
    destination: &Path,
    context: &BackupKeyContext,
    private_recipient: &BackupRecipientPrivateKey,
    receiver_wrap: &BackupKeyWrap,
    ciphertext: &BackupCiphertext,
) -> Result<(), HomeBackupError> {
    prepare_empty_destination(destination)?;
    let key = unwrap_data_key(context, private_recipient, receiver_wrap)
        .map_err(|_| HomeBackupError::Open)?;
    let archive = decrypt_point(&key, ciphertext).map_err(|_| HomeBackupError::Open)?;
    decode_into(&archive, destination)
}

fn encode_root(root: &Path) -> Result<Vec<u8>, HomeBackupError> {
    if !root.is_dir() {
        return Err(HomeBackupError::Source);
    }
    let mut archive = MAGIC.to_vec();
    encode_directory(root, root, &mut archive)?;
    archive.push(ENTRY_END);
    Ok(archive)
}

fn encode_directory(
    root: &Path,
    directory: &Path,
    archive: &mut Vec<u8>,
) -> Result<(), HomeBackupError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|_| HomeBackupError::Source)?
        .collect::<Result<Vec<_>, io::Error>>()
        .map_err(|_| HomeBackupError::Source)?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| HomeBackupError::Source)?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| HomeBackupError::Source)?;
        let encoded_path = relative_path_bytes(relative)?;
        if metadata.file_type().is_dir() {
            archive.push(ENTRY_DIRECTORY);
            push_path(archive, &encoded_path)?;
            encode_directory(root, &path, archive)?;
        } else if metadata.file_type().is_file() {
            archive.push(ENTRY_FILE);
            push_path(archive, &encoded_path)?;
            let bytes = fs::read(&path).map_err(|_| HomeBackupError::Source)?;
            let length = u64::try_from(bytes.len()).map_err(|_| HomeBackupError::Archive)?;
            archive.extend_from_slice(&length.to_be_bytes());
            archive.extend_from_slice(&bytes);
        } else {
            // A symlink or special file can escape/reinterpret a Home root on
            // restore, so the cut refuses it rather than guessing its meaning.
            return Err(HomeBackupError::Source);
        }
    }
    Ok(())
}

fn relative_path_bytes(path: &Path) -> Result<Vec<u8>, HomeBackupError> {
    if path.as_os_str().is_empty()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(HomeBackupError::Archive);
    }
    let text = path.to_str().ok_or(HomeBackupError::Archive)?;
    if text.len() > 16 * 1024 || text.chars().any(char::is_control) {
        return Err(HomeBackupError::Archive);
    }
    Ok(text.as_bytes().to_vec())
}

fn push_path(archive: &mut Vec<u8>, path: &[u8]) -> Result<(), HomeBackupError> {
    let length = u32::try_from(path.len()).map_err(|_| HomeBackupError::Archive)?;
    archive.extend_from_slice(&length.to_be_bytes());
    archive.extend_from_slice(path);
    Ok(())
}

fn prepare_empty_destination(destination: &Path) -> Result<(), HomeBackupError> {
    if destination.exists() {
        let mut entries = fs::read_dir(destination).map_err(|_| HomeBackupError::Destination)?;
        if entries.next().is_some() {
            return Err(HomeBackupError::Destination);
        }
    } else {
        fs::create_dir_all(destination).map_err(|_| HomeBackupError::Destination)?;
    }
    Ok(())
}

fn decode_into(archive: &[u8], destination: &Path) -> Result<(), HomeBackupError> {
    if !archive.starts_with(MAGIC) {
        return Err(HomeBackupError::Archive);
    }
    let mut cursor = MAGIC.len();
    let mut seen = BTreeSet::new();
    loop {
        let tag = *archive.get(cursor).ok_or(HomeBackupError::Archive)?;
        cursor += 1;
        if tag == ENTRY_END {
            return (cursor == archive.len())
                .then_some(())
                .ok_or(HomeBackupError::Archive);
        }
        let path = read_path(archive, &mut cursor)?;
        if !seen.insert(path.clone()) {
            return Err(HomeBackupError::Archive);
        }
        let output = destination.join(&path);
        match tag {
            ENTRY_DIRECTORY => {
                fs::create_dir_all(output).map_err(|_| HomeBackupError::Destination)?
            }
            ENTRY_FILE => {
                let length = read_u64(archive, &mut cursor)?;
                let length = usize::try_from(length).map_err(|_| HomeBackupError::Archive)?;
                let bytes = archive
                    .get(cursor..cursor.checked_add(length).ok_or(HomeBackupError::Archive)?)
                    .ok_or(HomeBackupError::Archive)?;
                cursor += length;
                let parent = output.parent().ok_or(HomeBackupError::Archive)?;
                fs::create_dir_all(parent).map_err(|_| HomeBackupError::Destination)?;
                let mut file =
                    fs::File::create(output).map_err(|_| HomeBackupError::Destination)?;
                file.write_all(bytes)
                    .map_err(|_| HomeBackupError::Destination)?;
            }
            _ => return Err(HomeBackupError::Archive),
        }
    }
}

fn read_path(archive: &[u8], cursor: &mut usize) -> Result<PathBuf, HomeBackupError> {
    let length = read_u32(archive, cursor)?;
    let length = usize::try_from(length).map_err(|_| HomeBackupError::Archive)?;
    let bytes = archive
        .get(*cursor..cursor.checked_add(length).ok_or(HomeBackupError::Archive)?)
        .ok_or(HomeBackupError::Archive)?;
    *cursor += length;
    let text = std::str::from_utf8(bytes).map_err(|_| HomeBackupError::Archive)?;
    let path = Path::new(text);
    relative_path_bytes(path)?;
    Ok(path.to_path_buf())
}

fn read_u32(archive: &[u8], cursor: &mut usize) -> Result<u32, HomeBackupError> {
    let bytes: [u8; 4] = archive
        .get(*cursor..cursor.checked_add(4).ok_or(HomeBackupError::Archive)?)
        .ok_or(HomeBackupError::Archive)?
        .try_into()
        .map_err(|_| HomeBackupError::Archive)?;
    *cursor += 4;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(archive: &[u8], cursor: &mut usize) -> Result<u64, HomeBackupError> {
    let bytes: [u8; 8] = archive
        .get(*cursor..cursor.checked_add(8).ok_or(HomeBackupError::Archive)?)
        .ok_or(HomeBackupError::Archive)?
        .try_into()
        .map_err(|_| HomeBackupError::Archive)?;
    *cursor += 8;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup_keyring::{BackupRecipientPrivateKey, BackupRecipientPublicKey};

    fn private(seed: u8) -> BackupRecipientPrivateKey {
        BackupRecipientPrivateKey::from_seed([seed; 32]).unwrap()
    }

    fn recipient(id: &str, private: &BackupRecipientPrivateKey) -> BackupRecipient {
        BackupRecipient::new(id, private.public_key()).unwrap()
    }

    fn point_context() -> BackupKeyContext {
        BackupKeyContext::new("tenant:acme", "point:cut-42").unwrap()
    }

    #[test]
    fn home_seals_a_nested_cut_and_only_a_recipient_can_restore_it() {
        let source = tempfile::tempdir().unwrap();
        fs::create_dir_all(source.path().join("nested")).unwrap();
        fs::write(source.path().join("root.txt"), b"home secret").unwrap();
        fs::write(source.path().join("nested/child.bin"), [0, 1, 2, 3]).unwrap();
        let holder = private(31);
        let cut = seal_home_root(
            source.path(),
            &point_context(),
            &[recipient("recovery-holder", &holder)],
        )
        .unwrap();

        let rendered = serde_json::to_string(&cut).unwrap();
        assert!(!rendered.contains("home secret"));
        assert_eq!(cut.wraps.len(), 1);

        let restored = tempfile::tempdir().unwrap();
        restore_home_root(
            restored.path(),
            &point_context(),
            &holder,
            &cut.wraps[0],
            &cut.ciphertext,
        )
        .unwrap();
        assert_eq!(
            fs::read(restored.path().join("root.txt")).unwrap(),
            b"home secret"
        );
        assert_eq!(
            fs::read(restored.path().join("nested/child.bin")).unwrap(),
            [0, 1, 2, 3]
        );
    }

    #[test]
    fn wrong_recipient_or_context_cannot_restore_a_cut() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("fact"), b"tenant a only").unwrap();
        let holder = private(41);
        let wrong = private(42);
        let cut = seal_home_root(
            source.path(),
            &point_context(),
            &[recipient("holder", &holder)],
        )
        .unwrap();

        let wrong_destination = tempfile::tempdir().unwrap();
        assert_eq!(
            restore_home_root(
                wrong_destination.path(),
                &point_context(),
                &wrong,
                &cut.wraps[0],
                &cut.ciphertext,
            ),
            Err(HomeBackupError::Open)
        );
        let other_tenant = BackupKeyContext::new("tenant:beta", "point:cut-42").unwrap();
        let other_destination = tempfile::tempdir().unwrap();
        assert_eq!(
            restore_home_root(
                other_destination.path(),
                &other_tenant,
                &holder,
                &cut.wraps[0],
                &cut.ciphertext,
            ),
            Err(HomeBackupError::Open)
        );
    }

    #[test]
    fn cuts_refuse_duplicate_recipients_and_nonempty_restore_destinations() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("fact"), b"sealed").unwrap();
        let holder = private(51);
        let same = recipient("holder", &holder);
        assert_eq!(
            seal_home_root(source.path(), &point_context(), &[same.clone(), same]),
            Err(HomeBackupError::DuplicateRecipient)
        );

        let cut = seal_home_root(
            source.path(),
            &point_context(),
            &[recipient("holder", &holder)],
        )
        .unwrap();
        let destination = tempfile::tempdir().unwrap();
        fs::write(destination.path().join("already-here"), b"preserve").unwrap();
        assert_eq!(
            restore_home_root(
                destination.path(),
                &point_context(),
                &holder,
                &cut.wraps[0],
                &cut.ciphertext,
            ),
            Err(HomeBackupError::Destination)
        );
    }

    #[test]
    fn malformed_public_key_cannot_be_smuggled_as_a_recipient() {
        assert!(BackupRecipientPublicKey::parse("not-a-key").is_err());
    }
}
