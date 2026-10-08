use super::*;

const NOW: u64 = 1_000;

#[test]
fn each_account_holds_its_own_keys_and_a_second_mint_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = AccountKeyStore::new(dir.path());
    assert!(store.held("acct-a", NOW).unwrap().is_none());

    let a = store.mint("acct-a", NOW).unwrap();
    let b = store.mint("acct-b", NOW).unwrap();
    assert_ne!(a.root.public_key(), b.root.public_key());
    assert_ne!(a.account_key, b.account_key);
    assert_ne!(a.root.public_key(), a.device.public_key());
    assert_eq!(a.delegation.authority_root, a.root.public_key());
    assert_eq!(a.delegation.subkey, a.device.public_key());
    assert!(a.delegation.verify(NOW).is_ok());

    let again = AccountKeyStore::new(dir.path())
        .held("acct-a", NOW)
        .unwrap()
        .unwrap();
    assert_eq!(again.root.public_key(), a.root.public_key());
    assert_eq!(again.account_key, a.account_key);
    assert_eq!(again.device.public_key(), a.device.public_key());
    assert_eq!(again.delegation, a.delegation);

    let refused = store.mint("acct-a", NOW).err().expect("a second mint");
    assert_eq!(refused.kind(), io::ErrorKind::AlreadyExists);
    assert!(
        store.adopt("acct-a", &b).is_err(),
        "a held root is never replaced in place"
    );
}

#[test]
fn a_lapsed_delegation_is_issued_again_under_the_root() {
    let dir = tempfile::tempdir().unwrap();
    let store = AccountKeyStore::new(dir.path());
    let minted = store.mint("acct-a", NOW).unwrap();
    let later = minted.delegation.expiry + 1;
    let renewed = store.held("acct-a", later).unwrap().unwrap();
    assert!(renewed.delegation.verify(later).is_ok());
    assert_eq!(renewed.delegation.subkey, minted.device.public_key());
    assert_eq!(
        store.held("acct-a", later).unwrap().unwrap().delegation,
        renewed.delegation,
        "the renewed delegation is kept"
    );
}

#[cfg(unix)]
#[test]
fn the_keys_are_readable_by_their_owner_alone() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    AccountKeyStore::new(dir.path())
        .mint("acct-a", NOW)
        .unwrap();
    let account_dir = dir.path().join("accounts").join(hex::encode("acct-a"));
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&account_dir), 0o700);
    for file in [ROOT_FILE, ACCOUNT_KEY_FILE, DEVICE_FILE, DELEGATION_FILE] {
        assert_eq!(mode(&account_dir.join(file)), 0o600, "{file}");
    }
}

#[test]
fn an_account_id_too_long_for_a_hex_directory_name_mints_and_reloads() {
    let dir = tempfile::tempdir().unwrap();
    let store = AccountKeyStore::new(dir.path());
    // ~130 characters, like an account named by its public key: hex of it is
    // past the 255-byte file-name limit.
    let account = format!("acct-{}", "k".repeat(125));
    let minted = store.mint(&account, NOW).unwrap();
    let held = AccountKeyStore::new(dir.path())
        .held(&account, NOW)
        .unwrap()
        .expect("the minted keys are held");
    assert_eq!(held.root.public_key(), minted.root.public_key());
    assert_eq!(held.account_key, minted.account_key);
    assert_eq!(held.device.public_key(), minted.device.public_key());
    let name = store.account_dir(&account);
    let name = name.file_name().unwrap().to_str().unwrap();
    assert!(name.starts_with("sha256-"), "{name}");
    // A short id keeps its hex directory, so keys already held still open.
    assert_eq!(
        store.account_dir("acct-a").file_name().unwrap(),
        hex::encode("acct-a").as_str()
    );
}

#[test]
fn the_recovery_code_restores_the_root_and_the_account_key() {
    let first = tempfile::tempdir().unwrap();
    let minted = AccountKeyStore::new(first.path())
        .mint("acct-a", NOW)
        .unwrap();
    assert_eq!(minted.account_key, account_key_from_root(&minted.root));
    let code = AccountKeyStore::new(first.path())
        .recovery_code("acct-a", NOW)
        .unwrap()
        .expect("a computer holding the keys shows the code");

    let second = tempfile::tempdir().unwrap();
    let store = AccountKeyStore::new(second.path());
    assert_eq!(store.recovery_code("acct-a", NOW).unwrap(), None);
    let root = gaugedesk_core::recovery::import_recovery(&code).unwrap();
    let restored = store.restore("acct-a", root, NOW).unwrap();
    assert_eq!(restored.root.public_key(), minted.root.public_key());
    assert_eq!(restored.account_key, minted.account_key);
    assert_ne!(
        restored.device.public_key(),
        minted.device.public_key(),
        "the restored computer has a device key of its own"
    );
    assert!(restored.delegation.verify(NOW).is_ok());
    let again = gaugedesk_core::recovery::import_recovery(&code).unwrap();
    assert!(
        store.restore("acct-a", again, NOW).is_err(),
        "never over held keys"
    );
}
