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
