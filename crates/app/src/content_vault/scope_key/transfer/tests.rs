use super::*;
use crate::at_rest::LoopbackKeyWrap;

fn vault(root: &Path, kek: u8) -> ContentVault {
    ContentVault::new(root, Box::new(LoopbackKeyWrap::new([kek; 32]))).with_ledger(Box::new(
        LocalFileErasureLedger::new(root.join("erased.ledger")),
    ))
}
fn recipient(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32]).unwrap()
}
fn capsule(vault: &ContentVault, recipient: &SigningKey) -> ScopeKeyCapsule {
    vault
        .prepare_scope_transfer("project", &recipient.public_key())
        .unwrap()
        .with_retained::<_, std::io::Error>(|_, capsule| Ok(capsule.clone()))
        .unwrap()
}

#[test]
fn recipient_capsules_rewrap_the_same_key_and_replay_without_replacement() {
    let source = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let sender = vault(source.path(), 7);
    let receiver = vault(target.path(), 8);
    let key = sender.initialize_scope_key("project").unwrap();
    let recipient = recipient(3);
    let capsule = capsule(&sender, &recipient);
    let wire = serde_json::to_string(&capsule).unwrap();
    assert!(!wire.contains("data_key"));
    let capsule: ScopeKeyCapsule = serde_json::from_str(&wire).unwrap();
    let received = receiver
        .receive_scope_key("project", &recipient, &capsule)
        .unwrap();
    let body = b"private binary\0\xffworkflow";
    let ciphertext = key.seal(b"coordinate", body).unwrap();
    assert_eq!(received.open(b"coordinate", &ciphertext).unwrap(), body);
    assert!(received.open(b"other-coordinate", &ciphertext).is_err());
    let wrapped = std::fs::read(receiver.key_path("project")).unwrap();
    assert_ne!(wrapped, std::fs::read(sender.key_path("project")).unwrap());
    let fresh = vault(target.path(), 8);
    let again = fresh
        .receive_scope_key("project", &recipient, &capsule)
        .unwrap();
    assert_eq!(std::fs::read(fresh.key_path("project")).unwrap(), wrapped);
    assert_eq!(again.open(b"coordinate", &ciphertext).unwrap(), body);
    assert!(sender.prepare_scope_key("project").is_ok());
}

#[test]
fn capsule_scope_recipient_protocol_and_ciphertext_must_all_match() {
    let source = tempfile::tempdir().unwrap();
    let sender = vault(source.path(), 7);
    sender.initialize_scope_key("project").unwrap();
    let recipient = recipient(3);
    let original = capsule(&sender, &recipient);
    let target = tempfile::tempdir().unwrap();
    let receiver = vault(target.path(), 8);
    assert!(receiver
        .receive_scope_key("other", &recipient, &original)
        .is_err());
    assert!(receiver
        .receive_scope_key(
            "project",
            &SigningKey::from_seed(&[4; 32]).unwrap(),
            &original
        )
        .is_err());
    for field in ["protocol", "scope", "recipient", "ciphertext"] {
        let mut changed = original.clone();
        match field {
            "protocol" => changed.protocol = "other".into(),
            "scope" => changed.scope = "other".into(),
            "recipient" => changed.recipient = PublicKey::new("other"),
            _ => changed.sealed.ciphertext.push_str("00"),
        }
        assert!(receiver
            .receive_scope_key("project", &recipient, &changed)
            .is_err());
        assert!(!receiver.key_path("project").exists());
    }
    // Cleartext outer fields cannot relabel an authenticated inner scope.
    let mut relabeled = original.clone();
    relabeled.scope = "other".into();
    assert!(receiver
        .receive_scope_key("other", &recipient, &relabeled)
        .is_err());
    assert!(!receiver.key_path("other").exists());
    assert!(sender
        .prepare_scope_transfer("project", &PublicKey::new("invalid-point"))
        .is_err());
    assert!(sender
        .prepare_scope_transfer("missing", &recipient.public_key())
        .is_err());
    assert!(!sender.key_path("missing").exists());
}

#[test]
fn conflicting_erased_and_unconfirmed_receivers_never_replace_custody() {
    let source = tempfile::tempdir().unwrap();
    let sender = vault(source.path(), 7);
    sender.initialize_scope_key("project").unwrap();
    let recipient = recipient(3);
    let capsule = capsule(&sender, &recipient);
    let target = tempfile::tempdir().unwrap();
    let receiver = vault(target.path(), 8);
    receiver.initialize_scope_key("project").unwrap();
    let original = std::fs::read(receiver.key_path("project")).unwrap();
    assert_eq!(
        receiver
            .receive_scope_key("project", &recipient, &capsule)
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        std::fs::read(receiver.key_path("project")).unwrap(),
        original
    );
    receiver.erase_scope_key("project").unwrap();
    assert!(receiver
        .receive_scope_key("project", &recipient, &capsule)
        .is_err());
    assert!(!receiver.key_path("project").exists());
    let unavailable = tempfile::tempdir().unwrap();
    let receiver = ContentVault::new(
        unavailable.path().join("content-keys"),
        Box::new(LoopbackKeyWrap::new([8; 32])),
    )
    .with_ledger(erasure_ledger_from_config(
        unavailable.path(),
        Some("https://example.invalid".into()),
        None,
        true,
    ));
    assert!(receiver
        .receive_scope_key("project", &recipient, &capsule)
        .is_err());
    assert!(!receiver.key_path("project").exists());
    assert!(sender.prepare_scope_key("project").is_ok());
}

#[test]
fn transfer_publication_retains_source_custody_and_refuses_stale_preparation() {
    let source = tempfile::tempdir().unwrap();
    let sender = vault(source.path(), 7);
    sender.initialize_scope_key("project").unwrap();
    let recipient = recipient(3);
    let transfer = sender
        .prepare_scope_transfer("project", &recipient.public_key())
        .unwrap();
    let error = transfer
        .with_retained::<(), std::io::Error>(|key, _| {
            assert_eq!(
                sender.erase_scope_key("project").unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            let ciphertext = key.seal(b"aad", b"snapshot")?;
            assert_eq!(key.open(b"aad", &ciphertext)?, b"snapshot");
            Err(std::io::Error::other("fixture offer rollback"))
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "fixture offer rollback");
    assert!(sender.prepare_scope_key("project").is_ok());
    sender.erase_scope_key("project").unwrap();
    let called = std::cell::Cell::new(false);
    assert!(transfer
        .with_retained::<(), std::io::Error>(|_, _| {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
}
