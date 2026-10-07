use super::*;

const NOW: u64 = 1_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32]).unwrap()
}

/// A root, a device subkey it delegates to, and that root's public key.
fn device() -> (SigningKey, DeviceDelegation, String) {
    let root = key(1);
    let subkey = key(2);
    let delegation = DeviceDelegation::issue(&root, subkey.public_key(), NOW + 100);
    (subkey, delegation, root.public_key().as_str().to_owned())
}

#[test]
fn an_enrolled_devices_proof_publishes_its_root_once_per_challenge() {
    let (subkey, delegation, root) = device();
    let challenge = issue_challenge("acct").unwrap();
    let proof = prove(&challenge, &root, &subkey, &delegation);
    assert_eq!(
        verify(&proof, "acct", &root, "", true, NOW),
        Ok(subkey.public_key()),
        "a device carrying no subkey takes this one on its first write"
    );
    assert_eq!(
        verify(&proof, "acct", &root, "", true, NOW),
        Err(Refusal::Challenge),
        "a challenge answers once"
    );

    let challenge = issue_challenge("acct").unwrap();
    let proof = prove(&challenge, &root, &subkey, &delegation);
    assert_eq!(
        verify(
            &proof,
            "acct",
            &root,
            subkey.public_key().as_str(),
            true,
            NOW
        ),
        Ok(subkey.public_key())
    );
}

#[test]
fn a_bearer_alone_cannot_publish_a_root_of_its_own() {
    let (subkey, delegation, root) = device();

    // Another account's challenge.
    let challenge = issue_challenge("acct-other").unwrap();
    let proof = prove(&challenge, &root, &subkey, &delegation);
    assert_eq!(
        verify(&proof, "acct", &root, "", true, NOW),
        Err(Refusal::Challenge)
    );

    // A signature over a different root.
    let challenge = issue_challenge("acct").unwrap();
    let mut proof = prove(&challenge, &root, &subkey, &delegation);
    proof.signature = subkey.sign(&publication_signing_bytes(&challenge, "another-root"));
    assert_eq!(
        verify(&proof, "acct", &root, "", true, NOW),
        Err(Refusal::Signature)
    );

    // A root that delegates to some other subkey, or a lapsed delegation.
    let challenge = issue_challenge("acct").unwrap();
    let elsewhere = DeviceDelegation::issue(&key(1), key(3).public_key(), NOW + 100);
    let proof = prove(&challenge, &root, &subkey, &elsewhere);
    assert_eq!(
        verify(&proof, "acct", &root, "", true, NOW),
        Err(Refusal::Delegation)
    );
    let challenge = issue_challenge("acct").unwrap();
    let proof = prove(&challenge, &root, &subkey, &delegation);
    assert_eq!(
        verify(&proof, "acct", &root, "", true, NOW + 100),
        Err(Refusal::Delegation)
    );

    // A subkey the session's device does not carry.
    let challenge = issue_challenge("acct").unwrap();
    let proof = prove(&challenge, &root, &subkey, &delegation);
    assert_eq!(
        verify(
            &proof,
            "acct",
            &root,
            key(9).public_key().as_str(),
            true,
            NOW
        ),
        Err(Refusal::NotThisDevice)
    );

    // A thief's own root, against an account that already projects one.
    let thief_root = key(7);
    let thief_subkey = key(8);
    let thief_delegation =
        DeviceDelegation::issue(&thief_root, thief_subkey.public_key(), NOW + 100);
    let challenge = issue_challenge("acct").unwrap();
    let proof = prove(
        &challenge,
        thief_root.public_key().as_str(),
        &thief_subkey,
        &thief_delegation,
    );
    assert_eq!(
        verify(
            &proof,
            "acct",
            thief_root.public_key().as_str(),
            "",
            false,
            NOW
        ),
        Err(Refusal::ForeignRoot)
    );
}
