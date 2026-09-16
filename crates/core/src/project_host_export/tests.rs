use super::*;
use crate::signature::SigningKey;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32]).unwrap()
}

const CIPHERTEXT: &[u8] = b"sealed-home-cut-bytes";

fn manifest(holder: &SigningKey) -> ExportManifest {
    ExportManifest {
        version: EXPORT_MANIFEST_VERSION,
        operation_id: "op-export-1".into(),
        home_id: "home:studio".into(),
        tenant_id: "tenant:acme".into(),
        cut_basis: "revision-4211".into(),
        holder: RecoveryHolder {
            holder_id: "device:studio-mac".into(),
            recipient_pubkey: holder.public_key().as_str().to_owned(),
        },
        entries: vec![
            ManifestEntry {
                kind: "project".into(),
                id: "project:alpha".into(),
                sha256: sha256_hex(b"alpha"),
                bytes: 5,
            },
            ManifestEntry {
                kind: "store".into(),
                id: "store:library".into(),
                sha256: sha256_hex(b"library"),
                bytes: 7,
            },
        ],
        ciphertext_sha256: sha256_hex(CIPHERTEXT),
        created_at: 1_000,
    }
}

fn target() -> RestoreTarget {
    RestoreTarget {
        holder_id: "device:studio-mac".into(),
        tenant_id: "tenant:acme".into(),
        home_is_live: false,
    }
}

#[test]
fn a_signed_manifest_describes_its_artifact_and_every_piece_of_the_cut() {
    let source = key(1);
    let holder = key(2);
    let signed = sign_manifest(&source, manifest(&holder)).unwrap();

    assert_eq!(verify_artifact(&signed, CIPHERTEXT), Ok(()));
    assert_eq!(verify_restore_admission(&signed, &target()), Ok(()));
    assert_eq!(verify_entry(&signed, "project:alpha", b"alpha"), Ok(()));
    assert_eq!(verify_entry(&signed, "store:library", b"library"), Ok(()));

    // A manifest carries no secret. That is what lets managed storage, relays
    // and the web Desk handle it, so it is worth asserting rather than assuming:
    // nothing in the rendered manifest matches the holder's private scalar or
    // the source's.
    let rendered = format!("{signed:?}");
    for private in [key(2).to_seed_bytes(), key(1).to_seed_bytes()] {
        assert!(
            !rendered.contains(&hex::encode(private)),
            "manifest leaked a private key"
        );
    }
    assert!(rendered.contains(&signed.manifest.holder.recipient_pubkey));
}

#[test]
fn a_modified_artifact_is_refused_before_anything_is_decrypted() {
    let source = key(1);
    let holder = key(2);
    let signed = sign_manifest(&source, manifest(&holder)).unwrap();

    assert_eq!(
        verify_artifact(&signed, b"sealed-home-cut-byteS"),
        Err(ExportError::ContentDigest)
    );

    // Editing the manifest to match a substituted artifact breaks the source
    // signature, so the two cannot be made to agree without the Home's key.
    let mut tampered = signed.clone();
    tampered.manifest.ciphertext_sha256 = sha256_hex(b"other");
    assert_eq!(
        verify_artifact(&tampered, b"other"),
        Err(ExportError::Signature)
    );

    // Dropping an entry from a signed manifest breaks it too: the count is
    // signed alongside the entries.
    let mut trimmed = signed.clone();
    trimmed.manifest.entries.pop();
    assert_eq!(
        verify_artifact(&trimmed, CIPHERTEXT),
        Err(ExportError::Signature)
    );

    // A whole cut that arrives intact can still contain a piece that does not
    // match what the manifest named.
    assert_eq!(
        verify_entry(&signed, "project:alpha", b"alphb"),
        Err(ExportError::ContentDigest)
    );
}

#[test]
fn restore_fails_closed_on_wrong_holder_wrong_tenant_and_a_live_home() {
    let source = key(1);
    let holder = key(2);
    let signed = sign_manifest(&source, manifest(&holder)).unwrap();

    for (mutate, expected) in [
        (
            (|target: &mut RestoreTarget| target.holder_id = "device:other".into())
                as fn(&mut RestoreTarget),
            ExportError::WrongHolder,
        ),
        (
            |target: &mut RestoreTarget| target.tenant_id = "tenant:other".into(),
            ExportError::WrongTenant,
        ),
        (
            |target: &mut RestoreTarget| target.home_is_live = true,
            ExportError::ConflictingLiveHome,
        ),
    ] {
        let mut candidate = target();
        mutate(&mut candidate);
        assert_eq!(verify_restore_admission(&signed, &candidate), Err(expected));
    }
}

#[test]
fn holding_the_artifact_is_not_authority_to_restore_it() {
    let source = key(1);
    let holder = key(2);
    let signed = sign_manifest(&source, manifest(&holder)).unwrap();

    // Someone who fetched the bytes through a bounded download handle has a
    // verifiable artifact and no admission: the handle carries bytes, not the
    // right to open or import them.
    assert_eq!(verify_artifact(&signed, CIPHERTEXT), Ok(()));
    let bearer = RestoreTarget {
        holder_id: "device:someone-else".into(),
        tenant_id: "tenant:acme".into(),
        home_is_live: false,
    };
    assert_eq!(
        verify_restore_admission(&signed, &bearer),
        Err(ExportError::WrongHolder)
    );
}

#[test]
fn an_unsupported_version_or_an_empty_cut_is_refused() {
    let source = key(1);
    let holder = key(2);

    let mut future = manifest(&holder);
    future.version = EXPORT_MANIFEST_VERSION + 1;
    assert_eq!(
        sign_manifest(&source, future).unwrap_err(),
        ExportError::UnsupportedVersion
    );

    // A cut that contains nothing is not a recovery point, and signing one
    // would produce an artifact a restore could "succeed" against.
    let mut empty = manifest(&holder);
    empty.entries.clear();
    assert_eq!(
        sign_manifest(&source, empty).unwrap_err(),
        ExportError::Malformed
    );
}
