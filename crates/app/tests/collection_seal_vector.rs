//! Cross-language seal vector (ADR 0109 §7).
//!
//! `collection-emitted-vector.json` was produced by the WhippleScript session
//! host's Durable Object — by driving `emitCollection` under workerd and
//! capturing the artifact it actually deposited, not by calling `sealArtifact`
//! directly. That distinction is the whole point of `COLLECT-15`: the direct
//! call proved the two ECIES constructions agreed, but it never exercised the
//! path a real collection takes — workspace selection, canonical byte assembly,
//! the size bound, and the per-recipient wrap as the DO emits them. A mismatch
//! anywhere along that path seals successfully, deposits successfully, and never
//! decrypts, and nothing surfaces until ingest, after real responses are sealed.
//!
//! Regenerate with `npm run capture:collection-vector` in
//! `whipplescript/crates/whipplescript-host-do/worker`, then copy the file here.

use gaugewright_app::collection_recipient::{
    ingest_sealed_collection, open_sealed_collection, CollectionIngestError, CollectionOpenError,
    SealedCollection,
};

#[derive(serde::Deserialize)]
struct Vector {
    admission_scope: String,
    recipient_private_seed_hex: String,
    recipient_public_key_hex: String,
    expected_plaintext: String,
    sealed: SealedCollection,
}

fn vector() -> Vector {
    let raw = include_str!("collection-emitted-vector.json");
    serde_json::from_str(raw).expect("seal vector parses")
}

fn seed(hex_seed: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_seed).expect("seed is hex");
    bytes.as_slice().try_into().expect("seed is 32 bytes")
}

fn opened() -> Vec<u8> {
    let vector = vector();
    open_sealed_collection(
        &vector.sealed,
        &seed(&vector.recipient_private_seed_hex),
        &vector.admission_scope,
    )
    .expect("sealed collection opens")
}

#[test]
fn the_session_host_seals_what_this_home_opens() {
    let vector = vector();
    assert_eq!(
        String::from_utf8(opened()).expect("artifact is utf-8"),
        vector.expected_plaintext,
    );
}

/// Canonical byte assembly, checked from the far side.
///
/// The Durable Object built these bytes out of an envelope and a selected
/// workspace; if its key order or separators ever drift, the artifact still
/// decrypts but stops parsing into the shape a receiving Home reads.
#[test]
fn the_opened_artifact_carries_the_envelope_and_the_selected_workspace() {
    let artifact: serde_json::Value =
        serde_json::from_slice(&opened()).expect("the artifact is canonical JSON");
    assert_eq!(artifact["envelope"]["schema_ref"], "survey.v1");
    assert_eq!(artifact["envelope"]["revision"], 1);
    assert_eq!(
        artifact["workspace"]["responses.json"],
        "{\"q1\":\"collected\"}",
    );
}

/// Selection is enforced in the session, not here.
///
/// The undeclared file existed in the emitting session's workspace. It is absent
/// from the artifact because the release never declared it exportable — and this
/// is the only place that claim is checked against ciphertext a real emission
/// produced, rather than against the selector function in isolation.
#[test]
fn a_file_the_release_never_declared_is_absent_from_what_was_sealed() {
    let artifact: serde_json::Value =
        serde_json::from_slice(&opened()).expect("the artifact is canonical JSON");
    let workspace = artifact["workspace"]
        .as_object()
        .expect("the artifact carries a workspace");
    assert_eq!(workspace.len(), 1, "only the declared path was selected");
    assert!(!workspace.contains_key("private-notes.md"));
}

/// `byte_len` travels in the clear, so it must describe the sealed plaintext.
///
/// The opener already refuses a length mismatch; this states the property that
/// refusal exists for — an embedder metering or bounding a deposit on the
/// declared length is metering the artifact it will actually receive.
#[test]
fn the_declared_byte_length_describes_the_sealed_artifact() {
    let vector = vector();
    assert_eq!(opened().len() as u64, vector.sealed.byte_len);
}

#[test]
fn the_wrap_addresses_exactly_the_declared_recipient() {
    let vector = vector();
    assert_eq!(
        vector.sealed.wraps[0].recipient_public_key,
        vector.recipient_public_key_hex,
    );
}

#[test]
fn a_wrap_cannot_be_replayed_under_another_admission_scope() {
    let vector = vector();
    let outcome = open_sealed_collection(
        &vector.sealed,
        &seed(&vector.recipient_private_seed_hex),
        "some-other-deployment",
    );
    assert_eq!(outcome, Err(CollectionOpenError::Decrypt));
}

#[test]
fn a_wrap_cannot_be_replayed_at_another_revision() {
    let mut vector = vector();
    vector.sealed.envelope.revision += 1;
    let outcome = open_sealed_collection(
        &vector.sealed,
        &seed(&vector.recipient_private_seed_hex),
        &vector.admission_scope,
    );
    assert_eq!(outcome, Err(CollectionOpenError::Decrypt));
}

#[test]
fn another_recipient_finds_no_wrap_addressed_to_it() {
    let vector = vector();
    let outcome = open_sealed_collection(&vector.sealed, &[7u8; 32], &vector.admission_scope);
    assert_eq!(outcome, Err(CollectionOpenError::NoWrapForRecipient));
}

#[test]
fn ingest_revalidates_the_schema_against_this_home_s_own_release_copy() {
    let vector = vector();
    let ingested = ingest_sealed_collection(
        &vector.sealed,
        &seed(&vector.recipient_private_seed_hex),
        &vector.admission_scope,
        "survey.v1",
    )
    .expect("artifact ingests");
    assert_eq!(ingested.revision, 1);
    assert!(String::from_utf8(ingested.plaintext)
        .expect("utf-8")
        .contains("collected"));
}

#[test]
fn ingest_refuses_an_artifact_whose_schema_the_release_does_not_declare() {
    let vector = vector();
    let outcome = ingest_sealed_collection(
        &vector.sealed,
        &seed(&vector.recipient_private_seed_hex),
        &vector.admission_scope,
        "some.other.schema",
    );
    assert_eq!(outcome, Err(CollectionIngestError::SchemaMismatch));
}
