//! Project Host recovery export: the manifest, and what a restore must check
//! before it will import anything (ADR 0171).
//!
//! An export is one crash-consistent, self-contained cut of one exact Home,
//! encrypted under a fresh data key that is wrapped **only** to a selected
//! native recovery holder. This module owns the manifest that describes the cut
//! and the checks a restore performs. It deliberately owns neither the bytes nor
//! the key: sealing and unsealing happen where the holder's non-extractable key
//! lives, and a manifest is secret-free by construction so that managed storage,
//! relays and the web Desk can carry it.
//!
//! The distinction the whole design turns on is that a **download handle is
//! transport authority and never decryption authority**. Holding the artifact
//! proves nothing; only the selected holder can open it. So the checks here are
//! about whether this artifact is the one it claims to be, and whether this
//! target is allowed to receive it — never about whether the caller possesses
//! the bytes.

use crate::ids::PublicKey;
use crate::signature::{verify_signature, Signature, SigningKey};
use sha2::{Digest, Sha256};

pub const EXPORT_MANIFEST_VERSION: u8 = 1;
pub const EXPORT_MANIFEST_DOMAIN: &str = "gaugedesk-project-host-export.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportError {
    /// The manifest does not speak this contract version.
    UnsupportedVersion,
    /// A required field is empty, or the cut describes nothing.
    Malformed,
    /// The source Home's signature over the manifest does not verify.
    Signature,
    /// The artifact's bytes do not match the digest the manifest binds.
    ContentDigest,
    /// This artifact was sealed to a different recovery holder.
    WrongHolder,
    /// The cut belongs to a different tenant than the restore target.
    WrongTenant,
    /// The restore target already carries a live Home for this cut.
    ConflictingLiveHome,
}

/// One thing the cut contains. `bytes` and `digest` are what a restore checks
/// before importing; nothing here names a person, a grant, or a payload.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManifestEntry {
    pub kind: String,
    pub id: String,
    pub sha256: String,
    pub bytes: u64,
}

/// Which Home signed this manifest, and therefore what its signature means.
///
/// A self-managed Home signs with a governance root it generated and holds, so
/// its signature attests that the Home the tenant runs produced this cut. A
/// managed Home signs with a key the operator generated and holds on the
/// tenant's behalf, so its signature attests that the operator produced the cut
/// — not that the tenant asked for one. That is a weaker claim, and it is
/// recorded rather than smoothed over so a restore can say which it is looking
/// at (GaugeWright DR-0122).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerKind {
    /// The tenant runs this Home and holds its governance root.
    SelfManaged,
    /// The operator runs this Home and holds the key that signed.
    OperatorManaged,
}

impl SignerKind {
    /// Stable token for the signing preimage. Written out rather than derived
    /// from the enum's name so renaming a variant cannot silently change what
    /// every previously signed manifest verifies against.
    fn as_str(self) -> &'static str {
        match self {
            Self::SelfManaged => "self-managed",
            Self::OperatorManaged => "operator-managed",
        }
    }
}

/// The selected recovery holder, by stable identity and public recipient key.
/// The private half never leaves the device's operating-system key store, and
/// never appears in this type, a receipt, a transcript, or operator storage.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecoveryHolder {
    pub holder_id: String,
    pub recipient_pubkey: String,
}

/// The secret-free description of one export. Storage, relays and the web Desk
/// may carry this and the ciphertext, and nothing else.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExportManifest {
    pub version: u8,
    pub operation_id: String,
    pub home_id: String,
    pub tenant_id: String,
    /// The Home state this cut was taken at, so a restore can say what it is
    /// restoring rather than "the latest".
    pub cut_basis: String,
    pub holder: RecoveryHolder,
    /// Signed, not merely carried: a restore that trusted an unsigned signer
    /// kind could be told an operator-produced cut was tenant-produced.
    pub signer_kind: SignerKind,
    pub entries: Vec<ManifestEntry>,
    /// Digest of the sealed artifact as it crosses. A restore checks this
    /// before it decrypts, which is what makes a modified artifact a refusal
    /// rather than a decryption failure.
    pub ciphertext_sha256: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedExportManifest {
    pub manifest: ExportManifest,
    /// The source Home's signature. A manifest is only as good as the Home that
    /// signed it; an unsigned one describes an artifact nobody vouched for.
    pub source_pubkey: String,
    pub source_signature: Signature,
}

/// What the restoring device knows about itself and its target, supplied by the
/// caller rather than read here: this module performs no I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreTarget {
    /// The holder identity this device actually holds a private key for.
    pub holder_id: String,
    /// The tenant the operator explicitly selected to restore into.
    pub tenant_id: String,
    /// Whether a live Home with the manifest's `home_id` already exists here.
    pub home_is_live: bool,
}

fn encode(value: &str) -> String {
    hex::encode(value.as_bytes())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Canonical manifest preimage. Entries are folded in order, and the count is
/// signed alongside them so entries cannot be dropped from a signed manifest
/// without breaking it.
pub fn manifest_signing_bytes(manifest: &ExportManifest) -> Vec<u8> {
    let mut parts = vec![
        EXPORT_MANIFEST_DOMAIN.to_owned(),
        manifest.version.to_string(),
        encode(&manifest.operation_id),
        encode(&manifest.home_id),
        encode(&manifest.tenant_id),
        encode(&manifest.cut_basis),
        encode(&manifest.holder.holder_id),
        manifest.holder.recipient_pubkey.clone(),
        manifest.signer_kind.as_str().to_owned(),
        manifest.ciphertext_sha256.clone(),
        manifest.created_at.to_string(),
        manifest.entries.len().to_string(),
    ];
    for entry in &manifest.entries {
        parts.push(encode(&entry.kind));
        parts.push(encode(&entry.id));
        parts.push(entry.sha256.clone());
        parts.push(entry.bytes.to_string());
    }
    parts.join("\n").into_bytes()
}

fn well_formed(manifest: &ExportManifest) -> bool {
    !manifest.operation_id.trim().is_empty()
        && !manifest.home_id.trim().is_empty()
        && !manifest.tenant_id.trim().is_empty()
        && !manifest.cut_basis.trim().is_empty()
        && !manifest.holder.holder_id.trim().is_empty()
        && !manifest.holder.recipient_pubkey.trim().is_empty()
        && !manifest.ciphertext_sha256.trim().is_empty()
        && !manifest.entries.is_empty()
        && manifest
            .entries
            .iter()
            .all(|entry| !entry.id.trim().is_empty() && !entry.sha256.trim().is_empty())
}

/// Sign a manifest as the source Home.
pub fn sign_manifest(
    signer: &SigningKey,
    manifest: ExportManifest,
) -> Result<SignedExportManifest, ExportError> {
    if manifest.version != EXPORT_MANIFEST_VERSION {
        return Err(ExportError::UnsupportedVersion);
    }
    if !well_formed(&manifest) {
        return Err(ExportError::Malformed);
    }
    let source_signature = signer.sign(&manifest_signing_bytes(&manifest));
    Ok(SignedExportManifest {
        manifest,
        source_pubkey: signer.public_key().as_str().to_owned(),
        source_signature,
    })
}

/// Check that this signed manifest describes this artifact.
///
/// The ciphertext digest is checked here, before any decryption is attempted,
/// so a modified artifact is a refusal that names the problem rather than a
/// decryption failure that looks like a wrong key.
pub fn verify_artifact(
    signed: &SignedExportManifest,
    ciphertext: &[u8],
) -> Result<(), ExportError> {
    if signed.manifest.version != EXPORT_MANIFEST_VERSION {
        return Err(ExportError::UnsupportedVersion);
    }
    if !well_formed(&signed.manifest) {
        return Err(ExportError::Malformed);
    }
    let key = PublicKey::new(signed.source_pubkey.clone());
    match verify_signature(
        &manifest_signing_bytes(&signed.manifest),
        &signed.source_signature,
        &key,
    ) {
        Ok(true) => {}
        _ => return Err(ExportError::Signature),
    }
    if sha256_hex(ciphertext) != signed.manifest.ciphertext_sha256 {
        return Err(ExportError::ContentDigest);
    }
    Ok(())
}

/// Whether this target may import this cut, checked before anything is written.
///
/// Possessing the artifact is not part of this decision. A bounded download
/// handle carried it here; that handle is transport authority and never
/// decryption authority, and it has no say in admission either.
pub fn verify_restore_admission(
    signed: &SignedExportManifest,
    target: &RestoreTarget,
) -> Result<(), ExportError> {
    if signed.manifest.version != EXPORT_MANIFEST_VERSION {
        return Err(ExportError::UnsupportedVersion);
    }
    if signed.manifest.holder.holder_id != target.holder_id {
        return Err(ExportError::WrongHolder);
    }
    if signed.manifest.tenant_id != target.tenant_id {
        return Err(ExportError::WrongTenant);
    }
    // Importing over a running Home would give one Home id two authorities,
    // which is the split-brain handoff exists to prevent. The operator retires
    // or selects a different target first.
    if target.home_is_live {
        return Err(ExportError::ConflictingLiveHome);
    }
    Ok(())
}

/// Check one decrypted entry against the digest the signed manifest binds.
/// Verifying the artifact proves the cut arrived whole; this proves each piece
/// of it is the piece the manifest named.
pub fn verify_entry(
    signed: &SignedExportManifest,
    id: &str,
    plaintext: &[u8],
) -> Result<(), ExportError> {
    let entry = signed
        .manifest
        .entries
        .iter()
        .find(|entry| entry.id == id)
        .ok_or(ExportError::Malformed)?;
    if entry.sha256 != sha256_hex(plaintext) || entry.bytes != plaintext.len() as u64 {
        return Err(ExportError::ContentDigest);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
