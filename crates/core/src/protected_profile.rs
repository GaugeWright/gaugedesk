//! Provider-neutral protected commercial profile artifacts.
//!
//! GaugeDesk owns only this verification contract. A private or third-party service may
//! package profile bytes, make lease/key-release decisions, and meter use; the open runtime
//! does not contain a GaugeWright issuer or a second federation implementation.
//!
//! The protection blob is deliberately opaque here. Verification proves who issued it, which
//! recipient/root and revision it is bound to, that its bytes were not replaced, and that its
//! lease is current. It does not claim that software running on a recipient-controlled Home
//! can keep opened instructions secret from that Home.

use crate::ids::PublicKey;
use crate::signature::{verify_signature, Signature, SigningKey};
use sha2::{Digest, Sha256};

pub const PROTECTED_PROFILE_VERSION: u8 = 1;
pub const PROTECTED_PROFILE_DOMAIN: &str = "gaugedesk-protected-profile.v1";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProtectedProfileClaims {
    pub version: u8,
    pub profile_id: String,
    pub revision: String,
    pub issuer_authority: String,
    /// The recipient's pinned/root public key, in the same SEC1 hex form federation uses.
    pub recipient_root_pubkey: String,
    pub package_sha256: String,
    pub license_id: String,
    pub watermark: String,
    pub issued_at: u64,
    pub expires_at: u64,
    /// `0` means the signed lease carries no run-count ceiling. Metering may still happen at
    /// the issuer's release/execution boundary.
    pub max_runs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProtectedProfileArtifact {
    pub claims: ProtectedProfileClaims,
    /// Issuer-defined recipient-bound encrypted/obfuscated package bytes.
    pub protection_blob: Vec<u8>,
    pub issuer_signature: Signature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectedProfileError {
    UnsupportedVersion,
    WrongRecipient,
    InvalidDigest,
    InvalidIssuerKey,
    BadSignature,
    NotYetValid,
    Expired,
    InvalidLease,
}

impl ProtectedProfileError {
    pub fn message(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "unsupported protected profile version",
            Self::WrongRecipient => "protected profile is bound to a different recipient",
            Self::InvalidDigest => "protected profile package digest does not match",
            Self::InvalidIssuerKey => "protected profile issuer key is invalid",
            Self::BadSignature => "protected profile issuer signature does not verify",
            Self::NotYetValid => "protected profile lease is not yet valid",
            Self::Expired => "protected profile lease has expired",
            Self::InvalidLease => "protected profile lease is invalid",
        }
    }
}

impl std::fmt::Display for ProtectedProfileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for ProtectedProfileError {}

/// Canonical, delimiter-safe issuer preimage. Free-form strings are hex encoded; numeric fields
/// are decimal; there is no trailing newline.
pub fn signing_bytes(claims: &ProtectedProfileClaims) -> Vec<u8> {
    [
        PROTECTED_PROFILE_DOMAIN.to_owned(),
        claims.version.to_string(),
        hex::encode(claims.profile_id.as_bytes()),
        hex::encode(claims.revision.as_bytes()),
        hex::encode(claims.issuer_authority.as_bytes()),
        claims.recipient_root_pubkey.clone(),
        claims.package_sha256.clone(),
        hex::encode(claims.license_id.as_bytes()),
        hex::encode(claims.watermark.as_bytes()),
        claims.issued_at.to_string(),
        claims.expires_at.to_string(),
        claims.max_runs.to_string(),
    ]
    .join("\n")
    .into_bytes()
}

pub fn package_digest(protection_blob: &[u8]) -> String {
    hex::encode(Sha256::digest(protection_blob))
}

/// Issuer-side constructor shared only as a wire-compatibility primitive. Choosing whether a
/// profile may be issued, how its blob is protected, and how use is metered remain service work.
pub fn sign_artifact(
    signer: &SigningKey,
    claims: ProtectedProfileClaims,
    protection_blob: Vec<u8>,
) -> Result<ProtectedProfileArtifact, ProtectedProfileError> {
    if claims.version != PROTECTED_PROFILE_VERSION
        || claims.expires_at <= claims.issued_at
        || claims.package_sha256 != package_digest(&protection_blob)
    {
        return Err(ProtectedProfileError::InvalidLease);
    }
    let issuer_signature = signer.sign(&signing_bytes(&claims));
    Ok(ProtectedProfileArtifact {
        claims,
        protection_blob,
        issuer_signature,
    })
}

/// Verify a protected artifact against an independently pinned issuer key and the exact
/// recipient root that is attempting to use it. Every mismatch fails closed.
pub fn verify_artifact(
    artifact: &ProtectedProfileArtifact,
    pinned_issuer_key: &PublicKey,
    recipient_root_pubkey: &PublicKey,
    now: u64,
) -> Result<(), ProtectedProfileError> {
    let claims = &artifact.claims;
    if claims.version != PROTECTED_PROFILE_VERSION {
        return Err(ProtectedProfileError::UnsupportedVersion);
    }
    if claims.recipient_root_pubkey != recipient_root_pubkey.as_str() {
        return Err(ProtectedProfileError::WrongRecipient);
    }
    if claims.expires_at <= claims.issued_at {
        return Err(ProtectedProfileError::InvalidLease);
    }
    if claims.issued_at > now {
        return Err(ProtectedProfileError::NotYetValid);
    }
    if claims.expires_at <= now {
        return Err(ProtectedProfileError::Expired);
    }
    if claims.package_sha256 != package_digest(&artifact.protection_blob) {
        return Err(ProtectedProfileError::InvalidDigest);
    }
    match verify_signature(
        &signing_bytes(claims),
        &artifact.issuer_signature,
        pinned_issuer_key,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ProtectedProfileError::BadSignature),
        Err(_) => Err(ProtectedProfileError::InvalidIssuerKey),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> (ProtectedProfileArtifact, SigningKey, PublicKey) {
        let issuer = SigningKey::from_seed(&[17; 32]).unwrap();
        let recipient = SigningKey::from_seed(&[23; 32]).unwrap().public_key();
        let blob = b"opaque-recipient-bound-package".to_vec();
        let claims = ProtectedProfileClaims {
            version: PROTECTED_PROFILE_VERSION,
            profile_id: "profile:forecast".into(),
            revision: "sha256:source".into(),
            issuer_authority: "vendor:gaugewright".into(),
            recipient_root_pubkey: recipient.as_str().into(),
            package_sha256: package_digest(&blob),
            license_id: "license-1".into(),
            watermark: "recipient-42".into(),
            issued_at: 100,
            expires_at: 200,
            max_runs: 10,
        };
        (
            sign_artifact(&issuer, claims, blob).unwrap(),
            issuer,
            recipient,
        )
    }

    #[test]
    fn exact_recipient_artifact_verifies_during_lease() {
        let (artifact, issuer, recipient) = artifact();
        assert_eq!(
            verify_artifact(&artifact, &issuer.public_key(), &recipient, 150),
            Ok(())
        );
    }

    #[test]
    fn copied_tampered_wrong_recipient_and_expired_artifacts_fail_closed() {
        let (artifact, issuer, recipient) = artifact();
        let other = SigningKey::from_seed(&[29; 32]).unwrap().public_key();
        assert_eq!(
            verify_artifact(&artifact, &issuer.public_key(), &other, 150),
            Err(ProtectedProfileError::WrongRecipient)
        );
        assert_eq!(
            verify_artifact(&artifact, &issuer.public_key(), &recipient, 200),
            Err(ProtectedProfileError::Expired)
        );
        let mut tampered = artifact;
        tampered.protection_blob.push(0);
        assert_eq!(
            verify_artifact(&tampered, &issuer.public_key(), &recipient, 150),
            Err(ProtectedProfileError::InvalidDigest)
        );
    }
}
