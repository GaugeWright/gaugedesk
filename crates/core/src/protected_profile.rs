//! Provider-neutral protected commercial Agent profile contract.
//!
//! GaugeDesk owns canonical owner authorization, artifact verification, and recipient
//! release proof. A private or third-party service owns entitlement policy, encryption,
//! key custody, metering, and audit. This raises copying cost; software running on a
//! recipient-controlled Home cannot promise secrecy from that Home.

use crate::ids::PublicKey;
use crate::signature::{verify_signature, Signature, SigningKey};
use sha2::{Digest, Sha256};

pub const PROTECTED_PROFILE_VERSION: u8 = 2;
pub const PROTECTED_PROFILE_DOMAIN: &str = "gaugedesk-protected-profile.v2";
pub const ISSUE_AUTHORIZATION_DOMAIN: &str = "gaugedesk-protected-profile-issue.v2";
pub const RELEASE_AUTHORIZATION_DOMAIN: &str = "gaugedesk-protected-profile-release.v2";
pub const ATTRIBUTION_ENVELOPE_VERSION: u8 = 1;

/// The exact release an Agent owner authorizes a protection service to issue.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IssueAuthorization {
    pub version: u8,
    pub request_id: String,
    pub profile_id: String,
    pub agent_id: String,
    pub revision: String,
    pub owner_authority: String,
    pub owner_root_pubkey: String,
    pub issuer_authority: String,
    pub issuer_pubkey: String,
    pub service_origin: String,
    pub recipient_authority: String,
    pub recipient_root_pubkey: String,
    pub plaintext_sha256: String,
    pub export_format: String,
    pub authorized_at: u64,
    pub authorization_expires_at: u64,
    pub lease_expires_at: u64,
    /// `0` means no signed run-count ceiling. The service may still meter use.
    pub max_runs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedIssueAuthorization {
    pub authorization: IssueAuthorization,
    pub owner_signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProtectedProfileClaims {
    pub version: u8,
    pub profile_id: String,
    pub agent_id: String,
    pub revision: String,
    pub owner_authority: String,
    pub owner_root_pubkey: String,
    pub issuer_authority: String,
    pub service_origin: String,
    pub recipient_authority: String,
    pub recipient_root_pubkey: String,
    /// Digest of the plaintext export the owner authorized.
    pub plaintext_sha256: String,
    /// Digest of the opaque protected bytes carried by the artifact.
    pub protection_blob_sha256: String,
    pub export_format: String,
    pub license_id: String,
    /// Signed package-envelope attribution. It is not a payload watermark.
    pub attribution_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub max_runs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProtectedProfileArtifact {
    pub claims: ProtectedProfileClaims,
    /// Issuer-defined recipient-bound encrypted package bytes.
    pub protection_blob: Vec<u8>,
    pub issuer_signature: Signature,
}

/// Recoverable recipient attribution packaged inside the protected ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttributedPackageEnvelope {
    pub version: u8,
    pub profile_id: String,
    pub agent_id: String,
    pub revision: String,
    pub owner_root_pubkey: String,
    pub recipient_root_pubkey: String,
    pub attribution_id: String,
    pub plaintext_sha256: String,
    pub payload: Vec<u8>,
}

/// One short-lived recipient proof. Repeating the exact `request_id` is idempotent;
/// reusing its nonce for different content is a replay and must be refused.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReleaseAuthorization {
    pub version: u8,
    pub request_id: String,
    pub license_id: String,
    pub artifact_sha256: String,
    pub recipient_root_pubkey: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedReleaseAuthorization {
    pub authorization: ReleaseAuthorization,
    pub recipient_signature: Signature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectedProfileError {
    UnsupportedVersion,
    WrongOwner,
    WrongRecipient,
    InvalidDigest,
    InvalidKey,
    BadSignature,
    NotYetValid,
    Expired,
    InvalidLease,
    InvalidAuthorization,
}

impl ProtectedProfileError {
    pub fn message(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "unsupported protected profile version",
            Self::WrongOwner => "protected profile is bound to a different owner",
            Self::WrongRecipient => "protected profile is bound to a different recipient",
            Self::InvalidDigest => "protected profile digest does not match",
            Self::InvalidKey => "protected profile public key is invalid",
            Self::BadSignature => "protected profile signature does not verify",
            Self::NotYetValid => "protected profile authorization is not yet valid",
            Self::Expired => "protected profile authorization has expired",
            Self::InvalidLease => "protected profile lease is invalid",
            Self::InvalidAuthorization => "protected profile authorization is invalid",
        }
    }
}

impl std::fmt::Display for ProtectedProfileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for ProtectedProfileError {}

fn encode(value: &str) -> String {
    hex::encode(value.as_bytes())
}

fn verify(sig: &Signature, bytes: &[u8], key: &PublicKey) -> Result<(), ProtectedProfileError> {
    match verify_signature(bytes, sig, key) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ProtectedProfileError::BadSignature),
        Err(_) => Err(ProtectedProfileError::InvalidKey),
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    hex::decode(value).is_ok_and(|bytes| bytes.len() == 32)
}

fn validate_issue(value: &IssueAuthorization) -> Result<(), ProtectedProfileError> {
    if value.request_id.is_empty()
        || value.profile_id.is_empty()
        || value.agent_id.is_empty()
        || value.revision.is_empty()
        || value.owner_authority.is_empty()
        || value.issuer_authority.is_empty()
        || value.service_origin.is_empty()
        || value.recipient_authority.is_empty()
        || value.export_format.is_empty()
        || !is_sha256(&value.plaintext_sha256)
        || value.authorization_expires_at <= value.authorized_at
        || value.lease_expires_at <= value.authorized_at
    {
        return Err(ProtectedProfileError::InvalidAuthorization);
    }
    Ok(())
}

/// Canonical, delimiter-safe owner authorization preimage.
pub fn issue_authorization_bytes(value: &IssueAuthorization) -> Vec<u8> {
    [
        ISSUE_AUTHORIZATION_DOMAIN.to_owned(),
        value.version.to_string(),
        encode(&value.request_id),
        encode(&value.profile_id),
        encode(&value.agent_id),
        encode(&value.revision),
        encode(&value.owner_authority),
        value.owner_root_pubkey.clone(),
        encode(&value.issuer_authority),
        value.issuer_pubkey.clone(),
        encode(&value.service_origin),
        encode(&value.recipient_authority),
        value.recipient_root_pubkey.clone(),
        value.plaintext_sha256.clone(),
        encode(&value.export_format),
        value.authorized_at.to_string(),
        value.authorization_expires_at.to_string(),
        value.lease_expires_at.to_string(),
        value.max_runs.to_string(),
    ]
    .join("\n")
    .into_bytes()
}

pub fn sign_issue_authorization(
    signer: &SigningKey,
    authorization: IssueAuthorization,
) -> SignedIssueAuthorization {
    let owner_signature = signer.sign(&issue_authorization_bytes(&authorization));
    SignedIssueAuthorization {
        authorization,
        owner_signature,
    }
}

pub fn verify_issue_authorization(
    signed: &SignedIssueAuthorization,
    owner_root: &PublicKey,
    now: u64,
) -> Result<(), ProtectedProfileError> {
    let value = &signed.authorization;
    if value.version != PROTECTED_PROFILE_VERSION {
        return Err(ProtectedProfileError::UnsupportedVersion);
    }
    if value.owner_root_pubkey != owner_root.as_str() {
        return Err(ProtectedProfileError::WrongOwner);
    }
    validate_issue(value)?;
    if value.authorized_at > now {
        return Err(ProtectedProfileError::NotYetValid);
    }
    if value.authorization_expires_at <= now {
        return Err(ProtectedProfileError::Expired);
    }
    verify(
        &signed.owner_signature,
        &issue_authorization_bytes(value),
        owner_root,
    )
}

/// Canonical issuer artifact preimage.
pub fn signing_bytes(claims: &ProtectedProfileClaims) -> Vec<u8> {
    [
        PROTECTED_PROFILE_DOMAIN.to_owned(),
        claims.version.to_string(),
        encode(&claims.profile_id),
        encode(&claims.agent_id),
        encode(&claims.revision),
        encode(&claims.owner_authority),
        claims.owner_root_pubkey.clone(),
        encode(&claims.issuer_authority),
        encode(&claims.service_origin),
        encode(&claims.recipient_authority),
        claims.recipient_root_pubkey.clone(),
        claims.plaintext_sha256.clone(),
        claims.protection_blob_sha256.clone(),
        encode(&claims.export_format),
        encode(&claims.license_id),
        encode(&claims.attribution_id),
        claims.issued_at.to_string(),
        claims.expires_at.to_string(),
        claims.max_runs.to_string(),
    ]
    .join("\n")
    .into_bytes()
}

pub fn sign_artifact(
    signer: &SigningKey,
    claims: ProtectedProfileClaims,
    protection_blob: Vec<u8>,
) -> Result<ProtectedProfileArtifact, ProtectedProfileError> {
    if claims.version != PROTECTED_PROFILE_VERSION
        || claims.expires_at <= claims.issued_at
        || claims.protection_blob_sha256 != sha256_hex(&protection_blob)
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

pub fn artifact_digest(artifact: &ProtectedProfileArtifact) -> String {
    let bytes = signing_bytes(&artifact.claims);
    let mut digest = Sha256::new();
    digest.update(PROTECTED_PROFILE_DOMAIN.as_bytes());
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(&bytes);
    digest.update((artifact.protection_blob.len() as u64).to_be_bytes());
    digest.update(&artifact.protection_blob);
    digest.update(artifact.issuer_signature.as_bytes());
    hex::encode(digest.finalize())
}

/// Verify against issuer and recipient keys independently pinned by the owner/profile.
pub fn verify_artifact(
    artifact: &ProtectedProfileArtifact,
    pinned_issuer_key: &PublicKey,
    recipient_root: &PublicKey,
    now: u64,
) -> Result<(), ProtectedProfileError> {
    let claims = &artifact.claims;
    if claims.version != PROTECTED_PROFILE_VERSION {
        return Err(ProtectedProfileError::UnsupportedVersion);
    }
    if claims.recipient_root_pubkey != recipient_root.as_str() {
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
    if !is_sha256(&claims.plaintext_sha256)
        || claims.protection_blob_sha256 != sha256_hex(&artifact.protection_blob)
    {
        return Err(ProtectedProfileError::InvalidDigest);
    }
    verify(
        &artifact.issuer_signature,
        &signing_bytes(claims),
        pinned_issuer_key,
    )
}

/// Verify the artifact is the exact consequence of the owner-signed issuance. This is the
/// load-bearing comparison that prevents an otherwise valid issuer artifact being substituted
/// for a different Agent, recipient, service, lease, or owner. Historical owner authorization
/// may be past its issue window when an artifact executes, so its signature and issue-time
/// relation are checked here without requiring that window to still be open at `now`.
pub fn verify_artifact_against_issue(
    artifact: &ProtectedProfileArtifact,
    signed_issue: &SignedIssueAuthorization,
    owner_root: &PublicKey,
    pinned_issuer_key: &PublicKey,
    recipient_root: &PublicKey,
    now: u64,
) -> Result<(), ProtectedProfileError> {
    let issue = &signed_issue.authorization;
    if issue.version != PROTECTED_PROFILE_VERSION {
        return Err(ProtectedProfileError::UnsupportedVersion);
    }
    if issue.owner_root_pubkey != owner_root.as_str() {
        return Err(ProtectedProfileError::WrongOwner);
    }
    validate_issue(issue)?;
    verify(
        &signed_issue.owner_signature,
        &issue_authorization_bytes(issue),
        owner_root,
    )?;

    let claims = &artifact.claims;
    if claims.profile_id != issue.profile_id
        || claims.agent_id != issue.agent_id
        || claims.revision != issue.revision
        || claims.owner_authority != issue.owner_authority
        || claims.owner_root_pubkey != issue.owner_root_pubkey
        || claims.issuer_authority != issue.issuer_authority
        || claims.service_origin != issue.service_origin
        || claims.recipient_authority != issue.recipient_authority
        || claims.recipient_root_pubkey != issue.recipient_root_pubkey
        || claims.plaintext_sha256 != issue.plaintext_sha256
        || claims.export_format != issue.export_format
        || claims.issued_at < issue.authorized_at
        || claims.issued_at >= issue.authorization_expires_at
        || claims.expires_at != issue.lease_expires_at
        || claims.max_runs != issue.max_runs
        || issue.issuer_pubkey != pinned_issuer_key.as_str()
    {
        return Err(ProtectedProfileError::InvalidAuthorization);
    }
    verify_artifact(artifact, pinned_issuer_key, recipient_root, now)
}

pub fn release_authorization_bytes(value: &ReleaseAuthorization) -> Vec<u8> {
    [
        RELEASE_AUTHORIZATION_DOMAIN.to_owned(),
        value.version.to_string(),
        encode(&value.request_id),
        encode(&value.license_id),
        value.artifact_sha256.clone(),
        value.recipient_root_pubkey.clone(),
        value.issued_at.to_string(),
        value.expires_at.to_string(),
        encode(&value.nonce),
    ]
    .join("\n")
    .into_bytes()
}

pub fn sign_release_authorization(
    signer: &SigningKey,
    authorization: ReleaseAuthorization,
) -> SignedReleaseAuthorization {
    let recipient_signature = signer.sign(&release_authorization_bytes(&authorization));
    SignedReleaseAuthorization {
        authorization,
        recipient_signature,
    }
}

pub fn verify_release_authorization(
    signed: &SignedReleaseAuthorization,
    recipient_root: &PublicKey,
    artifact: &ProtectedProfileArtifact,
    now: u64,
) -> Result<(), ProtectedProfileError> {
    let value = &signed.authorization;
    if value.version != PROTECTED_PROFILE_VERSION {
        return Err(ProtectedProfileError::UnsupportedVersion);
    }
    if value.recipient_root_pubkey != recipient_root.as_str()
        || artifact.claims.recipient_root_pubkey != recipient_root.as_str()
    {
        return Err(ProtectedProfileError::WrongRecipient);
    }
    if value.license_id != artifact.claims.license_id
        || value.artifact_sha256 != artifact_digest(artifact)
        || value.request_id.is_empty()
        || value.nonce.is_empty()
        || value.expires_at <= value.issued_at
    {
        return Err(ProtectedProfileError::InvalidAuthorization);
    }
    if value.issued_at > now {
        return Err(ProtectedProfileError::NotYetValid);
    }
    if value.expires_at <= now {
        return Err(ProtectedProfileError::Expired);
    }
    verify(
        &signed.recipient_signature,
        &release_authorization_bytes(value),
        recipient_root,
    )
}

pub fn verify_attributed_package(
    envelope: &AttributedPackageEnvelope,
    claims: &ProtectedProfileClaims,
) -> Result<(), ProtectedProfileError> {
    if envelope.version != ATTRIBUTION_ENVELOPE_VERSION
        || envelope.profile_id != claims.profile_id
        || envelope.agent_id != claims.agent_id
        || envelope.revision != claims.revision
        || envelope.owner_root_pubkey != claims.owner_root_pubkey
        || envelope.recipient_root_pubkey != claims.recipient_root_pubkey
        || envelope.attribution_id != claims.attribution_id
        || envelope.plaintext_sha256 != claims.plaintext_sha256
        || sha256_hex(&envelope.payload) != claims.plaintext_sha256
    {
        return Err(ProtectedProfileError::InvalidDigest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release() -> (ProtectedProfileArtifact, SigningKey, SigningKey, SigningKey) {
        let owner = SigningKey::from_seed(&[11; 32]).unwrap();
        let issuer = SigningKey::from_seed(&[17; 32]).unwrap();
        let recipient = SigningKey::from_seed(&[23; 32]).unwrap();
        let blob = b"opaque-recipient-bound-package".to_vec();
        let claims = ProtectedProfileClaims {
            version: PROTECTED_PROFILE_VERSION,
            profile_id: "profile:forecast".into(),
            agent_id: "agent:forecast".into(),
            revision: "revision-7".into(),
            owner_authority: "consultant".into(),
            owner_root_pubkey: owner.public_key().as_str().into(),
            issuer_authority: "vendor:gaugewright".into(),
            service_origin: "https://profiles.example".into(),
            recipient_authority: "client".into(),
            recipient_root_pubkey: recipient.public_key().as_str().into(),
            plaintext_sha256: sha256_hex(b"agent export"),
            protection_blob_sha256: sha256_hex(&blob),
            export_format: "gaugedesk-target-bundle.v1".into(),
            license_id: "license-1".into(),
            attribution_id: "attribution-42".into(),
            issued_at: 100,
            expires_at: 200,
            max_runs: 10,
        };
        (
            sign_artifact(&issuer, claims, blob).unwrap(),
            owner,
            issuer,
            recipient,
        )
    }

    #[test]
    fn owner_authorizes_the_exact_release() {
        let (_, owner, issuer, recipient) = release();
        let authorization = IssueAuthorization {
            version: PROTECTED_PROFILE_VERSION,
            request_id: "issue-1".into(),
            profile_id: "profile:forecast".into(),
            agent_id: "agent:forecast".into(),
            revision: "revision-7".into(),
            owner_authority: "consultant".into(),
            owner_root_pubkey: owner.public_key().as_str().into(),
            issuer_authority: "vendor:gaugewright".into(),
            issuer_pubkey: issuer.public_key().as_str().into(),
            service_origin: "https://profiles.example".into(),
            recipient_authority: "client".into(),
            recipient_root_pubkey: recipient.public_key().as_str().into(),
            plaintext_sha256: sha256_hex(b"agent export"),
            export_format: "gaugedesk-target-bundle.v1".into(),
            authorized_at: 100,
            authorization_expires_at: 120,
            lease_expires_at: 200,
            max_runs: 10,
        };
        let signed = sign_issue_authorization(&owner, authorization);
        assert_eq!(
            verify_issue_authorization(&signed, &owner.public_key(), 110),
            Ok(())
        );

        let mut changed = signed;
        changed.authorization.recipient_root_pubkey = issuer.public_key().as_str().into();
        assert_eq!(
            verify_issue_authorization(&changed, &owner.public_key(), 110),
            Err(ProtectedProfileError::BadSignature)
        );
    }

    #[test]
    fn artifact_and_recipient_release_proof_are_exact() {
        let (artifact, _, issuer, recipient) = release();
        assert_eq!(
            verify_artifact(
                &artifact,
                &issuer.public_key(),
                &recipient.public_key(),
                150
            ),
            Ok(())
        );
        let authorization = ReleaseAuthorization {
            version: PROTECTED_PROFILE_VERSION,
            request_id: "unwrap-1".into(),
            license_id: artifact.claims.license_id.clone(),
            artifact_sha256: artifact_digest(&artifact),
            recipient_root_pubkey: recipient.public_key().as_str().into(),
            issued_at: 150,
            expires_at: 160,
            nonce: "nonce-1".into(),
        };
        let signed = sign_release_authorization(&recipient, authorization);
        assert_eq!(
            verify_release_authorization(&signed, &recipient.public_key(), &artifact, 155),
            Ok(())
        );

        let mut wrong_artifact = artifact;
        wrong_artifact.protection_blob.push(0);
        assert_eq!(
            verify_release_authorization(&signed, &recipient.public_key(), &wrong_artifact, 155),
            Err(ProtectedProfileError::InvalidAuthorization)
        );
    }

    #[test]
    fn a_valid_issuer_cannot_substitute_a_different_owner_release() {
        let (artifact, owner, issuer, recipient) = release();
        let issue = IssueAuthorization {
            version: PROTECTED_PROFILE_VERSION,
            request_id: "issue-1".into(),
            profile_id: artifact.claims.profile_id.clone(),
            agent_id: artifact.claims.agent_id.clone(),
            revision: artifact.claims.revision.clone(),
            owner_authority: artifact.claims.owner_authority.clone(),
            owner_root_pubkey: owner.public_key().as_str().into(),
            issuer_authority: artifact.claims.issuer_authority.clone(),
            issuer_pubkey: issuer.public_key().as_str().into(),
            service_origin: artifact.claims.service_origin.clone(),
            recipient_authority: artifact.claims.recipient_authority.clone(),
            recipient_root_pubkey: recipient.public_key().as_str().into(),
            plaintext_sha256: artifact.claims.plaintext_sha256.clone(),
            export_format: artifact.claims.export_format.clone(),
            authorized_at: 90,
            authorization_expires_at: 110,
            lease_expires_at: 200,
            max_runs: 10,
        };
        let signed = sign_issue_authorization(&owner, issue);
        assert_eq!(
            verify_artifact_against_issue(
                &artifact,
                &signed,
                &owner.public_key(),
                &issuer.public_key(),
                &recipient.public_key(),
                150,
            ),
            Ok(())
        );

        let mut substituted = artifact;
        substituted.claims.agent_id = "agent:other".into();
        substituted.issuer_signature = issuer.sign(&signing_bytes(&substituted.claims));
        assert_eq!(
            verify_artifact_against_issue(
                &substituted,
                &signed,
                &owner.public_key(),
                &issuer.public_key(),
                &recipient.public_key(),
                150,
            ),
            Err(ProtectedProfileError::InvalidAuthorization)
        );
    }

    #[test]
    fn copied_tampered_wrong_recipient_and_expired_artifacts_fail_closed() {
        let (artifact, _, issuer, recipient) = release();
        let other = SigningKey::from_seed(&[29; 32]).unwrap().public_key();
        assert_eq!(
            verify_artifact(&artifact, &issuer.public_key(), &other, 150),
            Err(ProtectedProfileError::WrongRecipient)
        );
        assert_eq!(
            verify_artifact(
                &artifact,
                &issuer.public_key(),
                &recipient.public_key(),
                200
            ),
            Err(ProtectedProfileError::Expired)
        );
        let mut tampered = artifact;
        tampered.protection_blob.push(0);
        assert_eq!(
            verify_artifact(
                &tampered,
                &issuer.public_key(),
                &recipient.public_key(),
                150
            ),
            Err(ProtectedProfileError::InvalidDigest)
        );
    }

    #[test]
    fn attribution_envelope_is_recoverable_and_payload_bound() {
        let (artifact, _, _, _) = release();
        let claims = artifact.claims;
        let mut envelope = AttributedPackageEnvelope {
            version: ATTRIBUTION_ENVELOPE_VERSION,
            profile_id: claims.profile_id.clone(),
            agent_id: claims.agent_id.clone(),
            revision: claims.revision.clone(),
            owner_root_pubkey: claims.owner_root_pubkey.clone(),
            recipient_root_pubkey: claims.recipient_root_pubkey.clone(),
            attribution_id: claims.attribution_id.clone(),
            plaintext_sha256: claims.plaintext_sha256.clone(),
            payload: b"agent export".to_vec(),
        };
        assert_eq!(verify_attributed_package(&envelope, &claims), Ok(()));
        envelope.payload.push(0);
        assert_eq!(
            verify_attributed_package(&envelope, &claims),
            Err(ProtectedProfileError::InvalidDigest)
        );
    }
}
