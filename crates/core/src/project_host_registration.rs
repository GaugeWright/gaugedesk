//! Project Host registration claims (ADR 0171).
//!
//! Registering a self-managed Project Host is an admission ceremony, not a form
//! submission. Administration mints a single-use expiring challenge; the
//! claimant Home returns a claim signed by its own governance root; the verifier
//! checks that signature and *then* proves live possession by dialing the
//! claimed certificate-pinned route for a fresh nonce signature over the same
//! identity and intent.
//!
//! This module owns the two canonical preimages and their pure verification. It
//! performs no I/O on purpose: dialing the route belongs to the operated
//! verifier, and a claim that verifies here is not by itself an admission. A
//! Home id that arrives in a form is an assertion to be checked; only a
//! signature over a challenge this tenant minted, followed by a possession
//! answer from the route the claim names, admits anything.

use crate::ids::PublicKey;
use crate::signature::{verify_signature, Signature, SigningKey};

pub const REGISTRATION_VERSION: u8 = 1;
pub const CLAIM_DOMAIN: &str = "gaugedesk-project-host-claim.v1";
pub const POSSESSION_DOMAIN: &str = "gaugedesk-project-host-possession.v1";

/// The operational capabilities a claim may assert. Closed and versioned: an
/// unrecognized name is refused rather than ignored, so a newer Home cannot
/// quietly widen what registration admits by inventing one.
pub const ADMITTED_CAPABILITIES: &[&str] =
    &["carry-project-home", "accept-handoff", "serve-export"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationError {
    /// The claim or challenge does not speak this contract version.
    UnsupportedVersion,
    /// The challenge has expired, or the claim outlives it.
    Expired,
    /// The claim answers a different challenge than the one presented.
    ChallengeMismatch,
    /// The claim names a different tenant than the challenge was minted for.
    TenantMismatch,
    /// The claim asserts a capability outside the closed set, or none at all.
    UnadmittedCapability,
    /// A required field is empty, or the claim's own validity window is absurd.
    Malformed,
    /// The governance signature does not verify under the claimed key.
    Signature,
    /// The possession answer reports a different identity, route, or epoch than
    /// the claim it is supposed to be proving.
    RouteSubstituted,
    /// The possession answer is for a different possession nonce.
    NonceMismatch,
    /// The route epoch went backwards, so this answer is replayed or stale.
    StaleEpoch,
}

/// What Administration minted: bounded, single-use, and bound to the tenant,
/// the initiating actor, the proposed label, and the operation it belongs to.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RegistrationChallenge {
    pub version: u8,
    pub challenge_id: String,
    pub tenant_id: String,
    pub initiating_actor: String,
    pub proposed_label: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// What the claimant Home returns. Everything a verifier needs to decide *which*
/// Home this is and *where* to go and check, and nothing about the work it
/// carries: registration transfers no content and grants no project access.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostClaim {
    pub version: u8,
    pub home_id: String,
    pub governance_pubkey: String,
    pub tenant_id: String,
    pub challenge_id: String,
    pub challenge_nonce: String,
    pub route: String,
    pub route_epoch: u64,
    pub transport_pin: String,
    pub capabilities: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedHostClaim {
    pub claim: HostClaim,
    pub governance_signature: Signature,
}

/// The fresh nonce a verifier puts to the claimed route after the claim's
/// signature checks out. Answering it is what distinguishes a Home that holds
/// this identity from one that merely copied a claim.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PossessionChallenge {
    pub version: u8,
    pub challenge_id: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// The route's answer. It restates the identity it is answering for so that a
/// substituted route cannot pass by signing only an opaque nonce.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PossessionAnswer {
    pub version: u8,
    pub challenge_id: String,
    pub nonce: String,
    pub home_id: String,
    pub governance_pubkey: String,
    pub tenant_id: String,
    pub route: String,
    pub route_epoch: u64,
    pub transport_pin: String,
    pub signature: Signature,
}

fn encode(value: &str) -> String {
    hex::encode(value.as_bytes())
}

/// Canonical claim preimage. Hex-encoding every free-text field keeps the
/// newline separator unambiguous: a route containing a newline cannot shift the
/// fields after it and sign a different statement than it appears to.
pub fn claim_signing_bytes(claim: &HostClaim) -> Vec<u8> {
    [
        CLAIM_DOMAIN.to_owned(),
        claim.version.to_string(),
        encode(&claim.home_id),
        claim.governance_pubkey.clone(),
        encode(&claim.tenant_id),
        encode(&claim.challenge_id),
        encode(&claim.challenge_nonce),
        encode(&claim.route),
        claim.route_epoch.to_string(),
        encode(&claim.transport_pin),
        encode(&claim.capabilities.join(",")),
        claim.issued_at.to_string(),
        claim.expires_at.to_string(),
    ]
    .join("\n")
    .into_bytes()
}

/// Canonical possession preimage. It repeats the claim's identity fields rather
/// than signing the nonce alone, so the answer says *who* is answering.
pub fn possession_signing_bytes(answer: &PossessionAnswer) -> Vec<u8> {
    [
        POSSESSION_DOMAIN.to_owned(),
        answer.version.to_string(),
        encode(&answer.challenge_id),
        encode(&answer.nonce),
        encode(&answer.home_id),
        answer.governance_pubkey.clone(),
        encode(&answer.tenant_id),
        encode(&answer.route),
        answer.route_epoch.to_string(),
        encode(&answer.transport_pin),
    ]
    .join("\n")
    .into_bytes()
}

fn capabilities_admitted(capabilities: &[String]) -> bool {
    !capabilities.is_empty()
        && capabilities
            .iter()
            .all(|name| ADMITTED_CAPABILITIES.contains(&name.as_str()))
        && capabilities.windows(2).all(|pair| pair[0] < pair[1])
}

fn well_formed(claim: &HostClaim) -> bool {
    ![
        &claim.home_id,
        &claim.governance_pubkey,
        &claim.tenant_id,
        &claim.challenge_id,
        &claim.challenge_nonce,
        &claim.route,
        &claim.transport_pin,
    ]
    .iter()
    .any(|field| field.trim().is_empty())
        && claim.expires_at > claim.issued_at
}

/// Sign a claim with the Home's governance root.
pub fn sign_claim(
    signer: &SigningKey,
    claim: HostClaim,
) -> Result<SignedHostClaim, RegistrationError> {
    if claim.version != REGISTRATION_VERSION {
        return Err(RegistrationError::UnsupportedVersion);
    }
    if !well_formed(&claim) {
        return Err(RegistrationError::Malformed);
    }
    if !capabilities_admitted(&claim.capabilities) {
        return Err(RegistrationError::UnadmittedCapability);
    }
    let governance_signature = signer.sign(&claim_signing_bytes(&claim));
    Ok(SignedHostClaim {
        claim,
        governance_signature,
    })
}

/// Check a claim against the challenge it answers. Success means the claim is
/// internally coherent and genuinely signed by the key it names — it does not
/// mean the Home is reachable, and it does not admit the Host. Live possession
/// is a separate step and is required.
pub fn verify_claim(
    signed: &SignedHostClaim,
    challenge: &RegistrationChallenge,
    now: u64,
) -> Result<(), RegistrationError> {
    let claim = &signed.claim;
    if claim.version != REGISTRATION_VERSION || challenge.version != REGISTRATION_VERSION {
        return Err(RegistrationError::UnsupportedVersion);
    }
    if !well_formed(claim) {
        return Err(RegistrationError::Malformed);
    }
    // The challenge fences the whole ceremony. A claim that outlives it would
    // let a captured answer be presented after the window the tenant opened.
    if now >= challenge.expires_at || now >= claim.expires_at {
        return Err(RegistrationError::Expired);
    }
    if claim.challenge_id != challenge.challenge_id || claim.challenge_nonce != challenge.nonce {
        return Err(RegistrationError::ChallengeMismatch);
    }
    if claim.tenant_id != challenge.tenant_id {
        return Err(RegistrationError::TenantMismatch);
    }
    if !capabilities_admitted(&claim.capabilities) {
        return Err(RegistrationError::UnadmittedCapability);
    }
    let key = PublicKey::new(claim.governance_pubkey.clone());
    match verify_signature(
        &claim_signing_bytes(claim),
        &signed.governance_signature,
        &key,
    ) {
        Ok(true) => Ok(()),
        _ => Err(RegistrationError::Signature),
    }
}

/// Check the answer that came back from dialing the claimed route.
///
/// `last_known_epoch` is the highest route epoch this verifier has already
/// accepted for this Home, if any. An answer at or below it is replayed or
/// stale and cannot re-admit a route that has since moved.
pub fn verify_possession(
    answer: &PossessionAnswer,
    claim: &HostClaim,
    challenge: &PossessionChallenge,
    last_known_epoch: Option<u64>,
    now: u64,
) -> Result<(), RegistrationError> {
    if answer.version != REGISTRATION_VERSION || challenge.version != REGISTRATION_VERSION {
        return Err(RegistrationError::UnsupportedVersion);
    }
    if now >= challenge.expires_at {
        return Err(RegistrationError::Expired);
    }
    if answer.challenge_id != challenge.challenge_id {
        return Err(RegistrationError::ChallengeMismatch);
    }
    if answer.nonce != challenge.nonce {
        return Err(RegistrationError::NonceMismatch);
    }
    // Everything the claim asserted about identity must come back unchanged.
    // Checking only the signature would admit a different Home that holds the
    // same key, and checking only the nonce would admit a substituted route.
    if answer.home_id != claim.home_id
        || answer.governance_pubkey != claim.governance_pubkey
        || answer.tenant_id != claim.tenant_id
        || answer.route != claim.route
        || answer.transport_pin != claim.transport_pin
    {
        return Err(RegistrationError::RouteSubstituted);
    }
    if answer.route_epoch != claim.route_epoch {
        return Err(RegistrationError::RouteSubstituted);
    }
    if last_known_epoch.is_some_and(|known| answer.route_epoch <= known) {
        return Err(RegistrationError::StaleEpoch);
    }
    let key = PublicKey::new(answer.governance_pubkey.clone());
    match verify_signature(&possession_signing_bytes(answer), &answer.signature, &key) {
        Ok(true) => Ok(()),
        _ => Err(RegistrationError::Signature),
    }
}

#[cfg(test)]
mod tests;
