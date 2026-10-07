//! Proof that an account's own enrolled device is publishing its root
//! ([ADR 0133](../../../specs/decisions/0133-the-hub-projects-the-account-root-key.md) §2).
//!
//! Holding an account's bearer must not be enough to install a root a
//! first-sight browser then pins. So the Hub hands out a single-use challenge,
//! and the publisher answers with two proofs over it: a signature by a device
//! subkey, and the root's delegation to that subkey. The subkey must be the one
//! the publishing session's own device record carries. A device that carries
//! none yet takes the presented one on this first write, never an overwrite,
//! which is the trust-on-first-use ADR 0133 names; after that every
//! publication must come from that subkey, under a root that delegates to it.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use gaugedesk_core::delegation::DeviceDelegation;
use gaugedesk_core::ids::PublicKey;
use gaugedesk_core::signature::{verify_signature, Signature, SigningKey};
use serde::{Deserialize, Serialize};

/// How long a challenge stays answerable.
const CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);

/// What a publisher presents with a root.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicationProof {
    pub challenge: String,
    pub subkey: PublicKey,
    pub delegation: DeviceDelegation,
    /// The subkey's signature over [`publication_signing_bytes`].
    pub signature: Signature,
}

/// The exact bytes the device subkey signs to publish `root` against
/// `challenge`.
pub fn publication_signing_bytes(challenge: &str, root: &str) -> Vec<u8> {
    serde_json::to_vec(&("gaugedesk-root-publication-v1", challenge, root))
        .expect("a tuple of strings serializes")
}

/// Answer `challenge` for `root` with this device's subkey and the root's
/// delegation to it.
pub fn prove(
    challenge: &str,
    root: &str,
    subkey: &SigningKey,
    delegation: &DeviceDelegation,
) -> PublicationProof {
    PublicationProof {
        challenge: challenge.to_owned(),
        subkey: subkey.public_key(),
        delegation: delegation.clone(),
        signature: subkey.sign(&publication_signing_bytes(challenge, root)),
    }
}

fn challenges() -> &'static Mutex<HashMap<String, (String, Instant)>> {
    static CHALLENGES: OnceLock<Mutex<HashMap<String, (String, Instant)>>> = OnceLock::new();
    CHALLENGES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Issue a single-use challenge for `account`.
pub fn issue_challenge(account: &str) -> Option<String> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).ok()?;
    let challenge = hex::encode(bytes);
    let mut held = challenges()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = Instant::now();
    held.retain(|_, (_, issued)| now.duration_since(*issued) < CHALLENGE_TTL);
    held.insert(challenge.clone(), (account.to_owned(), now));
    Some(challenge)
}

/// Spend `challenge` for `account`: true once, for a challenge issued to that
/// account within its lifetime.
fn spend_challenge(challenge: &str, account: &str) -> bool {
    let mut held = challenges()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match held.remove(challenge) {
        Some((owner, issued)) => owner == account && issued.elapsed() < CHALLENGE_TTL,
        None => false,
    }
}

/// Why a proof was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Challenge,
    Signature,
    Delegation,
    /// The subkey is not the one the session's own device carries.
    NotThisDevice,
    /// The delegation's root is not the one the account already projects, and
    /// no signed hand-over leads from it.
    ForeignRoot,
}

impl Refusal {
    pub fn reason(self) -> &'static str {
        match self {
            Refusal::Challenge => "the publication challenge is unknown, spent or expired",
            Refusal::Signature => "the device subkey's signature does not hold",
            Refusal::Delegation => "the root's delegation to the device subkey does not hold",
            Refusal::NotThisDevice => "the subkey is not the one this session's device carries",
            Refusal::ForeignRoot => "the delegation does not chain to the account's projected root",
        }
    }
}

/// Check `proof` for publishing `root` on `account`. `device_subkey` is what
/// the session's own device record carries ("" when nothing yet), and
/// `continues_projected` whether `root` is the projected root or one a signed
/// hand-over from it reaches. `Ok` names the subkey the device record should
/// carry from now on.
pub fn verify(
    proof: &PublicationProof,
    account: &str,
    root: &str,
    device_subkey: &str,
    continues_projected: bool,
    now_secs: u64,
) -> Result<PublicKey, Refusal> {
    if !spend_challenge(&proof.challenge, account) {
        return Err(Refusal::Challenge);
    }
    let signed = verify_signature(
        &publication_signing_bytes(&proof.challenge, root),
        &proof.signature,
        &proof.subkey,
    )
    .unwrap_or(false);
    if !signed {
        return Err(Refusal::Signature);
    }
    if proof.delegation.verify(now_secs).is_err()
        || proof.delegation.subkey != proof.subkey
        || proof.delegation.authority_root.as_str() != root
    {
        return Err(Refusal::Delegation);
    }
    if !device_subkey.is_empty() && device_subkey != proof.subkey.as_str() {
        return Err(Refusal::NotThisDevice);
    }
    if !continues_projected {
        return Err(Refusal::ForeignRoot);
    }
    Ok(proof.subkey.clone())
}

#[cfg(test)]
#[path = "root_publication_tests.rs"]
mod tests;
