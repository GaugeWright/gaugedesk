//! The device-enrollment **wire** (`ACCT-1`, [ADR 0055]) — the app-layer shell that carries
//! the enrollment handshake over the dumb rendezvous relay and drives the pure, proptested
//! reducer [`gaugedesk_core::device_enrollment`]. A new device joins an existing account
//! **root** (the "this is also me" act, distinct from federation's `INV-13` crossing).
//!
//! The three-message handshake ([ADR 0055]) over the shared binary-WSS relay:
//! 1. **Request** — the new device mints a subkey and opens a rendezvous session, presenting
//!    `(session, subkey)`. No authority — a claim awaiting proof.
//! 2. **Challenge + SAS** — a device holding the root picks up the request. Both ends derive a
//!    [`device_sas`] over `(session, subkey)` — the new device over its *real* subkey, the
//!    holder over the *presented* one (whatever the relay delivered). The humans compare the
//!    SAS **out of band**; a relay substitution yields a different SAS and is declined. This is
//!    the channel binding the reducer enforces structurally (`presented == requested`).
//! 3. **Authorize** — on a matched SAS the holder issues a root-signed [`DeviceDelegation`]
//!    (FED-5a self-delegation) **and** the account key **sealed to the subkey** ([`seal_to_subkey`],
//!    ECIES — crosses as ciphertext the relay cannot read, `INV-10`).
//! 4. **Complete** — the new device verifies the delegation chains to the pinned root + is
//!    unexpired, unseals the account key, and is enrolled.
//!
//! The relay transport is the broker byte-splice (verified live); the novel parts here are the
//! SAS, the seal-to-subkey, and feeding the reducer. The reducer owns the safety properties
//! (`CHANNEL_BINDING_HOLDS` / `NO_ATTACKER_ENROLLED` / `SELF_DELEGATION_ONLY` /
//! `KEY_SEALED_TO_DEVICE` / `FAIL_CLOSED`); this shell never bypasses it.
//!
//! [ADR 0055]: ../../specs/decisions/0055-enrollment-handshake-protocol.md

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{ecdh::diffie_hellman, PublicKey as P256PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use gaugedesk_core::delegation::DeviceDelegation;
use gaugedesk_core::device_enrollment::{
    decide, evolve, Delegation, EnrollmentCommand, EnrollmentPhase, EnrollmentState, Seal,
};
use gaugedesk_core::ids::PublicKey;
use gaugedesk_core::signature::SigningKey;

use crate::at_rest::{Encryptor, LocalAeadEncryptor};

/// The out-of-band short authentication string: a collision-resistant commitment over the
/// rendezvous `session` **and** the device `subkey` ([ADR 0055] §2). Distinct subkeys yield
/// distinct SAS, so a relay-substituted subkey shows up as a mismatch the humans catch. The
/// length/encoding is a UX detail, not a safety variable (any collision-resistant commitment
/// satisfies the model) — six digits here, like Bluetooth numeric comparison.
pub fn device_sas(session: &str, subkey: &PublicKey) -> String {
    let mut h = Sha256::new();
    h.update(b"gaugewright/acct-1/sas/v1|");
    h.update(session.as_bytes());
    h.update(b"|");
    h.update(subkey.as_str().as_bytes());
    let d = h.finalize();
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
    format!("{n:06}")
}

/// The account key sealed to a device subkey (ECIES): an ephemeral P-256 public key + the
/// AES-256-GCM ciphertext. Only the holder of the subkey's private half re-derives the shared
/// secret and opens it; the relay sees only ciphertext (`INV-10`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedKey {
    /// The ephemeral SEC1 public key (hex) the recipient ECDHs against.
    pub ephemeral_pubkey: String,
    /// AES-256-GCM ciphertext (hex) under the ECDH-derived key.
    pub ciphertext: String,
}

/// Derive the symmetric key from the ECDH shared secret (domain-separated SHA-256).
fn derive_key(shared: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"gaugewright/acct-1/device-enroll/ecies/v1");
    h.update(shared);
    h.finalize().into()
}

/// Seal `plaintext` to `subkey_pub` (ECIES: fresh ephemeral ECDH → SHA-256 KDF → AES-256-GCM),
/// so only the holder of the subkey's private half can open it. `None` if `subkey_pub` is not
/// a valid P-256 point or the RNG/cipher fails.
pub fn seal_to_subkey(subkey_pub: &PublicKey, plaintext: &[u8]) -> Option<SealedKey> {
    let peer = P256PublicKey::from_sec1_bytes(&hex::decode(subkey_pub.as_str()).ok()?).ok()?;
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).ok()?;
    let eph = SecretKey::from_slice(&seed).ok()?;
    let shared = diffie_hellman(eph.to_nonzero_scalar(), peer.as_affine());
    let key = derive_key(shared.raw_secret_bytes().as_ref());
    let ct = LocalAeadEncryptor::new(key).encrypt(plaintext).ok()?;
    Some(SealedKey {
        ephemeral_pubkey: hex::encode(eph.public_key().to_encoded_point(false).as_bytes()),
        ciphertext: hex::encode(ct),
    })
}

/// Open a [`SealedKey`] with the subkey's private half (the inverse ECDH). `None` if the
/// ephemeral key is malformed or the ciphertext does not authenticate under the derived key
/// (a wrong subkey or a tampered blob fails closed).
pub fn open_sealed(subkey: &SigningKey, sealed: &SealedKey) -> Option<Vec<u8>> {
    let eph_pub =
        P256PublicKey::from_sec1_bytes(&hex::decode(&sealed.ephemeral_pubkey).ok()?).ok()?;
    let secret = SecretKey::from_slice(&subkey.to_seed_bytes()).ok()?;
    let shared = diffie_hellman(secret.to_nonzero_scalar(), eph_pub.as_affine());
    let key = derive_key(shared.raw_secret_bytes().as_ref());
    LocalAeadEncryptor::new(key)
        .decrypt(&hex::decode(&sealed.ciphertext).ok()?)
        .ok()
}

/// Message 1 (new device → relay → holder): the pairing request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub session: String,
    pub account_root: String,
    /// The new device's freshly-minted subkey (hex SEC1 public key).
    pub subkey: String,
}

/// Message 3 (holder → relay → new device): the authorization — a self-delegation + the
/// account key sealed to the confirmed subkey.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollAuthorize {
    pub delegation: DeviceDelegation,
    pub sealed_key: SealedKey,
}

/// Why the wire shell refused an enrollment step (fail-closed; the reducer owns the rest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrollError {
    SasMismatch,
    BadDelegation,
    ForeignRoot,
    NotOurSubkey,
    Unseal,
    Reducer(&'static str),
}

/// The new-device side: holds its minted subkey + what root/session it is joining.
pub struct NewDevice {
    pub subkey: SigningKey,
    pub session: String,
    pub account_root: String,
}

impl NewDevice {
    pub fn open(
        session: impl Into<String>,
        account_root: impl Into<String>,
        subkey: SigningKey,
    ) -> Self {
        Self {
            subkey,
            session: session.into(),
            account_root: account_root.into(),
        }
    }

    /// The subkey pubkey this device minted (what its SAS commits to).
    pub fn subkey_pubkey(&self) -> PublicKey {
        self.subkey.public_key()
    }

    /// Message 1 — open the pairing session.
    pub fn request(&self) -> EnrollRequest {
        EnrollRequest {
            session: self.session.clone(),
            account_root: self.account_root.clone(),
            subkey: self.subkey_pubkey().as_str().to_string(),
        }
    }

    /// This device's SAS — over its *real* subkey.
    pub fn sas(&self) -> String {
        device_sas(&self.session, &self.subkey_pubkey())
    }

    /// Message 4 — verify the authorization and unseal the account key. Fail-closed: the
    /// delegation must chain to the pinned root, be unexpired, bind *our* subkey, and the
    /// sealed key must open under our private subkey.
    pub fn complete(&self, auth: &EnrollAuthorize, now: u64) -> Result<[u8; 32], EnrollError> {
        auth.delegation
            .verify(now)
            .map_err(|_| EnrollError::BadDelegation)?;
        if auth.delegation.authority_root.as_str() != self.account_root {
            return Err(EnrollError::ForeignRoot);
        }
        if auth.delegation.subkey.as_str() != self.subkey_pubkey().as_str() {
            return Err(EnrollError::NotOurSubkey);
        }
        let bytes = open_sealed(&self.subkey, &auth.sealed_key).ok_or(EnrollError::Unseal)?;
        bytes.try_into().map_err(|_| EnrollError::Unseal)
    }
}

/// The holder side: holds the account root key + the account key to hand over.
pub struct Holder {
    pub root: SigningKey,
    pub account_key: [u8; 32],
    pub session: String,
}

impl Holder {
    pub fn new(root: SigningKey, account_key: [u8; 32], session: impl Into<String>) -> Self {
        Self {
            root,
            account_key,
            session: session.into(),
        }
    }

    /// The account root pubkey (the self-certifying identity the new device pins).
    pub fn account_root(&self) -> PublicKey {
        self.root.public_key()
    }

    /// The holder's SAS — over the *presented* subkey (whatever the relay delivered). The
    /// human compares this with the new device's SAS before authorizing.
    pub fn sas_for(&self, presented_subkey: &PublicKey) -> String {
        device_sas(&self.session, presented_subkey)
    }

    /// Message 3 — issue the self-delegation + seal the account key to the confirmed subkey.
    /// The caller invokes this only after the human confirms the SAS matches.
    pub fn authorize(&self, presented_subkey: &PublicKey, expiry: u64) -> Option<EnrollAuthorize> {
        let delegation = DeviceDelegation::issue(&self.root, presented_subkey.clone(), expiry);
        let sealed_key = seal_to_subkey(presented_subkey, &self.account_key)?;
        Some(EnrollAuthorize {
            delegation,
            sealed_key,
        })
    }
}

/// Run the full handshake through the reducer, with `relay` modeling the (untrusted) transport
/// — identity for an honest relay, or a substitution for an attacker. Returns the account key
/// the new device recovered (success) or the fail-closed reason. Every transition goes through
/// the pure reducer, so its safety properties gate the outcome.
pub fn run_enrollment(
    nd: &NewDevice,
    holder: &Holder,
    relay: impl Fn(PublicKey) -> PublicKey,
    expiry: u64,
    now: u64,
) -> Result<[u8; 32], EnrollError> {
    let mut state = EnrollmentState::default();
    let real_subkey = nd.subkey_pubkey();

    // 1. Request — the reducer records the device's *real* subkey.
    let req = nd.request();
    state = step(
        &state,
        EnrollmentCommand::RequestEnrollment {
            account_root: req.account_root.clone(),
            new_subkey: real_subkey.as_str().to_string(),
        },
    )?;

    // 2. Challenge — the holder sees whatever the relay delivered (possibly substituted).
    let presented = relay(real_subkey.clone());
    state = step(
        &state,
        EnrollmentCommand::ChallengeEnrollment {
            presented_subkey: presented.as_str().to_string(),
        },
    )?;

    // SAS comparison (the out-of-band human step). A substituted subkey fails here.
    if nd.sas() != holder.sas_for(&presented) {
        return Err(EnrollError::SasMismatch);
    }

    // 3. Authorize — self-delegation + sealed key for the presented (confirmed) subkey.
    let auth = holder
        .authorize(&presented, expiry)
        .ok_or(EnrollError::BadDelegation)?;
    state = step(
        &state,
        EnrollmentCommand::AuthorizeEnrollment {
            delegation: Delegation {
                subkey: auth.delegation.subkey.as_str().to_string(),
                root: auth.delegation.authority_root.as_str().to_string(),
            },
            seal: Seal {
                target_subkey: auth.delegation.subkey.as_str().to_string(),
                plaintext: false,
            },
        },
    )?;

    // 4. Complete — the new device verifies + unseals, then the reducer marks it enrolled.
    let recovered = nd.complete(&auth, now)?;
    state = step(&state, EnrollmentCommand::CompleteEnrollment)?;
    debug_assert_eq!(state.phase, EnrollmentPhase::Enrolled);

    Ok(recovered)
}

/// Drive one reducer command, folding the event(s) into the next state (fail-closed).
fn step(state: &EnrollmentState, cmd: EnrollmentCommand) -> Result<EnrollmentState, EnrollError> {
    let events = decide(state, cmd).map_err(|r| EnrollError::Reducer(r.reason))?;
    Ok(events.into_iter().fold(state.clone(), |s, e| evolve(&s, e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subkey(seed: u8) -> SigningKey {
        SigningKey::from_seed(&[seed; 32]).unwrap()
    }

    #[test]
    fn sas_distinguishes_distinct_subkeys() {
        let a = subkey(1).public_key();
        let b = subkey(2).public_key();
        assert_ne!(device_sas("sess", &a), device_sas("sess", &b));
        // Stable for the same inputs, and 6 digits.
        assert_eq!(device_sas("sess", &a), device_sas("sess", &a));
        assert_eq!(device_sas("sess", &a).len(), 6);
    }

    #[test]
    fn ecies_round_trips_only_for_the_right_subkey() {
        let device = subkey(5);
        let wrong = subkey(6);
        let secret = b"a-32-byte-account-key-payload!!!";
        let sealed = seal_to_subkey(&device.public_key(), secret).unwrap();
        assert_eq!(open_sealed(&device, &sealed).as_deref(), Some(&secret[..]));
        // A different subkey cannot open it (fail-closed AEAD under a different ECDH secret).
        assert_eq!(open_sealed(&wrong, &sealed), None);
        // A tampered ciphertext fails to authenticate.
        let mut bad = sealed.clone();
        bad.ciphertext.replace_range(0..2, "00");
        assert_eq!(open_sealed(&device, &bad), None);
    }

    #[test]
    fn honest_relay_enrolls_the_device_and_delivers_the_account_key() {
        let nd = NewDevice::open("sess-1", "", subkey(11));
        let holder = Holder::new(subkey(99), *b"ACCOUNT-KEY-32-bytes-exactly!!!!", "sess-1");
        // The new device joins the holder's actual root.
        let nd = NewDevice {
            account_root: holder.account_root().as_str().to_string(),
            ..nd
        };
        let recovered = run_enrollment(&nd, &holder, |k| k, 100, 1).expect("should enroll");
        assert_eq!(&recovered, b"ACCOUNT-KEY-32-bytes-exactly!!!!");
    }

    #[test]
    fn a_substituting_relay_is_caught_by_the_sas() {
        let nd = NewDevice::open("sess-2", "", subkey(11));
        let holder = Holder::new(subkey(99), *b"ACCOUNT-KEY-32-bytes-exactly!!!!", "sess-2");
        let nd = NewDevice {
            account_root: holder.account_root().as_str().to_string(),
            ..nd
        };
        let attacker = subkey(66).public_key();
        // The relay substitutes the attacker's subkey for the device's real one.
        let out = run_enrollment(&nd, &holder, |_| attacker.clone(), 100, 1);
        assert_eq!(out, Err(EnrollError::SasMismatch));
    }

    #[test]
    fn an_expired_delegation_is_refused_at_complete() {
        let nd = NewDevice::open("sess-3", "", subkey(11));
        let holder = Holder::new(subkey(99), *b"ACCOUNT-KEY-32-bytes-exactly!!!!", "sess-3");
        let nd = NewDevice {
            account_root: holder.account_root().as_str().to_string(),
            ..nd
        };
        // now >= expiry → the new device's verify() rejects.
        let out = run_enrollment(&nd, &holder, |k| k, 10, 10);
        assert_eq!(out, Err(EnrollError::BadDelegation));
    }
}
