//! Device subkey delegation — Model A authority identity (ADR 0039;
//! `remote-substrate.md` "Authority identity & keys").
//!
//! An authority's **stable public identity is its root key**. Each device holds a
//! short-lived **subkey** the root signs into a delegation: *"this subkey acts for
//! authority `<root>` until `<expiry>`"*. Federated envelopes are then signed by the
//! **subkey**, and a verifier checks two links: the delegation chains to the known
//! root (signed by it, unexpired), and the envelope verifies under the delegated
//! subkey. The single-key slice (no delegation) stays valid — a delegation is an
//! *optional* upgrade that does not change the authority's pinned root.
//!
//! **Multi-device / per-device revocation** falls out for free: add a device by
//! issuing it a subkey; revoke one by letting its subkey expire (or, durably, by a
//! root-signed revocation pushed over the bridge — deferred with the broader
//! revocation-distribution story). The authority's pinned root is unchanged either
//! way, so peers keep trusting the authority across device churn.

use crate::ids::PublicKey;
use crate::signature::{verify_signature, Signature, SigningKey};

/// A root-signed statement binding a device `subkey` to an `authority_root` until
/// `expiry`. The signature is over [`delegation_bytes`] under the root key; the
/// inner fields are the claim, trusted only after [`DeviceDelegation::verify`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeviceDelegation {
    /// The device subkey this delegation authorizes (the envelope's actual signer).
    pub subkey: PublicKey,
    /// The authority root that issued (signed) the delegation — must equal the
    /// grant's pinned `source_authority_root_pubkey` for a crossing to admit (C-1).
    pub authority_root: PublicKey,
    /// The clock value at/after which the delegation is no longer valid.
    pub expiry: u64,
    /// The root's signature over [`delegation_bytes`].
    pub signature: Signature,
}

/// The canonical bytes a delegation's root signs — a versioned, unambiguous binding
/// of (root, subkey, expiry) so both sides hash identical bytes and a delegation
/// for one (subkey, expiry) cannot be replayed as another.
pub fn delegation_bytes(subkey: &PublicKey, authority_root: &PublicKey, expiry: u64) -> Vec<u8> {
    format!(
        "gaugewright-device-delegation::v1::root={}::sub={}::exp={}",
        authority_root.as_str(),
        subkey.as_str(),
        expiry
    )
    .into_bytes()
}

/// Why a delegation was refused (fail-closed): it was not signed by the claimed
/// root, or it has expired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelegationRejection {
    /// The signature does not verify under the claimed `authority_root`.
    BadSignature,
    /// The delegation is expired at the admission clock.
    Expired,
}

impl DeviceDelegation {
    /// Issue a delegation: the **root** signs the binding of `subkey` to itself
    /// until `expiry`. The root key lives in the shell's key store and never leaves
    /// it; only this signed statement crosses the wire.
    pub fn issue(root: &SigningKey, subkey: PublicKey, expiry: u64) -> Self {
        let authority_root = root.public_key();
        let bytes = delegation_bytes(&subkey, &authority_root, expiry);
        let signature = root.sign(&bytes);
        Self {
            subkey,
            authority_root,
            expiry,
            signature,
        }
    }

    /// Verify the delegation at `now`: its signature must verify under its claimed
    /// `authority_root`, and it must not be expired. Fail-closed — anything but a
    /// valid, unexpired, correctly-signed delegation is refused.
    pub fn verify(&self, now: u64) -> Result<(), DelegationRejection> {
        if now >= self.expiry {
            return Err(DelegationRejection::Expired);
        }
        let bytes = delegation_bytes(&self.subkey, &self.authority_root, self.expiry);
        match verify_signature(&bytes, &self.signature, &self.authority_root) {
            Ok(true) => Ok(()),
            _ => Err(DelegationRejection::BadSignature),
        }
    }
}

/// A root-signed statement **revoking** a device subkey before its delegation
/// expires (Model A / `remote-substrate.md` "Open"). With no directory, peers learn
/// of a revoked key only via these statements pushed over the existing bridge: a
/// peer that has pinned the authority's root verifies the revocation under it and
/// then refuses any crossing presenting the revoked subkey — so a lost or
/// compromised device is cut off immediately, not at delegation expiry.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SubkeyRevocation {
    /// The device subkey being revoked.
    pub subkey: PublicKey,
    /// The authority root that issued (signed) the revocation — must equal the
    /// grant's pinned root for a peer to honor it.
    pub authority_root: PublicKey,
    /// When the revocation was issued (audit/ordering; revocations never expire).
    pub issued_at: u64,
    /// The root's signature over [`revocation_bytes`].
    pub signature: Signature,
}

/// The canonical bytes a revocation's root signs — distinct from [`delegation_bytes`]
/// (a different `v1` tag) so a delegation can never be replayed as a revocation or
/// vice-versa.
pub fn revocation_bytes(subkey: &PublicKey, authority_root: &PublicKey, issued_at: u64) -> Vec<u8> {
    format!(
        "gaugewright-subkey-revocation::v1::root={}::sub={}::at={}",
        authority_root.as_str(),
        subkey.as_str(),
        issued_at
    )
    .into_bytes()
}

impl SubkeyRevocation {
    /// Issue a revocation: the **root** signs the revocation of `subkey`.
    pub fn issue(root: &SigningKey, subkey: PublicKey, issued_at: u64) -> Self {
        let authority_root = root.public_key();
        let bytes = revocation_bytes(&subkey, &authority_root, issued_at);
        let signature = root.sign(&bytes);
        Self {
            subkey,
            authority_root,
            issued_at,
            signature,
        }
    }

    /// Verify the revocation was signed by its claimed `authority_root` (revocations
    /// do not expire). Fail-closed.
    pub fn verify(&self) -> Result<(), DelegationRejection> {
        let bytes = revocation_bytes(&self.subkey, &self.authority_root, self.issued_at);
        match verify_signature(&bytes, &self.signature, &self.authority_root) {
            Ok(true) => Ok(()),
            _ => Err(DelegationRejection::BadSignature),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> SigningKey {
        SigningKey::from_seed(&[3u8; 32]).unwrap()
    }
    fn subkey() -> SigningKey {
        SigningKey::from_seed(&[4u8; 32]).unwrap()
    }

    /// Finite fixture domain paired with delegation-admission.qnt; signatures
    /// are actual P256, not a synthetic "valid" boolean. Not a crypto proof.
    #[test]
    fn crypto_model_domain_delegation() {
        let roots = [root(), SigningKey::from_seed(&[9; 32]).unwrap()];
        let subkeys = [
            subkey().public_key(),
            SigningKey::from_seed(&[7; 32]).unwrap().public_key(),
        ];
        let claimed_roots = [
            roots[0].public_key(),
            roots[1].public_key(),
            PublicKey::new("malformed"),
        ];
        let bytes = delegation_bytes(&subkeys[0], &claimed_roots[0], 1);
        for (root_id, claimed_root) in claimed_roots.iter().enumerate() {
            for (subkey_id, presented_subkey) in subkeys.iter().enumerate() {
                for expiry in 0..=2 {
                    for (signer_id, signer) in roots.iter().enumerate() {
                        for malformed in [false, true] {
                            let d = DeviceDelegation {
                                authority_root: claimed_root.clone(),
                                subkey: presented_subkey.clone(),
                                expiry,
                                signature: if malformed {
                                    Signature::new(vec![0; 3])
                                } else {
                                    signer.sign(&bytes)
                                },
                            };
                            for now in 0..=2 {
                                let expected = if now >= expiry {
                                    Err(DelegationRejection::Expired)
                                } else if root_id == 0
                                    && subkey_id == 0
                                    && expiry == 1
                                    && signer_id == 0
                                    && !malformed
                                {
                                    Ok(())
                                } else {
                                    Err(DelegationRejection::BadSignature)
                                };
                                assert_eq!(d.verify(now), expected, "root={root_id} subkey={subkey_id} expiry={expiry} signer={signer_id} malformed={malformed} now={now}");
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_genuine_revocation_verifies_and_a_forged_one_is_refused() {
        let r = SubkeyRevocation::issue(&root(), subkey().public_key(), 42);
        assert_eq!(r.authority_root, root().public_key());
        assert_eq!(r.verify(), Ok(()));

        // Signed by an attacker but claiming the victim's root → refused.
        let attacker = SigningKey::from_seed(&[9u8; 32]).unwrap();
        let bytes = revocation_bytes(&subkey().public_key(), &root().public_key(), 42);
        let forged = SubkeyRevocation {
            subkey: subkey().public_key(),
            authority_root: root().public_key(),
            issued_at: 42,
            signature: attacker.sign(&bytes),
        };
        assert_eq!(forged.verify(), Err(DelegationRejection::BadSignature));

        // Tampering with the revoked subkey breaks the signature.
        let mut tampered = SubkeyRevocation::issue(&root(), subkey().public_key(), 42);
        tampered.subkey = SigningKey::from_seed(&[8u8; 32]).unwrap().public_key();
        assert_eq!(tampered.verify(), Err(DelegationRejection::BadSignature));
    }

    #[test]
    fn a_genuine_delegation_verifies_before_expiry() {
        let d = DeviceDelegation::issue(&root(), subkey().public_key(), 100);
        assert_eq!(d.authority_root, root().public_key());
        assert_eq!(d.verify(50), Ok(()));
    }

    #[test]
    fn an_expired_delegation_is_refused() {
        let d = DeviceDelegation::issue(&root(), subkey().public_key(), 100);
        assert_eq!(d.verify(100), Err(DelegationRejection::Expired));
        assert_eq!(d.verify(200), Err(DelegationRejection::Expired));
    }

    #[test]
    fn a_delegation_signed_by_a_non_root_key_is_refused() {
        // An attacker self-issues a delegation for some subkey under THEIR own key,
        // then claims it is the victim's root — the claimed root did not sign it.
        let attacker = SigningKey::from_seed(&[9u8; 32]).unwrap();
        let victim_root = root().public_key();
        let bytes = delegation_bytes(&subkey().public_key(), &victim_root, 100);
        let forged = DeviceDelegation {
            subkey: subkey().public_key(),
            authority_root: victim_root,
            expiry: 100,
            signature: attacker.sign(&bytes), // signed by the attacker, not the root
        };
        assert_eq!(forged.verify(50), Err(DelegationRejection::BadSignature));
    }

    #[test]
    fn tampering_with_the_bound_subkey_breaks_the_signature() {
        let mut d = DeviceDelegation::issue(&root(), subkey().public_key(), 100);
        // Swap in a different subkey the root never delegated to.
        d.subkey = SigningKey::from_seed(&[7u8; 32]).unwrap().public_key();
        assert_eq!(d.verify(50), Err(DelegationRejection::BadSignature));
    }

    #[test]
    fn extending_the_expiry_breaks_the_signature() {
        let mut d = DeviceDelegation::issue(&root(), subkey().public_key(), 100);
        d.expiry = 10_000; // a longer life the root never signed for
        assert_eq!(d.verify(50), Err(DelegationRejection::BadSignature));
    }
}
