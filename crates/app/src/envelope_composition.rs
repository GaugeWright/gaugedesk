//! Composing the supplied envelope set (ADR 0139 §5 layer 3 — SUPPLY-4).
//!
//! [`crate::envelope_supply`] derives *which* authorities govern a run and hands
//! over the roster and the composition record. This module is the consumption
//! half: it verifies each constituent's signature against that authority's
//! governance root and asks WhippleScript to compose them, so the run is checked
//! under the **meet** of the set rather than under one envelope.
//!
//! Composition itself is not implemented here and must not be. `whip`'s
//! `Composition::compose` owns the definition of a legal composition (ADR 0139
//! §6); a check that does not run inside it is advisory, and two definitions in
//! two repositories is what the shared cross-repository-artifact rule exists to
//! prevent. What this side owns is *authentication* — which key speaks for which
//! authority — because only the home holds the pinned roots.
//!
//! **Why the signed document has to be stored.** SUPPLY-2 registered envelopes as
//! `(authority, envelope_hash, epoch, signer)` on the reasoning that supply never
//! parses policy. That was right for supply and is not sufficient here:
//! `Composition::compose` takes `VerifiedEnvelope`s, and a hash cannot be
//! verified into one. So the registry carries the signed document too, and this
//! module is the only thing that reads it.

use gaugedesk_core::boundary::Authority;
use gaugedesk_core::ids::PublicKey;
use gaugedesk_core::signature::{verify_signature, Signature};
use whipplescript_kernel::gov::{ExternalAttestation, GovernanceAttestationVerifier};
use whipplescript_kernel::ifc::{Composition, CompositionEntry, VerifiedEnvelope};

/// Verifies a governance attestation against the **root** key bound to the
/// authority the signature itself names (ADR 0139 §3).
///
/// This is where SUPPLY-3's rule stops being a separate check and becomes part of
/// verification. A device subkey is not the root, so it cannot produce a
/// signature this accepts — there is no ordering in which a subkey-signed
/// envelope is admitted and then rejected.
///
/// The authority is read from the **attestation**, never from the envelope body
/// or from a caller argument: under `:v2` the authority is inside the signed
/// preimage, so taking it from anywhere else would authenticate the signer
/// without authenticating whose policy it is.
pub struct GovernanceRootVerifier<F> {
    root_key_of: F,
}

impl<F> GovernanceRootVerifier<F>
where
    F: Fn(&Authority) -> Option<PublicKey>,
{
    pub fn new(root_key_of: F) -> Self {
        Self { root_key_of }
    }
}

impl<F> GovernanceAttestationVerifier for GovernanceRootVerifier<F>
where
    F: Fn(&Authority) -> Option<PublicKey>,
{
    fn verify(
        &self,
        signing_bytes: &[u8],
        attestation: &ExternalAttestation,
    ) -> Result<(), String> {
        // `:v1` carries no authority, so there is nothing to resolve a root
        // against. Refused rather than verified against a guessed key.
        let Some(named) = attestation.authority.as_deref() else {
            return Err(
                "a composed set admits only :v2 envelopes, whose signature covers the authority"
                    .to_owned(),
            );
        };
        if attestation.algorithm != "p256-sha256" {
            return Err(format!(
                "unsupported governance signature algorithm {:?}",
                attestation.algorithm
            ));
        }
        let authority = Authority::new(named);
        let Some(root) = (self.root_key_of)(&authority) else {
            return Err(format!("no governance root key is bound to {authority}"));
        };
        let bytes = hex::decode(&attestation.signature)
            .map_err(|_| "the governance signature is not valid hex".to_owned())?;
        match verify_signature(signing_bytes, &Signature::new(bytes), &root) {
            Ok(true) => Ok(()),
            Ok(false) => Err(format!(
                "the envelope for {authority} is not signed by that authority's governance root \
                 — a device subkey does not author policy"
            )),
            Err(error) => Err(format!(
                "governance signature check failed: {}",
                error.reason
            )),
        }
    }
}

/// Why a supplied set could not be composed. Every variant refuses the run: the
/// meet is the third restrict-only layer at admission, and a layer that cannot be
/// evaluated must not be skipped (ADR 0139 §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompositionRefusal {
    /// One constituent's document failed to verify, or is not `:v2`, or is not
    /// signed by its authority's governance root.
    Unverified {
        authority: Authority,
        reason: String,
    },
    /// The set verified individually but is not a legal composition. The message
    /// is `whip`'s, unmodified — it names the tripped constraint, and rewording
    /// it here would put a second account of legality on this side.
    Illegal(String),
}

impl std::fmt::Display for CompositionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unverified { authority, reason } => {
                write!(
                    f,
                    "the envelope supplied for {authority} did not verify: {reason}"
                )
            }
            Self::Illegal(reason) => {
                write!(f, "the supplied envelope set is not composable: {reason}")
            }
        }
    }
}

impl std::error::Error for CompositionRefusal {}

/// One constituent as this side holds it: the signed document, plus the authority
/// it is registered under so a refusal can name it before verification has
/// established anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedConstituent {
    pub authority: Authority,
    pub signed_document: String,
}

/// Verify every constituent against its authority's governance root and compose
/// the set, yielding the [`Composition`] the crossing is evaluated against.
///
/// `record` is the composition record assembled by
/// [`crate::envelope_supply::assemble`] — passed through unchanged, because
/// `compose` cross-checks it against the signatures itself (it refuses a record
/// that names an authority twice, at the wrong epoch, or for a different
/// envelope). Re-deriving it here would substitute this side's reading of the
/// signatures for the checker's.
pub fn compose(
    constituents: &[SignedConstituent],
    record: Vec<CompositionEntry>,
    root_key_of: impl Fn(&Authority) -> Option<PublicKey>,
) -> Result<Composition, CompositionRefusal> {
    let verifier = GovernanceRootVerifier::new(root_key_of);
    let mut verified = Vec::with_capacity(constituents.len());
    for constituent in constituents {
        let envelope =
            VerifiedEnvelope::verify_signed_text_with(&constituent.signed_document, &verifier)
                .map_err(|reason| CompositionRefusal::Unverified {
                    authority: constituent.authority.clone(),
                    reason,
                })?;
        verified.push(envelope);
    }
    Composition::compose(verified, record).map_err(CompositionRefusal::Illegal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(name: &str) -> Authority {
        Authority::new(name)
    }

    fn attestation(
        authority: Option<&str>,
        algorithm: &str,
        signature: &str,
    ) -> ExternalAttestation {
        ExternalAttestation {
            algorithm: algorithm.into(),
            key_id: "gov-1".into(),
            signature: signature.into(),
            epoch: Some(7),
            authority: authority.map(str::to_string),
        }
    }

    /// `:v1` has no authority in the preimage, so there is no root to resolve.
    #[test]
    fn a_v1_attestation_is_refused_rather_than_verified_against_a_guess() {
        let verifier =
            GovernanceRootVerifier::new(|_: &Authority| Some(PublicKey::new("04deadbeef")));
        let error = verifier
            .verify(b"bytes", &attestation(None, "p256-sha256", "00"))
            .expect_err("refuses");
        assert!(error.contains(":v2"), "{error}");
    }

    #[test]
    fn an_unbound_authority_is_refused() {
        let verifier = GovernanceRootVerifier::new(|_: &Authority| None);
        let error = verifier
            .verify(b"bytes", &attestation(Some("acme"), "p256-sha256", "00"))
            .expect_err("refuses");
        assert!(
            error.contains("no governance root key is bound to acme"),
            "{error}"
        );
    }

    #[test]
    fn an_unknown_algorithm_is_refused_before_any_key_lookup() {
        let looked_up = std::cell::Cell::new(false);
        let verifier = GovernanceRootVerifier::new(|_: &Authority| {
            looked_up.set(true);
            None
        });
        let error = verifier
            .verify(b"bytes", &attestation(Some("acme"), "ed25519", "00"))
            .expect_err("refuses");
        assert!(error.contains("unsupported"), "{error}");
        assert!(!looked_up.get(), "an unsupported algorithm short-circuits");
    }

    /// The tooth SUPPLY-3 exists for, now inside verification rather than beside
    /// it: a key that is not the authority's root cannot produce an accepted
    /// signature, whatever else is well-formed.
    #[test]
    fn a_signature_from_a_non_root_key_is_refused() {
        use gaugedesk_core::signature::SigningKey;
        let subkey = SigningKey::from_seed(&[7u8; 32]).expect("valid scalar");
        let root = SigningKey::from_seed(&[9u8; 32]).expect("valid scalar");
        let signed = subkey.sign(b"preimage");
        let verifier = GovernanceRootVerifier::new(move |_: &Authority| Some(root.public_key()));
        let error = verifier
            .verify(
                b"preimage",
                &attestation(Some("acme"), "p256-sha256", &hex::encode(signed.as_bytes())),
            )
            .expect_err("refuses a subkey signature");
        assert!(error.contains("governance root"), "{error}");
    }

    /// And the positive direction, so the refusal above is discrimination rather
    /// than a verifier that rejects everything.
    #[test]
    fn a_signature_from_the_root_verifies() {
        use gaugedesk_core::signature::SigningKey;
        let root = SigningKey::from_seed(&[9u8; 32]).expect("valid scalar");
        let signed = root.sign(b"preimage");
        let public = root.public_key();
        let verifier = GovernanceRootVerifier::new(move |_: &Authority| Some(public.clone()));
        verifier
            .verify(
                b"preimage",
                &attestation(Some("acme"), "p256-sha256", &hex::encode(signed.as_bytes())),
            )
            .expect("the root's own signature verifies");
    }

    /// An unsigned document never reaches `Composition::compose`, and the refusal
    /// names which authority's envelope was at fault.
    #[test]
    fn an_unsigned_document_refuses_and_names_its_authority() {
        let constituents = [SignedConstituent {
            authority: authority("acme"),
            signed_document: r#"{"readers":{}}"#.into(),
        }];
        let refusal = match compose(&constituents, Vec::new(), |_| {
            Some(PublicKey::new("04deadbeef"))
        }) {
            Ok(_) => panic!("an unsigned document must not compose"),
            Err(refusal) => refusal,
        };
        match refusal {
            CompositionRefusal::Unverified { authority: a, .. } => assert_eq!(a, authority("acme")),
            other => panic!("expected Unverified, got {other:?}"),
        }
    }

    /// The empty set composes: no envelope is no claim, which is the ungoverned
    /// posture and must not become a refusal.
    #[test]
    fn the_empty_set_composes() {
        let Ok(composition) = compose(&[], Vec::new(), |_| None) else {
            panic!("no envelope is no claim; the empty set must compose");
        };
        assert!(composition.record().is_empty());
    }
}
