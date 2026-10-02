//! Pinned-TLS egress policy for an attested host (D-ATTEST / ADR 0040, ATTEST-11).
//!
//! An *attested* placement runs the method inside a confidential VM whose code is
//! measured (`attestation.rs`). For the host-blind ceiling to hold, the VM's
//! outbound traffic must be just as constrained as its loaded code: it may reach
//! **only** the model endpoint it was attested to talk to, over a connection
//! whose server certificate matches a **pin** carried in the policy. An attested
//! VM that could open an arbitrary TLS connection could exfiltrate the very
//! method/data the attestation is meant to keep host-blind — so egress is
//! pinned, fail-closed, exactly as the federation relay pins peer certificates
//! (`net_server.rs` `CERT-PIN-1`), but here it governs the model provider rather
//! than another authority.
//!
//! These are pure domain types — never a bare `Vec<u8>`/`String` in the domain
//! (`principles.md` "Contracts at the boundary"). [`verify_cert_chain`] is a pure
//! predicate, the loopback counterpart of [`crate::signature::verify_signature`]:
//! the imperative shell ferries the presented chain in, the core decides
//! accept/reject with no I/O. Real certificate-chain validation (SAN match, time
//! bounds, chain-to-root) attaches behind this same seam under `D-CRYPTO` /
//! confidential-inference infra with no change to the policy wiring here.

/// A pinned server certificate: the fingerprint an attested host compares a
/// presented certificate against before trusting an egress connection.
///
/// The bytes are an opaque fingerprint of the certificate (e.g. SHA-256 of its
/// DER) — private so callers construct via [`PinnedCertificate::new`] and compare
/// by value (`==`), the only operation the egress policy needs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PinnedCertificate(Vec<u8>);

impl PinnedCertificate {
    /// Construct from an already-collected certificate fingerprint (computed at
    /// the boundary from the provider's leaf certificate).
    pub fn new(fingerprint: impl Into<Vec<u8>>) -> Self {
        Self(fingerprint.into())
    }

    /// The pinned fingerprint bytes.
    pub fn fingerprint(&self) -> &[u8] {
        &self.0
    }

    /// Whether the pin carries no fingerprint bytes at all (an empty pin trusts
    /// nothing — every chain is refused, fail-closed).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The egress policy for an attested host: the single model endpoint it is
/// permitted to reach and the [`PinnedCertificate`] that endpoint must present.
///
/// An attested VM consults this before dialing: the host name must match
/// `model_endpoint` and the presented certificate chain must pin to
/// `pinned_certificate`. Any other destination, or a chain that does not match
/// the pin, is refused — the host stays blind to the method and the data cannot
/// leave through an unpinned connection.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttestedModelEgress {
    /// The only endpoint host this attested placement may reach (e.g. the model
    /// provider's inference host).
    model_endpoint: String,
    /// The certificate that endpoint must present for the connection to be
    /// trusted.
    pinned_certificate: PinnedCertificate,
}

/// Why an attested-host egress connection was refused before any application
/// traffic flowed — every variant is fail-closed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EgressRejection {
    /// The dialed host is not the endpoint this policy permits (the attested VM
    /// may reach only its one attested model endpoint).
    EndpointNotAllowed { dialed: String },
    /// The host matched but the presented certificate chain did not pin to the
    /// expected certificate (a possible interception — fail closed).
    CertificateNotPinned,
    /// The presented chain was malformed or empty in a way that prevents a
    /// verdict (no certificate to compare against the pin).
    MalformedChain,
    /// The leaf certificate's subject-alternative-names do not cover the endpoint
    /// host the policy permits (the pinned cert is for a different name).
    SanMismatch { endpoint: String },
    /// The connection time is outside the leaf certificate's validity window —
    /// before `not_before` or at/after `not_after`.
    CertificateExpired,
}

/// The **parsed** view of a presented leaf certificate that the imperative shell
/// extracts (with a vetted X.509/DER parser at the boundary — never hand-rolled in
/// the pure core) and hands to [`AttestedModelEgress::admit_leaf`] for the policy
/// decision. The bytes-level parse is the live-TLS-membrane's job (D-CRYPTO); the
/// SAN-match and validity-window *decision* over the parsed fields is pure here.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LeafCertificate {
    /// The leaf's subject-alternative-name DNS entries (lowercased at the
    /// boundary). The endpoint host must be covered by one of these.
    pub subject_alt_names: Vec<String>,
    /// `notBefore` as unix epoch seconds — the connection clock must be ≥ this.
    pub not_before: u64,
    /// `notAfter` as unix epoch seconds — the connection clock must be < this.
    pub not_after: u64,
}

impl LeafCertificate {
    /// Whether `host` is covered by one of the SANs — an exact match, or a single
    /// leftmost-label wildcard (`*.example.com` covers `a.example.com` but not
    /// `example.com` nor `a.b.example.com`), the same shape the TLS RFC permits.
    pub fn covers_host(&self, host: &str) -> bool {
        self.subject_alt_names
            .iter()
            .any(|san| san_matches(san, host))
    }

    /// Whether the connection clock `now` is within `[not_before, not_after)`.
    pub fn valid_at(&self, now: u64) -> bool {
        now >= self.not_before && now < self.not_after
    }
}

/// One SAN-vs-host match: exact, or a single leftmost `*.` wildcard label.
fn san_matches(san: &str, host: &str) -> bool {
    if let Some(suffix) = san.strip_prefix("*.") {
        // `*.example.com` matches exactly one extra leftmost label.
        match host.split_once('.') {
            Some((_label, rest)) => rest == suffix && !rest.is_empty(),
            None => false,
        }
    } else {
        san == host
    }
}

impl AttestedModelEgress {
    /// Construct an egress policy permitting exactly `model_endpoint`, pinned to
    /// `pinned_certificate`.
    pub fn new(model_endpoint: impl Into<String>, pinned_certificate: PinnedCertificate) -> Self {
        Self {
            model_endpoint: model_endpoint.into(),
            pinned_certificate,
        }
    }

    /// The single endpoint host this policy permits.
    pub fn model_endpoint(&self) -> &str {
        &self.model_endpoint
    }

    /// The certificate that endpoint must present.
    pub fn pinned_certificate(&self) -> &PinnedCertificate {
        &self.pinned_certificate
    }

    /// Decide whether an attested host may complete an egress connection to
    /// `dialed_host` that presented `presented_chain`.
    ///
    /// Pure: no I/O, deterministic in its arguments. The connection is permitted
    /// only when the dialed host is exactly the allowed endpoint *and* the
    /// presented chain verifies against the pinned certificate. Any other case
    /// returns a structured [`EgressRejection`] — fail-closed.
    pub fn admit(
        &self,
        dialed_host: &str,
        presented_chain: &[PinnedCertificate],
    ) -> Result<(), EgressRejection> {
        if dialed_host != self.model_endpoint {
            return Err(EgressRejection::EndpointNotAllowed {
                dialed: dialed_host.to_string(),
            });
        }
        verify_cert_chain(presented_chain, &self.pinned_certificate)
    }

    /// Decide egress with the **parsed leaf** in hand (`CORE-1`): in addition to the
    /// endpoint and pin checks of [`Self::admit`], verify the leaf certificate's SAN
    /// covers the endpoint host and the connection clock `now` is within the leaf's
    /// validity window. Pure, fail-closed, and ordered so a name/time failure is
    /// reported before the pin. The DER parse that produces `leaf`, and chain-to-root
    /// signature verification, remain the live-TLS-membrane's job (D-CRYPTO).
    pub fn admit_leaf(
        &self,
        dialed_host: &str,
        leaf: &LeafCertificate,
        now: u64,
        presented_chain: &[PinnedCertificate],
    ) -> Result<(), EgressRejection> {
        if dialed_host != self.model_endpoint {
            return Err(EgressRejection::EndpointNotAllowed {
                dialed: dialed_host.to_string(),
            });
        }
        if !leaf.covers_host(&self.model_endpoint) {
            return Err(EgressRejection::SanMismatch {
                endpoint: self.model_endpoint.clone(),
            });
        }
        if !leaf.valid_at(now) {
            return Err(EgressRejection::CertificateExpired);
        }
        verify_cert_chain(presented_chain, &self.pinned_certificate)
    }
}

/// Verify a presented certificate `chain` against a [`PinnedCertificate`]
/// (ATTEST-11).
///
/// Pure: no I/O, deterministic in its arguments. The connection is accepted only
/// when the chain's leaf (its first certificate) matches the pin by value.
///
// The SAN-match and validity-window *decision* is now real and pure — see
// [`AttestedModelEgress::admit_leaf`] / [`LeafCertificate`], which the boundary
// calls with a parsed leaf. This fingerprint-pin function remains the loopback
// pin check.
//
// Remaining (D-CRYPTO / confidential-inference, needs-infra): the **byte-level**
// work that must use a vetted X.509 verifier in the live TLS membrane, never a
// hand-rolled parser in this pure core — DER-parse each certificate to produce
// the [`LeafCertificate`] view, and verify the chain links up to a trusted root.
// Both attach at the boundary with no change to the policy decisions here.
pub fn verify_cert_chain(
    chain: &[PinnedCertificate],
    pin: &PinnedCertificate,
) -> Result<(), EgressRejection> {
    let Some(leaf) = chain.first() else {
        return Err(EgressRejection::MalformedChain);
    };
    if pin.is_empty() || leaf != pin {
        return Err(EgressRejection::CertificateNotPinned);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cbor_round_trip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).unwrap();
        ciborium::from_reader(bytes.as_slice()).unwrap()
    }

    fn pin() -> PinnedCertificate {
        PinnedCertificate::new(vec![0xaa; 32])
    }

    fn policy() -> AttestedModelEgress {
        AttestedModelEgress::new("inference.model.example", pin())
    }

    /// Complete host/pin/ordered-chain domain from pinned-tls-admission.qnt.
    /// No DER, SAN, validity-time, network, or admit_leaf claim is made here.
    #[test]
    fn crypto_model_domain_pinned_tls() {
        let pins = [
            PinnedCertificate::new(Vec::<u8>::new()),
            PinnedCertificate::new(vec![1; 32]),
            PinnedCertificate::new(vec![2; 32]),
        ];
        let chains = [vec![], vec![0], vec![1], vec![2], vec![1, 2], vec![2, 1]];
        for host in ["A", "B"] {
            for (pin_id, pin) in pins.iter().enumerate() {
                let policy = AttestedModelEgress::new("A", pin.clone());
                for chain_ids in &chains {
                    let chain: Vec<_> = chain_ids.iter().map(|id| pins[*id].clone()).collect();
                    let expected = host == "A"
                        && match pin_id {
                            1 => chain_ids == &[1] || chain_ids == &[1, 2],
                            2 => chain_ids == &[2] || chain_ids == &[2, 1],
                            _ => false,
                        };
                    assert_eq!(
                        policy.admit(host, &chain).is_ok(),
                        expected,
                        "host={host} pin={pin_id} chain={chain_ids:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn pinned_certificate_compares_by_value() {
        assert_eq!(pin(), PinnedCertificate::new(vec![0xaa; 32]));
        assert_ne!(pin(), PinnedCertificate::new(vec![0xbb; 32]));
        assert_eq!(pin().fingerprint(), &[0xaa; 32]);
        assert!(!pin().is_empty());
        assert!(PinnedCertificate::new(Vec::<u8>::new()).is_empty());
    }

    /// A chain whose leaf matches the pin verifies.
    #[test]
    fn chain_with_pinned_leaf_verifies() {
        assert_eq!(verify_cert_chain(&[pin()], &pin()), Ok(()));
        // Intermediates after the leaf are ignored by the stub.
        let chain = vec![pin(), PinnedCertificate::new(vec![0xcc; 32])];
        assert_eq!(verify_cert_chain(&chain, &pin()), Ok(()));
    }

    /// A chain whose leaf does not match the pin is refused (fail-closed).
    #[test]
    fn chain_with_unpinned_leaf_refused() {
        let chain = vec![PinnedCertificate::new(vec![0xbb; 32])];
        assert_eq!(
            verify_cert_chain(&chain, &pin()),
            Err(EgressRejection::CertificateNotPinned),
        );
    }

    /// An empty chain has no leaf to compare — malformed, refused.
    #[test]
    fn empty_chain_is_malformed() {
        assert_eq!(
            verify_cert_chain(&[], &pin()),
            Err(EgressRejection::MalformedChain)
        );
    }

    /// An empty pin trusts nothing — even a matching empty leaf is refused.
    #[test]
    fn empty_pin_refuses_every_chain() {
        let empty = PinnedCertificate::new(Vec::<u8>::new());
        assert_eq!(
            verify_cert_chain(std::slice::from_ref(&empty), &empty),
            Err(EgressRejection::CertificateNotPinned),
        );
    }

    /// The policy admits a connection to the allowed endpoint with a pinned leaf.
    #[test]
    fn policy_admits_allowed_endpoint_with_pinned_cert() {
        assert_eq!(policy().admit("inference.model.example", &[pin()]), Ok(()));
    }

    /// The policy refuses any other endpoint, even with a valid pinned cert — the
    /// attested host may reach only its one attested model endpoint.
    #[test]
    fn policy_refuses_other_endpoint() {
        assert_eq!(
            policy().admit("evil.example", &[pin()]),
            Err(EgressRejection::EndpointNotAllowed {
                dialed: "evil.example".to_string()
            }),
        );
    }

    /// The policy refuses the allowed endpoint when the presented cert is not
    /// pinned (a possible interception).
    #[test]
    fn policy_refuses_allowed_endpoint_with_wrong_cert() {
        let wrong = vec![PinnedCertificate::new(vec![0xbb; 32])];
        assert_eq!(
            policy().admit("inference.model.example", &wrong),
            Err(EgressRejection::CertificateNotPinned),
        );
    }

    #[test]
    fn policy_exposes_its_endpoint_and_pin() {
        let p = policy();
        assert_eq!(p.model_endpoint(), "inference.model.example");
        assert_eq!(p.pinned_certificate(), &pin());
    }

    #[test]
    fn policy_serde_round_trips() {
        let p = policy();
        assert_eq!(cbor_round_trip(&p), p);
    }

    #[test]
    fn rejection_serde_round_trips() {
        let r = EgressRejection::EndpointNotAllowed {
            dialed: "x".to_string(),
        };
        assert_eq!(cbor_round_trip(&r), r);
    }

    // --- CORE-1: parsed-leaf SAN + validity-window decision -------------------

    fn leaf(sans: &[&str], not_before: u64, not_after: u64) -> LeafCertificate {
        LeafCertificate {
            subject_alt_names: sans.iter().map(|s| s.to_string()).collect(),
            not_before,
            not_after,
        }
    }

    #[test]
    fn san_exact_and_wildcard_matching() {
        let l = leaf(&["inference.model.example", "*.api.example"], 0, 100);
        assert!(l.covers_host("inference.model.example")); // exact
        assert!(l.covers_host("v1.api.example")); // single-label wildcard
        assert!(!l.covers_host("api.example")); // wildcard does NOT match the apex
        assert!(!l.covers_host("a.b.api.example")); // nor more than one label
        assert!(!l.covers_host("other.example")); // unrelated host
    }

    #[test]
    fn validity_window_is_half_open() {
        let l = leaf(&["h"], 10, 20);
        assert!(!l.valid_at(9)); // before not_before
        assert!(l.valid_at(10)); // inclusive lower bound
        assert!(l.valid_at(19));
        assert!(!l.valid_at(20)); // exclusive upper bound (expired)
    }

    #[test]
    fn admit_leaf_happy_path() {
        let l = leaf(&["inference.model.example"], 0, 100);
        assert_eq!(
            policy().admit_leaf("inference.model.example", &l, 50, &[pin()]),
            Ok(())
        );
    }

    #[test]
    fn admit_leaf_refuses_san_mismatch_before_time_or_pin() {
        // The pinned cert is for a different name than the endpoint — refused on SAN,
        // even though the pin and time would pass.
        let wrong_name = leaf(&["evil.example"], 0, 100);
        assert_eq!(
            policy().admit_leaf("inference.model.example", &wrong_name, 50, &[pin()]),
            Err(EgressRejection::SanMismatch {
                endpoint: "inference.model.example".to_string()
            }),
        );
    }

    #[test]
    fn admit_leaf_refuses_outside_validity_window() {
        let l = leaf(&["inference.model.example"], 10, 20);
        assert_eq!(
            policy().admit_leaf("inference.model.example", &l, 25, &[pin()]),
            Err(EgressRejection::CertificateExpired),
        );
        assert_eq!(
            policy().admit_leaf("inference.model.example", &l, 5, &[pin()]),
            Err(EgressRejection::CertificateExpired),
        );
    }

    #[test]
    fn admit_leaf_still_enforces_endpoint_and_pin() {
        let l = leaf(&["evil.example", "inference.model.example"], 0, 100);
        // Wrong endpoint refused first.
        assert_eq!(
            policy().admit_leaf("evil.example", &l, 50, &[pin()]),
            Err(EgressRejection::EndpointNotAllowed {
                dialed: "evil.example".to_string()
            }),
        );
        // Right name + time but an unpinned leaf is still refused.
        let unpinned = vec![PinnedCertificate::new(vec![0xbb; 32])];
        assert_eq!(
            policy().admit_leaf("inference.model.example", &l, 50, &unpinned),
            Err(EgressRejection::CertificateNotPinned),
        );
    }

    #[test]
    fn leaf_and_new_rejections_serde_round_trip() {
        let l = leaf(&["*.api.example"], 1, 2);
        assert_eq!(cbor_round_trip(&l), l);
        let r = EgressRejection::SanMismatch {
            endpoint: "h".to_string(),
        };
        assert_eq!(cbor_round_trip(&r), r);
        assert_eq!(
            cbor_round_trip(&EgressRejection::CertificateExpired),
            EgressRejection::CertificateExpired
        );
    }
}
