//! Attestation evidence — the typed records that ride an *attested* placement
//! (`Placement { attested: true }`, D-ATTEST / ADR 0040).
//!
//! Attestation is a **boundary modifier**, not a separate runtime: when a host
//! runs in a confidential VM, it produces an [`AttestationQuote`] over the
//! [`CodeMeasurement`] of the loaded image. A verifier turns that quote into a
//! [`QuoteVerificationResult`]; the accepted quote plus its verdict is the
//! [`AttestationEvidence`] that rides in `BoundaryEvent::Accepted` (ATTEST-2).
//!
//! These are pure domain types — never a bare `Vec<u8>`/`String` in the domain
//! (`principles.md` "Contracts at the boundary"). The real quote-generation and
//! signature verification happen at the imperative shell behind the
//! `QuoteVerifier` seam (ATTEST-3); the core only carries and decides over the
//! typed evidence. Real TEE verifiers (SEV-SNP / TDX / Nitro / SGX) attach
//! behind that seam with no change here — that hardware-bound work is DEFERRED
//! (see `DEFERRED.md` at the repo root; ATTEST-15, needs-infra).

/// A reproducible-build measurement of the code loaded into an attested host —
/// the SHA-256 of the confidential-VM image the quote vouches for (ADR 0040).
///
/// The digest hex is private so callers construct via [`CodeMeasurement::new`]
/// and compare measurements by value (`==`), the operation the boundary gate and
/// the measurement store both rely on (ATTEST-10).
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CodeMeasurement {
    /// Lower-case hex of the image digest (a SHA-256 is 64 hex chars).
    digest_hex: String,
}

impl CodeMeasurement {
    /// Construct from an already-validated digest hex string (parsed at the
    /// boundary from a real quote or a reproducible-build manifest).
    pub fn new(digest_hex: impl Into<String>) -> Self {
        Self {
            digest_hex: digest_hex.into(),
        }
    }

    /// The image digest as lower-case hex.
    pub fn digest_hex(&self) -> &str {
        &self.digest_hex
    }
}

/// A signed attestation quote produced by a confidential-VM host over the
/// [`CodeMeasurement`] of its loaded image, bound to a freshness nonce.
///
/// The `quote_bytes` are opaque, TEE-specific report material (SEV-SNP / TDX /
/// Nitro / SGX); the core never parses them — it carries them to the
/// `QuoteVerifier` seam (ATTEST-3) and reads back a [`QuoteVerificationResult`].
/// The `nonce` is the anti-replay challenge the verifier must find echoed inside
/// the report, so a stale quote cannot be replayed into a fresh acceptance.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttestationQuote {
    /// The measurement the host claims to be running (the quote vouches for it).
    pub measurement: CodeMeasurement,
    /// The freshness challenge the verifier requires the report to echo.
    pub nonce: String,
    /// Opaque TEE-specific report bytes — parsed only behind the verifier seam.
    quote_bytes: Vec<u8>,
}

impl AttestationQuote {
    /// Construct from a measurement, an anti-replay nonce, and the raw report
    /// bytes collected at the boundary.
    pub fn new(
        measurement: CodeMeasurement,
        nonce: impl Into<String>,
        quote_bytes: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            measurement,
            nonce: nonce.into(),
            quote_bytes: quote_bytes.into(),
        }
    }

    /// The opaque report bytes — only the verifier seam parses these.
    pub fn quote_bytes(&self) -> &[u8] {
        &self.quote_bytes
    }
}

/// The verdict a [`QuoteVerifier`](crate) returns for an [`AttestationQuote`]:
/// either the quote was accepted (yielding the trusted measurement it proves) or
/// it was rejected with a structured reason.
///
/// The reason is structured (not free text) so the boundary gate and projections
/// can branch on *why* a quote failed without string-matching (ATTEST-14).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum QuoteVerificationResult {
    /// The quote verified: its signature is trusted and the nonce matched. The
    /// carried measurement is the one downstream may release sealed keys to.
    Verified { measurement: CodeMeasurement },
    /// The quote did not verify, for the given reason.
    Rejected { reason: QuoteRejection },
}

/// Why an [`AttestationQuote`] failed verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum QuoteRejection {
    /// The quote signature did not chain to a trusted TEE root.
    UntrustedSignature,
    /// The report did not echo the challenge nonce (a possible replay).
    StaleNonce,
    /// The quote measured an image that is not an allowed measurement.
    UnknownMeasurement,
    /// The report bytes were not well-formed for the expected TEE.
    MalformedQuote,
}

impl QuoteVerificationResult {
    /// The measurement this result vouches for, if it verified.
    pub fn verified_measurement(&self) -> Option<&CodeMeasurement> {
        match self {
            Self::Verified { measurement } => Some(measurement),
            Self::Rejected { .. } => None,
        }
    }

    /// Whether the quote was accepted.
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }
}

/// The attestation evidence carried on an *attested* acceptance: the quote a host
/// presented and the verifier's verdict over it (ATTEST-2).
///
/// This is the payload that rides in `BoundaryEvent::Accepted { evidence }` when
/// the accepted placement is `attested`. The reducer carries it; the app-layer
/// `boundary_keeper` gate (ATTEST-5) refuses to release sealed keys unless the
/// carried [`QuoteVerificationResult`] verified to a trusted measurement.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttestationEvidence {
    /// The quote the attesting host presented.
    pub quote: AttestationQuote,
    /// The verifier's verdict over that quote.
    pub result: QuoteVerificationResult,
}

impl AttestationEvidence {
    /// Construct evidence pairing a quote with its verification result.
    pub fn new(quote: AttestationQuote, result: QuoteVerificationResult) -> Self {
        Self { quote, result }
    }

    /// Whether this evidence attests a trusted measurement: the verdict verified
    /// *and* it vouches for the very measurement the presented quote claimed.
    ///
    /// Pure: the app gate consults this before any key release (ATTEST-5).
    pub fn is_trustworthy(&self) -> bool {
        self.result.verified_measurement() == Some(&self.quote.measurement)
    }
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

    fn measurement() -> CodeMeasurement {
        CodeMeasurement::new("a".repeat(64))
    }

    fn quote() -> AttestationQuote {
        AttestationQuote::new(measurement(), "nonce-1", vec![1, 2, 3, 4])
    }

    /// Complete typed-result domain from attestation-admission.qnt. Quote
    /// bytes and nonce remain opaque inputs to the separate verifier seam.
    #[test]
    fn crypto_model_domain_attestation() {
        let measurements = [measurement(), CodeMeasurement::new("b".repeat(64))];
        let mut verdicts: Vec<_> = measurements
            .iter()
            .map(|m| QuoteVerificationResult::Verified {
                measurement: m.clone(),
            })
            .collect();
        for reason in [
            QuoteRejection::UntrustedSignature,
            QuoteRejection::StaleNonce,
            QuoteRejection::UnknownMeasurement,
            QuoteRejection::MalformedQuote,
        ] {
            verdicts.push(QuoteVerificationResult::Rejected { reason });
        }
        for (measurement_id, m) in measurements.iter().enumerate() {
            for (verdict_id, verdict) in verdicts.iter().enumerate() {
                let q = AttestationQuote::new(m.clone(), "nonce", vec![1, 2]);
                let evidence = AttestationEvidence::new(q, verdict.clone());
                assert_eq!(evidence.is_trustworthy(), verdict_id == measurement_id);
            }
        }
    }

    #[test]
    fn measurements_compare_by_value() {
        assert_eq!(measurement(), CodeMeasurement::new("a".repeat(64)));
        assert_ne!(measurement(), CodeMeasurement::new("b".repeat(64)));
        assert_eq!(measurement().digest_hex(), "a".repeat(64));
    }

    #[test]
    fn quote_carries_opaque_report_bytes() {
        let q = quote();
        assert_eq!(q.quote_bytes(), &[1, 2, 3, 4]);
        assert_eq!(q.nonce, "nonce-1");
        assert_eq!(q.measurement, measurement());
    }

    #[test]
    fn verified_result_exposes_its_measurement() {
        let r = QuoteVerificationResult::Verified {
            measurement: measurement(),
        };
        assert!(r.is_verified());
        assert_eq!(r.verified_measurement(), Some(&measurement()));
    }

    #[test]
    fn rejected_result_has_no_measurement() {
        let r = QuoteVerificationResult::Rejected {
            reason: QuoteRejection::StaleNonce,
        };
        assert!(!r.is_verified());
        assert_eq!(r.verified_measurement(), None);
    }

    /// Evidence is trustworthy only when the verdict verified the *same*
    /// measurement the quote claimed — the precondition the app key-release gate
    /// checks (ATTEST-5).
    #[test]
    fn evidence_is_trustworthy_when_verdict_matches_quote() {
        let evidence = AttestationEvidence::new(
            quote(),
            QuoteVerificationResult::Verified {
                measurement: measurement(),
            },
        );
        assert!(evidence.is_trustworthy());
    }

    /// A verified verdict over a *different* measurement than the quote claimed
    /// is not trustworthy — the gate must not release keys to it.
    #[test]
    fn evidence_not_trustworthy_when_measurement_differs() {
        let evidence = AttestationEvidence::new(
            quote(),
            QuoteVerificationResult::Verified {
                measurement: CodeMeasurement::new("b".repeat(64)),
            },
        );
        assert!(!evidence.is_trustworthy());
    }

    /// A rejected verdict is never trustworthy.
    #[test]
    fn rejected_evidence_is_not_trustworthy() {
        let evidence = AttestationEvidence::new(
            quote(),
            QuoteVerificationResult::Rejected {
                reason: QuoteRejection::UntrustedSignature,
            },
        );
        assert!(!evidence.is_trustworthy());
    }

    #[test]
    fn evidence_serde_round_trips() {
        let evidence = AttestationEvidence::new(
            quote(),
            QuoteVerificationResult::Verified {
                measurement: measurement(),
            },
        );
        assert_eq!(cbor_round_trip(&evidence), evidence);
    }
}
