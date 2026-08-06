//! Attestation quote verification seam (ATTEST-3): the `QuoteVerifier` trait the
//! app layer calls to turn an [`AttestationQuote`] into a
//! [`QuoteVerificationResult`], plus the loopback-first implementations.
//!
//! Attestation is a **boundary modifier**, not a separate runtime (ADR 0040): an
//! attested host presents a quote over the [`CodeMeasurement`] of its image; the
//! verifier decides whether that quote is trustworthy *before* the boundary gate
//! releases any sealed key (ATTEST-5). The core carries the typed evidence; the
//! *parsing of opaque report bytes and the trust decision live here*, behind the
//! seam, exactly like the federation relay (`RELAY-TRAIT-1`).
//!
//! - [`LoopbackVerifier`] is the buildable-now impl: honest in-process checks
//!   (nonce freshness, measurement allow-list, well-formed report bytes) with no
//!   TEE hardware. It is what the loopback two-authority shape and the e2e
//!   attested-boundary flow run against.
//! - [`StubVerifier`] is a placeholder that accepts every well-formed quote — a
//!   fixture for tests that exercise the *downstream* gate (key release) without
//!   caring about the verdict path. It is never the default.
//!
//! Real TEE verifiers (SEV-SNP / TDX / Nitro / SGX) attach behind [`QuoteVerifier`]
//! with no rearchitecture: they replace the report-bytes check with real signature
//! chaining to an Intel/AMD root and real report parsing (ATTEST-15, needs-infra).

use gaugedesk_core::attestation::{
    AttestationQuote, CodeMeasurement, QuoteRejection, QuoteVerificationResult,
};

/// The quote-verification seam (ATTEST-3): turn a presented [`AttestationQuote`]
/// into a [`QuoteVerificationResult`], given the freshness challenge the verifier
/// itself issued. The verifier is the only place that parses the opaque,
/// TEE-specific report bytes and decides trust; the core only carries the verdict.
///
/// `expected_nonce` is the anti-replay challenge the verifier handed the host when
/// it requested the quote — verification must confirm the report echoes it, so a
/// stale quote cannot be replayed into a fresh acceptance.
pub trait QuoteVerifier {
    /// Verify `quote` against `expected_nonce`, yielding the trusted measurement on
    /// success or a structured [`QuoteRejection`] on failure. Pure over its inputs
    /// and the verifier's configured trust roots — no I/O in the loopback impls.
    fn verify(&self, quote: &AttestationQuote, expected_nonce: &str) -> QuoteVerificationResult;
}

/// Why a deployment could not construct its real quote verifier.
///
/// The route layer keeps this neutral so open boundary acceptance can stay
/// source-owned by the public app surface while private managed-service builds
/// provide the concrete verifier behind the workbench seam.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RealQuoteVerifierError {
    /// This build has no real verifier implementation wired in.
    Unavailable,
    /// The host-supplied endorsement material could not construct a verifier.
    InvalidEndorsement(String),
}

impl std::fmt::Display for RealQuoteVerifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => f.write_str("real attestation verifier unavailable in this build"),
            Self::InvalidEndorsement(reason) => write!(f, "invalid endorsement material: {reason}"),
        }
    }
}

impl std::error::Error for RealQuoteVerifierError {}

/// A deployment-injected factory that builds the real quote verifier from the
/// host-supplied endorsement material (the VCEK, DER) and the operator's
/// trusted-measurement allow-list (ATTEST-10). The open app never names a
/// concrete TEE implementation; a private managed-service composition installs
/// its factory via [`Workbench::set_real_quote_verifier_factory`].
pub type RealQuoteVerifierFactory = std::sync::Arc<
    dyn Fn(&[u8], Vec<CodeMeasurement>) -> Result<Box<dyn QuoteVerifier>, RealQuoteVerifierError>
        + Send
        + Sync,
>;

/// The real-verifier injection seam (ATTEST-15). The attested-accept path calls
/// [`Workbench::real_quote_verifier`] without naming any managed-service
/// implementation; a build with no installed factory **fails closed**
/// ([`RealQuoteVerifierError::Unavailable`]), and the private managed
/// deployment installs the real SEV-SNP factory at workbench open time.
impl crate::Workbench {
    /// Install the deployment's real quote verifier factory. The hosted
    /// composition calls this once at workbench open time, before routes are
    /// built; open builds never call it and stay fail-closed.
    pub fn set_real_quote_verifier_factory(&mut self, factory: RealQuoteVerifierFactory) {
        self.real_verifier_factory = Some(factory);
    }

    /// Build the deployment's real quote verifier for an attested acceptance.
    ///
    /// The public boundary route calls this Workbench seam without naming any
    /// managed-service implementation. Builds without an installed factory fail
    /// closed; private managed-service compositions provide the real
    /// implementation behind [`RealQuoteVerifierFactory`].
    pub fn real_quote_verifier(
        &self,
        vcek: &[u8],
        allowed: impl IntoIterator<Item = CodeMeasurement>,
    ) -> Result<Box<dyn QuoteVerifier>, RealQuoteVerifierError> {
        match &self.real_verifier_factory {
            Some(factory) => factory(vcek, allowed.into_iter().collect()),
            None => Err(RealQuoteVerifierError::Unavailable),
        }
    }
}

/// The buildable-now loopback verifier: an honest in-process check with no TEE
/// hardware. It vouches for a quote iff (in order) the report bytes are well-formed
/// (non-empty — the stand-in for "signature chains to a trusted root"), the report
/// echoes the freshness `expected_nonce`, and the claimed measurement is one of the
/// verifier's allowed measurements (the reproducible-build allow-list, ATTEST-10).
///
/// The check order matches the [`QuoteRejection`] taxonomy so the boundary gate and
/// projections can branch on *why* a quote failed (ATTEST-14): a malformed report is
/// rejected before its nonce is read, and a stale nonce before its measurement is
/// consulted.
#[derive(Clone, Debug, Default)]
pub struct LoopbackVerifier {
    /// The measurements this verifier trusts (reproducible-build allow-list). Empty
    /// ⇒ no measurement is trusted, so every quote is `UnknownMeasurement`.
    allowed: Vec<CodeMeasurement>,
}

impl LoopbackVerifier {
    /// A verifier that trusts exactly the given measurements.
    pub fn new(allowed: impl IntoIterator<Item = CodeMeasurement>) -> Self {
        Self {
            allowed: allowed.into_iter().collect(),
        }
    }

    /// A verifier trusting a single measurement — the common loopback case.
    pub fn trusting(measurement: CodeMeasurement) -> Self {
        Self::new([measurement])
    }

    /// Whether this verifier trusts `measurement` (reproducible-build allow-list).
    pub fn trusts(&self, measurement: &CodeMeasurement) -> bool {
        self.allowed.iter().any(|m| m == measurement)
    }
}

impl QuoteVerifier for LoopbackVerifier {
    fn verify(&self, quote: &AttestationQuote, expected_nonce: &str) -> QuoteVerificationResult {
        // 1. Report well-formedness — the loopback stand-in for "signature chains
        //    to a trusted TEE root". Empty report bytes never chain.
        if quote.quote_bytes().is_empty() {
            return QuoteVerificationResult::Rejected {
                reason: QuoteRejection::UntrustedSignature,
            };
        }
        // 2. Freshness — the report must echo the challenge the verifier issued, or
        //    it is a possible replay of a stale quote.
        if quote.nonce != expected_nonce {
            return QuoteVerificationResult::Rejected {
                reason: QuoteRejection::StaleNonce,
            };
        }
        // 3. Measurement allow-list — only a reproducible-build measurement we trust
        //    may have sealed keys released to it (ATTEST-5/-10).
        if !self.trusts(&quote.measurement) {
            return QuoteVerificationResult::Rejected {
                reason: QuoteRejection::UnknownMeasurement,
            };
        }
        QuoteVerificationResult::Verified {
            measurement: quote.measurement.clone(),
        }
    }
}

/// A placeholder verifier that accepts every well-formed quote (non-empty report)
/// at face value — it vouches for whatever measurement the quote claims, without a
/// trust root or an allow-list. It exists to drive *downstream* tests (the
/// key-release gate, ATTEST-5) that need a trustworthy verdict without exercising
/// the verification path.
///
/// **Test-only (CONF-8).** It is `#[cfg(test)]`-gated so a production build cannot
/// even name it, let alone select this fail-open verifier; a real placement uses
/// [`LoopbackVerifier`] or a real TEE verifier (e.g. `SevSnpVerifier`).
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub struct StubVerifier;

#[cfg(test)]
impl QuoteVerifier for StubVerifier {
    fn verify(&self, quote: &AttestationQuote, _expected_nonce: &str) -> QuoteVerificationResult {
        if quote.quote_bytes().is_empty() {
            return QuoteVerificationResult::Rejected {
                reason: QuoteRejection::MalformedQuote,
            };
        }
        QuoteVerificationResult::Verified {
            measurement: quote.measurement.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measurement() -> CodeMeasurement {
        CodeMeasurement::new("a".repeat(64))
    }

    fn quote_with(nonce: &str, bytes: Vec<u8>) -> AttestationQuote {
        AttestationQuote::new(measurement(), nonce, bytes)
    }

    fn good_quote() -> AttestationQuote {
        quote_with("challenge-1", vec![1, 2, 3, 4])
    }

    #[test]
    fn loopback_verifies_fresh_quote_for_trusted_measurement() {
        let verifier = LoopbackVerifier::trusting(measurement());
        let result = verifier.verify(&good_quote(), "challenge-1");
        assert!(result.is_verified());
        assert_eq!(result.verified_measurement(), Some(&measurement()));
    }

    #[test]
    fn loopback_rejects_empty_report_as_untrusted_signature() {
        let verifier = LoopbackVerifier::trusting(measurement());
        let result = verifier.verify(&quote_with("challenge-1", vec![]), "challenge-1");
        assert_eq!(
            result,
            QuoteVerificationResult::Rejected {
                reason: QuoteRejection::UntrustedSignature
            }
        );
    }

    /// A quote whose report echoes a *different* nonce than the verifier issued is a
    /// possible replay — rejected as `StaleNonce`, the anti-replay tooth (ATTEST-9).
    #[test]
    fn loopback_rejects_stale_nonce() {
        let verifier = LoopbackVerifier::trusting(measurement());
        let result = verifier.verify(&good_quote(), "challenge-2");
        assert_eq!(
            result,
            QuoteVerificationResult::Rejected {
                reason: QuoteRejection::StaleNonce
            }
        );
    }

    #[test]
    fn loopback_rejects_unknown_measurement() {
        let verifier = LoopbackVerifier::trusting(CodeMeasurement::new("b".repeat(64)));
        let result = verifier.verify(&good_quote(), "challenge-1");
        assert_eq!(
            result,
            QuoteVerificationResult::Rejected {
                reason: QuoteRejection::UnknownMeasurement
            }
        );
    }

    /// An empty allow-list trusts nothing — every quote is `UnknownMeasurement`.
    #[test]
    fn loopback_with_no_allowed_measurements_trusts_nothing() {
        let verifier = LoopbackVerifier::default();
        assert!(!verifier.trusts(&measurement()));
        let result = verifier.verify(&good_quote(), "challenge-1");
        assert_eq!(
            result,
            QuoteVerificationResult::Rejected {
                reason: QuoteRejection::UnknownMeasurement
            }
        );
    }

    /// Rejection-reason precedence: a malformed report is rejected before its nonce
    /// is read, and a stale nonce before its measurement is consulted — so the gate
    /// always learns the *first* failure, never a misleading later one.
    #[test]
    fn loopback_rejection_reasons_follow_check_order() {
        // Untrusted (empty) takes precedence over a stale nonce + unknown measurement.
        let verifier = LoopbackVerifier::default();
        assert_eq!(
            verifier.verify(&quote_with("wrong", vec![]), "challenge-1"),
            QuoteVerificationResult::Rejected {
                reason: QuoteRejection::UntrustedSignature
            }
        );
        // Stale nonce takes precedence over an unknown measurement.
        assert_eq!(
            verifier.verify(&quote_with("wrong", vec![9]), "challenge-1"),
            QuoteVerificationResult::Rejected {
                reason: QuoteRejection::StaleNonce
            }
        );
    }

    /// The stub vouches for any non-empty quote regardless of nonce or allow-list —
    /// the fixture for downstream-gate tests.
    #[test]
    fn stub_verifies_any_well_formed_quote() {
        let result = StubVerifier.verify(&good_quote(), "ignored-nonce");
        assert!(result.is_verified());
        assert_eq!(result.verified_measurement(), Some(&measurement()));
    }

    #[test]
    fn stub_rejects_malformed_empty_quote() {
        let result = StubVerifier.verify(&quote_with("n", vec![]), "ignored");
        assert_eq!(
            result,
            QuoteVerificationResult::Rejected {
                reason: QuoteRejection::MalformedQuote
            }
        );
    }
}
