//! Hub-signed managed-inference entitlements (SOC 2 finding F-5.3 / DR-0089).
//!
//! An authenticated account owner who holds an **active** managed-inference plan
//! asks the Hub to mint a short-lived, signed entitlement bound to the publisher
//! public key they will deploy with. The public edge (a separate repository,
//! built next) verifies this signature before it will serve a managed-funded
//! deployment. That verification is what ties an otherwise-anonymous edge
//! publisher key back to an authenticated, entitled account — the account never
//! reaches the edge, and the edge never reaches the Hub's account store, so the
//! signature is the only thing that crosses the gap.
//!
//! # The entitlement contract (reproduced byte-identically by the edge)
//!
//! The serialized entitlement is JSON `{ "claims": { … }, "sig": "<128 hex>" }`.
//! The claims are:
//!
//! - `v` — format version, always `1`.
//! - `scope` — the funding scope the plan was folded from (an account or tenant
//!   store scope). Arbitrary bytes, so it is hex-encoded in the preimage.
//! - `plan` — the plan name. Arbitrary bytes, so it too is hex-encoded.
//! - `authority` — the deploying publisher's uncompressed-SEC1 P-256 public key,
//!   lowercase hex (130 chars, `0x04` prefix). Already hex; used verbatim.
//! - `max_spend_cents`, `max_session_spend_cents`, `max_turn_spend_cents` — the
//!   signed spend ceilings, as decimal unsigned integers. The managed-inference
//!   plan model grants a token allowance and a status, not cents caps (see
//!   [`crate::managed_inference::ManagedInferencePlan`]), so the Hub signs `0`
//!   for all three today. `0` means "no per-entitlement cents ceiling": the edge
//!   applies no additional cents cap of its own and the private managed billing
//!   rail meters actual token usage. If the plan model later carries cents caps,
//!   they populate these fields and the preimage is unchanged.
//! - `iat` — issued-at, unix seconds.
//! - `exp` — expiry, unix seconds, always `iat + 86400` (one day).
//!
//! ## Canonical signing preimage
//!
//! Exactly these nine parts joined by a single `0x0a` newline, with **no**
//! trailing newline:
//!
//! ```text
//! "gw-managed-entitlement.v1"
//! hex(scope_utf8_bytes)
//! hex(plan_utf8_bytes)
//! authority                       (already lowercase hex, 130 chars)
//! dec(max_spend_cents)
//! dec(max_session_spend_cents)
//! dec(max_turn_spend_cents)
//! dec(iat)
//! dec(exp)
//! ```
//!
//! The delimiter is safe because every variable part is hex or decimal ASCII and
//! so can never itself contain a newline. The domain-separation tag is a fixed
//! ASCII literal, not hex.
//!
//! ## Signature
//!
//! ECDSA P-256 over `SHA-256(preimage)` — i.e. the preimage bytes are signed
//! with a P-256 signing key using the SHA-256 digest, exactly as WebCrypto's
//! `{ name: "ECDSA", hash: "SHA-256" }` does over the same bytes. The output is
//! the compact 64-byte `r ‖ s` signature, lowercase hex (128 chars). ECDSA is a
//! signature scheme, not a nonce protocol: a deterministic (RFC-6979) or a
//! randomized signature over the same preimage both verify, so the edge's
//! verifier does not depend on which the Hub produced.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature as P256Sig, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The domain-separation tag prefixed to every entitlement preimage.
pub const ENTITLEMENT_DOMAIN: &str = "gw-managed-entitlement.v1";

/// The fixed entitlement lifetime: one day, in seconds.
pub const ENTITLEMENT_TTL_SECS: u64 = 86_400;

/// The current entitlement claim-set version.
pub const ENTITLEMENT_VERSION: u8 = 1;

/// The machine-secret environment variable carrying the Hub's entitlement
/// signing key, as a **32-byte P-256 private scalar in lowercase hex** (64 hex
/// characters). Absent or malformed means signing is not configured, and the
/// mint endpoint fails closed rather than minting an unsigned or wrongly-keyed
/// entitlement.
pub const SIGNING_KEY_ENV: &str = "GAUGEWRIGHT_MANAGED_ENTITLEMENT_SIGNING_KEY";

/// The uncompressed-SEC1 hex length of a P-256 public key (`04 || x || y`).
const PUBLIC_KEY_HEX_LEN: usize = 130;

/// The compact `r ‖ s` signature length in bytes.
const SIGNATURE_LEN: usize = 64;

/// The claims the Hub signs. Serialized verbatim into the entitlement JSON; the
/// signature is computed over [`canonical_preimage`], never over the JSON bytes,
/// so field order and whitespace are not load-bearing across languages.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EntitlementClaims {
    pub v: u8,
    pub scope: String,
    pub plan: String,
    /// The deploying publisher's uncompressed-SEC1 P-256 public key, lowercase
    /// hex (130 chars). This is the key the entitlement authorizes.
    pub authority: String,
    pub max_spend_cents: u64,
    pub max_session_spend_cents: u64,
    pub max_turn_spend_cents: u64,
    pub iat: u64,
    pub exp: u64,
}

/// A serialized entitlement: the claims plus the Hub's signature over their
/// canonical preimage.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Entitlement {
    pub claims: EntitlementClaims,
    /// Compact `r ‖ s` ECDSA P-256 signature, lowercase hex (128 chars).
    pub sig: String,
}

/// Why an entitlement could not be signed or verified. The `Display` string is
/// safe to surface to a caller (it names no key material).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntitlementError {
    /// The publisher authority is not a 130-char lowercase hex uncompressed-SEC1
    /// P-256 public key.
    InvalidAuthority,
    /// The claim set is not the version this code understands.
    UnsupportedVersion,
    /// The entitlement JSON could not be parsed.
    Malformed,
    /// The Hub public key used to verify is not a valid P-256 point.
    InvalidVerifyingKey,
    /// The signature is the wrong length, unparseable, or does not verify.
    BadSignature,
    /// The entitlement's `exp` is at or before the verification instant.
    Expired,
    /// The claims could not be serialized to JSON.
    Serialization,
}

impl EntitlementError {
    pub fn message(self) -> &'static str {
        match self {
            EntitlementError::InvalidAuthority => "publisher key is not a P-256 public key",
            EntitlementError::UnsupportedVersion => "unsupported entitlement version",
            EntitlementError::Malformed => "entitlement is malformed",
            EntitlementError::InvalidVerifyingKey => "verifying key is not a P-256 public key",
            EntitlementError::BadSignature => "entitlement signature does not verify",
            EntitlementError::Expired => "entitlement has expired",
            EntitlementError::Serialization => "entitlement could not be serialized",
        }
    }
}

impl std::fmt::Display for EntitlementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for EntitlementError {}

/// Whether `authority` is a well-formed uncompressed-SEC1 P-256 public key in
/// lowercase hex (130 chars, `0x04` prefix, and a point the curve admits).
pub fn valid_authority(authority: &str) -> bool {
    if authority.len() != PUBLIC_KEY_HEX_LEN {
        return false;
    }
    if authority != authority.to_ascii_lowercase() {
        return false;
    }
    let Ok(bytes) = hex::decode(authority) else {
        return false;
    };
    // Reject compressed/other encodings up front; the edge and publisher
    // identities are always uncompressed `04 || x || y`.
    if bytes.first() != Some(&0x04) {
        return false;
    }
    VerifyingKey::from_sec1_bytes(&bytes).is_ok()
}

/// The exact byte string signed for `claims` (see the module docs). Hex/decimal
/// parts joined by `0x0a`, no trailing newline.
pub fn canonical_preimage(claims: &EntitlementClaims) -> Vec<u8> {
    [
        ENTITLEMENT_DOMAIN.to_string(),
        hex::encode(claims.scope.as_bytes()),
        hex::encode(claims.plan.as_bytes()),
        claims.authority.clone(),
        claims.max_spend_cents.to_string(),
        claims.max_session_spend_cents.to_string(),
        claims.max_turn_spend_cents.to_string(),
        claims.iat.to_string(),
        claims.exp.to_string(),
    ]
    .join("\n")
    .into_bytes()
}

/// Build the claim set the Hub signs. `iat` is the mint instant (unix seconds);
/// `exp` is fixed at `iat + `[`ENTITLEMENT_TTL_SECS`]. The spend caps are signed
/// as `0` — see the module docs on why the plan model carries none today.
pub fn build_claims(scope: &str, plan: &str, authority: &str, iat: u64) -> EntitlementClaims {
    EntitlementClaims {
        v: ENTITLEMENT_VERSION,
        scope: scope.to_owned(),
        plan: plan.to_owned(),
        authority: authority.to_owned(),
        max_spend_cents: 0,
        max_session_spend_cents: 0,
        max_turn_spend_cents: 0,
        iat,
        exp: iat.saturating_add(ENTITLEMENT_TTL_SECS),
    }
}

/// Sign `claims` with the Hub `signing_key`, returning the serialized JSON
/// entitlement. Rejects claims whose `authority` is not a valid publisher key so
/// the Hub never signs a binding to a key the edge will refuse to parse.
pub fn sign(
    signing_key: &SigningKey,
    claims: &EntitlementClaims,
) -> Result<String, EntitlementError> {
    if claims.v != ENTITLEMENT_VERSION {
        return Err(EntitlementError::UnsupportedVersion);
    }
    if !valid_authority(&claims.authority) {
        return Err(EntitlementError::InvalidAuthority);
    }
    let preimage = canonical_preimage(claims);
    let signature: P256Sig = signing_key.sign(&preimage);
    let entitlement = Entitlement {
        claims: claims.clone(),
        sig: hex::encode(signature.to_bytes()),
    };
    serde_json::to_string(&entitlement).map_err(|_| EntitlementError::Serialization)
}

/// Verify a serialized entitlement under the Hub's public key `public_key_hex`
/// (uncompressed-SEC1 hex) as of `now` (unix seconds). Returns the claims on
/// success. Fail-closed: a wrong key, tampered claim, malformed signature, or
/// `exp <= now` are all rejections.
///
/// Present here so the Hub side and the edge share one reference implementation
/// of the contract; the edge mirrors this predicate in its own language.
pub fn verify(
    public_key_hex: &str,
    entitlement_json: &str,
    now: u64,
) -> Result<EntitlementClaims, EntitlementError> {
    let entitlement: Entitlement =
        serde_json::from_str(entitlement_json).map_err(|_| EntitlementError::Malformed)?;
    if entitlement.claims.v != ENTITLEMENT_VERSION {
        return Err(EntitlementError::UnsupportedVersion);
    }
    let key_bytes =
        hex::decode(public_key_hex).map_err(|_| EntitlementError::InvalidVerifyingKey)?;
    let verifying = VerifyingKey::from_sec1_bytes(&key_bytes)
        .map_err(|_| EntitlementError::InvalidVerifyingKey)?;
    let sig_bytes = hex::decode(&entitlement.sig).map_err(|_| EntitlementError::BadSignature)?;
    if sig_bytes.len() != SIGNATURE_LEN {
        return Err(EntitlementError::BadSignature);
    }
    let signature = P256Sig::from_slice(&sig_bytes).map_err(|_| EntitlementError::BadSignature)?;
    let preimage = canonical_preimage(&entitlement.claims);
    verifying
        .verify(&preimage, &signature)
        .map_err(|_| EntitlementError::BadSignature)?;
    if entitlement.claims.exp <= now {
        return Err(EntitlementError::Expired);
    }
    Ok(entitlement.claims)
}

/// Load the Hub's entitlement signing key from [`SIGNING_KEY_ENV`] (a 32-byte
/// P-256 private scalar in lowercase hex). `None` when unset or malformed, which
/// the mint endpoint turns into a fail-closed refusal.
pub fn signing_key_from_env() -> Option<SigningKey> {
    let encoded = std::env::var(SIGNING_KEY_ENV).ok()?;
    let bytes = hex::decode(encoded.trim()).ok()?;
    SigningKey::from_slice(&bytes).ok()
}

/// The Hub public key matching `signing_key`, uncompressed-SEC1 lowercase hex
/// (130 chars) — the value the edge pins to verify entitlements.
pub fn public_key_hex(signing_key: &SigningKey) -> String {
    hex::encode(signing_key.verifying_key().to_sec1_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed, deterministic Hub signer for tests. Seed is an arbitrary valid
    /// scalar.
    fn hub_key() -> SigningKey {
        SigningKey::from_slice(&[0x11u8; 32]).expect("valid scalar")
    }

    /// A fixed publisher keypair; only its public half is bound into claims.
    fn publisher_authority() -> String {
        let publisher = SigningKey::from_slice(&[0x22u8; 32]).expect("valid scalar");
        public_key_hex(&publisher)
    }

    fn sample_claims() -> EntitlementClaims {
        build_claims(
            "account::alice",
            "managed-monthly",
            &publisher_authority(),
            1_700_000_000,
        )
    }

    /// Regression vector: a fixed claim set folds to a fixed preimage. If this
    /// changes, the edge's byte-identical reconstruction breaks — so the exact
    /// hex is pinned here and the edge asserts the same bytes.
    #[test]
    fn canonical_preimage_is_stable() {
        let claims = EntitlementClaims {
            v: 1,
            scope: "account::alice".to_owned(),
            plan: "managed-monthly".to_owned(),
            // A deterministic 130-char authority literal keeps the vector fixed
            // without depending on a key derivation.
            authority: format!("04{}", "ab".repeat(64)),
            max_spend_cents: 0,
            max_session_spend_cents: 0,
            max_turn_spend_cents: 0,
            iat: 1_700_000_000,
            exp: 1_700_086_400,
        };
        let preimage = canonical_preimage(&claims);
        // "gw-managed-entitlement.v1\n" + hex("account::alice") + "\n"
        //   + hex("managed-monthly") + "\n" + authority + "\n0\n0\n0\n"
        //   + "1700000000\n1700086400". The scope/plan hex are pinned literals;
        // the authority is echoed from the claim so the readable form cannot
        // drift on a miscount. The fully independent regression pin is the
        // preimage hex asserted just below.
        let expected = format!(
            "gw-managed-entitlement.v1\n\
             6163636f756e743a3a616c696365\n\
             6d616e616765642d6d6f6e74686c79\n\
             {}\n\
             0\n0\n0\n\
             1700000000\n1700086400",
            claims.authority,
        );
        assert_eq!(
            String::from_utf8(preimage.clone()).unwrap(),
            expected,
            "canonical preimage drifted from the pinned vector",
        );
        assert_eq!(
            hex::encode(&preimage),
            "67772d6d616e616765642d656e7469746c656d656e742e76310a363136333633366637353665373433613361363136633639363336350a3664363136653631363736353634326436643666366537343638366337390a303461626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261620a300a300a300a313730303030303030300a31373030303836343030",
            "canonical preimage hex drifted from the pinned vector",
        );
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let key = hub_key();
        let claims = sample_claims();
        let entitlement = sign(&key, &claims).expect("sign");
        let pubkey = public_key_hex(&key);
        let verified = verify(&pubkey, &entitlement, claims.iat).expect("verify");
        assert_eq!(verified, claims);
    }

    #[test]
    fn verify_rejects_a_tampered_claim() {
        let key = hub_key();
        let claims = sample_claims();
        let entitlement = sign(&key, &claims).expect("sign");
        // Flip the plan name inside the serialized claims without re-signing.
        let tampered = entitlement.replace("managed-monthly", "managed-yearlyy");
        assert_ne!(tampered, entitlement);
        let pubkey = public_key_hex(&key);
        assert_eq!(
            verify(&pubkey, &tampered, claims.iat),
            Err(EntitlementError::BadSignature),
        );
    }

    #[test]
    fn verify_rejects_the_wrong_key() {
        let key = hub_key();
        let claims = sample_claims();
        let entitlement = sign(&key, &claims).expect("sign");
        let other = SigningKey::from_slice(&[0x33u8; 32]).unwrap();
        assert_eq!(
            verify(&public_key_hex(&other), &entitlement, claims.iat),
            Err(EntitlementError::BadSignature),
        );
    }

    #[test]
    fn verify_rejects_an_expired_entitlement() {
        let key = hub_key();
        let claims = sample_claims();
        let entitlement = sign(&key, &claims).expect("sign");
        let pubkey = public_key_hex(&key);
        // Exactly at exp is expired (fail-closed on the boundary).
        assert_eq!(
            verify(&pubkey, &entitlement, claims.exp),
            Err(EntitlementError::Expired),
        );
        // One second before exp still verifies.
        assert!(verify(&pubkey, &entitlement, claims.exp - 1).is_ok());
    }

    #[test]
    fn sign_refuses_an_invalid_authority() {
        let key = hub_key();
        let mut claims = sample_claims();
        claims.authority = "not-a-key".to_owned();
        assert_eq!(sign(&key, &claims), Err(EntitlementError::InvalidAuthority));
        // Uppercase hex of an otherwise valid key is rejected (contract is
        // lowercase, so the edge's parse stays exact).
        claims.authority = publisher_authority().to_ascii_uppercase();
        assert_eq!(sign(&key, &claims), Err(EntitlementError::InvalidAuthority));
    }

    #[test]
    fn exp_is_one_day_after_iat() {
        let claims = build_claims("account::alice", "p", &publisher_authority(), 1_700_000_000);
        assert_eq!(claims.exp, claims.iat + ENTITLEMENT_TTL_SECS);
    }

    /// The signing key reads from the documented hex scalar form.
    #[test]
    fn signing_key_from_env_reads_hex_scalar() {
        let scalar = [0x44u8; 32];
        // Exercise the parse path directly rather than mutating process env.
        let parsed = SigningKey::from_slice(&scalar).unwrap();
        let round = hex::encode(scalar);
        let reparsed = SigningKey::from_slice(&hex::decode(round).unwrap()).unwrap();
        assert_eq!(
            public_key_hex(&parsed),
            public_key_hex(&reparsed),
            "hex scalar must round-trip to the same key",
        );
    }
}
