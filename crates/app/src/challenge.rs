//! Server-issued attestation challenges — real anti-replay for the attested-accept
//! route (ADR 0049).
//!
//! The verifier requires a host's quote to echo a freshness nonce in its `report_data`
//! (the deployment's real verifier, e.g. the SEV-SNP verifier in
//! `gaugewright-cloud-attestation`). For that to actually prevent replay, the nonce must be
//! chosen by the **server**, not supplied by the caller — otherwise an attacker simply
//! replays an old quote and claims its own "expected" nonce. So the accept flow is:
//! an attestation client must first ask the server to mint an unpredictable nonce
//! and record it per `(boundary, participant)`, then the host produces
//! a quote binding *that* nonce, and the accept route checks the quote against the
//! recorded challenge — never a caller-claimed value. A stale quote carries an old
//! nonce and can never match the current challenge.
//!
//! The challenge is a store record (latest-wins per participant); issuing/looking up is
//! pure over the store, so the nonce is passed in here and the route supplies a fresh
//! random one ([`fresh_nonce`]) — keeping this module deterministic and unit-testable.
//! The primitive is intentionally not routed until a shipped attestation client owns
//! the complete challenge/quote/accept ceremony; the former handler-only route was
//! removed under DR-0051 rather than retained as compatibility surface.

use gaugedesk_store::{AdmitError, Store};

/// The record kind under which a per-participant attestation challenge is stored in a
/// boundary scope.
const CHALLENGE_KIND: &str = "attest-challenge";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ChallengeRecord {
    participant: String,
    nonce: String,
}

/// Record `nonce` as the current challenge for (`bid`, `participant`). Latest-wins: a
/// re-issue supersedes the prior challenge, so only the freshest nonce is accepted.
pub fn issue(
    store: &mut Store,
    bid: &str,
    participant: &str,
    nonce: &str,
) -> Result<(), AdmitError> {
    let payload = serde_json::to_string(&ChallengeRecord {
        participant: participant.to_string(),
        nonce: nonce.to_string(),
    })?;
    store.append_record(bid, CHALLENGE_KIND, &payload)?;
    Ok(())
}

/// The current (latest-wins) challenge nonce issued for (`bid`, `participant`), if any.
/// The accept route checks the presented quote against this — not a caller-supplied
/// nonce — so a replayed stale quote cannot satisfy freshness.
pub fn current(store: &Store, bid: &str, participant: &str) -> Result<Option<String>, AdmitError> {
    let mut latest = None;
    // records() is position-ordered (oldest→newest); a later issue wins.
    for row in store.records(bid, CHALLENGE_KIND)? {
        let rec: ChallengeRecord = serde_json::from_str(&row)?;
        if rec.participant == participant {
            latest = Some(rec.nonce);
        }
    }
    Ok(latest)
}

/// A fresh, unpredictable 128-bit challenge nonce as lower-case hex — the server side
/// of the anti-replay handshake. CSPRNG via `getrandom` (same source as session ids).
pub fn fresh_nonce() -> String {
    let mut buf = [0u8; 16];
    let _ = getrandom::getrandom(&mut buf);
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_is_none_until_issued() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(current(&store, "b1", "A").unwrap(), None);
    }

    #[test]
    fn issue_then_current_returns_the_nonce_per_participant() {
        let mut store = Store::open_in_memory().unwrap();
        issue(&mut store, "b1", "A", "nonce-a").unwrap();
        issue(&mut store, "b1", "B", "nonce-b").unwrap();
        assert_eq!(
            current(&store, "b1", "A").unwrap().as_deref(),
            Some("nonce-a")
        );
        assert_eq!(
            current(&store, "b1", "B").unwrap().as_deref(),
            Some("nonce-b")
        );
        // Isolated per boundary.
        assert_eq!(current(&store, "b2", "A").unwrap(), None);
    }

    #[test]
    fn reissue_supersedes_latest_wins() {
        let mut store = Store::open_in_memory().unwrap();
        issue(&mut store, "b1", "A", "old").unwrap();
        issue(&mut store, "b1", "A", "new").unwrap();
        assert_eq!(current(&store, "b1", "A").unwrap().as_deref(), Some("new"));
    }

    #[test]
    fn fresh_nonce_is_unpredictable_and_distinct() {
        let a = fresh_nonce();
        let b = fresh_nonce();
        assert_eq!(a.len(), 32, "128-bit hex");
        assert_ne!(a, b, "each challenge is distinct");
    }
}
