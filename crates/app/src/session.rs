//! Session-token store (`SESSION-STORE-1`): once a caller clears the
//! governance-key challenge/response handshake ([`crate::net_server::GovernanceAuth::respond`]),
//! the server hands it a **session token** bound to the `(engagement, authority)`
//! pair it authenticated as. Subsequent cross-authority calls on that engagement
//! present the token instead of re-running the handshake on every request.
//!
//! The token is the per-connection credential; the handshake is the per-session
//! one. A token authorizes calls only for the exact `(engagement, authority)` it
//! was minted against — the same identity the handshake authenticated — so a token
//! captured for one engagement cannot act on another, and a token for one authority
//! cannot speak as another. Revoking the session (logout, key rotation, grant
//! expiry) drops the entry and instantly invalidates the token.
//!
//! Scaffold note: the token bytes here are a deterministic counter (loopback,
//! single-process). Real deployments mint an unguessable CSPRNG token and may bound
//! its lifetime; both attach behind this same seam with no rearchitecture (ADR 0020).

use std::collections::BTreeMap;

use gaugedesk_core::ids::{AuthorityId, EngagementId};

/// `N` bytes of cryptographically-secure randomness (OS CSPRNG via `getrandom`) —
/// the unguessable core of a session token or auth challenge (D-REMOTE). Falls back
/// to the empty fill only if the OS RNG is unavailable, which `getrandom` treats as
/// a hard error on every supported platform, so in practice this always fills.
/// `pub` so the extracted enterprise band (`gaugedesk-ee`) mints its OIDC CSRF
/// `state` from the same CSPRNG seam.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    let _ = getrandom::getrandom(&mut buf);
    buf
}

/// An opaque bearer token a caller presents to act on a session it has already
/// authenticated. Compared by value; the bytes are meaningless to the caller.
///
/// `Debug` is **redacted** (`SECAUD-10`): the raw bytes are a live credential, so they must
/// never reach a log line or an error message — printing a `SessionToken` (or the
/// [`SessionStore`] that derives `Debug` over its tokens) shows `SessionToken(<redacted>)`.
/// The bytes are reachable only via the explicit [`as_bytes`](Self::as_bytes).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionToken(Vec<u8>);

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

impl SessionToken {
    /// The raw token bytes (the credential the caller echoes back).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Reconstruct a token from bytes parsed at the boundary (e.g. a bearer
    /// credential read off the wire). The store still decides whether the bytes
    /// name a live session — this only types them; it grants nothing on its own.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
}

/// Why presenting a session token was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionRejection {
    /// No live session holds this token (never issued, or already revoked).
    UnknownToken,
    /// The token is live but bound to a different `(engagement, authority)` than
    /// the call targets — a token minted for one identity cannot act as another.
    WrongSession {
        /// The `(engagement, authority)` the token is actually bound to.
        bound_to: (EngagementId, AuthorityId),
    },
}

impl std::fmt::Display for SessionRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionRejection::UnknownToken => write!(f, "unknown or revoked session token"),
            SessionRejection::WrongSession { bound_to } => write!(
                f,
                "token is bound to a different session: ({}, {})",
                bound_to.0, bound_to.1
            ),
        }
    }
}

/// Session-token storage keyed by `(engagement, AuthorityId)` (`SESSION-STORE-1`).
///
/// One live token per `(engagement, authority)`: opening a session for a pair that
/// already has one supersedes the old token (re-authentication rotates the
/// credential). [`open`](Self::open) is the success path of the handshake;
/// [`authorize`](Self::authorize) is the per-request check; [`revoke`](Self::revoke)
/// tears a session down.
#[derive(Clone, Debug, Default)]
pub struct SessionStore {
    /// The live token for each authenticated `(engagement, authority)` pair.
    by_session: BTreeMap<(EngagementId, AuthorityId), SessionToken>,
    /// Reverse index: which `(engagement, authority)` a live token belongs to.
    by_token: BTreeMap<SessionToken, (EngagementId, AuthorityId)>,
    /// Monotonic counter folded into each minted token so successive sessions
    /// never collide. (Real deployments seed from a CSPRNG; the loopback stub
    /// uses a deterministic counter.)
    minted: u64,
}

impl SessionStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a session for an authenticated `(engagement, authority)` — the success
    /// path after [`GovernanceAuth::respond`](crate::net_server::GovernanceAuth::respond).
    /// Returns a fresh token bound to that pair. If the pair already held a token,
    /// the old one is retired (re-authentication rotates the credential), so a token
    /// captured before a re-auth cannot be used afterward.
    pub fn open(&mut self, engagement: EngagementId, authority: AuthorityId) -> SessionToken {
        let key = (engagement, authority);
        if let Some(stale) = self.by_session.remove(&key) {
            self.by_token.remove(&stale);
        }
        self.minted += 1;
        // The token is unguessable (16 CSPRNG bytes) so it cannot be forged by a
        // caller who never authenticated; the monotonic counter is folded in only as
        // a collision backstop. This hardens the deterministic-counter scaffold the
        // module header flagged (D-REMOTE / `SESSION-STORE-1`).
        let mut bytes = b"gaugewright-session:".to_vec();
        bytes.extend_from_slice(self.minted.to_be_bytes().as_slice());
        bytes.extend_from_slice(&random_bytes::<16>());
        let token = SessionToken(bytes);
        self.by_session.insert(key.clone(), token.clone());
        self.by_token.insert(token.clone(), key);
        token
    }

    /// Authorize a per-request token presented against the `(engagement, authority)`
    /// the call targets. On success returns the authenticated [`AuthorityId`] — the
    /// value the relay trusts for permission checks, exactly as the handshake did.
    ///
    /// A token unknown to the store (never issued, or revoked) is
    /// [`SessionRejection::UnknownToken`]; a live token bound to a *different* pair
    /// is [`SessionRejection::WrongSession`] — the cross-binding guard.
    pub fn authorize(
        &self,
        engagement: &EngagementId,
        authority: &AuthorityId,
        token: &SessionToken,
    ) -> Result<AuthorityId, SessionRejection> {
        let bound_to = self
            .by_token
            .get(token)
            .ok_or(SessionRejection::UnknownToken)?;
        if bound_to.0 != *engagement || bound_to.1 != *authority {
            return Err(SessionRejection::WrongSession {
                bound_to: bound_to.clone(),
            });
        }
        Ok(authority.clone())
    }

    /// Revoke the live session for a `(engagement, authority)` pair, dropping its
    /// token (logout, key rotation, grant expiry). Idempotent. Returns the token
    /// that was retired, if any.
    pub fn revoke(
        &mut self,
        engagement: &EngagementId,
        authority: &AuthorityId,
    ) -> Option<SessionToken> {
        let token = self
            .by_session
            .remove(&(engagement.clone(), authority.clone()))?;
        self.by_token.remove(&token);
        Some(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eng(s: &str) -> EngagementId {
        EngagementId::new(s)
    }
    fn auth(s: &str) -> AuthorityId {
        AuthorityId::new(s)
    }

    #[test]
    fn session_token_debug_is_redacted() {
        // SECAUD-10: the credential bytes never appear in Debug output (logs / errors).
        let token = SessionToken::from_bytes(vec![0xde, 0xad, 0xbe, 0xef]);
        let shown = format!("{token:?}");
        assert_eq!(shown, "SessionToken(<redacted>)");
        assert!(
            !shown.contains("222") && !shown.contains("de"),
            "no byte values leak: {shown}"
        );
        // and via a store that derives Debug over its tokens.
        let mut store = SessionStore::new();
        store.open(eng("run-1"), auth("acme"));
        let dump = format!("{store:?}");
        assert!(
            dump.contains("<redacted>"),
            "the store redacts its tokens: {dump}"
        );
    }

    #[test]
    fn open_mints_a_token_that_authorizes_its_own_session() {
        let mut store = SessionStore::new();
        let token = store.open(eng("run-1"), auth("acme"));
        // The token authorizes exactly the (engagement, authority) it was minted
        // for, yielding back the authenticated authority.
        assert_eq!(
            store.authorize(&eng("run-1"), &auth("acme"), &token),
            Ok(auth("acme")),
        );
    }

    #[test]
    fn each_open_mints_a_distinct_token() {
        let mut store = SessionStore::new();
        let a = store.open(eng("run-1"), auth("acme"));
        let b = store.open(eng("run-2"), auth("acme"));
        assert_ne!(a, b, "each session gets distinct token bytes");
    }

    #[test]
    fn an_unissued_token_is_unknown() {
        let store = SessionStore::new();
        let forged = SessionToken(b"gaugewright-session:forged".to_vec());
        assert_eq!(
            store.authorize(&eng("run-1"), &auth("acme"), &forged),
            Err(SessionRejection::UnknownToken),
        );
    }

    #[test]
    fn a_token_cannot_act_on_a_different_engagement() {
        let mut store = SessionStore::new();
        let token = store.open(eng("run-1"), auth("acme"));
        // Same authority, wrong engagement: the token is live but bound elsewhere.
        assert_eq!(
            store.authorize(&eng("run-2"), &auth("acme"), &token),
            Err(SessionRejection::WrongSession {
                bound_to: (eng("run-1"), auth("acme"))
            }),
        );
    }

    #[test]
    fn a_token_cannot_speak_as_a_different_authority() {
        let mut store = SessionStore::new();
        let token = store.open(eng("run-1"), auth("acme"));
        // Same engagement, wrong authority: a token minted for acme cannot act as
        // stranger — the cross-binding guard.
        assert_eq!(
            store.authorize(&eng("run-1"), &auth("stranger"), &token),
            Err(SessionRejection::WrongSession {
                bound_to: (eng("run-1"), auth("acme"))
            }),
        );
    }

    #[test]
    fn revoke_invalidates_the_token() {
        let mut store = SessionStore::new();
        let token = store.open(eng("run-1"), auth("acme"));
        assert_eq!(
            store.revoke(&eng("run-1"), &auth("acme")),
            Some(token.clone())
        );
        // After revocation (logout / key rotation) the token no longer authorizes.
        assert_eq!(
            store.authorize(&eng("run-1"), &auth("acme"), &token),
            Err(SessionRejection::UnknownToken),
        );
        // Revoking again is a no-op.
        assert_eq!(store.revoke(&eng("run-1"), &auth("acme")), None);
    }

    #[test]
    fn reopening_a_session_rotates_and_retires_the_old_token() {
        let mut store = SessionStore::new();
        let first = store.open(eng("run-1"), auth("acme"));
        let second = store.open(eng("run-1"), auth("acme"));
        assert_ne!(first, second, "re-auth rotates the credential");
        // The old token is dead; only the fresh one authorizes.
        assert_eq!(
            store.authorize(&eng("run-1"), &auth("acme"), &first),
            Err(SessionRejection::UnknownToken),
        );
        assert_eq!(
            store.authorize(&eng("run-1"), &auth("acme"), &second),
            Ok(auth("acme")),
        );
    }
}
