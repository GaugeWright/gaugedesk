//! Opaque Hub account sessions (`AUTH-2`).
//!
//! A session authenticates the durable GaugeDesk account id, never the
//! WebAuthn credential that happened to prove control. Raw bearer values exist
//! only at issuance and in the browser's HttpOnly cookie; this store keys them
//! by a domain-separated digest and bounds every entry by an absolute expiry.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use base64::Engine as _;
use sha2::{Digest, Sha256};

const MAX_ACTIVE_SESSIONS: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Eq)]
struct AccountSession {
    account_id: String,
    expires_at: u64,
}

#[derive(Default)]
pub struct AccountSessionStore {
    sessions: Mutex<BTreeMap<String, AccountSession>>,
}

impl AccountSessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint 256 bits of bearer entropy and retain only its digest.
    pub fn issue(&self, account_id: &str, now: u64, lifetime_secs: u64) -> Option<String> {
        if account_id.trim().is_empty() || lifetime_secs == 0 {
            return None;
        }
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).ok()?;
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let mut sessions = self.lock();
        sessions.retain(|_, session| session.expires_at > now);
        if sessions.len() >= MAX_ACTIVE_SESSIONS {
            return None;
        }
        sessions.insert(
            token_digest(&token),
            AccountSession {
                account_id: account_id.to_owned(),
                expires_at: now.saturating_add(lifetime_secs),
            },
        );
        Some(token)
    }

    pub fn resolve(&self, token: &str, now: u64) -> Option<String> {
        let key = token_digest(token);
        let mut sessions = self.lock();
        let session = sessions.get(&key)?.clone();
        if session.expires_at <= now {
            sessions.remove(&key);
            return None;
        }
        Some(session.account_id)
    }

    pub fn resolve_now(&self, token: &str) -> Option<String> {
        self.resolve(token, unix_now())
    }

    pub fn revoke(&self, token: &str) -> bool {
        self.lock().remove(&token_digest(token)).is_some()
    }

    #[cfg(test)]
    fn contains_raw_token(&self, token: &str) -> bool {
        self.lock().keys().any(|key| key.contains(token))
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, AccountSession>> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn token_digest(token: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"gaugedesk:account-session:v1");
    digest.update((token.len() as u64).to_be_bytes());
    digest.update(token.as_bytes());
    hex::encode(digest.finalize())
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_names_account_not_authenticator_and_stores_no_bearer() {
        let sessions = AccountSessionStore::new();
        let token = sessions.issue("account-root", 10, 60).unwrap();
        assert_eq!(
            sessions.resolve(&token, 69).as_deref(),
            Some("account-root")
        );
        assert!(!sessions.contains_raw_token(&token));
    }

    #[test]
    fn expiry_and_revocation_fail_closed() {
        let sessions = AccountSessionStore::new();
        let expired = sessions.issue("account-root", 10, 60).unwrap();
        assert_eq!(sessions.resolve(&expired, 70), None);

        let revoked = sessions.issue("account-root", 80, 60).unwrap();
        assert!(sessions.revoke(&revoked));
        assert_eq!(sessions.resolve(&revoked, 81), None);
    }
}
