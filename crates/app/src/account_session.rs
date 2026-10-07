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
    /// The sign-in method that minted this session. Consumer sessions use
    /// `"oidc"` or `"passkey"`; organization SSO sessions bind the exact
    /// connection as `"enterprise-oidc:<connection>"` or
    /// `"enterprise-saml:<connection>"`. The session surface reports the safe
    /// family label (`get_session`); the durable index carries the exact value
    /// (`ADR 0147` §1).
    method: String,
    expires_at: u64,
}

/// Current non-secret bounds of one verified opaque session (DR-0262).
/// This is authenticated response evidence, never an offline work capability.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AccountSessionEvidence {
    pub session_ref: String,
    pub method: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

/// Verify durable session bounds without needing the original bearer. Both
/// request authentication and retained action read bases consult this authority.
/// Callers fence the legacy catalog, exact account-auth and account scopes in
/// their dispatch basis. Unreadable authority rows never reveal older standing.
///
/// Only a session of `account_id` — the account the caller already holds for
/// this bearer — is answered, and only that account's authority is read: both
/// callers refuse a session of any other account, so reading every account's
/// to find it would decide nothing more (WS-849).
pub(crate) fn durable_evidence(
    store: &gaugedesk_store::Store,
    session_ref: &str,
    account_id: &str,
    now_ms: u64,
) -> Result<Option<(String, AccountSessionEvidence)>, gaugedesk_store::AdmitError> {
    let custody = crate::account_auth_custody::AccountAuthCustodyCatalog::rebuild_retained(store)?
        .account(account_id);
    if !custody.reads_account_scope() {
        store.retained_events(crate::account_auth::ACCOUNT_AUTH_SCOPE)?;
    }
    let auth = crate::account_auth::AccountAuth::rebuild_for_account(store, account_id)?;
    let Some(record) = auth.sessions.get(session_ref) else {
        return Ok(None);
    };
    if record.issued_at_ms == 0 || record.lifetime_secs == 0 {
        return Ok(None);
    }
    let auth_scope =
        crate::account_auth_custody::account_auth_scope(&record.account_id).map_err(|_| {
            gaugedesk_store::AdmitError::Codec("invalid account-auth scope identity".into())
        })?;
    store.retained_events(&auth_scope)?;
    let scope = crate::account::account_scope(&record.account_id);
    store.retained_events(&scope)?;
    let account = crate::account::Account::rebuild_in(store, &scope)?;
    if !record.device_id.is_empty()
        && !account
            .devices
            .get(&record.device_id)
            .is_some_and(|device| device.status == crate::account::DeviceStatus::Active)
    {
        return Ok(None);
    }
    let mut last_seen_ms = record.last_seen_ms;
    let mut expires_at_ms = record
        .issued_at_ms
        .saturating_add(record.lifetime_secs.saturating_mul(1000))
        .min(
            record
                .issued_at_ms
                .saturating_add(crate::account::SESSION_ABSOLUTE_LIFETIME_MS),
        );
    if let Some(grant) = account.refresh_sessions.get(session_ref) {
        if grant.issued_at_ms == 0
            || grant.device_id != record.device_id
            || (!grant.device_id.is_empty()
                && grant.binding != crate::account::RefreshBinding::Device)
        {
            return Ok(None);
        }
        last_seen_ms = grant.last_seen_ms;
        expires_at_ms = expires_at_ms.min(
            grant
                .issued_at_ms
                .saturating_add(crate::account::SESSION_ABSOLUTE_LIFETIME_MS),
        );
    }
    expires_at_ms = expires_at_ms.min(last_seen_ms.saturating_add(crate::account::SESSION_IDLE_MS));
    if last_seen_ms == 0 || expires_at_ms <= now_ms {
        return Ok(None);
    }
    Ok(Some((
        record.account_id.clone(),
        AccountSessionEvidence {
            session_ref: session_ref.to_owned(),
            method: record.method.clone(),
            issued_at_ms: record.issued_at_ms,
            expires_at_ms,
        },
    )))
}

/// The in-memory hot cache of live opaque sessions. It is the request-path resolver
/// (`authenticate_bearer`); its durable backing is the `AccountSessionRecord` index
/// in the shared `account-auth` scope (`ADR 0147` §1), written through on mint/revoke
/// and rebuilt into this cache on startup so a session survives a restart.
#[derive(Default)]
pub struct AccountSessionStore {
    sessions: Mutex<BTreeMap<String, AccountSession>>,
}

impl AccountSessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint 256 bits of bearer entropy for a `method` session and retain only its
    /// digest. Returns the raw token; the caller writes the durable index record and
    /// keys the per-session refresh grant by [`session_id`]`(&token)`.
    pub fn issue_with_method(
        &self,
        account_id: &str,
        method: &str,
        now: u64,
        lifetime_secs: u64,
    ) -> Option<String> {
        if account_id.trim().is_empty() || method.trim().is_empty() || lifetime_secs == 0 {
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
                method: method.to_owned(),
                expires_at: now.saturating_add(lifetime_secs),
            },
        );
        Some(token)
    }

    /// Back-compat shim: mint a `"passkey"` session. New call sites route through the
    /// Workbench so the durable index is written; this remains for the pure-cache
    /// unit tests.
    pub fn issue(&self, account_id: &str, now: u64, lifetime_secs: u64) -> Option<String> {
        self.issue_with_method(account_id, "passkey", now, lifetime_secs)
    }

    /// Re-seat one session in the cache from its durable index record on startup,
    /// keyed by the stored session id (token digest). `expires_at` bounds cache
    /// liveness independently of the durable log.
    pub fn insert_loaded(&self, session_id: &str, account_id: &str, method: &str, expires_at: u64) {
        let mut sessions = self.lock();
        if sessions.len() >= MAX_ACTIVE_SESSIONS {
            return;
        }
        sessions.insert(
            session_id.to_owned(),
            AccountSession {
                account_id: account_id.to_owned(),
                method: method.to_owned(),
                expires_at,
            },
        );
    }

    pub fn resolve(&self, token: &str, now: u64) -> Option<String> {
        self.resolve_session_at(token, now)
            .map(|(account, _)| account)
    }

    pub fn resolve_now(&self, token: &str) -> Option<String> {
        self.resolve(token, unix_now())
    }

    /// Resolve the live session to `(account_id, method)`, or `None` if unknown or
    /// past its cache expiry. The session surface reads the method through this so it
    /// reports the true sign-in method rather than a hardcoded label (`ADR 0147` §1).
    pub fn resolve_session(&self, token: &str) -> Option<(String, String)> {
        self.resolve_session_at(token, unix_now())
    }

    fn resolve_session_at(&self, token: &str, now: u64) -> Option<(String, String)> {
        self.resolve_bounds_at(token, now)
            .map(|(account, method, _)| (account, method))
    }

    /// Live cache bounds, used only alongside the authoritative durable record.
    pub(crate) fn resolve_bounds(&self, token: &str) -> Option<(String, String, u64)> {
        self.resolve_bounds_at(token, unix_now())
    }

    fn resolve_bounds_at(&self, token: &str, now: u64) -> Option<(String, String, u64)> {
        let key = token_digest(token);
        let mut sessions = self.lock();
        let session = sessions.get(&key)?.clone();
        if session.expires_at <= now {
            sessions.remove(&key);
            return None;
        }
        Some((session.account_id, session.method, session.expires_at))
    }

    pub fn revoke(&self, token: &str) -> bool {
        self.lock().remove(&token_digest(token)).is_some()
    }

    /// Evict a session by its durable, already-digested id. Administrative and
    /// account-management surfaces never possess another session's raw bearer;
    /// revocation therefore names the same opaque id carried by the durable index.
    pub fn revoke_id(&self, session_id: &str) -> bool {
        self.lock().remove(session_id).is_some()
    }

    /// Evict every hot bearer for one account and return their opaque session
    /// ids. Account erasure uses this after its global fence wins; the returned
    /// ids are safe coordination values and never reveal the bearer tokens.
    pub fn revoke_account(&self, account_id: &str) -> Vec<String> {
        let mut sessions = self.lock();
        let ids = sessions
            .iter()
            .filter_map(|(id, session)| (session.account_id == account_id).then_some(id.clone()))
            .collect::<Vec<_>>();
        for id in &ids {
            sessions.remove(id);
        }
        ids
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

/// The session id for an opaque token: its domain-separated digest. The raw token is
/// never stored anywhere; this id keys both the durable session index and the
/// per-session refresh grant (`ADR 0147` §1/§2).
pub fn session_id(token: &str) -> String {
    token_digest(token)
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
    fn resolve_session_carries_the_minting_method() {
        let sessions = AccountSessionStore::new();
        // Mint relative to the wall clock so the un-parameterized `resolve_session`
        // (which reads `unix_now`) still sees a live session.
        let base = unix_now();
        let oidc = sessions
            .issue_with_method("account-root", "oidc", base, 3600)
            .unwrap();
        assert_eq!(
            sessions.resolve_session(&oidc),
            Some(("account-root".to_string(), "oidc".to_string()))
        );
        // A blank method or account is refused at issuance.
        assert!(sessions
            .issue_with_method("account-root", "", base, 3600)
            .is_none());
        assert!(sessions.issue_with_method("", "oidc", base, 3600).is_none());
        // The back-compat `issue` shim mints a passkey session.
        let passkey = sessions.issue("account-root", base, 3600).unwrap();
        assert_eq!(
            sessions.resolve_session(&passkey),
            Some(("account-root".to_string(), "passkey".to_string()))
        );
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

    #[test]
    fn account_eviction_removes_only_that_accounts_opaque_bearers() {
        let sessions = AccountSessionStore::new();
        let alice_one = sessions.issue("alice", 10, 60).unwrap();
        let alice_two = sessions.issue("alice", 10, 60).unwrap();
        let bob = sessions.issue("bob", 10, 60).unwrap();

        let mut removed = sessions.revoke_account("alice");
        removed.sort();
        let mut expected = vec![session_id(&alice_one), session_id(&alice_two)];
        expected.sort();
        assert_eq!(removed, expected);
        assert_eq!(sessions.resolve(&alice_one, 11), None);
        assert_eq!(sessions.resolve(&alice_two, 11), None);
        assert_eq!(sessions.resolve(&bob, 11).as_deref(), Some("bob"));
    }
}
