//! Per-session activity tracking for the org **session-timeout policy** (`SEC-2`). The org
//! security policy declares an absolute `session_lifetime_secs` and an `idle_timeout_secs`;
//! this enforces them on the enterprise data-route admission: each authenticated session
//! (keyed by a hash of its bearer, never the raw credential) records its first-seen and
//! last-seen, and a request is refused once the session exceeds either bound — forcing a
//! genuine re-authentication (a new token → a fresh session key).
//!
//! Pure over an **injected** monotonic `now_ms` so the timeout logic is exhaustively
//! unit-tested; the live impl reads an internal [`Instant`] epoch. Additive to the auth
//! middleware — a future unified session registry (`ITGOV-2`) can subsume it. No-op when the
//! policy leaves both bounds unset (`0`), so the single-user / no-policy path is untouched.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Instant;

use crate::client_admission::{ClientAdmission, ClientAdmissionStatus, ClientBuild};

/// Why a session was refused (`SEC-2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionExpiry {
    /// The session exceeded the absolute `session_lifetime_secs`.
    Lifetime,
    /// The session was idle longer than `idle_timeout_secs`.
    Idle,
}

impl SessionExpiry {
    /// A client-facing reason string.
    pub fn reason(self) -> &'static str {
        match self {
            SessionExpiry::Lifetime => "session expired (max lifetime); re-authenticate",
            SessionExpiry::Idle => "session timed out (idle); re-authenticate",
        }
    }
}

/// One live session in the **IT session roster** (`ITGOV-2`): which member is active and
/// how long since first-seen / last-seen. The bearer is never included — only the authority.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SessionInfo {
    pub authority: String,
    pub age_ms: u64,
    pub idle_ms: u64,
    /// Compatibility evidence reported by the client; never device attestation.
    pub client: ClientBuild,
    pub software_status: ClientAdmissionStatus,
    pub software_reason: String,
}

#[derive(Clone)]
struct SessionEntry {
    authority: String,
    first_seen_ms: u64,
    last_seen_ms: u64,
    client: ClientBuild,
    admission: ClientAdmission,
}

/// The activity ledger: `key(bearer-hash) -> (authority, first_seen_ms, last_seen_ms)`.
pub struct SessionActivity {
    epoch: Instant,
    inner: Mutex<BTreeMap<String, SessionEntry>>,
}

impl Default for SessionActivity {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionActivity {
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
            inner: Mutex::new(BTreeMap::new()),
        }
    }

    /// Milliseconds since this tracker's epoch — the live monotonic clock.
    pub fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Check `key`'s session against the policy bounds at `now_ms`, recording activity for
    /// `authority`. A bound of `0` ms is **unset** (not enforced). On the **first** sighting
    /// the session starts now (always allowed). Within bounds, `last_seen` is refreshed. On a
    /// violation the entry is left **as-is** (not refreshed) so the same expired token keeps
    /// being refused until the client re-authenticates with a fresh one. Recording here is
    /// what makes the session appear in the IT roster (`ITGOV-2`/`ITGOV-3(d)`).
    pub fn check_and_touch(
        &self,
        key: &str,
        authority: &str,
        now_ms: u64,
        lifetime_ms: u64,
        idle_ms: u64,
    ) -> Result<(), SessionExpiry> {
        self.check_and_touch_client(
            key,
            authority,
            now_ms,
            lifetime_ms,
            idle_ms,
            ClientBuild::default(),
            ClientAdmission {
                status: ClientAdmissionStatus::Unmanaged,
                reason: "no organization software policy".to_string(),
            },
        )
    }

    /// The session-timeout check plus `ITGOV-4`'s reported build/status update.
    /// A software-blocked attempt is deliberately recorded before the caller refuses
    /// the request, so IT can see the session that needs repair.
    #[allow(clippy::too_many_arguments)]
    pub fn check_and_touch_client(
        &self,
        key: &str,
        authority: &str,
        now_ms: u64,
        lifetime_ms: u64,
        idle_ms: u64,
        client: ClientBuild,
        admission: ClientAdmission,
    ) -> Result<(), SessionExpiry> {
        let mut m = self.inner.lock().expect("session-activity mutex");
        let (first, last) = m
            .get(key)
            .map(|entry| (entry.first_seen_ms, entry.last_seen_ms))
            .unwrap_or((now_ms, now_ms));
        if lifetime_ms > 0 && now_ms.saturating_sub(first) > lifetime_ms {
            return Err(SessionExpiry::Lifetime);
        }
        if idle_ms > 0 && now_ms.saturating_sub(last) > idle_ms {
            return Err(SessionExpiry::Idle);
        }
        m.insert(
            key.to_string(),
            SessionEntry {
                authority: authority.to_string(),
                first_seen_ms: first,
                last_seen_ms: now_ms,
                client,
                admission,
            },
        );
        Ok(())
    }

    /// The live session roster at `now_ms` (`ITGOV-2`): one entry per tracked session, most
    /// recently active first, with the authority (never the bearer) and its age/idle.
    pub fn roster(&self, now_ms: u64) -> Vec<SessionInfo> {
        let m = self.inner.lock().expect("session-activity mutex");
        let mut out: Vec<SessionInfo> = m
            .values()
            .map(|entry| SessionInfo {
                authority: entry.authority.clone(),
                age_ms: now_ms.saturating_sub(entry.first_seen_ms),
                idle_ms: now_ms.saturating_sub(entry.last_seen_ms),
                client: entry.client.clone(),
                software_status: entry.admission.status,
                software_reason: entry.admission.reason.clone(),
            })
            .collect();
        out.sort_by_key(|s| s.idle_ms);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sighting_is_always_allowed_and_starts_the_clock() {
        let a = SessionActivity::new();
        assert_eq!(a.check_and_touch("k", "u", 1000, 5000, 2000), Ok(()));
    }

    #[test]
    fn within_bounds_refreshes_idle_and_stays_allowed() {
        let a = SessionActivity::new();
        assert_eq!(a.check_and_touch("k", "u", 0, 10_000, 3000), Ok(()));
        // 2s later (< 3s idle, < 10s lifetime) — allowed, and idle clock resets.
        assert_eq!(a.check_and_touch("k", "u", 2000, 10_000, 3000), Ok(()));
        // another 2s (idle since last = 2s < 3s) — still allowed.
        assert_eq!(a.check_and_touch("k", "u", 4000, 10_000, 3000), Ok(()));
    }

    #[test]
    fn idle_beyond_the_timeout_is_refused() {
        let a = SessionActivity::new();
        assert_eq!(a.check_and_touch("k", "u", 0, 0, 3000), Ok(()));
        // 4s idle > 3s — refused.
        assert_eq!(
            a.check_and_touch("k", "u", 4000, 0, 3000),
            Err(SessionExpiry::Idle)
        );
        // and it keeps being refused (entry not refreshed on rejection).
        assert_eq!(
            a.check_and_touch("k", "u", 5000, 0, 3000),
            Err(SessionExpiry::Idle)
        );
    }

    #[test]
    fn lifetime_beyond_the_max_is_refused_even_when_active() {
        let a = SessionActivity::new();
        assert_eq!(a.check_and_touch("k", "u", 0, 5000, 0), Ok(()));
        // active every 1s, but total age crosses 5s → refused on lifetime.
        assert_eq!(a.check_and_touch("k", "u", 3000, 5000, 0), Ok(()));
        assert_eq!(
            a.check_and_touch("k", "u", 6000, 5000, 0),
            Err(SessionExpiry::Lifetime)
        );
    }

    #[test]
    fn unset_policy_never_refuses() {
        let a = SessionActivity::new();
        for t in [0, 10_000, 10_000_000] {
            assert_eq!(a.check_and_touch("k", "u", t, 0, 0), Ok(()));
        }
    }

    #[test]
    fn sessions_are_keyed_independently() {
        let a = SessionActivity::new();
        assert_eq!(a.check_and_touch("ka", "alice", 0, 0, 3000), Ok(()));
        assert_eq!(a.check_and_touch("kb", "bob", 4000, 0, 3000), Ok(())); // bob's first sighting
        assert_eq!(
            a.check_and_touch("ka", "alice", 4000, 0, 3000),
            Err(SessionExpiry::Idle)
        ); // alice idle
    }

    #[test]
    fn roster_lists_active_sessions_by_authority_most_recent_first() {
        // ITGOV-2: the roster surfaces who is active — the authority (never the bearer),
        // ordered by least-idle first.
        let a = SessionActivity::new();
        a.check_and_touch("ka", "alice", 0, 0, 0).unwrap();
        a.check_and_touch("kb", "bob", 0, 0, 0).unwrap();
        a.check_and_touch("kb", "bob", 5000, 0, 0).unwrap(); // bob active more recently
        let r = a.roster(6000);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].authority, "bob", "least-idle first");
        assert_eq!(r[0].idle_ms, 1000);
        assert_eq!(r[1].authority, "alice");
        assert_eq!(r[1].idle_ms, 6000);
        assert_eq!(r[1].age_ms, 6000);
    }
}
