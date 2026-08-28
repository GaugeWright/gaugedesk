//! Failed-attempt throttling for authentication surfaces (`SECAUD-8`, SOC 2
//! CC6.6/CC6.7) — defense-in-depth brute-force protection.
//!
//! High-entropy bearer tokens already make online brute force impractical, and the
//! **primary** rate-limit control belongs at the deployment edge (WAF / reverse
//! proxy). This is the in-process backstop: after too many failures for a key within
//! a window, the key is **locked out** until the window passes, so a guessing loop is
//! slowed even if it reaches the process directly.
//!
//! Fixed-window lockout, keyed by an arbitrary string. Callers key it on the **real client
//! IP** (`workbench_auth::throttle_scope` — `CF-Connecting-IP` at the hosted edge, the socket
//! peer below it), never on a client-supplied header: a header an attacker controls could be
//! rotated for a fresh bucket per request, or spoofed to lock a victim out. Time is supplied
//! as monotonic milliseconds so the policy is pure and unit-testable; production reads it from
//! an internal start [`Instant`](std::time::Instant) via [`Throttle::now_ms`].

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// A fixed-window failed-attempt lockout. After `max_failures` failures for a key
/// within `window_ms`, the key is denied until that window elapses; a success clears
/// the key. Keyed by string; cheap and lock-guarded for shared use.
pub struct Throttle {
    inner: Mutex<HashMap<String, Attempts>>,
    max_failures: u32,
    window_ms: u64,
    start: Instant,
}

#[derive(Clone, Copy)]
struct Attempts {
    failures: u32,
    window_start_ms: u64,
}

impl Throttle {
    /// `max_failures` within `window_ms` triggers a lockout for the rest of the window.
    pub fn new(max_failures: u32, window_ms: u64) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_failures: max_failures.max(1),
            window_ms,
            start: Instant::now(),
        }
    }

    /// Monotonic milliseconds since construction — the production clock source.
    pub fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Whether `key` is currently allowed (not locked out) at `now_ms`.
    pub fn allowed(&self, key: &str, now_ms: u64) -> bool {
        let m = self.inner.lock().expect("throttle mutex");
        !matches!(
            m.get(key),
            Some(a)
                if a.failures >= self.max_failures
                    && now_ms.saturating_sub(a.window_start_ms) < self.window_ms
        )
    }

    /// Record a failed attempt for `key` at `now_ms`. A failure after the window has
    /// elapsed starts a fresh window.
    pub fn record_failure(&self, key: &str, now_ms: u64) {
        let mut m = self.inner.lock().expect("throttle mutex");
        let a = m.entry(key.to_string()).or_insert(Attempts {
            failures: 0,
            window_start_ms: now_ms,
        });
        if now_ms.saturating_sub(a.window_start_ms) >= self.window_ms {
            a.failures = 0;
            a.window_start_ms = now_ms;
        }
        a.failures = a.failures.saturating_add(1);
    }

    /// Clear `key`'s failure record (on a successful authentication).
    pub fn record_success(&self, key: &str) {
        self.inner.lock().expect("throttle mutex").remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_out_after_max_failures_within_the_window() {
        let t = Throttle::new(3, 1000);
        assert!(t.allowed("k", 0), "allowed before any failure");
        t.record_failure("k", 0);
        t.record_failure("k", 100);
        assert!(t.allowed("k", 200), "still allowed below the threshold");
        t.record_failure("k", 200); // third failure trips the lockout
        assert!(!t.allowed("k", 300), "locked out within the window");
    }

    #[test]
    fn the_lockout_expires_when_the_window_passes() {
        let t = Throttle::new(2, 1000);
        t.record_failure("k", 0);
        t.record_failure("k", 10);
        assert!(!t.allowed("k", 500), "locked within the window");
        assert!(
            t.allowed("k", 1010),
            "allowed again once the window elapses"
        );
    }

    #[test]
    fn a_success_clears_the_failure_record() {
        let t = Throttle::new(2, 1000);
        t.record_failure("k", 0);
        t.record_failure("k", 10);
        assert!(!t.allowed("k", 100));
        t.record_success("k");
        assert!(t.allowed("k", 100), "a success resets the counter");
    }

    #[test]
    fn keys_are_isolated() {
        // Keys are opaque strings; callers pass a client IP, so one abused client never
        // locks out another (nor, at the callsite, another tenant).
        let t = Throttle::new(1, 1000);
        t.record_failure("198.51.100.1", 0);
        assert!(!t.allowed("198.51.100.1", 1), "the abused key is locked");
        assert!(t.allowed("198.51.100.2", 1), "another key is unaffected");
    }
}
