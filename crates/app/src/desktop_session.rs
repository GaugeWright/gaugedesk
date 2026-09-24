//! The desktop hands its own UI a Home session (DR-0188).
//!
//! The Hub session stays sealed here (ADR 0123). What the webview receives is
//! an ordinary account session in this Home's own store, for the account the
//! Hub session names, minted only while that account has standing in this
//! Home's directory and never outliving the sign-in behind it. The shell hands
//! it to the webview over IPC; it never crosses HTTP.

use crate::{account_signin::HubStanding, org::Org, LockUnpoisoned, SharedWorkbench};

/// The authentication method recorded on the session.
pub const METHOD: &str = "desktop-hub";

/// The longest one session lives before it is minted again.
const MAX_LIFETIME_MS: i64 = 12 * 60 * 60 * 1000;

/// A session handed to this process's UI, and what it was minted for.
#[derive(Clone, Debug)]
pub(crate) struct DesktopUiSession {
    token: String,
    hub: HubStanding,
    expires_ms: i64,
}

fn now_ms() -> i64 {
    i64::try_from(crate::account::session_now_ms()).unwrap_or(i64::MAX)
}

/// Revoke whatever this process last handed its UI.
fn revoke_held(wb: &SharedWorkbench) {
    let mut guard = wb.lock_unpoisoned();
    if let Some(held) = guard.desktop_ui_session.take() {
        guard.revoke_account_session(&held.token);
    }
}

/// The Home session this desktop's UI should present now, or `None` when the
/// UI should keep the local posture: nobody signed in, the sign-in expired, or
/// the signed-in account holds no standing here. Reuses the session it minted
/// while that still holds; otherwise revokes it and mints another.
pub fn home_session(wb: &SharedWorkbench) -> Option<String> {
    // Read before the guard: this locks the workbench itself.
    let hub = crate::account_signin::hub_standing(wb);
    let now = now_ms();
    let Some(hub) = hub.filter(|hub| hub.expires_ms > now) else {
        revoke_held(wb);
        return None;
    };
    let standing = Org::rebuild(wb.lock_unpoisoned().store_ref())
        .ok()
        .is_some_and(|org| org.role_of(&hub.person).is_some());
    if !standing {
        revoke_held(wb);
        return None;
    }
    let mut guard = wb.lock_unpoisoned();
    if let Some(held) = &guard.desktop_ui_session {
        // Kept while it is the same sign-in, not near its end, and live here.
        if held.hub == hub
            && held.expires_ms - now > MAX_LIFETIME_MS / 12
            && guard.account_sessions().resolve_now(&held.token).is_some()
        {
            return Some(held.token.clone());
        }
    }
    if let Some(held) = guard.desktop_ui_session.take() {
        guard.revoke_account_session(&held.token);
    }
    let expires_ms = hub.expires_ms.min(now.saturating_add(MAX_LIFETIME_MS));
    let lifetime_secs = u64::try_from((expires_ms - now) / 1000)
        .ok()
        .filter(|s| *s > 0)?;
    let token = guard.mint_account_session(&hub.person, METHOD, lifetime_secs)?;
    guard.desktop_ui_session = Some(DesktopUiSession {
        token: token.clone(),
        hub,
        expires_ms,
    });
    Some(token)
}

/// Revoke the UI's session now, for a sign-out that should not wait for the
/// next read.
pub fn revoke(wb: &SharedWorkbench) {
    revoke_held(wb);
}

#[cfg(test)]
#[path = "desktop_session_tests.rs"]
mod tests;
