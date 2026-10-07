//! The desktop hands its own UI a Home session (DR-0188).
//!
//! The Hub session stays sealed here (ADR 0123). What the webview receives is
//! an ordinary account session in this Home's own store, for the account the
//! Hub session names, minted only while that account has standing in this
//! Home's directory and never outliving the sign-in behind it. The shell hands
//! it to the webview over IPC; it never crosses HTTP.

use crate::retained_signin_log::Outcome;
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

/// Which held session: the UI's own, or the one an account's relay
/// crossings are served under. One slot per account, so rotating one never
/// revokes another's token, and any account signed in here may cross
/// (DR-0328 §6).
#[derive(Clone, Copy)]
enum Slot<'a> {
    Ui,
    Relay(&'a str),
}

fn slot<'w>(guard: &'w mut crate::Workbench, which: Slot<'_>) -> &'w mut Option<DesktopUiSession> {
    match which {
        Slot::Ui => &mut guard.desktop_ui_session,
        Slot::Relay(account) => guard.relay_sessions.entry(account.to_owned()).or_default(),
    }
}

/// Revoke whatever this process last handed from one slot.
fn revoke_held(wb: &SharedWorkbench, which: Slot<'_>) {
    let mut guard = wb.lock_unpoisoned();
    if let Some(held) = slot(&mut guard, which).take() {
        guard.revoke_account_session(&held.token);
    }
}

/// The Home session this desktop's UI should present now, or `None` when the
/// UI should keep the local posture: nobody signed in, the sign-in expired, or
/// the signed-in account holds no standing here. Reuses the session it minted
/// while that still holds; otherwise revokes it and mints another.
pub fn home_session(wb: &SharedWorkbench) -> Option<String> {
    session_for(wb, Slot::Ui, None)
}

/// The Home session a relay crossing is served under once the Hub has said
/// its bearer is `account`'s (DR-0206): a session for that exact retained
/// sign-in, independent of which account the window currently selects.
///
/// Without that account's retained sign-in or Home membership it is `None`,
/// and the crossing is refused. Signing that account out ends its remote access.
pub(crate) fn relay_session(wb: &SharedWorkbench, account: &str) -> Option<String> {
    session_for(wb, Slot::Relay(account), Some(account))
}

fn session_for(wb: &SharedWorkbench, which: Slot<'_>, account: Option<&str>) -> Option<String> {
    // Read before the guard: this locks the workbench itself.
    let hub = match account {
        Some(person) => crate::account_signin::hub_standing_for(wb, person),
        None => crate::account_signin::hub_standing(wb),
    };
    let now = now_ms();
    // A sign-in that does not open or is not retained was already named in
    // the log where it was read; an expired one is named here.
    if let Some(hub) = hub.as_ref().filter(|hub| hub.expires_ms <= now) {
        crate::retained_signin_log::note(&hub.person, Outcome::Expired);
    }
    let Some(hub) = hub
        .filter(|hub| hub.expires_ms > now)
        .filter(|hub| account.is_none_or(|account| hub.person == account))
    else {
        revoke_held(wb, which);
        return None;
    };
    // Any account signed in on this computer works here as itself; a role in
    // its directory is not standing (DR-0268, DR-0328). What it reaches is
    // decided per project. Off a desktop a role is still required.
    let standing = {
        let guard = wb.lock_unpoisoned();
        guard.desktop_account_mode()
            || Org::rebuild(guard.store_ref())
                .ok()
                .is_some_and(|org| org.role_of(&hub.person).is_some())
    };
    if !standing {
        crate::retained_signin_log::note(&hub.person, Outcome::NoHomeSession);
        revoke_held(wb, which);
        return None;
    }
    // The account working in this window has a Personal of its own here
    // (DR-0268 §5). A relay caller works on its own host, so gets none.
    if matches!(which, Slot::Ui) {
        if let Err(error) = wb.lock_unpoisoned().ensure_account_personal(&hub.person) {
            tracing::warn!("could not prepare this account's Personal: {error}");
        }
    }
    let mut guard = wb.lock_unpoisoned();
    if let Some(held) = slot(&mut guard, which).clone() {
        // Kept while it is the same sign-in, not near its end, and live here.
        if held.hub == hub
            && held.expires_ms - now > MAX_LIFETIME_MS / 12
            && guard.account_sessions().resolve_now(&held.token).is_some()
        {
            return Some(held.token.clone());
        }
    }
    if let Some(held) = slot(&mut guard, which).take() {
        guard.revoke_account_session(&held.token);
    }
    let expires_ms = hub.expires_ms.min(now.saturating_add(MAX_LIFETIME_MS));
    let minted = u64::try_from((expires_ms - now) / 1000)
        .ok()
        .filter(|s| *s > 0)
        .and_then(|lifetime_secs| guard.mint_account_session(&hub.person, METHOD, lifetime_secs));
    let Some(token) = minted else {
        crate::retained_signin_log::note(&hub.person, Outcome::NoHomeSession);
        return None;
    };
    crate::retained_signin_log::note(&hub.person, Outcome::Opened);
    *slot(&mut guard, which) = Some(DesktopUiSession {
        token: token.clone(),
        hub,
        expires_ms,
    });
    Some(token)
}

/// The session a project member's relay crossings are served under: an
/// account the Hub named that is not signed in on this computer but holds a
/// grant to a project this Home serves (DR-0328 §6, DR-0332). It is this
/// Home's own and never leaves it; the relay puts it on each admitted
/// crossing in place of whatever the caller brought.
#[derive(Clone, Debug)]
pub(crate) struct MemberSession {
    token: String,
    expires_ms: i64,
}

/// The authentication method recorded on a member's session.
pub(crate) const MEMBER_METHOD: &str = "relay-member";

/// Standing is read again on every crossing and the session never leaves this
/// Home, so its lifetime bounds only how long it outlives a process that
/// forgot it. The window's own session's ceiling, which also keeps the
/// durable session facts a member's work writes to two a day.
const MEMBER_LIFETIME_MS: i64 = MAX_LIFETIME_MS;

/// The projects this Home serves that `account` holds an explicit grant to,
/// as an active member of its directory. Owning a project does not count:
/// an owner reaches its projects by being signed in on the computer, and
/// signing out ends that (DR-0328 §6). Unreadable evidence grants nothing.
pub(crate) fn member_projects(
    wb: &crate::Workbench,
    account: &str,
) -> std::collections::BTreeSet<String> {
    let Ok(org) = Org::rebuild(wb.store_ref()) else {
        return Default::default();
    };
    if account.is_empty() || org.role_of(account).is_none() {
        return Default::default();
    }
    org.granted_project_ids(account)
        .into_iter()
        .filter(|project| wb.owns_project(project))
        .collect()
}

/// The Home session a project member's relay crossing is served under, or
/// `None` once the account holds no grant here. The session reaches what any
/// account session for that account reaches on this desktop: its owned and
/// granted projects (DR-0268), which for a member is its grants alone.
pub(crate) fn member_session(wb: &SharedWorkbench, account: &str) -> Option<String> {
    let mut guard = wb.lock_unpoisoned();
    let standing = guard.desktop_account_mode() && !member_projects(&guard, account).is_empty();
    let now = now_ms();
    if standing {
        if let Some(held) = guard.relay_member_sessions.get(account) {
            if held.expires_ms - now > MEMBER_LIFETIME_MS / 12
                && guard.account_sessions().resolve_now(&held.token).is_some()
            {
                return Some(held.token.clone());
            }
        }
    }
    if let Some(held) = guard.relay_member_sessions.remove(account) {
        guard.revoke_account_session(&held.token);
    }
    if !standing {
        return None;
    }
    let lifetime_secs = u64::try_from(MEMBER_LIFETIME_MS / 1000).unwrap_or(12 * 60 * 60);
    let token = guard.mint_account_session(account, MEMBER_METHOD, lifetime_secs)?;
    guard.relay_member_sessions.insert(
        account.to_owned(),
        MemberSession {
            token: token.clone(),
            expires_ms: now.saturating_add(MEMBER_LIFETIME_MS),
        },
    );
    Some(token)
}

/// Revoke both sessions now, for a sign-out that should not wait for the next
/// read: the UI's, and the one remote crossings were being served under.
pub fn revoke(wb: &SharedWorkbench) {
    revoke_held(wb, Slot::Ui);
    let accounts: Vec<String> = wb
        .lock_unpoisoned()
        .relay_sessions
        .keys()
        .cloned()
        .collect();
    for account in accounts {
        revoke_held(wb, Slot::Relay(&account));
    }
}

#[cfg(test)]
#[path = "desktop_session_tests.rs"]
mod tests;
