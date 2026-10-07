//! What became of each retained sign-in, in the persistent log.
//!
//! A sign-in the desktop retains can stop presenting for several reasons — its
//! sealed session no longer opens, it expired, the selection names an account
//! this computer holds no sign-in for, or the Home would not mint the window a
//! session for it — and each of those used to be a silent `None`. After an
//! update on 2026-10-07 the window asked the person to sign in again and the
//! log said nothing about why. Each account's outcome is now logged when it
//! changes, so the status polls that ask every few seconds do not repeat it,
//! and a sign-in that stops opening is named with its reason the first time.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// What happened the last time a retained sign-in was asked to present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The sealed session opened.
    Opened,
    /// The Hub session it holds has expired.
    Expired,
    /// The sealed session does not open under this computer's account key.
    Unsealable,
    /// The selection names an account this computer retains no sign-in for.
    NotRetained,
    /// The Home would not mint this window a session for the account.
    NoHomeSession,
}

static LAST: Mutex<BTreeMap<String, Outcome>> = Mutex::new(BTreeMap::new());

/// A short, stable tag for an account id in the log: enough to tell two
/// accounts apart and to match a store row, without writing out a 130-byte
/// public-key id on every line.
pub(crate) fn account_tag(person: &str) -> String {
    let mut chars = person.chars();
    let head: String = chars.by_ref().take(12).collect();
    if chars.next().is_some() {
        format!("{head}…({} chars)", person.chars().count())
    } else {
        head
    }
}

/// Record `outcome` for `person`, logging it when it differs from the last one
/// recorded in this process. Returns whether it was logged.
pub(crate) fn note(person: &str, outcome: Outcome) -> bool {
    let changed = {
        let mut last = LAST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        last.insert(person.to_owned(), outcome) != Some(outcome)
    };
    if changed {
        log(person, outcome);
    }
    changed
}

fn log(person: &str, outcome: Outcome) {
    let account = account_tag(person);
    match outcome {
        Outcome::Opened => tracing::info!(%account, "retained sign-in opened"),
        Outcome::Expired => tracing::info!(
            %account,
            "retained sign-in has expired; the account must sign in again"
        ),
        Outcome::Unsealable => tracing::warn!(
            %account,
            "retained sign-in could not be opened: its sealed Hub session does not open \
             under this computer's account key"
        ),
        Outcome::NotRetained => tracing::warn!(
            %account,
            "the selected account has no retained sign-in on this computer"
        ),
        Outcome::NoHomeSession => tracing::warn!(
            %account,
            "retained sign-in opened, but this Home could not mint the window a session for it"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_outcome_is_logged_when_it_changes_and_not_on_every_poll() {
        let person = "retained-signin-log-test-account";
        assert!(note(person, Outcome::Opened));
        assert!(!note(person, Outcome::Opened), "a repeated poll is quiet");
        assert!(note(person, Outcome::Unsealable), "a change is logged");
        assert!(note(person, Outcome::Opened), "and so is recovering");
    }

    #[test]
    fn a_long_account_id_is_tagged_short() {
        let long = "04d9d697".repeat(16);
        let tag = account_tag(&long);
        assert!(tag.starts_with("04d9d69704d9"), "{tag}");
        assert!(tag.ends_with("(128 chars)"), "{tag}");
        assert_eq!(account_tag("108747823322"), "108747823322");
    }
}
