//! A root hand-over waits, with notice, before the Hub takes it
//! ([DR-0464](../../../specs/decisions/0464-a-root-hand-over-waits-with-notice-before-the-hub-takes-it.md)).
//!
//! Every computer signed in to an account holds its root, a stolen one
//! included, so a hand-over the outgoing root signs could be the owner's or a
//! thief's. Away from a root an enrolled device proved, the Hub records it as
//! pending and keeps projecting the outgoing root. It tells the account at
//! once and again a day before the wait ends, and the wait runs from when the
//! first notice was delivered, so a notice that is late never shortens the
//! owner's window. A hand-over no channel has been told of never takes
//! effect. Revoking the computer that submitted it withdraws it.
//!
//! Whoever finds a hand-over due under the Workbench lock takes it: the
//! directory routes and the sweeper here, which also sends the notices. The
//! clock is always the caller's, so a test moves it instead of sleeping.
//!
//! Cancellation, the freeze and the recovery key (DR-0464 §3–§5, §8) are not
//! here yet (WS-984).

use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use gaugedesk_directory_protocol::RootTransition;
use gaugedesk_store::{AdmitError, Store};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::account::{
    Account, AccountDirectoryRecord, DeviceRecord, DeviceStatus, RecordOp, DIRECTORY_RECORD_ID,
    DIRECTORY_RECORD_KIND,
};
use crate::account_auth_ceremony::EmailChallengeSender;
use crate::{LockUnpoisoned, SharedWorkbench, Workbench};

/// Record kind for an account's root hand-over, in its account scope.
pub const ROOT_HAND_OVER_RECORD_KIND: &str = "account_root_hand_over";
/// Latest-wins: an account has at most one hand-over in flight.
pub const ROOT_HAND_OVER_RECORD_ID: &str = "root";
/// How long a hand-over away from a proven root waits, from when the account
/// was first told of it (DR-0464 §1–§2).
pub const HAND_OVER_WAIT_MS: u64 = 72 * 60 * 60 * 1000;
/// How long before it takes effect the account is reminded (DR-0464 §2).
pub const REMINDER_BEFORE_MS: u64 = 24 * 60 * 60 * 1000;
/// How often the sweeper looks for notices owed and hand-overs due.
pub const SWEEP_EVERY: Duration = Duration::from_secs(5 * 60);
/// The account-mail template a notice is sent with.
pub const NOTICE_TEMPLATE: &str = "gaugedesk-root-hand-over";

/// Which of the two notices DR-0464 §2 owes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeKind {
    /// On submission.
    Submitted,
    /// A day before it takes effect.
    Reminder,
}

impl NoticeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NoticeKind::Submitted => "submitted",
            NoticeKind::Reminder => "reminder",
        }
    }
}

/// What a notice says. It names the computer and when the hand-over takes
/// effect; it carries no key and grants nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootHandOverNotice {
    pub kind: NoticeKind,
    /// The submitting computer's label, as the account named it.
    pub computer: String,
    pub effective_at_ms: u64,
}

/// When each notice was recorded delivered to every verified address, and to
/// at least one.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct NoticeState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitted_sent_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reminder_sent_at_ms: Option<u64>,
}

/// One root hand-over the Hub holds before taking it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RootHandOverRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    /// The account it was submitted on, whose verified addresses are told.
    pub account_id: String,
    pub transition: RootTransition,
    /// The directory origin the submission named, taken with its root.
    #[serde(default)]
    pub origin: String,
    pub device_id: String,
    #[serde(default)]
    pub device_label: String,
    /// The subkey the submitting computer proved with. Its device record takes
    /// it when the hand-over takes effect, if it carries none, because only
    /// then is the root that delegates it the projected one (ADR 0133 §2).
    #[serde(default)]
    pub device_subkey: String,
    pub submitted_at_ms: u64,
    /// When it takes effect: [`HAND_OVER_WAIT_MS`] after its submission
    /// notice was delivered, and unknown until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_at_ms: Option<u64>,
    #[serde(default)]
    pub notice: NoticeState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub withdrawn_reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_at_ms: Option<u64>,
}

impl RootHandOverRecord {
    /// A hand-over submitted at `now_ms` by `device`, over `transition`.
    pub fn submitted(
        account_id: &str,
        transition: RootTransition,
        origin: String,
        device: &DeviceRecord,
        device_subkey: &str,
        now_ms: u64,
    ) -> Self {
        Self {
            id: ROOT_HAND_OVER_RECORD_ID.to_owned(),
            op: RecordOp::Upsert,
            account_id: account_id.to_owned(),
            transition,
            origin,
            device_id: device.id.clone(),
            device_label: device.label.clone(),
            device_subkey: device_subkey.to_owned(),
            submitted_at_ms: now_ms,
            effective_at_ms: None,
            notice: NoticeState::default(),
            withdrawn_at_ms: None,
            withdrawn_reason: String::new(),
            settled_at_ms: None,
        }
    }

    /// Neither withdrawn nor taken.
    pub fn is_pending(&self) -> bool {
        self.withdrawn_at_ms.is_none() && self.settled_at_ms.is_none()
    }

    /// Whether it takes effect at `now_ms`: its submission notice was
    /// delivered and the wait since has passed, because the notice precedes
    /// the effect (DR-0464 §2).
    pub fn is_due(&self, now_ms: u64) -> bool {
        self.is_pending()
            && self.notice.submitted_sent_at_ms.is_some()
            && self
                .effective_at_ms
                .is_some_and(|effective| now_ms >= effective)
    }

    /// The notice owed at `now_ms`, if any: the submission notice until it is
    /// sent, then one reminder in the last day of the wait.
    pub fn notice_owed(&self, now_ms: u64) -> Option<NoticeKind> {
        if !self.is_pending() {
            return None;
        }
        if self.notice.submitted_sent_at_ms.is_none() {
            return Some(NoticeKind::Submitted);
        }
        let reminding = self.effective_at_ms.is_some_and(|effective| {
            now_ms >= effective.saturating_sub(REMINDER_BEFORE_MS) && now_ms < effective
        });
        (reminding && self.notice.reminder_sent_at_ms.is_none()).then_some(NoticeKind::Reminder)
    }

    /// What the account's own sessions are shown of it: which computer, which
    /// root, when, and what the account has been told.
    pub fn view(&self) -> serde_json::Value {
        json!({
            "root_pubkey": self.transition.to,
            "device_id": self.device_id,
            "computer": self.device_label,
            "submitted_at_ms": self.submitted_at_ms,
            "effective_at_ms": self.effective_at_ms,
            "notice": {
                "submitted_sent_at_ms": self.notice.submitted_sent_at_ms,
                "reminder_sent_at_ms": self.notice.reminder_sent_at_ms,
            },
        })
    }

    fn withdrawn(&self, reason: &str, now_ms: u64) -> Self {
        Self {
            withdrawn_at_ms: Some(now_ms),
            withdrawn_reason: reason.to_owned(),
            ..self.clone()
        }
    }
}

/// The pending hand-over `device_id` submitted, withdrawn for `reason`, for
/// writing beside that computer's revocation (DR-0464 §7).
pub(crate) fn withdrawn_by(
    account: &Account,
    device_id: &str,
    reason: &str,
    now_ms: u64,
) -> Option<RootHandOverRecord> {
    account
        .root_hand_over
        .as_ref()
        .filter(|hand_over| hand_over.is_pending() && hand_over.device_id == device_id)
        .map(|hand_over| hand_over.withdrawn(reason, now_ms))
}

fn encoded<T: Serialize>(record: &T) -> String {
    serde_json::to_string(record).expect("an account record serializes")
}

/// Take `scope`'s hand-over if it is due at `now_ms`, under the Workbench
/// lock: the directory moves to its root, keeps its statement and counts as
/// proven, because an enrolled computer's proof came with it. `Ok(true)` when
/// it moved.
///
/// One whose computer is no longer active is withdrawn instead, so a
/// revocation that did not reach it still stops it, as is one whose outgoing
/// root is no longer the projected one.
pub(crate) fn settle_due_in(
    wb: &mut Workbench,
    scope: &str,
    now_ms: u64,
) -> Result<bool, AdmitError> {
    let account = Account::rebuild_in(wb.store_ref(), scope)?;
    let Some(hand_over) = account
        .root_hand_over
        .as_ref()
        .filter(|hand_over| hand_over.is_due(now_ms))
    else {
        return Ok(false);
    };
    let device = account
        .devices
        .get(&hand_over.device_id)
        .filter(|device| device.status == DeviceStatus::Active);
    let previous = account
        .directory
        .as_ref()
        .filter(|directory| directory.root_pubkey == hand_over.transition.from);
    let (Some(device), Some(previous)) = (device, previous) else {
        let reason = if device.is_none() {
            "revoked"
        } else {
            "superseded"
        };
        let withdrawn = hand_over.withdrawn(reason, now_ms);
        wb.write_account_record_in(scope, ROOT_HAND_OVER_RECORD_KIND, &withdrawn.id, &withdrawn)?;
        return Ok(false);
    };
    let mut transitions = previous.transitions.clone();
    transitions.push(hand_over.transition.clone());
    let directory = AccountDirectoryRecord {
        id: DIRECTORY_RECORD_ID.to_owned(),
        op: RecordOp::Upsert,
        root_pubkey: hand_over.transition.to.clone(),
        origin: if hand_over.origin.is_empty() {
            previous.origin.clone()
        } else {
            hand_over.origin.clone()
        },
        transitions,
        proven: true,
    };
    let settled = RootHandOverRecord {
        settled_at_ms: Some(now_ms),
        ..hand_over.clone()
    };
    let mut writes = vec![
        (DIRECTORY_RECORD_KIND, encoded(&directory)),
        (ROOT_HAND_OVER_RECORD_KIND, encoded(&settled)),
    ];
    if device.subkey_pubkey.is_empty() && !hand_over.device_subkey.is_empty() {
        writes.push((
            "device",
            encoded(&DeviceRecord {
                subkey_pubkey: hand_over.device_subkey.clone(),
                ..device.clone()
            }),
        ));
    }
    let borrowed: Vec<(&str, &str, &str)> = writes
        .iter()
        .map(|(kind, payload)| (scope, *kind, payload.as_str()))
        .collect();
    wb.store_mut().append_records_atomically(&borrowed)?;
    wb.notify_library_changed("account", DIRECTORY_RECORD_ID, "upsert");
    Ok(true)
}

/// Make sure `wb`'s sweeper runs. It needs a Tokio runtime and does nothing
/// off one; it stops when the Workbench is dropped.
///
/// The Hub composes its own server and calls into this repository only
/// through functions it names (AGENTS.md §9), so the directory routes start
/// it on first use rather than waiting for a call at startup. It runs every
/// [`SWEEP_EVERY`], and at once when [`submitted`] wakes it.
pub fn watch(wb: &SharedWorkbench) {
    let (running, wake) = {
        let guard = wb.lock_unpoisoned();
        (
            Arc::clone(&guard.root_hand_over_sweeping),
            Arc::clone(&guard.root_hand_over_submitted),
        )
    };
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    if running.swap(true, Ordering::AcqRel) {
        return;
    }
    let weak = Arc::downgrade(wb);
    runtime.spawn(async move {
        let mail = crate::account_auth_ceremony::email_sender_from_env();
        let mut ticks = tokio::time::interval(SWEEP_EVERY);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticks.tick() => {}
                () = wake.notified() => {}
            }
            let Some(wb) = weak.upgrade() else { break };
            let mail = mail.clone();
            let swept = tokio::task::spawn_blocking(move || {
                sweep(&wb, mail.as_deref(), crate::account::session_now_ms());
            })
            .await;
            if swept.is_err() {
                tracing::warn!("the root hand-over sweep failed; it runs again next time");
            }
        }
        running.store(false, Ordering::Release);
    });
}

/// Wake `wb`'s sweeper for a hand-over just submitted, so its notice goes
/// now rather than at the next tick.
pub fn submitted(wb: &SharedWorkbench) {
    watch(wb);
    wb.lock_unpoisoned().root_hand_over_submitted.notify_one();
}

/// One pass over every account that has had a hand-over: send what notice is
/// owed and take what has come due, at `now_ms`. Mail goes with the
/// Workbench lock released. A send that fails is retried by the next pass,
/// and `None` — no relay configured — fails every send.
pub fn sweep(wb: &SharedWorkbench, mail: Option<&dyn EmailChallengeSender>, now_ms: u64) {
    let scopes = match scopes_with_hand_overs(wb) {
        Ok(scopes) => scopes,
        Err(error) => {
            tracing::warn!("root hand-overs could not be listed: {error:?}");
            return;
        }
    };
    for scope in scopes {
        if let Err(error) = sweep_scope(wb, &scope, mail, now_ms) {
            tracing::warn!("a root hand-over could not be swept: {error:?}");
        }
    }
}

fn scopes_with_hand_overs(wb: &SharedWorkbench) -> Result<Vec<String>, AdmitError> {
    let page = NonZeroUsize::new(256).expect("nonzero");
    let mut scopes = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let found = wb.lock_unpoisoned().store_ref().scope_ids_with_kind(
            ROOT_HAND_OVER_RECORD_KIND,
            after.as_deref(),
            page,
        )?;
        let Some(last) = found.last().cloned() else {
            return Ok(scopes);
        };
        scopes.extend(found);
        after = Some(last);
    }
}

/// The account's active verified addresses.
fn verified_addresses(store: &Store, account_id: &str) -> Result<BTreeSet<String>, AdmitError> {
    Ok(
        crate::account_auth::AccountAuth::rebuild_for_account(store, account_id)?
            .emails
            .into_values()
            .filter(|email| {
                email.account_id == account_id
                    && email.status == crate::account_auth::AuthMethodStatus::Active
            })
            .map(|email| email.email)
            .collect(),
    )
}

fn sweep_scope(
    wb: &SharedWorkbench,
    scope: &str,
    mail: Option<&dyn EmailChallengeSender>,
    now_ms: u64,
) -> Result<(), AdmitError> {
    let (hand_over, kind, addresses) = {
        let mut guard = wb.lock_unpoisoned();
        settle_due_in(&mut guard, scope, now_ms)?;
        let account = Account::rebuild_in(guard.store_ref(), scope)?;
        let Some(hand_over) = account.root_hand_over else {
            return Ok(());
        };
        let Some(kind) = hand_over.notice_owed(now_ms) else {
            return Ok(());
        };
        let addresses = verified_addresses(guard.store_ref(), &hand_over.account_id)?;
        (hand_over, kind, addresses)
    };
    // The submission notice starts the wait, so it names the moment the wait
    // ends if it is delivered now.
    let effective_at_ms = match kind {
        NoticeKind::Submitted => now_ms.saturating_add(HAND_OVER_WAIT_MS),
        NoticeKind::Reminder => hand_over.effective_at_ms.unwrap_or_default(),
    };
    let notice = RootHandOverNotice {
        kind,
        computer: if hand_over.device_label.is_empty() {
            hand_over.device_id.clone()
        } else {
            hand_over.device_label.clone()
        },
        effective_at_ms,
    };
    // A hand-over nobody has been told of does not take effect. Email is the
    // only channel the Hub has; an account with no verified address keeps its
    // hand-over pending until it has one, or until the desktop's notice to
    // the account's other computers exists (DR-0464 §2, WS-984).
    if addresses.is_empty() {
        tracing::warn!(
            "a root hand-over {} notice has no verified address to go to",
            kind.as_str()
        );
        return Ok(());
    }
    for address in &addresses {
        let sent = match mail {
            Some(mail) => mail.send_root_hand_over_notice(address, &notice),
            None => Err("no account-mail relay is configured".to_owned()),
        };
        if let Err(error) = sent {
            tracing::warn!(
                "a root hand-over {} notice was not sent: {error}",
                kind.as_str()
            );
            return Ok(());
        }
    }
    let mut guard = wb.lock_unpoisoned();
    let account = Account::rebuild_in(guard.store_ref(), scope)?;
    let Some(mut current) = account
        .root_hand_over
        .filter(|current| current.is_pending() && current.transition == hand_over.transition)
    else {
        return Ok(());
    };
    let recorded = match kind {
        NoticeKind::Submitted if current.notice.submitted_sent_at_ms.is_none() => {
            current.notice.submitted_sent_at_ms = Some(now_ms);
            current.effective_at_ms = Some(effective_at_ms);
            true
        }
        NoticeKind::Reminder if current.notice.reminder_sent_at_ms.is_none() => {
            current.notice.reminder_sent_at_ms = Some(now_ms);
            true
        }
        _ => false,
    };
    if recorded {
        guard.write_account_record_in(scope, ROOT_HAND_OVER_RECORD_KIND, &current.id, &current)?;
    }
    settle_due_in(&mut guard, scope, now_ms)?;
    Ok(())
}

#[cfg(test)]
#[path = "root_hand_over_tests.rs"]
mod tests;
