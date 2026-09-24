//! WHIP-4: a person claims, renews, releases and reassigns a task through the
//! same governed admission as completing one.
use super::*;
use crate::project_tracker::{ControlTrackerIssue, TrackerIssueControl};
use crate::project_workflow::launch::tracker_control::{
    MAX_LEASE_SECONDS, TRACKER_CONTROL_REFUSED,
};

fn control(
    close: &crate::project_tracker::CompleteTrackerIssue,
    request_id: &str,
    control: TrackerIssueControl,
) -> ControlTrackerIssue {
    ControlTrackerIssue {
        project: close.project.clone(),
        queue: close.queue.clone(),
        item_id: close.item_id.clone(),
        subject_id: close.subject_id.clone(),
        request_id: request_id.into(),
        control,
    }
}

fn issue(
    wb: &Workbench,
    context: &AuthenticatedActionContext,
    close: &crate::project_tracker::CompleteTrackerIssue,
) -> crate::project_tracker::ProjectTrackerIssue {
    wb.read_project_tracker_backlog(context, &close.project, &close.queue)
        .unwrap()
        .issues
        .into_iter()
        .find(|issue| issue.id == close.item_id)
        .unwrap()
}

#[test]
fn a_claim_is_leased_renewed_and_released_by_request_key() {
    let (_root, shared, context, _invocation, close) = super::completion::setup();
    let mut wb = shared.lock_unpoisoned();

    let claim = control(
        &close,
        "claim-1",
        TrackerIssueControl::Claim {
            lease_seconds: 3600,
        },
    );
    let claimed = wb
        .control_project_tracker_issue(&context, &claim, LIMITS)
        .unwrap();
    assert!(claimed.executed_effect.is_some());
    let held = issue(&wb, &context, &close);
    assert_eq!(held.claimed_by.as_deref(), Some(LOCAL_AUTHORITY));
    let first_expiry = held
        .claim_expires_at
        .clone()
        .expect("a claim carries its lease");

    // The same request key replays the same act; nothing is claimed twice.
    let again = wb
        .control_project_tracker_issue(&context, &claim, LIMITS)
        .unwrap();
    assert!(again.executed_effect.is_none());
    assert_eq!(
        issue(&wb, &context, &close).claim_expires_at.as_deref(),
        Some(first_expiry.as_str())
    );

    let renew = control(
        &close,
        "renew-1",
        TrackerIssueControl::Renew {
            lease_seconds: 7200,
        },
    );
    wb.control_project_tracker_issue(&context, &renew, LIMITS)
        .unwrap();
    let renewed = issue(&wb, &context, &close).claim_expires_at.unwrap();
    assert!(renewed > first_expiry, "{renewed} after {first_expiry}");

    // Releasing names the holder expected now; a stale expectation is refused.
    let stale = control(
        &close,
        "release-stale",
        TrackerIssueControl::Release {
            expected_holder: Some("someone-else".into()),
        },
    );
    let refused = wb
        .control_project_tracker_issue(&context, &stale, LIMITS)
        .unwrap_err();
    assert!(refused.starts_with(TRACKER_CONTROL_REFUSED), "{refused}");
    assert!(
        refused.contains(LOCAL_AUTHORITY),
        "names who holds it: {refused}"
    );
    let release = control(
        &close,
        "release-1",
        TrackerIssueControl::Release {
            expected_holder: Some(LOCAL_AUTHORITY.into()),
        },
    );
    wb.control_project_tracker_issue(&context, &release, LIMITS)
        .unwrap();
    let free = issue(&wb, &context, &close);
    assert_eq!(free.claimed_by, None);
    assert_eq!(free.claim_expires_at, None);

    // A lease longer than a week is refused before anything is admitted.
    let greedy = control(
        &close,
        "claim-forever",
        TrackerIssueControl::Claim {
            lease_seconds: MAX_LEASE_SECONDS + 1,
        },
    );
    assert!(wb
        .control_project_tracker_issue(&context, &greedy, LIMITS)
        .is_err());
}

#[test]
fn reassignment_compares_first_and_never_grants_access() {
    let (_root, shared, context, _invocation, close) = super::completion::setup();
    let mut wb = shared.lock_unpoisoned();
    assert_eq!(
        issue(&wb, &context, &close).assigned_to.as_deref(),
        Some(LOCAL_AUTHORITY)
    );

    // Someone who cannot read this tracker cannot be given its task.
    let outsider = control(
        &close,
        "assign-outsider",
        TrackerIssueControl::Assign {
            expected_assignee: Some(LOCAL_AUTHORITY.into()),
            assigned_to: Some("stranger".into()),
        },
    );
    assert!(wb
        .control_project_tracker_issue(&context, &outsider, LIMITS)
        .unwrap_err()
        .contains("cannot read"));

    // Reassigning expects the current assignee, so a stale view cannot win.
    let stale = control(
        &close,
        "assign-stale",
        TrackerIssueControl::Assign {
            expected_assignee: None,
            assigned_to: None,
        },
    );
    let changed = wb
        .control_project_tracker_issue(&context, &stale, LIMITS)
        .unwrap_err();
    assert!(changed.starts_with(TRACKER_CONTROL_REFUSED), "{changed}");
    let unassign = control(
        &close,
        "unassign",
        TrackerIssueControl::Assign {
            expected_assignee: Some(LOCAL_AUTHORITY.into()),
            assigned_to: None,
        },
    );
    wb.control_project_tracker_issue(&context, &unassign, LIMITS)
        .unwrap();
    assert_eq!(issue(&wb, &context, &close).assigned_to, None);
    let assign = control(
        &close,
        "assign-back",
        TrackerIssueControl::Assign {
            expected_assignee: None,
            assigned_to: Some(LOCAL_AUTHORITY.into()),
        },
    );
    wb.control_project_tracker_issue(&context, &assign, LIMITS)
        .unwrap();
    assert_eq!(
        issue(&wb, &context, &close).assigned_to.as_deref(),
        Some(LOCAL_AUTHORITY)
    );
}

/// Durable closure attribution: who closed a task and what they reported stay
/// on it after the claim that preceded the close is released.
#[test]
fn a_closed_task_says_who_closed_it_after_its_claim_is_gone() {
    let (_root, shared, context, _invocation, mut close) = super::completion::setup();
    let mut wb = shared.lock_unpoisoned();
    let claim = control(
        &close,
        "claim-then-close",
        TrackerIssueControl::Claim { lease_seconds: 600 },
    );
    wb.control_project_tracker_issue(&context, &claim, LIMITS)
        .unwrap();
    close.claim = crate::project_tracker::TrackerCompletionClaim::Holder {
        holder: LOCAL_AUTHORITY.into(),
    };
    wb.complete_project_tracker_issue(&context, &close, LIMITS)
        .unwrap();
    let closed = issue(&wb, &context, &close);
    assert_eq!(closed.status, "closed");
    assert_eq!(closed.claimed_by, None, "closing releases the claim");
    assert_eq!(closed.closed_by.as_deref(), Some(LOCAL_AUTHORITY));
    assert_eq!(
        closed.closing_summary.as_deref(),
        Some(close.summary.as_str())
    );
}
