use super::*;
use crate::project_tracker::{
    CompleteTrackerIssue, TrackerAccessDecision, TrackerCompletionClaim, TrackerPermission,
};
use gaugedesk_whip_runtime::host_actions::action_result::ActionInstanceStatus;

pub(super) fn setup() -> (
    tempfile::TempDir,
    crate::SharedWorkbench,
    AuthenticatedActionContext,
    ProjectWorkflowInvocation,
    CompleteTrackerIssue,
) {
    let (root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    wb.declare_project_tracker(
        &context,
        DEFAULT_PROJECT,
        "tutorials",
        "declare",
        ResourceAttributes::default(),
    )
    .unwrap();
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    wb.step_project_workflow(&context, DEFAULT_PROJECT, &request.request_id, LIMITS)
        .unwrap();
    let item = stores(&wb, &invocation)
        .runtime
        .items
        .list_items(Some("tutorials"), None)
        .unwrap()
        .remove(0);
    drop(wb);
    let close = CompleteTrackerIssue {
        project: DEFAULT_PROJECT.into(),
        queue: "tutorials".into(),
        subject_id: stores(&shared.lock_unpoisoned(), &invocation)
            .runtime
            .items
            .subject_content_id(&item.id)
            .unwrap()
            .unwrap(),
        item_id: item.id,
        request_id: "close-first".into(),
        summary: "I created my chat".into(),
        claim: TrackerCompletionClaim::Override,
    };
    (root, shared, context, invocation, close)
}
#[test]
fn completion_replays_across_restart_and_preserves_human_native_lineage() {
    let (root, shared, context, invocation, request) = setup();
    let completed = shared
        .lock_unpoisoned()
        .complete_project_tracker_issue(&context, &request, LIMITS)
        .unwrap();
    assert_eq!(
        completed.snapshot.instance_status,
        ActionInstanceStatus::Completed
    );
    let wb = shared.lock_unpoisoned();
    let native = stores(&wb, &invocation);
    let events = native.runtime.items.export_events().unwrap();
    let closed: Vec<_> = events
        .iter()
        .filter(|event| event.kind == "issue.closed")
        .collect();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].actor.as_deref(), Some(LOCAL_AUTHORITY));
    let payload: serde_json::Value = serde_json::from_str(&closed[0].payload_json).unwrap();
    assert_eq!(payload["summary"], request.summary);
    assert_ne!(
        payload["operation"]["instance_id"],
        invocation.admission.instance_ref
    );
    assert_eq!(
        payload["operation"]["effect_id"],
        completed.executed_effect.clone().unwrap()
    );
    let histories = native.runtime.list_instances().unwrap();
    assert_eq!(histories.len(), 2);
    drop(native);
    drop(wb);
    drop(shared);
    let shared = open(root.path());
    let mut wb = shared.lock_unpoisoned();
    let replay = wb
        .complete_project_tracker_issue(&context, &request, LIMITS)
        .unwrap();
    assert_eq!(replay.snapshot.command, completed.snapshot.command);
    assert!(replay.executed_effect.is_none());
    assert!(replay.recovered_effect.is_none());
    assert_eq!(
        stores(&wb, &invocation)
            .runtime
            .items
            .export_events()
            .unwrap(),
        events
    );
    for changed in [
        CompleteTrackerIssue {
            summary: "different".into(),
            ..request.clone()
        },
        CompleteTrackerIssue {
            claim: TrackerCompletionClaim::Holder {
                holder: "someone".into(),
            },
            ..request.clone()
        },
        CompleteTrackerIssue {
            item_id: "missing".into(),
            ..request.clone()
        },
    ] {
        assert!(wb
            .complete_project_tracker_issue(&context, &changed, LIMITS)
            .is_err());
    }
    assert_eq!(
        stores(&wb, &invocation)
            .runtime
            .items
            .export_events()
            .unwrap(),
        events
    );
}
#[test]
fn completion_keeps_explicit_holder_precondition_after_claim_release() {
    let (_root, shared, context, invocation, mut request) = setup();
    let mut wb = shared.lock_unpoisoned();
    // Existing native claim fixture; the completion command must not replace it
    // with the executor's identity, nor silently override it.
    stores(&wb, &invocation)
        .runtime
        .items
        .claim_item(&request.item_id, "worker-claim", None)
        .unwrap();
    request.claim = TrackerCompletionClaim::Holder {
        holder: "wrong-holder".into(),
    };
    let failed = wb
        .complete_project_tracker_issue(&context, &request, LIMITS)
        .unwrap();
    assert_eq!(
        failed.snapshot.instance_status,
        ActionInstanceStatus::Failed
    );
    assert_eq!(
        stores(&wb, &invocation)
            .runtime
            .items
            .get_item(&request.item_id)
            .unwrap()
            .unwrap()
            .claimed_by
            .as_deref(),
        Some("worker-claim")
    );
    request.request_id = "correct-holder".into();
    request.claim = TrackerCompletionClaim::Holder {
        holder: "worker-claim".into(),
    };
    let closed = wb
        .complete_project_tracker_issue(&context, &request, LIMITS)
        .unwrap();
    assert_eq!(
        closed.snapshot.instance_status,
        ActionInstanceStatus::Completed
    );
    let item = stores(&wb, &invocation)
        .runtime
        .items
        .get_item(&request.item_id)
        .unwrap()
        .unwrap();
    assert_eq!(item.status, "closed");
    assert!(item.claimed_by.is_none());
    let replay = wb
        .complete_project_tracker_issue(&context, &request, LIMITS)
        .unwrap();
    assert_eq!(replay.snapshot.command, closed.snapshot.command);
    assert!(replay.executed_effect.is_none());
}
#[test]
fn completion_refuses_wrong_queue_and_revoked_grant_before_new_native_evidence() {
    let (_root, shared, context, invocation, request) = setup();
    let mut wb = shared.lock_unpoisoned();
    wb.declare_project_tracker(
        &context,
        DEFAULT_PROJECT,
        "other",
        "declare-other",
        ResourceAttributes::default(),
    )
    .unwrap();
    let before = stores(&wb, &invocation)
        .runtime
        .items
        .export_events()
        .unwrap();
    assert!(wb
        .complete_project_tracker_issue(
            &context,
            &CompleteTrackerIssue {
                queue: "other".into(),
                ..request.clone()
            },
            LIMITS
        )
        .is_err());
    assert_eq!(
        stores(&wb, &invocation)
            .runtime
            .list_instances()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        stores(&wb, &invocation)
            .runtime
            .items
            .export_events()
            .unwrap(),
        before
    );
    // A different queue is different intent and uses a fresh request key.
    let request = CompleteTrackerIssue {
        request_id: "correct-queue".into(),
        ..request
    };
    wb.complete_project_tracker_issue(&context, &request, LIMITS)
        .unwrap();
    let scope = format!(
        "project::{DEFAULT_PROJECT}::tracker::{}",
        hex::encode("tutorials")
    );
    let grant = wb
        .store_ref()
        .records(&scope, "project_tracker_access_basis_v1")
        .unwrap()
        .into_iter()
        .map(|row| {
            serde_json::from_str::<crate::project_tracker::TrackerAccessBasis>(&row).unwrap()
        })
        .find(|grant| {
            grant.recipient == LOCAL_AUTHORITY && grant.permission == TrackerPermission::Contribute
        })
        .unwrap();
    wb.decide_project_tracker_access(
        &context,
        DEFAULT_PROJECT,
        "tutorials",
        "revoke-completion",
        &grant.id,
        TrackerAccessDecision::Revoke,
    )
    .unwrap();
    let before = stores(&wb, &invocation)
        .runtime
        .items
        .export_events()
        .unwrap();
    assert!(wb
        .complete_project_tracker_issue(&context, &request, LIMITS)
        .is_err());
    assert_eq!(
        stores(&wb, &invocation)
            .runtime
            .items
            .export_events()
            .unwrap(),
        before
    );
}
#[test]
fn completion_recovers_committed_closure_after_lost_terminal_without_redispatch() {
    let (root, shared, context, invocation, request) = setup();
    let native_root = root
        .path()
        .join("collaboration-workspaces")
        .join(&invocation.workspace)
        .join(".repo.whipplescript/workflow");
    let fault = rusqlite::Connection::open(native_root.join("runtime.sqlite")).unwrap();
    fault.execute_batch("CREATE TRIGGER lose_closure_terminal BEFORE INSERT ON events WHEN NEW.event_type = 'effect.terminal' BEGIN SELECT RAISE(ABORT, 'lost closure result'); END;").unwrap();
    let events = {
        let mut wb = shared.lock_unpoisoned();
        assert!(wb
            .complete_project_tracker_issue(&context, &request, LIMITS)
            .is_err());
        let native = stores(&wb, &invocation);
        assert_eq!(
            native
                .runtime
                .items
                .get_item(&request.item_id)
                .unwrap()
                .unwrap()
                .status,
            "closed"
        );
        native.runtime.items.export_events().unwrap()
    };
    fault
        .execute_batch("DROP TRIGGER lose_closure_terminal")
        .unwrap();
    drop(fault);
    drop(shared);
    let shared = open(root.path());
    let mut wb = shared.lock_unpoisoned();
    let recovered = wb
        .complete_project_tracker_issue(&context, &request, LIMITS)
        .unwrap();
    assert!(recovered.recovered_effect.is_some());
    assert!(recovered.executed_effect.is_none());
    assert_eq!(
        recovered.snapshot.instance_status,
        ActionInstanceStatus::Completed
    );
    let replay = wb
        .complete_project_tracker_issue(&context, &request, LIMITS)
        .unwrap();
    assert!(replay.recovered_effect.is_none());
    assert!(replay.executed_effect.is_none());
    let native = stores(&wb, &invocation);
    assert_eq!(native.runtime.items.export_events().unwrap(), events);
    assert_eq!(native.runtime.list_instances().unwrap().len(), 2);
}

#[test]
fn readable_contributor_can_close_an_away_assignees_task_as_themselves() {
    let (_root, shared, context, invocation, request) = setup();
    let mut wb = shared.lock_unpoisoned();
    wb.store_mut().append_record(crate::org::ORG_SCOPE, "membership", &serde_json::json!({
        "id":"colleague", "op":"upsert", "org_id":crate::org::ORG_ID,
        "authority":"colleague", "email":"", "role":"admin", "status":"active", "managed_by_scim":false
    }).to_string()).unwrap();
    let token = wb
        .mint_account_session("colleague", "passkey", 3600)
        .unwrap();
    let colleague = wb.authenticate_action_context(&token).unwrap();
    for permission in [TrackerPermission::Read, TrackerPermission::Contribute] {
        assert!(wb
            .complete_project_tracker_issue(&colleague, &request, LIMITS)
            .is_err());
        let id = format!("colleague-{permission:?}");
        let basis = wb
            .request_project_tracker_access(
                &context,
                DEFAULT_PROJECT,
                "tutorials",
                &id,
                "colleague",
                permission,
            )
            .unwrap();
        wb.decide_project_tracker_access(
            &context,
            DEFAULT_PROJECT,
            "tutorials",
            &format!("approve-{id}"),
            &basis.id,
            TrackerAccessDecision::Approve,
        )
        .unwrap();
    }
    let closed = wb
        .complete_project_tracker_issue(&colleague, &request, LIMITS)
        .unwrap();
    assert_eq!(
        closed.snapshot.instance_status,
        ActionInstanceStatus::Completed
    );
    assert_eq!(closed.snapshot.command.provenance.executor, "colleague");
    let native = stores(&wb, &invocation);
    let item = native
        .runtime
        .items
        .get_item(&request.item_id)
        .unwrap()
        .unwrap();
    assert_eq!(item.assigned_to.as_deref(), Some(LOCAL_AUTHORITY));
    assert_eq!(item.status, "closed");
    let events = native.runtime.items.export_events().unwrap();
    let event = events
        .iter()
        .find(|event| event.kind == "issue.closed")
        .unwrap();
    assert_eq!(event.actor.as_deref(), Some("colleague"));
}

#[test]
fn completion_without_a_committed_closing_receipt_remains_unresolved() {
    let (root, shared, context, invocation, request) = setup();
    let native_root = root
        .path()
        .join("collaboration-workspaces")
        .join(&invocation.workspace)
        .join(".repo.whipplescript/workflow");
    let runtime_fault = rusqlite::Connection::open(native_root.join("runtime.sqlite")).unwrap();
    runtime_fault.execute_batch("CREATE TRIGGER lose_closure_terminal BEFORE INSERT ON events WHEN NEW.event_type = 'effect.terminal' BEGIN SELECT RAISE(ABORT, 'lost closure result'); END;").unwrap();
    let item_fault = rusqlite::Connection::open(native_root.join("items.sqlite")).unwrap();
    item_fault.execute_batch("CREATE TRIGGER refuse_closure BEFORE UPDATE ON tracker_issues BEGIN SELECT RAISE(ABORT, 'lost closure'); END;").unwrap();
    let mut wb = shared.lock_unpoisoned();
    assert!(wb
        .complete_project_tracker_issue(&context, &request, LIMITS)
        .is_err());
    runtime_fault
        .execute_batch("DROP TRIGGER lose_closure_terminal")
        .unwrap();
    item_fault
        .execute_batch("DROP TRIGGER refuse_closure")
        .unwrap();
    let before = stores(&wb, &invocation)
        .runtime
        .items
        .export_events()
        .unwrap();
    for _ in 0..2 {
        let error = wb
            .complete_project_tracker_issue(&context, &request, LIMITS)
            .unwrap_err();
        assert!(error.contains("no committed closing receipt"), "{error}");
    }
    let native = stores(&wb, &invocation);
    assert_eq!(
        native
            .runtime
            .items
            .get_item(&request.item_id)
            .unwrap()
            .unwrap()
            .status,
        "open"
    );
    assert_eq!(native.runtime.items.export_events().unwrap(), before);
    assert_eq!(native.runtime.list_instances().unwrap().len(), 2);
}

#[test]
fn pending_project_handoff_prevents_human_closure() {
    let (_root, shared, context, invocation, request) = setup();
    let mut wb = shared.lock_unpoisoned();
    wb.store_mut()
        .append_record(
            &crate::federation::handoff_scope(DEFAULT_PROJECT),
            "event",
            &serde_json::to_string(&gaugedesk_core::handoff::HandoffEvent::HandoffOffered).unwrap(),
        )
        .unwrap();
    let before = stores(&wb, &invocation)
        .runtime
        .items
        .export_events()
        .unwrap();
    assert!(wb
        .complete_project_tracker_issue(&context, &request, LIMITS)
        .is_err());
    let native = stores(&wb, &invocation);
    assert_eq!(native.runtime.items.export_events().unwrap(), before);
    assert_eq!(native.runtime.list_instances().unwrap().len(), 1);
}
