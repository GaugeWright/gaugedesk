use super::*;
use crate::project_tracker::{CompleteTrackerIssue, TrackerAccessDecision, TrackerPermission};

#[test]
fn agent_task_tool_files_a_real_personal_issue_once_under_current_authority() {
    let (_root, shared, context, _request) = fixture(ECHO);
    let mut wb = shared.lock_unpoisoned();
    wb.create_default_engagement("chat-one".into(), "Task chat".into())
        .unwrap_or_else(|_| panic!("task chat in Personal"));
    wb.ensure_project_tasks_tracker(DEFAULT_PROJECT).unwrap();
    let mut changes = wb.sender(crate::library::LIBRARY_SCOPE).subscribe();
    let id = wb
        .file_agent_project_task(
            &context,
            DEFAULT_PROJECT,
            "chat-one",
            "chat:one:call:one",
            "Test task\nVerify the app works",
            None,
        )
        .expect("first task initializes protected tracker and commits");
    assert!(matches!(
        changes.try_recv(),
        Ok(crate::stream::ServerEvent::WorkspaceChanged { record, id, .. })
            if record == "project_tracker" && id == DEFAULT_PROJECT
    ));
    assert_eq!(
        wb.file_agent_project_task(
            &context,
            DEFAULT_PROJECT,
            "chat-one",
            "chat:one:call:one",
            "Test task\nVerify the app works",
            None,
        )
        .unwrap(),
        id
    );
    assert!(
        wb.file_agent_project_task(
            &context,
            DEFAULT_PROJECT,
            "chat-one",
            "chat:one:call:one",
            "A different task",
            None,
        )
        .is_err(),
        "one tool call cannot acquire a different meaning"
    );
    let tasks = wb
        .read_project_tracker_tasks(&context, DEFAULT_PROJECT, "tasks")
        .unwrap();
    assert_eq!(tasks.backlog.issues.len(), 1);
    assert_eq!(tasks.backlog.issues[0].id, id);
    assert_eq!(tasks.backlog.issues[0].title, "Test task");
    assert_eq!(tasks.backlog.issues[0].body, "Verify the app works");
    assert_eq!(
        tasks.backlog.issues[0].filed_by.as_deref(),
        Some(LOCAL_AUTHORITY)
    );
    let outsider_token = wb
        .mint_account_session("outsider", "passkey", 3600)
        .unwrap();
    let outsider = wb.authenticate_action_context(&outsider_token).unwrap();
    assert!(wb
        .file_agent_project_task(
            &outsider,
            DEFAULT_PROJECT,
            "chat-one",
            "chat:two:call:one",
            "Forbidden task",
            None,
        )
        .is_err());
    assert_eq!(
        wb.read_project_tracker_backlog(&context, DEFAULT_PROJECT, "tasks")
            .unwrap()
            .issues
            .len(),
        1
    );
}

#[test]
fn personal_tasks_follow_actual_assignment_status_and_current_read_authority() {
    let (_root, shared, context, invocation, request) = completion::setup();
    let mut wb = shared.lock_unpoisoned();
    wb.store_mut().append_record(crate::org::ORG_SCOPE, "membership", &serde_json::json!({"id":"reader", "op":"upsert", "org_id":crate::org::ORG_ID, "authority":"reader", "email":"", "role":"admin", "status":"active", "managed_by_scim":false}).to_string()).unwrap();
    let token = wb.mint_account_session("reader", "passkey", 3600).unwrap();
    let reader = wb.authenticate_action_context(&token).unwrap();
    let mut native = stores(&wb, &invocation);
    // Native/imported work deliberately mixes assignments and statuses. These
    // fixture writes are not an alternate product assignment path.
    for (queue, title, assigned_to, status) in [
        ("tutorials", "shared", None, "open"),
        ("tutorials", "reader task", Some("reader"), "open"),
        ("tutorials", "agent task", Some("agent:helper"), "open"),
        ("tutorials", "started", Some(LOCAL_AUTHORITY), "in_progress"),
        ("tutorials", "closed", Some(LOCAL_AUTHORITY), "closed"),
        ("tutorials", "canceled", Some(LOCAL_AUTHORITY), "canceled"),
        ("tutorials", "archived", Some(LOCAL_AUTHORITY), "archived"),
        ("private", "other queue", Some(LOCAL_AUTHORITY), "open"),
    ] {
        let item = native
            .runtime
            .items
            .file_item(
                queue,
                title,
                "Instructions",
                &[],
                &serde_json::json!({}),
                None,
                assigned_to,
            )
            .unwrap();
        native
            .runtime
            .items
            .set_field(&item.id, "status", status)
            .unwrap();
    }
    native
        .runtime
        .items
        .claim_item(&request.item_id, "reader", None)
        .unwrap();
    let before = native.runtime.items.export_events().unwrap();
    let own = wb
        .read_project_tracker_tasks(&context, DEFAULT_PROJECT, "tutorials")
        .unwrap();
    assert_eq!(own.actor, LOCAL_AUTHORITY);
    assert_eq!(own.backlog.issues.len(), 2);
    let claimed = own
        .backlog
        .issues
        .iter()
        .find(|issue| issue.id == request.item_id)
        .unwrap();
    assert_eq!(claimed.subject_id, request.subject_id);
    assert_eq!(claimed.assigned_to.as_deref(), Some(LOCAL_AUTHORITY));
    assert_eq!(claimed.claimed_by.as_deref(), Some("reader"));
    assert!(own
        .backlog
        .issues
        .iter()
        .any(|issue| issue.title == "started"));
    // Having an assignment (and even being an admin) cannot grant a read.
    assert!(wb
        .read_project_tracker_tasks(&reader, DEFAULT_PROJECT, "tutorials")
        .is_err());
    let grant = wb
        .request_project_tracker_access(
            &context,
            DEFAULT_PROJECT,
            "tutorials",
            "reader-tasks-access",
            "reader",
            TrackerPermission::Read,
        )
        .unwrap();
    wb.decide_project_tracker_access(
        &context,
        DEFAULT_PROJECT,
        "tutorials",
        "approve-reader-tasks",
        &grant.id,
        TrackerAccessDecision::Approve,
    )
    .unwrap();
    let theirs = wb
        .read_project_tracker_tasks(&reader, DEFAULT_PROJECT, "tutorials")
        .unwrap();
    assert_eq!(theirs.actor, "reader");
    assert_eq!(theirs.backlog.issues.len(), 1);
    assert_eq!(theirs.backlog.issues[0].title, "reader task");
    assert!(!theirs.backlog.tracker.can_complete);
    assert_eq!(native.runtime.items.export_events().unwrap(), before);
    // Reassignment changes the next projection without rewriting actor or claim.
    native
        .runtime
        .items
        .assign_item(&request.item_id, Some("reader"))
        .unwrap();
    assert_eq!(
        wb.read_project_tracker_tasks(&context, DEFAULT_PROJECT, "tutorials")
            .unwrap()
            .backlog
            .issues
            .len(),
        1
    );
    assert_eq!(
        wb.read_project_tracker_tasks(&reader, DEFAULT_PROJECT, "tutorials")
            .unwrap()
            .backlog
            .issues
            .len(),
        2
    );
    wb.decide_project_tracker_access(
        &context,
        DEFAULT_PROJECT,
        "tutorials",
        "revoke-reader-tasks",
        &grant.id,
        TrackerAccessDecision::Revoke,
    )
    .unwrap();
    assert!(wb
        .read_project_tracker_tasks(&reader, DEFAULT_PROJECT, "tutorials")
        .is_err());
    // The ordinary backlog still carries every issue in this readable queue.
    assert_eq!(
        wb.read_project_tracker_backlog(&context, DEFAULT_PROJECT, "tutorials")
            .unwrap()
            .issues
            .len(),
        8
    );
}

#[test]
fn backlog_keeps_unassigned_other_people_and_completed_work_with_native_identity() {
    let (_root, shared, context, invocation, request) = completion::setup();
    let mut wb = shared.lock_unpoisoned();
    let mut native = stores(&wb, &invocation);
    // Existing/imported native work is not limited to this tutorial's assignments.
    for (title, assigned_to) in [
        ("shared", None),
        ("colleague work", Some("colleague")),
        ("agent work", Some("agent:helper")),
    ] {
        native
            .runtime
            .items
            .file_item(
                "tutorials",
                title,
                "Task details",
                &[],
                &serde_json::json!({}),
                None,
                assigned_to,
            )
            .unwrap();
    }
    let foreign = native
        .runtime
        .items
        .file_item(
            "private",
            "Private task",
            "Another queue",
            &[],
            &serde_json::json!({}),
            None,
            None,
        )
        .unwrap();
    let before = native.runtime.items.export_events().unwrap();
    let discovered = wb.list_project_trackers(&context, DEFAULT_PROJECT).unwrap();
    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].queue, "tutorials");
    assert!(discovered[0].can_complete);
    let backlog = wb
        .read_project_tracker_backlog(&context, DEFAULT_PROJECT, "tutorials")
        .unwrap();
    assert_eq!(backlog.issues.len(), 4);
    assert!(backlog.issues.iter().any(|item| item.assigned_to.is_none()));
    assert!(backlog
        .issues
        .iter()
        .any(|item| item.assigned_to.as_deref() == Some("colleague")));
    assert!(backlog
        .issues
        .iter()
        .any(|item| item.assigned_to.as_deref() == Some("agent:helper")));
    assert!(!backlog.issues.iter().any(|item| item.id == foreign.id));
    for item in &backlog.issues {
        assert_eq!(
            native
                .runtime
                .items
                .subject_content_id(&item.id)
                .unwrap()
                .as_deref(),
            Some(item.subject_id.as_str())
        );
    }
    assert_eq!(native.runtime.items.export_events().unwrap(), before);
    let observed = backlog
        .issues
        .iter()
        .find(|item| item.id == request.item_id)
        .unwrap();
    let wrong_subject = CompleteTrackerIssue {
        subject_id: native
            .runtime
            .items
            .subject_content_id(&foreign.id)
            .unwrap()
            .unwrap(),
        ..request.clone()
    };
    assert!(wb
        .complete_project_tracker_issue(&context, &wrong_subject, LIMITS)
        .is_err());
    assert_eq!(native.runtime.items.export_events().unwrap(), before);
    assert_eq!(native.runtime.list_instances().unwrap().len(), 1);
    let close = CompleteTrackerIssue {
        subject_id: observed.subject_id.clone(),
        ..request
    };
    wb.complete_project_tracker_issue(&context, &close, LIMITS)
        .unwrap();
    let backlog = wb
        .read_project_tracker_backlog(&context, DEFAULT_PROJECT, "tutorials")
        .unwrap();
    assert_eq!(backlog.issues.len(), 4);
    assert_eq!(
        backlog
            .issues
            .iter()
            .find(|item| item.id == close.item_id)
            .unwrap()
            .status,
        "closed"
    );
}

#[test]
fn discovery_and_backlog_require_current_read_grant_not_administrator_membership() {
    let (_root, shared, context, _invocation, request) = completion::setup();
    let mut wb = shared.lock_unpoisoned();
    wb.store_mut().append_record(crate::org::ORG_SCOPE, "membership", &serde_json::json!({"id":"reader", "op":"upsert", "org_id":crate::org::ORG_ID, "authority":"reader", "email":"", "role":"admin", "status":"active", "managed_by_scim":false}).to_string()).unwrap();
    let token = wb.mint_account_session("reader", "passkey", 3600).unwrap();
    let reader = wb.authenticate_action_context(&token).unwrap();
    assert!(wb
        .list_project_trackers(&reader, DEFAULT_PROJECT)
        .unwrap()
        .is_empty());
    assert!(wb
        .read_project_tracker_backlog(&reader, DEFAULT_PROJECT, "tutorials")
        .is_err());
    let grant = wb
        .request_project_tracker_access(
            &context,
            DEFAULT_PROJECT,
            "tutorials",
            "reader-access",
            "reader",
            TrackerPermission::Read,
        )
        .unwrap();
    wb.decide_project_tracker_access(
        &context,
        DEFAULT_PROJECT,
        "tutorials",
        "approve-reader",
        &grant.id,
        TrackerAccessDecision::Approve,
    )
    .unwrap();
    let directory = wb.list_project_trackers(&reader, DEFAULT_PROJECT).unwrap();
    assert_eq!(directory.len(), 1);
    assert!(!directory[0].can_complete);
    let backlog = wb
        .read_project_tracker_backlog(&reader, DEFAULT_PROJECT, "tutorials")
        .unwrap();
    assert_eq!(backlog.issues.len(), 1);
    assert!(!backlog.tracker.can_complete);
    assert!(wb
        .complete_project_tracker_issue(&reader, &request, LIMITS)
        .is_err());
    wb.decide_project_tracker_access(
        &context,
        DEFAULT_PROJECT,
        "tutorials",
        "revoke-reader",
        &grant.id,
        TrackerAccessDecision::Revoke,
    )
    .unwrap();
    assert!(wb
        .list_project_trackers(&reader, DEFAULT_PROJECT)
        .unwrap()
        .is_empty());
    assert!(wb
        .read_project_tracker_backlog(&reader, DEFAULT_PROJECT, "tutorials")
        .is_err());
}

#[test]
fn unavailable_backlog_never_becomes_empty_or_recreates_native_authority() {
    for fault in ["missing", "corrupt", "erased"] {
        let (root, shared, context, invocation, _request) = completion::setup();
        let wb = shared.lock_unpoisoned();
        let items = root
            .path()
            .join("collaboration-workspaces")
            .join(&invocation.workspace)
            .join(".repo.whipplescript/workflow/items.sqlite");
        let before = wb.store_ref().scope_high_water_marks().unwrap();
        match fault {
            "missing" => std::fs::remove_file(&items).unwrap(),
            "corrupt" => std::fs::write(&items, b"corrupt native storage").unwrap(),
            "erased" => {
                wb.content_vault
                    .as_ref()
                    .unwrap()
                    .erase_scope_key(&content_scope(DEFAULT_PROJECT).unwrap())
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            wb.read_project_tracker_backlog(&context, DEFAULT_PROJECT, "tutorials")
                .is_err(),
            "{fault}"
        );
        assert!(
            wb.read_project_tracker_tasks(&context, DEFAULT_PROJECT, "tutorials")
                .is_err(),
            "{fault}"
        );
        assert_eq!(wb.store_ref().scope_high_water_marks().unwrap(), before);
        if fault == "missing" {
            assert!(!items.exists());
        }
        if fault == "corrupt" {
            assert_eq!(std::fs::read(&items).unwrap(), b"corrupt native storage");
        }
    }
}

#[test]
fn declared_tracker_without_native_storage_is_discoverable_but_not_an_empty_backlog() {
    let (root, shared, context, _request) = fixture(ECHO);
    let mut wb = shared.lock_unpoisoned();
    let tracker = wb
        .declare_project_tracker(
            &context,
            DEFAULT_PROJECT,
            "unopened",
            "declare-unused",
            ResourceAttributes::default(),
        )
        .unwrap();
    let path = root
        .path()
        .join("collaboration-workspaces")
        .join(&tracker.workspace_id)
        .join(".repo.whipplescript/workflow");
    assert!(!path.exists());
    assert_eq!(
        wb.list_project_trackers(&context, DEFAULT_PROJECT)
            .unwrap()
            .len(),
        1
    );
    assert!(wb
        .read_project_tracker_backlog(&context, DEFAULT_PROJECT, "unopened")
        .is_err());
    assert!(!path.exists());
}

#[test]
fn backlog_remains_readable_during_pending_handoff_but_completion_is_unavailable() {
    let (_root, shared, context, _invocation, _request) = completion::setup();
    let mut wb = shared.lock_unpoisoned();
    wb.store_mut()
        .append_record(
            &crate::federation::handoff_scope(DEFAULT_PROJECT),
            "event",
            &serde_json::to_string(&gaugedesk_core::handoff::HandoffEvent::HandoffOffered).unwrap(),
        )
        .unwrap();
    let directory = wb.list_project_trackers(&context, DEFAULT_PROJECT).unwrap();
    assert!(!directory[0].can_complete);
    let backlog = wb
        .read_project_tracker_backlog(&context, DEFAULT_PROJECT, "tutorials")
        .unwrap();
    assert_eq!(backlog.issues.len(), 1);
    assert!(!backlog.tracker.can_complete);
}
