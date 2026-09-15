use super::*;
use crate::project_tracker::{TrackerAccessDecision, TrackerPermission};
use gaugedesk_whip_runtime::host_actions::action_result::ActionInstanceStatus;

fn declare(wb: &mut Workbench, context: &AuthenticatedActionContext) {
    wb.declare_project_tracker(
        context,
        DEFAULT_PROJECT,
        "tutorials",
        "declare",
        ResourceAttributes::default(),
    )
    .unwrap();
}
fn step(
    wb: &mut Workbench,
    context: &AuthenticatedActionContext,
    request: &ProjectWorkflowLaunch,
) -> ProjectWorkflowStep {
    wb.step_project_workflow(context, &request.project, &request.request_id, LIMITS)
        .unwrap()
}

#[test]
fn product_execution_files_basics_once_and_parks_without_a_provider_run() {
    let (root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    let filed = step(&mut wb, &context, &request);
    assert!(filed.executed_effect.is_some());
    let items = stores(&wb, &invocation)
        .runtime
        .items
        .list_items(Some("tutorials"), None)
        .unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].title, "Create a chat in Personal");
    assert_eq!(items[0].assigned_to.as_deref(), Some(LOCAL_AUTHORITY));
    assert_eq!(items[0].filed_by.as_deref(), Some(LOCAL_AUTHORITY));
    let waiting = step(&mut wb, &context, &request);
    assert!(waiting.executed_effect.is_none());
    assert_eq!(
        waiting.snapshot.instance_status,
        ActionInstanceStatus::Running
    );
    let history = stores(&wb, &invocation)
        .runtime
        .list_events(&invocation.admission.instance_ref)
        .unwrap();
    let runs = stores(&wb, &invocation)
        .runtime
        .list_runs(&invocation.admission.instance_ref)
        .unwrap();
    assert_eq!(runs.len(), 1, "closure wait did not reserve a provider");
    assert_eq!(runs[0].status, "completed");
    drop(wb);
    drop(shared);
    let shared = open(root.path());
    let mut wb = shared.lock_unpoisoned();
    for _ in 0..2 {
        assert!(step(&mut wb, &context, &request).executed_effect.is_none());
    }
    assert_eq!(
        stores(&wb, &invocation)
            .runtime
            .list_events(&invocation.admission.instance_ref)
            .unwrap(),
        history
    );
    assert_eq!(
        stores(&wb, &invocation)
            .runtime
            .items
            .list_items(Some("tutorials"), None)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn product_steps_follow_native_closings_across_restart_through_all_four_tasks() {
    let (root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let invocation = {
        let mut wb = shared.lock_unpoisoned();
        declare(&mut wb, &context);
        wb.launch_project_workflow(&context, &request, LIMITS)
            .unwrap()
    };
    drop(shared);
    for (index, title) in [
        "Create a chat in Personal",
        "Make your personal assistant",
        "Create a project",
        "Invite a colleague",
    ]
    .into_iter()
    .enumerate()
    {
        let shared = open(root.path());
        let mut wb = shared.lock_unpoisoned();
        for _ in 0..4 {
            let progress = step(&mut wb, &context, &request);
            if progress.executed_effect.is_none() {
                break;
            }
        }
        let native = stores(&wb, &invocation);
        let items = native
            .runtime
            .items
            .list_items(Some("tutorials"), None)
            .unwrap();
        assert_eq!(items.len(), index + 1);
        let pending: Vec<_> = items.iter().filter(|item| item.status == "open").collect();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].title, title);
        let close = crate::project_tracker::CompleteTrackerIssue {
            project: request.project.clone(),
            queue: "tutorials".into(),
            item_id: pending[0].id.clone(),
            subject_id: native
                .runtime
                .items
                .subject_content_id(&pending[0].id)
                .unwrap()
                .unwrap(),
            request_id: format!("close-{index}"),
            summary: "I completed this task".into(),
            claim: crate::project_tracker::TrackerCompletionClaim::Override,
        };
        drop(native);
        let completed = wb
            .complete_project_tracker_issue(&context, &close, LIMITS)
            .unwrap();
        assert_eq!(
            completed.snapshot.instance_status,
            ActionInstanceStatus::Completed
        );
        assert_eq!(
            completed.snapshot.command.provenance.executor,
            LOCAL_AUTHORITY
        );
        assert_eq!(
            completed.snapshot.command.provenance.initiator,
            LOCAL_AUTHORITY
        );
        assert_ne!(completed.snapshot.command.scope, invocation.command.scope);
        let replay = wb
            .complete_project_tracker_issue(&context, &close, LIMITS)
            .unwrap();
        assert_eq!(replay.snapshot.command, completed.snapshot.command);
        assert!(replay.executed_effect.is_none());
    }
    let shared = open(root.path());
    let mut wb = shared.lock_unpoisoned();
    let mut result = step(&mut wb, &context, &request);
    for _ in 0..3 {
        if result.snapshot.instance_status == ActionInstanceStatus::Completed {
            break;
        }
        result = step(&mut wb, &context, &request);
    }
    assert_eq!(
        result.snapshot.instance_status,
        ActionInstanceStatus::Completed
    );
    assert!(result.snapshot.terminal.is_some());
    assert_eq!(
        stores(&wb, &invocation)
            .runtime
            .items
            .list_items(Some("tutorials"), None)
            .unwrap()
            .len(),
        4
    );
    assert_eq!(
        stores(&wb, &invocation)
            .runtime
            .list_instances()
            .unwrap()
            .len(),
        5
    );
    assert!(step(&mut wb, &context, &request).executed_effect.is_none());
}

#[test]
fn assignment_requires_recipient_read_access_even_for_an_administrator() {
    let (_root, shared, context, mut request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let member = crate::org::MembershipRecord {
        id: "colleague".into(),
        op: crate::org::RecordOp::Upsert,
        org_id: crate::org::ORG_ID.into(),
        authority: "colleague".into(),
        email: String::new(),
        role: "admin".into(),
        status: crate::org::MembershipStatus::Active,
        managed_by_scim: false,
        team: None,
    };
    wb.store_mut()
        .append_record(
            crate::org::ORG_SCOPE,
            "membership",
            &serde_json::to_string(&member).unwrap(),
        )
        .unwrap();
    request.inputs.insert(
        "learner".into(),
        serde_json::json!({"authority":"colleague"}),
    );
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    let error = wb
        .step_project_workflow(&context, DEFAULT_PROJECT, &request.request_id, LIMITS)
        .unwrap_err();
    assert!(error.contains("current readable recipient"), "{error}");
    assert!(stores(&wb, &invocation)
        .runtime
        .items
        .list_items(Some("tutorials"), None)
        .unwrap()
        .is_empty());
    assert!(stores(&wb, &invocation)
        .runtime
        .list_runs(&invocation.admission.instance_ref)
        .unwrap()
        .is_empty());
    let access = wb
        .request_project_tracker_access(
            &context,
            DEFAULT_PROJECT,
            "tutorials",
            "colleague-read",
            "colleague",
            TrackerPermission::Read,
        )
        .unwrap();
    wb.decide_project_tracker_access(
        &context,
        DEFAULT_PROJECT,
        "tutorials",
        "approve-colleague",
        &access.id,
        TrackerAccessDecision::Approve,
    )
    .unwrap();
    assert!(step(&mut wb, &context, &request).executed_effect.is_some());
    let items = stores(&wb, &invocation)
        .runtime
        .items
        .list_items(Some("tutorials"), None)
        .unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].assigned_to.as_deref(), Some("colleague"));
    assert_eq!(items[0].filed_by.as_deref(), Some(LOCAL_AUTHORITY));
}

#[test]
fn revoked_membership_prevents_rule_observation_and_filing() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    // Deprovision the actual actor after admission, before any rule pass.
    wb.store_mut().append_record(crate::org::ORG_SCOPE, "membership", &serde_json::json!({
        "id": LOCAL_AUTHORITY, "op":"upsert", "org_id":crate::org::ORG_ID,
        "authority":LOCAL_AUTHORITY,"email":"","role":"owner","status":"deprovisioned","managed_by_scim":false
    }).to_string()).unwrap();
    let before = stores(&wb, &invocation)
        .runtime
        .list_events(&invocation.admission.instance_ref)
        .unwrap();
    assert!(wb
        .step_project_workflow(&context, DEFAULT_PROJECT, &request.request_id, LIMITS)
        .is_err());
    assert_eq!(
        stores(&wb, &invocation)
            .runtime
            .list_events(&invocation.admission.instance_ref)
            .unwrap(),
        before
    );
    assert!(stores(&wb, &invocation)
        .runtime
        .items
        .list_items(Some("tutorials"), None)
        .unwrap()
        .is_empty());
}

#[test]
fn interrupted_filing_recovers_its_receipt_without_a_second_issue_or_attempt() {
    let (root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let invocation = {
        let mut wb = shared.lock_unpoisoned();
        declare(&mut wb, &context);
        wb.launch_project_workflow(&context, &request, LIMITS)
            .unwrap()
    };
    let native_root = root
        .path()
        .join("collaboration-workspaces")
        .join(&invocation.workspace)
        .join(".repo.whipplescript/workflow");
    let fault = rusqlite::Connection::open(native_root.join("runtime.sqlite")).unwrap();
    fault.execute_batch("CREATE TRIGGER lose_filing_terminal BEFORE INSERT ON events WHEN NEW.event_type = 'effect.terminal' BEGIN SELECT RAISE(ABORT, 'lost filing result'); END;").unwrap();
    {
        let mut wb = shared.lock_unpoisoned();
        assert!(wb
            .step_project_workflow(&context, DEFAULT_PROJECT, &request.request_id, LIMITS)
            .is_err());
        let native = stores(&wb, &invocation);
        assert_eq!(
            native
                .runtime
                .items
                .list_items(Some("tutorials"), None)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            native
                .runtime
                .list_runs(&invocation.admission.instance_ref)
                .unwrap()
                .len(),
            1
        );
    }
    fault
        .execute_batch("DROP TRIGGER lose_filing_terminal")
        .unwrap();
    drop(fault);
    drop(shared);
    let shared = open(root.path());
    let mut wb = shared.lock_unpoisoned();
    let recovered = step(&mut wb, &context, &request);
    assert!(recovered.recovered_effect.is_some());
    assert!(recovered.executed_effect.is_none());
    assert!(step(&mut wb, &context, &request).executed_effect.is_none());
    let native = stores(&wb, &invocation);
    assert_eq!(
        native
            .runtime
            .items
            .list_items(Some("tutorials"), None)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        native
            .runtime
            .list_runs(&invocation.admission.instance_ref)
            .unwrap()
            .len(),
        1
    );
    assert!(native
        .runtime
        .list_events(&invocation.admission.instance_ref)
        .unwrap()
        .iter()
        .any(|event| event.event_type == "tracker.filing.result_delivered"));
}

#[test]
fn interrupted_filing_without_a_receipt_is_unresolved_and_never_retried() {
    let (root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    let native_root = root
        .path()
        .join("collaboration-workspaces")
        .join(&invocation.workspace)
        .join(".repo.whipplescript/workflow");
    let runtime_fault = rusqlite::Connection::open(native_root.join("runtime.sqlite")).unwrap();
    runtime_fault.execute_batch("CREATE TRIGGER lose_filing_terminal BEFORE INSERT ON events WHEN NEW.event_type = 'effect.terminal' BEGIN SELECT RAISE(ABORT, 'lost filing result'); END;").unwrap();
    let item_fault = rusqlite::Connection::open(native_root.join("items.sqlite")).unwrap();
    item_fault.execute_batch("CREATE TRIGGER refuse_filing BEFORE INSERT ON tracker_issues BEGIN SELECT RAISE(ABORT, 'lost issue'); END;").unwrap();
    assert!(wb
        .step_project_workflow(&context, DEFAULT_PROJECT, &request.request_id, LIMITS)
        .is_err());
    runtime_fault
        .execute_batch("DROP TRIGGER lose_filing_terminal")
        .unwrap();
    item_fault
        .execute_batch("DROP TRIGGER refuse_filing")
        .unwrap();
    let before = stores(&wb, &invocation)
        .runtime
        .list_events(&invocation.admission.instance_ref)
        .unwrap();
    for _ in 0..2 {
        let error = wb
            .step_project_workflow(&context, DEFAULT_PROJECT, &request.request_id, LIMITS)
            .unwrap_err();
        assert!(error.contains("no committed filing receipt"), "{error}");
    }
    let native = stores(&wb, &invocation);
    assert_eq!(
        native
            .runtime
            .list_events(&invocation.admission.instance_ref)
            .unwrap(),
        before
    );
    assert!(native
        .runtime
        .items
        .list_items(Some("tutorials"), None)
        .unwrap()
        .is_empty());
    assert_eq!(
        native
            .runtime
            .list_runs(&invocation.admission.instance_ref)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn expired_native_wait_fails_the_workflow_without_filing_the_next_task() {
    let source = include_str!("tutorials/basics.whip").replace("timeout 30d", "timeout 1s");
    let (_root, shared, context, request) = fixture(&source);
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    assert!(step(&mut wb, &context, &request).executed_effect.is_some());
    assert!(step(&mut wb, &context, &request).executed_effect.is_none());
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let expired = step(&mut wb, &context, &request);
    assert_eq!(
        expired.snapshot.instance_status,
        ActionInstanceStatus::Failed
    );
    // The native failure net records an instance transition, not an authored
    // `fail` terminal. Assert that evidence and its actual timeout trigger.
    assert_eq!(
        expired.snapshot.status_evidence.kind,
        "instance.transitioned"
    );
    let native = stores(&wb, &invocation);
    assert!(native
        .runtime
        .list_events(&invocation.admission.instance_ref)
        .unwrap()
        .iter()
        .any(|event| event.event_id == expired.snapshot.status_evidence.event_id));
    assert!(native
        .runtime
        .list_facts_including_consumed(&invocation.admission.instance_ref)
        .unwrap()
        .iter()
        .any(|fact| fact.name == "effect.timed_out"));
    assert_eq!(
        stores(&wb, &invocation)
            .runtime
            .items
            .list_items(Some("tutorials"), None)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn revoked_contribution_grant_prevents_execution_after_admission() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
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
        .map(|record| {
            serde_json::from_str::<crate::project_tracker::TrackerAccessBasis>(&record).unwrap()
        })
        .find(|grant| {
            grant.recipient == LOCAL_AUTHORITY && grant.permission == TrackerPermission::Contribute
        })
        .unwrap();
    wb.decide_project_tracker_access(
        &context,
        DEFAULT_PROJECT,
        "tutorials",
        "revoke-contribute",
        &grant.id,
        TrackerAccessDecision::Revoke,
    )
    .unwrap();
    let before = stores(&wb, &invocation)
        .runtime
        .list_events(&invocation.admission.instance_ref)
        .unwrap();
    assert!(wb
        .step_project_workflow(&context, DEFAULT_PROJECT, &request.request_id, LIMITS)
        .is_err());
    let native = stores(&wb, &invocation);
    assert_eq!(
        native
            .runtime
            .list_events(&invocation.admission.instance_ref)
            .unwrap(),
        before
    );
    assert!(native
        .runtime
        .items
        .list_items(Some("tutorials"), None)
        .unwrap()
        .is_empty());
}
