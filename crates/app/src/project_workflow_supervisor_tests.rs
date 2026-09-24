//! DR-0191: a launched folder whip is stepped by the Home under its launcher's
//! standing, not their session, and that standing serves only its own launch.
use super::*;
use crate::identity::ActorAuthentication;
use gaugedesk_whip_runtime::host_actions::action_result::ActionInstanceStatus;
use std::{num::NonZeroUsize, time::Duration};

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

fn open_items(
    wb: &Workbench,
    invocation: &ProjectWorkflowInvocation,
) -> Vec<whipplescript_store::items::WorkItem> {
    stores(wb, invocation)
        .runtime
        .items
        .list_items(Some("tutorials"), Some("open"))
        .unwrap()
}

fn close_open_task(
    wb: &mut Workbench,
    context: &AuthenticatedActionContext,
    invocation: &ProjectWorkflowInvocation,
    request_id: &str,
) {
    let pending = open_items(wb, invocation);
    assert_eq!(pending.len(), 1, "one task is open at a time");
    let close = crate::project_tracker::CompleteTrackerIssue {
        project: invocation.project.clone(),
        queue: "tutorials".into(),
        item_id: pending[0].id.clone(),
        subject_id: stores(wb, invocation)
            .runtime
            .items
            .subject_content_id(&pending[0].id)
            .unwrap()
            .unwrap(),
        request_id: request_id.into(),
        summary: "I completed this task".into(),
        claim: crate::project_tracker::TrackerCompletionClaim::Override,
    };
    wb.complete_project_tracker_issue(context, &close, LIMITS)
        .unwrap();
}

fn set_membership(wb: &mut Workbench, status: crate::org::MembershipStatus) {
    let membership = crate::org::MembershipRecord {
        id: LOCAL_AUTHORITY.into(),
        op: crate::org::RecordOp::Upsert,
        org_id: crate::org::ORG_ID.into(),
        authority: LOCAL_AUTHORITY.into(),
        email: String::new(),
        role: "owner".into(),
        status,
        managed_by_scim: false,
        team: None,
    };
    wb.store_mut()
        .append_record(
            crate::org::ORG_SCOPE,
            "membership",
            &serde_json::to_string(&membership).unwrap(),
        )
        .unwrap();
}

fn revoke_session(wb: &mut Workbench, context: &AuthenticatedActionContext) {
    let ActorAuthentication::AccountSession { session_ref } = context.authentication() else {
        panic!("the fixture launches from an account session");
    };
    assert!(wb.revoke_account_session_id(session_ref));
}

#[test]
fn a_launch_scope_names_exactly_its_project_launcher_and_request() {
    let scope = request_scope("personal", "alice@example.com", "basics").unwrap();
    assert_eq!(
        launch_scope_parts(&scope),
        Some((
            "personal".into(),
            "alice@example.com".into(),
            "basics".into()
        ))
    );
    for other in [
        "project::personal::workflow",
        "project::personal::workflow-launch::zz::00",
        &format!("{scope}::extra"),
        &format!("x{scope}"),
    ] {
        assert_eq!(launch_scope_parts(other), None, "{other}");
    }
}

#[test]
fn an_unattended_step_outlives_the_launch_session() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    revoke_session(&mut wb, &context);

    let expired = wb
        .step_project_workflow(&context, &request.project, &request.request_id, LIMITS)
        .unwrap_err();
    assert!(
        expired.contains("session is not durably active"),
        "the launcher's own session no longer steps anything: {expired}"
    );
    let step = wb
        .step_project_workflow_unattended(&invocation.product_scope, LIMITS)
        .unwrap();
    assert!(step.executed_effect.is_some(), "the first task is filed");
    let items = open_items(&wb, &invocation);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].assigned_to.as_deref(), Some(LOCAL_AUTHORITY));
    assert_eq!(items[0].filed_by.as_deref(), Some(LOCAL_AUTHORITY));
}

#[test]
fn losing_membership_stops_an_unattended_run_until_it_returns() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();

    set_membership(&mut wb, crate::org::MembershipStatus::Deprovisioned);
    let stopped = wb
        .step_project_workflow_unattended(&invocation.product_scope, LIMITS)
        .unwrap_err();
    assert!(
        stopped.contains("exceeds current project"),
        "a deprovisioned launcher's run does not step: {stopped}"
    );
    assert!(open_items(&wb, &invocation).is_empty(), "and files nothing");

    set_membership(&mut wb, crate::org::MembershipStatus::Active);
    let step = wb
        .step_project_workflow_unattended(&invocation.product_scope, LIMITS)
        .unwrap();
    assert!(
        step.executed_effect.is_some(),
        "restored standing resumes it"
    );
}

#[test]
fn unattended_authority_serves_only_its_own_launch() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    let unattended = AuthenticatedActionContext::project_workflow_invocation(
        context.actor().clone(),
        invocation.product_scope.clone(),
    );

    let mut another = request.clone();
    another.request_id = "second".into();
    for refused in [
        wb.launch_project_workflow(&unattended, &another, LIMITS)
            .map(drop),
        wb.launch_project_workflow(&unattended, &request, LIMITS)
            .map(drop),
    ] {
        assert_eq!(
            refused.unwrap_err(),
            "workflow authority cannot launch a workflow"
        );
    }
    assert_eq!(
        wb.step_project_workflow(&unattended, &request.project, "second", LIMITS)
            .unwrap_err(),
        "workflow authority serves only its own invocation"
    );
    let declared = wb
        .declare_project_tracker(
            &unattended,
            DEFAULT_PROJECT,
            "other",
            "declare-other",
            ResourceAttributes::default(),
        )
        .expect_err("it cannot change tracker access");
    assert!(
        format!("{declared:?}").contains("workflow authority cannot change tracker access"),
        "{declared:?}"
    );

    let forged = AuthenticatedActionContext::project_workflow_invocation(
        gaugedesk_core::ids::AuthorityId::new("colleague"),
        invocation.product_scope.clone(),
    );
    assert_eq!(
        wb.step_project_workflow(&forged, &request.project, &request.request_id, LIMITS)
            .unwrap_err(),
        "workflow authority serves only its own invocation",
        "it is keyed to its launcher"
    );
    let unlaunched = wb
        .step_project_workflow_unattended(
            &request_scope(&request.project, LOCAL_AUTHORITY, "never-launched").unwrap(),
            LIMITS,
        )
        .unwrap_err();
    assert!(
        unlaunched.contains("workflow authority has no retained launch"),
        "a scope with no retained launch confers nothing: {unlaunched}"
    );
}

async fn notice(
    notices: &mut tokio::sync::mpsc::Receiver<ProjectWorkflowNotice>,
    scope: &str,
) -> ProjectWorkflowOutcome {
    loop {
        let notice = tokio::time::timeout(Duration::from_secs(30), notices.recv())
            .await
            .expect("the supervisor answers")
            .expect("the supervisor is running");
        if notice.scope == scope {
            return notice.outcome;
        }
    }
}

/// Basics end to end with no caller stepping it: launching wakes the Home, each
/// closure wakes it again, and the run completes after the fourth task.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_supervisor_drives_basics_from_launch_to_completion() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let (tx, mut notices) = tokio::sync::mpsc::channel(64);
    let supervisor = tokio::spawn(supervise_project_workflows(
        shared.clone(),
        ProjectWorkflowSupervisorConfig {
            limits: LIMITS,
            discovery_page_size: NonZeroUsize::new(16).unwrap(),
            steps_per_wake: 8,
            sweep: Duration::from_secs(3600),
        },
        shutdown,
        tx,
    ));

    let invocation = {
        let mut wb = shared.lock_unpoisoned();
        declare(&mut wb, &context);
        wb.launch_project_workflow(&context, &request, LIMITS)
            .unwrap()
    };
    let scope = invocation.product_scope.clone();
    assert_eq!(
        notice(&mut notices, &scope).await,
        ProjectWorkflowOutcome::Parked
    );
    for (index, title) in [
        "Create a chat in Personal",
        "Make your personal assistant",
        "Create a project",
        "Invite a colleague",
    ]
    .into_iter()
    .enumerate()
    {
        {
            let mut wb = shared.lock_unpoisoned();
            let open = open_items(&wb, &invocation);
            assert_eq!(open.len(), 1);
            assert_eq!(open[0].title, title);
            close_open_task(&mut wb, &context, &invocation, &format!("close-{index}"));
        }
        let expected = if index == 3 {
            ProjectWorkflowOutcome::Finished("completed".into())
        } else {
            ProjectWorkflowOutcome::Parked
        };
        assert_eq!(
            notice(&mut notices, &scope).await,
            expected,
            "after {title}"
        );
    }
    let result = shared
        .lock_unpoisoned()
        .step_project_workflow(&context, &request.project, &request.request_id, LIMITS)
        .unwrap();
    assert_eq!(
        result.snapshot.instance_status,
        ActionInstanceStatus::Completed
    );
    stop.send(true).unwrap();
    supervisor.await.unwrap().unwrap();
}

/// A restart rediscovers a parked run from its retained launch alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_rediscovers_a_launch_nobody_hinted() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let invocation = {
        let mut wb = shared.lock_unpoisoned();
        declare(&mut wb, &context);
        wb.launch_project_workflow(&context, &request, LIMITS)
            .unwrap()
    };
    // Launched before any supervisor listened: the hint went nowhere.
    assert!(open_items(&shared.lock_unpoisoned(), &invocation).is_empty());
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let (tx, mut notices) = tokio::sync::mpsc::channel(64);
    let supervisor = tokio::spawn(supervise_project_workflows(
        shared.clone(),
        ProjectWorkflowSupervisorConfig {
            limits: LIMITS,
            discovery_page_size: NonZeroUsize::new(1).unwrap(),
            steps_per_wake: 8,
            sweep: Duration::from_secs(3600),
        },
        shutdown,
        tx,
    ));
    assert_eq!(
        notice(&mut notices, &invocation.product_scope).await,
        ProjectWorkflowOutcome::Parked
    );
    assert_eq!(open_items(&shared.lock_unpoisoned(), &invocation).len(), 1);
    stop.send(true).unwrap();
    supervisor.await.unwrap().unwrap();
}

/// Replacing the workbench value in place — the debug reset route does — drops
/// the hint channel the supervisor listens on. It keeps supervising the
/// workbench now there instead of stopping, which it did until the first
/// real-browser run found it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervision_survives_the_workbench_being_replaced_in_place() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let (tx, mut notices) = tokio::sync::mpsc::channel(64);
    let supervisor = tokio::spawn(supervise_project_workflows(
        shared.clone(),
        ProjectWorkflowSupervisorConfig {
            limits: LIMITS,
            discovery_page_size: NonZeroUsize::new(16).unwrap(),
            steps_per_wake: 8,
            sweep: Duration::from_secs(3600),
        },
        shutdown,
        tx,
    ));
    // Let the supervisor subscribe, then swap the value under it the way the
    // reset route does: the same state root, rebuilt.
    tokio::time::sleep(Duration::from_millis(200)).await;
    {
        let mut guard = shared.lock_unpoisoned();
        let root = guard.root_path();
        let rebuilt =
            crate::workbench_state::open_lean_workbench_with_content_keywrap(&root, |_| {
                Ok(Box::new(crate::at_rest::LoopbackKeyWrap::new([37; 32])))
            })
            .unwrap();
        let rebuilt = std::sync::Arc::try_unwrap(rebuilt)
            .ok()
            .unwrap()
            .into_inner()
            .unwrap();
        drop(std::mem::replace(&mut *guard, rebuilt));
    }
    let invocation = {
        let mut wb = shared.lock_unpoisoned();
        declare(&mut wb, &context);
        wb.launch_project_workflow(&context, &request, LIMITS)
            .unwrap()
    };
    assert_eq!(
        notice(&mut notices, &invocation.product_scope).await,
        ProjectWorkflowOutcome::Parked,
        "the replaced workbench's launch is still driven"
    );
    assert!(
        !supervisor.is_finished(),
        "and the supervisor is still running"
    );
    stop.send(true).unwrap();
    supervisor.await.unwrap().unwrap();
}
