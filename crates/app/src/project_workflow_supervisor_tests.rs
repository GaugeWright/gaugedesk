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
        "tasks",
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
        .list_items(Some("tasks"), Some("open"))
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
        queue: "tasks".into(),
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
    // This launcher holds a legacy organization-issued project grant, so
    // directory deprovisioning really revokes its project standing.
    let mut project = wb.library.projects[DEFAULT_PROJECT].clone();
    crate::project_owner::record_owner(&mut project.extra, "another-account");
    wb.store_mut()
        .append_record(
            crate::library::LIBRARY_SCOPE,
            "project",
            &serde_json::to_string(&project).unwrap(),
        )
        .unwrap();
    project_grant(&mut wb, LOCAL_AUTHORITY, DEFAULT_PROJECT);
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

async fn settles(
    notices: &mut tokio::sync::mpsc::Receiver<ProjectWorkflowNotice>,
    scope: &str,
    expected: ProjectWorkflowOutcome,
) {
    loop {
        let notice = tokio::time::timeout(Duration::from_secs(30), notices.recv())
            .await
            .unwrap_or_else(|_| panic!("the supervisor reports {expected:?} for {scope}"))
            .expect("the supervisor is running");
        if notice.scope != scope {
            continue;
        }
        if let ProjectWorkflowOutcome::NeedsAttention { detail } = &notice.outcome {
            panic!("{scope} needs attention instead of reporting {expected:?}: {detail}");
        }
        if notice.outcome == expected {
            return;
        }
    }
}

/// The one open task, once the supervisor has filed it.
///
/// Waits rather than reading once, because the supervisor is asynchronous and
/// a notice is not a receipt for the caller's own action. It promises to drive
/// a scope whenever something hints at it, not to emit one notice per action:
/// its sweep interval fires its FIRST tick immediately, so a launch that lands
/// before that tick is driven by both the startup sweep and its own hint and
/// reports `Parked` twice. A caller taking one notice per action then runs a
/// step ahead of the supervisor and reads the tracker before the next task is
/// filed.
///
/// That is not hypothetical. On 2026-09-24 the public mirror's bar failed here
/// on `open.len()` being 0 where 1 was expected, while the trunk's bar passed
/// the identical commit — the only difference being that the mirror's lane
/// runs the suite at full parallelism in a cold clone and the trunk's runs as
/// a Buck2 action with a declared core count. Thirty-six runs of this test
/// under six-way parallelism on a quiet machine did not reproduce it, which is
/// the point: the assertion was about scheduling rather than about behaviour.
async fn open_task(
    shared: &crate::SharedWorkbench,
    invocation: &ProjectWorkflowInvocation,
) -> whipplescript_store::items::WorkItem {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        {
            let wb = shared.lock_unpoisoned();
            let mut open = open_items(&wb, invocation);
            assert!(
                open.len() <= 1,
                "one task is open at a time, found {}",
                open.len()
            );
            if let Some(task) = open.pop() {
                return task;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the supervisor files the next task"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
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
    settles(&mut notices, &scope, ProjectWorkflowOutcome::Parked).await;
    for (index, title) in [
        "Create a chat in Personal",
        "Make your personal assistant",
        "Create a project",
        "Invite a colleague",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(open_task(&shared, &invocation).await.title, title);
        {
            let mut wb = shared.lock_unpoisoned();
            close_open_task(&mut wb, &context, &invocation, &format!("close-{index}"));
        }
        let expected = if index == 3 {
            ProjectWorkflowOutcome::Finished("completed".into())
        } else {
            ProjectWorkflowOutcome::Parked
        };
        settles(&mut notices, &scope, expected).await;
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
    settles(
        &mut notices,
        &invocation.product_scope,
        ProjectWorkflowOutcome::Parked,
    )
    .await;
    open_task(&shared, &invocation).await;
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
        rebuilt
            .lock_unpoisoned()
            .hold_session_for_tests(DEFAULT_PROJECT);
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
    // The replaced workbench's launch is still driven.
    settles(
        &mut notices,
        &invocation.product_scope,
        ProjectWorkflowOutcome::Parked,
    )
    .await;
    assert!(
        !supervisor.is_finished(),
        "and the supervisor is still running"
    );
    stop.send(true).unwrap();
    supervisor.await.unwrap().unwrap();
}

// ---- DR-0312: background work holds only the keys its declaration names ----

use crate::key_delegation::{workflow_delegation_id, DelegationState, LAPSE_MS};

fn delegation_state(wb: &Workbench, scope: &str, now: u64) -> DelegationState {
    let ledger = wb.project_delegations(DEFAULT_PROJECT).unwrap();
    ledger.delegations[&workflow_delegation_id(scope)].state(ledger.last_member_use_ms, now)
}

fn ledger_events(wb: &Workbench) -> Vec<serde_json::Value> {
    wb.store_ref()
        .records(
            &crate::key_delegation::ledger_scope(DEFAULT_PROJECT),
            "key_delegation",
        )
        .unwrap()
        .iter()
        .map(|record| serde_json::from_str(record).unwrap())
        .collect()
}

fn count(events: &[serde_json::Value], event: &str) -> usize {
    events.iter().filter(|e| e["event"] == event).count()
}

fn resume_tasks(wb: &Workbench) -> Vec<serde_json::Value> {
    wb.task_queue_value(LOCAL_AUTHORITY)["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|task| task["kind"] == "resume")
        .cloned()
        .collect()
}

#[test]
fn launching_hands_the_host_only_the_keys_the_workflow_declares() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    let ledger = wb.project_delegations(DEFAULT_PROJECT).unwrap();
    assert_eq!(ledger.delegations.len(), 1, "one launch, one delegation");
    let record = &ledger.delegations[&workflow_delegation_id(&invocation.product_scope)];
    assert_eq!(
        record.delegation.scopes,
        std::iter::once(content_scope(DEFAULT_PROJECT).unwrap()).collect(),
        "the workflow names its own storage, and nothing else of the project"
    );
    assert_eq!(record.delegation.granted_from, LOCAL_AUTHORITY);
    assert_eq!(
        record.delegation.work,
        crate::key_delegation::DelegatedWork::Workflow {
            launch: invocation.product_scope.clone(),
            target: request.target.clone(),
            path: request.path.clone(),
        }
    );

    // Launching the same request again recovers it; it derives nothing new.
    wb.launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    assert_eq!(count(&ledger_events(&wb), "derived"), 1);

    let view = wb
        .project_delegations_value(DEFAULT_PROJECT, crate::key_delegation::now_ms())
        .unwrap();
    let shown = &view["delegations"][0];
    assert_eq!(shown["state"], "held");
    assert_eq!(shown["work"]["path"], request.path.as_str());
    assert_eq!(shown["keys"][0]["label"], "workflow storage");
    assert_eq!(shown["granted_from"], LOCAL_AUTHORITY);
}

#[test]
fn every_unattended_step_that_acts_is_recorded() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    let step = wb
        .step_project_workflow_unattended(&invocation.product_scope, LIMITS)
        .unwrap();
    let effect = step.executed_effect.expect("the first task is filed");
    // A step that finds the run waiting acts on nothing and is not a use.
    let waiting = wb
        .step_project_workflow_unattended(&invocation.product_scope, LIMITS)
        .unwrap();
    assert!(waiting.executed_effect.is_none() && waiting.recovered_effect.is_none());

    let events = ledger_events(&wb);
    let uses: Vec<_> = events.iter().filter(|e| e["event"] == "used").collect();
    assert_eq!(uses.len(), 1);
    assert_eq!(uses[0]["effect"], effect.as_str());
    let view = wb
        .project_delegations_value(DEFAULT_PROJECT, crate::key_delegation::now_ms())
        .unwrap();
    assert_eq!(view["delegations"][0]["use_count"], 1);
}

#[test]
fn work_nobody_has_used_for_thirty_days_pauses_and_resumes_when_a_member_returns() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    let scope = invocation.product_scope.clone();
    let granted = wb.project_delegations(DEFAULT_PROJECT).unwrap().delegations
        [&workflow_delegation_id(&scope)]
        .delegation
        .granted_at_ms;

    // A day short of the lapse it still holds its keys.
    let nearly = granted + LAPSE_MS - 24 * 60 * 60 * 1000;
    assert!(matches!(
        delegation_state(&wb, &scope, nearly),
        DelegationState::Held { .. }
    ));
    wb.step_project_workflow_unattended_at(&scope, LIMITS, nearly)
        .unwrap();
    assert_eq!(wb.lapsed_background_work(DEFAULT_PROJECT, nearly), 0);

    let lapsed = granted + LAPSE_MS;
    let paused = wb
        .step_project_workflow_unattended_at(&scope, LIMITS, lapsed)
        .unwrap_err();
    assert!(paused.contains("paused"), "{paused}");
    wb.step_project_workflow_unattended_at(&scope, LIMITS, lapsed + 60_000)
        .unwrap_err();
    assert_eq!(
        count(&ledger_events(&wb), "lapsed"),
        1,
        "one lapse is recorded once however often it is found"
    );
    let view = wb
        .project_delegations_value(DEFAULT_PROJECT, lapsed + 60_000)
        .unwrap();
    assert_eq!(view["delegations"][0]["state"], "lapsed");
    assert_eq!(wb.lapsed_background_work(DEFAULT_PROJECT, lapsed), 1);

    // A member uses the project: the delegation renews and the work resumes.
    let back = lapsed + 2 * 60 * 60 * 1000;
    wb.note_member_use(DEFAULT_PROJECT, back);
    assert!(matches!(
        delegation_state(&wb, &scope, back),
        DelegationState::Held { expires_at_ms } if expires_at_ms == back + LAPSE_MS
    ));
    wb.step_project_workflow_unattended_at(&scope, LIMITS, back + 1)
        .unwrap();
    assert_eq!(wb.lapsed_background_work(DEFAULT_PROJECT, back + 1), 0);

    // A second lapse is a second record.
    wb.step_project_workflow_unattended_at(&scope, LIMITS, back + LAPSE_MS)
        .unwrap_err();
    assert_eq!(count(&ledger_events(&wb), "lapsed"), 2);
}

#[test]
fn a_lapsed_project_appears_in_its_members_task_queue() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    assert!(resume_tasks(&wb).is_empty(), "held work raises nothing");
    // The queue reads the real clock and a ledger is append-only, so age the
    // project the way a real one ages: an older launch whose delegation was
    // granted before the lapse window, with no member use since.
    let mut old = wb.project_delegations(DEFAULT_PROJECT).unwrap().delegations
        [&workflow_delegation_id(&invocation.product_scope)]
        .delegation
        .clone();
    old.id = workflow_delegation_id("an older launch");
    old.granted_at_ms = crate::key_delegation::now_ms() - LAPSE_MS - 1;
    let mut derived = serde_json::to_value(&old).unwrap();
    derived["event"] = "derived".into();
    wb.store_mut()
        .append_record(
            &crate::key_delegation::ledger_scope(DEFAULT_PROJECT),
            "key_delegation",
            &derived.to_string(),
        )
        .unwrap();
    let tasks = resume_tasks(&wb);
    assert_eq!(tasks.len(), 1, "{tasks:?}");
    assert_eq!(tasks[0]["project"], DEFAULT_PROJECT);
    assert_eq!(tasks[0]["waiting"], 1);
    assert_eq!(tasks[0]["assignee"], LOCAL_AUTHORITY);
    assert!(
        wb.task_queue_value("someone-else")["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|task| task["kind"] != "resume"),
        "a non-member is not told about a project it cannot open"
    );

    wb.note_member_use(DEFAULT_PROJECT, crate::key_delegation::now_ms());
    assert!(resume_tasks(&wb).is_empty(), "a member's use renews it");
}

#[test]
fn a_launch_from_before_delegations_derives_its_own_at_its_first_unattended_step() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let invocation = wb
        .launch_project_workflow_admitted(&context, &request, LIMITS)
        .unwrap();
    assert!(wb
        .project_delegations(DEFAULT_PROJECT)
        .unwrap()
        .delegations
        .is_empty());
    wb.step_project_workflow_unattended(&invocation.product_scope, LIMITS)
        .unwrap();
    let ledger = wb.project_delegations(DEFAULT_PROJECT).unwrap();
    let record = &ledger.delegations[&workflow_delegation_id(&invocation.product_scope)];
    assert_eq!(record.delegation.granted_from, LOCAL_AUTHORITY);
    assert_eq!(record.uses.len(), 1);
}

#[test]
fn work_that_reaches_outside_its_declaration_is_refused_and_says_what_it_could_not_reach() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let invocation = wb
        .launch_project_workflow_admitted(&context, &request, LIMITS)
        .unwrap();
    // A delegation that names some other part of the project, standing in
    // for work whose declaration does not cover what it does.
    let workflow = content_scope(DEFAULT_PROJECT).unwrap();
    wb.store_mut()
        .append_record(
            &crate::key_delegation::ledger_scope(DEFAULT_PROJECT),
            "key_delegation",
            &serde_json::to_string(&serde_json::json!({
                "event": "derived",
                "id": workflow_delegation_id(&invocation.product_scope),
                "project": DEFAULT_PROJECT,
                "work": {"kind": "workflow", "launch": invocation.product_scope,
                         "target": request.target, "path": request.path},
                "scopes": [crate::account::project_scope(DEFAULT_PROJECT)],
                "granted_from": LOCAL_AUTHORITY,
                "granted_at_ms": crate::key_delegation::now_ms(),
            }))
            .unwrap(),
        )
        .unwrap();
    let refused = wb
        .step_project_workflow_unattended(&invocation.product_scope, LIMITS)
        .unwrap_err();
    assert!(
        refused.contains("reached outside what it declared") && refused.contains(&workflow),
        "{refused}"
    );
    assert!(open_items(&wb, &invocation).is_empty(), "it filed nothing");
    let events = ledger_events(&wb);
    let refusals: Vec<_> = events.iter().filter(|e| e["event"] == "refused").collect();
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0]["scope"], workflow.as_str());
    let view = wb
        .project_delegations_value(DEFAULT_PROJECT, crate::key_delegation::now_ms())
        .unwrap();
    assert_eq!(
        view["delegations"][0]["refusals"][0]["label"],
        "workflow storage"
    );

    // The person who launched it is present and may still step it: an
    // attended step is their own session, not the delegation.
    wb.step_project_workflow(&context, &request.project, &request.request_id, LIMITS)
        .unwrap();
}

#[test]
fn finished_work_holds_no_keys() {
    let (_root, shared, context, request) = fixture(ECHO);
    let mut wb = shared.lock_unpoisoned();
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    let step = wb
        .step_project_workflow_unattended(&invocation.product_scope, LIMITS)
        .unwrap();
    assert_eq!(
        step.snapshot.instance_status,
        ActionInstanceStatus::Completed
    );
    assert_eq!(
        delegation_state(
            &wb,
            &invocation.product_scope,
            crate::key_delegation::now_ms()
        ),
        DelegationState::Ended
    );
    let after = wb
        .step_project_workflow_unattended(&invocation.product_scope, LIMITS)
        .unwrap_err();
    assert!(after.contains("ended"), "{after}");
    let view = wb
        .project_delegations_value(DEFAULT_PROJECT, crate::key_delegation::now_ms())
        .unwrap();
    assert!(view["delegations"].as_array().unwrap().is_empty());
    assert_eq!(view["ended"][0]["ended"]["outcome"], "completed");
}

fn supervise(
    shared: &crate::SharedWorkbench,
    sweep: Duration,
) -> (
    tokio::sync::watch::Sender<bool>,
    tokio::sync::mpsc::Receiver<ProjectWorkflowNotice>,
    tokio::task::JoinHandle<Result<(), String>>,
) {
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let (tx, notices) = tokio::sync::mpsc::channel(256);
    let supervisor = tokio::spawn(supervise_project_workflows(
        shared.clone(),
        ProjectWorkflowSupervisorConfig {
            limits: LIMITS,
            discovery_page_size: NonZeroUsize::new(16).unwrap(),
            steps_per_wake: 8,
            sweep,
        },
        shutdown,
        tx,
    ));
    (stop, notices, supervisor)
}

/// Paused work is not a fault: the supervisor parks it without stepping it,
/// and resumes it as soon as a member uses the project rather than at the
/// next sweep.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_supervisor_parks_paused_work_and_wakes_it_when_a_member_returns() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let invocation = {
        let mut wb = shared.lock_unpoisoned();
        declare(&mut wb, &context);
        let invocation = wb
            .launch_project_workflow_admitted(&context, &request, LIMITS)
            .unwrap();
        // Launched before the window, and nobody has used the project since.
        let mut derived = serde_json::json!({
            "event": "derived",
            "id": workflow_delegation_id(&invocation.product_scope),
            "project": DEFAULT_PROJECT,
            "work": {"kind": "workflow", "launch": invocation.product_scope,
                     "target": request.target, "path": request.path},
            "scopes": [content_scope(DEFAULT_PROJECT).unwrap()],
            "granted_from": LOCAL_AUTHORITY,
        });
        derived["granted_at_ms"] = (crate::key_delegation::now_ms() - LAPSE_MS - 1).into();
        wb.store_mut()
            .append_record(
                &crate::key_delegation::ledger_scope(DEFAULT_PROJECT),
                "key_delegation",
                &derived.to_string(),
            )
            .unwrap();
        invocation
    };
    let scope = invocation.product_scope.clone();
    // The startup sweep is the only one within the test: resuming must come
    // from the member's use waking it, not from a sweep happening by.
    let (stop, mut notices, supervisor) = supervise(&shared, Duration::from_secs(3600));
    settles(&mut notices, &scope, ProjectWorkflowOutcome::Parked).await;
    {
        let wb = shared.lock_unpoisoned();
        assert!(
            open_items(&wb, &invocation).is_empty(),
            "paused work filed nothing"
        );
        assert_eq!(count(&ledger_events(&wb), "lapsed"), 1);
        assert_eq!(resume_tasks(&wb).len(), 1, "its member is told");
    }

    shared
        .lock_unpoisoned()
        .note_member_use(DEFAULT_PROJECT, crate::key_delegation::now_ms());
    assert_eq!(
        open_task(&shared, &invocation).await.title,
        "Create a chat in Personal"
    );
    assert!(resume_tasks(&shared.lock_unpoisoned()).is_empty());
    stop.send(true).unwrap();
    supervisor.await.unwrap().unwrap();
}

/// A restarted Home finds work that finished before it stopped. Its
/// delegation ended, so it reads as finished, not as a refusal each sweep.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finished_work_reads_as_finished_after_a_restart() {
    let (_root, shared, context, request) = fixture(ECHO);
    let scope = {
        let mut wb = shared.lock_unpoisoned();
        let invocation = wb
            .launch_project_workflow(&context, &request, LIMITS)
            .unwrap();
        wb.step_project_workflow_unattended(&invocation.product_scope, LIMITS)
            .unwrap();
        invocation.product_scope
    };
    let (stop, mut notices, supervisor) = supervise(&shared, Duration::from_millis(40));
    settles(
        &mut notices,
        &scope,
        ProjectWorkflowOutcome::Finished("completed".into()),
    )
    .await;
    stop.send(true).unwrap();
    supervisor.await.unwrap().unwrap();
    assert_eq!(count(&ledger_events(&shared.lock_unpoisoned()), "ended"), 1);
}

#[test]
fn a_run_found_waiting_is_recorded_as_checked_at_most_hourly() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    let scope = invocation.product_scope.clone();
    let now = crate::key_delegation::now_ms();
    wb.step_project_workflow_unattended_at(&scope, LIMITS, now)
        .unwrap();
    for minute in 1..=3 {
        wb.step_project_workflow_unattended_at(&scope, LIMITS, now + minute * 60_000)
            .unwrap();
    }
    assert_eq!(count(&ledger_events(&wb), "checked"), 1, "one an hour");
    wb.step_project_workflow_unattended_at(
        &scope,
        LIMITS,
        now + crate::key_delegation::CHECK_GRANULARITY_MS + 60_000,
    )
    .unwrap();
    assert_eq!(count(&ledger_events(&wb), "checked"), 2);
    let view = wb.project_delegations_value(DEFAULT_PROJECT, now).unwrap();
    assert_eq!(
        view["delegations"][0]["use_count"], 1,
        "checks are not acts"
    );
    assert!(view["delegations"][0]["last_checked_ms"].is_u64());
}

/// WS-740: with no session holding the project, an unattended step opens its
/// declared key for the step and leaves nothing open after it.
#[test]
fn an_unattended_step_leaves_no_key_open_after_it() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    declare(&mut wb, &context);
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    // The launcher's session ends.
    wb.test_session_holds.clear();
    let vault = wb.content_vault.clone().unwrap();
    assert_eq!(vault.open_project_keys(), 0);
    let step = wb
        .step_project_workflow_unattended(&invocation.product_scope, LIMITS)
        .unwrap();
    assert!(step.executed_effect.is_some(), "it still files its task");
    assert_eq!(vault.open_project_keys(), 0, "and leaves no key open");
    assert!(vault.opened_projects().is_empty());
}
