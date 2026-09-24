//! WHIP-3's Run control: a chat's `.whip` file is described and launched at
//! the kept revision on its target's Main, under the ordinary launch authority.
use super::tracker_routes::{app, auth, send};
use super::*;
use axum::http::StatusCode;

fn chat(shared: &crate::SharedWorkbench) -> String {
    shared
        .lock_unpoisoned()
        .create_default_engagement("run-chat".into(), "Run".into())
        .unwrap_or_else(|_| panic!("a chat in Personal"));
    "run-chat".into()
}

#[test]
fn a_chat_file_resolves_to_its_target_and_the_kept_revision() {
    let (_root, shared, context, request) = fixture(ECHO);
    let chat = chat(&shared);
    let wb = shared.lock_unpoisoned();
    let source = wb
        .chat_workflow_source(&chat, "lessons/hello.whip")
        .unwrap();
    assert_eq!(source.project, DEFAULT_PROJECT);
    assert_eq!(source.target, request.target);
    assert_eq!(source.path, "lessons/hello.whip");
    assert_eq!(
        source.cut, request.cut,
        "Main's head, never the chat's own revision"
    );
    let described = wb
        .describe_project_workflow(&context, &source, LIMITS)
        .unwrap();
    assert_eq!(described["workflow"], "Greeting");
    assert_eq!(described["inputs"][0]["name"], "learner");
    assert_eq!(described["inputs"][0]["type"]["kind"], "object");

    let refused = wb
        .chat_workflow_source(&chat, "lessons/notes.md")
        .unwrap_err();
    assert!(refused.contains(".whip"), "{refused}");
    assert!(wb
        .chat_workflow_source("no-such-chat", "lessons/hello.whip")
        .is_err());
}

/// The same authority as a launch: someone who may not run it may not read its
/// declaration through here either.
#[test]
fn describing_needs_the_launch_authority() {
    let (_root, shared, _context, _request) = fixture(ECHO);
    let chat = chat(&shared);
    let mut wb = shared.lock_unpoisoned();
    let token = wb
        .mint_account_session("stranger", "passkey", 3600)
        .unwrap();
    let stranger = wb.authenticate_action_context(&token).unwrap();
    let source = wb
        .chat_workflow_source(&chat, "lessons/hello.whip")
        .unwrap();
    wb.describe_project_workflow(&stranger, &source, LIMITS)
        .expect_err("a stranger to the project reads nothing");
}

#[tokio::test]
async fn a_chat_whip_is_described_then_run_over_http() {
    let (_root, shared, _context, _request) = fixture(ECHO);
    let chat = chat(&shared);
    let (token, admission) = auth(&mut shared.lock_unpoisoned());
    let app = app(&shared, false);
    let inputs = format!("/chats/{chat}/whips/inputs?path=lessons%2Fhello.whip");
    let (status, _) = send(&app, "GET", &inputs, None, None, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, described) = send(
        &app,
        "GET",
        &inputs,
        Some(&token),
        Some(&admission),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{described}");
    assert_eq!(described["workflow"], "Greeting");
    let run = format!("/chats/{chat}/whips/run");
    let body = serde_json::json!({
        "path": "lessons/hello.whip",
        "cut": described["cut"],
        "inputs": { "learner": { "authority": LOCAL_AUTHORITY } },
    });
    let (status, first) = send(
        &app,
        "POST",
        &run,
        Some(&token),
        Some(&admission),
        Some("run-1"),
        Some(body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (status, again) = send(
        &app,
        "POST",
        &run,
        Some(&token),
        Some(&admission),
        Some("run-1"),
        Some(body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(
        first["product_scope"], again["product_scope"],
        "one key, one run"
    );
    let (status, _) = send(
        &app,
        "POST",
        &run,
        Some(&token),
        Some(&admission),
        None,
        Some(body),
    )
    .await;
    assert!(status.is_client_error(), "a run needs its key");
}

/// Put the target back the way every managed target is created: the Home's,
/// with the Home its only party. Labelled internal, as a team labels files an
/// ordinary member may work with; unlabelled files are regulated, which a
/// member's role does not clear for chats or workflows alike.
fn home_owned(wb: &mut Workbench, target: &str) {
    let mut record = wb.library.work_targets[target].clone();
    record.attributes.classification = gaugedesk_core::abac::Classification::Internal;
    record.authority = wb.home_id().as_str().to_owned();
    record.parties = vec![wb.home_id().as_str().to_owned()];
    wb.store_mut()
        .append_record(
            crate::library::LIBRARY_SCOPE,
            "work_target",
            &serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
    wb.rebuild_library();
}

/// A person who is a member of the Home and holds a grant on one project.
fn member(
    wb: &mut Workbench,
    authority: &str,
    project: Option<&str>,
) -> AuthenticatedActionContext {
    let membership = crate::org::MembershipRecord {
        id: authority.into(),
        op: crate::org::RecordOp::Upsert,
        org_id: crate::org::ORG_ID.into(),
        authority: authority.into(),
        email: String::new(),
        role: "member".into(),
        status: crate::org::MembershipStatus::Active,
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
    if let Some(project) = project {
        let grant = crate::org::MemberGrantRecord {
            id: crate::org::MemberGrantRecord::make_id(authority, project),
            op: crate::org::RecordOp::Upsert,
            authority: authority.into(),
            project_id: project.into(),
        };
        wb.store_mut()
            .append_record(
                crate::org::ORG_SCOPE,
                "member_grant",
                &serde_json::to_string(&grant).unwrap(),
            )
            .unwrap();
    }
    let token = wb.mint_account_session(authority, "passkey", 3600).unwrap();
    wb.authenticate_action_context(&token).unwrap()
}

/// Basics, filing into the project's own tracker instead of the learner's.
fn project_basics() -> String {
    include_str!("tutorials/basics.whip").replace(" tutorials", " tasks")
}

/// A project's files belong to its Home, and the Home runs a workflow from them
/// for anyone with access to the project, filing into the project's `tasks`
/// tracker, which every such member reads (DR-0199).
#[test]
fn a_projects_home_owned_files_run_and_file_into_its_tasks_tracker() {
    let (_root, shared, _owner, mut request) = fixture(&project_basics());
    let chat = chat(&shared);
    let mut wb = shared.lock_unpoisoned();
    home_owned(&mut wb, &request.target);
    let person = member(&mut wb, "member-a", Some(DEFAULT_PROJECT));
    let colleague = member(&mut wb, "member-b", Some(DEFAULT_PROJECT));
    let outsider = member(&mut wb, "member-c", None);

    let source = wb
        .chat_workflow_source(&chat, "lessons/hello.whip")
        .unwrap();
    wb.describe_project_workflow(&person, &source, LIMITS)
        .expect("a member reads the project's shared workflow");
    wb.describe_project_workflow(&outsider, &source, LIMITS)
        .expect_err("someone without access to the project does not");

    assert!(wb.ensure_project_tasks_tracker(DEFAULT_PROJECT).unwrap());
    assert!(
        !wb.ensure_project_tasks_tracker(DEFAULT_PROJECT).unwrap(),
        "declared once"
    );
    request.inputs = BTreeMap::from([(
        "learner".into(),
        serde_json::json!({ "authority": "member-b" }),
    )]);
    wb.launch_project_workflow(&person, &request, LIMITS)
        .expect("the Home runs it at a member's request");
    let filed = wb
        .step_project_workflow(&person, &request.project, &request.request_id, LIMITS)
        .unwrap();
    assert!(filed.executed_effect.is_some());

    let assigned = wb
        .read_project_tracker_tasks(&colleague, DEFAULT_PROJECT, "tasks")
        .unwrap();
    assert_eq!(assigned.backlog.issues.len(), 1);
    assert_eq!(
        assigned.backlog.issues[0].title,
        "Create a chat in Personal"
    );
    let backlog = wb
        .read_project_tracker_backlog(&person, DEFAULT_PROJECT, "tasks")
        .unwrap();
    assert_eq!(backlog.issues.len(), 1, "the launcher reads it too");
    assert!(wb
        .read_project_tracker_backlog(&outsider, DEFAULT_PROJECT, "tasks")
        .is_err());
}

/// The project's tracker is the Home's: nobody declares over it, and nobody
/// requests or grants access to it — project access is its only rule.
#[test]
fn the_projects_tasks_tracker_takes_no_grants() {
    let (_root, shared, owner, _request) = fixture(ECHO);
    let mut wb = shared.lock_unpoisoned();
    wb.ensure_project_tasks_tracker(DEFAULT_PROJECT).unwrap();
    let tracker = wb
        .read_project_tracker(
            &owner,
            DEFAULT_PROJECT,
            "tasks",
            crate::project_tracker::TrackerPermission::Contribute,
        )
        .unwrap();
    assert_eq!(
        tracker.resource.resource.owner.as_str(),
        wb.home_id().as_str()
    );
    assert!(wb
        .declare_project_tracker(
            &owner,
            DEFAULT_PROJECT,
            "tasks",
            "mine",
            gaugedesk_core::abac::ResourceAttributes::default(),
        )
        .is_err());
    let person = member(&mut wb, "member-a", None);
    assert!(wb
        .request_project_tracker_access(
            &owner,
            DEFAULT_PROJECT,
            "tasks",
            "share",
            "member-a",
            crate::project_tracker::TrackerPermission::Read,
        )
        .is_err());
    assert!(wb
        .read_project_tracker(
            &person,
            DEFAULT_PROJECT,
            "tasks",
            crate::project_tracker::TrackerPermission::Read,
        )
        .is_err());
}

/// What the Run button's status, a file's dot and its Runs history read: a run
/// of a person's own file shows only to them; once the file is the project's
/// Home-owned material, its runs show to everyone with access (DR-0199).
#[test]
fn runs_of_shared_files_show_to_the_project_and_of_own_files_to_their_launcher() {
    let (_root, shared, owner, request) = fixture(ECHO);
    let chat = chat(&shared);
    let mut wb = shared.lock_unpoisoned();
    let colleague = member(&mut wb, "member-b", Some(DEFAULT_PROJECT));
    let outsider = member(&mut wb, "member-c", None);
    assert!(wb.chat_whip_runs(&owner, &chat, None).unwrap().is_empty());

    wb.launch_project_workflow(&owner, &request, LIMITS)
        .unwrap();
    wb.step_project_workflow(&owner, &request.project, &request.request_id, LIMITS)
        .unwrap();
    let mine = wb.chat_whip_runs(&owner, &chat, None).unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].launched_by, LOCAL_AUTHORITY);
    assert_eq!(mine[0].state, "completed");
    assert!(mine[0].started_at.is_some());
    assert!(
        mine[0].path.starts_with("targets/") && mine[0].path.ends_with("/lessons/hello.whip"),
        "{}",
        mine[0].path
    );
    assert!(
        wb.chat_whip_runs(&colleague, &chat, None)
            .unwrap()
            .is_empty(),
        "a person's own file's runs are theirs"
    );

    home_owned(&mut wb, &request.target);
    let person = member(&mut wb, "member-a", Some(DEFAULT_PROJECT));
    let mut theirs = request.clone();
    theirs.cut = wb
        .chat_workflow_source(&chat, "lessons/hello.whip")
        .unwrap()
        .cut;
    wb.launch_project_workflow(&person, &theirs, LIMITS)
        .unwrap();
    let seen = wb
        .chat_whip_runs(&colleague, &chat, Some("lessons/hello.whip"))
        .unwrap();
    assert_eq!(seen.len(), 2, "the project's file's runs are the project's");
    assert!(seen.iter().any(|run| run.launched_by == "member-a"));
    assert!(
        wb.chat_whip_runs(&colleague, &chat, Some("lessons/other.whip"))
            .unwrap()
            .is_empty(),
        "another file's runs are not this one's"
    );
    assert!(wb.chat_whip_runs(&outsider, &chat, None).is_err());
}
