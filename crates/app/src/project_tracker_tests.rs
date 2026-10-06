use super::*;
use crate::app_support::{LockUnpoisoned, DEFAULT_PROJECT};
use crate::org::{MembershipRecord, MembershipStatus, RecordOp, ORG_ID};

fn member(wb: &mut Workbench, actor: &str, role: &str, status: MembershipStatus) {
    let record = MembershipRecord {
        id: actor.into(),
        op: RecordOp::Upsert,
        org_id: ORG_ID.into(),
        authority: actor.into(),
        email: String::new(),
        role: role.into(),
        status,
        managed_by_scim: false,
        team: None,
    };
    wb.store_mut()
        .append_record(ORG_SCOPE, "membership", &encode(&record).unwrap())
        .unwrap();
}

fn project_grant(wb: &mut Workbench, actor: &str, project: &str, op: RecordOp) {
    let grant = crate::org::MemberGrantRecord {
        id: crate::org::MemberGrantRecord::make_id(actor, project),
        authority: actor.into(),
        project_id: project.into(),
        op,
    };
    wb.store_mut()
        .append_record(ORG_SCOPE, "member_grant", &encode(&grant).unwrap())
        .unwrap();
}

fn context(wb: &mut Workbench, actor: &str, role: &str) -> (AuthenticatedActionContext, String) {
    member(wb, actor, role, MembershipStatus::Active);
    // These resource-sharing fixtures start with explicit project standing.
    project_grant(wb, actor, DEFAULT_PROJECT, RecordOp::Upsert);
    let token = wb.mint_account_session(actor, "passkey", 3600).unwrap();
    (wb.authenticate_action_context(&token).unwrap(), token)
}

#[test]
fn project_standing_fences_home_trackers_resource_grants_and_assignment_recipients() {
    let directory = tempfile::tempdir().unwrap();
    let shared = crate::workbench_state::open_lean_workbench(directory.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let (alice, _) = context(&mut wb, "alice", "owner");
    let (bob, _) = context(&mut wb, "bob", "admin");
    let mut project = wb.library.projects[DEFAULT_PROJECT].clone();
    crate::project_owner::record_owner(&mut project.extra, "alice");
    wb.store_mut()
        .append_record(LIBRARY_SCOPE, "project", &encode(&project).unwrap())
        .unwrap();
    project_grant(&mut wb, "alice", DEFAULT_PROJECT, RecordOp::Tombstone);
    wb.ensure_project_tasks_tracker(DEFAULT_PROJECT).unwrap();
    // A recorded owner needs no redundant project grant; organization rank
    // supplies no access to Home-owned tasks after Bob's grant is removed.
    wb.read_project_tracker(
        &alice,
        DEFAULT_PROJECT,
        PROJECT_TASKS,
        TrackerPermission::Read,
    )
    .unwrap();
    member(&mut wb, "alice", "owner", MembershipStatus::Deprovisioned);
    wb.read_project_tracker(
        &alice,
        DEFAULT_PROJECT,
        PROJECT_TASKS,
        TrackerPermission::Read,
    )
    .expect("the account's own Home tasks do not require directory membership");
    let (_, recipients, _, _) = wb
        .prepare_project_tracker_recipients(&alice, DEFAULT_PROJECT, PROJECT_TASKS)
        .unwrap();
    assert!(recipients.iter().any(|recipient| recipient == "alice"));
    member(&mut wb, "alice", "owner", MembershipStatus::Active);
    project_grant(&mut wb, "bob", DEFAULT_PROJECT, RecordOp::Tombstone);
    assert!(wb
        .read_project_tracker(
            &bob,
            DEFAULT_PROJECT,
            PROJECT_TASKS,
            TrackerPermission::Read
        )
        .is_err());
    wb.declare_project_tracker(
        &alice,
        DEFAULT_PROJECT,
        "private",
        "declare-private",
        ResourceAttributes::default(),
    )
    .unwrap();
    let before = wb.store_ref().scope_high_water_marks().unwrap();
    assert!(wb
        .request_project_tracker_access(
            &alice,
            DEFAULT_PROJECT,
            "private",
            "ungranted-recipient",
            "bob",
            TrackerPermission::Read
        )
        .is_err());
    assert_eq!(wb.store_ref().scope_high_water_marks().unwrap(), before);

    project_grant(&mut wb, "bob", DEFAULT_PROJECT, RecordOp::Upsert);
    let read = wb
        .request_project_tracker_access(
            &alice,
            DEFAULT_PROJECT,
            "private",
            "read-bob",
            "bob",
            TrackerPermission::Read,
        )
        .unwrap();
    wb.decide_project_tracker_access(
        &alice,
        DEFAULT_PROJECT,
        "private",
        "approve-bob",
        &read.id,
        TrackerAccessDecision::Approve,
    )
    .unwrap();
    wb.read_project_tracker(&bob, DEFAULT_PROJECT, "private", TrackerPermission::Read)
        .unwrap();
    let (_, recipients, _, _) = wb
        .prepare_project_tracker_recipients(&alice, DEFAULT_PROJECT, "private")
        .unwrap();
    assert!(recipients.iter().any(|recipient| recipient == "bob"));
    let pending = wb
        .request_project_tracker_access(
            &alice,
            DEFAULT_PROJECT,
            "private",
            "pending-contribution",
            "bob",
            TrackerPermission::Contribute,
        )
        .unwrap();
    let (_, stale) = capture(
        wb.store_ref(),
        wb.home_id(),
        &wb.project_owner_resolver(),
        &alice,
        DEFAULT_PROJECT,
        "private",
        Some("stale-request"),
    )
    .unwrap();

    project_grant(&mut wb, "bob", DEFAULT_PROJECT, RecordOp::Tombstone);
    assert!(wb
        .read_project_tracker(&bob, DEFAULT_PROJECT, "private", TrackerPermission::Read)
        .is_err());
    let (_, recipients, _, _) = wb
        .prepare_project_tracker_recipients(&alice, DEFAULT_PROJECT, "private")
        .unwrap();
    assert!(!recipients.iter().any(|recipient| recipient == "bob"));
    assert!(wb.store_mut().with_dispatch_basis(&stale, || ()).is_err());
    // An outstanding resource request cannot be approved around the new
    // project membership decision, even by the resource's actual owner.
    assert!(wb
        .decide_project_tracker_access(
            &alice,
            DEFAULT_PROJECT,
            "private",
            "approve-bob-again",
            &pending.id,
            TrackerAccessDecision::Approve
        )
        .is_err());

    project_grant(&mut wb, "bob", DEFAULT_PROJECT, RecordOp::Upsert);
    member(&mut wb, "bob", "admin", MembershipStatus::Deprovisioned);
    assert!(wb
        .read_project_tracker(&bob, DEFAULT_PROJECT, "private", TrackerPermission::Read)
        .is_err());
    let (_, recipients, _, _) = wb
        .prepare_project_tracker_recipients(&alice, DEFAULT_PROJECT, "private")
        .unwrap();
    assert!(!recipients.iter().any(|recipient| recipient == "bob"));
}

#[test]
fn tracker_identity_is_workspace_owned_and_does_not_grant_admins_payload_access() {
    let directory = tempfile::tempdir().unwrap();
    let shared = crate::open_workbench(directory.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let (alice, _) = context(&mut wb, "alice", "owner");
    let (bob, _) = context(&mut wb, "bob", "admin");
    let chats = wb.library.chats.len();
    let tracker = wb
        .declare_project_tracker(
            &alice,
            DEFAULT_PROJECT,
            "tutorials",
            "declare",
            ResourceAttributes::default(),
        )
        .unwrap();
    assert_eq!(tracker.resource.resource.owner.as_str(), "alice");
    assert_eq!(
        wb.declare_project_tracker(
            &alice,
            DEFAULT_PROJECT,
            "tutorials",
            "declare",
            ResourceAttributes::default()
        )
        .unwrap(),
        tracker
    );
    assert!(wb
        .declare_project_tracker(
            &bob,
            DEFAULT_PROJECT,
            "tutorials",
            "declare",
            ResourceAttributes::default()
        )
        .is_err());
    assert!(wb
        .read_project_tracker(&bob, DEFAULT_PROJECT, "tutorials", TrackerPermission::Read)
        .is_err());
    assert_eq!(
        wb.read_project_tracker(
            &alice,
            DEFAULT_PROJECT,
            "tutorials",
            TrackerPermission::Contribute
        )
        .unwrap(),
        tracker
    );

    let mut project = wb.library.projects[DEFAULT_PROJECT].clone();
    project.id = "other-project".into();
    crate::project_owner::record_owner(&mut project.extra, "bob");
    project.is_default = false;
    let mut workspace = wb.library.project_collaboration_workspaces[DEFAULT_PROJECT].clone();
    workspace.project_id = project.id.clone();
    workspace.workspace_id = "other-workspace".into();
    wb.store_mut()
        .append_record(LIBRARY_SCOPE, "project", &encode(&project).unwrap())
        .unwrap();
    wb.store_mut()
        .append_record(
            LIBRARY_SCOPE,
            "project_collaboration_workspace",
            &encode(&workspace).unwrap(),
        )
        .unwrap();
    let other = wb
        .declare_project_tracker(
            &bob,
            "other-project",
            "tutorials",
            "declare",
            ResourceAttributes::default(),
        )
        .unwrap();
    assert_ne!(other.resource.resource.id, tracker.resource.resource.id);
    assert!(wb
        .read_project_tracker(
            &alice,
            "other-project",
            "tutorials",
            TrackerPermission::Read
        )
        .is_err());
    assert_eq!(
        wb.library.chats.len(),
        chats,
        "tracker declaration creates no chat"
    );
}

#[test]
fn sharing_uses_existing_access_lifecycle_and_replay_never_revives_revoked_grants() {
    let directory = tempfile::tempdir().unwrap();
    let shared = crate::open_workbench(directory.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let (alice, _) = context(&mut wb, "alice", "owner");
    let (bob, _) = context(&mut wb, "bob", "admin");
    wb.declare_project_tracker(
        &alice,
        DEFAULT_PROJECT,
        "tasks",
        "declare",
        ResourceAttributes::default(),
    )
    .unwrap();
    let read = wb
        .request_project_tracker_access(
            &bob,
            DEFAULT_PROJECT,
            "tasks",
            "read",
            "bob",
            TrackerPermission::Read,
        )
        .unwrap();
    assert_eq!(
        wb.request_project_tracker_access(
            &bob,
            DEFAULT_PROJECT,
            "tasks",
            "read",
            "bob",
            TrackerPermission::Read
        )
        .unwrap(),
        read
    );
    assert!(wb
        .read_project_tracker(&bob, DEFAULT_PROJECT, "tasks", TrackerPermission::Read)
        .is_err());
    assert!(wb
        .decide_project_tracker_access(
            &bob,
            DEFAULT_PROJECT,
            "tasks",
            "self-approve",
            &read.id,
            TrackerAccessDecision::Approve
        )
        .is_err());
    assert_eq!(
        wb.decide_project_tracker_access(
            &alice,
            DEFAULT_PROJECT,
            "tasks",
            "approve-read",
            &read.id,
            TrackerAccessDecision::Approve
        )
        .unwrap(),
        AccessPhase::Granted
    );
    assert!(wb
        .read_project_tracker(&bob, DEFAULT_PROJECT, "tasks", TrackerPermission::Read)
        .is_ok());
    assert!(wb
        .read_project_tracker(
            &bob,
            DEFAULT_PROJECT,
            "tasks",
            TrackerPermission::Contribute
        )
        .is_err());
    let contribute = wb
        .request_project_tracker_access(
            &bob,
            DEFAULT_PROJECT,
            "tasks",
            "contribute",
            "bob",
            TrackerPermission::Contribute,
        )
        .unwrap();
    wb.decide_project_tracker_access(
        &alice,
        DEFAULT_PROJECT,
        "tasks",
        "approve-contribute",
        &contribute.id,
        TrackerAccessDecision::Approve,
    )
    .unwrap();
    assert!(wb
        .read_project_tracker(
            &bob,
            DEFAULT_PROJECT,
            "tasks",
            TrackerPermission::Contribute
        )
        .is_ok());
    wb.decide_project_tracker_access(
        &alice,
        DEFAULT_PROJECT,
        "tasks",
        "revoke-read",
        &read.id,
        TrackerAccessDecision::Revoke,
    )
    .unwrap();
    assert!(wb
        .read_project_tracker(
            &bob,
            DEFAULT_PROJECT,
            "tasks",
            TrackerPermission::Contribute
        )
        .is_err());
    assert_eq!(
        wb.decide_project_tracker_access(
            &alice,
            DEFAULT_PROJECT,
            "tasks",
            "approve-read",
            &read.id,
            TrackerAccessDecision::Approve
        )
        .unwrap(),
        AccessPhase::Revoked
    );
    assert!(wb
        .decide_project_tracker_access(
            &alice,
            DEFAULT_PROJECT,
            "tasks",
            "new-approval-old-basis",
            &read.id,
            TrackerAccessDecision::Approve
        )
        .is_err());
    let fresh = wb
        .request_project_tracker_access(
            &bob,
            DEFAULT_PROJECT,
            "tasks",
            "read-again",
            "bob",
            TrackerPermission::Read,
        )
        .unwrap();
    assert_ne!(fresh.id, read.id);
    wb.decide_project_tracker_access(
        &alice,
        DEFAULT_PROJECT,
        "tasks",
        "approve-fresh",
        &fresh.id,
        TrackerAccessDecision::Approve,
    )
    .unwrap();
    assert!(wb
        .read_project_tracker(
            &bob,
            DEFAULT_PROJECT,
            "tasks",
            TrackerPermission::Contribute
        )
        .is_ok());
}

#[test]
fn registration_reopening_and_purpose_changes_cannot_refresh_owner_access() {
    let directory = tempfile::tempdir().unwrap();
    let shared = crate::open_workbench(directory.path()).unwrap();
    let (token, tracker) = {
        let mut wb = shared.lock_unpoisoned();
        let (alice, token) = context(&mut wb, "alice", "owner");
        let tracker = wb
            .declare_project_tracker(
                &alice,
                DEFAULT_PROJECT,
                "tasks",
                "declare",
                ResourceAttributes::default(),
            )
            .unwrap();
        let scope = registry_scope(DEFAULT_PROJECT, "tasks").unwrap();
        let owner_read = new_basis(
            &scope,
            "alice",
            "declare",
            "alice",
            TrackerPermission::Read,
            None,
        )
        .unwrap();
        wb.decide_project_tracker_access(
            &alice,
            DEFAULT_PROJECT,
            "tasks",
            "revoke-own-read",
            &owner_read.id,
            TrackerAccessDecision::Revoke,
        )
        .unwrap();
        (token, tracker)
    };
    drop(shared);
    let reopened = crate::open_workbench(directory.path()).unwrap();
    let mut wb = reopened.lock_unpoisoned();
    let alice = wb.authenticate_action_context(&token).unwrap();
    assert_eq!(
        wb.declare_project_tracker(
            &alice,
            DEFAULT_PROJECT,
            "tasks",
            "declare",
            ResourceAttributes::default()
        )
        .unwrap(),
        tracker
    );
    assert!(wb
        .read_project_tracker(&alice, DEFAULT_PROJECT, "tasks", TrackerPermission::Read)
        .is_err());
    let fresh = wb
        .request_project_tracker_access(
            &alice,
            DEFAULT_PROJECT,
            "tasks",
            "own-read",
            "alice",
            TrackerPermission::Read,
        )
        .unwrap();
    wb.decide_project_tracker_access(
        &alice,
        DEFAULT_PROJECT,
        "tasks",
        "approve-own",
        &fresh.id,
        TrackerAccessDecision::Approve,
    )
    .unwrap();
    assert!(wb
        .read_project_tracker(
            &alice,
            DEFAULT_PROJECT,
            "tasks",
            TrackerPermission::Contribute
        )
        .is_ok());
    let mut project = wb.library.projects[DEFAULT_PROJECT].clone();
    project.run_purpose = Some("new-purpose".into());
    wb.store_mut()
        .append_record(LIBRARY_SCOPE, "project", &encode(&project).unwrap())
        .unwrap();
    assert!(wb
        .read_project_tracker(&alice, DEFAULT_PROJECT, "tasks", TrackerPermission::Read)
        .is_err());
}

#[test]
fn authority_changes_and_handoff_pause_prevent_tracker_writes() {
    use gaugedesk_core::handoff::HandoffEvent;
    let directory = tempfile::tempdir().unwrap();
    let shared = crate::open_workbench(directory.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let (alice, _) = context(&mut wb, "alice", "owner");
    let (bob, _) = context(&mut wb, "bob", "admin");
    wb.declare_project_tracker(
        &alice,
        DEFAULT_PROJECT,
        "tasks",
        "declare",
        ResourceAttributes::default(),
    )
    .unwrap();
    let (_, stale) = capture(
        wb.store_ref(),
        wb.home_id(),
        &wb.project_owner_resolver(),
        &alice,
        DEFAULT_PROJECT,
        "tasks",
        Some("stale"),
    )
    .unwrap();
    let grant = wb
        .request_project_tracker_access(
            &bob,
            DEFAULT_PROJECT,
            "tasks",
            "read",
            "bob",
            TrackerPermission::Read,
        )
        .unwrap();
    let before = wb.store_ref().scope_high_water_marks().unwrap();
    let scope = registry_scope(DEFAULT_PROJECT, "tasks").unwrap();
    assert!(commit(
        wb.store_mut(),
        &stale,
        &command_scope(&scope, "alice"),
        "stale",
        "{}",
        &[]
    )
    .is_err());
    assert_eq!(wb.store_ref().scope_high_water_marks().unwrap(), before);
    let handoff = crate::federation::handoff_scope(DEFAULT_PROJECT);
    wb.store_mut()
        .append_record(
            &handoff,
            "event",
            &encode(&HandoffEvent::HandoffOffered).unwrap(),
        )
        .unwrap();
    assert!(wb
        .declare_project_tracker(
            &alice,
            DEFAULT_PROJECT,
            "new",
            "new",
            ResourceAttributes::default()
        )
        .is_err());
    assert!(wb
        .request_project_tracker_access(
            &bob,
            DEFAULT_PROJECT,
            "tasks",
            "another",
            "bob",
            TrackerPermission::Read
        )
        .is_err());
    assert!(wb
        .decide_project_tracker_access(
            &alice,
            DEFAULT_PROJECT,
            "tasks",
            "approve",
            &grant.id,
            TrackerAccessDecision::Approve
        )
        .is_err());
    assert!(wb
        .read_project_tracker(&alice, DEFAULT_PROJECT, "tasks", TrackerPermission::Read)
        .is_ok());
    wb.store_mut()
        .append_record(
            &handoff,
            "event",
            &encode(&HandoffEvent::HandoffAborted).unwrap(),
        )
        .unwrap();
    wb.decide_project_tracker_access(
        &alice,
        DEFAULT_PROJECT,
        "tasks",
        "approve",
        &grant.id,
        TrackerAccessDecision::Approve,
    )
    .unwrap();
    member(&mut wb, "bob", "admin", MembershipStatus::Deprovisioned);
    assert!(wb
        .read_project_tracker(&bob, DEFAULT_PROJECT, "tasks", TrackerPermission::Read)
        .is_err());
    let mut project = wb.library.projects[DEFAULT_PROJECT].clone();
    project.home_id = HomeId::new("another-home");
    wb.store_mut()
        .append_record(LIBRARY_SCOPE, "project", &encode(&project).unwrap())
        .unwrap();
    assert!(wb
        .read_project_tracker(&alice, DEFAULT_PROJECT, "tasks", TrackerPermission::Read)
        .is_err());
}

#[test]
fn unavailable_access_history_cannot_be_replaced_by_fresh_authority() {
    struct MissingAccess;
    impl gaugedesk_store::ContentCodec for MissingAccess {
        fn encode(&self, _: &str, _: &str, payload: &str) -> Result<String, String> {
            Ok(payload.into())
        }
        fn decode(&self, _: &str, kind: &str, payload: &str) -> Option<String> {
            (kind != AccessState::KIND).then(|| payload.into())
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let shared = crate::open_workbench(directory.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let (alice, _) = context(&mut wb, "alice", "owner");
    wb.declare_project_tracker(
        &alice,
        DEFAULT_PROJECT,
        "tasks",
        "declare",
        ResourceAttributes::default(),
    )
    .unwrap();
    wb.store = wb
        .store_ref()
        .sibling()
        .unwrap()
        .with_codec(std::sync::Arc::new(MissingAccess));
    assert!(wb
        .read_project_tracker(&alice, DEFAULT_PROJECT, "tasks", TrackerPermission::Read)
        .is_err());
    assert!(wb
        .declare_project_tracker(
            &alice,
            DEFAULT_PROJECT,
            "tasks",
            "again",
            ResourceAttributes::default()
        )
        .is_err());
}

#[test]
fn a_retained_declaration_receipt_cannot_replace_missing_resource_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let shared = crate::open_workbench(directory.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let (alice, _) = context(&mut wb, "alice", "owner");
    wb.declare_project_tracker(
        &alice,
        DEFAULT_PROJECT,
        "tasks",
        "declare",
        ResourceAttributes::default(),
    )
    .unwrap();
    let scope = registry_scope(DEFAULT_PROJECT, "tasks").unwrap();
    let commands = command_scope(&scope, "alice");
    // Simulate an incomplete relocation retaining the real receipt and current
    // authentication but losing the definition and its access scopes.
    let archive = wb
        .store_ref()
        .export_command_scopes(|s| !s.starts_with(&scope) || s == commands)
        .unwrap();
    let mut receiving = Store::open_in_memory().unwrap();
    receiving.import_command_scopes(&archive, |_| true).unwrap();
    wb.store = receiving;
    assert!(wb
        .store_ref()
        .committed_record_snapshot(&commands, "declare")
        .unwrap()
        .is_some());
    assert!(wb
        .declare_project_tracker(
            &alice,
            DEFAULT_PROJECT,
            "tasks",
            "declare",
            ResourceAttributes::default(),
        )
        .is_err());
    assert!(wb.store_ref().retained_events(&scope).unwrap().is_empty());
}

#[test]
fn new_access_scopes_are_fenced_and_orphaned_evidence_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let shared = crate::open_workbench(directory.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let (alice, _) = context(&mut wb, "alice", "owner");
    let scope = registry_scope(DEFAULT_PROJECT, "tasks").unwrap();
    let (_, captured) = capture(
        wb.store_ref(),
        wb.home_id(),
        &wb.project_owner_resolver(),
        &alice,
        DEFAULT_PROJECT,
        "tasks",
        Some("declare"),
    )
    .unwrap();
    let grant = new_basis(
        &scope,
        "alice",
        "declare",
        "alice",
        TrackerPermission::Read,
        None,
    )
    .unwrap();
    wb.store_mut()
        .append_record(
            &access_scope(&scope, &grant.id),
            AccessState::KIND,
            &encode(&resource_access::AccessEvent::Granted).unwrap(),
        )
        .unwrap();
    assert!(commit(
        wb.store_mut(),
        &captured,
        &command_scope(&scope, "alice"),
        "declare",
        "uncommitted",
        &[]
    )
    .is_err());
    assert!(wb
        .declare_project_tracker(
            &alice,
            DEFAULT_PROJECT,
            "tasks",
            "declare",
            ResourceAttributes::default(),
        )
        .is_err());
    assert!(wb.store_ref().retained_events(&scope).unwrap().is_empty());
}

#[test]
fn a_granted_marker_without_approvals_cannot_confer_access() {
    let directory = tempfile::tempdir().unwrap();
    let shared = crate::open_workbench(directory.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let (alice, _) = context(&mut wb, "alice", "owner");
    let (bob, _) = context(&mut wb, "bob", "admin");
    wb.declare_project_tracker(
        &alice,
        DEFAULT_PROJECT,
        "tasks",
        "declare",
        ResourceAttributes::default(),
    )
    .unwrap();
    let grant = wb
        .request_project_tracker_access(
            &bob,
            DEFAULT_PROJECT,
            "tasks",
            "read",
            "bob",
            TrackerPermission::Read,
        )
        .unwrap();
    let scope = registry_scope(DEFAULT_PROJECT, "tasks").unwrap();
    // Corrupt retained evidence: a grant marker with no owner's approval.
    wb.store_mut()
        .append_record(
            &access_scope(&scope, &grant.id),
            AccessState::KIND,
            &encode(&resource_access::AccessEvent::Granted).unwrap(),
        )
        .unwrap();
    assert!(wb
        .read_project_tracker(&bob, DEFAULT_PROJECT, "tasks", TrackerPermission::Read)
        .is_err());
}

#[test]
fn access_evidence_without_its_original_receipt_cannot_be_reissued() {
    let directory = tempfile::tempdir().unwrap();
    let shared = crate::open_workbench(directory.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let (alice, _) = context(&mut wb, "alice", "owner");
    wb.declare_project_tracker(
        &alice,
        DEFAULT_PROJECT,
        "tasks",
        "declare",
        ResourceAttributes::default(),
    )
    .unwrap();
    let scope = registry_scope(DEFAULT_PROJECT, "tasks").unwrap();
    let commands = command_scope(&scope, "alice");
    let archive = wb
        .store_ref()
        .export_command_scopes(|s| s != commands)
        .unwrap();
    let mut receiving = Store::open_in_memory().unwrap();
    receiving.import_command_scopes(&archive, |_| true).unwrap();
    wb.store = receiving;
    assert!(wb
        .declare_project_tracker(
            &alice,
            DEFAULT_PROJECT,
            "tasks",
            "declare",
            ResourceAttributes::default(),
        )
        .is_err());
    assert!(wb
        .store_ref()
        .committed_record_snapshot(&commands, "declare")
        .unwrap()
        .is_none());
}
#[test]
fn a_new_home_owned_tracker_reads_as_empty_without_creating_native_storage() {
    let directory = tempfile::tempdir().unwrap();
    let shared = crate::open_workbench(directory.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let (owner, _) = context(&mut wb, "owner-account", "owner");
    wb.ensure_project_tasks_tracker(DEFAULT_PROJECT).unwrap();
    let tracker = wb
        .read_project_tracker(
            &owner,
            DEFAULT_PROJECT,
            PROJECT_TASKS,
            TrackerPermission::Read,
        )
        .unwrap();
    let storage = wb.workflow_storage(&tracker.workspace_id).unwrap();
    assert_eq!(
        storage.protection_mode(&tracker.workspace_id).unwrap(),
        None
    );

    let backlog = wb
        .read_project_tracker_backlog(&owner, DEFAULT_PROJECT, PROJECT_TASKS)
        .unwrap();
    assert!(backlog.issues.is_empty());
    assert_eq!(backlog.tracker.project_id, DEFAULT_PROJECT);
    assert_eq!(
        storage.protection_mode(&tracker.workspace_id).unwrap(),
        None
    );
}

#[test]
fn desktop_account_and_local_turns_bind_the_real_task_filer() {
    use gaugedesk_harness::{
        EgressGate, Harness, HarnessFactory, HarnessSpec, ImageContent, Observation, TaskFiler,
        TurnOutcome,
    };
    use std::{
        io,
        sync::{Arc, Mutex},
    };

    struct FilingHarness {
        actor: String,
        filer: Option<Arc<dyn TaskFiler>>,
        observed: Arc<Mutex<Option<(String, String)>>>,
    }
    impl Harness for FilingHarness {
        fn bind_authenticated_actor(&mut self, actor: &str) {
            self.actor = actor.into();
        }
        fn bind_task_filer(&mut self, filer: Option<Arc<dyn TaskFiler>>) {
            self.filer = filer;
        }
        fn run_turn(
            &mut self,
            _gate: &dyn EgressGate,
            _prompt: &str,
            _images: &[ImageContent],
            _sink: &mut dyn FnMut(&Observation),
        ) -> io::Result<TurnOutcome> {
            let id = self
                .filer
                .as_ref()
                .ok_or_else(|| io::Error::other("task filer absent"))?
                .file_task("test-call", "Test task\nVerify the app works", None)
                .map_err(io::Error::other)?;
            *self.observed.lock().unwrap() = Some((self.actor.clone(), id.clone()));
            Ok(TurnOutcome {
                assistant_text: id,
                ..TurnOutcome::default()
            })
        }
    }
    struct FilingFactory(Arc<Mutex<Option<(String, String)>>>);
    impl HarnessFactory for FilingFactory {
        fn kind(&self) -> &'static str {
            "whip"
        }
        fn create(&self, _: &HarnessSpec) -> io::Result<Box<dyn Harness>> {
            Ok(Box::new(FilingHarness {
                actor: String::new(),
                filer: None,
                observed: self.0.clone(),
            }))
        }
        fn reuse_across_turns(&self) -> bool {
            false
        }
        fn credential_status(
            &self,
            _: &str,
            _: Option<&dyn gaugedesk_harness::CredentialCapability>,
        ) -> gaugedesk_harness::CredentialProbe {
            gaugedesk_harness::CredentialProbe::Ready
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let shared = crate::open_workbench(directory.path()).unwrap();
    let (token, context, turn) = {
        let mut wb = shared.lock_unpoisoned();
        wb.create_default_engagement("chat-task".into(), "Task chat".into())
            .unwrap_or_else(|_| panic!("create task chat"));
        wb.ensure_project_tasks_tracker(DEFAULT_PROJECT).unwrap();
        let (_, token) = context(&mut wb, "signed-in-owner", "owner");
        let context = wb.authenticate_action_context(&token).unwrap();
        let turn = wb.engagement_task_context("chat-task").unwrap();
        (token, context, turn)
    };
    let observed = Arc::new(Mutex::new(None));
    // The fake adapter does not publish WhippleScript's durable turn boundary,
    // so the turn cannot settle after the tool call. The filing receipt and
    // current tracker read below prove the admission path under test.
    let _ = crate::engine::run_engagement_turn(
        &shared,
        "chat-task",
        &turn.worktree,
        &turn.sender,
        crate::engine::EngagementTurnInput {
            task: "file the task",
            images: &[],
            mode: turn.mode,
            authenticated_actor: None,
            authenticated_context: None,
            client_build: None,
            contribution_by: None,
            account_scope: crate::account::ACCOUNT_SCOPE,
            tenant_scope: crate::org::ORG_SCOPE,
            account_bearer: Some(&token),
            local_operator: false,
            runtime_command_id: None,
            original_http_command: None,
            harness_factory: Some(crate::engine::TurnHarnessFactory::Custom(Arc::new(
                FilingFactory(observed.clone()),
            ))),
        },
    );
    let (actor, id) = observed.lock().unwrap().clone().unwrap();
    assert_eq!(actor, "signed-in-owner");
    let wb = shared.lock_unpoisoned();
    let backlog = wb
        .read_project_tracker_backlog(&context, DEFAULT_PROJECT, PROJECT_TASKS)
        .unwrap();
    assert_eq!(backlog.issues[0].id, id);
    assert_eq!(backlog.issues[0].title, "Test task");
    assert_eq!(backlog.issues[0].assigned_to, None);

    drop(wb);
    let local_turn = {
        let mut wb = shared.lock_unpoisoned();
        wb.create_default_engagement("chat-local-task".into(), "Local task chat".into())
            .unwrap_or_else(|_| panic!("create local task chat"));
        wb.engagement_task_context("chat-local-task").unwrap()
    };
    let local_observed = Arc::new(Mutex::new(None));
    let _ = crate::engine::run_engagement_turn(
        &shared,
        "chat-local-task",
        &local_turn.worktree,
        &local_turn.sender,
        crate::engine::EngagementTurnInput {
            task: "file the local task",
            images: &[],
            mode: local_turn.mode,
            authenticated_actor: None,
            authenticated_context: None,
            client_build: None,
            contribution_by: None,
            account_scope: crate::account::ACCOUNT_SCOPE,
            tenant_scope: crate::org::ORG_SCOPE,
            account_bearer: None,
            local_operator: true,
            runtime_command_id: None,
            original_http_command: None,
            harness_factory: Some(crate::engine::TurnHarnessFactory::Custom(Arc::new(
                FilingFactory(local_observed.clone()),
            ))),
        },
    );
    let (actor, id) = local_observed.lock().unwrap().clone().unwrap();
    assert_eq!(actor, crate::LOCAL_AUTHORITY);
    let wb = shared.lock_unpoisoned();
    let local = wb.local_personal_tracker_context(DEFAULT_PROJECT).unwrap();
    let backlog = wb
        .read_project_tracker_backlog(&local, DEFAULT_PROJECT, PROJECT_TASKS)
        .unwrap();
    assert!(backlog
        .issues
        .iter()
        .any(|issue| issue.id == id && issue.assigned_to.is_none()));
}

#[test]
fn prepared_tracker_authority_fences_the_actual_account_device() {
    let root = tempfile::tempdir().unwrap();
    let shared = crate::workbench_state::open_lean_workbench(root.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let (alice, token) = context(&mut wb, "alice", "owner");
    wb.ensure_project_tasks_tracker(DEFAULT_PROJECT).unwrap();
    let scope = crate::account::account_scope("alice");
    let mut device = crate::account::DeviceRecord {
        id: "tracker-device".into(),
        op: crate::account::RecordOp::Upsert,
        label: "Tracker fixture".into(),
        kind: crate::account::DeviceKind::Computer,
        subkey_pubkey: "fixture-key".into(),
        status: crate::account::DeviceStatus::Active,
        enrolled_at: 1,
    };
    wb.upsert_account_device_in(&scope, &device).unwrap();
    assert!(wb.bind_account_session_device(
        &crate::account_session::session_id(&token),
        "alice",
        &device.id
    ));
    let (_, prepared) = capture(
        wb.store_ref(),
        wb.home_id(),
        &wb.project_owner_resolver(),
        &alice,
        DEFAULT_PROJECT,
        PROJECT_TASKS,
        None,
    )
    .unwrap();
    assert!(wb.store_mut().with_dispatch_basis(&prepared, || ()).is_ok());
    let before = wb.store_ref().scope_high_water_marks().unwrap();
    device.status = crate::account::DeviceStatus::Revoked;
    wb.upsert_account_device_in(&scope, &device).unwrap();
    let after = wb.store_ref().scope_high_water_marks().unwrap();
    assert_eq!(
        before.get(crate::account_auth::ACCOUNT_AUTH_SCOPE),
        after.get(crate::account_auth::ACCOUNT_AUTH_SCOPE)
    );
    assert!(wb.account_sessions().resolve_now(&token).is_some());
    assert!(wb
        .read_project_tracker_backlog(&alice, DEFAULT_PROJECT, PROJECT_TASKS)
        .is_err());
    assert!(wb
        .store_mut()
        .with_dispatch_basis(&prepared, || panic!(
            "revoked device published prepared tracker work"
        ))
        .is_err());
}
