use super::*;
use crate::{at_rest::LoopbackKeyWrap, LockUnpoisoned, DEFAULT_PROJECT, LOCAL_AUTHORITY};
use gaugedesk_core::abac::ResourceAttributes;
use whipplescript_store::RuntimeStore;

const ECHO: &str = r#"workflow Greeting(learner: Learner) -> string
class Learner { authority string }
rule greet
  when Learner as learner
=> { complete result learner.authority }
"#;
const LIMITS: ProjectWorkflowLimits = ProjectWorkflowLimits {
    source_bytes: 256 * 1024,
    input_bytes: 64 * 1024,
};
fn open(root: &std::path::Path) -> crate::SharedWorkbench {
    // Lean: a project workflow runs in the Personal project's target and reads
    // neither the archetype library nor the onboarding tracker
    // (`StartupSeed::lean`).
    let shared = crate::workbench_state::open_lean_workbench_with_content_keywrap(root, |_| {
        Ok(Box::new(LoopbackKeyWrap::new([37; 32])))
    })
    .unwrap();
    // The launcher's session is open, as it is when a route serves them,
    // including on a reopened workbench; unattended steps still act only
    // under their delegation.
    shared
        .lock_unpoisoned()
        .hold_session_for_tests(DEFAULT_PROJECT);
    shared
}
fn fixture(
    source: &str,
) -> (
    tempfile::TempDir,
    crate::SharedWorkbench,
    AuthenticatedActionContext,
    ProjectWorkflowLaunch,
) {
    let root = tempfile::tempdir().unwrap();
    let shared = open(root.path());
    let mut wb = shared.lock_unpoisoned();
    let actor = LOCAL_AUTHORITY;
    let membership = crate::org::MembershipRecord {
        id: actor.into(),
        op: crate::org::RecordOp::Upsert,
        org_id: crate::org::ORG_ID.into(),
        authority: actor.into(),
        email: String::new(),
        role: "owner".into(),
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
    let token = wb.mint_account_session(actor, "passkey", 3600).unwrap();
    let context = wb.authenticate_action_context(&token).unwrap();
    let target = crate::library_state::managed_project_target_id(DEFAULT_PROJECT);
    // This authored source belongs to the human. Legacy default target records
    // name the Home as content owner; a separate refusal test preserves that
    // compartment instead of silently laundering it into a human-owned tracker.
    let mut target_record = wb.library.work_targets[&target].clone();
    target_record.authority = actor.into();
    target_record.parties = vec![actor.into()];
    wb.store_mut()
        .append_record(
            crate::library::LIBRARY_SCOPE,
            "work_target",
            &serde_json::to_string(&target_record).unwrap(),
        )
        .unwrap();
    wb.rebuild_library();
    let workspace = wb.targets.get(&target).unwrap();
    workspace
        .seed_main(&[("lessons/hello.whip", source)])
        .unwrap();
    let cut = workspace.current_main_cut().unwrap().unwrap();
    let request = ProjectWorkflowLaunch {
        project: DEFAULT_PROJECT.into(),
        target,
        path: "lessons/hello.whip".into(),
        cut,
        request_id: "first".into(),
        inputs: BTreeMap::from([("learner".into(), serde_json::json!({"authority": actor}))]),
    };
    drop(wb);
    (root, shared, context, request)
}
fn project_grant(wb: &mut Workbench, actor: &str, project: &str) {
    let grant = crate::org::MemberGrantRecord {
        id: crate::org::MemberGrantRecord::make_id(actor, project),
        authority: actor.into(),
        project_id: project.into(),
        op: crate::org::RecordOp::Upsert,
    };
    wb.store_mut()
        .append_record(
            crate::org::ORG_SCOPE,
            "member_grant",
            &serde_json::to_string(&grant).unwrap(),
        )
        .unwrap();
}
fn stores(
    wb: &Workbench,
    invocation: &ProjectWorkflowInvocation,
) -> gaugedesk_workspace::NativeWorkflowStores {
    let key = wb
        .content_vault
        .as_ref()
        .unwrap()
        .prepare_scope_key(&content_scope(&invocation.project).unwrap())
        .unwrap();
    let protection = gaugedesk_workspace::WorkflowProtection::new(
        &invocation.workspace,
        std::sync::Arc::new(key),
    )
    .unwrap();
    wb.collaboration_workspaces[&invocation.workspace]
        .native_workflow_storage()
        .unwrap()
        .open_existing_protected(&protection)
        .unwrap()
}

#[test]
fn account_owned_workflow_does_not_require_organization_membership() {
    let (_root, shared, context, request) = fixture(ECHO);
    let mut wb = shared.lock_unpoisoned();
    let mut project = wb.library.projects[DEFAULT_PROJECT].clone();
    crate::project_owner::record_owner(&mut project.extra, context.actor().as_str());
    wb.store_mut()
        .append_record(
            crate::library::LIBRARY_SCOPE,
            "project",
            &serde_json::to_string(&project).unwrap(),
        )
        .unwrap();
    let mut member =
        crate::org::Org::rebuild(wb.store_ref()).unwrap().members[context.actor().as_str()].clone();
    member.status = crate::org::MembershipStatus::Deprovisioned;
    wb.store_mut()
        .append_record(
            crate::org::ORG_SCOPE,
            "membership",
            &serde_json::to_string(&member).unwrap(),
        )
        .unwrap();
    wb.rebuild_library();
    assert!(crate::org::Org::rebuild(wb.store_ref())
        .unwrap()
        .role_of(context.actor().as_str())
        .is_none());
    // Project ownership supplies no additional source clearance. The default
    // regulated source is still refused when the directory supplies no role.
    assert_eq!(
        wb.launch_project_workflow(&context, &request, LIMITS)
            .unwrap_err(),
        "workflow source exceeds actor clearance"
    );
    let mut target = wb.library.work_targets[&request.target].clone();
    target.attributes.classification = gaugedesk_core::abac::Classification::Public;
    wb.store_mut()
        .append_record(
            crate::library::LIBRARY_SCOPE,
            "work_target",
            &serde_json::to_string(&target).unwrap(),
        )
        .unwrap();
    wb.launch_project_workflow(&context, &request, LIMITS)
        .expect("an account's own project does not depend on organization membership");
}

#[test]
fn ordinary_folder_launch_retains_source_inputs_and_one_native_root_across_restart() {
    let (root, shared, context, mut request) = fixture(ECHO);
    let mut wb = shared.lock_unpoisoned();
    let chats = wb.library.chats.len();
    let original = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    let (project_authority, project_key) = wb.project_authority_identity(DEFAULT_PROJECT).unwrap();
    assert_eq!(original.command.issuer, project_authority.as_str());
    assert_ne!(project_key, wb.governance_public_key());
    let identity = crate::action_policy::ActionPolicyIdentity {
        issuer: original.command.issuer.clone(),
        scope: original.command.scope.clone(),
        request_id: original.command.request_id.clone(),
    };
    let project_root =
        gaugedesk_whip_runtime::GovernanceRootVerifier::new(project_authority.clone(), project_key);
    assert!(crate::action_policy::load_project_action_policy(
        wb.store_ref(),
        DEFAULT_PROJECT,
        &identity,
        &original.command.policy,
        &project_root,
    )
    .is_ok());
    let host_root = gaugedesk_whip_runtime::GovernanceRootVerifier::new(
        project_authority,
        wb.governance_public_key(),
    );
    assert!(crate::action_policy::load_project_action_policy(
        wb.store_ref(),
        DEFAULT_PROJECT,
        &identity,
        &original.command.policy,
        &host_root,
    )
    .is_err());
    assert_eq!(wb.library.chats.len(), chats);
    assert_eq!(original.command.provenance.initiator, LOCAL_AUTHORITY);
    assert_eq!(original.command.provenance.origin, "folder.launch");
    assert!(original.command.provenance.causes.is_empty());
    assert_eq!(
        original.command.instance_ref().unwrap(),
        original.admission.instance_ref
    );
    let events = stores(&wb, &original)
        .runtime
        .list_events(&original.admission.instance_ref)
        .unwrap();
    assert!(!events.is_empty());
    let replay = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    assert_eq!(original.command, replay.command);
    assert_eq!(original.admission, replay.admission);
    assert_eq!(
        stores(&wb, &original)
            .runtime
            .list_events(&original.admission.instance_ref)
            .unwrap(),
        events
    );
    request.inputs.insert(
        "learner".into(),
        serde_json::json!({"authority": "someone-else"}),
    );
    assert!(wb
        .launch_project_workflow(&context, &request, LIMITS)
        .is_err());
    wb.targets[&request.target]
        .seed_main(&[("lessons/hello.whip", &ECHO.replace("Greeting", "Changed"))])
        .unwrap();
    drop(wb);
    drop(shared);
    let reopened = open(root.path());
    let mut wb = reopened.lock_unpoisoned();
    let resumed = wb
        .resume_project_workflow(&context, DEFAULT_PROJECT, "first", LIMITS)
        .unwrap();
    assert_eq!(resumed.command, original.command);
    assert_eq!(resumed.admission, original.admission);
    assert_eq!(
        stores(&wb, &resumed)
            .runtime
            .list_events(&resumed.admission.instance_ref)
            .unwrap(),
        events
    );
    request.request_id = "second".into();
    request.cut = wb.targets[&request.target]
        .current_main_cut()
        .unwrap()
        .unwrap();
    let another = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    assert_ne!(
        another.admission.instance_ref,
        original.admission.instance_ref
    );
    assert_ne!(
        another.command.program_version_ref,
        original.command.program_version_ref
    );
}

#[test]
fn missing_project_signing_custody_stops_workflow_use_without_recreating_keys() {
    let (root, shared, context, request) = fixture(ECHO);
    let mut wb = shared.lock_unpoisoned();
    let original = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    let before = stores(&wb, &original)
        .runtime
        .list_events(&original.admission.instance_ref)
        .unwrap();
    let retained = wb
        .store_ref()
        .project_authority_key(DEFAULT_PROJECT)
        .unwrap()
        .unwrap();
    let path = root
        .path()
        .join("content-keys/projects")
        .join(format!("{}.key", crate::org::sha256_hex(DEFAULT_PROJECT)));
    std::fs::remove_file(&path).unwrap();
    assert!(wb
        .resume_project_workflow(&context, DEFAULT_PROJECT, "first", LIMITS)
        .is_err());
    assert!(!path.exists());
    assert!(
        wb.store_ref()
            .project_authority_key(DEFAULT_PROJECT)
            .unwrap()
            .unwrap()
            == retained
    );
    assert_eq!(
        stores(&wb, &original)
            .runtime
            .list_events(&original.admission.instance_ref)
            .unwrap(),
        before
    );
}

#[test]
fn basics_uses_the_same_launcher_and_requires_its_existing_tracker_grant() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    assert!(wb
        .launch_project_workflow(&context, &request, LIMITS)
        .is_err());
    wb.declare_project_tracker(
        &context,
        DEFAULT_PROJECT,
        "tasks",
        "declare",
        ResourceAttributes::default(),
    )
    .unwrap();
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    assert_eq!(
        invocation.command.resources["tasks"]
            .resource
            .selector
            .as_deref(),
        Some("tasks")
    );
    let tracker = wb
        .read_project_tracker(
            &context,
            DEFAULT_PROJECT,
            "tasks",
            crate::project_tracker::TrackerPermission::Read,
        )
        .unwrap();
    assert_eq!(
        invocation.command.resources["tasks"].resource.handle,
        tracker.resource.resource.id.as_str()
    );
    assert_eq!(invocation.workspace, tracker.workspace_id);
}

#[test]
fn failed_native_acknowledgment_recovers_the_original_instance() {
    let (_root, shared, context, request) = fixture(ECHO);
    let mut wb = shared.lock_unpoisoned();
    let scope = request_scope(DEFAULT_PROJECT, LOCAL_AUTHORITY, "first").unwrap();
    let conn = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_ack BEFORE INSERT ON command_receipts WHEN NEW.scope_id LIKE '%::runtime-admission' BEGIN SELECT RAISE(ABORT, 'ack fault'); END;").unwrap();
    assert!(wb
        .launch_project_workflow(&context, &request, LIMITS)
        .is_err());
    let command = wb
        .store_ref()
        .fold::<ProductActionAdmission>(&scope)
        .unwrap()
        .command
        .unwrap();
    assert!(wb
        .store_mut()
        .committed_dispatch::<ProductActionAdmission>(&scope, "first")
        .unwrap()
        .is_some());
    conn.execute_batch("DROP TRIGGER reject_ack").unwrap();
    let recovered = wb
        .resume_project_workflow(&context, DEFAULT_PROJECT, "first", LIMITS)
        .unwrap();
    assert_eq!(recovered.command, command);
    assert_eq!(
        recovered.admission.instance_ref,
        command.instance_ref().unwrap()
    );
}

#[test]
fn source_scope_budget_and_erasure_refuse_without_another_admission() {
    let (_root, shared, context, mut request) = fixture(ECHO);
    let mut wb = shared.lock_unpoisoned();
    assert!(wb
        .launch_project_workflow(
            &context,
            &request,
            ProjectWorkflowLimits {
                source_bytes: 2,
                ..LIMITS
            }
        )
        .is_err());
    request.path = "../outside.whip".into();
    assert!(wb
        .launch_project_workflow(&context, &request, LIMITS)
        .is_err());
    request.path = "lessons/hello.whip".into();
    let first = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    wb.content_vault
        .as_ref()
        .unwrap()
        .erase_scope_key(&content_scope(DEFAULT_PROJECT).unwrap())
        .unwrap();
    assert!(wb
        .resume_project_workflow(&context, DEFAULT_PROJECT, "first", LIMITS)
        .is_err());
    assert_eq!(
        wb.store_ref()
            .fold::<ProductActionAdmission>(&first.product_scope)
            .unwrap()
            .command,
        Some(first.command)
    );
}

#[test]
fn source_ownership_is_not_discarded_when_filing_into_another_party_tracker() {
    let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
    let mut wb = shared.lock_unpoisoned();
    wb.declare_project_tracker(
        &context,
        DEFAULT_PROJECT,
        "tasks",
        "declare",
        ResourceAttributes::default(),
    )
    .unwrap();
    let mut record = wb.library.work_targets[&request.target].clone();
    record.authority = wb.home_id().as_str().into();
    record.parties = vec![record.authority.clone(), LOCAL_AUTHORITY.into()];
    wb.store_mut()
        .append_record(
            crate::library::LIBRARY_SCOPE,
            "work_target",
            &serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
    let error = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap_err();
    assert_eq!(error, "workflow source cannot flow to this tracker");
    let scope = request_scope(DEFAULT_PROJECT, LOCAL_AUTHORITY, "first").unwrap();
    assert!(wb
        .store_ref()
        .fold::<ProductActionAdmission>(&scope)
        .unwrap()
        .command
        .is_none());
}

#[test]
fn project_administration_is_not_a_source_party_grant() {
    let (_root, shared, context, request) = fixture(ECHO);
    let mut wb = shared.lock_unpoisoned();
    let mut target = wb.library.work_targets[&request.target].clone();
    target.authority = "another-party".into();
    target.parties = vec!["another-party".into()];
    wb.store_mut()
        .append_record(
            crate::library::LIBRARY_SCOPE,
            "work_target",
            &serde_json::to_string(&target).unwrap(),
        )
        .unwrap();
    assert!(wb
        .launch_project_workflow(&context, &request, LIMITS)
        .is_err());
    let scope = request_scope(DEFAULT_PROJECT, LOCAL_AUTHORITY, "first").unwrap();
    assert!(wb
        .store_ref()
        .fold::<ProductActionAdmission>(&scope)
        .unwrap()
        .command
        .is_none());
}

#[test]
fn two_clients_share_one_request_and_revocation_stops_resume() {
    let (root, shared, context, request) = fixture(ECHO);
    {
        let mut wb = shared.lock_unpoisoned();
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
    }
    let second = open(root.path());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let run = |wb: crate::SharedWorkbench| {
        let barrier = barrier.clone();
        let context = context.clone();
        let request = request.clone();
        std::thread::spawn(move || {
            barrier.wait();
            wb.lock_unpoisoned()
                .launch_project_workflow(&context, &request, LIMITS)
        })
    };
    let first = run(shared.clone());
    let other = run(second);
    let first = first.join().unwrap();
    let other = other.join().unwrap();
    let mut wb = shared.lock_unpoisoned();
    let resumed = wb
        .resume_project_workflow(&context, DEFAULT_PROJECT, "first", LIMITS)
        .unwrap();
    // A resource observation can lose the admission race; retry resolves the
    // winning original command. Neither client can mint a replacement instance.
    for invocation in [first, other].into_iter().flatten() {
        assert_eq!(invocation.admission, resumed.admission);
        assert_eq!(invocation.command, resumed.command);
    }
    let before = stores(&wb, &resumed)
        .runtime
        .list_events(&resumed.admission.instance_ref)
        .unwrap();
    let membership = crate::org::MembershipRecord {
        id: LOCAL_AUTHORITY.into(),
        op: crate::org::RecordOp::Upsert,
        org_id: crate::org::ORG_ID.into(),
        authority: LOCAL_AUTHORITY.into(),
        email: String::new(),
        role: "owner".into(),
        status: crate::org::MembershipStatus::Deprovisioned,
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
    assert!(wb
        .resume_project_workflow(&context, DEFAULT_PROJECT, "first", LIMITS)
        .is_err());
    assert_eq!(
        stores(&wb, &resumed)
            .runtime
            .list_events(&resumed.admission.instance_ref)
            .unwrap(),
        before
    );
}

#[test]
fn an_empty_input_contract_rejects_extra_values_before_product_admission() {
    let source =
        "workflow Empty() -> bool\nrule done\n when external.started\n=> { complete result true }";
    let (_root, shared, context, mut request) = fixture(source);
    let mut wb = shared.lock_unpoisoned();
    let compiled = CompiledHostAction::compile_materialized_inputs("workflow.launch", source, None);
    assert!(compiled.is_ok(), "{}", compiled.err().unwrap_or_default());
    assert_eq!(
        wb.launch_project_workflow(&context, &request, LIMITS)
            .unwrap_err(),
        "workflow input names do not match its declared contract"
    );
    let scope = request_scope(DEFAULT_PROJECT, LOCAL_AUTHORITY, "first").unwrap();
    assert!(wb
        .store_ref()
        .fold::<ProductActionAdmission>(&scope)
        .unwrap()
        .command
        .is_none());
    request.inputs.clear();
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    assert!(invocation.command.inputs.is_empty());
}

#[test]
fn prepared_workflow_authority_fences_device_and_migrated_session_revocation() {
    for migrated in [false, true] {
        let (_root, shared, context, request) = fixture(ECHO);
        let mut wb = shared.lock_unpoisoned();
        let crate::identity::ActorAuthentication::AccountSession { session_ref } =
            context.authentication()
        else {
            panic!("fixture must use actual account authentication");
        };
        let account_scope = crate::account::account_scope(LOCAL_AUTHORITY);
        let mut device = crate::account::DeviceRecord {
            id: "workflow-device".into(),
            op: crate::account::RecordOp::Upsert,
            label: "Workflow fixture".into(),
            kind: crate::account::DeviceKind::Computer,
            subkey_pubkey: "fixture-key".into(),
            status: crate::account::DeviceStatus::Active,
            enrolled_at: 1,
        };
        wb.upsert_account_device_in(&account_scope, &device)
            .unwrap();
        assert!(wb.bind_account_session_device(session_ref, LOCAL_AUTHORITY, &device.id));
        let mut session = crate::account_auth::AccountAuth::rebuild(wb.store_ref())
            .unwrap()
            .sessions[session_ref]
            .clone();
        if migrated {
            use crate::account_auth_custody::{
                command_record_facts, AccountAuthCustodyCatalog, CustodyCommand,
            };
            // Retain this exact session in its real account-auth scope, then
            // advance its catalog through the ordinary custody reducer.
            for command in [
                CustodyCommand::BeginMigration {
                    operation_id: "fixture-session-migration".into(),
                    source_basis: "fixture-original-session".into(),
                },
                CustodyCommand::CompleteMigration {
                    operation_id: "fixture-session-migration".into(),
                    destination_basis: "fixture-current-session".into(),
                    evidence_id: "fixture-retained-session".into(),
                },
            ] {
                let state = AccountAuthCustodyCatalog::rebuild(wb.store_ref())
                    .unwrap()
                    .account(LOCAL_AUTHORITY);
                for fact in command_record_facts(LOCAL_AUTHORITY, &state, command).unwrap() {
                    wb.store_mut()
                        .append_record(&fact.scope_id, &fact.kind, &fact.payload)
                        .unwrap();
                }
                crate::account_auth::append_facts(
                    wb.store_mut(),
                    &[crate::account_auth::AccountAuthFact::Session(
                        session.clone(),
                    )],
                )
                .unwrap();
            }
        }
        let prepared = wb.prepare_workflow_authority(&context, &request).unwrap();
        assert!(wb
            .store_mut()
            .with_dispatch_basis(&prepared.basis, || ())
            .is_ok());
        let before = wb.store_ref().scope_high_water_marks().unwrap();
        if migrated {
            session.op = crate::account_auth::RecordOp::Tombstone;
            crate::account_auth::append_facts(
                wb.store_mut(),
                &[crate::account_auth::AccountAuthFact::Session(session)],
            )
            .unwrap();
        } else {
            // Keep the session fact and hot cache unchanged: only the actual
            // enrolled device's standing moves.
            device.status = crate::account::DeviceStatus::Revoked;
            wb.upsert_account_device_in(&account_scope, &device)
                .unwrap();
        }
        let after = wb.store_ref().scope_high_water_marks().unwrap();
        for scope in [
            crate::library::LIBRARY_SCOPE,
            crate::org::ORG_SCOPE,
            crate::account_auth::ACCOUNT_AUTH_SCOPE,
            crate::mobile_machine_session::SCOPE,
        ] {
            assert_eq!(before.get(scope), after.get(scope), "unrelated scope moved");
        }
        assert!(wb.prepare_workflow_authority(&context, &request).is_err());
        assert!(wb
            .store_mut()
            .with_dispatch_basis(&prepared.basis, || panic!(
                "revoked account authority published prepared workflow work"
            ))
            .is_err());
    }
}

#[test]
fn retained_workflow_authority_does_not_borrow_the_creators_device_session() {
    let (_root, shared, context, request) = fixture(ECHO);
    let mut wb = shared.lock_unpoisoned();
    let crate::identity::ActorAuthentication::AccountSession { session_ref } =
        context.authentication()
    else {
        panic!("fixture must use account authentication");
    };
    let scope = crate::account::account_scope(LOCAL_AUTHORITY);
    let mut device = crate::account::DeviceRecord {
        id: "launch-device".into(),
        op: crate::account::RecordOp::Upsert,
        label: "Launch fixture".into(),
        kind: crate::account::DeviceKind::Computer,
        subkey_pubkey: "fixture-key".into(),
        status: crate::account::DeviceStatus::Active,
        enrolled_at: 1,
    };
    wb.upsert_account_device_in(&scope, &device).unwrap();
    assert!(wb.bind_account_session_device(session_ref, LOCAL_AUTHORITY, &device.id));
    let invocation = wb
        .launch_project_workflow(&context, &request, LIMITS)
        .unwrap();
    let unattended = AuthenticatedActionContext::project_workflow_invocation(
        context.actor().clone(),
        invocation.product_scope,
    );
    let prepared = wb
        .prepare_workflow_authority(&unattended, &request)
        .unwrap();
    assert!(wb
        .store_mut()
        .with_dispatch_basis(&prepared.basis, || ())
        .is_ok());
    device.status = crate::account::DeviceStatus::Revoked;
    wb.upsert_account_device_in(&scope, &device).unwrap();
    assert!(wb.prepare_workflow_authority(&context, &request).is_err());
    assert!(wb.prepare_workflow_authority(&unattended, &request).is_ok());
    assert!(wb
        .store_mut()
        .with_dispatch_basis(&prepared.basis, || ())
        .is_ok());
}

#[path = "project_workflow_execution_tests.rs"]
mod execution;

#[path = "project_workflow_supervisor_tests.rs"]
mod supervision;

#[path = "project_tracker_completion_tests.rs"]
mod completion;

#[path = "project_tracker_control_tests.rs"]
mod control;

#[path = "project_tracker_query_tests.rs"]
mod backlog;

#[path = "project_tracker_route_tests.rs"]
mod tracker_routes;

#[path = "project_workflow_route_tests.rs"]
mod workflow_routes;

#[path = "project_workflow_chat_tests.rs"]
mod chat_runs;

#[path = "pending_move_tests.rs"]
mod pending_move;
