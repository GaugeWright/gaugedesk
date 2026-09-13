use super::*;
use crate::{
    app_support::{LockUnpoisoned, DEFAULT_PLACEMENT},
    home_admission::HOME_ADMISSION_HEADER,
    SharedWorkbench,
};
use axum::{
    body::Body,
    extract::{Extension, State},
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use gaugedesk_core::{ids::AuthorityId, Lifecycle};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;

#[derive(serde::Deserialize, serde::Serialize)]
struct Intent {
    chat_id: String,
    request_id: String,
    path: String,
    base_cut: String,
    content: String,
}

fn router(wb: SharedWorkbench, input_path: std::path::PathBuf) -> Router {
    Router::new().merge(crate::home_routes::routes()).route("/factory", post(move |
        State(wb): State<SharedWorkbench>, Extension(context): Extension<AuthenticatedActionContext>, Json(intent): Json<Intent>
    | {
        let path = input_path.clone();
        async move {
            let mut wb = wb.lock_unpoisoned();
            let custody = NativeActionInputCustody::open(path, wb.home_id().as_str(), 4096).unwrap();
            match wb.admit_editor_file_save(&context, &custody, &EditorFileSave {
                chat_id: &intent.chat_id, request_id: &intent.request_id, path: &intent.path,
                base_cut: &intent.base_cut, content: &intent.content,
            }) {
                Ok(admitted) => (StatusCode::ACCEPTED, Json(serde_json::json!({"command": admitted.command, "replayed": admitted.replayed}))).into_response(),
                Err(reason) => (StatusCode::FORBIDDEN, reason).into_response(),
            }
        }
    })).route_layer(axum::middleware::from_fn_with_state(wb.clone(), crate::home_routes::require_home_admission)).with_state(wb)
}

async fn send(
    router: &Router,
    path: &str,
    token: Option<&str>,
    admission: Option<&str>,
    body: &str,
) -> (StatusCode, String) {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    if let Some(admission) = admission {
        req = req.header(HOME_ADMISSION_HEADER, admission);
    }
    let response = router
        .clone()
        .oneshot(req.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

pub(super) fn membership(wb: &mut Workbench, actor: &str, role: &str) {
    let member = crate::org::MembershipRecord {
        id: actor.into(),
        op: crate::org::RecordOp::Upsert,
        org_id: crate::org::ORG_ID.into(),
        authority: actor.into(),
        email: String::new(),
        role: role.into(),
        status: crate::org::MembershipStatus::Active,
        managed_by_scim: false,
        team: None,
    };
    wb.store_mut()
        .append_record(
            ORG_SCOPE,
            "membership",
            &serde_json::to_string(&member).unwrap(),
        )
        .unwrap();
}

fn setup(root: &std::path::Path) -> (SharedWorkbench, Intent, String) {
    setup_content(root, "recorded base", "private editor draft")
}

fn setup_content(
    root: &std::path::Path,
    base_body: &str,
    draft: &str,
) -> (SharedWorkbench, Intent, String) {
    let wb = crate::open_workbench(root).unwrap();
    let (intent, token) = {
        let mut wb = wb.lock_unpoisoned();
        wb.set_identity_provider(Some(Arc::new(
            crate::identity::LoopbackIdentityProvider::new(),
        )));
        membership(&mut wb, "alice", "owner");
        let token = wb.mint_account_session("alice", "passkey", 3600).unwrap();
        let chat = wb
            .create_chat_in_instance(DEFAULT_PLACEMENT, "File action")
            .unwrap();
        let chat_id = chat["id"].as_str().unwrap().to_owned();
        let path = wb.engagement_workspace_path(&chat_id, "note.txt");
        let engagement = &wb.engagements[&chat_id];
        engagement.write_file(&path, base_body).unwrap();
        let base = engagement.commit_turn("fixture base").unwrap().unwrap().0;
        (
            Intent {
                chat_id,
                request_id: "save-1".into(),
                path: "note.txt".into(),
                base_cut: base,
                content: draft.into(),
            },
            token,
        )
    };
    (wb, intent, token)
}

async fn home_admission(app: &Router, token: &str) -> String {
    let (status, body) = send(app, "/home/admissions", Some(token), None, "{}").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    serde_json::from_str::<serde_json::Value>(&body).unwrap()["admission"]
        .as_str()
        .unwrap()
        .into()
}

#[tokio::test]
async fn real_home_factory_retains_exact_command_through_renewal_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let input_path = dir.path().join("action-inputs.sqlite");
    let (wb, mut intent, token) = setup(dir.path());
    let app = router(wb.clone(), input_path.clone());
    let body = serde_json::to_string(&intent).unwrap();
    assert_eq!(
        send(&app, "/factory", None, None, &body).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, "/factory", Some(&token), None, &body).await.0,
        StatusCode::UNAUTHORIZED
    );
    let admission = home_admission(&app, &token).await;
    let (status, response) = send(&app, "/factory", Some(&token), Some(&admission), &body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{response}");
    let result: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(result["replayed"], false);
    let command: HostActionCommand = serde_json::from_value(result["command"].clone()).unwrap();
    assert_eq!(command.provenance.initiator, "alice");
    assert_eq!(command.provenance.executor, "alice");
    assert_ne!(command.issuer, "alice");
    assert!(!response.contains(&intent.content));
    let scope = command.instance_ref().unwrap();
    {
        let mut wb = wb.lock_unpoisoned();
        let custody =
            NativeActionInputCustody::open(&input_path, wb.home_id().as_str(), 4096).unwrap();
        assert_eq!(
            custody.resolve(&command.inputs["content"]).unwrap().content,
            intent.content
        );
        let delivery = wb
            .store_mut()
            .committed_dispatch::<ProductActionAdmission>(&scope, &intent.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(delivery.command, command);
        assert_eq!(
            wb.engagements[&intent.chat_id]
                .read_file(&wb.engagement_workspace_path(&intent.chat_id, "note.txt"))
                .unwrap(),
            "recorded base"
        );
    }
    drop(app);
    drop(wb);
    let wb = crate::open_workbench(dir.path()).unwrap();
    let renewed = {
        let mut wb = wb.lock_unpoisoned();
        wb.set_identity_provider(Some(Arc::new(
            crate::identity::LoopbackIdentityProvider::new(),
        )));
        wb.mint_account_session("alice", "passkey", 3600).unwrap()
    };
    let app = router(wb.clone(), input_path);
    let admission = home_admission(&app, &renewed).await;
    let (status, replay) = send(&app, "/factory", Some(&renewed), Some(&admission), &body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{replay}");
    let replay: serde_json::Value = serde_json::from_str(&replay).unwrap();
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["command"], result["command"]);
    intent.content.push_str(" changed");
    assert_eq!(
        send(
            &app,
            "/factory",
            Some(&renewed),
            Some(&admission),
            &serde_json::to_string(&intent).unwrap()
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let mut wb = wb.lock_unpoisoned();
    assert_eq!(
        wb.store_ref()
            .records(&scope, ProductActionAdmission::KIND)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        wb.store_mut()
            .committed_dispatch::<ProductActionAdmission>(&scope, &intent.request_id)
            .unwrap()
            .unwrap()
            .command,
        command
    );
    wb.revoke_account_session(&renewed);
}

#[tokio::test]
async fn factory_requires_current_project_grants_and_committed_target_permission() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, intent, token) = setup(dir.path());
    let app = router(wb.clone(), dir.path().join("inputs.sqlite"));
    let admission = home_admission(&app, &token).await;
    let body = serde_json::to_string(&intent).unwrap();
    {
        let mut wb = wb.lock_unpoisoned();
        membership(&mut wb, "alice", "consultant");
    }
    let (status, refusal) = send(&app, "/factory", Some(&token), Some(&admission), &body).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    assert!(refusal.contains("current grant"), "{refusal}");
    {
        let mut wb = wb.lock_unpoisoned();
        membership(&mut wb, "alice", "owner");
        let id = wb
            .library
            .current_target_set(&intent.chat_id)
            .unwrap()
            .members[0]
            .target_id
            .clone();
        let mut target = wb.library.work_targets[&id].clone();
        target.capabilities.propose = false;
        wb.store_mut()
            .append_record(
                LIBRARY_SCOPE,
                "work_target",
                &serde_json::to_string(&target).unwrap(),
            )
            .unwrap();
        assert!(
            wb.library.work_targets[&id].capabilities.propose,
            "cache deliberately stays stale"
        );
    }
    let (status, refusal) = send(&app, "/factory", Some(&token), Some(&admission), &body).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    assert!(refusal.contains("target authority"), "{refusal}");
}

#[test]
fn native_factory_refuses_revoked_or_unretained_account_context_before_preparation() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, intent, token) = setup(dir.path());
    let mut wb = wb.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    wb.revoke_account_session(&token);
    let inputs = NativeActionInputCustody::open(
        dir.path().join("inputs.sqlite"),
        wb.home_id().as_str(),
        4096,
    )
    .unwrap();
    let result = wb.admit_editor_file_save(
        &context,
        &inputs,
        &EditorFileSave {
            chat_id: &intent.chat_id,
            request_id: &intent.request_id,
            path: &intent.path,
            base_cut: &intent.base_cut,
            content: &intent.content,
        },
    );
    assert!(result.err().unwrap().contains("not durably active"));
    let fabricated = AuthenticatedActionContext::account_session(
        AuthorityId::new("alice"),
        "unretained-session".into(),
    );
    assert!(current_authority(
        wb.store_ref(),
        wb.home_id(),
        &fabricated,
        &EditorFileSave {
            chat_id: &intent.chat_id,
            request_id: &intent.request_id,
            path: &intent.path,
            base_cut: &intent.base_cut,
            content: &intent.content,
        }
    )
    .is_err());
}

#[tokio::test]
async fn factory_uses_target_restrictions_and_the_claims_of_the_actual_authentication_source() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, intent, token) = setup(dir.path());
    {
        let mut wb = wb.lock_unpoisoned();
        let id = wb
            .library
            .current_target_set(&intent.chat_id)
            .unwrap()
            .members[0]
            .target_id
            .clone();
        let mut target = wb.library.work_targets[&id].clone();
        target.attributes.region = Some(gaugedesk_core::abac::Region::new("eu"));
        wb.store_mut()
            .append_record(
                LIBRARY_SCOPE,
                "work_target",
                &serde_json::to_string(&target).unwrap(),
            )
            .unwrap();
        wb.set_identity_provider(Some(Arc::new(
            crate::identity::LoopbackIdentityProvider::new().enroll(
                "eu-idp-token",
                AuthorityId::new("alice"),
                AuthorityAttributes {
                    region: Some(gaugedesk_core::abac::Region::new("eu")),
                    ..AuthorityAttributes::default()
                },
            ),
        )));
    }
    let app = router(wb, dir.path().join("inputs.sqlite"));
    let admission = home_admission(&app, &token).await;
    let body = serde_json::to_string(&intent).unwrap();
    let (status, reason) = send(&app, "/factory", Some(&token), Some(&admission), &body).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reason}");
    assert!(reason.contains("resource policy"), "{reason}");
    let (status, response) = send(
        &app,
        "/factory",
        Some("eu-idp-token"),
        Some(&admission),
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{response}");
}

#[test]
fn controller_factory_checks_current_grant_and_refuses_malformed_history() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, intent, _) = setup(dir.path());
    let mut wb = wb.lock_unpoisoned();
    let grant = crate::mobile_machine_session::ControllerGrantRecord {
        id: "grant-1".into(),
        op: crate::account::RecordOp::Upsert,
        machine: wb.home_id().clone(),
        device: gaugedesk_core::ids::DeviceId::new("device-1"),
        public_key: SigningKey::from_seed(&[72; 32]).unwrap().public_key(),
        label: "fixture".into(),
        credential_hash: "fixture-only".into(),
        status: crate::mobile_machine_session::ControllerGrantStatus::Active,
        enrolled_at: 1,
    };
    // This is an explicit device directory grant, never an inferred human owner.
    membership(&mut wb, grant.device.as_str(), "owner");
    wb.store_mut()
        .append_record(
            crate::mobile_machine_session::SCOPE,
            "controller-grant",
            &serde_json::to_string(&grant).unwrap(),
        )
        .unwrap();
    let context = AuthenticatedActionContext::machine_controller(&grant);
    let request = EditorFileSave {
        chat_id: &intent.chat_id,
        request_id: &intent.request_id,
        path: &intent.path,
        base_cut: &intent.base_cut,
        content: &intent.content,
    };
    assert!(current_authority(wb.store_ref(), wb.home_id(), &context, &request).is_ok());
    let mut revoked = grant.clone();
    revoked.status = crate::mobile_machine_session::ControllerGrantStatus::Revoked;
    wb.store_mut()
        .append_record(
            crate::mobile_machine_session::SCOPE,
            "controller-grant",
            &serde_json::to_string(&revoked).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        current_authority(wb.store_ref(), wb.home_id(), &context, &request),
        Err(AdmitError::Rejected(_))
    ));
    wb.store_mut()
        .append_record(
            crate::mobile_machine_session::SCOPE,
            "controller-grant",
            &serde_json::to_string(&grant).unwrap(),
        )
        .unwrap();
    wb.store_mut()
        .append_record(
            crate::mobile_machine_session::SCOPE,
            "controller-grant",
            "malformed revocation",
        )
        .unwrap();
    assert!(
        crate::mobile_machine_session::current_action_grant(wb.store_ref(), &grant.id).is_err()
    );
    assert!(current_authority(wb.store_ref(), wb.home_id(), &context, &request).is_err());
}

pub(super) fn admitted_fixture(
    root: &std::path::Path,
) -> (
    SharedWorkbench,
    HostActionCommand,
    NativeActionInputCustody,
    String,
) {
    admitted_content_fixture(root, "recorded base", "private editor draft")
}

pub(super) fn admitted_content_fixture(
    root: &std::path::Path,
    base_body: &str,
    draft: &str,
) -> (
    SharedWorkbench,
    HostActionCommand,
    NativeActionInputCustody,
    String,
) {
    let (wb, intent, token) = setup_content(root, base_body, draft);
    let (command, inputs) = {
        let mut wb = wb.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let inputs =
            NativeActionInputCustody::open(root.join("inputs.sqlite"), wb.home_id().as_str(), 4096)
                .unwrap();
        let admitted = wb
            .admit_editor_file_save(
                &context,
                &inputs,
                &EditorFileSave {
                    chat_id: &intent.chat_id,
                    request_id: &intent.request_id,
                    path: &intent.path,
                    base_cut: &intent.base_cut,
                    content: &intent.content,
                },
            )
            .unwrap();
        (admitted.command, inputs)
    };
    (wb, command, inputs, token)
}

pub(super) fn home_storage_fixture(
    root: &std::path::Path,
    config: NativeActionStorageConfig,
) -> (
    SharedWorkbench,
    HostActionCommand,
    NativeActionStorage,
    String,
) {
    let (wb, intent, token) = setup(root);
    let (command, storage) = {
        let mut wb = wb.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let storage = wb.open_native_action_storage(config).unwrap();
        let command = wb
            .admit_editor_file_save(
                &context,
                storage.inputs(),
                &EditorFileSave {
                    chat_id: &intent.chat_id,
                    request_id: &intent.request_id,
                    path: &intent.path,
                    base_cut: &intent.base_cut,
                    content: &intent.content,
                },
            )
            .unwrap()
            .command;
        (command, storage)
    };
    (wb, command, storage, token)
}

pub(super) fn editor_runtime(
    wb: &Workbench,
    command: &HostActionCommand,
    root_path: &std::path::Path,
) -> gaugedesk_whip_runtime::host_actions::facade::GovernedHostFacade<
    gaugedesk_whip_runtime::host_actions::NativeStores,
> {
    use gaugedesk_whip_runtime::host_actions::{facade::GovernedHostFacade, NativeStores};
    let key = SigningKey::from_seed(&wb.governance_seed()).unwrap();
    let root = GovernanceRootVerifier::new(wb.authority().clone(), key.public_key());
    let policy = crate::action_policy::load_action_policy(
        wb.store_ref(),
        &ActionPolicyIdentity {
            issuer: command.issuer.clone(),
            scope: command.scope.clone(),
            request_id: command.request_id.clone(),
        },
        &command.policy,
        &root,
    )
    .unwrap();
    GovernedHostFacade::from_signed_store_with_verifier(
        NativeStores::open(
            root_path.join("runtime.sqlite"),
            root_path.join("coord.sqlite"),
            root_path.join("items.sqlite"),
        )
        .unwrap(),
        command.policy.epoch,
        policy.signed_envelope(),
        &root,
    )
    .unwrap()
}

#[test]
fn native_delivery_recovers_lost_acknowledgment_after_restart_with_current_authentication() {
    use crate::host_action_delivery::ACKNOWLEDGMENT_KIND;
    use gaugedesk_whip_runtime::host_actions::RuntimeStore;
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, inputs, token) = admitted_fixture(dir.path());
    let scope = command.instance_ref().unwrap();
    let events = {
        let mut wb = wb.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let mut runtime = editor_runtime(&wb, &command, dir.path());
        let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
        fault
            .execute_batch(
                "CREATE TRIGGER fail_editor_ack BEFORE INSERT ON events
            WHEN NEW.kind = 'host_action_runtime_admission_v1'
            BEGIN SELECT RAISE(ABORT, 'lost product acknowledgment'); END;",
            )
            .unwrap();
        let error = wb
            .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
            .unwrap_err();
        assert!(error.contains("acknowledgment"), "{error}");
        assert_eq!(runtime.kernel().store().list_instances().unwrap().len(), 1);
        assert!(runtime
            .kernel()
            .store()
            .list_effects(&scope)
            .unwrap()
            .is_empty());
        assert!(wb
            .store_ref()
            .records(&scope, ACKNOWLEDGMENT_KIND)
            .unwrap()
            .is_empty());
        let events = runtime.kernel().store().list_events(&scope).unwrap();
        fault.execute_batch("DROP TRIGGER fail_editor_ack").unwrap();
        events
    };
    drop(wb);
    let wb = crate::open_workbench(dir.path()).unwrap();
    let mut wb = wb.lock_unpoisoned();
    let token = wb.mint_account_session("alice", "passkey", 3600).unwrap();
    let context = wb.authenticate_action_context(&token).unwrap();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    let acknowledgment = wb
        .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
        .unwrap();
    assert_eq!(
        wb.deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
            .unwrap(),
        acknowledgment
    );
    assert_eq!(
        runtime.kernel().store().list_events(&scope).unwrap(),
        events
    );
    assert_eq!(
        wb.store_ref()
            .records(&scope, ACKNOWLEDGMENT_KIND)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        acknowledgment.receipt.fingerprint,
        command.fingerprint().unwrap()
    );
    assert_eq!(acknowledgment.receipt.instance_ref, scope);
    let (_, _, chat_id): (String, String, String) = serde_json::from_str(&command.scope).unwrap();
    let (_, _, path): (String, String, String) = serde_json::from_str(
        command.resources["target"]
            .resource
            .selector
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        wb.engagements[&chat_id].read_file(&path).unwrap(),
        "recorded base"
    );
}

#[test]
fn native_delivery_refuses_revocation_changed_authority_and_unadmitted_commands() {
    use gaugedesk_whip_runtime::host_actions::RuntimeStore;
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, inputs, token) = admitted_fixture(dir.path());
    let mut wb = wb.lock_unpoisoned();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    let context = wb.authenticate_action_context(&token).unwrap();
    wb.revoke_account_session(&token);
    assert!(wb
        .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
        .is_err());
    let token = wb.mint_account_session("alice", "passkey", 3600).unwrap();
    let context = wb.authenticate_action_context(&token).unwrap();
    let mut changed = command.clone();
    changed.inputs.get_mut("content").unwrap().version_ref = "unadmitted bytes".into();
    assert!(wb
        .deliver_editor_file_save(&context, &inputs, &changed, &mut runtime)
        .is_err());
    changed = command.clone();
    changed.request_id = "missing product admission".into();
    assert!(wb
        .deliver_editor_file_save(&context, &inputs, &changed, &mut runtime)
        .is_err());
    membership(&mut wb, "alice", "consultant");
    assert!(wb
        .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
        .is_err());
    membership(&mut wb, "alice", "owner");
    let (id, _, _): (String, String, String) = serde_json::from_str(
        command.resources["target"]
            .resource
            .selector
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    let mut target = wb.library.work_targets[&id].clone();
    target.capabilities.propose = false;
    wb.store_mut()
        .append_record(
            LIBRARY_SCOPE,
            "work_target",
            &serde_json::to_string(&target).unwrap(),
        )
        .unwrap();
    assert!(wb
        .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
        .is_err());
    assert!(runtime
        .kernel()
        .store()
        .list_instances()
        .unwrap()
        .is_empty());
}

#[test]
fn native_delivery_requires_retained_inputs_and_unchanged_policy_bindings() {
    use gaugedesk_whip_runtime::host_actions::RuntimeStore;
    use whipplescript_store::content::{ContentBlobs, ContentStore};
    for erased in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (wb, command, inputs, token) = admitted_fixture(dir.path());
        let mut wb = wb.lock_unpoisoned();
        let mut runtime = editor_runtime(&wb, &command, dir.path());
        let context = wb.authenticate_action_context(&token).unwrap();
        if erased {
            ContentStore::open(dir.path().join("inputs.sqlite"))
                .unwrap()
                .erase(
                    &command.inputs["content"].version_ref,
                    "erase admitted input",
                )
                .unwrap();
        } else {
            let (id, _, _): (String, String, String) = serde_json::from_str(
                command.resources["target"]
                    .resource
                    .selector
                    .as_deref()
                    .unwrap(),
            )
            .unwrap();
            let mut target = wb.library.work_targets[&id].clone();
            // The current actor still clears this less restrictive resource,
            // but it cannot relabel a command admitted under the old policy.
            target.attributes.classification = gaugedesk_core::abac::Classification::Public;
            wb.store_mut()
                .append_record(
                    LIBRARY_SCOPE,
                    "work_target",
                    &serde_json::to_string(&target).unwrap(),
                )
                .unwrap();
        }
        let error = wb
            .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
            .unwrap_err();
        if !erased {
            assert!(error.contains("admitted ceiling"), "{error}");
        }
        assert!(runtime
            .kernel()
            .store()
            .list_instances()
            .unwrap()
            .is_empty());
    }
}

#[test]
fn native_delivery_refuses_receipted_snapshot_without_matching_admission_history() {
    use gaugedesk_whip_runtime::host_actions::RuntimeStore;
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, inputs, token) = admitted_fixture(dir.path());
    let mut wb = wb.lock_unpoisoned();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    let context = wb.authenticate_action_context(&token).unwrap();
    let scope = command.instance_ref().unwrap();
    // Fault injection: leave the receipt, snapshot and outbox all consistent,
    // but remove the authoritative product event they are supposed to witness.
    let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    fault
        .execute(
            "DELETE FROM events WHERE scope_id = ?1 AND kind = ?2",
            rusqlite::params![scope, ProductActionAdmission::KIND],
        )
        .unwrap();
    assert!(wb
        .store_mut()
        .committed_dispatch::<ProductActionAdmission>(&scope, &command.request_id)
        .unwrap()
        .is_some());
    let error = wb
        .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
        .unwrap_err();
    assert!(error.contains("original admission history"), "{error}");
    assert!(runtime
        .kernel()
        .store()
        .list_instances()
        .unwrap()
        .is_empty());
}

pub(super) fn configure_native_files(store: &gaugedesk_whip_runtime::host_actions::NativeStores) {
    gaugedesk_whip_runtime::host_actions::register_native_file_package(&store.runtime).unwrap();
}

#[test]
fn native_editor_executes_reference_read_and_versioned_write_without_materializing_disk() {
    use gaugedesk_whip_runtime::host_actions::{action_result::ActionWorkflowStatus, RuntimeStore};
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, inputs, token) = admitted_fixture(dir.path());
    let mut wb = wb.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    configure_native_files(runtime.kernel().store());
    let acknowledgment = wb
        .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
        .unwrap();
    let admission = &acknowledgment.receipt;
    let first = wb
        .advance_editor_file_save(&context, &inputs, &command, admission, &mut runtime)
        .unwrap();
    assert_eq!(first.len(), 1);
    let read = runtime
        .kernel()
        .claimable_effects(&admission.instance_ref)
        .unwrap()
        .remove(0);
    assert_eq!(read.kind, "file.read");
    wb.execute_editor_file_save_effect(
        &context,
        &inputs,
        &command,
        admission,
        &first[0],
        &mut runtime,
    )
    .unwrap_or_else(|error| panic!("{error}; {read:?}"));
    let second = wb
        .advance_editor_file_save(&context, &inputs, &command, admission, &mut runtime)
        .unwrap();
    assert_eq!(second.len(), 1);
    let write = runtime
        .kernel()
        .claimable_effects(&admission.instance_ref)
        .unwrap()
        .remove(0);
    assert_eq!(write.kind, "file.write");
    let payload: serde_json::Value = serde_json::from_str(&write.input_json).unwrap();
    let resolved = inputs.resolve(&command.inputs["content"]).unwrap();
    assert_eq!(payload["body_ref"]["content_hash"], resolved.content_hash);
    assert_ne!(resolved.content_hash, command.inputs["content"].version_ref);
    wb.execute_editor_file_save_effect(
        &context,
        &inputs,
        &command,
        admission,
        &second[0],
        &mut runtime,
    )
    .unwrap_or_else(|error| panic!("{error}; {write:?}"));
    assert!(wb
        .advance_editor_file_save(&context, &inputs, &command, admission, &mut runtime)
        .unwrap()
        .is_empty());
    let result = wb
        .read_editor_file_save_result(&context, &inputs, &command, admission, &runtime)
        .unwrap();
    assert_eq!(
        result.terminal.as_ref().unwrap().status,
        ActionWorkflowStatus::Completed
    );
    assert_eq!(result.effects.len(), 2);
    let (_, _, chat): (String, String, String) = serde_json::from_str(&command.scope).unwrap();
    let (_, _, path): (String, String, String) = serde_json::from_str(
        command.resources["target"]
            .resource
            .selector
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        wb.engagements[&chat].observe().unwrap().recorded_cut,
        Some(whipplescript_store::vcs_file_save::save_cut_id(
            &admission.instance_ref,
            &second[0]
        ))
    );
    assert_eq!(
        wb.engagements[&chat].read_file(&path).unwrap(),
        "recorded base"
    );
    let events = runtime
        .kernel()
        .store()
        .list_events(&admission.instance_ref)
        .unwrap();
    assert!(!serde_json::to_string(&result)
        .unwrap()
        .contains("private editor draft"));
    assert_eq!(
        wb.read_editor_file_save_result(&context, &inputs, &command, admission, &runtime)
            .unwrap(),
        result
    );
    assert_eq!(
        runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap(),
        events
    );
    assert!(wb
        .execute_editor_file_save_effect(
            &context,
            &inputs,
            &command,
            admission,
            &second[0],
            &mut runtime
        )
        .is_err());
    assert_eq!(
        runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap(),
        events
    );
}

#[test]
fn native_editor_revocation_between_read_and_write_leaves_no_target_effect() {
    use gaugedesk_whip_runtime::host_actions::RuntimeStore;
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, inputs, token) = admitted_fixture(dir.path());
    let mut wb = wb.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    configure_native_files(runtime.kernel().store());
    let admission = wb
        .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
        .unwrap()
        .receipt;
    let effects = wb
        .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
        .unwrap();
    wb.execute_editor_file_save_effect(
        &context,
        &inputs,
        &command,
        &admission,
        &effects[0],
        &mut runtime,
    )
    .unwrap();
    let effects = wb
        .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
        .unwrap();
    let before = runtime
        .kernel()
        .store()
        .list_events(&admission.instance_ref)
        .unwrap();
    wb.revoke_account_session(&token);
    assert!(wb
        .execute_editor_file_save_effect(
            &context,
            &inputs,
            &command,
            &admission,
            &effects[0],
            &mut runtime
        )
        .is_err());
    assert!(wb
        .read_editor_file_save_result(&context, &inputs, &command, &admission, &runtime)
        .is_err());
    assert_eq!(
        runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap(),
        before
    );
    let (_, _, chat): (String, String, String) = serde_json::from_str(&command.scope).unwrap();
    let ActionBasis::Version { version_ref: base } = &command.resources["target"].basis else {
        panic!("base")
    };
    assert_eq!(
        wb.engagements[&chat]
            .observe()
            .unwrap()
            .recorded_cut
            .as_deref(),
        Some(base.as_str())
    );
}

#[test]
fn native_editor_conflict_preserves_competing_head_and_is_not_blindly_retried() {
    use gaugedesk_whip_runtime::host_actions::{action_result::ActionWorkflowStatus, RuntimeStore};
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, inputs, token) = admitted_fixture(dir.path());
    let mut wb = wb.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    configure_native_files(runtime.kernel().store());
    let admission = wb
        .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
        .unwrap()
        .receipt;
    let effects = wb
        .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
        .unwrap();
    wb.execute_editor_file_save_effect(
        &context,
        &inputs,
        &command,
        &admission,
        &effects[0],
        &mut runtime,
    )
    .unwrap();
    let writes = wb
        .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
        .unwrap();
    let (_, _, chat): (String, String, String) = serde_json::from_str(&command.scope).unwrap();
    let (_, _, path): (String, String, String) = serde_json::from_str(
        command.resources["target"]
            .resource
            .selector
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    // Fixture's separately recorded competing work, after the editor's base.
    wb.engagements[&chat]
        .write_file(&path, "competing recorded work")
        .unwrap();
    let head = wb.engagements[&chat]
        .commit_turn("competing fixture")
        .unwrap()
        .unwrap()
        .0;
    wb.execute_editor_file_save_effect(
        &context,
        &inputs,
        &command,
        &admission,
        &writes[0],
        &mut runtime,
    )
    .unwrap();
    assert!(wb
        .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
        .unwrap()
        .is_empty());
    let result = wb
        .read_editor_file_save_result(&context, &inputs, &command, &admission, &runtime)
        .unwrap();
    assert_eq!(
        result.terminal.as_ref().unwrap().status,
        ActionWorkflowStatus::Failed
    );
    assert_eq!(
        wb.engagements[&chat].observe().unwrap().recorded_cut,
        Some(head.clone())
    );
    let events = runtime
        .kernel()
        .store()
        .list_events(&admission.instance_ref)
        .unwrap();
    assert!(wb
        .execute_editor_file_save_effect(
            &context,
            &inputs,
            &command,
            &admission,
            &writes[0],
            &mut runtime
        )
        .is_err());
    assert_eq!(
        runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap(),
        events
    );
    assert_eq!(
        wb.engagements[&chat].observe().unwrap().recorded_cut,
        Some(head)
    );
}

#[test]
fn native_editor_erased_input_blocks_write_but_preserves_authorized_metadata_inspection() {
    use gaugedesk_whip_runtime::host_actions::RuntimeStore;
    use whipplescript_store::content::{ContentBlobs, ContentStore};
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, inputs, token) = admitted_fixture(dir.path());
    let mut wb = wb.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    configure_native_files(runtime.kernel().store());
    let admission = wb
        .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
        .unwrap()
        .receipt;
    let effects = wb
        .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
        .unwrap();
    wb.execute_editor_file_save_effect(
        &context,
        &inputs,
        &command,
        &admission,
        &effects[0],
        &mut runtime,
    )
    .unwrap();
    let writes = wb
        .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
        .unwrap();
    let before = wb
        .read_editor_file_save_result(&context, &inputs, &command, &admission, &runtime)
        .unwrap();
    let events = runtime
        .kernel()
        .store()
        .list_events(&admission.instance_ref)
        .unwrap();
    ContentStore::open(dir.path().join("inputs.sqlite"))
        .unwrap()
        .erase(&command.inputs["content"].version_ref, "erase input")
        .unwrap();
    assert!(wb
        .execute_editor_file_save_effect(
            &context,
            &inputs,
            &command,
            &admission,
            &writes[0],
            &mut runtime
        )
        .is_err());
    assert_eq!(
        wb.read_editor_file_save_result(&context, &inputs, &command, &admission, &runtime)
            .unwrap(),
        before
    );
    assert_eq!(
        runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap(),
        events
    );
}

#[test]
fn native_editor_resumes_after_read_restart_and_reopens_completed_save_without_reexecution() {
    use gaugedesk_whip_runtime::host_actions::RuntimeStore;
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, inputs, token) = admitted_fixture(dir.path());
    let (admission, write_id) = {
        let mut wb = wb.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let mut runtime = editor_runtime(&wb, &command, dir.path());
        configure_native_files(runtime.kernel().store());
        let admission = wb
            .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
            .unwrap()
            .receipt;
        let reads = wb
            .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
            .unwrap();
        wb.execute_editor_file_save_effect(
            &context,
            &inputs,
            &command,
            &admission,
            &reads[0],
            &mut runtime,
        )
        .unwrap();
        let writes = wb
            .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
            .unwrap();
        (admission, writes[0].clone())
    };
    drop(inputs);
    drop(wb);
    let wb = crate::open_workbench(dir.path()).unwrap();
    let (result, events) = {
        let mut wb = wb.lock_unpoisoned();
        let token = wb.mint_account_session("alice", "passkey", 3600).unwrap();
        let context = wb.authenticate_action_context(&token).unwrap();
        let inputs = NativeActionInputCustody::open(
            dir.path().join("inputs.sqlite"),
            wb.home_id().as_str(),
            4096,
        )
        .unwrap();
        let mut runtime = editor_runtime(&wb, &command, dir.path());
        wb.execute_editor_file_save_effect(
            &context,
            &inputs,
            &command,
            &admission,
            &write_id,
            &mut runtime,
        )
        .unwrap();
        wb.advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
            .unwrap();
        (
            wb.read_editor_file_save_result(&context, &inputs, &command, &admission, &runtime)
                .unwrap(),
            runtime
                .kernel()
                .store()
                .list_events(&admission.instance_ref)
                .unwrap(),
        )
    };
    drop(wb);
    let wb = crate::open_workbench(dir.path()).unwrap();
    let mut wb = wb.lock_unpoisoned();
    let token = wb.mint_account_session("alice", "passkey", 3600).unwrap();
    let context = wb.authenticate_action_context(&token).unwrap();
    let inputs = NativeActionInputCustody::open(
        dir.path().join("inputs.sqlite"),
        wb.home_id().as_str(),
        4096,
    )
    .unwrap();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    assert_eq!(
        wb.read_editor_file_save_result(&context, &inputs, &command, &admission, &runtime)
            .unwrap(),
        result
    );
    assert!(wb
        .execute_editor_file_save_effect(
            &context,
            &inputs,
            &command,
            &admission,
            &write_id,
            &mut runtime
        )
        .is_err());
    assert_eq!(
        runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap(),
        events
    );
    let (_, _, chat): (String, String, String) = serde_json::from_str(&command.scope).unwrap();
    assert_eq!(
        wb.engagements[&chat].observe().unwrap().recorded_cut,
        Some(whipplescript_store::vcs_file_save::save_cut_id(
            &admission.instance_ref,
            &write_id
        ))
    );
}

#[test]
fn native_editor_lost_runtime_settlement_preserves_unknown_outcome_and_target_evidence() {
    use gaugedesk_whip_runtime::host_actions::RuntimeStore;
    use whipplescript_store::effect_recovery::ExternalDisposition;
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, inputs, token) = admitted_fixture(dir.path());
    let (admission, write_id, result, events) = {
        let mut wb = wb.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let mut runtime = editor_runtime(&wb, &command, dir.path());
        configure_native_files(runtime.kernel().store());
        let admission = wb
            .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
            .unwrap()
            .receipt;
        let reads = wb
            .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
            .unwrap();
        wb.execute_editor_file_save_effect(
            &context,
            &inputs,
            &command,
            &admission,
            &reads[0],
            &mut runtime,
        )
        .unwrap();
        let writes = wb
            .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
            .unwrap();
        let fault = rusqlite::Connection::open(dir.path().join("runtime.sqlite")).unwrap();
        fault
            .execute_batch(
                "CREATE TRIGGER lose_editor_terminal BEFORE INSERT ON events
            WHEN NEW.event_type = 'effect.terminal'
            BEGIN SELECT RAISE(ABORT, 'lost runtime settlement'); END;",
            )
            .unwrap();
        assert!(wb
            .execute_editor_file_save_effect(
                &context,
                &inputs,
                &command,
                &admission,
                &writes[0],
                &mut runtime
            )
            .is_err());
        fault
            .execute_batch("DROP TRIGGER lose_editor_terminal")
            .unwrap();
        let (_, _, chat): (String, String, String) = serde_json::from_str(&command.scope).unwrap();
        assert_eq!(
            wb.engagements[&chat].observe().unwrap().recorded_cut,
            Some(whipplescript_store::vcs_file_save::save_cut_id(
                &admission.instance_ref,
                &writes[0]
            ))
        );
        let result = wb
            .read_editor_file_save_result(&context, &inputs, &command, &admission, &runtime)
            .unwrap();
        let evidence = result
            .effects
            .iter()
            .find(|effect| effect.effect_id == writes[0])
            .unwrap();
        assert_eq!(evidence.attempts.len(), 1);
        assert_eq!(
            evidence.attempts[0].disposition,
            ExternalDisposition::Unknown
        );
        assert!(result.terminal.is_none());
        let events = runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap();
        (admission, writes[0].clone(), result, events)
    };
    drop(inputs);
    drop(wb);
    let wb = crate::open_workbench(dir.path()).unwrap();
    let mut wb = wb.lock_unpoisoned();
    let token = wb.mint_account_session("alice", "passkey", 3600).unwrap();
    let context = wb.authenticate_action_context(&token).unwrap();
    let inputs = NativeActionInputCustody::open(
        dir.path().join("inputs.sqlite"),
        wb.home_id().as_str(),
        4096,
    )
    .unwrap();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    assert_eq!(
        wb.read_editor_file_save_result(&context, &inputs, &command, &admission, &runtime)
            .unwrap(),
        result
    );
    assert!(wb
        .execute_editor_file_save_effect(
            &context,
            &inputs,
            &command,
            &admission,
            &write_id,
            &mut runtime
        )
        .is_err());
    assert_eq!(
        runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap(),
        events
    );
}

#[test]
fn native_editor_forged_runtime_admission_cannot_advance_or_disclose_evidence() {
    use gaugedesk_whip_runtime::host_actions::RuntimeStore;
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, inputs, token) = admitted_fixture(dir.path());
    let mut wb = wb.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    configure_native_files(runtime.kernel().store());
    let mut admission = wb
        .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
        .unwrap()
        .receipt;
    let before = runtime
        .kernel()
        .store()
        .list_events(&admission.instance_ref)
        .unwrap();
    admission.admitted_at.head_digest = "unrelated runtime history".into();
    assert!(wb
        .read_editor_file_save_result(&context, &inputs, &command, &admission, &runtime)
        .is_err());
    assert!(wb
        .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
        .is_err());
    assert_eq!(
        runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap(),
        before
    );
    assert!(runtime
        .kernel()
        .store()
        .list_effects(&admission.instance_ref)
        .unwrap()
        .is_empty());
}

#[test]
fn native_editor_preparation_carries_the_actual_account_expiration_into_the_writer_fence() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, command, inputs, token) = admitted_fixture(dir.path());
    let mut wb = wb.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let ActorAuthentication::AccountSession { session_ref } = context.authentication() else {
        panic!("account context")
    };
    let auth = crate::account_auth::AccountAuth::rebuild(wb.store_ref()).unwrap();
    let session = &auth.sessions[session_ref];
    let expected = std::time::UNIX_EPOCH
        + std::time::Duration::from_millis(session.issued_at_ms + session.lifetime_secs * 1000);
    let prepared = wb
        .prepare_native_editor_action(&context, &inputs, &command, &command.policy)
        .unwrap();
    assert_eq!(prepared.basis.deadline(), Some(expected));
    // Model the same captured basis after its validity window, without a
    // timing-dependent sleep or a fabricated account/context in the factory.
    let expired = prepared.basis.with_deadline(std::time::UNIX_EPOCH);
    assert!(wb
        .store_mut()
        .with_dispatch_basis(&expired, || panic!("expired action entered runtime"))
        .is_err());
}

#[test]
fn native_resolution_scope_is_shared_by_authorized_actors_and_checks_current_path_grant() {
    use gaugedesk_whip_runtime::host_actions::RuntimeStore;
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, inputs, token) = admitted_fixture(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let (_, project, chat): (String, String, String) =
        serde_json::from_str(&command.scope).unwrap();
    let (id, _, path): (String, String, String) = serde_json::from_str(
        command.resources["target"]
            .resource
            .selector
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    let ActionBasis::Version { version_ref: base } = &command.resources["target"].basis else {
        panic!("base")
    };
    let expected = resolution_scope::original(&command).unwrap();
    let request = EditorFileSave {
        chat_id: &chat,
        request_id: "other-request",
        path: &path,
        base_cut: base,
        content: "",
    };
    assert_eq!(
        current_authority(wb.store_ref(), wb.home_id(), &context, &request)
            .unwrap()
            .resolution_scope,
        expected
    );
    membership(&mut wb, "agent:editor", "owner");
    let agent_token = wb
        .mint_account_session("agent:editor", "fixture-auth", 3600)
        .unwrap();
    let agent = wb.authenticate_action_context(&agent_token).unwrap();
    let authority = current_authority(wb.store_ref(), wb.home_id(), &agent, &request).unwrap();
    assert_eq!(authority.project_id, project);
    assert_eq!(authority.resolution_scope, expected);
    assert_ne!(
        authority.policy,
        current_authority(wb.store_ref(), wb.home_id(), &context, &request)
            .unwrap()
            .policy
    );
    let other_file = EditorFileSave {
        path: "another.txt",
        ..request
    };
    assert_eq!(
        current_authority(wb.store_ref(), wb.home_id(), &agent, &other_file)
            .unwrap()
            .resolution_scope,
        expected
    );
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    // Both resources still permit this exact file, but less knowledge is now
    // authorized. Current path access cannot silently replace the old namespace.
    let mut target = wb.library.work_targets[&id].clone();
    target.path_scope = vec!["note.txt".into()];
    wb.store_mut()
        .append_record(
            LIBRARY_SCOPE,
            "work_target",
            &serde_json::to_string(&target).unwrap(),
        )
        .unwrap();
    let changed = current_authority(wb.store_ref(), wb.home_id(), &context, &request).unwrap();
    assert_ne!(changed.resolution_scope, expected);
    assert!(wb
        .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
        .unwrap_err()
        .contains("resolution scope"));
    assert!(runtime
        .kernel()
        .store()
        .list_instances()
        .unwrap()
        .is_empty());
}

#[test]
fn native_resolution_delivery_refuses_missing_or_substituted_original_resource() {
    use gaugedesk_whip_runtime::host_actions::RuntimeStore;
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, inputs, token) = admitted_fixture(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    for field in [
        "missing",
        "authority",
        "resource",
        "compartment",
        "basis",
        "label",
        "writable",
        "handle",
    ] {
        let mut changed = command.clone();
        if field == "missing" {
            changed.resources.remove("resolutions");
        } else {
            let resource = changed.resources.get_mut("resolutions").unwrap();
            match field {
                "basis" => {
                    resource.basis = ActionBasis::Version {
                        version_ref: "other".into(),
                    }
                }
                "label" => resource.label_ref = "public".into(),
                "writable" => resource.resource.writable = Some(true),
                "handle" => resource.resource.handle = "admitted_target".into(),
                _ => {
                    let mut scope: serde_json::Value =
                        serde_json::from_str(resource.resource.selector.as_deref().unwrap())
                            .unwrap();
                    scope[field] = "foreign".into();
                    let scope = serde_json::from_value(scope).unwrap();
                    *resource =
                        resolution_scope::resource(&scope, &command.policy.envelope_hash).unwrap();
                }
            }
        }
        assert!(
            wb.deliver_editor_file_save(&context, &inputs, &changed, &mut runtime)
                .is_err(),
            "{field}"
        );
    }
    assert!(runtime
        .kernel()
        .store()
        .list_instances()
        .unwrap()
        .is_empty());
}

/// Populate synthetic historical knowledge in the fixture's actual native
/// store. This tests consumption; it does not qualify governed recording.
fn record_scope_fixture(
    root: &std::path::Path,
    base: &str,
    scope: &whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope,
) -> usize {
    let mut recorded = 0;
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            recorded += record_scope_fixture(&entry.path(), base, scope);
        } else if entry.file_name() == "content.sqlite" && root.join("branches.sqlite").is_file() {
            let mut workspace = whipplescript_store::vcs::NativeWorkspaceVcs::open(
                root.join("branches.sqlite"),
                entry.path(),
            )
            .unwrap();
            if workspace.get_cut(base).unwrap().is_some() {
                workspace.set_actor(Some("human:original-recorder".into()));
                workspace.set_intent(Some("independent historical correction fixture".into()));
                workspace
                    .record_region_resolutions_in_scope(
                        scope,
                        "original-correction",
                        &[whipplescript_store::text_merge::RegionResolution {
                            base_text: "dog".into(),
                            ours_text: "tiger".into(),
                            theirs_text: "lion".into(),
                            resolution_text: "liger".into(),
                        }],
                        "recorded-before-save",
                    )
                    .unwrap();
                recorded += 1;
            }
        }
    }
    recorded
}

#[test]
fn native_scoped_save_uses_only_admitted_knowledge_and_recovers_original_observations() {
    use whipplescript_store::branches::resolution_origin::ResolutionObservation;
    use whipplescript_store::vcs::resolution_scope::ResolutionPayloadUse;
    for foreign in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (shared, command, inputs, token) = admitted_content_fixture(dir.path(), "dog", "lion");
        let mut wb = shared.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let scope = resolution_scope::original(&command).unwrap();
        let mut recorded_scope = serde_json::to_value(&scope).unwrap();
        if foreign {
            recorded_scope["compartment"] = "foreign private knowledge".into();
        }
        let recorded_scope = serde_json::from_value(recorded_scope).unwrap();
        let ActionBasis::Version { version_ref: base } = &command.resources["target"].basis else {
            panic!("base")
        };
        assert_eq!(record_scope_fixture(dir.path(), base, &recorded_scope), 1);
        let (_, _, chat): (String, String, String) = serde_json::from_str(&command.scope).unwrap();
        let (_, _, path): (String, String, String) = serde_json::from_str(
            command.resources["target"]
                .resource
                .selector
                .as_deref()
                .unwrap(),
        )
        .unwrap();
        wb.engagements[&chat].write_file(&path, "tiger").unwrap();
        let head = wb.engagements[&chat]
            .commit_turn("competing work fixture")
            .unwrap()
            .unwrap()
            .0;
        let mut runtime = editor_runtime(&wb, &command, dir.path());
        configure_native_files(runtime.kernel().store());
        let admission = wb
            .deliver_editor_file_save(&context, &inputs, &command, &mut runtime)
            .unwrap()
            .receipt;
        let mut executed = Vec::new();
        for _ in 0..2 {
            let effects = wb
                .advance_editor_file_save(&context, &inputs, &command, &admission, &mut runtime)
                .unwrap();
            assert_eq!(effects.len(), 1);
            executed.push(effects[0].clone());
            wb.execute_editor_file_save_effect(
                &context,
                &inputs,
                &command,
                &admission,
                &effects[0],
                &mut runtime,
            )
            .unwrap();
        }
        let result = wb
            .read_editor_file_save_result(&context, &inputs, &command, &admission, &runtime)
            .unwrap();
        let write = result
            .effects
            .iter()
            .find(|effect| effect.effect_id == executed[1])
            .unwrap();
        let attempt = EditorFileSaveAttempt {
            effect_id: &write.effect_id,
            run_id: &write.attempts[0].run_id,
        };
        if foreign {
            assert!(wb
                .inspect_editor_file_save_attempt(
                    &context, &inputs, &command, &admission, attempt, &runtime
                )
                .unwrap()
                .is_none());
            assert_eq!(
                wb.engagements[&chat].observe().unwrap().recorded_cut,
                Some(head)
            );
        } else {
            let recovered = wb
                .inspect_editor_file_save_attempt(
                    &context, &inputs, &command, &admission, attempt, &runtime,
                )
                .unwrap()
                .unwrap();
            assert_eq!(recovered.accepted_content, "liger");
            assert_eq!(recovered.receipt.resolution_scope, scope);
            assert_eq!(recovered.receipt.binding.executing_principal, "alice");
            assert!(!recovered.receipt.observations.is_empty());
            assert!(recovered.receipt.observations.iter().any(|lookup|
                lookup.payload_use == ResolutionPayloadUse::Applied && matches!(&lookup.observed, ResolutionObservation::Recorded { origin, .. } if origin.operation_id == "original-correction")
            ));
            // The runtime's retained v2 result is the source on repeated reads.
            assert_eq!(
                wb.inspect_editor_file_save_attempt(
                    &context, &inputs, &command, &admission, attempt, &runtime
                )
                .unwrap()
                .unwrap()
                .receipt_json,
                recovered.receipt_json
            );
        }
    }
}

#[path = "resolution_recording_factory_tests.rs"]
mod recording;
