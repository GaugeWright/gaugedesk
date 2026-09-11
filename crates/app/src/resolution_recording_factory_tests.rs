//! Home-authenticated admission exercises the real factory, input custody and outbox.
use super::*;
use whipplescript_store::{
    text_merge::RegionResolution, vcs_resolution_recording::ResolutionRecordingInput,
};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CorrectionIntent {
    chat_id: String,
    request_id: String,
    path: String,
    corrections: ResolutionRecordingInput,
}
fn input(text: &str) -> ResolutionRecordingInput {
    ResolutionRecordingInput::new(vec![RegionResolution {
        base_text: "asserted base\r\n".into(),
        ours_text: "asserted local".into(),
        theirs_text: "asserted remote".into(),
        resolution_text: text.into(),
    }])
    .unwrap()
}
fn corrections(intent: &Intent) -> CorrectionIntent {
    CorrectionIntent {
        chat_id: intent.chat_id.clone(),
        request_id: "correction-1".into(),
        path: "never-created.txt".into(),
        corrections: input(""),
    }
}
fn recording_router(wb: SharedWorkbench, input_path: std::path::PathBuf, budget: usize) -> Router {
    Router::new().merge(crate::home_routes::routes()).route("/corrections", post(move |
        State(wb): State<SharedWorkbench>, Extension(context): Extension<AuthenticatedActionContext>, Json(intent): Json<CorrectionIntent>
    | {
        let path = input_path.clone();
        async move {
            let mut wb = wb.lock_unpoisoned();
            let custody = NativeActionInputCustody::open(path, wb.home_id().as_str(), budget).unwrap();
            match wb.admit_editor_corrections(&context, &custody, &EditorCorrections {
                chat_id: &intent.chat_id, request_id: &intent.request_id, path: &intent.path,
                corrections: &intent.corrections,
            }) {
                Ok(admitted) => (StatusCode::ACCEPTED, Json(serde_json::json!({"command": admitted.command, "replayed": admitted.replayed}))).into_response(),
                Err(reason) => (StatusCode::FORBIDDEN, reason).into_response(),
            }
        }
    })).route_layer(axum::middleware::from_fn_with_state(wb.clone(), crate::home_routes::require_home_admission)).with_state(wb)
}
async fn submit(
    app: &Router,
    token: &str,
    admission: &str,
    intent: &CorrectionIntent,
) -> (StatusCode, String) {
    send(
        app,
        "/corrections",
        Some(token),
        Some(admission),
        &serde_json::to_string(intent).unwrap(),
    )
    .await
}

#[tokio::test]
async fn correction_home_admission_retains_exact_input_and_outbox_without_a_file_base() {
    let dir = tempfile::tempdir().unwrap();
    let input_path = dir.path().join("inputs.sqlite");
    let (wb, file, token) = setup(dir.path());
    let mut intent = corrections(&file);
    let app = recording_router(wb.clone(), input_path.clone(), 4096);
    let body = serde_json::to_string(&intent).unwrap();
    for token in [None, Some(token.as_str())] {
        assert_eq!(
            send(&app, "/corrections", token, None, &body).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    let admission = home_admission(&app, &token).await;
    let (status, response) = submit(&app, &token, &admission, &intent).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{response}");
    let result: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(result["replayed"], false);
    let command: HostActionCommand = serde_json::from_value(result["command"].clone()).unwrap();
    assert_eq!(command.operation, "resolution.record");
    assert_eq!(command.provenance.initiator, "alice");
    assert_eq!(command.provenance.executor, "alice");
    assert_eq!(command.provenance.origin, "editor.corrections");
    assert!(command.provenance.causes.is_empty());
    assert!(command.provenance.delegation.is_empty());
    assert_eq!(command.resources.len(), 1);
    assert_eq!(
        command.resources["resolutions"].resource.writable,
        Some(true)
    );
    assert_eq!(command.inputs.len(), 1);
    assert_eq!(command.inputs["corrections"].handle, "admitted_corrections");
    assert!(!response.contains("asserted base"));
    let action =
        whipplescript_kernel::resolution_recording::ResolutionRecordingAction::compile().unwrap();
    assert_eq!(command.program_version_ref, action.action().version_ref());
    assert_eq!(command.input_schema_ref, action.action().input_schema_ref());
    let scope = command.instance_ref().unwrap();
    {
        let mut wb = wb.lock_unpoisoned();
        let custody =
            NativeActionInputCustody::open(&input_path, wb.home_id().as_str(), 4096).unwrap();
        assert_eq!(
            custody
                .resolve(&command.inputs["corrections"])
                .unwrap()
                .content,
            serde_json::to_string(&intent.corrections).unwrap()
        );
        let delivery = wb
            .store_mut()
            .committed_dispatch::<ProductActionAdmission>(&scope, &intent.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(delivery.command, command);
        let engagement = &wb.engagements[&file.chat_id];
        assert!(engagement
            .read_file(&wb.engagement_workspace_path(&file.chat_id, &intent.path))
            .is_err());
        assert_eq!(
            engagement
                .read_file(&wb.engagement_workspace_path(&file.chat_id, &file.path))
                .unwrap(),
            "recorded base"
        );
        let key = SigningKey::from_seed(&wb.governance_seed()).unwrap();
        let retained = crate::action_policy::load_action_policy(
            wb.store_ref(),
            &ActionPolicyIdentity {
                issuer: command.issuer.clone(),
                scope: command.scope.clone(),
                request_id: command.request_id.clone(),
            },
            &command.policy,
            &GovernanceRootVerifier::new(wb.authority().clone(), key.public_key()),
        )
        .unwrap();
        let signed: serde_json::Value = serde_json::from_str(retained.signed_envelope()).unwrap();
        assert!(!retained.signed_envelope().contains("file:/action/"));
        assert!(!retained.signed_envelope().contains("admitted_target"));
        assert!(retained
            .signed_envelope()
            .contains("vcs.record_resolutions"));
        assert!(signed.is_object());
        let context = wb.authenticate_action_context(&token).unwrap();
        let authority = current_authority(
            wb.store_ref(),
            wb.home_id(),
            &context,
            &EditorFileSave {
                chat_id: &file.chat_id,
                request_id: &file.request_id,
                path: &file.path,
                base_cut: &file.base_cut,
                content: &file.content,
            },
        )
        .unwrap();
        assert_eq!(
            command.resources["resolutions"]
                .resource
                .selector
                .as_deref()
                .unwrap(),
            serde_json::to_string(&authority.resolution_scope).unwrap()
        );
        assert!(
            resolution_scope::original(&command).is_err(),
            "recording is not a read-only file-save grant"
        );
    }
    drop(app);
    drop(wb);
    let wb = crate::open_workbench(dir.path()).unwrap();
    wb.lock_unpoisoned().set_identity_provider(Some(Arc::new(
        crate::identity::LoopbackIdentityProvider::new(),
    )));
    let renewed = wb
        .lock_unpoisoned()
        .mint_account_session("alice", "passkey", 3600)
        .unwrap();
    let app = recording_router(wb.clone(), input_path, 4096);
    let admission = home_admission(&app, &renewed).await;
    let (status, replay) = submit(&app, &renewed, &admission, &intent).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{replay}");
    let replay: serde_json::Value = serde_json::from_str(&replay).unwrap();
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["command"], result["command"]);
    intent.corrections = input("changed assertion");
    assert_eq!(
        submit(&app, &renewed, &admission, &intent).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        wb.lock_unpoisoned()
            .store_ref()
            .records(&scope, ProductActionAdmission::KIND)
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn correction_admission_uses_committed_membership_and_target_permission() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, file, token) = setup(dir.path());
    let intent = corrections(&file);
    let app = recording_router(wb.clone(), dir.path().join("inputs.sqlite"), 4096);
    let admission = home_admission(&app, &token).await;
    membership(&mut wb.lock_unpoisoned(), "alice", "consultant");
    let (status, reason) = submit(&app, &token, &admission, &intent).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reason}");
    assert!(reason.contains("current grant"), "{reason}");
    {
        let mut wb = wb.lock_unpoisoned();
        membership(&mut wb, "alice", "owner");
        let id = wb
            .library
            .current_target_set(&file.chat_id)
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
        assert!(wb.library.work_targets[&id].capabilities.propose);
    }
    let (status, reason) = submit(&app, &token, &admission, &intent).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reason}");
    assert!(reason.contains("target authority"), "{reason}");
}

#[tokio::test]
async fn correction_admission_refuses_budgets_controls_and_unselected_paths() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, file, token) = setup(dir.path());
    let mut intent = corrections(&file);
    let small = recording_router(wb.clone(), dir.path().join("small.sqlite"), 1);
    let admission = home_admission(&small, &token).await;
    let (status, reason) = submit(&small, &token, &admission, &intent).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reason}");
    assert!(reason.contains("byte budget"), "{reason}");
    let app = recording_router(wb.clone(), dir.path().join("inputs.sqlite"), 4096);
    for path in [
        "../secret",
        "targets/unselected/file.txt",
        ".gaugedesk-runtime/log.sqlite",
        "src\\file",
        "src\0file",
    ] {
        intent.path = path.into();
        let (status, reason) = submit(&app, &token, &admission, &intent).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path:?}: {reason}");
    }
    intent.path = "never-created.txt".into();
    let (status, response) = submit(&app, &token, &admission, &intent).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{response}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&response).unwrap()["replayed"],
        false
    );
}

#[test]
fn correction_factory_refuses_foreign_custody_and_revoked_context() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, file, token) = setup(dir.path());
    let mut wb = wb.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let body = input("authored");
    let request = EditorCorrections {
        chat_id: &file.chat_id,
        request_id: "correction-1",
        path: "missing.txt",
        corrections: &body,
    };
    let foreign =
        NativeActionInputCustody::open(dir.path().join("foreign.sqlite"), "other-home", 4096)
            .unwrap();
    assert!(wb
        .admit_editor_corrections(&context, &foreign, &request)
        .err()
        .unwrap()
        .contains("another Home"));
    let own =
        NativeActionInputCustody::open(dir.path().join("own.sqlite"), wb.home_id().as_str(), 4096)
            .unwrap();
    wb.revoke_account_session(&token);
    assert!(wb
        .admit_editor_corrections(&context, &own, &request)
        .err()
        .unwrap()
        .contains("not durably active"));
}

#[path = "resolution_recording_delivery_tests.rs"]
mod delivery;

#[path = "resolution_recording_execution_tests.rs"]
mod execution;

#[tokio::test]
async fn correction_home_refuses_command_publication_when_input_attestation_is_not_durable() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, file, token) = setup(dir.path());
    let intent = corrections(&file);
    let app = recording_router(wb.clone(), dir.path().join("inputs.sqlite"), 4096);
    let admission = home_admission(&app, &token).await;
    let fault = rusqlite::Connection::open(wb.lock_unpoisoned().store_ref().path()).unwrap();
    let count = || {
        fault
            .query_row(
                "SELECT COUNT(*) FROM events WHERE kind = ?1",
                [gaugedesk_store::command_dispatch::DISPATCH_KIND],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
    };
    let before = count();
    fault.execute_batch("CREATE TRIGGER lose_input_mapping BEFORE INSERT ON command_receipts WHEN NEW.scope_id LIKE 'native-input-binding:%' BEGIN SELECT RAISE(ABORT, 'lost original input mapping'); END;").unwrap();
    let (status, reason) = submit(&app, &token, &admission, &intent).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reason}");
    assert!(reason.contains("input mapping refused"), "{reason}");
    assert_eq!(count(), before);
    fault
        .execute_batch("DROP TRIGGER lose_input_mapping")
        .unwrap();
    let (status, response) = submit(&app, &token, &admission, &intent).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{response}");
    let response: serde_json::Value = serde_json::from_str(&response).unwrap();
    let command: HostActionCommand = serde_json::from_value(response["command"].clone()).unwrap();
    let wb = wb.lock_unpoisoned();
    let key = SigningKey::from_seed(&wb.governance_seed()).unwrap();
    let retained = crate::action_input_binding::load_input_binding(
        wb.store_ref(),
        &command.issuer,
        wb.home_id().as_str(),
        &command.inputs["corrections"],
        &key.public_key(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        retained.content_hash(),
        whipplescript_store::stable_hash_hex(&serde_json::to_string(&intent.corrections).unwrap())
    );
    assert_eq!(count(), before + 1);
}
