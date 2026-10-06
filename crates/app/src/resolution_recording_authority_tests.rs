//! Actual authentication changes fence prepared correction work.
use super::*;
use crate::LockUnpoisoned;

#[test]
fn correction_preparation_delivery_and_history_fence_actual_device_revocation() {
    let root = tempfile::tempdir().unwrap();
    let (shared, chat_id, token) =
        crate::file_action_factory::tests::authenticated_chat_fixture(root.path());
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let scope = crate::account::account_scope("alice");
    let mut device = crate::account::DeviceRecord {
        id: "correction-device".into(),
        op: crate::account::RecordOp::Upsert,
        label: "Correction fixture".into(),
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
    let inputs = NativeActionInputCustody::open(
        root.path().join("inputs.sqlite"),
        wb.home_id().as_str(),
        4096,
    )
    .unwrap();
    let corrections =
        whipplescript_store::vcs_resolution_recording::ResolutionRecordingInput::new(vec![
            whipplescript_store::text_merge::RegionResolution {
                base_text: "fixture base".into(),
                ours_text: "fixture local".into(),
                theirs_text: "fixture remote".into(),
                resolution_text: String::new(),
            },
        ])
        .unwrap();
    let request = EditorCorrections {
        chat_id: &chat_id,
        request_id: "device-correction",
        path: "never-created.txt",
        corrections: &corrections,
    };
    let prepared = wb
        .prepare_editor_corrections(&context, &inputs, &request, None)
        .unwrap();
    let command = wb
        .admit_editor_corrections(&context, &inputs, &request)
        .unwrap()
        .command;
    let delivery = wb
        .prepare_native_corrections(&context, &inputs, &command, &command.policy)
        .unwrap();
    let history = wb
        .prepare_correction_inspection(&context, &command)
        .unwrap();
    for basis in [&prepared.basis, &delivery.basis, &history.basis] {
        assert!(wb.store_mut().with_dispatch_basis(basis, || ()).is_ok());
    }
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
        .prepare_editor_corrections(&context, &inputs, &request, None)
        .is_err());
    assert!(wb
        .prepare_native_corrections(&context, &inputs, &command, &command.policy)
        .is_err());
    assert!(wb
        .prepare_correction_inspection(&context, &command)
        .is_err());
    for basis in [&prepared.basis, &delivery.basis, &history.basis] {
        assert!(wb
            .store_mut()
            .with_dispatch_basis(basis, || panic!(
                "revoked device used prepared correction authority"
            ))
            .is_err());
    }
}
