use super::*;
use crate::office_home_admission::source::{HubStaffSource, SourceCheck, VerifiedSourceSession};

const BEARER: &str = "synthetic-native-office-bearer";

fn configure(wb: &mut Workbench) {
    wb.enroll_office_profile_for_test("office-admin");
    wb.configure_office_staff_source(HubStaffSource::at("https://auth.example").unwrap())
        .unwrap();
}

fn source_context(wb: &mut Workbench) -> (AuthenticatedActionContext, String) {
    let source = wb.office_staff_verifier().unwrap();
    let now = crate::account::session_now_ms();
    static SOURCE_MINT: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let minted = *SOURCE_MINT.get_or_init(|| now.saturating_sub(1000));
    let reference = crate::account_session::session_id(BEARER);
    let lease = wb
        .observe_office_staff_check(
            &source,
            &reference,
            SourceCheck::Verified(VerifiedSourceSession::for_test(
                source.issuer(),
                "alice",
                crate::account_session::AccountSessionEvidence {
                    session_ref: reference.clone(),
                    method: "passkey".into(),
                    issued_at_ms: minted,
                    expires_at_ms: minted + 7_200_000,
                },
                now,
            )),
        )
        .unwrap();
    let home = wb.home_id().clone();
    let token = wb.home_admissions.open_office(&home, &lease).unwrap();
    let context = wb.office_staff_action_context(&lease, &token).unwrap();
    (context, token.encode())
}

#[test]
fn office_background_save_keeps_exact_live_source_and_stops_between_read_and_write() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, inputs, _) = admitted_fixture(dir.path());
    let mut wb = shared.lock_unpoisoned();
    configure(&mut wb);
    let (context, token) = source_context(&mut wb);
    let grant = wb
        .authorize_editor_file_save_dispatch(&context, &inputs, &command, "office-dispatch")
        .unwrap();
    let retry = wb
        .authorize_editor_file_save_dispatch(&context, &inputs, &command, "office-dispatch")
        .unwrap();
    assert!(retry.replayed);
    let snapshot = wb
        .store_ref()
        .committed_record_snapshot(&grant.grant_ref, "authorize")
        .unwrap()
        .unwrap();
    assert!(!snapshot.contains(BEARER));
    assert!(!snapshot.contains(&token));
    let saved: Signed<Grant> = serde_json::from_str(&snapshot).unwrap();
    assert!(matches!(saved.body.source, Source::OfficeStaff { .. }));
    assert_eq!(saved.body.actor, "alice");
    let scoped = wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .unwrap();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    super::super::super::tests::configure_native_files(runtime.kernel().store());
    let admission = wb
        .deliver_editor_file_save(&scoped.context, &inputs, &command, &mut runtime)
        .unwrap()
        .receipt;
    let reads = wb
        .advance_editor_file_save(&scoped.context, &inputs, &command, &admission, &mut runtime)
        .unwrap();
    wb.execute_editor_file_save_effect(
        &scoped.context,
        &inputs,
        &command,
        &admission,
        &reads[0],
        &mut runtime,
    )
    .unwrap();
    let writes = wb
        .advance_editor_file_save(&scoped.context, &inputs, &command, &admission, &mut runtime)
        .unwrap();
    let prepared = wb
        .prepare_native_editor_action(&scoped.context, &inputs, &command, &command.policy)
        .unwrap();
    let home = wb.home_id().clone();
    wb.home_admissions.revoke(&home, context.actor());
    assert!(wb
        .store_mut()
        .with_dispatch_basis(&prepared.basis, || panic!("revoked office action ran"))
        .is_err());
    assert!(wb
        .execute_editor_file_save_effect(
            &scoped.context,
            &inputs,
            &command,
            &admission,
            &writes[0],
            &mut runtime
        )
        .is_err());
    assert!(wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .is_err());
}

#[test]
fn office_background_grant_cannot_switch_to_a_new_admission_for_the_same_person() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, inputs, _) = admitted_fixture(dir.path());
    let mut wb = shared.lock_unpoisoned();
    configure(&mut wb);
    let (context, _) = source_context(&mut wb);
    let grant = wb
        .authorize_editor_file_save_dispatch(&context, &inputs, &command, "office-dispatch")
        .unwrap();
    let lease = wb.office_staff_lease(BEARER).unwrap();
    let home = wb.home_id().clone();
    let new_token = wb.home_admissions.open_office(&home, &lease).unwrap();
    let fresh = wb.office_staff_action_context(&lease, &new_token).unwrap();
    assert!(wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .is_err());
    assert!(wb
        .authorize_editor_file_save_dispatch(&fresh, &inputs, &command, "office-dispatch")
        .is_err());
    let new_grant = wb
        .authorize_editor_file_save_dispatch(&fresh, &inputs, &command, "new-admission-dispatch")
        .unwrap();
    assert!(wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &new_grant.grant_ref)
        .is_ok());
}

#[test]
fn office_background_grant_is_inert_after_restart_even_with_fresh_source_verification() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, inputs, _) = admitted_fixture(dir.path());
    let grant_ref = {
        let mut wb = shared.lock_unpoisoned();
        configure(&mut wb);
        let (context, _) = source_context(&mut wb);
        wb.authorize_editor_file_save_dispatch(&context, &inputs, &command, "office-dispatch")
            .unwrap()
            .grant_ref
    };
    drop(shared);
    let shared = crate::open_workbench(dir.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    configure(&mut wb);
    assert!(wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant_ref)
        .is_err());
    let _ = source_context(&mut wb);
    assert!(wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant_ref)
        .is_err());
    assert!(wb
        .discover_editor_file_save_dispatch(&grant_ref)
        .unwrap()
        .is_some());
}

#[test]
fn office_driver_completes_a_saved_result_during_source_outage_without_renewal() {
    let dir = tempfile::tempdir().unwrap();
    let config = NativeActionStorageConfig {
        input_byte_limit: 4096,
        file_lease: whipplescript_kernel::file_lease::FileLeasePolicy::new(17).unwrap(),
    };
    let (shared, command, storage, _) =
        super::super::super::tests::home_storage_fixture(dir.path(), config);
    let mut wb = shared.lock_unpoisoned();
    configure(&mut wb);
    let (context, _) = source_context(&mut wb);
    let before = wb.office_staff_lease(BEARER).unwrap();
    let grant = wb
        .authorize_editor_file_save_dispatch(&context, storage.inputs(), &command, "office-driver")
        .unwrap();
    let source = wb.office_staff_verifier().unwrap();
    let continued = wb
        .observe_office_staff_check(
            &source,
            &crate::account_session::session_id(BEARER),
            SourceCheck::Unavailable,
        )
        .unwrap();
    assert_eq!(continued.deadline_ms(), before.deadline_ms());
    let mut driver = wb
        .start_editor_file_save_driver(&storage, &command, &grant.grant_ref)
        .unwrap();
    for _ in 0..2 {
        assert!(matches!(
            wb.step_editor_file_save_driver(&storage, &mut driver)
                .unwrap(),
            NativeEditorSaveProgress::Advanced
        ));
    }
    let NativeEditorSaveProgress::Saved(result) = wb
        .step_editor_file_save_driver(&storage, &mut driver)
        .unwrap()
    else {
        panic!("office save did not settle")
    };
    assert_eq!(result.result.provenance.initiator, "alice");
    assert_eq!(result.result.provenance.executor, "alice");
    assert_eq!(
        result.result.content_hash,
        whipplescript_store::stable_hash_hex("private editor draft")
    );
    assert_eq!(
        wb.office_staff_lease(BEARER).unwrap().deadline_ms(),
        before.deadline_ms()
    );
}

#[test]
fn queued_office_work_stops_on_source_refusal_and_current_membership_removal() {
    for source_refusal in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (shared, command, inputs, _) = admitted_fixture(dir.path());
        let mut wb = shared.lock_unpoisoned();
        configure(&mut wb);
        let (context, _) = source_context(&mut wb);
        let grant = wb
            .authorize_editor_file_save_dispatch(&context, &inputs, &command, "office-dispatch")
            .unwrap();
        let scoped = wb
            .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
            .unwrap();
        let prepared = wb
            .prepare_native_editor_action(&scoped.context, &inputs, &command, &command.policy)
            .unwrap();
        if source_refusal {
            let source = wb.office_staff_verifier().unwrap();
            assert!(wb
                .observe_office_staff_check(
                    &source,
                    &crate::account_session::session_id(BEARER),
                    SourceCheck::Refused
                )
                .is_err());
        } else {
            let mut member =
                crate::org::Org::rebuild(wb.store_ref()).unwrap().members["alice"].clone();
            member.status = crate::org::MembershipStatus::Deprovisioned;
            wb.store_mut()
                .append_record(
                    crate::org::ORG_SCOPE,
                    "membership",
                    &serde_json::to_string(&member).unwrap(),
                )
                .unwrap();
        }
        assert!(wb
            .store_mut()
            .with_dispatch_basis(&prepared.basis, || panic!("revoked queued work ran"))
            .is_err());
        assert!(wb
            .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
            .is_err());
    }
}
