use super::*;
use crate::office_home_admission::source::{HubStaffSource, SourceCheck, VerifiedSourceSession};
use serde_json::Value;

const BEARER: &str = "synthetic-office-user";

fn staff(wb: &mut Workbench) -> AuthenticatedActionContext {
    let policy = crate::org::SecurityPolicyRecord {
        id: "security".into(),
        session_lifetime_secs: 7200,
        idle_timeout_secs: 120,
        ..Default::default()
    };
    wb.store_mut()
        .append_record(
            ORG_SCOPE,
            "security",
            &serde_json::to_string(&policy).unwrap(),
        )
        .unwrap();
    wb.enroll_office_profile_for_test("office-admin");
    wb.configure_office_staff_source(HubStaffSource::at("https://auth.example").unwrap())
        .unwrap();
    let source = wb.office_staff_verifier().unwrap();
    let now = crate::account::session_now_ms();
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
                    issued_at_ms: now.saturating_sub(1000),
                    expires_at_ms: now + 7_200_000,
                },
                now,
            )),
        )
        .unwrap();
    let home = wb.home_id().clone();
    let token = wb.home_admissions.open_office(&home, &lease).unwrap();
    wb.office_staff_action_context(&lease, &token).unwrap()
}

fn lease_record(wb: &Workbench) -> Value {
    let lease = wb.office_staff_lease(BEARER).unwrap();
    let rows = wb.store_ref().retained_events(lease.reference()).unwrap();
    serde_json::from_str(&rows.last().unwrap().2).unwrap()
}

fn admit(
    wb: &mut Workbench,
    context: &AuthenticatedActionContext,
    inputs: &NativeActionInputCustody,
    intent: &Intent,
) -> AdmittedEditorFileSave {
    wb.admit_editor_file_save(
        context,
        inputs,
        &intent.identity,
        &EditorFileSave {
            chat_id: &intent.chat_id,
            request_id: &intent.request_id,
            path: &intent.path,
            base_cut: &intent.base_cut,
            content: &intent.content,
        },
    )
    .unwrap()
}

#[test]
fn only_a_fresh_committed_user_intent_advances_office_activity() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, intent, _) = setup(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = staff(&mut wb);
    let inputs = NativeActionInputCustody::open(
        dir.path().join("office-inputs.sqlite"),
        wb.home_id().as_str(),
        4096,
    )
    .unwrap();
    let before = lease_record(&wb);
    let mut admitted = admit(&mut wb, &context, &inputs, &intent);
    assert!(!admitted.replayed);
    let current = wb
        .record_editor_user_activity(&context, &inputs, &mut admitted)
        .unwrap();
    let after = lease_record(&wb);
    assert_eq!(
        after["revision"].as_u64().unwrap(),
        before["revision"].as_u64().unwrap() + 1
    );
    assert!(after["last_activity_ms"].as_u64() >= before["last_activity_ms"].as_u64());
    for field in [
        "source_mint_ms",
        "office_started_ms",
        "last_verified_ms",
        "source_expiry_ms",
        "absolute_deadline_ms",
        "idle_timeout_ms",
    ] {
        assert_eq!(after[field], before[field], "{field}");
    }
    wb.record_editor_user_activity(&current, &inputs, &mut admitted)
        .unwrap();
    assert_eq!(lease_record(&wb), after);
    let mut replay = admit(&mut wb, &current, &inputs, &intent);
    assert!(replay.replayed);
    wb.record_editor_user_activity(&current, &inputs, &mut replay)
        .unwrap();
    assert_eq!(lease_record(&wb), after);
    let grant = wb
        .authorize_editor_file_save_dispatch(
            &current,
            &inputs,
            &admitted.command,
            "activity-dispatch",
        )
        .unwrap();
    let scoped = wb
        .load_editor_file_save_dispatch_authority(&inputs, &admitted.command, &grant.grant_ref)
        .unwrap();
    wb.prepare_native_editor_action(
        &scoped.context,
        &inputs,
        &admitted.command,
        &admitted.command.policy,
    )
    .unwrap();
    wb.observe_native_file_content(&current, &intent.chat_id, &intent.path)
        .unwrap();
    assert_eq!(lease_record(&wb), after);
}

#[test]
fn failed_activity_keeps_the_original_admission_and_cannot_renew_by_retry() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, intent, _) = setup(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = staff(&mut wb);
    let inputs = NativeActionInputCustody::open(
        dir.path().join("office-inputs.sqlite"),
        wb.home_id().as_str(),
        4096,
    )
    .unwrap();
    let before = lease_record(&wb);
    let mut admitted = admit(&mut wb, &context, &inputs, &intent);
    let reference = wb
        .office_staff_lease(BEARER)
        .unwrap()
        .reference()
        .to_owned();
    let fault = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    fault.execute_batch(&format!("CREATE TRIGGER fail_activity BEFORE INSERT ON events WHEN NEW.kind = '{}' BEGIN SELECT RAISE(ABORT, 'activity unavailable'); END;", crate::office_home_admission::lease::LEASE_KIND)).unwrap();
    assert!(wb
        .record_editor_user_activity(&context, &inputs, &mut admitted)
        .is_err());
    assert!(admitted.user_activity.is_none());
    assert_eq!(lease_record(&wb), before);
    fault.execute_batch("DROP TRIGGER fail_activity").unwrap();
    let mut replay = admit(&mut wb, &context, &inputs, &intent);
    assert!(replay.replayed);
    wb.record_editor_user_activity(&context, &inputs, &mut replay)
        .unwrap();
    assert_eq!(lease_record(&wb), before);
    assert!(!wb
        .store_ref()
        .retained_events(&reference)
        .unwrap()
        .is_empty());
}

#[test]
fn admission_revocation_between_intent_and_activity_prevents_idle_extension() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, intent, _) = setup(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = staff(&mut wb);
    let inputs = NativeActionInputCustody::open(
        dir.path().join("office-inputs.sqlite"),
        wb.home_id().as_str(),
        4096,
    )
    .unwrap();
    let before = lease_record(&wb);
    let mut admitted = admit(&mut wb, &context, &inputs, &intent);
    let home = wb.home_id().clone();
    wb.home_admissions.revoke(&home, context.actor());
    assert!(wb
        .record_editor_user_activity(&context, &inputs, &mut admitted)
        .is_err());
    assert_eq!(lease_record(&wb), before);
    assert!(wb
        .authorize_editor_file_save_dispatch(
            &context,
            &inputs,
            &admitted.command,
            "revoked-activity"
        )
        .is_err());
}

#[tokio::test]
async fn typed_office_save_submission_records_activity_once_and_exposes_the_original_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, intent, _) = setup(dir.path());
    let (token, before) = {
        let mut wb = shared.lock_unpoisoned();
        let _ = staff(&mut wb);
        let home = wb.home_id().clone();
        let lease = wb.office_staff_lease(BEARER).unwrap();
        let token = wb
            .home_admissions
            .open_office(&home, &lease)
            .unwrap()
            .encode();
        (token, lease_record(&wb))
    };
    let app = crate::file_action_submission_routes::routes(
        shared.clone(),
        NativeActionStorageConfig {
            input_byte_limit: 4096,
            file_lease: whipplescript_kernel::file_lease::FileLeasePolicy::new(17).unwrap(),
        },
    );
    let body = serde_json::json!({
        "expected_actor": "alice", "identity": intent.identity,
        "path": intent.path, "base_cut": intent.base_cut, "content": intent.content,
        "dispatch_request_id": "office-activity-dispatch",
    });
    let send = || {
        let request = Request::builder()
            .method("POST")
            .uri(format!("/chats/{}/file-actions/save", intent.chat_id))
            .header("authorization", format!("Bearer {BEARER}"))
            .header(HOME_ADMISSION_HEADER, &token)
            .header("idempotency-key", &intent.identity.request_id)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        app.clone().oneshot(request)
    };
    let response = send().await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let result: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(result["actor"], "alice");
    assert_eq!(result["replayed"], false);
    assert_eq!(result["dispatch"]["state"], "authorized");
    let after = lease_record(&shared.lock_unpoisoned());
    assert_eq!(
        after["revision"].as_u64().unwrap(),
        before["revision"].as_u64().unwrap() + 1
    );
    assert_eq!(after["last_verified_ms"], before["last_verified_ms"]);
    let grant_ref = result["dispatch"]["grant_ref"].as_str().unwrap();
    let grant: Value = serde_json::from_str(
        &shared
            .lock_unpoisoned()
            .store_ref()
            .committed_record_snapshot(grant_ref, "authorize")
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        grant["body"]["expires_at_ms"].as_u64(),
        Some(
            after["last_activity_ms"].as_u64().unwrap()
                + after["idle_timeout_ms"].as_u64().unwrap(),
        )
    );
    let response = send().await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let retry: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(retry["replayed"], true);
    assert_eq!(retry["dispatch"]["state"], "authorized");
    assert_eq!(
        retry["dispatch"]["grant_ref"],
        result["dispatch"]["grant_ref"]
    );
    assert_eq!(lease_record(&shared.lock_unpoisoned()), after);
}
