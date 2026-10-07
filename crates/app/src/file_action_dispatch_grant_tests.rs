use super::super::tests::{admitted_fixture, editor_runtime};
use super::*;
use crate::LockUnpoisoned;
use gaugedesk_whip_runtime::host_actions::RuntimeStore;

#[test]
fn retained_dispatch_grant_survives_restart_and_revocation_fences_every_use() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, inputs, token) = admitted_fixture(dir.path());
    let grant_ref = {
        let mut wb = shared.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let grant = wb
            .authorize_editor_file_save_dispatch(&context, &inputs, &command, "background-1")
            .unwrap();
        assert!(!grant.replayed);
        let retry = wb
            .authorize_editor_file_save_dispatch(&context, &inputs, &command, "background-1")
            .unwrap();
        assert!(retry.replayed);
        assert_eq!(retry.grant_ref, grant.grant_ref);
        let events = wb.store_ref().retained_events(&grant.grant_ref).unwrap();
        assert_eq!(events.len(), 1);
        assert!(!events[0].2.contains(&token));
        assert!(!events[0].2.contains("private editor draft"));
        let data: Signed<Grant> = serde_json::from_str(&events[0].2).unwrap();
        assert_eq!(data.body.actor, "alice");
        assert_eq!(
            data.body.original_admission.fingerprint,
            command.fingerprint().unwrap()
        );
        grant.grant_ref
    };
    drop(shared);
    let shared = crate::open_workbench(dir.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let authority = wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant_ref)
        .unwrap();
    let mut runtime = editor_runtime(&wb, &command, dir.path());
    super::super::tests::configure_native_files(runtime.kernel().store());
    let admission = wb
        .deliver_editor_file_save(&authority.context, &inputs, &command, &mut runtime)
        .unwrap()
        .receipt;
    let effects = wb
        .advance_editor_file_save(
            &authority.context,
            &inputs,
            &command,
            &admission,
            &mut runtime,
        )
        .unwrap();
    assert_eq!(effects.len(), 1);
    wb.execute_editor_file_save_effect(
        &authority.context,
        &inputs,
        &command,
        &admission,
        &effects[0],
        &mut runtime,
    )
    .unwrap();
    let writes = wb
        .advance_editor_file_save(
            &authority.context,
            &inputs,
            &command,
            &admission,
            &mut runtime,
        )
        .unwrap();
    assert_eq!(writes.len(), 1);
    let prepared = wb
        .prepare_native_editor_action(&authority.context, &inputs, &command, &command.policy)
        .unwrap();
    let before = runtime
        .kernel()
        .store()
        .list_events(&admission.instance_ref)
        .unwrap();
    let current = wb.authenticate_action_context(&token).unwrap();
    wb.revoke_editor_file_save_dispatch(&current, &inputs, &command, &grant_ref)
        .unwrap();
    wb.revoke_editor_file_save_dispatch(&current, &inputs, &command, &grant_ref)
        .unwrap();
    assert_eq!(wb.store_ref().retained_events(&grant_ref).unwrap().len(), 2);
    assert!(wb
        .store_mut()
        .with_dispatch_basis(&prepared.basis, || panic!("revoked grant executed"))
        .is_err());
    assert!(wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant_ref)
        .is_err());
    assert!(wb
        .execute_editor_file_save_effect(
            &authority.context,
            &inputs,
            &command,
            &admission,
            &writes[0],
            &mut runtime
        )
        .is_err());
    assert!(wb
        .deliver_editor_file_save(&authority.context, &inputs, &command, &mut runtime)
        .is_err());
    assert!(wb
        .advance_editor_file_save(
            &authority.context,
            &inputs,
            &command,
            &admission,
            &mut runtime
        )
        .is_err());
    assert!(wb
        .read_editor_file_save_result(&authority.context, &inputs, &command, &admission, &runtime)
        .is_err());
    assert_eq!(
        runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap(),
        before
    );
    assert!(wb
        .authorize_editor_file_save_dispatch(&current, &inputs, &command, "background-1")
        .is_err());
    let renewed = wb
        .authorize_editor_file_save_dispatch(&current, &inputs, &command, "background-2")
        .unwrap();
    assert_ne!(renewed.grant_ref, grant_ref);
    let active = wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &renewed.grant_ref)
        .unwrap();
    wb.execute_editor_file_save_effect(
        &active.context,
        &inputs,
        &command,
        &admission,
        &writes[0],
        &mut runtime,
    )
    .unwrap();
    // Revoking the source session invalidates even the newly issued grant.
    wb.revoke_account_session(&token);
    assert!(wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &renewed.grant_ref)
        .is_err());
    assert!(wb
        .advance_editor_file_save(&active.context, &inputs, &command, &admission, &mut runtime)
        .is_err());
}

#[test]
fn scoped_authority_cannot_mint_commands_renew_grants_or_change_the_admitted_command() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, inputs, token) = admitted_fixture(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let grant = wb
        .authorize_editor_file_save_dispatch(&context, &inputs, &command, "background")
        .unwrap();
    let scoped = wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .unwrap();
    let (_, _, chat): (String, String, String) = serde_json::from_str(&command.scope).unwrap();
    let base = match &command.resources["target"].basis {
        ActionBasis::Version { version_ref } => version_ref,
        _ => panic!("expected base"),
    };
    let identity = wb
        .prepare_editor_file_save_request(&context, &chat, "note.txt", "another-save")
        .unwrap();
    let error = wb
        .admit_editor_file_save(
            &scoped.context,
            &inputs,
            &identity,
            &EditorFileSave {
                chat_id: &chat,
                request_id: "another-save",
                path: "note.txt",
                base_cut: base,
                content: "not admitted",
            },
        )
        .err()
        .unwrap();
    assert!(error.contains("action-scoped authority"), "{error}");
    assert!(wb
        .authorize_editor_file_save_dispatch(&scoped.context, &inputs, &command, "renew")
        .is_err());
    assert!(wb
        .revoke_editor_file_save_dispatch(&scoped.context, &inputs, &command, &grant.grant_ref)
        .is_err());
    let idp = AuthenticatedActionContext::identity_provider(
        context.actor().clone(),
        AuthorityAttributes::default(),
    );
    assert!(wb
        .authorize_editor_file_save_dispatch(&idp, &inputs, &command, "idp-background")
        .unwrap_err()
        .contains("durable revocable"));
    for mutation in 0..4 {
        let mut changed = command.clone();
        match mutation {
            0 => changed.request_id.push_str("-other"),
            1 => changed
                .inputs
                .get_mut("content")
                .unwrap()
                .version_ref
                .push_str("-other"),
            2 => changed.policy.epoch += 1,
            _ => changed.provenance.executor = "mallory".into(),
        }
        assert!(wb
            .load_editor_file_save_dispatch_authority(&inputs, &changed, &grant.grant_ref)
            .is_err());
    }
    let fresh = wb.mint_account_session("alice", "passkey", 3600).unwrap();
    let fresh = wb.authenticate_action_context(&fresh).unwrap();
    assert!(wb
        .authorize_editor_file_save_dispatch(&fresh, &inputs, &command, "background")
        .unwrap_err()
        .contains("changed meaning"));
    let before = wb.store_ref().retained_events(&grant.grant_ref).unwrap();
    assert_eq!(before.len(), 1);
    // The matching Home key alone cannot widen the retained exact policy.
    let (target_id, _, _): (String, String, String) = serde_json::from_str(
        command.resources["target"]
            .resource
            .selector
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    let mut target = wb.library.work_targets[&target_id].clone();
    target.capabilities.propose = false;
    wb.store_mut()
        .append_record(
            LIBRARY_SCOPE,
            "work_target",
            &serde_json::to_string(&target).unwrap(),
        )
        .unwrap();
    assert!(wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .is_err());
    assert_eq!(
        wb.store_ref().retained_events(&grant.grant_ref).unwrap(),
        before
    );
}

#[test]
fn dispatch_grant_retains_original_session_expiration_and_refuses_uncommitted_admission() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, inputs, token) = admitted_fixture(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let grant = wb
        .authorize_editor_file_save_dispatch(&context, &inputs, &command, "background")
        .unwrap();
    let scoped = wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .unwrap();
    let first = wb
        .prepare_native_editor_action(&scoped.context, &inputs, &command, &command.policy)
        .unwrap();
    let ActorAuthentication::AccountSession { session_ref } = context.authentication() else {
        panic!("account")
    };
    let mut session = crate::account_auth::AccountAuth::rebuild(wb.store_ref())
        .unwrap()
        .sessions[session_ref]
        .clone();
    session.lifetime_secs += 3600;
    wb.store_mut()
        .append_record(
            crate::account_auth::ACCOUNT_AUTH_SCOPE,
            "account_auth_session",
            &serde_json::to_string(&session).unwrap(),
        )
        .unwrap();
    let later = wb
        .prepare_native_editor_action(&scoped.context, &inputs, &command, &command.policy)
        .unwrap();
    assert_eq!(first.basis.deadline(), later.basis.deadline());
    let retry = wb
        .authorize_editor_file_save_dispatch(&context, &inputs, &command, "background")
        .unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.grant_ref, grant.grant_ref);
    assert!(wb
        .store_mut()
        .with_dispatch_basis(
            &later.basis.with_deadline(std::time::UNIX_EPOCH),
            || panic!("expired grant executed")
        )
        .is_err());
    // Model an elapsed retained grant while the live session is still valid.
    let original = wb
        .store_ref()
        .committed_record_snapshot(&grant.grant_ref, "authorize")
        .unwrap()
        .unwrap();
    let mut body: Signed<Grant> = serde_json::from_str(&original).unwrap();
    body.body.expires_at_ms = Some(1);
    let key = wb
        .project_signing_key(&project_signature::command_project(&command).unwrap())
        .unwrap();
    let expired = serde_json::to_string(
        &sign(
            body.body,
            &key,
            &project_signature::command_project(&command).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let sql = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    sql.execute(
        "UPDATE commands SET snapshot_json = ?1 WHERE scope_id = ?2",
        rusqlite::params![expired, grant.grant_ref],
    )
    .unwrap();
    sql.execute(
        "UPDATE events SET payload = ?1 WHERE scope_id = ?2",
        rusqlite::params![expired, grant.grant_ref],
    )
    .unwrap();
    assert!(wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .is_err());
    assert!(wb
        .authorize_editor_file_save_dispatch(&context, &inputs, &command, "background")
        .is_err());
    session.issued_at_ms = 0;
    session.lifetime_secs = 1;
    wb.store_mut()
        .append_record(
            crate::account_auth::ACCOUNT_AUTH_SCOPE,
            "account_auth_session",
            &serde_json::to_string(&session).unwrap(),
        )
        .unwrap();
    assert!(wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .is_err());
    // A prepared signature without a committed original action cannot mint a grant.
    let fresh = wb.mint_account_session("alice", "passkey", 3600).unwrap();
    let fresh = wb.authenticate_action_context(&fresh).unwrap();
    let sql = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    sql.execute(
        "DELETE FROM command_receipts WHERE scope_id = ?1",
        [command.instance_ref().unwrap()],
    )
    .unwrap();
    assert!(wb
        .authorize_editor_file_save_dispatch(&fresh, &inputs, &command, "uncommitted")
        .is_err());
}

#[test]
fn missing_receipts_malformed_history_and_foreign_signatures_never_grant_dispatch() {
    for fault in 0..8 {
        let dir = tempfile::tempdir().unwrap();
        let (shared, command, inputs, token) = admitted_fixture(dir.path());
        let mut wb = shared.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let grant = wb
            .authorize_editor_file_save_dispatch(&context, &inputs, &command, "background")
            .unwrap();
        let sql = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
        match fault {
            0 => {
                sql.execute(
                    "DELETE FROM command_receipts WHERE scope_id = ?1",
                    [&grant.grant_ref],
                )
                .unwrap();
            }
            1 => {
                sql.execute(
                    "DELETE FROM commands WHERE scope_id = ?1",
                    [&grant.grant_ref],
                )
                .unwrap();
            }
            2 => {
                sql.execute("DELETE FROM events WHERE scope_id = ?1", [&grant.grant_ref])
                    .unwrap();
            }
            3 | 4 => {
                let original = wb
                    .store_ref()
                    .committed_record_snapshot(&grant.grant_ref, "authorize")
                    .unwrap()
                    .unwrap();
                let mut signed: Signed<Grant> = serde_json::from_str(&original).unwrap();
                if fault == 3 {
                    signed.body.source = Source::AccountSession {
                        session_ref: "forged".into(),
                    };
                } else {
                    signed.signature = SigningKey::from_seed(&[33; 32])
                        .unwrap()
                        .sign(&signing_bytes(&signed.body).unwrap());
                }
                let changed = serde_json::to_string(&signed).unwrap();
                sql.execute(
                    "UPDATE commands SET snapshot_json = ?1 WHERE scope_id = ?2",
                    rusqlite::params![changed, grant.grant_ref],
                )
                .unwrap();
                sql.execute(
                    "UPDATE events SET payload = ?1 WHERE scope_id = ?2",
                    rusqlite::params![changed, grant.grant_ref],
                )
                .unwrap();
            }
            5 => {
                wb.store_mut()
                    .append_record(&grant.grant_ref, REVOKE_KIND, "malformed revocation")
                    .unwrap();
            }
            6 | 7 => {
                wb.revoke_editor_file_save_dispatch(&context, &inputs, &command, &grant.grant_ref)
                    .unwrap();
                if fault == 6 {
                    sql.execute("DELETE FROM command_receipts WHERE scope_id = ?1 AND command_key = 'revoke'", [&grant.grant_ref]).unwrap();
                } else {
                    sql.execute(
                        "DELETE FROM events WHERE scope_id = ?1 AND kind = ?2",
                        rusqlite::params![grant.grant_ref, REVOKE_KIND],
                    )
                    .unwrap();
                }
            }
            _ => unreachable!(),
        }
        assert!(
            wb.load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
                .is_err(),
            "fault {fault}"
        );
        assert!(
            wb.authorize_editor_file_save_dispatch(&context, &inputs, &command, "background")
                .is_err(),
            "fault {fault}"
        );
    }
}

struct Unavailable {
    kind: &'static str,
    inner: Option<std::sync::Arc<dyn gaugedesk_store::ContentCodec>>,
}
impl gaugedesk_store::ContentCodec for Unavailable {
    fn encode(&self, scope: &str, kind: &str, payload: &str) -> Result<String, String> {
        self.inner.as_ref().map_or_else(
            || Ok(payload.into()),
            |inner| inner.encode(scope, kind, payload),
        )
    }
    fn decode(&self, scope: &str, kind: &str, payload: &str) -> Option<String> {
        if self.kind == kind && (kind != "account_auth_session" || payload.contains("tombstone")) {
            return None;
        }
        self.inner.as_ref().map_or_else(
            || Some(payload.into()),
            |inner| inner.decode(scope, kind, payload),
        )
    }
}

#[test]
fn unavailable_grant_or_revocation_and_failed_admission_never_publish_authority() {
    for erased in [GRANT_KIND, REVOKE_KIND, "account_auth_session"] {
        let dir = tempfile::tempdir().unwrap();
        let (shared, command, inputs, token) = admitted_fixture(dir.path());
        let mut wb = shared.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let scope = grant_scope(wb.home_id(), &command, "background").unwrap();
        let sql = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
        // Fail the receipt after the event insert: the entire product act rolls back.
        sql.execute_batch("CREATE TRIGGER lose_dispatch_grant BEFORE INSERT ON command_receipts WHEN NEW.command_key = 'authorize' BEGIN SELECT RAISE(ABORT, 'lost grant receipt'); END;").unwrap();
        assert!(wb
            .authorize_editor_file_save_dispatch(&context, &inputs, &command, "background")
            .is_err());
        assert!(wb.store_ref().retained_events(&scope).unwrap().is_empty());
        assert!(wb
            .store_ref()
            .command_for_key(&scope, "authorize")
            .unwrap()
            .is_none());
        assert!(wb
            .load_editor_file_save_dispatch_authority(&inputs, &command, &scope)
            .is_err());
        sql.execute_batch("DROP TRIGGER lose_dispatch_grant")
            .unwrap();
        wb.authorize_editor_file_save_dispatch(&context, &inputs, &command, "background")
            .unwrap();
        if erased == REVOKE_KIND {
            wb.revoke_editor_file_save_dispatch(&context, &inputs, &command, &scope)
                .unwrap();
        } else if erased == "account_auth_session" {
            wb.revoke_account_session(&token);
        }
        wb.store = wb
            .store_ref()
            .sibling()
            .unwrap()
            .with_codec(std::sync::Arc::new(Unavailable {
                kind: erased,
                inner: wb
                    .content_vault
                    .clone()
                    .map(|vault| vault as std::sync::Arc<dyn gaugedesk_store::ContentCodec>),
            }));
        assert!(
            wb.load_editor_file_save_dispatch_authority(&inputs, &command, &scope)
                .is_err(),
            "erased {erased}"
        );
        assert!(
            wb.authorize_editor_file_save_dispatch(&context, &inputs, &command, "background")
                .is_err(),
            "erased {erased}"
        );
    }
}

#[test]
fn controller_dispatch_uses_the_exact_revocable_device_source_and_home() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, original, inputs, _) = admitted_fixture(dir.path());
    let mut wb = shared.lock_unpoisoned();
    // The directory explicitly grants this device project standing. A
    // controller credential never implicitly becomes a human account.
    let mut controller = crate::mobile_machine_session::ControllerGrantRecord {
        id: "controller-background".into(),
        op: crate::account::RecordOp::Upsert,
        machine: wb.home_id().clone(),
        device: gaugedesk_core::ids::DeviceId::new("device-1"),
        public_key: SigningKey::from_seed(&[72; 32]).unwrap().public_key(),
        label: "fixture".into(),
        credential_hash: "fixture-credential-hash".into(),
        status: crate::mobile_machine_session::ControllerGrantStatus::Active,
        enrolled_at: 1,
    };
    let member = crate::org::MembershipRecord {
        id: "device-1".into(),
        op: crate::org::RecordOp::Upsert,
        org_id: crate::org::ORG_ID.into(),
        authority: "device-1".into(),
        email: String::new(),
        role: "owner".into(),
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
    wb.store_mut()
        .append_record(
            crate::mobile_machine_session::SCOPE,
            "controller-grant",
            &serde_json::to_string(&controller).unwrap(),
        )
        .unwrap();
    let context = AuthenticatedActionContext::machine_controller(&controller);
    let (_, _, chat): (String, String, String) = serde_json::from_str(&original.scope).unwrap();
    let ActionBasis::Version { version_ref } = &original.resources["target"].basis else {
        panic!("base")
    };
    assert!(wb
        .prepare_editor_file_save_request(&context, &chat, "note.txt", "device-save")
        .is_err());
    super::super::tests::project_grant(
        &mut wb,
        controller.device.as_str(),
        crate::org::RecordOp::Upsert,
    );
    let identity = wb
        .prepare_editor_file_save_request(&context, &chat, "note.txt", "device-save")
        .unwrap();
    let command = wb
        .admit_editor_file_save(
            &context,
            &inputs,
            &identity,
            &EditorFileSave {
                chat_id: &chat,
                request_id: "device-save",
                path: "note.txt",
                base_cut: version_ref,
                content: "device draft",
            },
        )
        .unwrap()
        .command;
    let grant = wb
        .authorize_editor_file_save_dispatch(&context, &inputs, &command, "background")
        .unwrap();
    let data: Signed<Grant> = serde_json::from_str(
        &wb.store_ref()
            .committed_record_snapshot(&grant.grant_ref, "authorize")
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(data.body.actor, controller.device.as_str());
    assert_eq!(
        data.body.source,
        Source::MachineController {
            grant_ref: controller.id.clone()
        }
    );
    assert_eq!(data.body.expires_at_ms, None);
    assert!(!serde_json::to_string(&data)
        .unwrap()
        .contains(&controller.credential_hash));
    let authority = wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .unwrap();
    let prepared = wb
        .prepare_native_editor_action(&authority.context, &inputs, &command, &command.policy)
        .unwrap();
    controller.status = crate::mobile_machine_session::ControllerGrantStatus::Revoked;
    wb.store_mut()
        .append_record(
            crate::mobile_machine_session::SCOPE,
            "controller-grant",
            &serde_json::to_string(&controller).unwrap(),
        )
        .unwrap();
    assert!(wb
        .store_mut()
        .with_dispatch_basis(&prepared.basis, || panic!("revoked device executed"))
        .is_err());
    assert!(wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .is_err());
    controller.status = crate::mobile_machine_session::ControllerGrantStatus::Active;
    controller.machine = HomeId::new("other-Home");
    wb.store_mut()
        .append_record(
            crate::mobile_machine_session::SCOPE,
            "controller-grant",
            &serde_json::to_string(&controller).unwrap(),
        )
        .unwrap();
    assert!(wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .is_err());
}

#[test]
fn retained_dispatch_refuses_an_idle_session_and_fences_already_prepared_work() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, inputs, token) = admitted_fixture(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let grant = wb
        .authorize_editor_file_save_dispatch(&context, &inputs, &command, "idle-background")
        .unwrap();
    let scoped = wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .unwrap();
    let prepared = wb
        .prepare_native_editor_action(&scoped.context, &inputs, &command, &command.policy)
        .unwrap();
    let session_ref = crate::account_session::session_id(&token);
    let mut session = crate::account_auth::AccountAuth::rebuild(wb.store_ref())
        .unwrap()
        .sessions[&session_ref]
        .clone();
    session.issued_at_ms =
        crate::account::session_now_ms() - crate::account::SESSION_IDLE_MS - 1000;
    session.last_seen_ms = session.issued_at_ms;
    session.lifetime_secs = crate::account::SESSION_ABSOLUTE_LIFETIME_MS / 1000;
    crate::account_auth::append_facts(
        wb.store_mut(),
        &[crate::account_auth::AccountAuthFact::Session(session)],
    )
    .unwrap();
    assert!(wb.account_sessions().resolve_now(&token).is_some());
    assert!(wb.authenticate_bearer(&token).is_none());
    assert!(wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .is_err());
    assert!(wb
        .prepare_native_editor_action(&scoped.context, &inputs, &command, &command.policy)
        .is_err());
    assert!(wb
        .store_mut()
        .with_dispatch_basis(&prepared.basis, || panic!(
            "idle source executed prepared work"
        ))
        .is_err());
}

#[test]
fn retained_dispatch_rechecks_the_bound_account_device_without_cache_eviction() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, inputs, token) = admitted_fixture(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let session_ref = crate::account_session::session_id(&token);
    let scope = crate::account::account_scope("alice");
    let mut device = crate::account::DeviceRecord {
        id: "office-device".into(),
        op: crate::account::RecordOp::Upsert,
        label: "Synthetic office client".into(),
        kind: crate::account::DeviceKind::Computer,
        subkey_pubkey: "synthetic-device-key".into(),
        status: crate::account::DeviceStatus::Active,
        enrolled_at: 1,
    };
    wb.upsert_account_device_in(&scope, &device).unwrap();
    assert!(wb.bind_account_session_device(&session_ref, "alice", &device.id));
    let context = wb.authenticate_action_context(&token).unwrap();
    let grant = wb
        .authorize_editor_file_save_dispatch(&context, &inputs, &command, "device-background")
        .unwrap();
    let scoped = wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .unwrap();
    let prepared = wb
        .prepare_native_editor_action(&scoped.context, &inputs, &command, &command.policy)
        .unwrap();
    device.status = crate::account::DeviceStatus::Revoked;
    wb.upsert_account_device_in(&scope, &device).unwrap();
    assert!(
        wb.account_sessions().resolve_now(&token).is_some(),
        "cache eviction is not the source of this refusal"
    );
    assert!(wb.authenticate_bearer(&token).is_none());
    assert!(wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .is_err());
    assert!(wb
        .prepare_native_editor_action(&scoped.context, &inputs, &command, &command.policy)
        .is_err());
    assert!(wb
        .store_mut()
        .with_dispatch_basis(&prepared.basis, || panic!(
            "revoked device executed prepared work"
        ))
        .is_err());
    // Losing the newer revocation payload must not expose the older active row.
    struct HiddenDeviceRevocation {
        inner: std::sync::Arc<dyn gaugedesk_store::ContentCodec>,
    }
    impl gaugedesk_store::ContentCodec for HiddenDeviceRevocation {
        fn encode(&self, scope: &str, kind: &str, payload: &str) -> Result<String, String> {
            self.inner.encode(scope, kind, payload)
        }
        fn decode(&self, scope: &str, kind: &str, payload: &str) -> Option<String> {
            let plain = self.inner.decode(scope, kind, payload)?;
            if kind == "device" && plain.contains("revoked") {
                None
            } else {
                Some(plain)
            }
        }
    }
    wb.store = wb
        .store_ref()
        .sibling()
        .unwrap()
        .with_codec(std::sync::Arc::new(HiddenDeviceRevocation {
            inner: wb.content_vault.clone().unwrap(),
        }));
    assert!(wb.authenticate_bearer(&token).is_none());
    assert!(wb
        .prepare_native_editor_action(&scoped.context, &inputs, &command, &command.policy)
        .is_err());
}

#[test]
fn retained_dispatch_keeps_its_original_idle_ceiling_after_provider_refresh() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, inputs, _) = admitted_fixture(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let token = wb
        .mint_account_session(
            "alice",
            "oidc",
            crate::account::SESSION_ABSOLUTE_LIFETIME_MS / 1000,
        )
        .unwrap();
    let context = wb.authenticate_action_context(&token).unwrap();
    let grant = wb
        .authorize_editor_file_save_dispatch(&context, &inputs, &command, "refresh-background")
        .unwrap();
    let scoped = wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .unwrap();
    let first = wb
        .prepare_native_editor_action(&scoped.context, &inputs, &command, &command.policy)
        .unwrap();
    let session_ref = crate::account_session::session_id(&token);
    let source = crate::account_session::durable_evidence(
        wb.store_ref(),
        &session_ref,
        "alice",
        crate::account::session_now_ms(),
    )
    .unwrap()
    .unwrap()
    .1;
    let expected = std::time::UNIX_EPOCH
        + std::time::Duration::from_millis(source.issued_at_ms + crate::account::SESSION_IDLE_MS);
    assert_eq!(first.basis.deadline(), Some(expected));
    let scope = crate::account::account_scope("alice");
    wb.upsert_account_refresh_in(
        &scope,
        &session_ref,
        crate::account::RefreshBinding::Web,
        "",
        "synthetic-sealed-refresh",
        source.issued_at_ms,
    )
    .unwrap();
    wb.touch_account_refresh_in(&scope, &session_ref, source.issued_at_ms + 1000)
        .unwrap();
    let fresh = crate::account_session::durable_evidence(
        wb.store_ref(),
        &session_ref,
        "alice",
        crate::account::session_now_ms(),
    )
    .unwrap()
    .unwrap()
    .1;
    assert!(fresh.expires_at_ms > source.expires_at_ms);
    assert!(wb
        .store_mut()
        .with_dispatch_basis(&first.basis, || panic!(
            "changed refresh executed prepared work"
        ))
        .is_err());
    let later = wb
        .prepare_native_editor_action(&scoped.context, &inputs, &command, &command.policy)
        .unwrap();
    assert_eq!(first.basis.deadline(), later.basis.deadline());
    let retry = wb
        .authorize_editor_file_save_dispatch(&context, &inputs, &command, "refresh-background")
        .unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.grant_ref, grant.grant_ref);
}

#[path = "file_action_office_dispatch_tests.rs"]
mod office;
#[test]
fn project_fact_frame_binds_the_original_project_authority_and_complete_body() {
    for fault in ["project", "authority", "protocol", "body", "removed"] {
        let dir = tempfile::tempdir().unwrap();
        let (shared, command, inputs, token) = admitted_fixture(dir.path());
        let mut wb = shared.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let admitted = wb
            .authorize_editor_file_save_dispatch(&context, &inputs, &command, "frame-check")
            .unwrap();
        let original = wb
            .store_ref()
            .committed_record_snapshot(&admitted.grant_ref, "authorize")
            .unwrap()
            .unwrap();
        let signed: Signed<Grant> = serde_json::from_str(&original).unwrap();
        let project = project_signature::command_project(&command).unwrap();
        let root = wb.project_authority_identity(&project).unwrap();
        assert_eq!(
            signed.project_signature.as_ref().unwrap().authority(),
            root.0.as_str()
        );
        verify(&signed, &root.1).unwrap();
        let host = SigningKey::from_seed(&wb.governance_seed()).unwrap();
        assert!(verify(&signed, &host.public_key()).is_err());
        let mut changed: serde_json::Value = serde_json::from_str(&original).unwrap();
        match fault {
            "body" => changed["body"]["source"]["session_ref"] = "foreign-session".into(),
            "removed" => {
                changed.as_object_mut().unwrap().remove("project_signature");
            }
            field => changed["project_signature"][field] = "foreign".into(),
        }
        if matches!(fault, "project" | "authority" | "protocol") {
            // Keep the cryptographic proof valid so this control exercises
            // the frame's independent project/authority/version check.
            let mut changed_signed: Signed<Grant> = serde_json::from_value(changed).unwrap();
            let frame = changed_signed.project_signature.as_ref().unwrap();
            let bytes = frame
                .signing_bytes(&signing_bytes(&changed_signed.body).unwrap())
                .unwrap();
            changed_signed.signature = wb.project_signing_key(&project).unwrap().sign(&bytes);
            verify(&changed_signed, &root.1).unwrap();
            changed = serde_json::to_value(changed_signed).unwrap();
        }
        let changed = serde_json::to_string(&changed).unwrap();
        let sql = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
        sql.execute(
            "UPDATE commands SET snapshot_json=?1 WHERE scope_id=?2",
            rusqlite::params![changed, admitted.grant_ref],
        )
        .unwrap();
        sql.execute(
            "UPDATE events SET payload=?1 WHERE scope_id=?2",
            rusqlite::params![changed, admitted.grant_ref],
        )
        .unwrap();
        assert!(
            wb.load_editor_file_save_dispatch_authority(&inputs, &command, &admitted.grant_ref)
                .is_err(),
            "{fault}"
        );
    }
}

#[test]
fn legacy_host_grant_replays_unchanged_and_project_authority_revokes_it() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, storage, token) = super::super::tests::legacy_home_storage_fixture(
        dir.path(),
        NativeActionStorageConfig {
            input_byte_limit: 4096,
            file_lease: whipplescript_kernel::file_lease::FileLeasePolicy::new(17).unwrap(),
        },
    );
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let scope = grant_scope(wb.home_id(), &command, "legacy-background").unwrap();
    let prepared = wb
        .prepare_native_editor_action_scoped(
            &context,
            storage.inputs(),
            &command,
            &command.policy,
            &[&scope],
            NativeActionAccess::Mutate,
        )
        .unwrap();
    // Retain the actual pre-migration wire format under its original host key.
    // No project frame or new signature replaces this historical fact.
    let host = SigningKey::from_seed(&wb.governance_seed()).unwrap();
    let body = Grant {
        protocol: PROTOCOL.into(),
        issuer: command.issuer.clone(),
        home_id: wb.home_id().as_str().into(),
        request_id: "legacy-background".into(),
        actor: context.actor().as_str().into(),
        origin: "editor.save.dispatch.authorize".into(),
        policy: command.policy.clone(),
        original_admission: ProductAdmissionCause {
            scope: prepared.scope.clone(),
            command_id: prepared.delivery.command_id.clone(),
            fingerprint: command.fingerprint().unwrap(),
        },
        source: Source::from_request(&context).unwrap(),
        expires_at_ms: prepared.basis.deadline().map(|deadline| {
            u64::try_from(
                deadline
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap()
        }),
    };
    let original = Signed {
        signature: host.sign(&signing_bytes(&body).unwrap()),
        body,
        project_signature: None,
    };
    let payload = serde_json::to_string(&original).unwrap();
    wb.store_mut()
        .with_dispatch_record_admission(&prepared.basis, |writer| {
            writer.commit(
                &scope,
                "authorize",
                &payload,
                &[CommandRecordFact {
                    scope_id: scope.clone(),
                    kind: GRANT_KIND.into(),
                    payload: payload.clone(),
                }],
            )
        })
        .unwrap()
        .unwrap();
    let before = wb.store_ref().retained_events(&scope).unwrap();
    let retry = wb
        .authorize_editor_file_save_dispatch(
            &context,
            storage.inputs(),
            &command,
            "legacy-background",
        )
        .unwrap();
    assert!(retry.replayed);
    assert_eq!(wb.store_ref().retained_events(&scope).unwrap(), before);
    assert_eq!(
        wb.store_ref()
            .committed_record_snapshot(&scope, "authorize")
            .unwrap()
            .unwrap(),
        payload
    );
    wb.load_editor_file_save_dispatch_authority(storage.inputs(), &command, &scope)
        .unwrap();
    wb.revoke_editor_file_save_dispatch(&context, storage.inputs(), &command, &scope)
        .unwrap();
    let revoked: Signed<Revocation> = serde_json::from_str(
        &wb.store_ref()
            .committed_record_snapshot(&scope, "revoke")
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let project = project_signature::command_project(&command).unwrap();
    let (authority, public) = wb.project_authority_identity(&project).unwrap();
    assert_eq!(
        revoked.project_signature.as_ref().unwrap().authority(),
        authority.as_str()
    );
    assert_eq!(revoked.body.grant_signature, original.signature);
    verify(&revoked, &public).unwrap();
    assert!(verify(&revoked, &host.public_key()).is_err());
    assert_eq!(
        wb.store_ref()
            .committed_record_snapshot(&scope, "authorize")
            .unwrap()
            .unwrap(),
        payload
    );
    assert!(wb
        .load_editor_file_save_dispatch_authority(storage.inputs(), &command, &scope)
        .is_err());
    let roots = NativeHistoryRoots::open(&wb).unwrap();
    assert!(
        load_grant(wb.store_ref(), wb.home_id(), &command, &scope, &roots)
            .unwrap()
            .unwrap()
            .1
    );
    drop(wb);
    drop(shared);
    let restarted = crate::open_workbench(dir.path()).unwrap();
    let wb = restarted.lock_unpoisoned();
    let roots = NativeHistoryRoots::open(&wb).unwrap();
    assert!(
        load_grant(wb.store_ref(), wb.home_id(), &command, &scope, &roots)
            .unwrap()
            .unwrap()
            .1
    );
}

#[test]
fn historical_project_grant_verification_survives_lost_private_custody_but_current_dispatch_refuses(
) {
    let dir = tempfile::tempdir().unwrap();
    let (shared, command, inputs, token) = admitted_fixture(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let grant = wb
        .authorize_editor_file_save_dispatch(&context, &inputs, &command, "custody-check")
        .unwrap();
    let authority = wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .unwrap();
    let prepared = wb
        .prepare_native_editor_action(&authority.context, &inputs, &command, &command.policy)
        .unwrap();
    let cause = prepared.grant_cause.unwrap();
    let provenance = with_grant_cause(command.provenance.clone(), Some(&cause));
    let history = NativeDispatchHistory::open(&wb).unwrap();
    let project = project_signature::command_project(&command).unwrap();
    let custody = dir
        .path()
        .join("content-keys/projects")
        .join(format!("{}.key", crate::org::sha256_hex(&project)));
    std::fs::remove_file(&custody).unwrap();
    history
        .verify(&command, &provenance, &command.provenance)
        .unwrap();
    let before = wb.store_ref().retained_events(&grant.grant_ref).unwrap();
    assert!(wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &grant.grant_ref)
        .is_err());
    assert!(wb
        .authorize_editor_file_save_dispatch(&context, &inputs, &command, "no-remint")
        .is_err());
    assert_eq!(
        wb.store_ref().retained_events(&grant.grant_ref).unwrap(),
        before
    );
    assert!(!custody.exists());
}
