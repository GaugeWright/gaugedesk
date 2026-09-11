use super::*;
use crate::LockUnpoisoned;
use gaugedesk_whip_runtime::host_actions::recovery::RecordedReconciliation;

fn saved() -> (tests::Saved, String) {
    let mut grant_ref = String::new();
    let fixture = tests::saved_with_context(true, |wb, inputs, command, token| {
        let context = wb.authenticate_action_context(token).unwrap();
        grant_ref = wb
            .authorize_editor_file_save_dispatch(&context, inputs, command, "execute-background")
            .unwrap()
            .grant_ref;
        wb.load_editor_file_save_dispatch_authority(inputs, command, &grant_ref)
            .unwrap()
            .context
    });
    (fixture, grant_ref)
}

fn assert_cause(cause: &ActionCause, authority: &str, grant_ref: &str) {
    assert_eq!(cause.authority, authority);
    let (protocol, reference, command): (String, String, String) =
        serde_json::from_str(&cause.record_ref).unwrap();
    assert_eq!(protocol, "gaugedesk.native-editor-dispatch-grant.v1");
    assert_eq!(reference, grant_ref);
    assert_eq!(command, "authorize");
    assert_eq!(cause.digest.len(), 64);
}

#[test]
fn interrupted_background_save_preserves_each_grant_through_recovery_and_result_redelivery() {
    let (fixture, first_grant) = saved();
    let tests::Saved {
        dir,
        wb: shared,
        command,
        inputs,
        token,
        admission,
        runtime,
        effect_id,
        run_id,
    } = fixture;
    let attempt = EditorFileSaveAttempt {
        effect_id: &effect_id,
        run_id: &run_id,
    };
    let mut wb = shared.lock_unpoisoned();
    let current = wb.authenticate_action_context(&token).unwrap();
    let before = runtime
        .kernel()
        .store()
        .list_events(&admission.instance_ref)
        .unwrap();
    let mut executions = Vec::new();
    for row in runtime
        .kernel()
        .store()
        .chain_prefix(&admission.instance_ref)
        .unwrap()
    {
        if row.event_type == "effect.run_started" {
            let payload: serde_json::Value = serde_json::from_str(&row.payload_json).unwrap();
            let request: ExecuteActionEffect =
                serde_json::from_value(payload["metadata"]["action_execution"]["request"].clone())
                    .unwrap();
            assert_eq!(request.provenance.initiator, command.provenance.initiator);
            assert_eq!(request.provenance.executor, command.provenance.executor);
            assert_eq!(request.provenance.causes.len(), 1);
            assert_cause(&request.provenance.causes[0], &command.issuer, &first_grant);
            executions.push(request);
        }
    }
    assert_eq!(executions.len(), 2);
    assert_eq!(executions[0].provenance, executions[1].provenance);
    wb.revoke_editor_file_save_dispatch(&current, &inputs, &command, &first_grant)
        .unwrap();
    wb.revoke_account_session(&token);
    drop(wb);
    drop(shared);
    drop(runtime);

    let shared = crate::open_workbench(dir.path()).unwrap();
    let mut wb = shared.lock_unpoisoned();
    let token = wb.mint_account_session("alice", "passkey", 3600).unwrap();
    let current = wb.authenticate_action_context(&token).unwrap();
    let runtime = super::super::tests::editor_runtime(&wb, &command, dir.path());
    assert!(wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &first_grant)
        .is_err());
    // Current permission admits inspection of an older, now-revoked grant's
    // actual save. It does not retry the interrupted write.
    let recovered = wb
        .inspect_editor_file_save_attempt(
            &current, &inputs, &command, &admission, attempt, &runtime,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        runtime
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap(),
        before
    );
    let recovery_grant = wb
        .authorize_editor_file_save_dispatch(&current, &inputs, &command, "recover-background")
        .unwrap()
        .grant_ref;
    let background = wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &recovery_grant)
        .unwrap();
    let mut owner = wb
        .claim_editor_file_save_runtime(&background.context, &inputs, &command, &admission, runtime)
        .unwrap();
    let reconciliation_receipt = wb
        .reconcile_editor_file_save_attempt(
            &background.context,
            &inputs,
            &command,
            &admission,
            EditorFileSaveReconciliation {
                request_id: "reconcile-background",
                attempt,
            },
            &mut owner,
        )
        .unwrap()
        .unwrap();
    let reconciliation: RecordedReconciliation = owner
        .runtime()
        .kernel()
        .store()
        .chain_prefix(&admission.instance_ref)
        .unwrap()
        .iter()
        .find(|row| row.event_type == "effect.disposition.reconciled")
        .map(|row| serde_json::from_str(&row.payload_json).unwrap())
        .unwrap();
    assert_eq!(reconciliation.command.provenance.causes.len(), 2);
    assert_cause(
        &reconciliation.command.provenance.causes[1],
        &command.issuer,
        &recovery_grant,
    );
    let admitted = wb
        .admit_editor_file_save_result(
            &background.context,
            &inputs,
            &command,
            &admission,
            attempt,
            owner.runtime(),
        )
        .unwrap()
        .unwrap();
    assert!(!admitted.replayed);
    assert_eq!(admitted.result.result_reference, recovered.reference);
    assert_eq!(admitted.result.provenance.causes.len(), 3);
    assert_cause(
        &admitted.result.provenance.causes[2],
        &command.issuer,
        &recovery_grant,
    );
    let events = owner
        .runtime()
        .kernel()
        .store()
        .list_events(&admission.instance_ref)
        .unwrap();
    wb.revoke_editor_file_save_dispatch(&current, &inputs, &command, &recovery_grant)
        .unwrap();
    let final_grant = wb
        .authorize_editor_file_save_dispatch(&current, &inputs, &command, "redeliver-background")
        .unwrap()
        .grant_ref;
    let later = wb
        .load_editor_file_save_dispatch_authority(&inputs, &command, &final_grant)
        .unwrap();
    let reconciliation_retry = wb
        .reconcile_editor_file_save_attempt(
            &later.context,
            &inputs,
            &command,
            &admission,
            EditorFileSaveReconciliation {
                request_id: "reconcile-background",
                attempt,
            },
            &mut owner,
        )
        .unwrap()
        .unwrap();
    assert_eq!(reconciliation_retry, reconciliation_receipt);
    let replay = wb
        .admit_editor_file_save_result(
            &later.context,
            &inputs,
            &command,
            &admission,
            attempt,
            owner.runtime(),
        )
        .unwrap()
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.result, admitted.result);
    let direct_replay = wb
        .admit_editor_file_save_result(
            &current,
            &inputs,
            &command,
            &admission,
            attempt,
            owner.runtime(),
        )
        .unwrap()
        .unwrap();
    assert!(direct_replay.replayed);
    assert_eq!(direct_replay.result, admitted.result);
    assert_eq!(
        owner
            .runtime()
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap(),
        events
    );
    assert_eq!(
        wb.store_ref()
            .records(&admission.instance_ref, "native_editor_saved_result_v1")
            .unwrap()
            .len(),
        1
    );
    // A cached result must still agree with the actual receipt and its original
    // committed product fact; status or a matching mutable snapshot is not enough.
    let original_payload = serde_json::to_string(&admitted.result).unwrap();
    let result_scope = format!("host-action-native-save-result:{}", admission.instance_ref);
    let sql = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    for fault in ["fact", "grant-cause", "saved-cut"] {
        let mut changed = admitted.result.clone();
        if fault == "grant-cause" {
            changed.provenance.causes[2].digest = "0".repeat(64);
        }
        if fault == "saved-cut" {
            changed.cut_id = "another cut".into();
        }
        let payload = serde_json::to_string(&changed).unwrap();
        sql.execute(
            "UPDATE commands SET snapshot_json = ?1 WHERE scope_id = ?2",
            rusqlite::params![payload, result_scope],
        )
        .unwrap();
        let stored = if fault == "fact" {
            "unrelated result"
        } else {
            &payload
        };
        sql.execute("UPDATE events SET payload = ?1 WHERE scope_id = ?2 AND kind = 'native_editor_saved_result_v1'", rusqlite::params![stored, admission.instance_ref]).unwrap();
        assert!(
            wb.admit_editor_file_save_result(
                &later.context,
                &inputs,
                &command,
                &admission,
                attempt,
                owner.runtime()
            )
            .is_err(),
            "{fault}"
        );
        sql.execute(
            "UPDATE commands SET snapshot_json = ?1 WHERE scope_id = ?2",
            rusqlite::params![original_payload, result_scope],
        )
        .unwrap();
        sql.execute("UPDATE events SET payload = ?1 WHERE scope_id = ?2 AND kind = 'native_editor_saved_result_v1'", rusqlite::params![original_payload, admission.instance_ref]).unwrap();
    }
    assert_eq!(
        owner
            .runtime()
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .unwrap(),
        events
    );
    assert!(wb
        .admit_editor_file_save_result(
            &background.context,
            &inputs,
            &command,
            &admission,
            attempt,
            owner.runtime()
        )
        .is_err());
}

#[test]
fn historical_grant_causes_require_exact_signed_receipted_history_without_live_authority() {
    let (fixture, grant_ref) = saved();
    let mut wb = fixture.wb.lock_unpoisoned();
    let context = wb.authenticate_action_context(&fixture.token).unwrap();
    let key = SigningKey::from_seed(&wb.governance_seed()).unwrap();
    let history = dispatch_grant::NativeDispatchHistory::open(&wb, key.public_key()).unwrap();
    let snapshot = wb
        .read_editor_file_save_result(
            &context,
            &fixture.inputs,
            &fixture.command,
            &fixture.admission,
            &fixture.runtime,
        )
        .unwrap();
    let store = fixture.runtime.kernel().store();
    let prefix = store.chain_prefix(&fixture.admission.instance_ref).unwrap();
    let effect = store
        .list_effects(&fixture.admission.instance_ref)
        .unwrap()
        .into_iter()
        .find(|effect| effect.effect_id == fixture.effect_id)
        .unwrap();
    let original = original_save(
        &snapshot,
        prefix.clone(),
        effect.clone(),
        &fixture.run_id,
        &history,
    )
    .unwrap();
    let provenance = &original.execution.provenance;
    assert!(history
        .verify(&fixture.command, provenance, &fixture.command.provenance)
        .is_ok());
    for field in [
        "actor",
        "source",
        "authority",
        "digest",
        "reference",
        "extra",
        "missing-original",
    ] {
        let mut changed = provenance.clone();
        match field {
            "actor" => changed.executor = "other actor".into(),
            "source" => changed.origin = "another surface".into(),
            "authority" => changed.causes[0].authority.push_str("-foreign"),
            "digest" => changed.causes[0].digest = "0".repeat(64),
            "reference" => {
                changed.causes[0].record_ref = serde_json::to_string(&(
                    "gaugedesk.native-editor-dispatch-grant.v1",
                    "missing grant",
                    "authorize",
                ))
                .unwrap()
            }
            "extra" => changed.causes.push(changed.causes[0].clone()),
            "missing-original" => changed.delegation.push(ActionDelegation {
                grant_ref: "forged delegation".into(),
                delegator: "alice".into(),
                delegate: "alice".into(),
            }),
            _ => unreachable!(),
        }
        assert!(
            history
                .verify(&fixture.command, &changed, &fixture.command.provenance)
                .is_err(),
            "{field}"
        );
    }
    wb.revoke_editor_file_save_dispatch(&context, &fixture.inputs, &fixture.command, &grant_ref)
        .unwrap();
    assert!(history
        .verify(&fixture.command, provenance, &fixture.command.provenance)
        .is_ok());
    let sql = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    sql.execute(
        "DELETE FROM command_receipts WHERE scope_id = ?1 AND command_key = 'authorize'",
        [&grant_ref],
    )
    .unwrap();
    assert!(history
        .verify(&fixture.command, provenance, &fixture.command.provenance)
        .is_err());
    assert!(wb
        .inspect_editor_file_save_attempt(
            &context,
            &fixture.inputs,
            &fixture.command,
            &fixture.admission,
            EditorFileSaveAttempt {
                effect_id: &fixture.effect_id,
                run_id: &fixture.run_id
            },
            &fixture.runtime
        )
        .is_err());
}
