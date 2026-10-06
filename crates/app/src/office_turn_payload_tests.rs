//! Actual pending-command phase/custody fixtures. Prepared bytes here are
//! synthetic inputs; published native callback integration is still owed.
use super::*;
use crate::engine::{
    office_turn_payload::{self, PreparedFile, KIND},
    office_turn_startup::{self, OfficeTurnContext},
};
use sha2::{Digest, Sha256};

fn consume_saved(
    office: &OfficeTurnContext<'_>,
    startup: &office_turn_startup::OfficeTurnStartup,
    files: &[PreparedFile],
    publish: impl FnOnce(
        std::collections::BTreeMap<String, Vec<u8>>,
    ) -> Result<(), crate::engine::EngineError>,
) -> Result<(), crate::engine::EngineError> {
    let preparation = office_turn_startup::recorded_runtime(office, startup, None)?;
    let plan = office_turn_payload::ResultPayloadPlan::new(office, startup, &preparation, files)?;
    let scopes = plan.scopes();
    let scopes: Vec<_> = scopes.iter().map(String::as_str).collect();
    let mut wb = office.wb.lock_unpoisoned();
    let authority = office.authority.prepare_basis(&wb)?;
    let key = wb
        .content_vault
        .as_ref()
        .ok_or_else(|| crate::engine::EngineError::Message("missing test vault".into()))?
        .prepare_scope_key(office.authority.chat())
        .map_err(crate::engine::EngineError::Harness)?;
    let (observed, basis) = wb
        .store_ref()
        .read_for_dispatch(&scopes, |reader| plan.observe(reader))?;
    let basis = authority.combine(basis)?;
    wb.store_mut()
        .with_dispatch_record_admission(&basis, |writer| {
            observed.consume(writer, &key, office.original, |writer, bodies| {
                writer.with_native_check(|check| check.check_current())??;
                publish(bodies)
            })
        })??;
    Ok(())
}

#[tokio::test]
async fn office_prepared_payload_phase_retains_encrypted_original_bytes_and_refuses_lost_authority()
{
    for case in [
        "roundtrip",
        "later-work",
        "missing-key",
        "erased",
        "completed",
        "revoked",
        "no-vault",
        "orphan",
        "phase-meaning",
        "duplicate",
        "insert-failure",
    ] {
        let root = tempfile::tempdir().unwrap();
        let (wb, app, _, _) = fixture(root.path());
        let hub = hub().await;
        install(&wb, &hub);
        let admission = admit(&app, ALICE).await;
        let chat = chat(&wb);
        let captured = context(&wb, &admission);
        let (original, finish, handler) =
            answers::claim_answers(&wb, &chat, "original-file-copy").await;
        let (mut finish, mut handler) = (Some(finish), Some(handler));
        let authority = OfficeTaskAuthority::for_turn(
            &wb,
            &chat,
            Some(&captured),
            Some(&Default::default()),
            Some(captured.actor()),
            Some(ALICE),
        )
        .unwrap()
        .unwrap();
        let office = OfficeTurnContext {
            wb: &wb,
            authority: &authority,
            original: &original,
        };
        let engagement = wb.lock_unpoisoned().engagements[&chat].boxed_clone();
        let mut fork = None;
        let startup = office_turn_startup::admit_startup(
            &office,
            engagement.as_ref(),
            &chat,
            "synthetic original task",
            &mut fork,
        )
        .unwrap();
        office_turn_startup::retain_runtime(
            &office,
            &startup,
            None,
            gaugedesk_harness::RuntimeTurnPreparation {
                command_json: "{\"synthetic\":\"not a native execution\"}".into(),
                start_position: gaugedesk_harness::RuntimePosition {
                    instance_ref: "synthetic-instance".into(),
                    sequence: 1,
                },
                start_head_digest: "synthetic-head".into(),
                workspace_targets: vec![],
                input_digest: gaugedesk_harness::runtime_input_digest(
                    "synthetic original task",
                    &[],
                ),
            },
        )
        .unwrap();
        let body = b"original synthetic binary payload\0\xff";
        let prefix = wb
            .lock_unpoisoned()
            .engagement_context_target_root(&chat, None)
            .unwrap()
            .unwrap_or_default();
        let path = if prefix.is_empty() {
            "result.bin".into()
        } else {
            format!("{prefix}/result.bin")
        };
        let file = PreparedFile {
            path,
            kind: "add".into(),
            sha256: hex::encode(Sha256::digest(body)),
            bytes: body.len() as u64,
        };
        assert!(office_turn_payload::recorded(&office, &startup, None, &file).is_err());
        let before = wb
            .lock_unpoisoned()
            .store_ref()
            .retained_events(&chat)
            .unwrap();
        assert!(
            office_turn_payload::retain(&office, &startup, None, &file, b"substituted body")
                .is_err()
        );
        assert_eq!(
            wb.lock_unpoisoned()
                .store_ref()
                .retained_events(&chat)
                .unwrap(),
            before
        );
        let database = wb.lock_unpoisoned().store_ref().path().to_owned();
        let db = rusqlite::Connection::open(&database).unwrap();
        if case == "insert-failure" {
            db.execute_batch("CREATE TRIGGER refuse_payload BEFORE INSERT ON events WHEN NEW.kind='office_turn_payload' BEGIN SELECT RAISE(ABORT, 'synthetic phase failure'); END;").unwrap();
            assert!(office_turn_payload::retain(&office, &startup, None, &file, body).is_err());
            assert_eq!(
                wb.lock_unpoisoned()
                    .store_ref()
                    .retained_events(&chat)
                    .unwrap(),
                before
            );
            original
                .verify_pending(wb.lock_unpoisoned().store_ref())
                .unwrap();
            db.execute_batch("DROP TRIGGER refuse_payload;").unwrap();
        }
        office_turn_payload::retain(&office, &startup, None, &file, body).unwrap();
        let after = wb
            .lock_unpoisoned()
            .store_ref()
            .retained_events(&chat)
            .unwrap();
        office_turn_payload::retain(&office, &startup, None, &file, body).unwrap();
        assert_eq!(
            wb.lock_unpoisoned()
                .store_ref()
                .retained_events(&chat)
                .unwrap(),
            after
        );
        engagement
            .write_file(&file.path, "later unsubmitted replacement")
            .unwrap();
        if case == "later-work" {
            engagement
                .commit_turn("later independently submitted work")
                .unwrap();
            let pending = file.path.replace("result.bin", "pending.txt");
            engagement
                .write_file(&pending, "never submitted pending edit")
                .unwrap();
        }
        assert_eq!(
            office_turn_payload::recorded(&office, &startup, None, &file).unwrap(),
            body
        );
        assert_eq!(
            engagement.read_file(&file.path).unwrap(),
            "later unsubmitted replacement"
        );
        let consumed = std::cell::Cell::new(false);
        let retained_before = wb
            .lock_unpoisoned()
            .store_ref()
            .retained_events(&chat)
            .unwrap();
        consume_saved(&office, &startup, std::slice::from_ref(&file), |bodies| {
            assert_eq!(bodies.len(), 1);
            assert_eq!(bodies[&file.path], body);
            // Real key custody spans the native/product publication callback.
            let vault = crate::content_vault::ContentVault::new(
                root.path().join("content-keys"),
                Box::new(crate::at_rest::LoopbackKeyWrap::new([0; 32])),
            )
            .with_ledger(Box::new(crate::content_vault::LocalFileErasureLedger::new(
                root.path().join("consumer-erasures"),
            )));
            assert_eq!(
                vault.erase_scope_key(&chat).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            consumed.set(true);
            Ok(())
        })
        .unwrap();
        assert!(consumed.get());
        assert_eq!(
            wb.lock_unpoisoned()
                .store_ref()
                .retained_events(&chat)
                .unwrap(),
            retained_before
        );
        if case == "roundtrip" {
            let changed_body = b"later prepared version";
            let changed = PreparedFile {
                path: file.path.clone(),
                kind: "modify".into(),
                sha256: hex::encode(Sha256::digest(changed_body)),
                bytes: changed_body.len() as u64,
            };
            office_turn_payload::retain(&office, &startup, None, &changed, changed_body).unwrap();
            consume_saved(
                &office,
                &startup,
                &[file.clone(), changed.clone()],
                |bodies| {
                    assert_eq!(bodies.len(), 1);
                    assert_eq!(bodies[&file.path], changed_body);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(
                office_turn_payload::recorded(&office, &startup, None, &changed).unwrap(),
                changed_body
            );
            assert_eq!(
                office_turn_payload::recorded(&office, &startup, None, &file).unwrap(),
                body
            );
            let deleted = PreparedFile {
                path: file.path.clone(),
                kind: "delete".into(),
                sha256: hex::encode(Sha256::digest([])),
                bytes: 0,
            };
            office_turn_payload::retain(&office, &startup, None, &deleted, &[]).unwrap();
            consume_saved(&office, &startup, &[changed, deleted], |bodies| {
                assert_eq!(bodies.len(), 1);
                assert!(bodies[&file.path].is_empty());
                Ok(())
            })
            .unwrap();
        }
        let envelope = wb
            .lock_unpoisoned()
            .store_ref()
            .records(&chat, KIND)
            .unwrap()
            .pop()
            .unwrap();
        let decoded: serde_json::Value = serde_json::from_str(&envelope).unwrap();
        let phase = decoded["phase"].as_str().unwrap();
        let phase_scope =
            gaugedesk_store::Store::claimed_lifecycle_prefix_scope(original.command_id(), phase);
        let raw: String = db
            .query_row(
                "SELECT payload FROM events WHERE scope_id=?1 AND kind='office_turn_payload'",
                [&chat],
                |row| row.get(0),
            )
            .unwrap();
        assert!(raw.starts_with("gwenc:1:"));
        assert!(!raw.contains("result.bin") && !raw.contains("original synthetic binary payload"));
        assert!(
            !envelope.contains("result.bin")
                && !envelope.contains("original synthetic binary payload")
        );
        let key_path = root
            .path()
            .join("content-keys")
            .join(format!("{}.dek", crate::org::sha256_hex(&chat)));
        match case {
            "missing-key" => std::fs::remove_file(&key_path).unwrap(),
            "erased" => {
                wb.lock_unpoisoned()
                    .content_vault
                    .as_ref()
                    .unwrap()
                    .erase_scope_key(&chat)
                    .unwrap();
            }
            "completed" => {
                finish.take().unwrap().send(()).unwrap();
                handler.take().unwrap().await.unwrap();
            }
            "revoked" => membership(&wb, "alice", crate::org::MembershipStatus::Deprovisioned),
            "no-vault" => wb.lock_unpoisoned().content_vault = None,
            "orphan" => {
                db.execute("DELETE FROM events WHERE scope_id=?1", [&phase_scope])
                    .unwrap();
                db.execute(
                    "DELETE FROM command_receipts WHERE scope_id=?1",
                    [&phase_scope],
                )
                .unwrap();
            }
            "phase-meaning" => {
                let raw: String = db.query_row("SELECT payload FROM events WHERE scope_id=?1 AND kind='command_prefix_result_v1'", [&phase_scope], |r| r.get(0)).unwrap();
                let mut changed: serde_json::Value = serde_json::from_str(&raw).unwrap();
                changed["meaning_sha256"] = "different original phase".into();
                db.execute("UPDATE events SET payload=?1 WHERE scope_id=?2 AND kind='command_prefix_result_v1'", rusqlite::params![changed.to_string(), phase_scope]).unwrap();
            }
            "duplicate" => {
                wb.lock_unpoisoned()
                    .store_mut()
                    .append_record(&chat, KIND, &envelope)
                    .unwrap();
            }
            _ => {}
        }
        if !matches!(case, "roundtrip" | "later-work" | "insert-failure") {
            assert!(
                consume_saved(&office, &startup, std::slice::from_ref(&file), |_| {
                    panic!("unavailable original payload reached publication: {case}");
                })
                .is_err(),
                "{case}"
            );
            assert!(
                office_turn_payload::recorded(&office, &startup, None, &file).is_err(),
                "{case}"
            );
            assert!(
                office_turn_payload::retain(&office, &startup, None, &file, body).is_err(),
                "{case}"
            );
            if case == "missing-key" {
                assert!(!key_path.exists());
            }
            if case == "revoked" {
                membership(&wb, "alice", crate::org::MembershipStatus::Active);
                assert!(office_turn_payload::recorded(&office, &startup, None, &file).is_err());
            }
        }
        if finish.is_some() {
            finish.take().unwrap().send(()).unwrap();
            handler.take().unwrap().await.unwrap();
        }
    }
}
