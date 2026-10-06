//! Native/product writer adapter proof. Staff source authorization is covered
//! separately; this fixture does not run an inference server or a full restart.
use super::*;
use gaugedesk_workspace::Instance;
use sha2::{Digest, Sha256};
use std::sync::Arc;

fn result(eng: &gaugedesk_workspace::Engagement, base: &str) -> NativeWitnessedTurn {
    eng.witnessed_turn_target_at(base)
        .unwrap()
        .import_result_guarded(
            &[NativeTurnFileWitness {
                path: "result.txt".into(),
                kind: "add".into(),
                sha256: hex::encode(Sha256::digest(b"original result")),
                bytes: 15,
            }],
            "original-runtime-witness",
            "staff:alice",
            "original-http",
            &mut || Ok(()),
        )
        .unwrap()
}
fn basis(store: &gaugedesk_store::Store) -> gaugedesk_store::command_dispatch::DispatchReadBasis {
    store.read_for_dispatch(&["chat"], |_| Ok(())).unwrap().1
}

#[test]
fn historical_office_adapter_publishes_original_history_under_same_pending_product_writer() {
    let root = tempfile::tempdir().unwrap();
    let instance = Instance::init_at(root.path().join("native")).unwrap();
    let eng = instance.create_engagement("office-history").unwrap();
    eng.write_file("base.txt", "original base").unwrap();
    let base = eng.commit_turn("base").unwrap().unwrap().0;
    eng.write_file("result.txt", "original result").unwrap();
    let native = result(&eng, &base);
    let original_result = native.cut().to_owned();
    let path = root.path().join("product.sqlite");
    let vault = Arc::new(
        crate::content_vault::ContentVault::new(
            root.path().join("keys"),
            Box::new(crate::at_rest::LoopbackKeyWrap::new([4; 32])),
        )
        .with_authenticated_record_writes(),
    );
    let mut store = gaugedesk_store::Store::open(path.to_str().unwrap())
        .unwrap()
        .with_codec(vault);
    store
        .claim_command("original-http", "http", "key", "exact-input")
        .unwrap();
    let observed = basis(&store);
    let (original_cut, original_op) = store
        .with_dispatch_record_admission(&observed, |writer| {
            writer
                .require_pending_claim("original-http", "http", "key", "exact-input")
                .map_err(native_error)?;
            let prepared = writer
                .with_native_check(|check| {
                    OfficeNativeResult::prepare(native, &mut || {
                        check.check_current().map_err(|error| WorkspaceError {
                            message: format!("{error:?}"),
                        })
                    })
                })
                .unwrap()
                .unwrap();
            assert!(matches!(prepared, OfficeNativeResult::Settled(_)));
            let mut original = None;
            assert!(prepared
                .publish::<()>(|_, evidence| {
                    let evidence = evidence.unwrap();
                    assert_eq!(evidence.kind(), "current-applied");
                    let (cut, op) = evidence.coordinates();
                    original = Some((cut.clone(), op.clone()));
                    Err(whipplescript_store::StoreError::Conflict(
                        "synthetic product publication failed".into(),
                    ))
                })
                .is_err());
            Ok::<_, whipplescript_store::StoreError>(original.unwrap())
        })
        .unwrap()
        .unwrap();
    assert!(store
        .pending_command_matches("original-http", "http", "key", "exact-input")
        .unwrap());
    assert!(store
        .records("chat", "office_native_settlement")
        .unwrap()
        .is_empty());
    eng.write_file("later.txt", "later independently submitted collaboration")
        .unwrap();
    let later = eng.commit_turn("later collaboration").unwrap().unwrap().0;
    assert_ne!(later, original_cut.cut_id);
    eng.write_file("result.txt", "unsubmitted replacement")
        .unwrap();
    let native = result(&eng, &base);
    let observed = basis(&store);
    store
        .with_dispatch_record_admission(&observed, |writer| {
            writer
                .require_pending_claim("original-http", "http", "key", "exact-input")
                .map_err(native_error)?;
            let prepared = writer
                .with_native_check(|check| {
                    OfficeNativeResult::prepare(native, &mut || {
                        check.check_current().map_err(|error| WorkspaceError {
                            message: format!("{error:?}"),
                        })
                    })
                })
                .unwrap()
                .unwrap();
            assert!(matches!(prepared, OfficeNativeResult::Historical(_)));
            prepared.publish(|native, evidence| {
                let evidence = evidence.unwrap();
                assert_eq!(evidence.coordinates(), (&original_cut, &original_op));
                let fact = settlement_fact("chat", "original-http", native.cut(), evidence)?;
                writer
                    .commit_claimed("original-http", "http", "key", "exact-input", &[fact])
                    .map_err(native_error)
            })
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        eng.observe().unwrap().recorded_cut.as_deref(),
        Some(later.as_str())
    );
    assert_eq!(
        eng.read_file("result.txt").unwrap(),
        "unsubmitted replacement"
    );
    let records = store.records("chat", "office_native_settlement").unwrap();
    assert_eq!(records.len(), 1);
    let fact: serde_json::Value = serde_json::from_str(&records[0]).unwrap();
    assert_eq!(fact["command_id"], "original-http");
    assert_eq!(fact["evidence_kind"], "original-history");
    assert_eq!(fact["result_cut"], original_result);
    assert_eq!(fact["settlement_cut"]["cut_id"], original_cut.cut_id);
    assert_eq!(fact["operation"]["op_id"], original_op.op_id);
    assert_eq!(
        store.command("original-http").unwrap().unwrap().status,
        "applied"
    );
    let sql = rusqlite::Connection::open(path).unwrap();
    let raw: String = sql
        .query_row(
            "SELECT payload FROM events WHERE kind='office_native_settlement'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(raw.starts_with("gwenc:2:"));
    let observed = basis(&store);
    assert!(store
        .with_dispatch_record_admission(&observed, |writer| {
            writer.require_pending_claim("original-http", "http", "key", "exact-input")
        })
        .unwrap()
        .is_err());
    assert_eq!(
        eng.observe().unwrap().recorded_cut.as_deref(),
        Some(later.as_str())
    );
}
