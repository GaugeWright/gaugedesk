//! WHIP-3: waiting for human consent must not preserve obsolete source authority.
use super::*;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use std::sync::Mutex;
use tower::ServiceExt;

pub(super) fn fixture() -> (
    SharedWorkbench,
    HandoffWire,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    let source_dir = tempfile::tempdir().unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let source_id = AuthorityId::new("alice");
    let target_id = AuthorityId::new("bob");
    let root = FileKeyStore::new(source_dir.path().join("keys")).signing_key(&source_id);
    let source = Federation::open(
        source_id.clone(),
        source_dir.path(),
        "wss://127.0.0.1:1".into(),
    )
    .unwrap();
    let ticket = source.mint_ticket(root.public_key(), "bridge:invoke".into(), Some(3600));
    let mut target = Federation::open(
        target_id.clone(),
        target_dir.path(),
        "wss://127.0.0.1:1".into(),
    )
    .unwrap();
    target.accept_ticket(&ticket, "grant-consent".into());
    let mut wb = Workbench::new(
        Store::open(target_dir.path().join("events.sqlite").to_str().unwrap()).unwrap(),
    )
    .with_authority(target_id)
    .with_root(target_dir.path())
    .with_federation(target);
    persist_bridge(wb.store_mut(), &ticket, "grant-consent", true);
    let mut source_store = Store::open_in_memory().unwrap();
    source_store
        .append_record(
            LIBRARY_SCOPE,
            "project",
            &serde_json::json!({
                "id": "p1", "op": "upsert", "name": "Incoming project", "is_default": false,
                "home_id": "home:alice", "network_isolated": false
            })
            .to_string(),
        )
        .unwrap();
    source_store
        .append_record("project_log::p1", "evidence", "original history")
        .unwrap();
    let home = HomeId::new("home:alice");
    let signed_bytes = handoff_bytes("p1", &home);
    let (subkey, delegation) = device_identity(source_dir.path(), &source_id, &root);
    let wire = HandoffWire {
        kind: HandoffMsgKind::OfferWithCommands,
        project: "p1".into(),
        source: "alice".into(),
        target: "bob".into(),
        source_home: home,
        log: collect_project_log(&source_store, "p1"),
        project_commands: Some(
            source_store
                .export_command_scopes(|scope| is_project_scope(scope, "p1"))
                .unwrap(),
        ),
        content: Vec::new(),
        credential_key: None,
        shared_route: None,
        signature: subkey.sign(&signed_bytes),
        source_pubkey: subkey.public_key().as_str().into(),
        signed_bytes,
        delegation: Some(delegation),
    };
    (Arc::new(Mutex::new(wb)), wire, source_dir, target_dir)
}

async fn accept(wb: &SharedWorkbench, batch: bool) -> (StatusCode, String) {
    let route = if batch {
        "/federation/handoff/accept-all"
    } else {
        "/federation/handoff/accept"
    };
    let request = Request::builder()
        .method("POST")
        .uri(route)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"project":"p1","source":"alice"}"#))
        .unwrap();
    let response = featured_routes(true)
        .with_state(wb.clone())
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn delayed_accept_rechecks_current_grant_subkey_and_policy_before_import() {
    for change in [
        "revoke_peer",
        "expire_grant",
        "inactive_grant",
        "replace_root",
        "revoke_subkey",
        "tighten_policy",
    ] {
        let (wb, wire, _source_dir, _target_dir) = fixture();
        assert_eq!(admit_handoff(&wb, &wire)["pending"], true);
        let before = {
            let mut guard = wb.lock_unpoisoned();
            let fed = guard.federation_mut().unwrap();
            match change {
                "revoke_peer" => {
                    assert!(fed.revoke_peer("alice"));
                }
                "expire_grant" => fed.grants.get_mut("alice").unwrap().expiry = 0,
                "inactive_grant" => fed.grants.get_mut("alice").unwrap().active = false,
                "replace_root" => {
                    fed.grants
                        .get_mut("alice")
                        .unwrap()
                        .source_authority_root_pubkey = PublicKey::new("different-root")
                }
                "revoke_subkey" => fed.record_revocation("alice", &wire.source_pubkey),
                "tighten_policy" => {
                    guard.store_mut().append_record("org", "placement_policy", &serde_json::json!({
                    "id": "", "op": "upsert", "policy": {"require_attested": true, "allowed_operators": []}
                }).to_string()).unwrap();
                }
                _ => unreachable!(),
            }
            guard.store_ref().scope_high_water_marks().unwrap()
        };
        let (status, reason) = accept(&wb, false).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{change}: {reason}");
        let (status, body) = accept(&wb, true).await;
        assert_eq!(status, StatusCode::OK, "{change}: {body}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["accepted"],
            serde_json::json!([])
        );
        let guard = wb.lock_unpoisoned();
        assert_eq!(
            guard.store_ref().scope_high_water_marks().unwrap(),
            before,
            "{change}"
        );
        assert_eq!(pending_incoming(guard.store_ref()).len(), 1);
        assert!(guard
            .store_ref()
            .records("project_log::p1", "evidence")
            .unwrap()
            .is_empty());
        assert_eq!(
            load_handoff(guard.store_ref(), "p1").phase,
            HandoffPhase::Draft
        );
    }
}

#[tokio::test]
async fn original_offer_survives_restart_and_accepts_under_restored_pairing() {
    for batch in [false, true] {
        let (wb, wire, _source_dir, target_dir) = fixture();
        assert_eq!(admit_handoff(&wb, &wire)["pending"], true);
        let path = wb.lock_unpoisoned().store_ref().path().to_owned();
        drop(wb);
        let store = Store::open(&path).unwrap();
        let offer = pending_incoming(&store).pop().unwrap();
        assert_eq!(
            serde_json::to_value(pending_handoff_wire(&offer).unwrap()).unwrap(),
            serde_json::to_value(&wire).unwrap()
        );
        let mut fed = Federation::open(
            AuthorityId::new("bob"),
            target_dir.path(),
            "wss://127.0.0.1:1".into(),
        )
        .unwrap();
        fed.restore_bridges(&folded_bridges(&store));
        let wb = Arc::new(Mutex::new(
            Workbench::new(store)
                .with_authority(AuthorityId::new("bob"))
                .with_root(target_dir.path())
                .with_federation(fed),
        ));
        let (status, body) = accept(&wb, batch).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let guard = wb.lock_unpoisoned();
        assert!(pending_incoming(guard.store_ref()).is_empty());
        assert_eq!(
            load_handoff(guard.store_ref(), "p1").phase,
            HandoffPhase::Committed
        );
        assert_eq!(guard.project_home_id("p1"), Some(guard.home_id()));
        assert_eq!(
            guard
                .store_ref()
                .records("project_log::p1", "evidence")
                .unwrap(),
            vec!["original history"]
        );
    }
}

#[tokio::test]
async fn missing_malformed_and_mismatched_pending_evidence_never_imports() {
    for damage in [
        "legacy",
        "missing_content",
        "missing_log",
        "missing_archive",
        "malformed_archive",
        "malformed_content",
        "wrong_kind",
        "wrong_project",
        "wrong_source",
        "wrong_target",
        "wrong_home",
        "expired_delegation",
    ] {
        let (wb, wire, source_dir, _target_dir) = fixture();
        assert_eq!(admit_handoff(&wb, &wire)["pending"], true);
        let before = {
            let mut guard = wb.lock_unpoisoned();
            let mut offer = pending_incoming(guard.store_ref()).pop().unwrap();
            match damage {
                "legacy" => {
                    offer.as_object_mut().unwrap().remove("wire");
                    offer["log"] = serde_json::to_value(&wire.log).unwrap();
                }
                "missing_content" => {
                    offer["wire"].as_object_mut().unwrap().remove("content");
                }
                "missing_log" => {
                    offer["wire"].as_object_mut().unwrap().remove("log");
                }
                "missing_archive" => offer["wire"]["project_commands"] = serde_json::Value::Null,
                "malformed_archive" => {
                    offer["wire"]["project_commands"] = serde_json::json!({"broken":true})
                }
                "malformed_content" => offer["wire"]["content"] = serde_json::json!("broken"),
                "wrong_kind" => offer["wire"]["kind"] = serde_json::json!("Committed"),
                "wrong_project" => offer["wire"]["project"] = serde_json::json!("other"),
                "wrong_source" => offer["wire"]["source"] = serde_json::json!("other"),
                "wrong_target" => offer["wire"]["target"] = serde_json::json!("other"),
                "wrong_home" => offer["wire"]["source_home"] = serde_json::json!("home:other"),
                "expired_delegation" => {
                    let root = FileKeyStore::new(source_dir.path().join("keys"))
                        .signing_key(&AuthorityId::new("alice"));
                    let expired = DeviceDelegation::issue(
                        &root,
                        PublicKey::new(wire.source_pubkey.clone()),
                        0,
                    );
                    offer["wire"]["delegation"] = serde_json::to_value(expired).unwrap();
                }
                _ => unreachable!(),
            }
            guard
                .store_mut()
                .append_record(HANDOFF_INCOMING_SCOPE, "event", &offer.to_string())
                .unwrap();
            guard.store_ref().scope_high_water_marks().unwrap()
        };
        let (status, body) = accept(&wb, false).await;
        assert!(
            matches!(status, StatusCode::CONFLICT | StatusCode::FORBIDDEN),
            "{damage}: {status} {body}"
        );
        let (status, body) = accept(&wb, true).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["accepted"],
            serde_json::json!([])
        );
        let guard = wb.lock_unpoisoned();
        assert_eq!(
            guard.store_ref().scope_high_water_marks().unwrap(),
            before,
            "{damage}"
        );
        assert_eq!(pending_incoming(guard.store_ref()).len(), 1);
    }
}

#[test]
fn failed_pending_publication_is_not_acknowledged_and_can_retry() {
    let (wb, wire, _source_dir, _target_dir) = fixture();
    let probe = rusqlite::Connection::open(wb.lock_unpoisoned().store_ref().path()).unwrap();
    probe.execute_batch("CREATE TRIGGER fail_pending BEFORE INSERT ON events WHEN NEW.scope_id = 'handoff::incoming' BEGIN SELECT RAISE(ABORT, 'pending fault'); END;").unwrap();
    let verdict = admit_handoff(&wb, &wire);
    assert_eq!(verdict["ok"], false);
    assert_ne!(verdict["pending"], true);
    assert!(pending_incoming(wb.lock_unpoisoned().store_ref()).is_empty());
    probe.execute_batch("DROP TRIGGER fail_pending").unwrap();
    assert_eq!(admit_handoff(&wb, &wire)["pending"], true);
}
