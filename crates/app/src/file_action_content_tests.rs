use super::*;

fn counts(wb: &Workbench) -> (i64, i64, i64) {
    let db = rusqlite::Connection::open_with_flags(
        wb.store_ref().path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.query_row("SELECT (SELECT COUNT(*) FROM events), (SELECT COUNT(*) FROM records), (SELECT COUNT(*) FROM commands)",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap()
}

#[test]
fn retained_file_read_uses_recorded_bytes_without_importing_or_admitting_saved() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, intent, token) = setup(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let selected = wb.engagement_workspace_path(&intent.chat_id, &intent.path);
    wb.engagements[&intent.chat_id]
        .write_file(&selected, "unadmitted disk edit")
        .unwrap();
    let events = wb.store_ref().retained_events(LIBRARY_SCOPE).unwrap();
    let before = counts(&wb);
    let observed = wb
        .observe_native_file_content(&context, &intent.chat_id, &intent.path)
        .unwrap();
    assert_eq!(observed.cut, intent.base_cut);
    assert_eq!(observed.content.as_deref(), Some("recorded base"));
    assert_eq!(
        observed.content_hash.as_deref(),
        Some(whipplescript_store::stable_hash_hex("recorded base").as_str())
    );
    assert_eq!(observed.observer, "alice");
    assert!(observed
        .restrictions
        .unwrap()
        .reader
        .contains("classification:regulated"));
    assert_eq!(
        wb.store_ref().retained_events(LIBRARY_SCOPE).unwrap(),
        events
    );
    assert_eq!(
        wb.engagements[&intent.chat_id]
            .read_file(&selected)
            .unwrap(),
        "unadmitted disk edit"
    );
    assert_eq!(
        wb.engagements[&intent.chat_id]
            .observe()
            .unwrap()
            .recorded_cut
            .as_deref(),
        Some(intent.base_cut.as_str())
    );
    let absent = wb
        .observe_native_file_content(&context, &intent.chat_id, "absent.txt")
        .unwrap();
    assert_eq!(absent.cut, intent.base_cut);
    assert!(
        absent.content.is_none() && absent.content_hash.is_none() && absent.restrictions.is_none()
    );
    assert_eq!(
        counts(&wb),
        before,
        "a file observation must not append action or Saved evidence"
    );
}

#[tokio::test]
async fn retained_file_content_http_binds_actor_home_and_selected_path() {
    for wrapped in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (shared, intent, token) = setup(dir.path());
        let mut app = crate::open_control_plane(shared.clone());
        if wrapped {
            app = app.layer(axum::middleware::from_fn_with_state(
                shared.clone(),
                crate::home_routes::require_home_admission,
            ));
        }
        let admission = {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/home/admissions")
                        .header("authorization", format!("Bearer {token}"))
                        .header("idempotency-key", "content-read-home")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            Some(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["admission"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
        };
        for (actor, authenticated, expected) in [
            ("alice", false, StatusCode::UNAUTHORIZED),
            ("different-reader", true, StatusCode::FORBIDDEN),
            ("alice", true, StatusCode::OK),
        ] {
            let query = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs([("expected_actor", actor), ("path", "note.txt")])
                .finish();
            let mut request = Request::builder().uri(format!(
                "/chats/{}/file-actions/content?{query}",
                intent.chat_id
            ));
            if authenticated {
                request = request.header("authorization", format!("Bearer {token}"));
            }
            if let Some(admission) = &admission {
                request = request.header(HOME_ADMISSION_HEADER, admission);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            if authenticated {
                assert_eq!(response.headers()["cache-control"], "no-store");
            }
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            if expected == StatusCode::OK {
                let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(body["content"], "recorded base");
                assert_eq!(body["cut"], intent.base_cut);
                assert_eq!(body["observer"], "alice");
                assert_eq!(body["chat"], intent.chat_id);
                assert_eq!(body["path"], "note.txt");
                assert_eq!(body["home"], shared.lock_unpoisoned().home_id().as_str());
                assert!(body.get("saved").is_none());
            } else {
                assert!(!String::from_utf8_lossy(&bytes).contains("recorded base"));
            }
        }
    }
}

#[test]
fn retained_file_read_keeps_original_restrictions_after_target_relaxation() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, intent, token) = setup(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let authority = current_target_authority(
        wb.store_ref(),
        wb.home_id(),
        &context,
        &NativeTargetIntent {
            chat_id: &intent.chat_id,
            path: &intent.path,
            request_id: "read",
        },
        NativeActionKind::InspectHistory,
    )
    .unwrap();
    let mut target = wb.library.work_targets[&authority.target_id].clone();
    target.attributes.classification = gaugedesk_core::abac::Classification::Public;
    wb.store_mut()
        .append_record(
            LIBRARY_SCOPE,
            "work_target",
            &serde_json::to_string(&target).unwrap(),
        )
        .unwrap();
    let observed = wb
        .observe_native_file_content(&context, &intent.chat_id, &intent.path)
        .unwrap();
    assert!(observed
        .restrictions
        .unwrap()
        .reader
        .contains("classification:regulated"));
    membership(&mut wb, "alice", "member");
    let grant = crate::org::MemberGrantRecord {
        id: "alice-project".into(),
        authority: "alice".into(),
        project_id: authority.project_id,
        ..Default::default()
    };
    wb.store_mut()
        .append_record(
            ORG_SCOPE,
            "member_grant",
            &serde_json::to_string(&grant).unwrap(),
        )
        .unwrap();
    // Current public-target access is valid; it cannot clear the older source.
    let current = current_target_authority(
        wb.store_ref(),
        wb.home_id(),
        &context,
        &NativeTargetIntent {
            chat_id: &intent.chat_id,
            path: &intent.path,
            request_id: "read",
        },
        NativeActionKind::InspectHistory,
    )
    .unwrap();
    assert!(!current.read_clearances.contains("classification:regulated"));
    let result = wb.observe_native_file_content(&context, &intent.chat_id, &intent.path);
    assert!(
        result.is_err(),
        "retained source disclosed to an uncleared reader"
    );
    let error = result.err().unwrap();
    assert!(error.contains("current actor does not clear"), "{error}");
}

#[test]
fn retained_file_read_refuses_opaque_history_and_revoked_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, intent, token) = setup(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let selected = wb.engagement_workspace_path(&intent.chat_id, &intent.path);
    wb.engagements[&intent.chat_id]
        .write_file(&selected, "unknown external writer")
        .unwrap();
    wb.engagements[&intent.chat_id]
        .commit_turn("opaque imported history")
        .unwrap();
    let error = wb
        .observe_native_file_content(&context, &intent.chat_id, &intent.path)
        .err()
        .unwrap();
    assert!(
        error.contains("requires explicit provenance migration"),
        "{error}"
    );
    wb.revoke_account_session(&token);
    assert!(wb
        .observe_native_file_content(&context, &intent.chat_id, "absent.txt")
        .is_err());
}
