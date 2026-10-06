use super::*;
use std::{convert::Infallible, time::Duration};

fn chat(wb: &SharedWorkbench) -> String {
    // Direct workbench calls in this fixture are an admitted session on shared.
    wb.lock_unpoisoned().hold_session_for_tests("shared");
    wb.lock_unpoisoned()
        .create_chat_in_instance_on_target(
            &crate::library_routes::general_placement_id("shared"),
            "Clinical work",
            None,
        )
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .into()
}

fn context(wb: &SharedWorkbench, admission: &str) -> AuthenticatedActionContext {
    let guard = wb.lock_unpoisoned();
    guard
        .office_staff_action_context(
            &guard.office_staff_lease(ALICE).unwrap(),
            &crate::home_admission::HomeAdmissionToken::parse(admission).unwrap(),
        )
        .unwrap()
}

fn app(wb: &SharedWorkbench) -> Router {
    Router::new()
        .route(
            "/chats/{id}/context/stream",
            axum::routing::post(crate::resource_store::post_context_stream)
                .get(crate::resource_store::get_context_stream),
        )
        .with_state(wb.clone())
}

fn request(chat: &str, body: Body, context: Option<AuthenticatedActionContext>) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!(
            "/chats/{chat}/context/stream?name=private-recording.txt"
        ))
        .header("authorization", format!("Bearer {ALICE}"))
        .header("idempotency-key", "upload-test")
        .body(body)
        .unwrap();
    if let Some(context) = context {
        request
            .extensions_mut()
            .insert(crate::identity::AuthenticatedActor(context.actor().clone()));
        request.extensions_mut().insert(context);
    }
    request
}

#[tokio::test]
async fn office_upload_requires_exact_context_before_staging() {
    let root = tempfile::tempdir().unwrap();
    let (wb, admission_app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let _ = admit(&admission_app, ALICE).await;
    let chat = chat(&wb);
    let response = app(&wb)
        .oneshot(request(&chat, Body::from("private bytes"), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!wb.lock_unpoisoned().staging_uploads_dir().exists());
}

#[tokio::test]
async fn office_upload_ends_quiet_reception_and_removes_partial_after_access_removal() {
    for removal in ["grant", "source", "admission"] {
        let root = tempfile::tempdir().unwrap();
        let (wb, admission_app, _, _) = fixture(root.path());
        let hub = hub().await;
        install(&wb, &hub);
        let admission = admit(&admission_app, ALICE).await;
        let context = context(&wb, &admission);
        let chat = chat(&wb);
        let staging = wb.lock_unpoisoned().staging_uploads_dir();
        let (sender, receiver) =
            tokio::sync::mpsc::channel::<Result<axum::body::Bytes, Infallible>>(2);
        sender
            .send(Ok(axum::body::Bytes::from_static(b"private prefix")))
            .await
            .unwrap();
        let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(receiver));
        let running = tokio::spawn(app(&wb).oneshot(request(&chat, body, Some(context))));
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if std::fs::read_dir(&staging).is_ok_and(|mut files| files.next().is_some()) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        match removal {
            "grant" => grant(&wb, "alice", crate::library::RecordOp::Tombstone),
            "source" => {
                let mut guard = wb.lock_unpoisoned();
                let source = guard.office_staff_verifier().unwrap();
                assert!(guard
                    .observe_office_staff_check(
                        &source,
                        &crate::account_session::session_id(ALICE),
                        source::SourceCheck::Refused
                    )
                    .is_err());
            }
            "admission" => {
                let mut guard = wb.lock_unpoisoned();
                let home = guard.home_id().clone();
                guard
                    .home_admissions
                    .revoke(&home, &AuthorityId::new("alice"));
            }
            _ => unreachable!(),
        }
        // Keep the sender open and send nothing: revocation must end reception
        // without waiting for the peer to finish the body.
        let response = tokio::time::timeout(Duration::from_secs(3), running)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{removal}");
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), b"office upload authority ended");
        assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0, "{removal}");
        assert!(sender
            .send(Ok(axum::body::Bytes::from_static(b"later bytes")))
            .await
            .is_err());
    }
}

#[tokio::test]
async fn office_upload_offset_requires_context_even_for_an_absent_prefix() {
    let root = tempfile::tempdir().unwrap();
    let (wb, admission_app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let _ = admit(&admission_app, ALICE).await;
    let chat = chat(&wb);
    let mut query = request(&chat, Body::empty(), None);
    *query.method_mut() = axum::http::Method::GET;
    let response = app(&wb).oneshot(query).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(body.as_ref(), b"office upload authority ended");
}

#[tokio::test]
async fn office_upload_offset_refuses_retained_bytes_after_grant_removal() {
    let root = tempfile::tempdir().unwrap();
    let (wb, admission_app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&admission_app, ALICE).await;
    let context = context(&wb, &admission);
    let chat = chat(&wb);
    let body = Body::from_stream(futures::stream::iter([
        Ok(axum::body::Bytes::from_static(b"private prefix")),
        Err(std::io::Error::other("synthetic disconnect")),
    ]));
    let response = app(&wb)
        .oneshot(request(&chat, body, Some(context.clone())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let query = || {
        let mut query = request(&chat, Body::empty(), Some(context.clone()));
        *query.method_mut() = axum::http::Method::GET;
        query
    };
    let response = app(&wb).oneshot(query()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["received"],
        14
    );
    grant(&wb, "alice", crate::library::RecordOp::Tombstone);
    let response = app(&wb).oneshot(query()).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(bytes.as_ref(), b"office upload authority ended");
}

fn interrupted(bytes: &'static [u8]) -> Body {
    Body::from_stream(futures::stream::iter([
        Ok(axum::body::Bytes::from_static(bytes)),
        Err(std::io::Error::other("synthetic disconnect")),
    ]))
}

async fn prefix(wb: &SharedWorkbench, chat: &str, context: &AuthenticatedActionContext) {
    assert_eq!(
        app(wb)
            .oneshot(request(
                chat,
                interrupted(b"private prefix"),
                Some(context.clone())
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn office_upload_resumes_only_original_parent_and_parameters() {
    for change in [
        "none",
        "admission",
        "target",
        "classification",
        "region",
        "lost-proof",
    ] {
        let root = tempfile::tempdir().unwrap();
        let (wb, admission_app, _, _) = fixture(root.path());
        let hub = hub().await;
        install(&wb, &hub);
        let admission = admit(&admission_app, ALICE).await;
        let captured = context(&wb, &admission);
        let chat = chat(&wb);
        prefix(&wb, &chat, &captured).await;
        let staging = wb.lock_unpoisoned().staging_uploads_dir();
        let path = std::fs::read_dir(&staging)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let current = if change == "admission" {
            let renewed = admit(&admission_app, ALICE).await;
            context(&wb, &renewed)
        } else {
            captured.clone()
        };
        if change == "lost-proof" {
            crate::resource_store::forget_office_upload_for_test(&path);
        }
        let suffix = match change {
            "target" => "&target_id=another-target",
            "classification" => "&classification=another-classification",
            "region" => "&region=another-region",
            _ => "",
        };
        if !suffix.is_empty() {
            let mut changed_query = request(&chat, Body::empty(), Some(current.clone()));
            *changed_query.method_mut() = axum::http::Method::GET;
            *changed_query.uri_mut() =
                format!("/chats/{chat}/context/stream?name=private-recording.txt{suffix}")
                    .parse()
                    .unwrap();
            assert_eq!(
                app(&wb).oneshot(changed_query).await.unwrap().status(),
                StatusCode::FORBIDDEN,
                "{change}"
            );
        }
        let mut retry = request(&chat, interrupted(b" suffix"), Some(current.clone()));
        *retry.uri_mut() =
            format!("/chats/{chat}/context/stream?name=private-recording.txt&offset=14{suffix}")
                .parse()
                .unwrap();
        let response = app(&wb).oneshot(retry).await.unwrap();
        assert_eq!(
            response.status(),
            if change == "none" {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::FORBIDDEN
            },
            "{change}"
        );
        let expected = if change == "none" {
            b"private prefix suffix".as_slice()
        } else {
            b"private prefix".as_slice()
        };
        assert_eq!(std::fs::read(&path).unwrap(), expected, "{change}");
        let mut query = request(&chat, Body::empty(), Some(current));
        *query.method_mut() = axum::http::Method::GET;
        let response = app(&wb).oneshot(query).await.unwrap();
        if matches!(change, "admission" | "lost-proof") {
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{change}");
        } else {
            assert_eq!(response.status(), StatusCode::OK, "{change}");
            let bytes = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["received"],
                expected.len(),
                "{change}"
            );
        }
    }
}

#[tokio::test]
async fn office_upload_source_recheck_does_not_renew_original_prefix_deadline() {
    let root = tempfile::tempdir().unwrap();
    let (wb, admission_app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&admission_app, ALICE).await;
    let chat = chat(&wb);
    {
        let mut guard = wb.lock_unpoisoned();
        let source = guard.office_staff_verifier().unwrap();
        let now = crate::account::session_now_ms();
        guard
            .observe_office_staff_check(
                &source,
                &crate::account_session::session_id(ALICE),
                source::SourceCheck::Verified(source::VerifiedSourceSession::for_test(
                    source.issuer(),
                    "alice",
                    crate::account_session::AccountSessionEvidence {
                        session_ref: crate::account_session::session_id(ALICE),
                        method: "passkey".into(),
                        issued_at_ms: hub.state.minted,
                        expires_at_ms: now + 1000,
                    },
                    now,
                )),
            )
            .unwrap();
    }
    prefix(&wb, &chat, &context(&wb, &admission)).await;
    assert_eq!(
        send(
            &admission_app,
            "GET",
            "/projects/shared/inspect",
            Some(ALICE),
            Some(&admission)
        )
        .await
        .0,
        StatusCode::OK
    );
    tokio::time::sleep(Duration::from_millis(1050)).await;
    // Fresh source evidence is valid, but it cannot replace the transfer's ceiling.
    let fresh = context(&wb, &admission);
    let mut query = request(&chat, Body::empty(), Some(fresh.clone()));
    *query.method_mut() = axum::http::Method::GET;
    assert_eq!(
        app(&wb).oneshot(query).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut retry = request(&chat, interrupted(b" suffix"), Some(fresh));
    *retry.uri_mut() = format!("/chats/{chat}/context/stream?name=private-recording.txt&offset=14")
        .parse()
        .unwrap();
    assert_eq!(
        app(&wb).oneshot(retry).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let staging = wb.lock_unpoisoned().staging_uploads_dir();
    let path = std::fs::read_dir(staging)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(std::fs::read(path).unwrap(), b"private prefix");
}

#[tokio::test]
async fn office_upload_commits_exact_binary_with_original_staff_and_http_receipt() {
    let root = tempfile::tempdir().unwrap();
    let (wb, admission_app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&admission_app, ALICE).await;
    let captured = context(&wb, &admission);
    let submitted = request("unused", Body::empty(), Some(captured.clone()));
    let client = crate::client_admission::ClientBuild::from_headers(submitted.headers());
    let chat = chat(&wb);
    let original = crate::engine::office_authority::OfficeTaskAuthority::for_turn(
        &wb,
        &chat,
        Some(&captured),
        Some(&client),
        Some(captured.actor()),
        Some(ALICE),
    )
    .unwrap()
    .unwrap();
    let native =
        gaugedesk_workspace::Instance::init_at(root.path().join("office-native-upload")).unwrap();
    let eng = native.create_engagement(&chat).unwrap();
    let prefix = wb
        .lock_unpoisoned()
        .engagement_context_target_root(&chat, None)
        .unwrap();
    let relative = prefix.map_or_else(
        || "private-recording.txt".to_string(),
        |prefix| format!("{prefix}/private-recording.txt"),
    );
    eng.write_file("unrelated.txt", "pending staff work")
        .unwrap();
    wb.lock_unpoisoned()
        .register_engagement(&chat, "shared", Box::new(eng.clone()));
    let bytes = vec![0xff; 9 * 1024 * 1024];
    let response = app(&wb)
        .oneshot(request(&chat, Body::from(bytes.clone()), Some(captured)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let reply: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let handle = reply["resource"].as_str().unwrap();
    let (scope, command_id) = crate::command_idempotency::command_identity(
        &axum::http::Method::POST,
        &format!("/chats/{chat}/context/stream"),
        &crate::command_idempotency::caller_hash(request(&chat, Body::empty(), None).headers()),
        "upload-test",
    );
    let guard = wb.lock_unpoisoned();
    let command = guard
        .store_ref()
        .command_for_key(&scope, "upload-test")
        .unwrap()
        .unwrap();
    assert_eq!(command.command_id, command_id);
    assert_eq!(command.status, "applied");
    let record = crate::resource_store::get(
        guard.store_ref(),
        &chat,
        &gaugedesk_core::resource::ResourceId::new(handle),
    )
    .unwrap()
    .unwrap();
    assert_eq!(record.resource.owner.as_str(), "alice");
    let gaugedesk_core::resource::ContentLocator::Workspace { commit, .. } = &record.locator else {
        panic!("native upload locator missing");
    };
    drop(guard);
    let vcs = whipplescript_store::vcs::NativeWorkspaceVcs::open_read_only(
        root.path()
            .join("office-native-upload/.repo.whipplescript/branches.sqlite"),
        root.path()
            .join("office-native-upload/.repo.whipplescript/content.sqlite"),
    )
    .unwrap();
    let cut = vcs.get_cut(commit).unwrap().unwrap();
    assert_eq!(cut.actor.as_deref(), Some("human:alice"));
    assert_eq!(cut.intent.as_deref(), Some(command_id.as_str()));
    let manifest = vcs.cut_manifest(commit).unwrap().unwrap();
    assert!(!manifest.contains_key("unrelated.txt"));
    assert_eq!(
        vcs.content_store()
            .get(&manifest[&relative])
            .unwrap()
            .unwrap(),
        bytes
    );
    assert_eq!(
        std::fs::read(eng.path().join("unrelated.txt")).unwrap(),
        b"pending staff work"
    );
    let mut receiver = wb.lock_unpoisoned().sender(&chat).subscribe();
    grant(&wb, "alice", crate::library::RecordOp::Tombstone);
    let mut guard = wb.lock_unpoisoned();
    let refused = crate::resource_store::finish_office_upload_response(
        &mut guard, &chat, &record, &original, 1,
    );
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert!(!guard
        .store_mut()
        .set_unreceipted_command_failure(&command_id, "rejected")
        .unwrap());
    assert_eq!(
        guard
            .store_ref()
            .command(&command_id)
            .unwrap()
            .unwrap()
            .status,
        "applied"
    );
}

#[tokio::test]
async fn office_upload_failed_product_receipt_preserves_native_fact_without_resource_grant() {
    let root = tempfile::tempdir().unwrap();
    let (wb, admission_app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&admission_app, ALICE).await;
    let captured = context(&wb, &admission);
    let chat = chat(&wb);
    let native =
        gaugedesk_workspace::Instance::init_at(root.path().join("office-native-upload")).unwrap();
    let eng = native.create_engagement(&chat).unwrap();
    wb.lock_unpoisoned()
        .register_engagement(&chat, "shared", Box::new(eng.clone()));
    let db = rusqlite::Connection::open(wb.lock_unpoisoned().store_ref().path()).unwrap();
    db.execute_batch("CREATE TRIGGER refuse_upload_receipt BEFORE INSERT ON command_receipts BEGIN SELECT RAISE(ABORT, 'synthetic receipt failure'); END;").unwrap();
    let response = app(&wb)
        .oneshot(request(
            &chat,
            Body::from("original completed upload"),
            Some(captured),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap()
            .as_ref(),
        b"office upload authority ended"
    );
    let guard = wb.lock_unpoisoned();
    assert!(crate::resource_store::list(guard.store_ref(), &chat)
        .unwrap()
        .is_empty());
    let grants: i64 = db
        .query_row(
            "SELECT count(*) FROM events WHERE kind = ?1",
            [<gaugedesk_core::resource_access::AccessState as gaugedesk_core::Lifecycle>::KIND],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(grants, 0);
    drop(guard);
    let vcs = whipplescript_store::vcs::NativeWorkspaceVcs::open_read_only(
        root.path()
            .join("office-native-upload/.repo.whipplescript/branches.sqlite"),
        root.path()
            .join("office-native-upload/.repo.whipplescript/content.sqlite"),
    )
    .unwrap();
    let cut = vcs
        .get_branch(eng.branch())
        .unwrap()
        .unwrap()
        .head_cut_id
        .expect("already committed native history survives");
    assert_eq!(
        vcs.get_cut(&cut).unwrap().unwrap().actor.as_deref(),
        Some("human:alice")
    );
}

fn buffered_app(wb: &SharedWorkbench, guarded: bool) -> Router {
    let router = Router::new().route(
        "/chats/{id}/context/upload",
        axum::routing::post(crate::resource_store::post_context_upload),
    );
    let router = if guarded {
        router.layer(axum::middleware::from_fn_with_state(
            wb.clone(),
            crate::command_idempotency::guard,
        ))
    } else {
        router
    };
    router.with_state(wb.clone())
}

fn buffered_request(
    chat: &str,
    files: serde_json::Value,
    context: Option<AuthenticatedActionContext>,
) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("/chats/{chat}/context/upload"))
        .header("authorization", format!("Bearer {ALICE}"))
        .header("idempotency-key", "buffered-test")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"files": files}).to_string()))
        .unwrap();
    if let Some(context) = context {
        request
            .extensions_mut()
            .insert(crate::identity::AuthenticatedActor(context.actor().clone()));
        request.extensions_mut().insert(context);
    }
    request
}

#[tokio::test]
async fn office_buffered_upload_publishes_all_files_with_one_original_command() {
    let root = tempfile::tempdir().unwrap();
    let (wb, admission_app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&admission_app, ALICE).await;
    let captured = context(&wb, &admission);
    let chat = chat(&wb);
    let native =
        gaugedesk_workspace::Instance::init_at(root.path().join("buffered-native")).unwrap();
    let eng = native.create_engagement(&chat).unwrap();
    eng.write_file("unrelated.txt", "pending work").unwrap();
    wb.lock_unpoisoned()
        .register_engagement(&chat, "shared", Box::new(eng.clone()));
    let files = serde_json::json!([
        {"name":"text.txt","content":"synthetic clinical text"},
        {"name":"binary.bin","content_base64":"/wCJ"}
    ]);
    let request = buffered_request(&chat, files, Some(captured));
    let (scope, command_id) = crate::command_idempotency::command_identity(
        &axum::http::Method::POST,
        request.uri().path(),
        &crate::command_idempotency::caller_hash(request.headers()),
        "buffered-test",
    );
    let response = buffered_app(&wb, true).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let reply: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reply["ingested"], 2);
    let guard = wb.lock_unpoisoned();
    let command = guard
        .store_ref()
        .command_for_key(&scope, "buffered-test")
        .unwrap()
        .unwrap();
    assert_eq!(command.command_id, command_id);
    assert_eq!(command.status, "applied");
    let record = crate::resource_store::get(
        guard.store_ref(),
        &chat,
        &gaugedesk_core::resource::ResourceId::new(reply["resource"].as_str().unwrap()),
    )
    .unwrap()
    .unwrap();
    assert_eq!(record.resource.owner.as_str(), "alice");
    let imports = guard.store_ref().records(&chat, "context-import").unwrap();
    assert_eq!(imports.len(), 1);
    let binding: serde_json::Value = serde_json::from_str(&imports[0]).unwrap();
    assert_eq!(binding["complete"], true);
    assert_eq!(binding["files"].as_object().unwrap().len(), 2);
    let gaugedesk_core::resource::ContentLocator::Workspace { commit, .. } = record.locator else {
        panic!("native locator missing");
    };
    drop(guard);
    let vcs = whipplescript_store::vcs::NativeWorkspaceVcs::open_read_only(
        root.path()
            .join("buffered-native/.repo.whipplescript/branches.sqlite"),
        root.path()
            .join("buffered-native/.repo.whipplescript/content.sqlite"),
    )
    .unwrap();
    let cut = vcs.get_cut(&commit).unwrap().unwrap();
    assert_eq!(cut.actor.as_deref(), Some("human:alice"));
    assert_eq!(cut.intent.as_deref(), Some(command_id.as_str()));
    let manifest = vcs.cut_manifest(&commit).unwrap().unwrap();
    assert!(!manifest.contains_key("unrelated.txt"));
    for (path, hash) in binding["files"].as_object().unwrap() {
        assert_eq!(manifest[path], hash.as_str().unwrap());
        let bytes = vcs
            .content_store()
            .get(hash.as_str().unwrap())
            .unwrap()
            .unwrap();
        if path.ends_with("binary.bin") {
            assert_eq!(bytes, [0xff, 0, 0x89]);
        } else {
            assert_eq!(bytes, b"synthetic clinical text");
        }
    }
    assert_eq!(
        std::fs::read(eng.path().join("unrelated.txt")).unwrap(),
        b"pending work"
    );
    assert_eq!(
        std::fs::read_dir(wb.lock_unpoisoned().staging_uploads_dir())
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn office_buffered_upload_refuses_missing_proof_duplicate_destination_and_revocation() {
    for failure in ["context", "intent", "duplicate", "revoked"] {
        let root = tempfile::tempdir().unwrap();
        let (wb, admission_app, _, _) = fixture(root.path());
        let hub = hub().await;
        install(&wb, &hub);
        let admission = admit(&admission_app, ALICE).await;
        let captured = context(&wb, &admission);
        let chat = chat(&wb);
        let native =
            gaugedesk_workspace::Instance::init_at(root.path().join("buffered-native")).unwrap();
        let eng = native.create_engagement(&chat).unwrap();
        wb.lock_unpoisoned()
            .register_engagement(&chat, "shared", Box::new(eng.clone()));
        if failure == "revoked" {
            grant(&wb, "alice", crate::library::RecordOp::Tombstone);
        }
        let files = if failure == "duplicate" {
            serde_json::json!([
                {"name":"one/Same.txt","content":"first"}, {"name":"two/same.txt","content":"second"}
            ])
        } else {
            serde_json::json!([{"name":"file.txt","content":"private"}])
        };
        let request = buffered_request(&chat, files, (failure != "context").then_some(captured));
        assert_eq!(
            buffered_app(&wb, failure != "intent")
                .oneshot(request)
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN,
            "{failure}"
        );
        let vcs = whipplescript_store::vcs::NativeWorkspaceVcs::open_read_only(
            root.path()
                .join("buffered-native/.repo.whipplescript/branches.sqlite"),
            root.path()
                .join("buffered-native/.repo.whipplescript/content.sqlite"),
        )
        .unwrap();
        assert!(
            vcs.get_branch(eng.branch())
                .unwrap()
                .unwrap()
                .head_cut_id
                .is_none(),
            "{failure}"
        );
        assert!(
            !wb.lock_unpoisoned().staging_uploads_dir().exists(),
            "{failure}"
        );
        assert!(
            crate::resource_store::list(wb.lock_unpoisoned().store_ref(), &chat)
                .unwrap()
                .is_empty(),
            "{failure}"
        );
    }
}

#[tokio::test]
async fn office_buffered_receipt_failure_leaves_no_partial_resource_or_access() {
    let root = tempfile::tempdir().unwrap();
    let (wb, admission_app, _, _) = fixture(root.path());
    let hub = hub().await;
    install(&wb, &hub);
    let admission = admit(&admission_app, ALICE).await;
    let captured = context(&wb, &admission);
    let chat = chat(&wb);
    let native =
        gaugedesk_workspace::Instance::init_at(root.path().join("buffered-native")).unwrap();
    let eng = native.create_engagement(&chat).unwrap();
    wb.lock_unpoisoned()
        .register_engagement(&chat, "shared", Box::new(eng.clone()));
    let db = rusqlite::Connection::open(wb.lock_unpoisoned().store_ref().path()).unwrap();
    db.execute_batch("CREATE TRIGGER refuse_buffered_receipt BEFORE INSERT ON command_receipts BEGIN SELECT RAISE(ABORT, 'synthetic receipt failure'); END;").unwrap();
    let request = buffered_request(
        &chat,
        serde_json::json!([
            {"name":"first.txt","content":"first private input"},
            {"name":"last.txt","content":"last private input"}
        ]),
        Some(captured),
    );
    let (scope, command_id) = crate::command_idempotency::command_identity(
        &axum::http::Method::POST,
        request.uri().path(),
        &crate::command_idempotency::caller_hash(request.headers()),
        "buffered-test",
    );
    let response = buffered_app(&wb, true).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let guard = wb.lock_unpoisoned();
    assert!(crate::resource_store::list(guard.store_ref(), &chat)
        .unwrap()
        .is_empty());
    assert!(guard
        .store_ref()
        .records(&chat, "context-import")
        .unwrap()
        .is_empty());
    let count: i64 = db
        .query_row(
            "SELECT count(*) FROM events WHERE kind = ?1",
            [<gaugedesk_core::resource_access::AccessState as gaugedesk_core::Lifecycle>::KIND],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    assert_eq!(
        guard
            .store_ref()
            .command_for_key(&scope, "buffered-test")
            .unwrap()
            .unwrap()
            .status,
        "rejected"
    );
    drop(guard);
    let vcs = whipplescript_store::vcs::NativeWorkspaceVcs::open_read_only(
        root.path()
            .join("buffered-native/.repo.whipplescript/branches.sqlite"),
        root.path()
            .join("buffered-native/.repo.whipplescript/content.sqlite"),
    )
    .unwrap();
    let cut = vcs
        .get_branch(eng.branch())
        .unwrap()
        .unwrap()
        .head_cut_id
        .unwrap();
    let actual = vcs.get_cut(&cut).unwrap().unwrap();
    assert_eq!(actual.actor.as_deref(), Some("human:alice"));
    assert_eq!(actual.intent.as_deref(), Some(command_id.as_str()));
    assert_eq!(vcs.cut_manifest(&cut).unwrap().unwrap().len(), 2);
    assert_eq!(
        std::fs::read_dir(wb.lock_unpoisoned().staging_uploads_dir())
            .unwrap()
            .count(),
        0
    );
}
