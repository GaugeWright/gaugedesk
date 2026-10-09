//! WS71 choice-card family through the actual Home socket and governed runtime.
//! This child shares the existing fixture's real IdP/Home admission and provider
//! wire. No handler actor extension or choice record is injected.
use super::*;

async fn ask(fixture: &Fixture, call_id: &str) -> Value {
    let questions = if call_id.ends_with("second") {
        json!([{ "prompt":"Choose several synthetic options", "multiple":true,
            "options":[{"label":"First","description":"Synthetic first"},
                {"label":"Second","description":"Synthetic second"},
                {"label":"Third","description":"Synthetic third"}]},
            {"prompt":"Or describe a synthetic Other", "options":[
                {"label":"One","description":"Synthetic one"},
                {"label":"Two","description":"Synthetic two"}]}])
    } else {
        json!([{ "prompt":"Which synthetic choice?", "options":[
        {"label":"First","description":"Synthetic first"},
        {"label":"Second","description":"Synthetic second"}]}])
    };
    let turn = fixture.start("Ask a synthetic choice card.");
    let first = fixture.next_call().await;
    first
        .finish
        .send((
            StatusCode::OK,
            tool("ask_choices", json!({"questions":questions}), call_id, 1),
        ))
        .expect("controlled provider reply");
    fixture
        .next_call()
        .await
        .finish
        .send((StatusCode::OK, answer("Card recorded.", 1)))
        .expect("controlled completion");
    let completed = turn.await.expect("asking runtime");
    assert_eq!(completed.0, 200, "asking turn: {}", completed.1);
    let cards = fixture
        .request(
            READER,
            "GET",
            &format!("/chats/{}/choice-cards", fixture.chat),
            None,
        )
        .await;
    assert_eq!(cards.0, 200);
    cards
        .1
        .as_array()
        .expect("cards")
        .last()
        .expect("actual durable card")
        .clone()
}

fn selections(card: &Value) -> Value {
    json!({"selections":[{"question_id":card["questions"][0]["id"],
        "option_ids":[card["questions"][0]["options"][0]["id"]]}]})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_participant_can_answer_default_owner_card_and_revocation_refuses() {
    let fixture = Fixture::new().await;
    fixture.grant_method().await;
    let card = ask(&fixture, "ws71-participant-card").await;
    assert_eq!(
        card["recipient"], READER,
        "default addressee is immutable attention, not eligibility"
    );
    let path = format!(
        "/chats/{}/choice-cards/{}/answer",
        fixture.chat,
        card["id"].as_str().expect("card id")
    );
    for method in ["GET", "POST"] {
        let denied_path = if method == "GET" {
            format!("/chats/{}/choice-cards", fixture.chat)
        } else {
            path.clone()
        };
        let before =
            crate::choice_prompt::list(fixture.wb.lock_unpoisoned().store_ref(), &fixture.chat)
                .expect("cards");
        let denied = fixture
            .request(
                STRANGER,
                method,
                &denied_path,
                (method == "POST").then(|| selections(&card)),
            )
            .await;
        assert_eq!(denied.0, 403, "no project standing: {}", denied.1);
        let after =
            crate::choice_prompt::list(fixture.wb.lock_unpoisoned().store_ref(), &fixture.chat)
                .expect("cards");
        assert_eq!(
            serde_json::to_value(before).expect("before"),
            serde_json::to_value(after).expect("after")
        );
    }
    // A revoked data grant is independent of roster membership and inspection.
    let project = fixture
        .wb
        .lock_unpoisoned()
        .library
        .project_of_chat(&fixture.chat)
        .expect("project")
        .to_owned();
    let mut grant = crate::org::MemberGrantRecord {
        id: crate::org::MemberGrantRecord::make_id(PUBLISHER, &project),
        op: crate::library::RecordOp::Tombstone,
        authority: PUBLISHER.into(),
        project_id: project,
    };
    fixture
        .wb
        .lock_unpoisoned()
        .store_mut()
        .append_record(
            crate::org::ORG_SCOPE,
            "member_grant",
            &serde_json::to_string(&grant).expect("grant"),
        )
        .expect("revoke");
    assert_eq!(
        fixture
            .request(PUBLISHER, "POST", &path, Some(selections(&card)))
            .await
            .0,
        403
    );
    grant.op = crate::library::RecordOp::Upsert;
    fixture
        .wb
        .lock_unpoisoned()
        .store_mut()
        .append_record(
            crate::org::ORG_SCOPE,
            "member_grant",
            &serde_json::to_string(&grant).expect("grant"),
        )
        .expect("restore current fixture standing");
    // The provider credential is linked separately for the responding person;
    // a choice answer does not supply an effect or provider grant.
    assert_eq!(
        fixture
            .request(
                PUBLISHER,
                "POST",
                "/account/credentials",
                Some(json!({
        "provider":"openai-generic","token":"synthetic-only",
        "base_url":format!("{}/v1",fixture.provider_origin)}))
            )
            .await
            .0,
        200
    );
    let request = fixture
        .client_request(PUBLISHER, "POST", &path)
        .timeout(Duration::from_secs(20))
        .header("content-type", "application/json")
        .body(selections(&card).to_string());
    let pending = tokio::spawn(async move { request.send().await.expect("answer HTTP") });
    fixture
        .turns
        .lock()
        .expect("turns")
        .push(pending.abort_handle());
    let actual = fixture.next_call().await;
    assert!(
        actual.body.to_string().contains("First"),
        "actual admitted continuation carries answer"
    );
    actual
        .finish
        .send((StatusCode::OK, answer("Answer continued.", 1)))
        .expect("continuation reply");
    let response = pending.await.expect("answer task");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let durable = crate::choice_prompt::get(
        fixture.wb.lock_unpoisoned().store_ref(),
        &fixture.chat,
        card["id"].as_str().expect("id"),
    )
    .expect("get")
    .expect("card");
    assert_eq!(durable.recipient, READER);
    assert_eq!(
        durable
            .answer
            .as_ref()
            .expect("attributed answer")
            .answered_by,
        PUBLISHER
    );
    assert_eq!(
        fixture
            .request(PUBLISHER, "POST", &path, Some(selections(&card)))
            .await
            .0,
        200,
        "same answer replay"
    );
    assert_eq!(
        fixture
            .request(READER, "POST", &path, Some(selections(&card)))
            .await
            .0,
        409,
        "competing participant cannot overwrite"
    );
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit WS71 socket infrastructure; not a product verdict"]
async fn serve() {
    use std::io::BufRead;
    let fixture = Fixture::new().await;
    fixture.grant_method().await;
    let first = ask(&fixture, "ws71-socket-first").await;
    let second = ask(&fixture, "ws71-socket-second").await;
    assert_eq!(
        fixture
            .request(
                PUBLISHER,
                "POST",
                "/account/credentials",
                Some(json!({
        "provider":"openai-generic","token":"synthetic-only",
        "base_url":format!("{}/v1",fixture.provider_origin)}))
            )
            .await
            .0,
        200
    );
    let fixture = Arc::new(fixture);
    let calls = Arc::new(AtomicU64::new(0));
    let respondent = fixture.clone();
    let observed = calls.clone();
    let responder = tokio::spawn(async move {
        loop {
            let call = respondent.next_call().await;
            assert!(
                call.body
                    .to_string()
                    .contains("Answer to your earlier choice card"),
                "actual answer continuation"
            );
            observed.fetch_add(1, Ordering::Relaxed);
            call.finish
                .send((StatusCode::OK, answer("Synthetic answer continued.", 1)))
                .expect("controlled provider");
        }
    });
    println!(
        "WS71_CHOICE_READY {}",
        json!({"protocol":"gaugedesk.choice-route-fixture.v1",
        "base":fixture.origin,"chat":fixture.chat,"owner":READER,"participant":PUBLISHER,
        "stranger":STRANGER,"admissions":fixture.headers,"cards":[first["id"],second["id"]]})
    );
    let (tx, mut rx) = mpsc::channel::<String>(4);
    let input = tokio::task::spawn_blocking(move || {
        for line in std::io::stdin().lock().lines() {
            if tx
                .blocking_send(line.expect("fixture control input"))
                .is_err()
            {
                break;
            }
        }
    });
    while let Some(line) = rx.recv().await {
        let command: Value = serde_json::from_str(&line).expect("closed fixture control");
        match command["op"].as_str().expect("operation") {
            "revoke-participant" | "restore-participant" => {
                let mut wb = fixture.wb.lock_unpoisoned();
                let project = wb
                    .library
                    .project_of_chat(&fixture.chat)
                    .expect("project")
                    .to_owned();
                let record = crate::org::MemberGrantRecord {
                    id: crate::org::MemberGrantRecord::make_id(PUBLISHER, &project),
                    op: if command["op"] == "revoke-participant" {
                        crate::library::RecordOp::Tombstone
                    } else {
                        crate::library::RecordOp::Upsert
                    },
                    authority: PUBLISHER.into(),
                    project_id: project,
                };
                wb.store_mut()
                    .append_record(
                        crate::org::ORG_SCOPE,
                        "member_grant",
                        &serde_json::to_string(&record).expect("record"),
                    )
                    .expect("synthetic standing transition");
            }
            "reopen" => {
                assert!(
                    !crate::engine::turn_is_live(&fixture.chat),
                    "no live turn during owned reopen"
                );
                let reopened = crate::open_workbench(fixture._root.as_ref().expect("root").path())
                    .expect("durable reopen");
                reopened
                    .lock_unpoisoned()
                    .set_identity_provider(Some(Arc::new(
                        LoopbackIdentityProvider::new()
                            .enroll(
                                READER,
                                AuthorityId::new(READER),
                                AuthorityAttributes::default(),
                            )
                            .enroll(
                                PUBLISHER,
                                AuthorityId::new(PUBLISHER),
                                AuthorityAttributes::default(),
                            )
                            .enroll(
                                STRANGER,
                                AuthorityId::new(STRANGER),
                                AuthorityAttributes::default(),
                            ),
                    )));
                let replacement = Arc::try_unwrap(reopened)
                    .unwrap_or_else(|_| panic!("sole reopened owner"))
                    .into_inner()
                    .expect("reopened workbench");
                *fixture.wb.lock_unpoisoned() = replacement;
            }
            "observe" => {}
            _ => panic!("unsupported closed fixture operation"),
        }
        println!(
            "WS71_CHOICE_CONTROL {}",
            json!({"op":command["op"],"provider_calls":calls.load(Ordering::Relaxed)})
        );
    }
    input.await.expect("fixture input retired");
    responder.abort();
    let _ = responder.await;
    Arc::try_unwrap(fixture)
        .unwrap_or_else(|_| panic!("sole fixture owner after responder retires"))
        .shutdown()
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn busy_continuation_keeps_answer_pending_and_replays_once_after_current_admission() {
    let fixture = Fixture::new().await;
    fixture.grant_method().await;
    let card = ask(&fixture, "ws71-delayed-continuation").await;
    let held = fixture.start("An ordinary turn holds the actual chat.");
    let held_call = fixture.next_call().await;
    let path = format!(
        "/chats/{}/choice-cards/{}/answer",
        fixture.chat,
        card["id"].as_str().expect("id")
    );
    let response = tokio::time::timeout(
        Duration::from_secs(20),
        fixture.request(READER, "POST", &path, Some(selections(&card))),
    )
    .await
    .expect("busy answer must settle");
    assert_eq!(response.0, 409, "busy dispatch is explicit: {}", response.1);
    let observed = fixture
        .request(
            READER,
            "GET",
            &format!("/chats/{}/choice-cards", fixture.chat),
            None,
        )
        .await;
    assert_eq!(observed.0, 200);
    assert_eq!(observed.1[0]["answer"]["answered_by"], READER);
    assert_eq!(observed.1[0]["continuation"]["status"], "pending");
    assert!(
        fixture.calls.lock().await.try_recv().is_err(),
        "no second provider turn while already running"
    );
    held_call
        .finish
        .send((StatusCode::OK, answer("Ordinary turn settled.", 1)))
        .expect("held turn reply");
    assert_eq!(held.await.expect("held turn").0, 200);
    let request = fixture
        .client_request(READER, "POST", &path)
        .timeout(Duration::from_secs(20))
        .header("content-type", "application/json")
        .body(selections(&card).to_string());
    let pending = tokio::spawn(async move { request.send().await.expect("retry HTTP") });
    fixture
        .turns
        .lock()
        .expect("turns")
        .push(pending.abort_handle());
    let call = fixture.next_call().await;
    assert!(call
        .body
        .to_string()
        .contains("Answer to your earlier choice card"));
    call.finish
        .send((StatusCode::OK, answer("Answer admitted now.", 1)))
        .expect("retry completion");
    assert_eq!(
        pending.await.expect("retry").status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        fixture
            .request(READER, "POST", &path, Some(selections(&card)))
            .await
            .0,
        200
    );
    assert!(
        fixture.calls.lock().await.try_recv().is_err(),
        "completed replay must not invoke provider"
    );
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_pending_handoff_blocks_execution_then_retry_runs_once_after_abort() {
    use gaugedesk_core::handoff::{self, HandoffCommand, HandoffState};
    let fixture = Fixture::new().await;
    fixture.grant_method().await;
    let card = ask(&fixture, "ws71-paused-execution").await;
    let project = fixture
        .wb
        .lock_unpoisoned()
        .library_project_of_chat(&fixture.chat)
        .expect("actual chat project");
    // This control stages the owning reducer's genuine offered state in the
    // disposable store. It proves current execution admission, not a network
    // relocation ceremony or a new permission derived from inspection.
    let events = handoff::decide(&HandoffState::default(), HandoffCommand::OfferHandoff)
        .expect("owning handoff reducer accepts offer");
    {
        let mut wb = fixture.wb.lock_unpoisoned();
        for event in events {
            wb.store_mut()
                .append_record(
                    &crate::federation::handoff_scope(&project),
                    "event",
                    &serde_json::to_string(&event).expect("handoff event"),
                )
                .expect("retained handoff state");
        }
        assert!(wb.chat_project_moving(&fixture.chat));
    }
    let path = format!(
        "/chats/{}/choice-cards/{}/answer",
        fixture.chat,
        card["id"].as_str().expect("card id")
    );
    let refused = tokio::time::timeout(
        Duration::from_secs(20),
        fixture.request(READER, "POST", &path, Some(selections(&card))),
    )
    .await
    .expect("current execution refusal must settle");
    // Startup currently carries this pause as EngineError::Message: HTTP502
    // with a pending continuation. Record this behavior without altering it.
    assert_eq!(refused.0, 502, "existing admission mapping: {}", refused.1);
    let retained = crate::choice_prompt::get(
        fixture.wb.lock_unpoisoned().store_ref(),
        &fixture.chat,
        card["id"].as_str().expect("id"),
    )
    .expect("retained card")
    .expect("card");
    assert_eq!(
        retained
            .answer
            .as_ref()
            .expect("attributed answer")
            .answered_by,
        READER
    );
    assert_eq!(
        retained
            .continuation
            .as_ref()
            .expect("pending continuation")
            .status,
        "pending"
    );
    assert!(retained
        .continuation
        .as_ref()
        .expect("refusal")
        .error
        .as_ref()
        .expect("reason")
        .contains(crate::federation::PAUSED_FOR_MOVE));
    assert!(
        fixture.calls.lock().await.try_recv().is_err(),
        "no provider work on refused admission"
    );
    crate::federation::abort_handoff(&mut fixture.wb.lock_unpoisoned(), &project)
        .expect("owning handoff abort");
    assert!(!fixture
        .wb
        .lock_unpoisoned()
        .chat_project_moving(&fixture.chat));
    let request = fixture
        .client_request(READER, "POST", &path)
        .timeout(Duration::from_secs(20))
        .header("content-type", "application/json")
        .body(selections(&card).to_string());
    let retry = tokio::spawn(async move { request.send().await.expect("retry HTTP") });
    fixture
        .turns
        .lock()
        .expect("turns")
        .push(retry.abort_handle());
    let call = fixture.next_call().await;
    assert!(call
        .body
        .to_string()
        .contains("Answer to your earlier choice card"));
    call.finish
        .send((
            StatusCode::OK,
            answer("Handoff aborted; answer continued.", 1),
        ))
        .expect("retry completion");
    assert_eq!(
        retry.await.expect("retry").status(),
        reqwest::StatusCode::OK
    );
    let completed = crate::choice_prompt::get(
        fixture.wb.lock_unpoisoned().store_ref(),
        &fixture.chat,
        card["id"].as_str().expect("id"),
    )
    .expect("card")
    .expect("retained");
    assert_eq!(
        completed.answer, retained.answer,
        "original attribution and selection retained"
    );
    assert_eq!(
        completed.continuation.as_ref().expect("completed").status,
        "completed"
    );
    assert_eq!(
        fixture
            .request(READER, "POST", &path, Some(selections(&card)))
            .await
            .0,
        200
    );
    assert!(
        fixture.calls.lock().await.try_recv().is_err(),
        "no work on completed redelivery"
    );
    fixture.shutdown().await;
}
