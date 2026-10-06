use super::*;
use crate::command_idempotency::ClaimedHttpCommand;
use crate::engine::office_turn_answers::{take, KIND};

pub(super) async fn claim_answers(
    wb: &SharedWorkbench,
    chat: &str,
    key: &str,
) -> (
    ClaimedHttpCommand,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let (send_original, receive_original) = tokio::sync::oneshot::channel();
    let (finish, finished) = tokio::sync::oneshot::channel();
    let output = Arc::new(std::sync::Mutex::new(Some((send_original, finished))));
    let app = Router::new()
        .route(
            "/chats/{id}/task",
            post(
                move |axum::extract::Extension(original): axum::extract::Extension<
                    ClaimedHttpCommand,
                >| {
                    let (send_original, finished) = output.lock().unwrap().take().unwrap();
                    async move {
                        send_original.send(original).ok().unwrap();
                        finished.await.unwrap();
                        StatusCode::ACCEPTED
                    }
                },
            ),
        )
        .with_state(wb.clone())
        .layer(axum::middleware::from_fn_with_state(
            wb.clone(),
            crate::command_idempotency::guard,
        ));
    let request = Request::builder()
        .method("POST")
        .uri(format!("/chats/{chat}/task"))
        .header("idempotency-key", key)
        .body(Body::from("synthetic clinical task"))
        .unwrap();
    let request = tokio::spawn(async move {
        assert_eq!(
            app.oneshot(request).await.unwrap().status(),
            StatusCode::ACCEPTED
        );
    });
    (receive_original.await.unwrap(), finish, request)
}

#[tokio::test]
async fn office_legacy_answers_retain_original_selection_and_refuse_failed_or_changed_authority() {
    for case in [
        "replay",
        "empty",
        "write-failure",
        "completed",
        "revoked-restored",
        "orphan",
        "receipt-loss",
        "snapshot-loss",
    ] {
        let root = tempfile::tempdir().unwrap();
        let (wb, app, _, _) = fixture(root.path());
        let hub = hub().await;
        install(&wb, &hub);
        let admission = admit(&app, ALICE).await;
        let chat = chat(&wb);
        let captured = context(&wb, &admission);
        let authority = OfficeTaskAuthority::for_turn(
            &wb,
            &chat,
            Some(&captured),
            Some(&Default::default()),
            None,
            Some(ALICE),
        )
        .unwrap()
        .unwrap();
        assert!(wb.lock_unpoisoned().content_vault.is_some());
        let (original, finish, request) = claim_answers(&wb, &chat, "original-answer-task").await;
        {
            let mut guard = wb.lock_unpoisoned();
            let first = guard
                .ask_question(&chat, "Synthetic first question", &[], None, false)
                .unwrap();
            if case != "empty" {
                guard
                    .answer_question(&chat, &first, "Synthetic first answer", "alice")
                    .unwrap();
            }
            let sql = rusqlite::Connection::open(guard.store_ref().path()).unwrap();
            if case == "write-failure" {
                sql.execute_batch("CREATE TRIGGER refuse_answer_delivery BEFORE INSERT ON events WHEN NEW.kind='agent-question' BEGIN SELECT RAISE(ABORT, 'synthetic delivery failure'); END;").unwrap();
                assert!(take(&mut guard, &authority, &original).is_err());
                assert!(guard.store_ref().records(&chat, KIND).unwrap().is_empty());
                assert!(
                    !crate::agent_question::get(guard.store_ref(), &chat, &first)
                        .unwrap()
                        .unwrap()
                        .answer_delivered
                );
                sql.execute_batch("DROP TRIGGER refuse_answer_delivery")
                    .unwrap();
            }
            let selected = take(&mut guard, &authority, &original).unwrap();
            assert_eq!(selected.len(), usize::from(case != "empty"));
            original.verify_pending(guard.store_ref()).unwrap();
            let raw: String = sql
                .query_row(
                    "SELECT payload FROM events WHERE scope_id=?1 AND kind=?2",
                    rusqlite::params![chat, KIND],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(raw.starts_with("gwenc:1:"));
            assert!(!raw.contains("Synthetic first answer"));
            let later = guard
                .ask_question(&chat, "Synthetic later question", &[], None, false)
                .unwrap();
            guard
                .answer_question(&chat, &later, "Synthetic later answer", "alice")
                .unwrap();
            assert_eq!(take(&mut guard, &authority, &original).unwrap(), selected);
            assert!(
                !crate::agent_question::get(guard.store_ref(), &chat, &later)
                    .unwrap()
                    .unwrap()
                    .answer_delivered
            );
            assert_eq!(guard.store_ref().records(&chat, KIND).unwrap().len(), 1);
            match case {
                "completed" => {
                    let basis = authority.prepare_basis(&guard).unwrap();
                    guard
                        .store_mut()
                        .with_dispatch_record_admission(&basis, |writer| {
                            writer.commit_claimed(
                                original.command_id(),
                                original.scope(),
                                original.key(),
                                original.snapshot(),
                                &[gaugedesk_store::CommandRecordFact {
                                    scope_id: chat.clone(),
                                    kind: "synthetic_completion".into(),
                                    payload: "done".into(),
                                }],
                            )
                        })
                        .unwrap()
                        .unwrap();
                }
                "revoked-restored" => {
                    drop(guard);
                    grant(&wb, "alice", crate::library::RecordOp::Tombstone);
                    assert!(take(&mut wb.lock_unpoisoned(), &authority, &original).is_err());
                    grant(&wb, "alice", crate::library::RecordOp::Upsert);
                    guard = wb.lock_unpoisoned();
                }
                "orphan" | "receipt-loss" => {
                    let phase = gaugedesk_store::Store::claimed_lifecycle_prefix_scope(
                        original.command_id(),
                        "legacy-answer-delivery",
                    );
                    sql.execute("DELETE FROM command_receipts WHERE scope_id=?1", [&phase])
                        .unwrap();
                    if case == "orphan" {
                        sql.execute("DELETE FROM events WHERE scope_id=?1", [&phase])
                            .unwrap();
                    }
                }
                "snapshot-loss" => {
                    sql.execute(
                        "DELETE FROM events WHERE scope_id=?1 AND kind=?2",
                        rusqlite::params![chat, KIND],
                    )
                    .unwrap();
                }
                _ => {}
            }
            if matches!(
                case,
                "completed" | "revoked-restored" | "orphan" | "receipt-loss" | "snapshot-loss"
            ) {
                assert!(take(&mut guard, &authority, &original).is_err(), "{case}");
            }
            assert!(
                !crate::agent_question::get(guard.store_ref(), &chat, &later)
                    .unwrap()
                    .unwrap()
                    .answer_delivered
            );
            drop(guard);
        }
        finish.send(()).unwrap();
        request.await.unwrap();
    }
}
