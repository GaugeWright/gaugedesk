//! DR-0201 §3: while a move of a project is pending, every writer to it refuses
//! with the same message, and nothing is queued; once the move is aborted the
//! same writes succeed.
use super::*;
use crate::federation::PAUSED_FOR_MOVE;
use gaugedesk_core::handoff::HandoffEvent;

fn handoff(wb: &mut Workbench, event: HandoffEvent) {
    wb.store_mut()
        .append_record(
            &crate::federation::handoff_scope(DEFAULT_PROJECT),
            "event",
            &serde_json::to_string(&event).unwrap(),
        )
        .unwrap();
}

fn paused<T: std::fmt::Debug, E: std::fmt::Display + std::fmt::Debug>(result: Result<T, E>) {
    let error = result.expect_err("a write while the project is mid-move must refuse");
    assert!(error.to_string().contains(PAUSED_FOR_MOVE), "{error}");
}

#[test]
fn every_writer_refuses_while_its_project_is_mid_move_and_works_after_an_abort() {
    let (root, shared, _context, request) = fixture(ECHO);
    let mut wb = shared.lock_unpoisoned();
    wb.create_default_engagement("mv-chat".into(), "Moving".into())
        .unwrap_or_else(|_| panic!("a chat in Personal"));
    let chat = "mv-chat";
    let placement = wb.library.chats[chat].instance_id.clone();
    handoff(&mut wb, HandoffEvent::HandoffOffered);
    assert!(wb.project_moving(DEFAULT_PROJECT));
    assert!(wb.chat_project_moving(chat));

    // Editor and import.
    paused(wb.write_engagement_file(chat, "note.txt", "x").unwrap());
    paused(wb.write_engagement_config(chat, "{}").unwrap());
    paused(wb.revert_engagement(chat).unwrap());
    paused(wb.sync_engagement_from_main(chat).unwrap());
    paused(
        wb.apply_engagement_merge_action(
            chat,
            crate::engagement_routes::EngagementMergeAction::Admit,
        )
        .unwrap(),
    );
    paused(
        wb.ingest_upload_into_engagement(chat, &[("a.txt".into(), b"a".to_vec())], None)
            .unwrap(),
    );
    assert!(matches!(
        wb.create_default_engagement("mv-chat-2".into(), "Another".into()),
        Err(crate::engagement_routes::EngagementCreateError::Git(reason)) if reason == PAUSED_FOR_MOVE
    ));

    // Chat and project topology.
    assert!(matches!(
        wb.fork_chat_with_destination(chat, crate::library_state::ForkDestination::Inherit),
        Err(crate::library_state::ForkChatError::Create(reason)) if reason == PAUSED_FOR_MOVE
    ));
    paused(wb.create_chat_in_instance_on_targets(&placement, "New", &[]));
    paused(wb.revise_chat_targets(
        chat,
        &[(
            request.target.clone(),
            crate::library::TargetParticipationMode::Writable,
        )],
    ));
    paused(wb.attach_external_target(
        DEFAULT_PROJECT,
        crate::target_adapter::AttachTargetBody {
            name: "Elsewhere".into(),
            kind: crate::library::WorkTargetKind::ExternalFolder,
            path: root.path().join("elsewhere"),
            path_scope: vec![".".into()],
        },
    ));

    // Home-maintained Personal content.
    assert!(!wb.ensure_project_tasks_tracker(DEFAULT_PROJECT).unwrap());
    paused(wb.ensure_shipped_tutorials());

    // An agent turn: refused before it starts, so nothing reaches the chat.
    drop(wb);
    let _fake = crate::test_support::fake_agent_env();
    // Refused before the worktree is ever read.
    let worktree = root.path().to_path_buf();
    let (tx, _rx) = tokio::sync::broadcast::channel(16);
    let turn = crate::engine::run_engagement_turn(
        &shared,
        chat,
        &worktree,
        &tx,
        crate::engine::EngagementTurnInput {
            task: "write a note",
            images: &[],
            mode: crate::library::ChatMode::Use,
            authenticated_actor: None,
            contribution_by: None,
            account_scope: crate::account::ACCOUNT_SCOPE,
            tenant_scope: crate::org::ORG_SCOPE,
            account_bearer: None,
            runtime_command_id: None,
            harness_factory: None,
        },
    );
    let Err(error) = turn else {
        panic!("a turn in a project mid-move must refuse");
    };
    assert!(format!("{error:?}").contains(PAUSED_FOR_MOVE), "{error:?}");

    // Aborted: the pause lifts and the same writes go through.
    let mut wb = shared.lock_unpoisoned();
    handoff(&mut wb, HandoffEvent::HandoffAborted);
    assert!(!wb.project_moving(DEFAULT_PROJECT));
    wb.write_engagement_file(chat, "note.txt", "x")
        .unwrap()
        .expect("writes resume once the move is aborted");
}

/// The routes that answer for a whole chat or project say so with a conflict,
/// not a missing resource.
#[tokio::test]
async fn deleting_a_chat_or_project_mid_move_is_a_conflict() {
    let (_root, shared, _context, _request) = fixture(ECHO);
    {
        let mut wb = shared.lock_unpoisoned();
        wb.create_default_engagement("mv-chat".into(), "Moving".into())
            .unwrap_or_else(|_| panic!("a chat in Personal"));
        handoff(&mut wb, HandoffEvent::HandoffOffered);
    }
    let placement = shared.lock_unpoisoned().library.chats["mv-chat"]
        .instance_id
        .clone();
    let app = super::tracker_routes::app(&shared, false);
    for path in ["/chats/mv-chat", &format!("/projects/{DEFAULT_PROJECT}")] {
        let (status, body) =
            super::tracker_routes::send(&app, "DELETE", path, None, None, Some("del"), None).await;
        assert_eq!(status, axum::http::StatusCode::CONFLICT, "{path}: {body}");
        assert!(body.to_string().contains(PAUSED_FOR_MOVE), "{path}: {body}");
    }
    for (path, body) in [
        (
            format!("/placements/{placement}/workstreams"),
            serde_json::json!({ "name": "During the move" }),
        ),
        (
            "/chats/mv-chat/settlements".to_owned(),
            serde_json::json!({ "members": [] }),
        ),
        (
            "/chats/mv-chat/target-acts/publish".to_owned(),
            serde_json::json!({}),
        ),
    ] {
        let (status, answer) =
            super::tracker_routes::send(&app, "POST", &path, None, None, Some("w"), Some(body))
                .await;
        assert_eq!(status, axum::http::StatusCode::CONFLICT, "{path}: {answer}");
        assert!(
            answer.to_string().contains(PAUSED_FOR_MOVE),
            "{path}: {answer}"
        );
    }
    let wb = shared.lock_unpoisoned();
    assert!(wb.library.chats.contains_key("mv-chat"));
    assert!(wb.library.projects.contains_key(DEFAULT_PROJECT));
}
