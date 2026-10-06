use super::*;

fn delegation(granted_at_ms: u64) -> KeyDelegation {
    KeyDelegation {
        id: "d1".into(),
        project: "p".into(),
        work: DelegatedWork::Workflow {
            launch: "project::p::workflow-launch::00::00".into(),
            target: "t".into(),
            path: "a.whip".into(),
        },
        scopes: std::iter::once("project::p::workflow".to_owned()).collect(),
        granted_from: "alice".into(),
        granted_at_ms,
    }
}

fn record(event: &Event) -> String {
    serde_json::to_string(event).unwrap()
}

#[test]
fn a_delegation_lapses_thirty_days_after_the_last_member_use_and_not_before() {
    let folded = ProjectDelegations::fold(&[record(&Event::Derived(delegation(1_000)))]);
    let held = &folded.delegations["d1"];
    assert_eq!(
        held.state(None, 1_000 + LAPSE_MS - 1),
        DelegationState::Held {
            expires_at_ms: 1_000 + LAPSE_MS
        }
    );
    assert_eq!(
        held.state(None, 1_000 + LAPSE_MS),
        DelegationState::Lapsed {
            since_ms: 1_000 + LAPSE_MS
        }
    );
    // A member use before the grant does not shorten it; one after extends it.
    assert_eq!(held.expires_at_ms(Some(500)), 1_000 + LAPSE_MS);
    assert_eq!(held.expires_at_ms(Some(9_000)), 9_000 + LAPSE_MS);
}

#[test]
fn the_ledger_folds_renewal_uses_and_an_end_and_skips_what_it_cannot_read() {
    let records = vec![
        record(&Event::Derived(delegation(1_000))),
        record(&Event::MemberUsed { at_ms: 5_000 }),
        record(&Event::MemberUsed { at_ms: 3_000 }),
        record(&Event::Used {
            delegation: "d1".into(),
            at_ms: 6_000,
            effect: "filed".into(),
        }),
        // A newer build's event, and one for a delegation never derived here.
        r#"{"event":"rebound","delegation":"d1","at_ms":7000}"#.to_owned(),
        record(&Event::Used {
            delegation: "unknown".into(),
            at_ms: 6_500,
            effect: "x".into(),
        }),
        // Derived twice: the first stands.
        record(&Event::Derived(delegation(99_999))),
        record(&Event::Ended {
            delegation: "d1".into(),
            at_ms: 8_000,
            outcome: "completed".into(),
        }),
        record(&Event::Ended {
            delegation: "d1".into(),
            at_ms: 9_000,
            outcome: "failed".into(),
        }),
    ];
    let folded = ProjectDelegations::fold(&records);
    assert_eq!(
        folded.last_member_use_ms,
        Some(5_000),
        "the latest use counts"
    );
    let d1 = &folded.delegations["d1"];
    assert_eq!(d1.delegation.granted_at_ms, 1_000);
    assert_eq!(d1.uses, vec![(6_000, "filed".to_owned())]);
    assert_eq!(d1.ended, Some((8_000, "completed".to_owned())));
    assert_eq!(
        d1.state(folded.last_member_use_ms, 8_500),
        DelegationState::Ended
    );
    assert_eq!(folded.delegations.len(), 1);
}

#[test]
fn a_path_prefix_names_the_thing_a_request_is_about() {
    assert_eq!(path_prefix("/chats/c1/events"), "/chats/c1");
    assert_eq!(path_prefix("/projects/p/key-delegations"), "/projects/p");
    assert_eq!(path_prefix("/workspace"), "/workspace");
}

#[test]
fn a_personal_queue_reading_every_project_is_not_using_any_of_them() {
    use axum::http::Method;
    for path in [
        "/projects/p/trackers",
        "/projects/p/trackers/",
        "/projects/p/trackers/tasks/tasks",
    ] {
        assert!(!counts_as_use(&Method::GET, path), "{path}");
    }
    assert!(!counts_as_use(
        &Method::OPTIONS,
        "/projects/p/key-delegations"
    ));
    for (method, path) in [
        (Method::GET, "/projects/p/trackers/tasks/issues"),
        (Method::GET, "/projects/p/key-delegations"),
        (Method::GET, "/chats/c1"),
        (
            Method::POST,
            "/projects/p/trackers/tasks/issues/i1/complete",
        ),
        (Method::POST, "/projects/p/trackers"),
    ] {
        assert!(counts_as_use(&method, path), "{method} {path}");
    }
}

#[test]
fn the_member_use_throttle_counts_a_prefix_once_an_interval() {
    let throttle = MemberUse::default();
    assert!(throttle.due("/chats/c1", 0));
    assert!(!throttle.due("/chats/c1", MEMBER_USE_GRANULARITY_MS - 1));
    assert!(throttle.due("/chats/c2", 1), "another prefix is its own");
    assert!(throttle.due("/chats/c1", MEMBER_USE_GRANULARITY_MS));
}

mod over_http {
    use super::*;
    use crate::at_rest::LoopbackKeyWrap;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn workbench() -> (tempfile::TempDir, SharedWorkbench) {
        let root = tempfile::tempdir().unwrap();
        let wb =
            crate::workbench_state::open_lean_workbench_with_content_keywrap(root.path(), |_| {
                Ok(Box::new(LoopbackKeyWrap::new([11; 32])))
            })
            .unwrap();
        (root, wb)
    }

    async fn get(app: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
        get_as(app, uri, None).await
    }

    async fn get_as(
        app: &axum::Router,
        uri: &str,
        bearer: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut request = Request::builder().uri(uri);
        if let Some(bearer) = bearer {
            request = request.header("authorization", format!("Bearer {bearer}"));
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// A chat in Personal with one transcript line, written inside a session
    /// that has then ended, so nothing holds the project.
    fn chat_with_transcript(wb: &SharedWorkbench) -> (String, String) {
        let mut guard = wb.lock_unpoisoned();
        let chat = guard
            .create_default_engagement("held-chat".into(), "a chat".into())
            .unwrap_or_else(|_| panic!("a chat is created"))
            .id;
        let project = guard.library.project_of_chat(&chat).unwrap().to_owned();
        guard.hold_session_for_tests(&project);
        guard
            .store_mut()
            .append_record(
                &chat,
                "transcript",
                r#"{"type":"user","text":"a private line"}"#,
            )
            .unwrap();
        guard.test_session_holds.clear();
        (chat, project)
    }

    fn vault(wb: &SharedWorkbench) -> std::sync::Arc<crate::content_vault::ContentVault> {
        wb.lock_unpoisoned().content_vault.clone().unwrap()
    }

    #[tokio::test]
    async fn a_session_opens_its_project_and_its_keys_go_when_the_session_does() {
        let (_root, wb) = workbench();
        let (chat, project) = chat_with_transcript(&wb);
        let vault = vault(&wb);
        assert!(vault.held_projects().is_empty());
        assert!(
            wb.lock_unpoisoned()
                .store_ref()
                .records(&chat, "transcript")
                .unwrap()
                .is_empty(),
            "with nothing holding the project, the host opens none of it"
        );

        let app = crate::open_control_plane(wb.clone());
        let (status, body) = get(&app, &format!("/chats/{chat}/transcript")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.to_string().contains("a private line"), "{body}");
        assert_eq!(vault.live_sessions(&project), 0, "the request has ended");
        assert!(vault.held_projects().contains(&project), "and lingers");

        vault.release_idle(now_ms() + crate::content_vault::LINGER_MS + 1);
        assert!(vault.held_projects().is_empty());
        assert!(
            vault.opened_projects().is_empty(),
            "its scope keys are gone"
        );
        assert_eq!(vault.open_project_keys(), 0, "and its project key");
    }

    #[tokio::test]
    async fn a_stream_holds_its_project_only_while_it_is_connected() {
        let (_root, wb) = workbench();
        let (chat, project) = chat_with_transcript(&wb);
        let vault = vault(&wb);
        let app = crate::open_control_plane(wb.clone());
        let stream = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/chats/{chat}/events"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stream.status(), StatusCode::OK);
        assert_eq!(vault.live_sessions(&project), 1, "connected");
        drop(stream);
        assert_eq!(vault.live_sessions(&project), 0, "disconnected");
    }

    #[tokio::test]
    async fn a_search_across_projects_opens_the_ones_its_caller_can_see() {
        let (_root, wb) = workbench();
        let (chat, project) = chat_with_transcript(&wb);
        let vault = vault(&wb);
        let app = crate::open_control_plane(wb.clone());
        let (status, body) = get(&app, "/search?q=private").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.to_string().contains(&chat),
            "the transcript was read under the session's holds: {body}"
        );
        assert!(vault.held_projects().contains(&project));
    }

    #[tokio::test]
    async fn a_refused_request_leaves_nothing_held() {
        let (_root, wb) = workbench();
        let (chat, project) = chat_with_transcript(&wb);
        let vault = vault(&wb);
        let app = crate::open_control_plane(wb.clone());
        // The hold is taken for the request, which the handler then refuses.
        let (status, body) = get(&app, &format!("/chats/{chat}/file?path=no/such/file")).await;
        assert!(status.is_client_error(), "{status} {body}");
        assert_eq!(vault.live_sessions(&project), 0);
        assert!(
            !vault.held_projects().contains(&project),
            "a refused request does not linger"
        );
    }

    fn member_uses(wb: &SharedWorkbench, project: &str) -> usize {
        wb.lock_unpoisoned()
            .store_ref()
            .records(&ledger_scope(project), RECORD_KIND)
            .unwrap()
            .iter()
            .filter(|record| record.contains(r#""event":"member_used""#))
            .count()
    }

    #[tokio::test]
    async fn a_successful_request_naming_a_project_counts_as_member_use_once_an_hour() {
        let (_root, wb) = workbench();
        let app = crate::open_control_plane(wb.clone());
        let project = crate::DEFAULT_PROJECT;

        let (status, body) = get(&app, &format!("/projects/{project}/key-delegations")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["project"], project);
        assert_eq!(body["lapse_after_ms"], LAPSE_MS);
        assert_eq!(member_uses(&wb, project), 1);

        let (status, _) = get(&app, &format!("/projects/{project}/key-delegations")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(member_uses(&wb, project), 1, "counted once an interval");

        // A request that fails renews nothing, and a path naming no project
        // names nothing to renew.
        let (status, _) = get(&app, "/projects/no-such-project/key-delegations").await;
        assert_ne!(status, StatusCode::OK);
        assert_eq!(member_uses(&wb, "no-such-project"), 0);
        let (status, _) = get(&app, "/workspace").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_task_bar_polling_a_project_does_not_renew_it() {
        let (_root, wb) = workbench();
        let token = {
            let mut guard = wb.lock_unpoisoned();
            let owner = crate::org::MembershipRecord {
                id: crate::LOCAL_AUTHORITY.into(),
                op: crate::org::RecordOp::Upsert,
                org_id: crate::org::ORG_ID.into(),
                authority: crate::LOCAL_AUTHORITY.into(),
                email: String::new(),
                role: "owner".into(),
                status: crate::org::MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            };
            guard
                .store_mut()
                .append_record(
                    crate::org::ORG_SCOPE,
                    "membership",
                    &serde_json::to_string(&owner).unwrap(),
                )
                .unwrap();
            let token = guard
                .mint_account_session(crate::LOCAL_AUTHORITY, "passkey", 3600)
                .unwrap();
            let context = guard.authenticate_action_context(&token).unwrap();
            guard
                .declare_project_tracker(
                    &context,
                    crate::DEFAULT_PROJECT,
                    "tasks",
                    "declare",
                    gaugedesk_core::abac::ResourceAttributes::default(),
                )
                .unwrap();
            token
        };
        let app = crate::open_control_plane(wb.clone());
        let project = crate::DEFAULT_PROJECT;
        // The tracker list succeeds, as the signed-in task bar's does. Its
        // other poll, the caller's tasks, needs workflow storage this
        // workbench has not made; `counts_as_use` covers its path.
        for _ in 0..2 {
            let (status, body) =
                get_as(&app, &format!("/projects/{project}/trackers"), Some(&token)).await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }
        assert_eq!(member_uses(&wb, project), 0);
        // And a poll does not spend the interval a real use then needs.
        let (status, _) = get(&app, &format!("/projects/{project}/key-delegations")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(member_uses(&wb, project), 1);
    }
}
