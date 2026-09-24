//! `POST /projects/:project/workflows` admits a launch and leaves stepping to
//! the Home (DR-0191).
use super::tracker_routes::{app, auth, send};
use super::*;
use axum::http::StatusCode;
use std::{num::NonZeroUsize, time::Duration};

fn body(request: &ProjectWorkflowLaunch) -> serde_json::Value {
    serde_json::json!({
        "target": request.target,
        "path": request.path,
        "cut": request.cut,
        "inputs": request.inputs,
    })
}

#[tokio::test]
async fn the_launch_route_refuses_anonymous_keyless_and_malformed_launches() {
    let (_root, shared, _context, request) = fixture(ECHO);
    let (token, admission) = auth(&mut shared.lock_unpoisoned());
    let path = format!("/projects/{DEFAULT_PROJECT}/workflows");
    for hosted in [false, true] {
        let app = app(&shared, hosted);
        let (status, _) = send(
            &app,
            "POST",
            &path,
            None,
            Some(&admission),
            Some("k"),
            Some(body(&request)),
        )
        .await;
        assert!(
            matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
            "anonymous: {status}"
        );
        let (status, data) = send(
            &app,
            "POST",
            &path,
            Some(&token),
            Some(&admission),
            None,
            Some(body(&request)),
        )
        .await;
        assert!(
            status.is_client_error(),
            "no idempotency key: {status} {data}"
        );
        let mut bad = request.clone();
        bad.path = "../escape.whip".into();
        let (status, data) = send(
            &app,
            "POST",
            &path,
            Some(&token),
            Some(&admission),
            Some("bad"),
            Some(body(&bad)),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "escaping path: {data}");
        let mut unknown = body(&request);
        unknown["actor"] = serde_json::json!("someone-else");
        let (status, _) = send(
            &app,
            "POST",
            &path,
            Some(&token),
            Some(&admission),
            Some("u"),
            Some(unknown),
        )
        .await;
        assert!(
            status.is_client_error(),
            "the caller never names the actor: {status}"
        );
    }
}

/// Desktop and hosted: a launch over HTTP is admitted once per key, and the
/// running supervisor files Basics' first task with nobody stepping it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_launch_over_http_is_driven_by_the_home() {
    for hosted in [false, true] {
        let (_root, shared, context, request) = fixture(include_str!("tutorials/basics.whip"));
        shared
            .lock_unpoisoned()
            .declare_project_tracker(
                &context,
                DEFAULT_PROJECT,
                "tutorials",
                "declare",
                ResourceAttributes::default(),
            )
            .unwrap();
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        let (tx, mut notices) = tokio::sync::mpsc::channel(64);
        let supervisor = tokio::spawn(supervise_project_workflows(
            shared.clone(),
            ProjectWorkflowSupervisorConfig {
                limits: LIMITS,
                discovery_page_size: NonZeroUsize::new(16).unwrap(),
                steps_per_wake: 8,
                sweep: Duration::from_secs(3600),
            },
            shutdown,
            tx,
        ));
        let (token, admission) = auth(&mut shared.lock_unpoisoned());
        let app = app(&shared, hosted);
        let path = format!("/projects/{DEFAULT_PROJECT}/workflows");
        let (status, first) = send(
            &app,
            "POST",
            &path,
            Some(&token),
            Some(&admission),
            Some("basics"),
            Some(body(&request)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{first}");
        let (status, again) = send(
            &app,
            "POST",
            &path,
            Some(&token),
            Some(&admission),
            Some("basics"),
            Some(body(&request)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(
            first["product_scope"], again["product_scope"],
            "one key, one run"
        );
        assert_eq!(
            first["admission"]["instance_ref"],
            again["admission"]["instance_ref"]
        );

        let scope = first["product_scope"].as_str().unwrap().to_owned();
        loop {
            let notice = tokio::time::timeout(Duration::from_secs(30), notices.recv())
                .await
                .expect("the supervisor answers")
                .unwrap();
            if notice.scope == scope && notice.outcome == ProjectWorkflowOutcome::Parked {
                break;
            }
        }
        let invocation: ProjectWorkflowInvocation = {
            let wb = shared.lock_unpoisoned();
            let command = wb
                .store_ref()
                .fold::<ProductActionAdmission>(&scope)
                .unwrap()
                .command
                .unwrap();
            ProjectWorkflowInvocation {
                project: DEFAULT_PROJECT.into(),
                workspace: first["workspace"].as_str().unwrap().into(),
                product_scope: scope.clone(),
                command,
                admission: serde_json::from_value(first["admission"].clone()).unwrap(),
            }
        };
        let items = stores(&shared.lock_unpoisoned(), &invocation)
            .runtime
            .items
            .list_items(Some("tutorials"), None)
            .unwrap();
        assert_eq!(items.len(), 1, "hosted={hosted}");
        assert_eq!(items[0].title, "Create a chat in Personal");
        stop.send(true).unwrap();
        supervisor.await.unwrap().unwrap();
    }
}
