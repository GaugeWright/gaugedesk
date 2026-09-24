use super::*;
use crate::project_tracker::TrackerPermission;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

pub(super) async fn send(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    admission: Option<&str>,
    key: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    if let Some(admission) = admission {
        request = request.header(crate::home_admission::HOME_ADMISSION_HEADER, admission);
    }
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    let body = if let Some(body) = body {
        request = request.header("content-type", "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&body)
        .unwrap_or_else(|_| serde_json::json!({"body":String::from_utf8_lossy(&body)}));
    (status, value)
}
pub(super) fn auth(wb: &mut Workbench) -> (String, String) {
    let token = wb
        .mint_account_session(LOCAL_AUTHORITY, "passkey", 3600)
        .unwrap();
    let home = wb.home_id().clone();
    let admission = wb
        .home_admissions
        .open(home, gaugedesk_core::ids::AuthorityId::new(LOCAL_AUTHORITY))
        .encode();
    (token, admission)
}
pub(super) fn app(shared: &crate::SharedWorkbench, hosted: bool) -> Router {
    let app = crate::open_control_plane(shared.clone());
    if hosted {
        app.layer(axum::middleware::from_fn_with_state(
            shared.clone(),
            crate::home_routes::require_home_admission,
        ))
    } else {
        app
    }
}

#[tokio::test]
async fn desktop_and_hosted_backlog_completion_use_authenticated_native_receipts() {
    for hosted in [false, true] {
        let (_root, shared, _context, invocation, intent) = completion::setup();
        let (token, admission) = auth(&mut shared.lock_unpoisoned());
        let app = app(&shared, hosted);
        let directory = format!("/projects/{DEFAULT_PROJECT}/trackers");
        let backlog = format!("{directory}/tutorials/issues");
        let complete = format!("{backlog}/{}/complete", intent.item_id);
        let (status, data) = send(
            &app,
            "GET",
            &directory,
            Some(&token),
            Some(&admission),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{data}");
        assert_eq!(data["trackers"].as_array().unwrap().len(), 1);
        let (status, data) = send(
            &app,
            "GET",
            &backlog,
            Some(&token),
            Some(&admission),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{data}");
        assert_eq!(data["issues"][0]["subject_id"], intent.subject_id);
        let tasks =
            format!("{directory}/tutorials/tasks?actor=someone-else&assigned_to=someone-else");
        let (status, assigned) = send(
            &app,
            "GET",
            &tasks,
            Some(&token),
            Some(&admission),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{assigned}");
        assert_eq!(assigned["actor"], LOCAL_AUTHORITY);
        assert_eq!(assigned["issues"].as_array().unwrap().len(), 1);
        assert_eq!(assigned["issues"][0]["assigned_to"], LOCAL_AUTHORITY);
        assert_eq!(assigned["issues"][0]["subject_id"], intent.subject_id);
        let body = serde_json::json!({"subject_id":data["issues"][0]["subject_id"], "summary":intent.summary, "claim":{"kind":"override"}});
        let (status, first) = send(
            &app,
            "POST",
            &complete,
            Some(&token),
            Some(&admission),
            Some("same-request"),
            Some(body.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!(first["snapshot"]["instance_status"], "completed");
        assert_eq!(
            first["snapshot"]["command"]["provenance"]["executor"],
            LOCAL_AUTHORITY
        );
        // A fresh credential for the same actor must deliver the same product
        // command, not hit the generic credential-keyed uncertain HTTP cache.
        let (new_token, new_admission) = auth(&mut shared.lock_unpoisoned());
        let (status, replay) = send(
            &app,
            "POST",
            &complete,
            Some(&new_token),
            Some(&new_admission),
            Some("same-request"),
            Some(body.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(replay["snapshot"]["command"], first["snapshot"]["command"]);
        assert_eq!(replay["executed_effect"], serde_json::Value::Null);
        let (status, after) = send(
            &app,
            "GET",
            &backlog,
            Some(&new_token),
            Some(&new_admission),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(after["issues"][0]["status"], "closed");
        let (status, assigned) = send(
            &app,
            "GET",
            &tasks,
            Some(&new_token),
            Some(&new_admission),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{assigned}");
        assert!(assigned["issues"].as_array().unwrap().is_empty());
        let mut changed = body;
        changed["summary"] = serde_json::json!("different intent");
        assert_eq!(
            send(
                &app,
                "POST",
                &complete,
                Some(&new_token),
                Some(&new_admission),
                Some("same-request"),
                Some(changed)
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            stores(&shared.lock_unpoisoned(), &invocation)
                .runtime
                .list_instances()
                .unwrap()
                .len(),
            2
        );
    }
}

#[tokio::test]
async fn tracker_routes_refuse_anonymous_unreadable_and_incomplete_commands() {
    for hosted in [false, true] {
        let (_root, shared, context, invocation, intent) = completion::setup();
        let (token, admission) = auth(&mut shared.lock_unpoisoned());
        let app = app(&shared, hosted);
        let directory = format!("/projects/{DEFAULT_PROJECT}/trackers");
        let backlog = format!("{directory}/tutorials/issues");
        let tasks = format!("{directory}/tutorials/tasks");
        let complete = format!("{backlog}/{}/complete", intent.item_id);
        let body = serde_json::json!({"subject_id": intent.subject_id, "summary":"done", "claim":{"kind":"override"}});
        for (method, path, payload) in [
            ("GET", &directory, None),
            ("GET", &backlog, None),
            ("GET", &tasks, None),
            ("POST", &complete, Some(body.clone())),
        ] {
            assert_eq!(
                send(
                    &app,
                    method,
                    path,
                    None,
                    Some(&admission),
                    Some("attempt"),
                    payload.clone()
                )
                .await
                .0,
                StatusCode::UNAUTHORIZED
            );
            assert!(!send(
                &app,
                method,
                path,
                Some("forged-token"),
                Some(&admission),
                Some("attempt"),
                payload
            )
            .await
            .0
            .is_success());
        }
        assert_eq!(
            send(
                &app,
                "POST",
                &complete,
                Some(&token),
                Some(&admission),
                None,
                Some(body.clone())
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        for (index, invalid) in [serde_json::json!({"subject_id":intent.subject_id,"summary":"done"}), serde_json::json!({"subject_id":intent.subject_id,"summary":"done","claim":{"kind":"override"},"actor":"someone"})].into_iter().enumerate() {
            assert_eq!(send(&app, "POST", &complete, Some(&token), Some(&admission), Some(&format!("invalid-{index}")), Some(invalid)).await.0, StatusCode::UNPROCESSABLE_ENTITY);
        }
        let unknown = format!("{directory}/private/issues");
        assert_eq!(
            send(
                &app,
                "GET",
                &unknown,
                Some(&token),
                Some(&admission),
                None,
                None
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        {
            let mut wb = shared.lock_unpoisoned();
            let scope = format!(
                "project::{DEFAULT_PROJECT}::tracker::{}",
                hex::encode("tutorials")
            );
            let grant = wb
                .store_ref()
                .records(&scope, "project_tracker_access_basis_v1")
                .unwrap()
                .into_iter()
                .map(|row| {
                    serde_json::from_str::<crate::project_tracker::TrackerAccessBasis>(&row)
                        .unwrap()
                })
                .find(|basis| basis.permission == TrackerPermission::Read)
                .unwrap();
            wb.decide_project_tracker_access(
                &context,
                DEFAULT_PROJECT,
                "tutorials",
                "revoke-route-read",
                &grant.id,
                crate::project_tracker::TrackerAccessDecision::Revoke,
            )
            .unwrap();
        }
        assert_eq!(
            send(
                &app,
                "GET",
                &backlog,
                Some(&token),
                Some(&admission),
                None,
                None
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(
                &app,
                "GET",
                &tasks,
                Some(&token),
                Some(&admission),
                None,
                None
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(
                &app,
                "POST",
                &complete,
                Some(&token),
                Some(&admission),
                Some("after-revoke"),
                Some(body)
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            stores(&shared.lock_unpoisoned(), &invocation)
                .runtime
                .list_instances()
                .unwrap()
                .len(),
            1
        );
    }
}

#[tokio::test]
async fn unavailable_tracker_route_returns_failure_without_an_empty_issue_list() {
    let (root, shared, _context, invocation, _intent) = completion::setup();
    let (token, admission) = auth(&mut shared.lock_unpoisoned());
    let app = app(&shared, false);
    let path = root
        .path()
        .join("collaboration-workspaces")
        .join(&invocation.workspace)
        .join(".repo.whipplescript/workflow/items.sqlite");
    std::fs::remove_file(&path).unwrap();
    let (status, body) = send(
        &app,
        "GET",
        &format!("/projects/{DEFAULT_PROJECT}/trackers/tutorials/issues"),
        Some(&token),
        Some(&admission),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.get("issues").is_none());
    assert!(!path.exists());
}

#[tokio::test]
async fn interrupted_tracker_http_command_recovers_native_closure_on_same_key() {
    let (root, shared, _context, invocation, intent) = completion::setup();
    let (token, admission) = auth(&mut shared.lock_unpoisoned());
    let app = app(&shared, true);
    let native_root = root
        .path()
        .join("collaboration-workspaces")
        .join(&invocation.workspace)
        .join(".repo.whipplescript/workflow");
    let fault = rusqlite::Connection::open(native_root.join("runtime.sqlite")).unwrap();
    fault.execute_batch("CREATE TRIGGER lose_http_closure_terminal BEFORE INSERT ON events WHEN NEW.event_type = 'effect.terminal' BEGIN SELECT RAISE(ABORT, 'lost closing result'); END;").unwrap();
    let path = format!(
        "/projects/{DEFAULT_PROJECT}/trackers/tutorials/issues/{}/complete",
        intent.item_id
    );
    let body = serde_json::json!({"subject_id":intent.subject_id,"summary":intent.summary,"claim":{"kind":"override"}});
    assert_eq!(
        send(
            &app,
            "POST",
            &path,
            Some(&token),
            Some(&admission),
            Some("recover-original"),
            Some(body.clone())
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let native = stores(&shared.lock_unpoisoned(), &invocation);
    assert_eq!(
        native
            .runtime
            .items
            .get_item(&intent.item_id)
            .unwrap()
            .unwrap()
            .status,
        "closed"
    );
    let original_events = native.runtime.items.export_events().unwrap();
    drop(native);
    fault
        .execute_batch("DROP TRIGGER lose_http_closure_terminal")
        .unwrap();
    let (status, result) = send(
        &app,
        "POST",
        &path,
        Some(&token),
        Some(&admission),
        Some("recover-original"),
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert!(result["recovered_effect"].is_string());
    assert!(result["executed_effect"].is_null());
    let native = stores(&shared.lock_unpoisoned(), &invocation);
    assert_eq!(
        native.runtime.items.export_events().unwrap(),
        original_events
    );
    assert_eq!(native.runtime.list_instances().unwrap().len(), 2);
}
