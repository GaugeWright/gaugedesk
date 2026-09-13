use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

fn identity(fixture: &Fixture) -> crate::file_action_factory::EditorFileSaveRequestIdentity {
    crate::file_action_factory::EditorFileSaveRequestIdentity {
        home: fixture.shared.lock_unpoisoned().home_id().as_str().into(),
        issuer: fixture.command.issuer.clone(),
        scope: fixture.command.scope.clone(),
        request_id: fixture.command.request_id.clone(),
    }
}

fn uri(identity: &crate::file_action_factory::EditorFileSaveRequestIdentity, view: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("home", &identity.home),
            ("issuer", &identity.issuer),
            ("scope", &identity.scope),
            ("request_id", &identity.request_id),
        ])
        .finish();
    format!("/file-actions/requests/{view}?{query}")
}

async fn get(
    app: &Router,
    path: &str,
    bearer: Option<&str>,
    admission: Option<&str>,
    forged: Option<&AuthenticatedActionContext>,
) -> (StatusCode, Value, Option<String>) {
    let mut request = Request::builder().uri(path);
    if let Some(token) = bearer {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    if let Some(token) = admission {
        request = request.header(crate::home_admission::HOME_ADMISSION_HEADER, token);
    }
    if let Some(context) = forged {
        request = request.extension(context.clone());
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let cache = response
        .headers()
        .get("cache-control")
        .map(|value| value.to_str().unwrap().to_owned());
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&bytes)}));
    (status, body, cache)
}

async fn admission(app: &Router, bearer: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/home/admissions")
                .header("authorization", format!("Bearer {bearer}"))
                .header("idempotency-key", "route-test-home-admission")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice::<Value>(&bytes).unwrap()["admission"]
        .as_str()
        .unwrap()
        .into()
}

#[tokio::test]
async fn saved_content_http_preserves_exact_cut_authority_and_erasure_boundaries() {
    for wrapped in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = saved(dir.path());
        let original = identity(&fixture);
        let (context, token, cut, hash) = {
            let mut wb = fixture.shared.lock_unpoisoned();
            let (context, token) = reader(&mut wb);
            wb.revoke_account_session(&fixture.token);
            let facts = wb
                .observe_editor_file_saved_results_by_request(&context, original.as_request())
                .unwrap();
            (
                context,
                token,
                facts.results()[0].result.cut_id.clone(),
                facts.results()[0].result.content_hash.clone(),
            )
        };
        let mut app = crate::open_control_plane(fixture.shared.clone());
        if wrapped {
            app = app.layer(axum::middleware::from_fn_with_state(
                fixture.shared.clone(),
                crate::home_routes::require_home_admission,
            ));
        }
        let content_uri = |identity: &crate::file_action_factory::EditorFileSaveRequestIdentity,
                           cut: &str| {
            let suffix = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("cut", cut)
                .finish();
            format!(
                "/file-actions/saved-content?{}&{suffix}",
                uri(identity, "saved").split_once('?').unwrap().1
            )
        };
        let path = content_uri(&original, &cut);
        assert_eq!(
            get(&app, &path, None, None, Some(&context)).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get(&app, &path, Some(&token), None, None).await.0,
            StatusCode::UNAUTHORIZED
        );
        let home = admission(&app, &token).await;
        let (status, body, cache) = get(&app, &path, Some(&token), Some(&home), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(cache.as_deref(), Some("no-store"));
        assert_eq!(body["identity"], json!(original));
        assert_eq!(body["cut"], cut);
        assert_eq!(body["content"], "private editor draft");
        assert_eq!(body["content_hash"], hash);
        assert_eq!(body["observer"], "bob");
        assert_eq!(body["merged"], false);
        assert!(body["restrictions"].is_object());
        assert_eq!(
            get(
                &app,
                &content_uri(&original, "other-cut"),
                Some(&token),
                Some(&home),
                None
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        let mut other = original.clone();
        other.home = "another-home".into();
        assert_eq!(
            get(
                &app,
                &content_uri(&other, &cut),
                Some(&token),
                Some(&home),
                None
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            super::super::super::tests::erase_fixture_result(dir.path(), &hash),
            1
        );
        let (status, _, cache) = get(&app, &path, Some(&token), Some(&home), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(cache.as_deref(), Some("no-store"));
        let (status, facts, _) = get(
            &app,
            &uri(&original, "saved"),
            Some(&token),
            Some(&home),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(facts["evidence"][0]["result"]["cut_id"], cut);
        fixture
            .shared
            .lock_unpoisoned()
            .revoke_account_session(&token);
        assert_ne!(
            get(&app, &path, Some(&token), Some(&home), None).await.0,
            StatusCode::OK
        );
    }
}

#[tokio::test]
async fn request_http_reads_use_real_home_credentials_in_native_and_wrapped_compositions() {
    for wrapped in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = saved(dir.path());
        let original = identity(&fixture);
        let (context, token) = {
            let mut wb = fixture.shared.lock_unpoisoned();
            wb.revoke_account_session(&fixture.token);
            reader(&mut wb)
        };
        let mut app = crate::open_control_plane(fixture.shared.clone());
        if wrapped {
            app = app.layer(axum::middleware::from_fn_with_state(
                fixture.shared.clone(),
                crate::home_routes::require_home_admission,
            ));
        }
        let path = uri(&original, "command");
        assert_eq!(
            get(&app, &path, None, None, Some(&context)).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get(&app, &path, Some(&token), None, None).await.0,
            StatusCode::UNAUTHORIZED
        );
        let home = admission(&app, &token).await;
        assert_ne!(
            get(&app, &path, None, Some(&home), Some(&context)).await.0,
            StatusCode::OK
        );
        let (status, body, cache) = get(&app, &path, Some(&token), Some(&home), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(cache.as_deref(), Some("no-store"));
        assert_eq!(body["identity"], json!(original));
        assert_eq!(body["observer"], "bob");
        assert_eq!(body["evidence"]["provenance"]["initiator"], "alice");
        assert_eq!(body["evidence"]["provenance"]["executor"], "alice");
        for invalid in [
            format!("{path}&unexpected=field"),
            uri(&original, "invalid-view"),
        ] {
            let (status, _, cache) = get(&app, &invalid, Some(&token), Some(&home), None).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(cache.as_deref(), Some("no-store"));
        }
        fixture
            .shared
            .lock_unpoisoned()
            .revoke_account_session(&token);
        assert_ne!(
            get(&app, &path, Some(&token), Some(&home), Some(&context))
                .await
                .0,
            StatusCode::OK
        );
    }
}

#[tokio::test]
async fn request_http_saved_facts_survive_unavailable_runtime_without_repair_or_false_success() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let original = identity(&fixture);
    let (_, token) = reader(&mut fixture.shared.lock_unpoisoned());
    let app = crate::open_control_plane(fixture.shared.clone());
    let home = admission(&app, &token).await;
    let scope = fixture.command.instance_ref().unwrap();
    let before = fixture
        .shared
        .lock_unpoisoned()
        .store_ref()
        .retained_events(&scope)
        .unwrap();
    let (status, execution, _) = get(
        &app,
        &uri(&original, "execution"),
        Some(&token),
        Some(&home),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{execution}");
    assert!(execution["evidence"]["runtime"].is_object());
    let (status, original_saved, _) = get(
        &app,
        &uri(&original, "saved"),
        Some(&token),
        Some(&home),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{original_saved}");
    for file in [
        "inputs.sqlite",
        "native/runtime.sqlite",
        "native/coord.sqlite",
        "native/items.sqlite",
    ] {
        forget(&dir.path().join("actions").join(file));
    }
    fixture.shared.lock_unpoisoned().engagements.clear();
    let (status, unavailable, cache) = get(
        &app,
        &uri(&original, "execution"),
        Some(&token),
        Some(&home),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(cache.as_deref(), Some("no-store"));
    for field in ["home", "request_id"] {
        let mut wrong = original.clone();
        if field == "home" {
            wrong.home.push_str("-other");
        } else {
            wrong.request_id.push_str("-absent");
        }
        let (status, body, _) =
            get(&app, &uri(&wrong, "saved"), Some(&token), Some(&home), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, unavailable);
    }
    let (status, saved, cache) = get(
        &app,
        &uri(&original, "saved"),
        Some(&token),
        Some(&home),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(cache.as_deref(), Some("no-store"));
    assert_eq!(saved["observer"], "bob");
    assert_eq!(saved["evidence"].as_array().unwrap().len(), 1);
    assert_eq!(saved["evidence"], original_saved["evidence"]);
    assert!(!saved["evidence"][0]["result"]["content_hash"]
        .as_str()
        .unwrap()
        .is_empty());
    assert!(!dir.path().join("actions/native/runtime.sqlite").exists());
    assert!(!dir.path().join("actions/inputs.sqlite").exists());
    assert_eq!(
        fixture
            .shared
            .lock_unpoisoned()
            .store_ref()
            .retained_events(&scope)
            .unwrap(),
        before
    );
}

#[tokio::test]
async fn request_http_preparation_is_not_admission_and_rechecks_target_write_authority() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = saved(dir.path());
    let (_, _, chat): (String, String, String) =
        serde_json::from_str(&fixture.command.scope).unwrap();
    let app = crate::open_control_plane(fixture.shared.clone());
    let home = admission(&app, &fixture.token).await;
    let path = format!("/chats/{chat}/file-actions/request?path=note.txt&request_id=future-save");
    let (status, body, cache) = get(&app, &path, Some(&fixture.token), Some(&home), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(cache.as_deref(), Some("no-store"));
    let prepared: crate::file_action_factory::EditorFileSaveRequestIdentity =
        serde_json::from_value(body).unwrap();
    assert_eq!(prepared.scope, fixture.command.scope);
    assert_eq!(prepared.request_id, "future-save");
    assert_eq!(
        get(
            &app,
            &uri(&prepared, "command"),
            Some(&fixture.token),
            Some(&home),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    {
        let mut wb = fixture.shared.lock_unpoisoned();
        let (id, _, _): (String, String, String) = serde_json::from_str(
            fixture.command.resources["target"]
                .resource
                .selector
                .as_deref()
                .unwrap(),
        )
        .unwrap();
        let mut target = wb.library.work_targets[&id].clone();
        target.capabilities.propose = false;
        wb.store_mut()
            .append_record(
                LIBRARY_SCOPE,
                "work_target",
                &serde_json::to_string(&target).unwrap(),
            )
            .unwrap();
    }
    assert_eq!(
        get(&app, &path, Some(&fixture.token), Some(&home), None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    // The historical read remains permitted when current write authority ends.
    assert_eq!(
        get(
            &app,
            &uri(&identity(&fixture), "command"),
            Some(&fixture.token),
            Some(&home),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
}
