use super::*;
use serde_json::{json, Value};
use std::{num::NonZeroUsize, time::Duration};
use tokio::sync::{mpsc, watch};
use whipplescript_kernel::file_lease::FileLeasePolicy;

fn config() -> NativeActionStorageConfig {
    NativeActionStorageConfig {
        input_byte_limit: 4096,
        file_lease: FileLeasePolicy::new(17).unwrap(),
    }
}
fn app(wb: &SharedWorkbench) -> Router {
    crate::open_control_plane_with_native_saves(wb.clone(), config())
}

async fn home_admission(app: &Router, token: &str, key: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/home/admissions")
                .header("authorization", format!("Bearer {token}"))
                .header("idempotency-key", key)
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
fn body(intent: &Intent) -> Value {
    json!({"expected_actor": "alice", "identity": intent.identity, "path": intent.path, "base_cut": intent.base_cut,
        "content": intent.content, "dispatch_request_id": "dispatch-original"})
}
async fn submit(
    app: &Router,
    intent: &Intent,
    token: Option<&str>,
    home: Option<&str>,
    body: Value,
    key: &str,
    forged: Option<AuthenticatedActionContext>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("/chats/{}/file-actions/save", intent.chat_id))
        .header("content-type", "application/json")
        .header("idempotency-key", key);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    if let Some(home) = home {
        request = request.header(HOME_ADMISSION_HEADER, home);
    }
    if let Some(forged) = forged {
        request = request.extension(forged);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    assert_eq!(
        response.headers().get("strict-transport-security").unwrap(),
        "max-age=63072000; includeSubDomains"
    );
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&bytes)})),
    )
}

#[tokio::test]
async fn submission_actor_read_uses_current_home_credentials_without_action_custody() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, _, token) = setup(dir.path());
    wb.lock_unpoisoned().set_identity_provider(None);
    let router = app(&wb);
    let home = home_admission(&router, &token, "actor-read-home").await;
    for authorized in [false, true] {
        let mut request = Request::builder().uri("/file-actions/actor");
        if authorized {
            request = request
                .header("authorization", format!("Bearer {token}"))
                .header(HOME_ADMISSION_HEADER, &home);
        } else {
            request = request.extension(
                wb.lock_unpoisoned()
                    .authenticate_action_context(&token)
                    .unwrap(),
            );
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            response.status(),
            if authorized {
                StatusCode::OK
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
        if authorized {
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                value,
                json!({"home": wb.lock_unpoisoned().home_id().as_str(), "actor": "alice"})
            );
        }
    }
    wb.lock_unpoisoned().revoke_account_session(&token);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/file-actions/actor")
                .header("authorization", format!("Bearer {token}"))
                .header(HOME_ADMISSION_HEADER, home)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(!response.status().is_success());
    assert!(!dir.path().join("actions").exists());
}

#[tokio::test]
async fn submission_http_refuses_a_changed_authenticated_actor_before_custody() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, intent, alice) = setup(dir.path());
    let bob = {
        let mut guard = wb.lock_unpoisoned();
        membership(&mut guard, "bob", "owner");
        let token = guard.mint_account_session("bob", "passkey", 3600).unwrap();
        let context = guard.authenticate_action_context(&token).unwrap();
        // Both accounts independently have target authority; a permission
        // failure must not masquerade as protection against the actor race.
        assert_eq!(
            guard
                .prepare_editor_file_save_request(
                    &context,
                    &intent.chat_id,
                    &intent.path,
                    &intent.request_id
                )
                .unwrap(),
            intent.identity
        );
        token
    };
    let router = app(&wb);
    let bob_home = home_admission(&router, &bob, "bob-home").await;
    let (status, response) = submit(
        &router,
        &intent,
        Some(&bob),
        Some(&bob_home),
        body(&intent),
        &intent.request_id,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
    assert_eq!(
        response["error"],
        "save actor changed; inspect the original request"
    );
    assert!(!dir.path().join("actions").exists());

    let alice_home = home_admission(&router, &alice, "alice-home").await;
    let mut missing = body(&intent);
    missing.as_object_mut().unwrap().remove("expected_actor");
    assert_eq!(
        submit(
            &router,
            &intent,
            Some(&alice),
            Some(&alice_home),
            missing,
            &intent.request_id,
            None
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert!(!dir.path().join("actions").exists());
    let (status, response) = submit(
        &router,
        &intent,
        Some(&alice),
        Some(&alice_home),
        body(&intent),
        &intent.request_id,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{response}");
    assert_eq!(response["actor"], "alice");
}

#[tokio::test]
async fn submission_http_configured_composition_preserves_browser_preflight() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, intent, _) = setup(dir.path());
    let response = app(&wb)
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri(format!("/chats/{}/file-actions/save", intent.chat_id))
                .header("origin", "tauri://localhost")
                .header("access-control-request-method", "POST")
                .header(
                    "access-control-request-headers",
                    "content-type,authorization,idempotency-key,x-gaugewright-home-admission",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "tauri://localhost"
    );
    assert_eq!(
        response.headers().get("strict-transport-security").unwrap(),
        "max-age=63072000; includeSubDomains"
    );
    let allowed = response
        .headers()
        .get("access-control-allow-headers")
        .unwrap()
        .to_str()
        .unwrap();
    for header in [
        "content-type",
        "authorization",
        "idempotency-key",
        "x-gaugewright-home-admission",
    ] {
        assert!(allowed.contains(header));
    }
    assert!(!dir.path().join("actions").exists());
}
async fn saved_view(app: &Router, intent: &Intent, token: &str, home: &str) -> Value {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("home", &intent.identity.home),
            ("issuer", &intent.identity.issuer),
            ("scope", &intent.identity.scope),
            ("request_id", &intent.identity.request_id),
        ])
        .finish();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/file-actions/requests/saved?{query}"))
                .header("authorization", format!("Bearer {token}"))
                .header(HOME_ADMISSION_HEADER, home)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn submission_http_lost_response_recovers_through_startup_dispatch_and_saved_read() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, intent, token) = setup(dir.path());
    // The durable account session is independent of optional IdP configuration,
    // both on first submission and after reopening this Home.
    wb.lock_unpoisoned().set_identity_provider(None);
    let router = app(&wb);
    let home = home_admission(&router, &token, "initial-home-admission").await;
    let (status, response) = submit(
        &router,
        &intent,
        Some(&token),
        Some(&home),
        body(&intent),
        &intent.request_id,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{response}");
    assert_eq!(response["admission"], "admitted");
    assert_eq!(response["dispatch"]["state"], "authorized");
    assert_eq!(response["identity"], json!(intent.identity));
    assert!(
        saved_view(&router, &intent, &token, &home).await["evidence"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        !dir.path().join("actions/native/runtime.sqlite").exists(),
        "HTTP admission executed the effect"
    );
    // Discard the submit response and every process-local hint. The caller has
    // only its pre-transmission identities, and the restarted Home has its log.
    drop(response);
    drop(router);
    drop(wb);
    let wb = crate::open_workbench(dir.path()).unwrap();
    let router = app(&wb);
    let home = home_admission(&router, &token, "restarted-home-admission").await;
    let (shutdown, signal) = watch::channel(false);
    let (notices, mut receiver) = mpsc::channel(4);
    let supervisor = tokio::spawn(supervise_native_editor_dispatch(
        wb.clone(),
        NativeEditorSupervisorConfig {
            storage: config(),
            discovery_page_size: NonZeroUsize::new(1).unwrap(),
        },
        signal,
        notices,
    ));
    let notice = tokio::time::timeout(Duration::from_secs(20), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    let NativeEditorDispatchOutcome::Saved { cut_id, .. } = notice.outcome else {
        panic!("not saved: {:?}", notice.outcome);
    };
    let saved = saved_view(&router, &intent, &token, &home).await;
    assert_eq!(saved["evidence"].as_array().unwrap().len(), 1);
    assert_eq!(saved["evidence"][0]["result"]["cut_id"], cut_id);
    shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(20), supervisor)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn submission_http_replay_retains_command_and_refuses_changed_meaning() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, intent, token) = setup(dir.path());
    let router = app(&wb);
    let home = home_admission(&router, &token, "initial-home-admission").await;
    let (_, first) = submit(
        &router,
        &intent,
        Some(&token),
        Some(&home),
        body(&intent),
        &intent.request_id,
        None,
    )
    .await;
    let (status, repeated) = submit(
        &router,
        &intent,
        Some(&token),
        Some(&home),
        body(&intent),
        &intent.request_id,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{repeated}");
    assert_eq!(repeated["replayed"], true);
    assert_eq!(repeated["dispatch"]["replayed"], true);
    assert_eq!(
        first["dispatch"]["grant_ref"],
        repeated["dispatch"]["grant_ref"]
    );
    let mut changed = body(&intent);
    changed["content"] = json!("different intent");
    assert_eq!(
        submit(
            &router,
            &intent,
            Some(&token),
            Some(&home),
            changed,
            &intent.request_id,
            None
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let mut guard = wb.lock_unpoisoned();
    let context = guard.authenticate_action_context(&token).unwrap();
    let observed = guard
        .observe_editor_file_save_request(&context, intent.identity.as_request())
        .unwrap();
    let storage = guard.open_native_action_storage(config()).unwrap();
    assert_eq!(
        storage
            .inputs()
            .resolve(&observed.command().inputs["content"])
            .unwrap()
            .content,
        intent.content
    );
    assert!(!dir.path().join("actions/native/runtime.sqlite").exists());
}

#[tokio::test]
async fn submission_http_revoked_dispatch_does_not_hide_admission_or_renew_authority() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, intent, token) = setup(dir.path());
    let router = app(&wb);
    let home = home_admission(&router, &token, "initial-home-admission").await;
    let (_, first) = submit(
        &router,
        &intent,
        Some(&token),
        Some(&home),
        body(&intent),
        &intent.request_id,
        None,
    )
    .await;
    {
        let mut guard = wb.lock_unpoisoned();
        let context = guard.authenticate_action_context(&token).unwrap();
        let command = guard
            .observe_editor_file_save_request(&context, intent.identity.as_request())
            .unwrap()
            .command()
            .clone();
        let storage = guard.open_native_action_storage(config()).unwrap();
        guard
            .revoke_editor_file_save_dispatch(
                &context,
                storage.inputs(),
                &command,
                first["dispatch"]["grant_ref"].as_str().unwrap(),
            )
            .unwrap();
    }
    let (status, repeated) = submit(
        &router,
        &intent,
        Some(&token),
        Some(&home),
        body(&intent),
        &intent.request_id,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{repeated}");
    assert_eq!(repeated["admission"], "admitted");
    assert_eq!(repeated["replayed"], true);
    assert_eq!(repeated["dispatch"], json!({"state": "unavailable"}));
    assert!(
        saved_view(&router, &intent, &token, &home).await["evidence"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(!dir.path().join("actions/native/runtime.sqlite").exists());
}

#[tokio::test]
async fn submission_http_refuses_untrusted_credentials_coordinates_keys_and_budgets_before_custody()
{
    let dir = tempfile::tempdir().unwrap();
    let (wb, intent, token) = setup(dir.path());
    let router = app(&wb);
    let home = home_admission(&router, &token, "initial-home-admission").await;
    let forged = wb
        .lock_unpoisoned()
        .authenticate_action_context(&token)
        .unwrap();
    assert_eq!(
        submit(
            &router,
            &intent,
            None,
            None,
            body(&intent),
            &intent.request_id,
            Some(forged)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        submit(
            &router,
            &intent,
            Some(&token),
            None,
            body(&intent),
            &intent.request_id,
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        submit(
            &router,
            &intent,
            Some(&token),
            Some(&home),
            body(&intent),
            "new-key",
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    for field in ["home", "issuer", "scope"] {
        let mut wrong = body(&intent);
        wrong["identity"][field] = json!("different");
        assert_eq!(
            submit(
                &router,
                &intent,
                Some(&token),
                Some(&home),
                wrong,
                &intent.request_id,
                None
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
    let mut large = body(&intent);
    large["content"] = json!("x".repeat(4097));
    assert_eq!(
        submit(
            &router,
            &intent,
            Some(&token),
            Some(&home),
            large,
            &intent.request_id,
            None
        )
        .await
        .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    wb.lock_unpoisoned().revoke_account_session(&token);
    assert_ne!(
        submit(
            &router,
            &intent,
            Some(&token),
            Some(&home),
            body(&intent),
            &intent.request_id,
            None
        )
        .await
        .0,
        StatusCode::ACCEPTED
    );
    assert!(
        !dir.path().join("actions").exists(),
        "refusal opened action custody"
    );
}
