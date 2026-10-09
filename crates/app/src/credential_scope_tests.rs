//! DR-0313: an unresolved presented account credential is never the install.
use super::*;

async fn refusal_get(app: &axum::Router, uri: &str, bearer: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn unresolved_bearers_refuse_actual_open_account_router_before_protected_io() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let claimant = session(&wb, CLAIMANT);
    let expired = session(&wb, CLAIMANT);
    wb.lock_unpoisoned().account_sessions().insert_loaded(
        &crate::account_session::session_id(&expired),
        CLAIMANT,
        crate::desktop_session::METHOD,
        1,
    );
    let revoked = session(&wb, CLAIMANT);
    assert!(wb.lock_unpoisoned().revoke_account_session(&revoked));
    let app = crate::open_control_plane(wb.clone());
    let home_credentials =
        crate::account_routes::home_runtime_credential_routes().with_state(wb.clone());
    let (status, _) = send(
        &app,
        "POST",
        "/account/credentials",
        Some(&claimant),
        Some(serde_json::json!({"provider":"anthropic","token":"synthetic-not-a-live-key"})),
    )
    .await;
    assert!(status.is_success());
    let (status, _) = send(
        &app,
        "PUT",
        "/account/settings/default-model",
        Some(&claimant),
        Some(serde_json::json!({"value":"synthetic-install-only-model"})),
    )
    .await;
    assert!(status.is_success());
    let before = wb
        .lock_unpoisoned()
        .store_ref()
        .retained_events(crate::account::ACCOUNT_SCOPE)
        .unwrap();
    for bearer in [
        "forged-account-bearer",
        "",
        expired.as_str(),
        revoked.as_str(),
    ] {
        assert!(wb
            .lock_unpoisoned()
            .resolve_account_session(bearer)
            .is_none());
        for uri in [
            "/account/credentials",
            "/account/settings",
            "/account/default-model",
            "/account/boxes",
            "/account/oauth/openai-codex",
            "/account/oauth/xai-grok",
            "/projects/personal/models",
            "/account/boxes/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/surface/environments/tokenwright/audit",
        ] {
            let (status, body) = refusal_get(&app, uri, bearer).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}: {body}");
            assert_eq!(body, "credential account session is unavailable");
        }
        for (method, uri, body) in [
            (
                "PUT",
                "/account/settings/default-model",
                Some(serde_json::json!({"value":"forbidden-write"})),
            ),
            (
                "POST",
                "/account/credentials",
                Some(serde_json::json!({"provider":"openai","token":"forbidden"})),
            ),
            (
                "POST",
                "/account/boxes/claim",
                Some(
                    serde_json::json!({"pairing_string":"tw1_eyJ2IjoxLCJyIjoid3NzOi8vcmVsYXkuZXhhbXBsZTo0NDMvciIsImMiOiJBQkNELUVGR0gtSktNTi1QUVJTLVRWV1giLCJmIjoic2hhMjU2OmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIifQ"}),
                ),
            ),
            (
                "POST",
                "/chats/absent-credential-guard/task",
                Some(serde_json::json!({"prompt":"must refuse before turn admission"})),
            ),
            ("DELETE", "/account/credentials/anthropic", None),
            (
                "DELETE",
                "/account/boxes/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                None,
            ),
            ("POST", "/account/oauth/openai-codex/start", None),
            ("POST", "/account/oauth/xai-grok/start", None),
            ("POST", "/account/oauth/xai-grok/cancel", None),
        ] {
            let (status, body) = send(&app, method, uri, Some(bearer), body).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}: {body}");
        }
        // The Desktop cancel route is the separate scope-independent browser
        // process cancellation. These are the actual scoped Home handlers.
        for uri in [
            "/account/oauth/openai-codex/cancel",
            "/account/oauth/xai-grok/cancel",
        ] {
            let (status, body) = send(&home_credentials, "POST", uri, Some(bearer), None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "Home {uri}: {body}");
        }
        assert_eq!(
            wb.lock_unpoisoned()
                .store_ref()
                .retained_events(crate::account::ACCOUNT_SCOPE)
                .unwrap(),
            before
        );
    }
}

#[tokio::test]
async fn absent_and_valid_account_credentials_keep_exact_scope_isolation() {
    let (_root, wb) = open();
    claim(&wb, CLAIMANT);
    let claimant = session(&wb, CLAIMANT);
    let other = session(&wb, OTHER);
    let app = crate::open_control_plane(wb.clone());
    for (bearer, value) in [
        (Some(claimant.as_str()), "claimant-only"),
        (Some(other.as_str()), "other-only"),
        (None, "local-only"),
    ] {
        let (status, body) = send(
            &app,
            "PUT",
            "/account/settings/scope-witness",
            bearer,
            Some(serde_json::json!({"value":value})),
        )
        .await;
        assert!(status.is_success(), "{status}: {body}");
    }
    for (bearer, value) in [
        (Some(claimant.as_str()), "claimant-only"),
        (Some(other.as_str()), "other-only"),
        (None, "local-only"),
    ] {
        let (status, body) = send(&app, "GET", "/account/settings", bearer, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["settings"]["scope-witness"], value);
    }
    let guard = wb.lock_unpoisoned();
    assert_eq!(
        guard.credential_scope_for(Some(&claimant)).unwrap(),
        crate::account::ACCOUNT_SCOPE
    );
    assert_eq!(
        guard.credential_scope_for(Some(&other)).unwrap(),
        crate::account::account_scope(OTHER)
    );
    assert_eq!(
        guard.credential_scope_for(None).unwrap(),
        crate::account::account_scope(guard.authority().as_str())
    );
}

#[test]
fn hub_scope_mapping_is_not_desktop_opaque_session_validation() {
    let (_root, wb) = open();
    let mut guard = wb.lock_unpoisoned();
    guard.enable_hosted_home_mode();
    for bearer in [None, Some("composition-resolves-its-own-authentication")] {
        assert_eq!(
            guard.credential_scope_for(bearer).unwrap(),
            guard.account_scope_for(bearer)
        );
    }
}
