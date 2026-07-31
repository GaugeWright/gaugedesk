#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

static NEXT_KEY: AtomicU64 = AtomicU64::new(1);

async fn request(
    app: &Router,
    method: &str,
    uri: &str,
    tenant: Option<&str>,
    token: Option<&str>,
    body: Value,
    keyed: bool,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(tenant) = tenant {
        builder = builder.header("x-gaugewright-tenant", tenant);
    }
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    if keyed {
        builder = builder.header(
            "idempotency-key",
            format!(
                "environment-integration-{}",
                NEXT_KEY.fetch_add(1, Ordering::Relaxed)
            ),
        );
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// Submit and human-accept one Administration command through the real shared
/// Environment routes. Integration tests use this instead of resurrecting the
/// retired `/admin/*` mutation surface.
pub async fn administration_command(
    app: &Router,
    tenant: Option<&str>,
    token: Option<&str>,
    document_id: &str,
    command_id: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let (status, opened) = request(
        app,
        "POST",
        "/environments/administration/sessions",
        tenant,
        token,
        json!({}),
        false,
    )
    .await;
    if status != StatusCode::OK {
        return (status, opened);
    }
    let session = &opened["session"];
    let Some(grant) = session["documents"].as_array().and_then(|documents| {
        documents
            .iter()
            .find(|document| document["id"] == document_id)
    }) else {
        return (
            StatusCode::FORBIDDEN,
            json!({ "error": "document not admitted" }),
        );
    };
    let envelope = json!({
        "session_id": session["id"],
        "environment": "administration",
        "scope": session["scope"],
        "document_id": document_id,
        "command_id": command_id,
        "base_revision": grant["revision"],
        "payload": payload,
        "client": "cli",
    });
    let (status, proposed) = request(
        app,
        "POST",
        "/environments/administration/commands",
        tenant,
        token,
        envelope,
        true,
    )
    .await;
    if status != StatusCode::OK {
        return (status, proposed);
    }
    let Some(change_id) = proposed["change"]["id"].as_str() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, proposed);
    };
    request(
        app,
        "POST",
        &format!("/environments/administration/changes/{change_id}/review"),
        tenant,
        token,
        json!({
            "session_id": session["id"],
            "environment": "administration",
            "scope": session["scope"],
            "decision": "accept",
            "client": "cli",
        }),
        true,
    )
    .await
}

/// Read one admitted Administration document using the same exact session.
pub async fn administration_document(
    app: &Router,
    tenant: Option<&str>,
    token: Option<&str>,
    document_id: &str,
) -> (StatusCode, Value) {
    let (status, opened) = request(
        app,
        "POST",
        "/environments/administration/sessions",
        tenant,
        token,
        json!({}),
        false,
    )
    .await;
    if status != StatusCode::OK {
        return (status, opened);
    }
    let session = &opened["session"];
    let uri = format!(
        "/environments/administration/documents/{document_id}?session={}&scope={}",
        session["id"].as_str().unwrap(),
        session["scope"]["id"].as_str().unwrap(),
    );
    request(app, "GET", &uri, tenant, token, Value::Null, false).await
}

/// Read the deterministic DNS challenge through the admitted Administration
/// session. This replaced the duplicate `/admin/domains/verify-token` façade.
pub async fn administration_domain_challenge(
    app: &Router,
    tenant: Option<&str>,
    token: Option<&str>,
    domain: &str,
) -> (StatusCode, Value) {
    let (status, opened) = request(
        app,
        "POST",
        "/environments/administration/sessions",
        tenant,
        token,
        json!({}),
        false,
    )
    .await;
    if status != StatusCode::OK {
        return (status, opened);
    }
    let session = &opened["session"];
    let query = format!(
        "session={}&scope={}&domain={domain}",
        session["id"].as_str().unwrap(),
        session["scope"]["id"].as_str().unwrap(),
    );
    request(
        app,
        "GET",
        &format!("/environments/administration/domain-verification?{query}"),
        tenant,
        token,
        Value::Null,
        false,
    )
    .await
}
