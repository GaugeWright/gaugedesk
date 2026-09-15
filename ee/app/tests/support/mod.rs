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
    key: Option<&str>,
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
    if let Some(key) = key {
        builder = builder.header("idempotency-key", key);
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
/// GaugeApp routes. Integration tests use this instead of resurrecting the
/// retired `/admin/*` mutation surface.
pub async fn administration_command(
    app: &Router,
    tenant: Option<&str>,
    token: Option<&str>,
    page_id: &str,
    command_id: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let (status, opened) = request(
        app,
        "POST",
        "/gaugeapps/administration/sessions",
        tenant,
        token,
        json!({}),
        None,
    )
    .await;
    if status != StatusCode::OK {
        return (status, opened);
    }
    let session = &opened["session"];
    let Some(grant) = session["pages"]
        .as_array()
        .and_then(|pages| pages.iter().find(|page| page["id"] == page_id))
    else {
        return (
            StatusCode::FORBIDDEN,
            json!({ "error": "page not admitted" }),
        );
    };
    let proposal_key = format!(
        "gaugeapp-integration-{}",
        NEXT_KEY.fetch_add(1, Ordering::Relaxed)
    );
    let envelope = json!({
        "session_id": session["id"],
        "generation": session["generation"],
        "app": "administration",
        "scope": session["scope"],
        "page_id": page_id,
        "command_id": command_id,
        "expected_basis": grant["resource_basis"],
        "idempotency_key": proposal_key,
        "payload": payload,
        "client": "desktop",
    });
    let (status, proposed) = request(
        app,
        "POST",
        "/gaugeapps/administration/commands",
        tenant,
        token,
        envelope,
        Some(&proposal_key),
    )
    .await;
    if status != StatusCode::OK {
        return (status, proposed);
    }
    let Some(change_id) = proposed["proposal"]["id"].as_str() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, proposed);
    };
    let review_key = format!(
        "gaugeapp-integration-review-{}",
        NEXT_KEY.fetch_add(1, Ordering::Relaxed)
    );
    request(
        app,
        "POST",
        &format!("/gaugeapps/administration/proposals/{change_id}/review"),
        tenant,
        token,
        json!({
            "session_id": session["id"],
            "generation": session["generation"],
            "app": "administration",
            "scope": session["scope"],
            "decision": "accept",
            "client": "desktop",
        }),
        Some(&review_key),
    )
    .await
}

/// Read one admitted Administration page using the same exact session.
pub async fn administration_document(
    app: &Router,
    tenant: Option<&str>,
    token: Option<&str>,
    page_id: &str,
) -> (StatusCode, Value) {
    let (status, opened) = request(
        app,
        "POST",
        "/gaugeapps/administration/sessions",
        tenant,
        token,
        json!({}),
        None,
    )
    .await;
    if status != StatusCode::OK {
        return (status, opened);
    }
    let session = &opened["session"];
    let uri = format!(
        "/gaugeapps/administration/pages/{page_id}?session={}&generation={}&scope={}",
        session["id"].as_str().unwrap(),
        session["generation"].as_str().unwrap(),
        session["scope"]["id"].as_str().unwrap(),
    );
    request(app, "GET", &uri, tenant, token, Value::Null, None).await
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
        "/gaugeapps/administration/sessions",
        tenant,
        token,
        json!({}),
        None,
    )
    .await;
    if status != StatusCode::OK {
        return (status, opened);
    }
    let session = &opened["session"];
    let query = format!(
        "session={}&generation={}&scope={}&domain={domain}",
        session["id"].as_str().unwrap(),
        session["generation"].as_str().unwrap(),
        session["scope"]["id"].as_str().unwrap(),
    );
    request(
        app,
        "GET",
        &format!("/gaugeapps/administration/organization/domain-verification?{query}"),
        tenant,
        token,
        Value::Null,
        None,
    )
    .await
}
