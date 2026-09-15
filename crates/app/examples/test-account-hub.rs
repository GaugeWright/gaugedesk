//! Hermetic stand-in Hub for the desktop account-handoff e2e (LOGIN-5, ADR 0123).
//!
//! Plays the Hub's side of the **native device handoff** so the journey —
//! sign-in, device-bound refresh, revocation stopping refresh, sign-out — is
//! drivable with no IdP and no network. The real Hub handlers (exchange
//! recording the device, refresh refusing a revoked one) carry their own unit
//! tests in `auth_oidc`; this stub proves the desktop *client* half (the local
//! control plane's custody + the surfaces) end-to-end.
//!
//! Deterministic: every refresh advances the next-renewal time by a strictly
//! increasing counter, so renewal is assertable across reads even within one
//! wall-clock second. `POST /test/revoke` flips the device to revoked, after
//! which the bound opaque session can no longer renew.

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

const PERSON: &str = "e2e-person@example.test";
const ACCOUNT: &str = "e2e-account-root";
const SESSION: &str = "e2e-opaque-account-session";
const CODE: &str = "e2e-handoff-code";
const DEVICE: &str = "native-e2e-device";
/// Short enough that every status read on the desktop control plane falls
/// inside its proactive-refresh window (10 minutes).
const TOKEN_LIFE_SECS: i64 = 360;

#[derive(Default)]
struct Hub {
    revoked: AtomicBool,
    refreshes: AtomicI64,
    provider_linked: AtomicBool,
    device_link_started: AtomicBool,
    account_messages: Mutex<Vec<(String, String)>>,
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

async fn exchange(
    State(hub): State<Arc<Hub>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // Real hub compositions carry the idempotency-key spine on every POST; the
    // stand-in enforces it too, so the e2e lane proves the client sends it
    // (the open-composition hub 400s without it — found live 2026-08-18).
    if !headers.contains_key("idempotency-key") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "missing Idempotency-Key header" })),
        )
            .into_response();
    }
    let code = body.get("code").and_then(Value::as_str).unwrap_or_default();
    let verifier = body
        .get("verifier")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if code != CODE || verifier.is_empty() {
        return (StatusCode::UNAUTHORIZED, "unknown handoff").into_response();
    }
    hub.revoked.store(false, Ordering::SeqCst);
    let now_ms = now_secs() * 1000;
    Json(json!({
        "account_id": ACCOUNT,
        "account_session": SESSION,
        "token_type": "Bearer",
        "device_id": DEVICE,
        "label": PERSON,
        "expires_at_ms": now_ms + 30 * 24 * 60 * 60 * 1000,
        "refresh_after_ms": now_ms + TOKEN_LIFE_SECS * 1000,
    }))
    .into_response()
}

async fn refresh(State(hub): State<Arc<Hub>>, headers: HeaderMap) -> impl IntoResponse {
    let authorized = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("Bearer "));
    if !authorized {
        return (StatusCode::UNAUTHORIZED, "authenticate to refresh").into_response();
    }
    if hub.revoked.load(Ordering::SeqCst) {
        return (
            StatusCode::UNAUTHORIZED,
            "this device's account session was revoked",
        )
            .into_response();
    }
    let n = hub.refreshes.fetch_add(1, Ordering::SeqCst) + 1;
    Json(json!({
        "refreshed": true,
        "person": ACCOUNT,
        "refresh_after_ms": (now_secs() + TOKEN_LIFE_SECS + n) * 1000,
    }))
    .into_response()
}

async fn homes() -> impl IntoResponse {
    Json(json!({
        "homes": [{
            "id": "e2e-home",
            "kind": "registered",
            "endpoint": "https://home.e2e.test",
            "relay": null,
        }],
        "selected_home": null,
    }))
}

async fn home_routes() -> impl IntoResponse {
    Json(json!({
        "routes": [{
            "project": "e2e-project",
            "home_id": "e2e-home",
            "endpoint": "https://home.e2e.test",
        }],
    }))
}

async fn revoke(State(hub): State<Arc<Hub>>) -> impl IntoResponse {
    hub.revoked.store(true, Ordering::SeqCst);
    StatusCode::NO_CONTENT
}

fn account_authorized(headers: &HeaderMap) -> bool {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        == Some(concat!("Bearer ", "e2e-opaque-account-session"))
}

fn account_session(provider_linked: bool, device_link_started: bool) -> Value {
    let scope = json!({ "kind": "person", "id": ACCOUNT });
    let pages = [
        ("account", "AccountSettingsPageV1"),
        ("provider-connections", "ProviderConnectionsPageV1"),
        ("trusted-devices", "TrustedDevicesPageV1"),
        ("application-settings", "ApplicationSettingsPageV1"),
    ]
    .into_iter()
    .map(|(id, read_model)| {
        let commands = match id {
            "provider-connections" => vec!["provider-connection.api-key.add"],
            "trusted-devices" => vec!["trusted-device.link.begin"],
            _ => Vec::new(),
        };
        let resource_basis = match id {
            "provider-connections" if provider_linked => {
                "native-e2e:provider-connections:linked".to_string()
            }
            "provider-connections" => "native-e2e:provider-connections:empty".to_string(),
            "trusted-devices" if device_link_started => {
                "native-e2e:trusted-devices:waiting".to_string()
            }
            "trusted-devices" => "native-e2e:trusted-devices:ready".to_string(),
            _ => format!("native-e2e:{id}:basis"),
        };
        json!({
            "id": id,
            "read_model": read_model,
            "version": 1,
            "resource_basis": resource_basis,
            "freshness": "live",
            "availability": "available",
            "commands": commands,
        })
    })
    .collect::<Vec<_>>();
    json!({
        "id": "native-e2e-account-session",
        "generation": "native-e2e-account-generation",
        "app": "account-settings",
        "scope": scope,
        "actor": ACCOUNT,
        "capabilities": ["account.read", "account.provider.write", "trusted-devices.link"],
        "pages": pages,
        "commands": [{
            "id": "provider-connection.api-key.add",
            "capability": "account.provider.write",
            "review": "immediate"
        }, {
            "id": "trusted-device.link.begin",
            "capability": "trusted-devices.link",
            "review": "immediate"
        }],
        "update_cursor": "native-e2e-account-update",
    })
}

async fn open_account_gaugeapp(State(hub): State<Arc<Hub>>, headers: HeaderMap) -> Response {
    if !account_authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, "sealed account session required").into_response();
    }
    Json(json!({
        "session": account_session(
            hub.provider_linked.load(Ordering::SeqCst),
            hub.device_link_started.load(Ordering::SeqCst),
        )
    }))
    .into_response()
}

async fn account_page(
    State(hub): State<Arc<Hub>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    if !account_authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, "sealed account session required").into_response();
    }
    let page = match id.as_str() {
        "account" => json!({
            "app": "account-settings",
            "scope": { "kind": "person", "id": ACCOUNT },
            "id": "account",
            "read_model": "AccountSettingsPageV1",
            "version": 1,
            "resource_basis": "native-e2e:account:basis",
            "freshness": "live",
            "model": {
                "profile": { "account_id": ACCOUNT, "display_name": "E2E Person" },
                "consumer_oidc": { "available": false, "connection_id": null, "label": null },
                "verified_contacts": [{ "id": "contact-1", "email": PERSON, "verified_at": 1 }],
                "authenticators": [],
                "recovery": { "batches": [] },
                "sessions": [],
                "memberships": [{
                    "id": "personal-e2e",
                    "display_name": "Personal",
                    "role": "owner",
                    "personal": true,
                    "provider_commercial": false
                }],
                "invitations": []
            }
        }),
        "provider-connections" => {
            let linked = hub.provider_linked.load(Ordering::SeqCst);
            let connections = if linked {
                vec![json!({
                    "id": "native-e2e-openai",
                    "provider": "openai",
                    "name": "OpenAI",
                    "kind": "api-key",
                    "endpoint_class": "provider-hosted",
                    "base_url": null,
                    "linked": true,
                    "status": "active",
                    "version": 1,
                    "execution_classes": ["local-interactive"],
                    "models": [],
                    "linked_at_ms": 1,
                    "last_verified_at_ms": null,
                    "verification": "unverified"
                })]
            } else {
                Vec::new()
            };
            json!({
                "app": "account-settings",
                "scope": { "kind": "person", "id": ACCOUNT },
                "id": "provider-connections",
                "read_model": "ProviderConnectionsPageV1",
                "version": 1,
                "resource_basis": if linked { "native-e2e:provider-connections:linked" } else { "native-e2e:provider-connections:empty" },
                "freshness": "live",
                "model": {
                    "connections": connections,
                    "default_model": null,
                    "subscription_sign_ins": {
                        "codex": { "provider": "openai-codex", "linked": false, "expires": null, "expired": false, "login": null },
                        "grok": { "provider": "xai-grok", "linked": false, "expires": null, "expired": false, "login": null }
                    },
                    "managed_inference": {
                        "plan": null,
                        "usage": {
                            "runs": 0, "input_tokens": 0, "output_tokens": 0,
                            "total_tokens": 0, "included_tokens": 0, "overage_tokens": 0,
                            "unattributed_runs": 0, "unattributed_tokens": 0
                        },
                        "billing": {
                            "customer_linked": false,
                            "subscription": null,
                            "processor_mode": "test",
                            "verification": "unlinked",
                            "configured_plan": { "name": "Managed inference", "included_tokens": 0, "checkout_available": false },
                            "management": { "plan_change": false, "seats": false, "cancellation": false },
                            "documents": {
                                "invoices": [], "estimate": null, "refreshed_at": null,
                                "history_complete": false, "freshness": "not-refreshed"
                            },
                            "freshness": "processor-reconciled"
                        }
                    }
                }
            })
        }
        "trusted-devices" => {
            let started = hub.device_link_started.load(Ordering::SeqCst);
            json!({
                "app": "account-settings",
                "scope": { "kind": "person", "id": ACCOUNT },
                "id": "trusted-devices",
                "read_model": "TrustedDevicesPageV1",
                "version": 1,
                "resource_basis": if started { "native-e2e:trusted-devices:waiting" } else { "native-e2e:trusted-devices:ready" },
                "freshness": "live",
                "model": {
                    "devices": [{
                        "id": DEVICE,
                        "label": "This computer",
                        "subkey_pubkey": "native-e2e-public-key",
                        "kind": "computer",
                        "status": "active",
                        "enrolled_at": 1,
                        "last_seen_ms": 1,
                        "current": true
                    }],
                    "pending_link": if started { Some(json!({
                        "id": "native-e2e-device-link",
                        "phase": "waiting-for-device",
                        "human_code": "DESK-4821",
                        "qr_payload": "native-e2e-device-link-payload",
                        "created_at_ms": 1,
                        "expires_at_ms": 4_102_444_800_000_i64,
                        "device": null,
                        "sas": null,
                        "completed_at_ms": null
                    })) } else { None },
                    "link_availability": { "available": true }
                }
            })
        }
        _ => return (StatusCode::NOT_FOUND, "fixture page is not populated").into_response(),
    };
    Json(json!({ "page": page })).into_response()
}

async fn account_command(
    State(hub): State<Arc<Hub>>,
    headers: HeaderMap,
    Json(envelope): Json<Value>,
) -> Response {
    if !account_authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, "sealed account session required").into_response();
    }
    if !headers.contains_key("idempotency-key") {
        return (StatusCode::BAD_REQUEST, "missing Idempotency-Key header").into_response();
    }
    let valid = envelope.get("app").and_then(Value::as_str) == Some("account-settings")
        && envelope
            .get("scope")
            .and_then(|scope| scope.get("id"))
            .and_then(Value::as_str)
            == Some(ACCOUNT)
        && envelope.get("page_id").and_then(Value::as_str) == Some("trusted-devices")
        && envelope.get("command_id").and_then(Value::as_str) == Some("trusted-device.link.begin")
        && envelope.get("expected_basis").and_then(Value::as_str)
            == Some("native-e2e:trusted-devices:ready");
    if !valid || hub.device_link_started.swap(true, Ordering::SeqCst) {
        return (StatusCode::CONFLICT, "device-link request was not current").into_response();
    }
    Json(json!({
        "receipt": {
            "id": "native-e2e-device-link-receipt",
            "session_id": "native-e2e-account-session",
            "generation": "native-e2e-account-generation",
            "app": "account-settings",
            "scope": { "kind": "person", "id": ACCOUNT },
            "page_id": "trusted-devices",
            "command_id": "trusted-device.link.begin",
            "expected_basis": "native-e2e:trusted-devices:ready",
            "status": "applied"
        }
    }))
    .into_response()
}

async fn account_provider_secret(
    State(hub): State<Arc<Hub>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !account_authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, "sealed account session required").into_response();
    }
    if !headers.contains_key("idempotency-key") {
        return (StatusCode::BAD_REQUEST, "missing Idempotency-Key header").into_response();
    }
    let envelope = body.get("envelope").cloned().unwrap_or(Value::Null);
    let valid = envelope.get("app").and_then(Value::as_str) == Some("account-settings")
        && envelope
            .get("scope")
            .and_then(|scope| scope.get("id"))
            .and_then(Value::as_str)
            == Some(ACCOUNT)
        && envelope.get("page_id").and_then(Value::as_str) == Some("provider-connections")
        && envelope.get("command_id").and_then(Value::as_str)
            == Some("provider-connection.api-key.add")
        && envelope.get("expected_basis").and_then(Value::as_str)
            == Some("native-e2e:provider-connections:empty")
        && envelope
            .get("payload")
            .and_then(|payload| payload.get("provider"))
            .and_then(Value::as_str)
            == Some("openai")
        && body.get("secret").and_then(Value::as_str) == Some("native-e2e-provider-secret");
    if !valid || hub.provider_linked.swap(true, Ordering::SeqCst) {
        return (StatusCode::CONFLICT, "credential intake was not current").into_response();
    }
    Json(json!({
        "receipt": {
            "id": "native-e2e-provider-receipt",
            "session_id": "native-e2e-account-session",
            "generation": "native-e2e-account-generation",
            "app": "account-settings",
            "scope": { "kind": "person", "id": ACCOUNT },
            "page_id": "provider-connections",
            "command_id": "provider-connection.api-key.add",
            "expected_basis": "native-e2e:provider-connections:empty",
            "status": "applied"
        },
        "result": { "connection_id": "native-e2e-openai", "verification": "unverified" }
    }))
    .into_response()
}

async fn account_updates(headers: HeaderMap) -> Response {
    if !account_authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, "sealed account session required").into_response();
    }
    Json(json!({ "cursor": "native-e2e-account-update", "invalidations": [] })).into_response()
}

async fn account_proposals(headers: HeaderMap) -> Response {
    if !account_authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, "sealed account session required").into_response();
    }
    Json(json!({ "proposals": [] })).into_response()
}

async fn account_messages(State(hub): State<Arc<Hub>>, headers: HeaderMap) -> Response {
    if !account_authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, "sealed account session required").into_response();
    }
    let exchanges = hub.account_messages.lock().expect("account messages");
    let messages = exchanges
        .iter()
        .enumerate()
        .flat_map(|(index, (message, reply))| {
            let sequence = (index * 2) as i64;
            [
                json!({
                    "id": format!("native-e2e-account-message-{sequence}"),
                    "thread_id": "native-e2e-account-thread",
                    "app": "account-settings",
                    "scope": { "kind": "person", "id": ACCOUNT },
                    "actor": ACCOUNT,
                    "sequence": sequence,
                    "role": "user",
                    "text": message,
                    "proposals": []
                }),
                json!({
                    "id": format!("native-e2e-account-message-{}", sequence + 1),
                    "thread_id": "native-e2e-account-thread",
                    "app": "account-settings",
                    "scope": { "kind": "person", "id": ACCOUNT },
                    "actor": ACCOUNT,
                    "sequence": sequence + 1,
                    "role": "assistant",
                    "text": reply,
                    "proposals": []
                }),
            ]
        })
        .collect::<Vec<_>>();
    Json(json!({
        "thread": {
            "id": "native-e2e-account-thread",
            "cursor": format!("native-e2e-account-thread:{}", messages.len()),
            "messages": messages
        }
    }))
    .into_response()
}

async fn send_account_message(
    State(hub): State<Arc<Hub>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !account_authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, "sealed account session required").into_response();
    }
    if !headers.contains_key("idempotency-key") {
        return (StatusCode::BAD_REQUEST, "missing Idempotency-Key header").into_response();
    }
    let message = body
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let valid = body.get("session_id").and_then(Value::as_str)
        == Some("native-e2e-account-session")
        && body.get("generation").and_then(Value::as_str) == Some("native-e2e-account-generation")
        && body
            .get("scope")
            .and_then(|scope| scope.get("id"))
            .and_then(Value::as_str)
            == Some(ACCOUNT)
        && message == "native account continuity marker";
    if !valid {
        return (StatusCode::BAD_REQUEST, "invalid Account conversation turn").into_response();
    }
    let reply = "Account authority remembers this conversation.".to_string();
    let mut messages = hub.account_messages.lock().expect("account messages");
    if messages.is_empty() {
        messages.push((message.to_string(), reply.clone()));
    }
    Json(json!({ "turn": { "message": reply, "proposals": [] } })).into_response()
}

async fn account_agent_events(headers: HeaderMap) -> Response {
    if !account_authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, "sealed account session required").into_response();
    }
    Sse::new(futures::stream::pending::<Result<Event, Infallible>>())
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response()
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let addr = gaugedesk_env::var("TEST_HUB_ADDR").unwrap_or_else(|| "127.0.0.1:7910".to_string());
    let hub = Arc::new(Hub::default());
    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/auth/mobile/exchange", post(exchange))
        .route("/auth/mobile/refresh", post(refresh))
        .route("/account/homes", get(homes))
        .route("/account/home-routes", get(home_routes))
        .route(
            "/gaugeapps/account-settings/sessions",
            post(open_account_gaugeapp),
        )
        .route("/gaugeapps/account-settings/pages/{id}", get(account_page))
        .route(
            "/gaugeapps/account-settings/commands",
            post(account_command),
        )
        .route(
            "/gaugeapps/account-settings/provider-connections/secrets",
            post(account_provider_secret),
        )
        .route("/gaugeapps/account-settings/updates", get(account_updates))
        .route(
            "/gaugeapps/account-settings/proposals",
            get(account_proposals),
        )
        .route(
            "/gaugeapps/account-settings/agent/messages",
            get(account_messages).post(send_account_message),
        )
        .route(
            "/gaugeapps/account-settings/agent/events",
            get(account_agent_events),
        )
        .route("/test/revoke", post(revoke))
        .with_state(hub);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind test hub");
    eprintln!("[test-account-hub] listening on http://{addr}");
    axum::serve(listener, app).await.expect("serve test hub");
}
