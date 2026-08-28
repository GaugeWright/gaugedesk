//! Authenticated local model-egress broker for remote DO development (ADR 0085 §2–3).
//!
//! A loopback GaugeDesk process may be exposed through an operator-owned outbound tunnel. The
//! Worker receives only a broker-hop token and the already-admitted credential reference; the
//! Codex refresh token remains sealed locally. This route is mounted only by the native runtime,
//! never by the hosted Home or public compositions.

use std::io::Read;

use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::account::{
    credentials_in_scope, CredentialAuthentication, ModelExecutionClass, ACCOUNT_SCOPE,
};
use crate::{LockUnpoisoned, SharedWorkbench};

const PROTOCOL: &str = "whipplescript.model-egress.v1";
const PATH: &str = "/internal/local-model-egress";
const TOKEN_ENV: &str = "GAUGEDESK_LOCAL_MODEL_BROKER_TOKEN";
const CODEX_URL: &str = "https://chatgpt.com/backend-api/codex/responses";
const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

pub fn routes() -> Router<SharedWorkbench> {
    Router::new().route(PATH, post(model_egress))
}

#[derive(Debug)]
struct BrokerError {
    status: StatusCode,
    message: &'static str,
}

impl BrokerError {
    fn new(status: StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }
}

impl IntoResponse for BrokerError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

#[derive(Debug, Deserialize)]
struct BrokerEnvelope {
    protocol: String,
    credential_ref: String,
    provider: String,
    request: ProviderRequest,
}

#[derive(Debug, Deserialize)]
struct ProviderRequest {
    url: String,
    headers: Vec<(String, String)>,
    body: Value,
}

trait ProviderTransport {
    fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &Value,
    ) -> Result<(u16, String, Option<String>), String>;
}

struct UreqTransport;

impl ProviderTransport for UreqTransport {
    fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &Value,
    ) -> Result<(u16, String, Option<String>), String> {
        let agent = ureq::AgentBuilder::new().redirects(0).build();
        let mut request = agent.post(url);
        for (name, value) in headers {
            request = request.set(name, value);
        }
        let encoded = serde_json::to_string(body).map_err(|_| "serialize provider body")?;
        let response = match request.send_string(&encoded) {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(error)) => return Err(format!("transport: {error}")),
        };
        let status = response.status();
        let reconciliation_ref = response.header("x-request-id").map(str::to_owned);
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read provider response: {error}"))?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err("provider response exceeds the size cap".to_owned());
        }
        let body = String::from_utf8(bytes)
            .map_err(|_| "provider response is not valid UTF-8".to_owned())?;
        Ok((status, body, reconciliation_ref))
    }
}

async fn model_egress(State(wb): State<SharedWorkbench>, request: Request) -> Response {
    if let Err(error) = authorize(&request) {
        return error.into_response();
    }
    let bytes = match to_bytes(request.into_body(), MAX_REQUEST_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return BrokerError::new(StatusCode::PAYLOAD_TOO_LARGE, "broker request is too large")
                .into_response()
        }
    };
    let envelope = match serde_json::from_slice::<BrokerEnvelope>(&bytes) {
        Ok(envelope) => envelope,
        Err(_) => {
            return BrokerError::new(StatusCode::BAD_REQUEST, "invalid model broker envelope")
                .into_response()
        }
    };
    match tokio::task::spawn_blocking(move || execute(&wb, envelope, &UreqTransport)).await {
        Ok(Ok(response)) => (StatusCode::OK, Json(response)).into_response(),
        Ok(Err(error)) => error.into_response(),
        Err(_) => BrokerError::new(StatusCode::BAD_GATEWAY, "local model broker task failed")
            .into_response(),
    }
}

fn authorize(request: &Request) -> Result<(), BrokerError> {
    let configured = std::env::var(TOKEN_ENV)
        .ok()
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| {
            BrokerError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "local model broker is not configured",
            )
        })?;
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            BrokerError::new(
                StatusCode::UNAUTHORIZED,
                "local model broker authentication required",
            )
        })?;
    let message = b"gaugedesk:local-model-broker:v1";
    let expected = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, configured.trim().as_bytes());
    let supplied = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, presented.as_bytes());
    let tag = ring::hmac::sign(&supplied, message);
    ring::hmac::verify(&expected, message, tag.as_ref()).map_err(|_| {
        BrokerError::new(
            StatusCode::UNAUTHORIZED,
            "local model broker authentication required",
        )
    })
}

fn execute(
    wb: &SharedWorkbench,
    envelope: BrokerEnvelope,
    transport: &dyn ProviderTransport,
) -> Result<Value, BrokerError> {
    if envelope.protocol != PROTOCOL {
        return Err(BrokerError::new(
            StatusCode::BAD_REQUEST,
            "unsupported model broker protocol",
        ));
    }
    if envelope.provider != "openai-codex" || envelope.request.url != CODEX_URL {
        return Err(BrokerError::new(
            StatusCode::FORBIDDEN,
            "local Codex broker provider or endpoint was not admitted",
        ));
    }
    let (authority, expected_ref) = {
        let workbench = wb.lock_unpoisoned();
        let authority = workbench.authority().as_str().to_owned();
        let record = credentials_in_scope(workbench.store_ref(), ACCOUNT_SCOPE)
            .remove("openai-codex")
            .filter(|record| {
                record.admits(ModelExecutionClass::LocalInteractive)
                    && record.authentication == CredentialAuthentication::OAuth
            })
            .ok_or_else(|| {
                BrokerError::new(
                    StatusCode::FORBIDDEN,
                    "local Codex credential is unavailable",
                )
            })?;
        (
            authority,
            crate::account::canonical_credential_ref(
                "account",
                workbench.authority().as_str(),
                "openai-codex",
                record.version,
            ),
        )
    };
    if envelope.credential_ref != expected_ref || authority.trim().is_empty() {
        return Err(BrokerError::new(
            StatusCode::FORBIDDEN,
            "credential ref does not name the current local Codex login",
        ));
    }
    let credential = crate::codex_oauth::resolve_runtime_credential(wb)
        .map_err(|_| {
            BrokerError::new(
                StatusCode::BAD_GATEWAY,
                "local Codex credential refresh failed",
            )
        })?
        .ok_or_else(|| {
            BrokerError::new(
                StatusCode::FORBIDDEN,
                "local Codex credential is unavailable",
            )
        })?;
    let headers = provider_headers(
        envelope.request.headers,
        &credential.access,
        &credential.account_id,
    )?;
    let (status, body, reconciliation_ref) = transport
        .post(CODEX_URL, &headers, &envelope.request.body)
        .map_err(|_| {
            BrokerError::new(StatusCode::BAD_GATEWAY, "Codex provider transport failed")
        })?;
    let mut response = json!({
        "protocol": PROTOCOL,
        "status": status,
        "body": body,
    });
    if let Some(reconciliation_ref) = reconciliation_ref {
        response["reconciliation_ref"] = Value::String(reconciliation_ref);
    }
    Ok(response)
}

fn provider_headers(
    headers: Vec<(String, String)>,
    access_token: &str,
    account_id: &str,
) -> Result<Vec<(String, String)>, BrokerError> {
    let mut output = Vec::new();
    for (name, value) in headers {
        let normalized = name.to_ascii_lowercase();
        if matches!(
            normalized.as_str(),
            "authorization" | "chatgpt-account-id" | "cookie" | "proxy-authorization" | "host"
        ) {
            return Err(BrokerError::new(
                StatusCode::BAD_REQUEST,
                "model request contains a forbidden authentication header",
            ));
        }
        if !matches!(
            normalized.as_str(),
            "content-type"
                | "accept"
                | "openai-beta"
                | "originator"
                | "session_id"
                | "idempotency-key"
        ) {
            return Err(BrokerError::new(
                StatusCode::BAD_REQUEST,
                "model request contains a forbidden forwarding header",
            ));
        }
        output.push((normalized, value));
    }
    output.push(("authorization".into(), format!("Bearer {access_token}")));
    output.push(("chatgpt-account-id".into(), account_id.to_owned()));
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::open_workbench;

    struct FakeTransport {
        headers: Mutex<Vec<(String, String)>>,
    }

    impl ProviderTransport for FakeTransport {
        fn post(
            &self,
            _url: &str,
            headers: &[(String, String)],
            _body: &Value,
        ) -> Result<(u16, String, Option<String>), String> {
            *self.headers.lock().unwrap() = headers.to_vec();
            Ok((200, "data: done\n\n".into(), Some("request-1".into())))
        }
    }

    #[test]
    fn exact_local_codex_ref_resolves_and_auth_is_injected_only_at_egress() {
        let root = tempfile::tempdir().unwrap();
        let wb = open_workbench(root.path()).unwrap();
        let authority = wb.lock_unpoisoned().authority().as_str().to_owned();
        let credential = crate::codex_oauth::CodexOAuthCredential {
            access: "short-lived-access".into(),
            refresh: "sealed-refresh".into(),
            expires: i64::MAX,
            account_id: "chatgpt-account".into(),
        };
        crate::codex_oauth::store_credential(&wb, &credential).unwrap();
        let record = credentials_in_scope(wb.lock_unpoisoned().store_ref(), ACCOUNT_SCOPE)
            .remove("openai-codex")
            .unwrap();
        let envelope = BrokerEnvelope {
            protocol: PROTOCOL.into(),
            credential_ref: crate::account::canonical_credential_ref(
                "account",
                &authority,
                "openai-codex",
                record.version,
            ),
            provider: "openai-codex".into(),
            request: ProviderRequest {
                url: CODEX_URL.into(),
                headers: vec![("content-type".into(), "application/json".into())],
                body: json!({ "model": "gpt-test" }),
            },
        };
        let transport = FakeTransport {
            headers: Mutex::new(Vec::new()),
        };
        let response = execute(&wb, envelope, &transport).unwrap();
        assert_eq!(response["status"], 200);
        let headers = transport.headers.lock().unwrap();
        assert!(headers.contains(&("authorization".into(), "Bearer short-lived-access".into())));
        assert!(headers.contains(&("chatgpt-account-id".into(), "chatgpt-account".into())));
        assert!(!format!("{response:?}").contains("short-lived-access"));
        assert!(!format!("{response:?}").contains("sealed-refresh"));
    }
}
