//! Desktop → Hub account sign-in: the local control plane's half of the
//! **native device handoff** (LOGIN-2, ADR 0123).
//!
//! The desktop links the person's GaugeWright account with the same handoff
//! native mobile uses: the system browser opens the Hub's `/auth/login` with a
//! PKCE-style challenge, the Hub authenticates the person and 302s to
//! `gaugewright://auth/callback#code=<single-use>`, and this module redeems the
//! code — with the verifier that never left this process — at the Hub's
//! exchange endpoint. The Hub returns a durable opaque account session; that
//! bearer is sealed at rest (`SEC-4`) in the local account scope while external
//! provider tokens remain inside the Hub. The webview sees only the one-time
//! code and non-secret status projections. Signing out appends a tombstone and
//! is idempotent; the device-bound provider grant is renewed proactively when
//! status is read (the account surfaces poll status, so a live desktop keeps
//! the Hub authority current without a background daemon).
//!
//! The Hub endpoint is deployment configuration, not edition:
//! `GAUGEDESK_ACCOUNT_HUB_URL` overrides the production default, and an
//! explicitly empty value disables the surface (status then reports
//! `available: false`, and the welcome/account UIs show their local-only
//! wording instead of a dead button).

use std::io::Read as _;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::account::ACCOUNT_SCOPE;
use crate::net_http::HttpClient;
use crate::{LockUnpoisoned, SharedWorkbench};

/// Marks the co-resident desktop composition. The hosted account authority
/// never installs this marker; it authenticates GaugeApp requests from its own
/// HttpOnly cookie or explicit bearer instead.
#[derive(Clone, Copy, Debug)]
pub struct NativeAccountPlane;

/// Exact native aliases for the hosted Account Settings GaugeApp. The browser
/// calls the ordinary product paths; this co-resident boundary attaches the
/// sealed account session and forwards them to the independently deployed
/// account authority. No catch-all is intentional: adding a hosted operation
/// requires adding its native custody boundary deliberately too.
pub fn gaugeapp_proxy_routes() -> Router<SharedWorkbench> {
    Router::new()
        .route(
            "/gaugeapps/account-settings/sessions",
            post(proxy_account_gaugeapp),
        )
        .route(
            "/gaugeapps/account-settings/pages/{id}",
            get(proxy_account_gaugeapp),
        )
        .route(
            "/gaugeapps/account-settings/updates",
            get(proxy_account_gaugeapp),
        )
        .route(
            "/gaugeapps/account-settings/agent/messages",
            get(proxy_account_gaugeapp).post(proxy_account_gaugeapp),
        )
        .route(
            "/gaugeapps/account-settings/agent/events",
            get(proxy_account_gaugeapp),
        )
        .route(
            "/gaugeapps/account-settings/agent/stop",
            post(proxy_account_gaugeapp),
        )
        .route(
            "/gaugeapps/account-settings/agent/erase",
            post(proxy_account_gaugeapp),
        )
        .route(
            "/gaugeapps/account-settings/commands",
            post(proxy_account_gaugeapp),
        )
        .route(
            "/gaugeapps/account-settings/provider-connections/secrets",
            post(proxy_account_gaugeapp),
        )
        .route(
            "/gaugeapps/account-settings/device-links/claim",
            post(proxy_account_gaugeapp),
        )
        .route(
            "/gaugeapps/account-settings/device-links/{id}",
            get(proxy_account_gaugeapp),
        )
        .route(
            "/gaugeapps/account-settings/device-links/{id}/complete",
            post(proxy_account_gaugeapp),
        )
        .route(
            "/gaugeapps/account-settings/proposals",
            get(proxy_account_gaugeapp).post(proxy_account_gaugeapp),
        )
        .route(
            "/gaugeapps/account-settings/proposals/{id}/review",
            post(proxy_account_gaugeapp),
        )
}

/// Latest-wins record family holding the sealed Hub session in the account scope.
const RECORD_KIND: &str = "hub-session";
const RECORD_ID: &str = "session";
/// Refresh when the Hub's next provider-renewal time is within this window.
const REFRESH_SKEW_MS: i64 = 10 * 60 * 1000;
/// A started sign-in that was never completed expires after this long.
const PENDING_TTL: Duration = Duration::from_secs(10 * 60);
/// The one native return URI the Hub admits (`auth_oidc::native_return_uri`).
const NATIVE_RETURN: &str = "gaugewright://auth/callback";

/// The Hub account-API base, or `None` when the surface is disabled.
/// `GAUGEDESK_ACCOUNT_HUB_URL` overrides; explicitly empty disables.
pub(crate) fn hub_base() -> Option<String> {
    let configured = gaugedesk_env::var("ACCOUNT_HUB_URL")
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|| "https://auth.gaugewright.com".to_string());
    if configured.is_empty() {
        return None;
    }
    Some(configured.trim_end_matches('/').to_string())
}

fn hub_tenant_url(hub: &str, tenant: &str, suffix: &[&str]) -> Result<String, String> {
    let mut url = url::Url::parse(hub).map_err(|_| "the Hub URL is invalid".to_string())?;
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|_| "the Hub URL cannot carry account paths".to_string())?;
        path.pop_if_empty();
        path.extend(["account", "tenants", tenant]);
        path.extend(suffix.iter().copied());
    }
    Ok(url.to_string())
}

struct AccountAuthorityResponse {
    status: u16,
    content_type: Option<String>,
    cache_control: Option<String>,
    reader: Box<dyn std::io::Read + Send + Sync + 'static>,
}

fn open_account_authority_request(
    method: &str,
    url: &str,
    bearer: &str,
    forwarded_headers: &[(String, String)],
    body: &[u8],
) -> Result<AccountAuthorityResponse, String> {
    // Credential-bearing proxy calls never follow redirects. A redirect could
    // otherwise carry the sealed account bearer outside the configured account
    // origin. The account authority returns explicit JSON launch URLs instead.
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(45))
        .build();
    let mut request = agent
        .request(method, url)
        .set("authorization", &format!("Bearer {bearer}"));
    for (name, value) in forwarded_headers {
        request = request.set(name, value);
    }
    let response = match if body.is_empty() {
        request.call()
    } else {
        request.send_bytes(body)
    } {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(ureq::Error::Transport(error)) => {
            return Err(format!("account authority transport: {error}"))
        }
    };
    Ok(AccountAuthorityResponse {
        status: response.status(),
        content_type: response.header("content-type").map(str::to_owned),
        cache_control: response.header("cache-control").map(str::to_owned),
        reader: response.into_reader(),
    })
}

fn forwarded_account_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    [
        "content-type",
        "idempotency-key",
        "x-gaugedesk-client-version",
        "x-gaugedesk-client-protocol",
        "x-gaugedesk-client-channel",
        "x-gaugedesk-client-platform",
    ]
    .into_iter()
    .filter_map(|name| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(|value| (name.to_owned(), value.to_owned()))
    })
    .collect()
}

/// Forward one exact Account Settings request through the local sealed-session
/// boundary. The caller supplies a product-owned path, never a URL; only the
/// configured account origin is addressable. Browser cookies, Authorization,
/// Origin, and arbitrary headers are deliberately not forwarded.
pub async fn proxy_account_authority(
    wb: &SharedWorkbench,
    method: Method,
    path_and_query: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(hub) = hub_base() else {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "account sign-in is not configured for this runtime" })),
        )
            .into_response();
    };
    let Some(bearer) = hub_session_token(wb) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "sign in to access Account Settings" })),
        )
            .into_response();
    };
    let url = format!("{hub}{path_and_query}");
    let forwarded = forwarded_account_headers(&headers);
    let method_name = method.as_str().to_owned();
    let response = tokio::task::spawn_blocking(move || {
        open_account_authority_request(&method_name, &url, &bearer, &forwarded, &body)
    })
    .await;
    let mut response = match response {
        Ok(Ok(response)) => response,
        Ok(Err(message)) => {
            return (StatusCode::BAD_GATEWAY, Json(json!({ "error": message }))).into_response()
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "account authority task failed" })),
            )
                .into_response()
        }
    };
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = response.content_type.take();
    let cache_control = response.cache_control.take();
    let stream = content_type
        .as_deref()
        .is_some_and(|value| value.starts_with("text/event-stream"));
    let body = if stream {
        let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(16);
        tokio::task::spawn_blocking(move || {
            let mut reader = response.reader;
            let mut buffer = vec![0u8; 8 * 1024];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        if sender
                            .blocking_send(Ok(Bytes::copy_from_slice(&buffer[..count])))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.blocking_send(Err(error));
                        break;
                    }
                }
            }
        });
        Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(receiver))
    } else {
        match tokio::task::spawn_blocking(move || {
            let mut bytes = Vec::new();
            response
                .reader
                .take(8 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        })
        .await
        {
            Ok(Ok(bytes)) if bytes.len() <= 8 * 1024 * 1024 => Body::from(bytes),
            _ => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({ "error": "account authority returned an unreadable response" })),
                )
                    .into_response()
            }
        }
    };
    let mut builder = Response::builder().status(status);
    if let Some(value) = content_type.as_deref() {
        builder = builder.header("content-type", value);
    }
    if let Some(value) = cache_control.as_deref() {
        builder = builder.header("cache-control", value);
    }
    builder.body(body).unwrap_or_else(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "could not build account authority response" })),
        )
            .into_response()
    })
}

async fn proxy_account_gaugeapp(
    State(wb): State<SharedWorkbench>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_else(|| uri.path().to_owned());
    proxy_account_authority(&wb, method, path, headers, body).await
}

/// Mint a fresh Hub entitlement through the desktop's sealed account session.
/// Hosted compositions mint in their browser-authenticated Hub plane and pass
/// the same public envelope to the Home; this is the native/Desktop crossing.
pub async fn mint_managed_entitlement(
    wb: &SharedWorkbench,
    tenant: &str,
    publisher_key: &str,
) -> Result<crate::managed_entitlement::Entitlement, (StatusCode, String)> {
    let Some(hub) = hub_base() else {
        return Err((
            StatusCode::CONFLICT,
            "account sign-in is not configured for this runtime".to_owned(),
        ));
    };
    let Some(bearer) = hub_session_token(wb) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "sign in to GaugeWright to use managed deployment funding".to_owned(),
        ));
    };
    let url = hub_tenant_url(&hub, tenant, &["managed-inference", "entitlement"])
        .map_err(|message| (StatusCode::INTERNAL_SERVER_ERROR, message))?;
    let body = json!({ "publisher_key": publisher_key }).to_string();
    let result = tokio::task::spawn_blocking(move || {
        HttpClient::new().post_json_headers(
            &url,
            &[("authorization".to_owned(), format!("Bearer {bearer}"))],
            &body,
        )
    })
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "managed entitlement task panicked".to_owned(),
        )
    })?
    .map_err(|message| (StatusCode::BAD_GATEWAY, message))?;
    let status = StatusCode::from_u16(result.0).unwrap_or(StatusCode::BAD_GATEWAY);
    if !status.is_success() {
        let detail = serde_json::from_str::<Value>(&result.1)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "the Hub refused managed deployment funding".to_owned());
        return Err((status, detail));
    }
    serde_json::from_str(&result.1).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "the Hub returned a malformed managed entitlement".to_owned(),
        )
    })
}

/// Desktop proxy for the signed-in person's tenant switcher. It exposes only
/// the Hub's non-secret tenant projection; the sealed bearer stays local.
pub async fn get_signin_tenants(State(wb): State<SharedWorkbench>) -> Response {
    let Some(hub) = hub_base() else {
        return (
            StatusCode::CONFLICT,
            "account sign-in is not configured for this runtime",
        )
            .into_response();
    };
    let Some(bearer) = hub_session_token(&wb) else {
        return (StatusCode::UNAUTHORIZED, "sign in to read account tenants").into_response();
    };
    let fetched = tokio::task::spawn_blocking(move || {
        HttpClient::new().get_string_headers(
            &format!("{hub}/account/tenants"),
            &[("authorization".to_owned(), format!("Bearer {bearer}"))],
        )
    })
    .await;
    let Ok(Ok((status, body))) = fetched else {
        return (StatusCode::BAD_GATEWAY, "the Hub was unreachable").into_response();
    };
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    match serde_json::from_str::<Value>(&body) {
        Ok(value) => (status, Json(value)).into_response(),
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            "the Hub returned malformed tenants",
        )
            .into_response(),
    }
}

/// One in-flight sign-in: the verifier stays here — in this process — until the
/// deep-linked code comes back. Single slot: starting again replaces it.
struct PendingSignin {
    verifier: String,
    started: Instant,
}

fn pending() -> MutexGuard<'static, Option<PendingSignin>> {
    static PENDING: OnceLock<Mutex<Option<PendingSignin>>> = OnceLock::new();
    PENDING
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A fresh 32-byte verifier, base64url without padding (43 chars — the shape
/// the Hub's `native_return_uri` guard requires of its S256 challenge).
fn new_verifier() -> String {
    let mut bytes = [0u8; 32];
    // getrandom failure means the OS RNG is broken; refuse to sign in rather
    // than fall back to anything predictable.
    getrandom::getrandom(&mut bytes).expect("OS randomness unavailable");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// S256: base64url(SHA-256(verifier)) — the challenge pinned to the login state.
fn challenge_for(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The Hub login URL that begins a native handoff bound to `challenge`. The
/// return is the `gaugewright://` scheme unless a dev web return (ADR 0140)
/// asks the Hub to hand the code back to a loopback browser origin instead.
fn login_url(hub: &str, challenge: &str, web_return: Option<&str>) -> String {
    // The challenge alphabet is base64url (alphanumeric, `-`, `_`) — URL-safe by
    // construction; only the return URI needs encoding.
    let return_to = match web_return {
        Some(uri) => encode_return(uri),
        None => encode_return(NATIVE_RETURN),
    };
    format!("{hub}/auth/login?return_to={return_to}&handoff_challenge={challenge}")
}

/// Percent-encode a return URI for a query value. The admitted return alphabets
/// (the fixed native scheme and the loopback web grammar) leave only `:` and `/`
/// as reserved characters.
fn encode_return(uri: &str) -> String {
    uri.replace(':', "%3A").replace('/', "%2F")
}

/// The dev web return (ADR 0140), validated: `GAUGEDESK_ACCOUNT_HUB_WEB_RETURN`
/// names the loopback browser URL the Hub should hand the one-time code back to,
/// for a browser dev client that cannot receive a `gaugewright://` deep link.
/// The Hub admits it only when its own `GAUGEDESK_DEV_WEB_RETURN` gate is set.
fn web_return_from_env() -> Result<Option<String>, &'static str> {
    validate_web_return(gaugedesk_env::var("ACCOUNT_HUB_WEB_RETURN"))
}

/// Pure half of [`web_return_from_env`]. A set-but-invalid value is an error —
/// fail closed rather than silently reverting to the native deep link the
/// operator just asked to avoid.
fn validate_web_return(raw: Option<String>) -> Result<Option<String>, &'static str> {
    let Some(raw) = raw else { return Ok(None) };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if crate::auth_oidc::loopback_web_return(trimmed) {
        Ok(Some(trimmed.to_string()))
    } else {
        Err("GAUGEDESK_ACCOUNT_HUB_WEB_RETURN must be a loopback URL: \
             http://localhost[:port][/path], http://127.0.0.1[:port][/path], \
             or the fabric's https://<name>.localhost[:port][/path]")
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

/// The stored session: sealed token + non-secret projection fields. A cleared
/// record (empty `sealed`) is the signed-out tombstone — logout stays a plain
/// append (`INV-6`), never a delete.
#[derive(Clone, Debug, serde::Serialize, Deserialize)]
struct SessionRecord {
    id: String,
    sealed: String,
    person: String,
    /// Absolute expiry of the opaque Hub account session.
    expires: i64,
    /// Next time the Hub asks this native client to renew the server-held
    /// provider grant. Zero means the session has no renewable provider grant.
    #[serde(default)]
    refresh_after: i64,
    /// The Hub-minted trusted-device id this session is bound to (LOGIN-3),
    /// projected for the local account surface. Refresh authorization comes
    /// from the Hub's stored session-to-device binding, never this field.
    #[serde(default)]
    device: String,
    /// Human display projected by the Hub from the verified assertion. The
    /// account id stays the identity (`person`) and external subjects never
    /// become local identity or display truth. Defaulted for older records.
    #[serde(default)]
    label: String,
}

fn write_session(wb: &SharedWorkbench, record: &SessionRecord) -> Result<(), String> {
    wb.lock_unpoisoned()
        .write_account_record_in(ACCOUNT_SCOPE, RECORD_KIND, RECORD_ID, record)
        .map_err(|error| format!("could not store the Hub session: {error:?}"))
}

fn latest_session(wb: &SharedWorkbench) -> Option<SessionRecord> {
    let workbench = wb.lock_unpoisoned();
    let rows = workbench
        .store_ref()
        .records(ACCOUNT_SCOPE, RECORD_KIND)
        .ok()?;
    let last = rows.last()?;
    let record: SessionRecord = serde_json::from_str(last).ok()?;
    if record.sealed.is_empty() {
        return None;
    }
    Some(record)
}

/// Who is signed in on this computer, as far as its Home needs to know: the
/// account, a digest identifying the Hub session that proves it (never the
/// bearer), and when that session ends. For claiming this computer's Home
/// (DR-0187) and for anything else bound to one sign-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HubStanding {
    pub person: String,
    pub session: String,
    pub expires_ms: i64,
}

pub(crate) fn hub_standing(wb: &SharedWorkbench) -> Option<HubStanding> {
    let record = latest_session(wb)?;
    let token = wb.lock_unpoisoned().unseal_account_secret(&record.sealed)?;
    Some(HubStanding {
        person: record.person,
        session: crate::account_session::session_id(&token),
        expires_ms: record.expires,
    })
}

/// The current account bearer, unsealed — for core callers that present the
/// person to the Hub (projections, opaque routes). Never crosses HTTP.
pub fn hub_session_token(wb: &SharedWorkbench) -> Option<String> {
    let record = latest_session(wb)?;
    let workbench = wb.lock_unpoisoned();
    workbench.unseal_account_secret(&record.sealed)
}

/// Seed a stored Hub session, so a test in another module can start from a
/// computer that is already signed in. The record type is private and stays
/// private; what a caller needs is the state, not the record.
#[cfg(test)]
pub(crate) fn store_session_for_test(wb: &SharedWorkbench) {
    store_session_as_for_test(wb, "account-root");
}

/// [`store_session_for_test`] for a named account: a second person signing in
/// on the same computer.
#[cfg(test)]
pub(crate) fn store_session_as_for_test(wb: &SharedWorkbench, person: &str) {
    store_session(
        wb,
        "opaque-account-session",
        person,
        "alice@example.test",
        4_102_444_800_000,
        4_102_441_800_000,
        "native-abc123",
    )
    .expect("store session");
}

/// The actor bound to the sealed Hub session. Project-owned organization model
/// selection uses this beside the unsealed bearer so a local loopback identity
/// cannot be mistaken for the remote organization member it is acting for.
pub fn hub_session_actor(wb: &SharedWorkbench) -> Option<String> {
    latest_session(wb).map(|record| record.person)
}

fn store_session(
    wb: &SharedWorkbench,
    account_session: &str,
    person: &str,
    label: &str,
    expires: i64,
    refresh_after: i64,
    device: &str,
) -> Result<SessionRecord, String> {
    let sealed = {
        let workbench = wb.lock_unpoisoned();
        workbench
            .seal_account_secret(account_session)
            .ok_or_else(|| "could not seal the Hub session".to_string())?
    };
    let record = SessionRecord {
        id: RECORD_ID.to_string(),
        sealed,
        person: person.to_string(),
        expires,
        refresh_after,
        device: device.to_string(),
        label: label.to_string(),
    };
    write_session(wb, &record)?;
    Ok(record)
}

/// Redeem the deep-linked single-use code at the Hub. Blocking (ureq) — run off
/// the async runtime.
struct RedeemedHubSession {
    account_session: String,
    person: String,
    label: String,
    expires: i64,
    refresh_after: i64,
    device: String,
}

fn redeem_at_hub(hub: &str, code: &str, verifier: &str) -> Result<RedeemedHubSession, String> {
    let http = HttpClient::new();
    let body = json!({
        "code": code,
        "verifier": verifier,
        "device_label": device_label(),
    })
    .to_string();
    // The exchange is a POST, and a hub composition may require the
    // idempotency-key spine on every mutation (the open composition does).
    // Key it by the single-use code: a retry of the same redemption is the
    // same command, and a different code is a different one.
    let idempotency = [(
        "idempotency-key".to_string(),
        format!("hub-exchange:{code}"),
    )];
    let (status, response) = http
        .post_json_headers(&format!("{hub}/auth/mobile/exchange"), &idempotency, &body)
        .map_err(|error| format!("the Hub was unreachable: {error}"))?;
    if status != 200 {
        return Err(format!("the Hub refused the handoff ({status})"));
    }
    let parsed: Value =
        serde_json::from_str(&response).map_err(|_| "malformed Hub response".to_string())?;
    let account_session = parsed
        .get("account_session")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "malformed Hub response".to_string())?;
    let person = parsed
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|person| !person.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "malformed Hub response".to_string())?;
    let label = parsed
        .get("label")
        .and_then(Value::as_str)
        .filter(|label| !label.trim().is_empty())
        .unwrap_or(&person)
        .to_string();
    let expires = parsed
        .get("expires_at_ms")
        .and_then(Value::as_i64)
        .filter(|expires| *expires > 0)
        .ok_or_else(|| "malformed Hub response".to_string())?;
    let refresh_after = parsed
        .get("refresh_after_ms")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let device = parsed
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok(RedeemedHubSession {
        account_session,
        person,
        label,
        expires,
        refresh_after,
        device,
    })
}

/// How this desktop names itself in the person's trusted-devices registry.
fn device_label() -> String {
    match std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.trim().is_empty())
    {
        Some(host) => format!("GaugeDesk on {host}"),
        None => "GaugeDesk desktop".to_string(),
    }
}

/// Refresh a still-valid session at the Hub. Blocking — run off the async runtime.
fn refresh_at_hub(hub: &str, bearer: &str) -> Result<i64, String> {
    let http = HttpClient::new();
    let headers = [("authorization".to_string(), format!("Bearer {bearer}"))];
    let (status, response) = http
        .post_json_headers(&format!("{hub}/auth/mobile/refresh"), &headers, "{}")
        .map_err(|error| format!("the Hub was unreachable: {error}"))?;
    if status != 200 {
        return Err(format!("the Hub refused the refresh ({status})"));
    }
    let parsed: Value =
        serde_json::from_str(&response).map_err(|_| "malformed Hub response".to_string())?;
    if parsed.get("refreshed").and_then(Value::as_bool) != Some(true) {
        return Err("malformed Hub response".to_string());
    }
    parsed
        .get("refresh_after_ms")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .ok_or_else(|| "malformed Hub response".to_string())
}

/// Tell the Hub which root signs this account's directory record, so a client
/// with no root of its own can find it (DESK-5f, ADR 0133 §2).
///
/// This is the one hub *write* the desktop performs, and it is deliberately
/// narrow. Only a public key crosses: the root's private half never leaves this
/// process, and `library_sync_routes` stays out of `hub_routes()` precisely so a
/// shared Hub never holds one. A signed-out desktop announces nothing, because
/// there is no session to announce under.
///
/// Returns whether the announcement landed. Callers treat `false` as reduced
/// discoverability rather than failure — the record it points at is already
/// published, and the next publish tries again.
pub async fn announce_directory_root(wb: &SharedWorkbench) -> bool {
    let Some(hub) = hub_base() else {
        return false;
    };
    let Some(bearer) = hub_session_token(wb) else {
        return false;
    };
    let root = {
        let workbench = wb.lock_unpoisoned();
        workbench.library_sync_root()
    };
    if root.is_empty() {
        return false;
    }
    let origin = crate::directory_sync::directory_url_from_env();
    tokio::task::spawn_blocking(move || {
        let http = HttpClient::new();
        let headers = vec![("authorization".to_string(), format!("Bearer {bearer}"))];
        let body = json!({ "root_pubkey": root, "origin": origin }).to_string();
        matches!(
            http.post_json_headers(&format!("{hub}/account/directory"), &headers, &body),
            Ok((200..=299, _))
        )
    })
    .await
    .unwrap_or(false)
}

/// Non-secret status projection, shared by the status route and the
/// post-refresh re-read.
fn status_json(record: Option<&SessionRecord>, available: bool) -> Value {
    match record {
        Some(record) => json!({
            "available": available,
            "linked": true,
            "person": record.person,
            // Records sealed before the label existed project the subject, so
            // the surfaces always have something to show.
            "label": if record.label.is_empty() { &record.person } else { &record.label },
            "expires": record.expires,
            "expired": record.expires <= now_ms(),
            "refresh_after": record.refresh_after,
            "device": record.device,
        }),
        None => json!({ "available": available, "linked": false }),
    }
}

/// `POST /account/hub-session/start` — mint the verifier, hold it here, and
/// return the Hub login URL for the client to open in the system browser.
pub async fn post_signin_start() -> impl IntoResponse {
    let Some(hub) = hub_base() else {
        return (
            StatusCode::CONFLICT,
            "account sign-in is not configured for this runtime",
        )
            .into_response();
    };
    let web_return = match web_return_from_env() {
        Ok(value) => value,
        Err(message) => return (StatusCode::CONFLICT, message).into_response(),
    };
    let verifier = new_verifier();
    let challenge = challenge_for(&verifier);
    *pending() = Some(PendingSignin {
        verifier,
        started: Instant::now(),
    });
    Json(json!({
        "url": login_url(&hub, &challenge, web_return.as_deref()),
        "return": web_return.as_deref().unwrap_or(NATIVE_RETURN),
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct SigninCallback {
    code: String,
}

/// `POST /account/hub-session/callback` — the deep-linked one-time code
/// arrives from the shell/webview; redeem it with the held verifier and seal
/// the session. The token itself never rides this route's request or response.
pub async fn post_signin_callback(
    State(wb): State<SharedWorkbench>,
    Json(request): Json<SigninCallback>,
) -> impl IntoResponse {
    let Some(hub) = hub_base() else {
        return (
            StatusCode::CONFLICT,
            "account sign-in is not configured for this runtime",
        )
            .into_response();
    };
    if request.code.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "missing handoff code").into_response();
    }
    // Single-use take, like the Hub's own state store: a second callback (or a
    // replay) finds nothing.
    let taken = pending().take();
    let Some(taken) = taken else {
        tracing::warn!("hub-session callback refused: no sign-in was started on this device");
        return (
            StatusCode::BAD_REQUEST,
            "no sign-in was started on this device",
        )
            .into_response();
    };
    if taken.started.elapsed() > PENDING_TTL {
        tracing::warn!("hub-session callback refused: the sign-in attempt expired");
        return (
            StatusCode::BAD_REQUEST,
            "the sign-in attempt expired; start again",
        )
            .into_response();
    }
    let code = request.code.trim().to_string();
    let redeemed =
        tokio::task::spawn_blocking(move || redeem_at_hub(&hub, &code, &taken.verifier)).await;
    let session = match redeemed {
        Ok(Ok(session)) => session,
        Ok(Err(message)) => {
            tracing::warn!("hub-session exchange failed: {message}");
            return (StatusCode::BAD_GATEWAY, message).into_response();
        }
        Err(_) => {
            tracing::warn!("hub-session exchange task panicked");
            return (StatusCode::INTERNAL_SERVER_ERROR, "sign-in task panicked").into_response();
        }
    };
    match store_session(
        &wb,
        &session.account_session,
        &session.person,
        &session.label,
        session.expires,
        session.refresh_after,
        &session.device,
    ) {
        Ok(record) => {
            // Signing in on a computer makes it that person's first Home
            // (DR-0183). Publication is a facility and reachability follows it,
            // so this is what lets a leg park at all; the registration itself
            // happens where the locator exists, in `first_home::reconcile`.
            //
            // Reported and not propagated: a person who has just signed in
            // successfully should not be told sign-in failed because the
            // machine could not also become a Home.
            match crate::first_home::attach_library_sync(&wb) {
                Ok(true) => eprintln!(
                    "[first-home] library sync attached; this computer is now publishing its reachability"
                ),
                Ok(false) => {}
                Err(error) => tracing::warn!("first Home not attached: {error}"),
            }
            // And the account that makes a computer its Home owns it
            // (DR-0187). Reported, not propagated, for the same reason.
            if let Err(error) = crate::home_owner::claim_if_never_claimed(&wb) {
                tracing::warn!("Home owner not claimed: {error}");
            }
            Json(status_json(Some(&record), true)).into_response()
        }
        Err(message) => {
            tracing::warn!("hub-session seal failed: {message}");
            (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
        }
    }
}

/// `GET /account/hub-session` — non-secret status. A session inside the
/// provider-renewal window is refreshed here, proactively: the account surfaces
/// poll this route, so an open desktop keeps the Hub-held provider grant current
/// without ever receiving an external token.
pub async fn get_signin_status(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let available = hub_base().is_some();
    let Some(record) = latest_session(&wb) else {
        return Json(status_json(None, available)).into_response();
    };
    let current_ms = now_ms();
    let due = record.refresh_after > 0
        && record.refresh_after <= current_ms.saturating_add(REFRESH_SKEW_MS);
    if available && due {
        if let (Some(hub), Some(bearer)) = (hub_base(), hub_session_token(&wb)) {
            let refreshed =
                tokio::task::spawn_blocking(move || refresh_at_hub(&hub, &bearer)).await;
            if let Ok(Ok(refresh_after)) = refreshed {
                let mut updated = record.clone();
                updated.refresh_after = refresh_after;
                if write_session(&wb, &updated).is_ok() {
                    return Json(status_json(Some(&updated), available)).into_response();
                }
            }
            // A failed refresh is not an error surface: the projection below
            // simply shows the real (soon-to-expire) state.
        }
    }
    Json(status_json(Some(&record), available)).into_response()
}

/// Fetch one Hub account projection with the sealed bearer. Blocking — run off
/// the async runtime. Returns the parsed JSON body, or `null` on any failure
/// (reach is a read-only convenience view; a partial Hub answer is not an
/// error surface).
fn fetch_hub_projection(http: &HttpClient, hub: &str, path: &str, bearer: &str) -> Value {
    let headers = [("authorization".to_string(), format!("Bearer {bearer}"))];
    match http.get_string_headers(&format!("{hub}{path}"), &headers) {
        Ok((200, body)) => serde_json::from_str(&body).unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

/// `GET /account/hub-session/reach` — what the signed-in account can reach
/// (the ADR 0114 composition): the person, their registered Homes, and the
/// opaque project-to-Home routes, fetched from the Hub with the sealed bearer.
/// The bearer never rides this route; reach carries only what the Hub itself
/// projects as non-secret. 409 unconfigured, 401 signed out.
pub async fn get_signin_reach(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let Some(hub) = hub_base() else {
        return (
            StatusCode::CONFLICT,
            "account sign-in is not configured for this runtime",
        )
            .into_response();
    };
    let Some(record) = latest_session(&wb) else {
        return (StatusCode::UNAUTHORIZED, "sign in to read account reach").into_response();
    };
    let Some(bearer) = hub_session_token(&wb) else {
        return (StatusCode::UNAUTHORIZED, "sign in to read account reach").into_response();
    };
    let fetched = tokio::task::spawn_blocking(move || {
        let http = HttpClient::new();
        let homes = fetch_hub_projection(&http, &hub, "/account/homes", &bearer);
        let routes = fetch_hub_projection(&http, &hub, "/account/home-routes", &bearer);
        (homes, routes)
    })
    .await;
    let Ok((homes, routes)) = fetched else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "reach task panicked").into_response();
    };
    Json(json!({
        "person": record.person,
        "device": record.device,
        "homes": homes,
        "routes": routes,
    }))
    .into_response()
}

/// `POST /account/hub-session/logout` — append the signed-out tombstone.
/// Idempotent: signing out while signed out is already the desired state.
pub async fn post_signin_logout(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    // The UI's Home session ends with the sign-in behind it (DR-0188).
    crate::desktop_session::revoke(&wb);
    if latest_session(&wb).is_none() {
        return StatusCode::NO_CONTENT.into_response();
    }
    let cleared = SessionRecord {
        id: RECORD_ID.to_string(),
        sealed: String::new(),
        person: String::new(),
        expires: 0,
        refresh_after: 0,
        device: String::new(),
        label: String::new(),
    };
    match write_session(&wb, &cleared) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(message) => (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_and_challenge_have_the_handoff_shape() {
        let verifier = new_verifier();
        assert_eq!(verifier.len(), 43, "32 bytes base64url-unpadded");
        let challenge = challenge_for(&verifier);
        assert_eq!(challenge.len(), 43, "SHA-256 base64url-unpadded");
        for value in [&verifier, &challenge] {
            assert!(
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
                "base64url alphabet only: {value}"
            );
        }
        assert_ne!(new_verifier(), new_verifier(), "verifiers are random");
    }

    #[test]
    fn challenge_matches_the_rfc7636_s256_vector() {
        // RFC 7636 appendix B: the canonical verifier/challenge pair.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            challenge_for(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn login_url_pins_the_native_return_and_carries_the_challenge() {
        let url = login_url("https://auth.example.test", "abc-_123", None);
        assert_eq!(
            url,
            "https://auth.example.test/auth/login?return_to=gaugewright%3A%2F%2Fauth%2Fcallback&handoff_challenge=abc-_123"
        );
    }

    #[test]
    fn login_url_carries_the_dev_web_return_when_asked() {
        let url = login_url(
            "https://auth.example.test",
            "abc-_123",
            Some("http://localhost:5176/auth/native-return"),
        );
        assert_eq!(
            url,
            "https://auth.example.test/auth/login?return_to=http%3A%2F%2Flocalhost%3A5176%2Fauth%2Fnative-return&handoff_challenge=abc-_123"
        );
    }

    #[test]
    fn web_return_validation_is_fail_closed() {
        // Unset / blank: the native deep link stays the return.
        assert_eq!(validate_web_return(None), Ok(None));
        assert_eq!(validate_web_return(Some("  ".to_string())), Ok(None));
        // A loopback URL is admitted (trimmed).
        assert_eq!(
            validate_web_return(Some(" http://127.0.0.1:5176/return ".to_string())),
            Ok(Some("http://127.0.0.1:5176/return".to_string()))
        );
        // Anything else errors rather than silently reverting to the deep link.
        assert!(validate_web_return(Some("https://evil.example/".to_string())).is_err());
        assert!(validate_web_return(Some("gaugewright://auth/callback".to_string())).is_err());
        // The fabric's named loopback origin is admitted (ADR 0140 amendment).
        assert_eq!(
            validate_web_return(Some("https://desk.gw.localhost:7443/".to_string())),
            Ok(Some("https://desk.gw.localhost:7443/".to_string()))
        );
    }

    #[test]
    fn session_seals_projects_and_clears_without_leaking_the_token() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let token = "opaque-account-session";

        let record = store_session(
            &wb,
            token,
            "account-root",
            "alice@example.test",
            4_102_444_800_000,
            4_102_441_800_000,
            "native-abc123",
        )
        .unwrap();
        assert_eq!(record.person, "account-root");
        assert_eq!(record.expires, 4_102_444_800_000);
        assert_eq!(record.refresh_after, 4_102_441_800_000);
        assert_eq!(record.device, "native-abc123");
        assert!(
            !record.sealed.contains(token),
            "the stored form is sealed, not plaintext"
        );
        assert_eq!(hub_session_token(&wb).as_deref(), Some(token));

        let projection = status_json(Some(&record), true);
        assert_eq!(projection["linked"], true);
        assert_eq!(projection["person"], "account-root");
        assert_eq!(projection["label"], "alice@example.test");
        assert_eq!(projection["expired"], false);
        assert_eq!(projection["device"], "native-abc123");
        assert!(
            !projection.to_string().contains("sealed"),
            "status never carries token material"
        );

        // Logout tombstones; a second logout finds nothing and stays 204-shaped.
        let cleared = SessionRecord {
            id: RECORD_ID.to_string(),
            sealed: String::new(),
            person: String::new(),
            expires: 0,
            refresh_after: 0,
            device: String::new(),
            label: String::new(),
        };
        write_session(&wb, &cleared).unwrap();
        assert!(latest_session(&wb).is_none());
        assert!(hub_session_token(&wb).is_none());
        assert_eq!(
            status_json(None, true),
            json!({ "available": true, "linked": false })
        );
    }

    #[test]
    fn an_expired_projection_says_so() {
        let record = SessionRecord {
            id: RECORD_ID.to_string(),
            sealed: "sealed".to_string(),
            person: "alice".to_string(),
            expires: 1,
            refresh_after: 0,
            device: String::new(),
            label: "alice@example.test".to_string(),
        };
        let projection = status_json(Some(&record), true);
        assert_eq!(projection["linked"], true);
        assert_eq!(projection["expired"], true);
    }

    #[test]
    fn account_proxy_forwards_only_product_protocol_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("idempotency-key", "attempt-1".parse().unwrap());
        headers.insert("x-gaugedesk-client-version", "0.4.9".parse().unwrap());
        headers.insert("authorization", "Bearer browser-secret".parse().unwrap());
        headers.insert("cookie", "session=browser-secret".parse().unwrap());
        headers.insert("origin", "https://untrusted.example".parse().unwrap());
        headers.insert("x-forwarded-host", "untrusted.example".parse().unwrap());

        let forwarded = forwarded_account_headers(&headers);
        assert_eq!(
            forwarded,
            vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("idempotency-key".to_string(), "attempt-1".to_string()),
                (
                    "x-gaugedesk-client-version".to_string(),
                    "0.4.9".to_string()
                ),
            ]
        );
        assert!(forwarded.iter().all(|(name, _)| !matches!(
            name.as_str(),
            "authorization" | "cookie" | "origin" | "x-forwarded-host"
        )));
    }
}
