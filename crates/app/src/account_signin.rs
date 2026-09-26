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
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{OriginalUri, Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_stream::StreamExt;

use crate::account::ACCOUNT_SCOPE;
use crate::net_http::HttpClient;
use crate::{LockUnpoisoned, SharedWorkbench};

/// Marks the co-resident desktop composition. The hosted account authority
/// never installs this marker; it authenticates GaugeApp requests from its own
/// HttpOnly cookie or explicit bearer instead.
#[derive(Clone, Copy, Debug)]
pub struct NativeAccountPlane;

/// The local window's operator listener, distinct from a hosted Home or Hub.
#[derive(Clone, Copy, Debug)]
pub struct DesktopOperatorPlane;

/// Exact native aliases for the hosted Account Settings GaugeApp. The browser
/// calls the ordinary product paths; this co-resident boundary attaches the
/// sealed account session and forwards them to the independently deployed
/// account authority. No catch-all is intentional: adding a hosted operation
/// requires adding its native custody boundary deliberately too.
pub fn gaugeapp_proxy_routes() -> Router<SharedWorkbench> {
    Router::new()
        .route(
            "/account/dictation/transcribe",
            post(proxy_account_gaugeapp),
        )
        .route(
            "/account/dictation/entitlement",
            post(proxy_account_gaugeapp),
        )
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

/// Legacy single-session record, read until the first additional sign-in or
/// selection migrates it. Never reinterpret its fixed id as an account id.
const RECORD_KIND: &str = "hub-session";
const RECORD_ID: &str = "session";
/// One sealed session per person. A tombstone clears only that person's local
/// session; selecting another account cannot overwrite its credential.
const ACCOUNT_SESSION_KIND: &str = "hub-session-account";
/// The selected account is separate from session custody. Empty means that no
/// retained account is active, including after signing out of the selected one.
const SELECTED_KIND: &str = "hub-session-selected";
const SELECTED_ID: &str = "selected";
const LOCAL_SELECTION: &str = "@local";
const DIRECTORY_ROOT_PIN_KIND: &str = "hub_directory_root_pin";
/// Latest-wins record family holding the one in-flight sign-in's sealed PKCE
/// verifier, so it survives the restart that the browser leg invites (DR-0198).
const RECORD_KIND_PENDING: &str = "hub-signin-pending";
const PENDING_RECORD_ID: &str = "pending";
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

struct RelayCarrierReader {
    inner: Box<dyn std::io::Read + Send + Sync + 'static>,
    carrier: tokio::task::AbortHandle,
}

impl std::io::Read for RelayCarrierReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl Drop for RelayCarrierReader {
    fn drop(&mut self) {
        self.carrier.abort();
    }
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
    let revision = selected_revision(wb);
    let Some(hub) = hub_base() else {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "account sign-in is not configured for this runtime" })),
        )
            .into_response();
    };
    let Some(record) = latest_session(wb).filter(|record| record.expires > now_ms()) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "sign in to access Account Settings" })),
        )
            .into_response();
    };
    let fence = SelectionFence::new(wb, record.person, revision);
    let Some(bearer) = hub_session_token(wb).filter(|_| fence.is_current()) else {
        return StatusCode::CONFLICT.into_response();
    };
    let url = format!("{hub}{path_and_query}");
    let forwarded = forwarded_account_headers(&headers);
    let method_name = method.as_str().to_owned();
    let dispatch_fence = fence.clone();
    let response = tokio::task::spawn_blocking(move || {
        if !dispatch_fence.is_current() {
            return Err("account selection changed before dispatch".to_string());
        }
        open_account_authority_request(&method_name, &url, &bearer, &forwarded, &body)
    })
    .await;
    if !fence.is_current() {
        return StatusCode::CONFLICT.into_response();
    }
    let response = match response {
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
    finish_proxy_response(response, false, Some(fence)).await
}

#[derive(Clone)]
struct SelectionFence {
    wb: SharedWorkbench,
    person: String,
    revision: usize,
}

impl SelectionFence {
    fn new(wb: &SharedWorkbench, person: String, revision: usize) -> Self {
        Self {
            wb: wb.clone(),
            person,
            revision,
        }
    }

    fn is_current(&self) -> bool {
        selected_revision(&self.wb) == self.revision
            && live_hub_session_actor(&self.wb).as_deref() == Some(self.person.as_str())
    }
}

async fn finish_proxy_response(
    mut response: AccountAuthorityResponse,
    stream_all: bool,
    fence: Option<SelectionFence>,
) -> Response {
    if fence.as_ref().is_some_and(|fence| !fence.is_current()) {
        return StatusCode::CONFLICT.into_response();
    }
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = response.content_type.take();
    let cache_control = response.cache_control.take();
    let stream = stream_all
        || content_type
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
        let stream = tokio_stream::wrappers::ReceiverStream::new(receiver)
            .take_while(move |_| fence.as_ref().is_none_or(SelectionFence::is_current));
        Body::from_stream(stream)
    } else {
        let bytes = match tokio::task::spawn_blocking(move || {
            let mut bytes = Vec::new();
            response
                .reader
                .take(8 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        })
        .await
        {
            Ok(Ok(bytes)) if bytes.len() <= 8 * 1024 * 1024 => bytes,
            _ => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({ "error": "account authority returned an unreadable response" })),
                )
                    .into_response()
            }
        };
        if fence.as_ref().is_some_and(|fence| !fence.is_current()) {
            return StatusCode::CONFLICT.into_response();
        }
        Body::from(bytes)
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

#[derive(Deserialize)]
pub struct HomeProxyPath {
    home: String,
    path: String,
}

/// A co-resident desktop's selected account reaches one of its admitted
/// Homes through this local broker. The webview names only a Home id and work
/// path. The broker resolves the endpoint from the selected account's Hub
/// projection and presents its sealed bearer. The webview keeps only the
/// Home's short-lived admission in memory, as the browser Home pool does; the
/// Home requires both that admission and the selected bearer on every work
/// request. The Hub bearer never reaches the UI.
pub async fn proxy_selected_home(
    State(wb): State<SharedWorkbench>,
    Path(route): Path<HomeProxyPath>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if crate::auth_oidc::web_account_mode() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let revision = selected_revision(&wb);
    let Some(hub) = hub_base() else {
        return (StatusCode::CONFLICT, "account sign-in is not configured").into_response();
    };
    let Some(record) = latest_session(&wb).filter(|record| record.expires > now_ms()) else {
        return (StatusCode::UNAUTHORIZED, "sign in to reach a Home").into_response();
    };
    let Some(bearer) = hub_session_token(&wb) else {
        return (StatusCode::UNAUTHORIZED, "sign in to reach a Home").into_response();
    };
    let raw_path = uri.path();
    let prefix = "/account/hub-session/home/";
    let Some((_, suffix)) = raw_path
        .strip_prefix(prefix)
        .and_then(|tail| tail.split_once('/'))
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if route.home.is_empty()
        || route.path.is_empty()
        || suffix.starts_with('/')
        || route.path.starts_with("auth/")
        || route.path.starts_with("account/hub-session/")
        || route
            .path
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let target_path = match uri.query() {
        Some(query) => format!("/{suffix}?{query}"),
        None => format!("/{suffix}"),
    };
    let mut forwarded = forwarded_account_headers(&headers);
    if let Some(admission) = headers
        .get(crate::home_admission::HOME_ADMISSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| crate::home_admission::HomeAdmissionToken::parse(value).is_some())
    {
        forwarded.push((
            crate::home_admission::HOME_ADMISSION_HEADER.to_string(),
            admission.to_string(),
        ));
    }
    let home = route.home;
    let method_name = method.as_str().to_owned();
    let request = HomeProxyRequest {
        hub,
        bearer,
        home,
        target_path,
        method: method_name,
        headers: forwarded,
        body,
        selected_person: record.person,
        selected_revision: revision,
    };
    let fence = SelectionFence {
        wb: wb.clone(),
        person: request.selected_person.clone(),
        revision,
    };
    let resolver_wb = wb.clone();
    let resolver_hub = request.hub.clone();
    let cache_hub = request.hub.clone();
    let resolver_bearer = request.bearer.clone();
    let resolver_home = request.home.clone();
    let resolver_person = request.selected_person.clone();
    let transport = tokio::task::spawn_blocking(move || {
        selected_home_transport(
            &resolver_wb,
            &resolver_hub,
            &resolver_bearer,
            &resolver_home,
            &resolver_person,
        )
    })
    .await;
    let transport = match transport {
        Ok(Ok(transport)) => transport,
        Ok(Err(error)) => {
            return (StatusCode::BAD_GATEWAY, Json(json!({ "error": error }))).into_response()
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if !fence.is_current() {
        return StatusCode::CONFLICT.into_response();
    }
    let (endpoint, carrier) = match transport {
        SelectedHomeTransport::Direct(endpoint) => (endpoint, None),
        SelectedHomeTransport::Relay(route) => {
            match gaugedesk_relay_transport::bind_client_loopback(route).await {
                Ok((address, carrier)) => {
                    (format!("http://{address}"), Some(carrier.abort_handle()))
                }
                Err(error) => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(json!({ "error": format!("could not open Home relay: {error}") })),
                    )
                        .into_response()
                }
            }
        }
    };
    let result =
        tokio::task::spawn_blocking(move || open_selected_home_request_at(&wb, request, &endpoint))
            .await;
    if !fence.is_current() {
        if let Some(carrier) = carrier {
            carrier.abort();
        }
        return StatusCode::CONFLICT.into_response();
    }
    match result {
        Ok(Ok(mut response)) => {
            if let Some(carrier) = carrier {
                response.reader = Box::new(RelayCarrierReader {
                    inner: response.reader,
                    carrier,
                });
            }
            finish_proxy_response(response, true, Some(fence)).await
        }
        Ok(Err(message)) => {
            let stale_relay =
                carrier.is_some() && message.starts_with("account authority transport:");
            let message = if stale_relay {
                invalidate_signed_route_cache(&fence.wb, &cache_hub, &fence.person);
                format!("stale Home relay route: {message}")
            } else {
                message
            };
            if let Some(carrier) = carrier {
                carrier.abort();
            }
            (StatusCode::BAD_GATEWAY, Json(json!({ "error": message }))).into_response()
        }
        Err(_) => {
            if let Some(carrier) = carrier {
                carrier.abort();
            }
            (StatusCode::INTERNAL_SERVER_ERROR, "Home broker task failed").into_response()
        }
    }
}

struct HomeProxyRequest {
    hub: String,
    bearer: String,
    home: String,
    target_path: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Bytes,
    selected_person: String,
    selected_revision: usize,
}

#[cfg(test)]
fn open_selected_home_request(
    wb: &SharedWorkbench,
    request: HomeProxyRequest,
) -> Result<AccountAuthorityResponse, String> {
    let endpoint = selected_home_endpoint(&request.hub, &request.bearer, &request.home)?;
    open_selected_home_request_at(wb, request, &endpoint)
}

fn open_selected_home_request_at(
    wb: &SharedWorkbench,
    request: HomeProxyRequest,
    endpoint: &str,
) -> Result<AccountAuthorityResponse, String> {
    let target = url::Url::parse(&format!("{endpoint}{}", request.target_path))
        .map_err(|_| "the Home work path is invalid")?;
    let base = url::Url::parse(endpoint).map_err(|_| "the Home endpoint is invalid")?;
    if target.origin() != base.origin()
        || target.path().starts_with("/auth/")
        || target.path().starts_with("/account/hub-session/")
    {
        return Err("the path is not a Home work route".to_string());
    }
    // A switch or sign-out while discovery was in flight cannot dispatch this
    // command under the old principal after the new one opens.
    if selected_revision(wb) != request.selected_revision
        || hub_session_actor(wb).as_deref() != Some(request.selected_person.as_str())
    {
        return Err("account selection changed while opening the Home".to_string());
    }
    if target.path() == "/home/admissions" && request.method == "POST" {
        let admission = admit_selected_home(endpoint, &request.bearer, &request.home)?;
        let body = json!({ "home": request.home, "admission": admission }).to_string();
        return Ok(AccountAuthorityResponse {
            status: StatusCode::CREATED.as_u16(),
            content_type: Some("application/json".to_string()),
            cache_control: Some("no-store".to_string()),
            reader: Box::new(std::io::Cursor::new(body.into_bytes())),
        });
    }
    if !request.headers.iter().any(|(name, value)| {
        name == crate::home_admission::HOME_ADMISSION_HEADER
            && crate::home_admission::HomeAdmissionToken::parse(value).is_some()
    }) {
        return Err("present the selected Home admission".to_string());
    }
    open_account_authority_request(
        &request.method,
        target.as_str(),
        &request.bearer,
        &request.headers,
        &request.body,
    )
}

fn selected_revision(wb: &SharedWorkbench) -> usize {
    wb.lock_unpoisoned()
        .store_ref()
        .records(ACCOUNT_SCOPE, SELECTED_KIND)
        .map_or(0, |records| records.len())
}

fn selected_home_endpoint(hub: &str, bearer: &str, home: &str) -> Result<String, String> {
    let response =
        open_account_authority_request("GET", &format!("{hub}/account/homes"), bearer, &[], &[])?;
    let homes = small_json_response(response, "account Homes")?;
    let registered = homes
        .get("homes")
        .and_then(Value::as_array)
        .and_then(|homes| homes.iter().find(|entry| entry["id"] == home))
        .and_then(|entry| entry.get("endpoint"))
        .and_then(Value::as_str)
        .filter(|endpoint| !endpoint.is_empty());
    // A project invitation may admit this account to someone else's Home
    // without registering that Home in its own account-home list. The Hub's
    // project route is still only discovery; the target Home must admit the
    // bearer separately before any work request is served.
    let routed = if registered.is_none() {
        let response = open_account_authority_request(
            "GET",
            &format!("{hub}/account/home-routes"),
            bearer,
            &[],
            &[],
        )?;
        let routes = small_json_response(response, "account Home routes")?;
        let endpoints: std::collections::HashSet<&str> = routes
            .get("routes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|route| route["home_id"] == home)
            .filter_map(|route| route.get("endpoint").and_then(Value::as_str))
            .filter(|endpoint| !endpoint.is_empty())
            .collect();
        if endpoints.len() > 1 {
            return Err("the selected account has conflicting routes to that Home".to_string());
        }
        endpoints.into_iter().next().map(str::to_owned)
    } else {
        None
    };
    let endpoint = registered
        .or(routed.as_deref())
        .ok_or_else(|| "the selected account has no direct route to that Home".to_string())?;
    validated_home_endpoint(endpoint)
}

fn validated_home_endpoint(endpoint: &str) -> Result<String, String> {
    let endpoint = endpoint.trim_end_matches('/');
    let parsed = url::Url::parse(endpoint).map_err(|_| "the Home endpoint is invalid")?;
    if !crate::account_routes::secure_home_endpoint(endpoint)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("the Home endpoint is not a secure origin".to_string());
    }
    Ok(endpoint.to_string())
}

enum SelectedHomeTransport {
    Direct(String),
    Relay(gaugedesk_relay_transport::RelayRoute),
}

#[derive(PartialEq, Eq)]
enum SignedHomeTransport {
    Direct(String),
    Relay(crate::home::OpaqueRelayLocator),
}

fn selected_home_transport(
    wb: &SharedWorkbench,
    hub: &str,
    bearer: &str,
    home: &str,
    person: &str,
) -> Result<SelectedHomeTransport, String> {
    let signed = match selected_signed_routes(wb, hub, bearer, person) {
        Ok(routes) => {
            let mut selected = None;
            for route in routes
                .into_iter()
                .filter(|route| route.home_id.as_str() == home)
            {
                let candidate = if !route.endpoint.is_empty() {
                    SignedHomeTransport::Direct(validated_home_endpoint(&route.endpoint)?)
                } else if let Some(relay) = route.relay {
                    SignedHomeTransport::Relay(relay)
                } else {
                    continue;
                };
                if selected.as_ref().is_some_and(|prior| prior != &candidate) {
                    return Err("the signed account routes disagree about that Home".to_string());
                }
                selected = Some(candidate);
            }
            selected
        }
        Err(error) => {
            tracing::warn!("selected account's signed Home routes unavailable: {error}");
            None
        }
    };
    match signed {
        Some(SignedHomeTransport::Direct(endpoint)) => Ok(SelectedHomeTransport::Direct(endpoint)),
        Some(SignedHomeTransport::Relay(relay)) => {
            let fingerprint: [u8; 32] = hex::decode(&relay.home_fingerprint)
                .map_err(|_| "the signed Home certificate pin is invalid".to_string())?
                .try_into()
                .map_err(|_| "the signed Home certificate pin is invalid".to_string())?;
            let route = gaugedesk_relay_transport::RelayRoute {
                endpoint: relay.endpoint,
                handle: relay.handle,
                epoch: relay.route_epoch,
                proof: gaugedesk_relay_transport::RouteProof::from_base64url(&relay.proof)
                    .map_err(|error| format!("invalid signed relay proof: {error}"))?,
                previous_proof: None,
                home_fingerprint: fingerprint,
            };
            route.validate().map_err(|error| error.to_string())?;
            Ok(SelectedHomeTransport::Relay(route))
        }
        None => selected_home_endpoint(hub, bearer, home).map(SelectedHomeTransport::Direct),
    }
}

fn admit_selected_home(endpoint: &str, bearer: &str, home: &str) -> Result<String, String> {
    // This is a new command at the Home, not a replay of the browser's command
    // to the desktop broker. Give it its own key so the Home's command guard can
    // admit it without colliding with the broker's idempotency record.
    let headers = [(
        "idempotency-key".to_string(),
        format!("native-home-admission:{}", new_verifier()),
    )];
    let response = open_account_authority_request(
        "POST",
        &format!("{endpoint}/home/admissions"),
        bearer,
        &headers,
        &[],
    )?;
    let admitted = small_json_response(response, "Home admission")?;
    if admitted.get("home").and_then(Value::as_str) != Some(home) {
        return Err("the Home admitted a different identity".to_string());
    }
    admitted
        .get("admission")
        .and_then(Value::as_str)
        .filter(|admission| !admission.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "the Home returned no admission".to_string())
}

fn small_json_response(response: AccountAuthorityResponse, what: &str) -> Result<Value, String> {
    if !(200..300).contains(&response.status) {
        return Err(format!("{what} refused with HTTP {}", response.status));
    }
    let mut bytes = Vec::new();
    response
        .reader
        .take(256 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| format!("could not read {what}"))?;
    if bytes.len() > 256 * 1024 {
        return Err(format!("{what} is too large"));
    }
    serde_json::from_slice(&bytes).map_err(|_| format!("{what} is malformed"))
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

/// One in-flight sign-in, at rest in the account scope (DR-0198). The person
/// leaves this application to authenticate, so the verifier has to outlive the
/// process that minted it — an updater restart, a quit, or a crash during the
/// browser leg used to discard it silently and refuse the code that came back
/// as though no sign-in had ever been started.
///
/// The verifier is authentication material, so it is sealed exactly as the
/// bearer it will be exchanged for is (`SEC-4`), never written in clear.
/// Latest-wins and single-use: starting again replaces it, and redeeming
/// appends the cleared tombstone rather than deleting the row (`INV-6`).
#[derive(Clone, Debug, serde::Serialize, Deserialize)]
struct PendingRecord {
    id: String,
    /// The sealed PKCE verifier. Empty is the consumed tombstone.
    sealed: String,
    /// Wall clock, because this outlives the process an `Instant` is relative
    /// to. Only ever compared against [`PENDING_TTL`], and the Hub bounds the
    /// same exchange independently, so a clock step costs at worst one retry.
    started_ms: i64,
    /// Which entrance began it, for the projection and the logs. Not authority:
    /// the Hub decides what it honours.
    #[serde(default)]
    provider: String,
    #[serde(default)]
    selection_revision: usize,
}

fn write_pending(wb: &SharedWorkbench, record: &PendingRecord) -> Result<(), String> {
    wb.lock_unpoisoned()
        .write_account_record_in(
            ACCOUNT_SCOPE,
            RECORD_KIND_PENDING,
            PENDING_RECORD_ID,
            record,
        )
        .map_err(|error| format!("could not store the sign-in attempt: {error:?}"))
}

fn latest_pending(wb: &SharedWorkbench) -> Option<PendingRecord> {
    let workbench = wb.lock_unpoisoned();
    let rows = workbench
        .store_ref()
        .records(ACCOUNT_SCOPE, RECORD_KIND_PENDING)
        .ok()?;
    let record: PendingRecord = serde_json::from_str(rows.last()?).ok()?;
    if record.sealed.is_empty() {
        return None;
    }
    Some(record)
}

/// Why a stored sign-in could not be used, kept apart from "there was none" so
/// the person is told which of the two happened.
enum PendingOutcome {
    Ready(String, usize),
    Expired,
    None,
}

/// Single-use take: clear the record first, then unseal, so a second callback
/// or a replay finds the tombstone whatever happens next.
fn take_pending(wb: &SharedWorkbench) -> PendingOutcome {
    let Some(record) = latest_pending(wb) else {
        return PendingOutcome::None;
    };
    let cleared = PendingRecord {
        id: PENDING_RECORD_ID.to_string(),
        sealed: String::new(),
        started_ms: record.started_ms,
        provider: record.provider.clone(),
        selection_revision: record.selection_revision,
    };
    if let Err(error) = write_pending(wb, &cleared) {
        // Refuse rather than redeem what could be redeemed twice.
        tracing::warn!("could not consume the sign-in attempt: {error}");
        return PendingOutcome::None;
    }
    if now_ms().saturating_sub(record.started_ms) > PENDING_TTL.as_millis() as i64 {
        return PendingOutcome::Expired;
    }
    match wb.lock_unpoisoned().unseal_account_secret(&record.sealed) {
        Some(verifier) => PendingOutcome::Ready(verifier, record.selection_revision),
        // Sealed under a key this workbench no longer holds: the attempt is
        // unusable, and it is not the same fact as never having started one.
        None => PendingOutcome::Expired,
    }
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
fn login_url(
    hub: &str,
    challenge: &str,
    web_return: Option<&str>,
    provider: Option<&str>,
) -> String {
    // The challenge alphabet is base64url (alphanumeric, `-`, `_`) — URL-safe by
    // construction; only the return URI needs encoding.
    let return_to = match web_return {
        Some(uri) => encode_return(uri),
        None => encode_return(NATIVE_RETURN),
    };
    let mut url = format!("{hub}/auth/login?return_to={return_to}&handoff_challenge={challenge}");
    // Which entrance the person pressed (DR-0189 §1). The Hub decides whether it
    // offers that one; this only carries the choice across the handoff, so that
    // a desktop showing two buttons does not send both to the same provider.
    // Restricted to the slug alphabet so nothing here can add a query parameter.
    if let Some(provider) = provider.map(str::trim).filter(|slug| {
        !slug.is_empty() && slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    }) {
        url.push_str("&provider=");
        url.push_str(provider);
    }
    url
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

#[derive(Clone, Debug, serde::Serialize, Deserialize)]
struct SelectedRecord {
    id: String,
    person: String,
}

fn selected_person(wb: &SharedWorkbench) -> Option<String> {
    let workbench = wb.lock_unpoisoned();
    selected_person_in_store(workbench.store_ref())
}

pub(crate) fn selected_person_in_store(store: &gaugedesk_store::Store) -> Option<String> {
    let rows = store.records(ACCOUNT_SCOPE, SELECTED_KIND).ok()?;
    serde_json::from_str::<SelectedRecord>(rows.last()?)
        .ok()
        .map(|record| record.person)
}

fn write_selected(wb: &SharedWorkbench, person: &str) -> Result<(), String> {
    wb.lock_unpoisoned()
        .write_account_record_in(
            ACCOUNT_SCOPE,
            SELECTED_KIND,
            SELECTED_ID,
            &SelectedRecord {
                id: SELECTED_ID.to_string(),
                person: person.to_string(),
            },
        )
        .map_err(|error| format!("could not select the account: {error:?}"))
}

fn write_selected_if_revision(
    wb: &SharedWorkbench,
    person: &str,
    expected_revision: usize,
) -> Result<bool, String> {
    let mut workbench = wb.lock_unpoisoned();
    let current = workbench
        .store_ref()
        .records(ACCOUNT_SCOPE, SELECTED_KIND)
        .map_err(|error| format!("could not inspect account selection: {error:?}"))?
        .len();
    if current != expected_revision {
        return Ok(false);
    }
    workbench
        .write_account_record_in(
            ACCOUNT_SCOPE,
            SELECTED_KIND,
            SELECTED_ID,
            &SelectedRecord {
                id: SELECTED_ID.to_string(),
                person: person.to_string(),
            },
        )
        .map_err(|error| format!("could not select the account: {error:?}"))?;
    Ok(true)
}

fn legacy_session(wb: &SharedWorkbench) -> Option<SessionRecord> {
    let workbench = wb.lock_unpoisoned();
    let rows = workbench
        .store_ref()
        .records(ACCOUNT_SCOPE, RECORD_KIND)
        .ok()?;
    let record: SessionRecord = serde_json::from_str(rows.last()?).ok()?;
    (record.id == RECORD_ID && !record.sealed.is_empty()).then_some(record)
}

fn retained_sessions(wb: &SharedWorkbench) -> std::collections::BTreeMap<String, SessionRecord> {
    let mut sessions = std::collections::BTreeMap::new();
    if let Some(legacy) = legacy_session(wb) {
        sessions.insert(legacy.person.clone(), legacy);
    }
    let workbench = wb.lock_unpoisoned();
    if let Ok(rows) = workbench
        .store_ref()
        .records(ACCOUNT_SCOPE, ACCOUNT_SESSION_KIND)
    {
        for row in rows {
            if let Ok(record) = serde_json::from_str::<SessionRecord>(&row) {
                // The id is the exact account id, not a display label. A
                // malformed row cannot install a session for a different one.
                if record.id == record.person && !record.person.is_empty() {
                    if record.sealed.is_empty() {
                        sessions.remove(&record.person);
                    } else {
                        sessions.insert(record.person.clone(), record);
                    }
                }
            }
        }
    }
    sessions
}

fn write_session_kind(
    wb: &SharedWorkbench,
    kind: &str,
    record: &SessionRecord,
) -> Result<(), String> {
    wb.lock_unpoisoned()
        .write_account_record_in(ACCOUNT_SCOPE, kind, &record.id, record)
        .map_err(|error| format!("could not store the Hub session: {error:?}"))
}

fn write_session(wb: &SharedWorkbench, record: &SessionRecord) -> Result<(), String> {
    write_session_kind(wb, ACCOUNT_SESSION_KIND, record)
}

fn write_legacy_session(wb: &SharedWorkbench, record: &SessionRecord) -> Result<(), String> {
    write_session_kind(wb, RECORD_KIND, record)
}

fn latest_session(wb: &SharedWorkbench) -> Option<SessionRecord> {
    match selected_person(wb) {
        Some(person) if !person.is_empty() => retained_sessions(wb).remove(&person),
        Some(_) => None,
        None => legacy_session(wb),
    }
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
    standing_from_record(wb, latest_session(wb)?)
}

/// The Home's owner may remain signed in while another account is selected
/// in the window. Selection never lends the owner's Home standing to another
/// account or shuts down the owner's relay while that sign-in remains valid.
pub(crate) fn hub_standing_for(wb: &SharedWorkbench, person: &str) -> Option<HubStanding> {
    standing_from_record(wb, retained_sessions(wb).remove(person)?)
}

fn standing_from_record(wb: &SharedWorkbench, record: SessionRecord) -> Option<HubStanding> {
    let token = wb.lock_unpoisoned().unseal_account_secret(&record.sealed)?;
    Some(HubStanding {
        person: record.person,
        session: crate::account_session::session_id(&token),
        expires_ms: record.expires,
    })
}

pub(crate) fn hub_session_token_for(wb: &SharedWorkbench, person: &str) -> Option<String> {
    let record = retained_sessions(wb).remove(person)?;
    if record.expires <= now_ms() {
        return None;
    }
    wb.lock_unpoisoned().unseal_account_secret(&record.sealed)
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

pub(crate) fn live_hub_session_actor(wb: &SharedWorkbench) -> Option<String> {
    latest_session(wb)
        .filter(|record| record.expires > now_ms())
        .map(|record| record.person)
}

pub(crate) fn local_operator_selected(wb: &SharedWorkbench) -> bool {
    selected_person(wb).as_deref() == Some(LOCAL_SELECTION)
}

#[cfg(test)]
fn store_session(
    wb: &SharedWorkbench,
    account_session: &str,
    person: &str,
    label: &str,
    expires: i64,
    refresh_after: i64,
    device: &str,
) -> Result<SessionRecord, String> {
    let session = RedeemedHubSession {
        account_session: account_session.to_string(),
        person: person.to_string(),
        label: label.to_string(),
        expires,
        refresh_after,
        device: device.to_string(),
    };
    store_session_with_selection(wb, &session, None).map(|(record, _)| record)
}

fn store_session_with_selection(
    wb: &SharedWorkbench,
    session: &RedeemedHubSession,
    expected_revision: Option<usize>,
) -> Result<(SessionRecord, bool), String> {
    // Promote the old single session before selecting another account. Both
    // writes are append-only; if a later write fails the old selection remains
    // readable and the next attempt can finish the migration.
    if selected_person(wb).is_none() {
        if let Some(mut legacy) = legacy_session(wb) {
            legacy.id = legacy.person.clone();
            write_session(wb, &legacy)?;
        }
    }
    let sealed = {
        let workbench = wb.lock_unpoisoned();
        workbench
            .seal_account_secret(&session.account_session)
            .ok_or_else(|| "could not seal the Hub session".to_string())?
    };
    let record = SessionRecord {
        id: session.person.clone(),
        sealed,
        person: session.person.clone(),
        expires: session.expires,
        refresh_after: session.refresh_after,
        device: session.device.clone(),
        label: session.label.clone(),
    };
    write_session(wb, &record)?;
    let selected = match expected_revision {
        Some(revision) => write_selected_if_revision(wb, &session.person, revision)?,
        None => {
            write_selected(wb, &session.person)?;
            true
        }
    };
    Ok((record, selected))
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

fn desktop_status_json(
    wb: &SharedWorkbench,
    record: Option<&SessionRecord>,
    available: bool,
) -> Value {
    let mut status = status_json(record, available);
    if let Ok(state) = crate::home_owner::claim_state(wb) {
        match state {
            crate::home_owner::HomeClaimState::Available { projects } => {
                status["home_claim"] = json!({ "state": "available", "projects": projects });
            }
            crate::home_owner::HomeClaimState::Claimed { owner } => {
                status["home_claim"] = json!({ "state": "claimed", "owner": owner });
            }
            crate::home_owner::HomeClaimState::Governed => {
                status["home_claim"] = json!({ "state": "governed" });
            }
        }
    }
    if local_operator_selected(wb) {
        status["local"] = Value::Bool(true);
    } else if wb.lock_unpoisoned().home_owner_account().is_some()
        && record.is_none_or(|record| record.expires <= now_ms())
    {
        status["local_choice_required"] = Value::Bool(true);
    }
    status
}

/// `POST /account/hub-session/start` — mint the verifier, hold it here, and
/// return the Hub login URL for the client to open in the system browser.
#[derive(Deserialize, Default)]
pub struct SigninStart {
    /// Which consumer entrance the person pressed; absent keeps the Hub's own
    /// default, so a client that predates DR-0189 is unchanged.
    #[serde(default)]
    provider: Option<String>,
}

pub async fn post_signin_start(
    State(wb): State<SharedWorkbench>,
    body: Option<Json<SigninStart>>,
) -> impl IntoResponse {
    let body = body.map(|Json(body)| body).unwrap_or_default();
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
    // Seal and store before handing out the URL. A verifier that reached the
    // browser but not the store is a sign-in that cannot complete, so fail
    // here — where it can still be reported — rather than at the callback.
    let Some(sealed) = wb.lock_unpoisoned().seal_account_secret(&verifier) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not seal the sign-in attempt",
        )
            .into_response();
    };
    let record = PendingRecord {
        id: PENDING_RECORD_ID.to_string(),
        sealed,
        started_ms: now_ms(),
        provider: body.provider.clone().unwrap_or_default(),
        selection_revision: selected_revision(&wb),
    };
    if let Err(message) = write_pending(&wb, &record) {
        return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response();
    }
    Json(json!({
        "url": login_url(&hub, &challenge, web_return.as_deref(), body.provider.as_deref()),
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
    // replay) finds the tombstone. Unlike the Hub's, this one is at rest, so a
    // restart during the browser leg no longer discards it (DR-0198).
    let (verifier, selection_revision) = match take_pending(&wb) {
        PendingOutcome::Ready(verifier, revision) => (verifier, revision),
        PendingOutcome::Expired => {
            tracing::warn!("hub-session callback refused: the sign-in attempt expired");
            return (
                StatusCode::BAD_REQUEST,
                "the sign-in attempt expired; start again",
            )
                .into_response();
        }
        PendingOutcome::None => {
            tracing::warn!("hub-session callback refused: no sign-in was started on this device");
            return (
                StatusCode::BAD_REQUEST,
                "no sign-in was started on this device",
            )
                .into_response();
        }
    };
    let code = request.code.trim().to_string();
    let redeemed = tokio::task::spawn_blocking(move || redeem_at_hub(&hub, &code, &verifier)).await;
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
    match store_session_with_selection(&wb, &session, Some(selection_revision)) {
        Ok((record, selected)) => {
            // A switch during the browser leg retains the arriving session
            // without replacing the account the person chose in the meantime.
            if selected {
                crate::desktop_session::revoke(&wb);
                reconcile_first_home_after_signin(&wb, &record.person);
            }
            Json(status_json(Some(&record), true)).into_response()
        }
        Err(message) => {
            tracing::warn!("hub-session seal failed: {message}");
            (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
        }
    }
}

/// A successful handoff may reconnect a Home already claimed by this account.
/// An unclaimed computer waits for the separate claim act (DR-0219).
fn reconcile_first_home_after_signin(wb: &SharedWorkbench, person: &str) {
    // Existing claims retain their owner, but a sign-in never changes the
    // person's publication choice. In particular, it must not undo a later
    // library-sync detach (DR-0219). The reachability supervisor catches up
    // an older claim that has never been offered.
    if wb.lock_unpoisoned().home_owner_account().as_deref() != Some(person) {
        return;
    }
    if let Err(error) = wb.lock_unpoisoned().ensure_shipped_tutorials() {
        tracing::warn!("shipped tutorials not reconciled: {error}");
    }
}

/// The separate, one-time act that gives the selected account ownership of
/// this computer's local Home (DR-0219). A fresh Hub check prevents a revoked
/// session in local custody from claiming it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimDesktopHome {
    person: String,
    confirm: bool,
}

pub async fn post_claim_desktop_home(
    State(wb): State<SharedWorkbench>,
    desktop: Option<Extension<DesktopOperatorPlane>>,
    Json(request): Json<ClaimDesktopHome>,
) -> Response {
    if desktop.is_none() || crate::auth_oidc::web_account_mode() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(standing) = hub_standing(&wb).filter(|s| s.expires_ms > now_ms()) else {
        return (StatusCode::UNAUTHORIZED, "select a signed-in account first").into_response();
    };
    if !request.confirm || request.person != standing.person {
        return (
            StatusCode::CONFLICT,
            "confirm the selected account before claiming this computer",
        )
            .into_response();
    }
    let Some(bearer) = hub_session_token(&wb) else {
        return (StatusCode::UNAUTHORIZED, "select a signed-in account first").into_response();
    };
    let checked = tokio::task::spawn_blocking(move || {
        use crate::relay_route_stack::BearerAccounts;
        crate::relay_route_stack::HubBearerAccounts::configured().account_for(&bearer)
    })
    .await;
    match checked {
        Ok(Ok(Some(account))) if account == standing.person => {}
        Ok(Ok(_)) => {
            return (
                StatusCode::UNAUTHORIZED,
                "the selected account session is no longer valid",
            )
                .into_response()
        }
        Ok(Err(error)) => return (StatusCode::SERVICE_UNAVAILABLE, error).into_response(),
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "the account service could not be checked",
            )
                .into_response()
        }
    }
    complete_verified_desktop_claim(&wb, &standing.person)
}

fn complete_verified_desktop_claim(wb: &SharedWorkbench, person: &str) -> Response {
    match crate::home_owner::claim_verified_selected(wb, person) {
        Ok(crate::home_owner::HomeClaim::Owner(account)) if account == person => {}
        Ok(crate::home_owner::HomeClaim::AlreadyClaimed)
            if matches!(
                crate::home_owner::claim_state(wb),
                Ok(crate::home_owner::HomeClaimState::Claimed { owner }) if owner == person
            ) => {}
        Ok(_) => {
            return (
                StatusCode::CONFLICT,
                "this computer cannot be claimed by the selected account",
            )
                .into_response()
        }
        Err(error) => return (StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    }
    // A failed publication does not unwind the durable claim. Repeating this
    // exact act under the owner session resumes setup without a second claim.
    // This endpoint is an explicit request to make the Home reachable, so it
    // may also re-enable publication after the owner turned it off. A sign-in
    // or background reconcile never makes that choice for them.
    if let Err(error) = crate::first_home::attach_library_sync(wb) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Home claimed; reachability setup needs a retry: {error}"),
        )
            .into_response();
    }
    let root = wb.lock_unpoisoned().root_path().to_path_buf();
    if let Err(error) = crate::first_home::attach_if_never_offered(wb, &root) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Home claimed; reachability setup needs a retry: {error}"),
        )
            .into_response();
    }
    if let Err(error) = wb.lock_unpoisoned().ensure_shipped_tutorials() {
        tracing::warn!("shipped tutorials not reconciled after Home claim: {error}");
    }
    Json(desktop_status_json(wb, latest_session(wb).as_ref(), true)).into_response()
}

/// `GET /account/hub-session` — non-secret status. A session inside the
/// provider-renewal window is refreshed here, proactively: the account surfaces
/// poll this route, so an open desktop keeps the Hub-held provider grant current
/// without ever receiving an external token.
pub async fn get_signin_status(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let available = hub_base().is_some();
    let revision = selected_revision(&wb);
    let Some(record) = latest_session(&wb) else {
        return Json(desktop_status_json(&wb, None, available)).into_response();
    };
    let fence = SelectionFence::new(&wb, record.person.clone(), revision);
    let current_ms = now_ms();
    let due = record.refresh_after > 0
        && record.refresh_after <= current_ms.saturating_add(REFRESH_SKEW_MS);
    if available && due {
        if let (Some(hub), Some(bearer)) = (hub_base(), hub_session_token(&wb)) {
            if !fence.is_current() {
                return Json(desktop_status_json(
                    &wb,
                    latest_session(&wb).as_ref(),
                    available,
                ))
                .into_response();
            }
            let refreshed =
                tokio::task::spawn_blocking(move || refresh_at_hub(&hub, &bearer)).await;
            if let Ok(Ok(refresh_after)) = refreshed {
                if !fence.is_current() {
                    return Json(desktop_status_json(
                        &wb,
                        latest_session(&wb).as_ref(),
                        available,
                    ))
                    .into_response();
                }
                let mut updated = record.clone();
                updated.refresh_after = refresh_after;
                if (if selected_person(&wb).is_none() {
                    write_legacy_session(&wb, &updated)
                } else {
                    write_session(&wb, &updated)
                })
                .is_ok()
                {
                    return Json(desktop_status_json(
                        &wb,
                        latest_session(&wb).as_ref(),
                        available,
                    ))
                    .into_response();
                }
            }
            // A failed refresh is not an error surface: the projection below
            // simply shows the real (soon-to-expire) state.
        }
    }
    Json(desktop_status_json(
        &wb,
        latest_session(&wb).as_ref(),
        available,
    ))
    .into_response()
}

/// Non-secret retained account roster for the native selector. Expired
/// accounts remain visible so the person can understand why they need to sign
/// in again; they cannot be selected until renewed by a fresh handoff.
pub async fn get_signin_accounts(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let selected = latest_session(&wb).map(|record| record.person);
    let accounts: Vec<Value> = retained_sessions(&wb)
        .into_values()
        .map(|record| {
            json!({
                "person": record.person,
                "label": if record.label.is_empty() { &record.person } else { &record.label },
                "expired": record.expires <= now_ms(),
            })
        })
        .collect();
    Json(json!({ "selected": selected, "accounts": accounts }))
}

#[derive(Deserialize)]
pub struct SelectAccount {
    person: String,
}

/// Selection changes no Hub session and grants no Home standing. The exact
/// retained, unexpired account must exist; a client-provided label or route
/// cannot install a principal here.
pub async fn post_signin_select(
    State(wb): State<SharedWorkbench>,
    Json(request): Json<SelectAccount>,
) -> impl IntoResponse {
    let Some(record) = retained_sessions(&wb).remove(&request.person) else {
        return (
            StatusCode::NOT_FOUND,
            "that account is not retained on this device",
        )
            .into_response();
    };
    if record.expires <= now_ms() {
        return (StatusCode::UNAUTHORIZED, "sign in to that account again").into_response();
    }
    if let Err(message) = write_selected(&wb, &record.person) {
        return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response();
    }
    crate::desktop_session::revoke(&wb);
    reconcile_first_home_after_signin(&wb, &record.person);
    Json(status_json(Some(&record), hub_base().is_some())).into_response()
}

/// Enter the co-resident Home's signed-out operator posture by an explicit
/// selection. This is a local mode, never a retained account or a Hub session.
pub async fn post_signin_select_local(
    State(wb): State<SharedWorkbench>,
    desktop: Option<Extension<DesktopOperatorPlane>>,
) -> impl IntoResponse {
    if desktop.is_none() || crate::auth_oidc::web_account_mode() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Err(message) = write_selected(&wb, LOCAL_SELECTION) {
        return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response();
    }
    crate::desktop_session::revoke(&wb);
    Json(desktop_status_json(&wb, None, hub_base().is_some())).into_response()
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

#[derive(Serialize, Deserialize)]
struct PinnedDirectoryRoot {
    id: String,
    root_pubkey: String,
}

/// The Hub identifies the root at first sight. Retain that public key by
/// account so a later Hub response cannot substitute a different certificate
/// pin inside an otherwise valid self-signed directory record.
fn pin_directory_root(wb: &SharedWorkbench, person: &str, root: &str) -> Result<(), String> {
    let mut guard = wb.lock_unpoisoned();
    let pinned = guard
        .store_ref()
        .records(ACCOUNT_SCOPE, DIRECTORY_ROOT_PIN_KIND)
        .map_err(|error| format!("{error:?}"))?
        .into_iter()
        .rev()
        .filter_map(|value| serde_json::from_str::<PinnedDirectoryRoot>(&value).ok())
        .find(|pin| pin.id == person);
    if let Some(pin) = pinned {
        return if pin.root_pubkey == root {
            Ok(())
        } else {
            Err("the selected account's pinned directory root changed".to_string())
        };
    }
    let pin = serde_json::to_string(&PinnedDirectoryRoot {
        id: person.to_string(),
        root_pubkey: root.to_string(),
    })
    .map_err(|error| error.to_string())?;
    guard
        .store_mut()
        .append_record(ACCOUNT_SCOPE, DIRECTORY_ROOT_PIN_KIND, &pin)
        .map(|_| ())
        .map_err(|error| format!("{error:?}"))
}

/// Native routing uses the same root-signed directory as the browser. The Hub
/// table may supply direct HTTPS endpoints, but cannot supply a relay TLS pin.
type SignedRouteCacheKey = (std::path::PathBuf, String, String);

struct CachedSignedRoutes {
    checked_at: std::time::Instant,
    result: Result<Vec<crate::home::OpaqueHomeRoute>, String>,
}

fn signed_route_cache(
) -> &'static std::sync::Mutex<std::collections::HashMap<SignedRouteCacheKey, CachedSignedRoutes>> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<SignedRouteCacheKey, CachedSignedRoutes>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn signed_route_cache_key(wb: &SharedWorkbench, hub: &str, person: &str) -> SignedRouteCacheKey {
    (
        wb.lock_unpoisoned().root_path().to_path_buf(),
        hub.to_string(),
        person.to_string(),
    )
}

fn invalidate_signed_route_cache(wb: &SharedWorkbench, hub: &str, person: &str) {
    let key = signed_route_cache_key(wb, hub, person);
    signed_route_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&key);
}

fn selected_signed_routes(
    wb: &SharedWorkbench,
    hub: &str,
    bearer: &str,
    person: &str,
) -> Result<Vec<crate::home::OpaqueHomeRoute>, String> {
    let key = signed_route_cache_key(wb, hub, person);
    let now = std::time::Instant::now();
    if let Some(cached) = signed_route_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
    {
        let lifetime = if cached.result.is_ok() {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(5)
        };
        if now.duration_since(cached.checked_at) < lifetime {
            return cached.result.clone();
        }
    }
    let result = selected_signed_routes_uncached(wb, hub, bearer, person);
    let checked_at = std::time::Instant::now();
    let mut cache = signed_route_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(newer) = cache.get(&key).filter(|cached| cached.checked_at > now) {
        return newer.result.clone();
    }
    cache
        .retain(|_, cached| checked_at.duration_since(cached.checked_at) < Duration::from_secs(60));
    cache.insert(
        key,
        CachedSignedRoutes {
            checked_at,
            result: result.clone(),
        },
    );
    result
}

fn selected_signed_routes_uncached(
    wb: &SharedWorkbench,
    hub: &str,
    bearer: &str,
    person: &str,
) -> Result<Vec<crate::home::OpaqueHomeRoute>, String> {
    let http = HttpClient::new();
    let projection = fetch_hub_projection(&http, hub, "/account/directory", bearer);
    let Some(root) = projection.get("root_pubkey").and_then(Value::as_str) else {
        return Ok(Vec::new());
    };
    if root.is_empty()
        || projection
            .get("subject")
            .and_then(Value::as_str)
            .is_some_and(|subject| subject != person)
    {
        return Err("the selected account's directory projection mismatched".to_string());
    }
    pin_directory_root(wb, person, root)?;
    let origin = projection
        .get("origin")
        .and_then(Value::as_str)
        .filter(|origin| !origin.is_empty())
        .unwrap_or(crate::directory_sync::DIRECTORY_URL);
    let parsed = url::Url::parse(origin).map_err(|_| "invalid directory origin".to_string())?;
    if !crate::account_routes::secure_home_endpoint(origin)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("invalid directory origin".to_string());
    }
    let Some(record) = crate::directory_sync::fetch(&http, origin, root)? else {
        return Ok(Vec::new());
    };
    if record.entry.retracted {
        return Ok(Vec::new());
    }
    match crate::directory_sync::route_trust(&record, root) {
        crate::directory_sync::RouteTrust::Signed => Ok(record
            .entry
            .directory
            .home_routes
            .into_iter()
            .filter(|route| !route.endpoint.is_empty() || route.relay.is_some())
            .collect()),
        declined => Err(declined
            .declined()
            .unwrap_or("directory route declined")
            .to_string()),
    }
}

/// `GET /account/hub-session/reach` — what the signed-in account can reach
/// (the ADR 0114 composition): the person, their registered Homes, and the
/// opaque project-to-Home routes, fetched from the Hub with the sealed bearer.
/// The bearer never rides this route; reach carries only what the Hub itself
/// projects as non-secret. 409 unconfigured, 401 signed out.
pub async fn get_signin_reach(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let revision = selected_revision(&wb);
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
    let fence = SelectionFence::new(&wb, record.person.clone(), revision);
    let Some(bearer) = hub_session_token(&wb) else {
        return (StatusCode::UNAUTHORIZED, "sign in to read account reach").into_response();
    };
    if !fence.is_current() {
        return StatusCode::CONFLICT.into_response();
    }
    let signed_wb = wb.clone();
    let signed_person = record.person.clone();
    let fetched = tokio::task::spawn_blocking(move || {
        let http = HttpClient::new();
        let homes = fetch_hub_projection(&http, &hub, "/account/homes", &bearer);
        let routes = fetch_hub_projection(&http, &hub, "/account/home-routes", &bearer);
        let signed_routes = selected_signed_routes(&signed_wb, &hub, &bearer, &signed_person)
            .unwrap_or_else(|error| {
                tracing::warn!("selected account's signed Home routes unavailable: {error}");
                Vec::new()
            });
        (homes, routes, signed_routes)
    })
    .await;
    let Ok((homes, routes, signed_routes)) = fetched else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "reach task panicked").into_response();
    };
    if !fence.is_current() {
        return StatusCode::CONFLICT.into_response();
    }
    Json(json!({
        "person": record.person,
        "device": record.device,
        "homes": homes,
        "routes": routes,
        "signed_routes": { "routes": signed_routes },
    }))
    .into_response()
}

/// `POST /account/hub-session/logout` — append the signed-out tombstone.
/// Idempotent: signing out while signed out is already the desired state.
pub async fn post_signin_logout(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    // The UI's Home session ends with the sign-in behind it (DR-0188).
    crate::desktop_session::revoke(&wb);
    let Some(active) = latest_session(&wb) else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let cleared = SessionRecord {
        id: active.id.clone(),
        sealed: String::new(),
        person: active.person,
        expires: 0,
        refresh_after: 0,
        device: String::new(),
        label: String::new(),
    };
    match if selected_person(&wb).is_none() {
        write_legacy_session(&wb, &cleared)
    } else {
        write_session(&wb, &cleared)
    } {
        Ok(()) => match write_selected(&wb, "") {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(message) => (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
        },
        Err(message) => (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_in_does_not_claim_or_publish_existing_local_projects() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        store_session_for_test(&wb);
        reconcile_first_home_after_signin(&wb, "account-root");
        assert!(matches!(
            crate::home_owner::claim_state(&wb).unwrap(),
            crate::home_owner::HomeClaimState::Available { .. }
        ));
        assert!(!wb.lock_unpoisoned().library_sync_active());
    }

    #[tokio::test]
    async fn home_claim_requires_exact_selected_account_confirmation() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        store_session_for_test(&wb);
        for request in [
            ClaimDesktopHome {
                person: "another-account".into(),
                confirm: true,
            },
            ClaimDesktopHome {
                person: "account-root".into(),
                confirm: false,
            },
        ] {
            let response = post_claim_desktop_home(
                State(wb.clone()),
                Some(Extension(DesktopOperatorPlane)),
                Json(request),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CONFLICT);
        }
        assert!(matches!(
            crate::home_owner::claim_state(&wb).unwrap(),
            crate::home_owner::HomeClaimState::Available { .. }
        ));
    }

    #[test]
    fn verified_home_claim_keeps_projects_in_place_and_owner_retry_is_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let original_home = wb.lock_unpoisoned().home_id().clone();
        let original_projects: Vec<_> = wb
            .lock_unpoisoned()
            .library
            .projects
            .iter()
            .map(|(id, project)| (id.clone(), project.home_id.clone()))
            .collect();
        store_session_for_test(&wb);
        assert_eq!(
            complete_verified_desktop_claim(&wb, "account-root").status(),
            StatusCode::OK
        );
        assert_eq!(
            wb.lock_unpoisoned().home_owner_account().as_deref(),
            Some("account-root")
        );
        assert!(wb.lock_unpoisoned().library_sync_active());
        assert_eq!(wb.lock_unpoisoned().home_id(), &original_home);
        let after_projects: Vec<_> = wb
            .lock_unpoisoned()
            .library
            .projects
            .iter()
            .map(|(id, project)| (id.clone(), project.home_id.clone()))
            .collect();
        assert!(original_projects
            .iter()
            .all(|project| after_projects.contains(project)));
        assert_eq!(after_projects.len(), original_projects.len() + 1);
        assert!(after_projects.iter().any(|(id, home)| id
            == &crate::shipped_tutorials::tutorial_project_id("account-root")
            && home == &original_home));
        assert_eq!(
            complete_verified_desktop_claim(&wb, "account-root").status(),
            StatusCode::OK
        );
        assert_eq!(
            wb.lock_unpoisoned()
                .store_ref()
                .records(crate::org::ORG_SCOPE, crate::home_owner::CLAIM_KIND)
                .unwrap()
                .len(),
            1,
        );
        store_session_as_for_test(&wb, "someone-else");
        assert_eq!(
            complete_verified_desktop_claim(&wb, "someone-else").status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            wb.lock_unpoisoned().home_owner_account().as_deref(),
            Some("account-root")
        );
    }

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
        let url = login_url("https://auth.example.test", "abc-_123", None, None);
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
            None,
        );
        assert_eq!(
            url,
            "https://auth.example.test/auth/login?return_to=http%3A%2F%2Flocalhost%3A5176%2Fauth%2Fnative-return&handoff_challenge=abc-_123"
        );
    }

    #[test]
    fn login_url_carries_the_provider_and_refuses_an_unslug_like_one() {
        assert!(
            login_url("https://hub.test", "abc", None, Some("microsoft"))
                .ends_with("&provider=microsoft")
        );
        // Nothing here may add a parameter of its own.
        for hostile in ["mic&rosoft", "a=b", "a b", " ", "a?b", "a#b"] {
            let url = login_url("https://hub.test", "abc", None, Some(hostile));
            assert!(
                !url.contains("provider="),
                "{hostile:?} must not reach the URL, got {url}"
            );
        }
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

        // Logout tombstones this account and clears selection.
        let cleared = SessionRecord {
            id: record.id.clone(),
            sealed: String::new(),
            person: record.person.clone(),
            expires: 0,
            refresh_after: 0,
            device: String::new(),
            label: String::new(),
        };
        write_session(&wb, &cleared).unwrap();
        write_selected(&wb, "").unwrap();
        assert!(latest_session(&wb).is_none());
        assert!(hub_session_token(&wb).is_none());
        assert_eq!(
            status_json(None, true),
            json!({ "available": true, "linked": false })
        );
    }

    #[test]
    fn two_account_sessions_remain_separate_through_switch_and_restart() {
        let root = tempfile::tempdir().unwrap();
        {
            let wb = crate::open_workbench(root.path()).unwrap();
            store_session(
                &wb,
                "alice-token",
                "alice",
                "Alice",
                4_102_444_800_000,
                0,
                "a",
            )
            .unwrap();
            store_session(&wb, "bob-token", "bob", "Bob", 4_102_444_800_000, 0, "b").unwrap();
            assert_eq!(hub_session_actor(&wb).as_deref(), Some("bob"));
            assert_eq!(hub_session_token(&wb).as_deref(), Some("bob-token"));
            assert_eq!(retained_sessions(&wb).len(), 2);
        }
        let wb = crate::open_workbench(root.path()).unwrap();
        assert_eq!(hub_session_actor(&wb).as_deref(), Some("bob"));
        write_selected(&wb, "alice").unwrap();
        assert_eq!(hub_session_token(&wb).as_deref(), Some("alice-token"));
        let alice = latest_session(&wb).unwrap();
        write_session(
            &wb,
            &SessionRecord {
                sealed: String::new(),
                ..alice
            },
        )
        .unwrap();
        write_selected(&wb, "").unwrap();
        assert!(hub_session_token(&wb).is_none());
        assert_eq!(retained_sessions(&wb).len(), 1);
        write_selected(&wb, "bob").unwrap();
        assert_eq!(hub_session_token(&wb).as_deref(), Some("bob-token"));
    }

    #[tokio::test]
    async fn selected_account_stream_drops_buffered_bytes_after_a_switch() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        store_session(
            &wb,
            "alice-token",
            "alice",
            "Alice",
            4_102_444_800_000,
            0,
            "a",
        )
        .unwrap();
        let fence = SelectionFence::new(&wb, "alice".to_string(), selected_revision(&wb));
        let response = finish_proxy_response(
            AccountAuthorityResponse {
                status: 200,
                content_type: Some("text/event-stream".to_string()),
                cache_control: None,
                reader: Box::new(std::io::Cursor::new(b"alice-only".to_vec())),
            },
            true,
            Some(fence),
        )
        .await;
        write_selected(&wb, LOCAL_SELECTION).unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            bytes.is_empty(),
            "the prior account's queued stream is fenced"
        );
    }

    #[test]
    fn directory_root_pin_is_separate_for_each_retained_account_and_survives_restart() {
        let root = tempfile::tempdir().unwrap();
        {
            let wb = crate::open_workbench(root.path()).unwrap();
            pin_directory_root(&wb, "alice", "root-a").unwrap();
            pin_directory_root(&wb, "bob", "root-b").unwrap();
        }
        let wb = crate::open_workbench(root.path()).unwrap();
        pin_directory_root(&wb, "alice", "root-a").unwrap();
        pin_directory_root(&wb, "bob", "root-b").unwrap();
        assert!(pin_directory_root(&wb, "alice", "root-b")
            .unwrap_err()
            .contains("changed"));
    }

    #[tokio::test]
    async fn signed_relay_route_overrides_unsigned_hub_home_endpoint() {
        use base64::Engine as _;

        let signer = gaugedesk_core::signature::SigningKey::from_seed(&[7u8; 32]).unwrap();
        let route = crate::home::OpaqueHomeRoute {
            project: "shared-project".to_string(),
            home_id: gaugedesk_core::ids::HomeId::new("home:shared"),
            endpoint: String::new(),
            relay: Some(crate::home::OpaqueRelayLocator {
                endpoint: "wss://relay.example.test".to_string(),
                handle: URL_SAFE_NO_PAD.encode([1u8; 32]),
                proof: URL_SAFE_NO_PAD.encode([2u8; 32]),
                route_epoch: 1,
                home_fingerprint: "ab".repeat(32),
            }),
            author_authority: String::new(),
            author_root_pubkey: String::new(),
            author_signature: None,
        };
        let signed = crate::directory_sync::signed_put(
            &signer,
            [3u8; 32],
            &crate::account::Account::default(),
            1,
            Vec::new(),
            vec![route],
        )
        .unwrap();
        let root_key = signed.entry.directory.root_pubkey.clone();
        let signed_body = serde_json::to_string(&signed).unwrap();
        let directory_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted_reads = directory_reads.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hub = format!("http://{}", listener.local_addr().unwrap());
        let projection_hub = hub.clone();
        let router = axum::Router::new()
            .route(
                "/account/homes",
                axum::routing::get(|| async {
                    Json(json!({ "homes": [{
                        "id": "home:shared",
                        "endpoint": "https://unsigned-home.example.test",
                    }] }))
                }),
            )
            .route(
                "/account/home-routes",
                axum::routing::get(|| async { Json(json!({ "routes": [] })) }),
            )
            .route(
                "/account/directory",
                axum::routing::get(move || {
                    let root_key = root_key.clone();
                    let origin = projection_hub.clone();
                    async move {
                        Json(json!({
                            "root_pubkey": root_key,
                            "subject": "bob",
                            "origin": origin,
                        }))
                    }
                }),
            )
            .route(
                "/directory/{root}",
                axum::routing::get(move || {
                    let signed_body = signed_body.clone();
                    counted_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async move { signed_body }
                }),
            );
        let service = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let checked_wb = wb.clone();
        let checked_hub = hub.clone();
        let transport = tokio::task::spawn_blocking(move || {
            selected_home_transport(&checked_wb, &checked_hub, "bob-token", "home:shared", "bob")
        })
        .await
        .unwrap()
        .unwrap();
        let SelectedHomeTransport::Relay(route) = transport else {
            panic!("the unsigned Hub table must not supply a relay pin");
        };
        assert_eq!(route.home_fingerprint, [0xabu8; 32]);
        assert_eq!(
            route.proof.to_base64url(),
            URL_SAFE_NO_PAD.encode([2u8; 32])
        );
        let checked_wb = wb.clone();
        let checked_hub = hub.clone();
        tokio::task::spawn_blocking(move || {
            selected_home_transport(&checked_wb, &checked_hub, "bob-token", "home:shared", "bob")
                .unwrap();
        })
        .await
        .unwrap();
        assert_eq!(
            directory_reads.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the verified route is reused across this account's work requests"
        );
        service.abort();
    }

    #[tokio::test]
    async fn selected_home_broker_carries_its_sealed_bearer_through_native_relay() {
        use base64::Engine as _;
        use gaugedesk_relay_transport::test_relay::TestRelay;

        let relay = TestRelay::bind().await.unwrap();
        let identity = gaugedesk_relay_transport::TlsIdentity::generate().unwrap();
        let route = gaugedesk_relay_transport::RelayRoute {
            endpoint: relay.endpoint().to_string(),
            handle: URL_SAFE_NO_PAD.encode([4u8; 32]),
            epoch: 1,
            proof: gaugedesk_relay_transport::RouteProof::new([5u8; 32]),
            previous_proof: None,
            home_fingerprint: identity.fingerprint(),
        };
        let home_router = axum::Router::new().route(
            "/home/admissions",
            axum::routing::post(|headers: HeaderMap| async move {
                assert_eq!(
                    headers.get("authorization").unwrap(),
                    "Bearer opaque-account-session"
                );
                Json(json!({ "home": "home:bob", "admission": "a".repeat(64) }))
            }),
        );
        let home_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let home_address = home_listener.local_addr().unwrap();
        let home_http = tokio::spawn(async move {
            axum::serve(home_listener, home_router).await.unwrap();
        });
        let home_leg = tokio::spawn(gaugedesk_relay_transport::serve_home_forever(
            route.clone(),
            home_address,
            identity,
        ));
        let (address, client_leg) = gaugedesk_relay_transport::bind_client_loopback(route)
            .await
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        store_session_as_for_test(&wb, "bob");
        let request = HomeProxyRequest {
            hub: String::new(),
            bearer: hub_session_token(&wb).unwrap(),
            home: "home:bob".to_string(),
            target_path: "/home/admissions".to_string(),
            method: "POST".to_string(),
            headers: Vec::new(),
            body: Bytes::new(),
            selected_person: "bob".to_string(),
            selected_revision: selected_revision(&wb),
        };
        let response = tokio::task::spawn_blocking(move || {
            open_selected_home_request_at(&wb, request, &format!("http://{address}"))
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status, 201);
        client_leg.abort();
        home_leg.abort();
        home_http.abort();
    }

    #[tokio::test]
    async fn selected_home_broker_uses_only_the_accounts_routed_home_and_its_admission() {
        let admission_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count_admissions = admission_calls.clone();
        let home_router = axum::Router::new()
            .route(
                "/home/admissions",
                axum::routing::post(move |headers: HeaderMap| {
                    let count_admissions = count_admissions.clone();
                    async move {
                        count_admissions.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        assert_eq!(
                            headers.get("authorization").unwrap(),
                            "Bearer opaque-account-session"
                        );
                        Json(json!({ "home": "home:bob", "admission": "a".repeat(64) }))
                    }
                }),
            )
            .route(
                "/workspace",
                axum::routing::get(|headers: HeaderMap| async move {
                    assert_eq!(
                        headers.get("authorization").unwrap(),
                        "Bearer opaque-account-session"
                    );
                    assert_eq!(
                        headers
                            .get(crate::home_admission::HOME_ADMISSION_HEADER)
                            .unwrap(),
                        "a".repeat(64).as_str()
                    );
                    Json(json!({ "actor": "bob" }))
                }),
            );
        let home_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let home_endpoint = format!("http://{}", home_listener.local_addr().unwrap());
        let home_task = tokio::spawn(async move {
            axum::serve(home_listener, home_router).await.unwrap();
        });

        let hub_router = axum::Router::new()
            .route(
                "/account/homes",
                axum::routing::get(
                    |State(endpoint): State<String>, headers: HeaderMap| async move {
                        assert_eq!(
                            headers.get("authorization").unwrap(),
                            "Bearer opaque-account-session"
                        );
                        Json(json!({ "homes": [{ "id": "home:bob", "endpoint": endpoint }] }))
                    },
                ),
            )
            .route(
                "/account/home-routes",
                axum::routing::get(
                    |State(endpoint): State<String>, headers: HeaderMap| async move {
                        assert_eq!(
                            headers.get("authorization").unwrap(),
                            "Bearer opaque-account-session"
                        );
                        Json(json!({ "routes": [{
                            "project": "shared-project",
                            "home_id": "home:shared",
                            "endpoint": endpoint,
                        }] }))
                    },
                ),
            )
            .with_state(home_endpoint);
        let hub_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hub = format!("http://{}", hub_listener.local_addr().unwrap());
        let hub_task = tokio::spawn(async move {
            axum::serve(hub_listener, hub_router).await.unwrap();
        });

        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        store_session_as_for_test(&wb, "bob");
        let admission_request = HomeProxyRequest {
            hub: hub.clone(),
            bearer: hub_session_token(&wb).unwrap(),
            home: "home:bob".into(),
            target_path: "/home/admissions".into(),
            method: "POST".into(),
            headers: vec![],
            body: Bytes::new(),
            selected_person: "bob".into(),
            selected_revision: selected_revision(&wb),
        };
        let wb_for_request = wb.clone();
        let admitted = tokio::task::spawn_blocking(move || -> Result<(u16, String), String> {
            let mut response = open_selected_home_request(&wb_for_request, admission_request)?;
            let mut body = String::new();
            response
                .reader
                .read_to_string(&mut body)
                .map_err(|e| e.to_string())?;
            Ok((response.status, body))
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(admitted.0, 201);
        let admission = serde_json::from_str::<Value>(&admitted.1).unwrap()["admission"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(admission, "a".repeat(64));

        let request = HomeProxyRequest {
            hub: hub.clone(),
            bearer: hub_session_token(&wb).unwrap(),
            home: "home:bob".into(),
            target_path: "/workspace".into(),
            method: "GET".into(),
            headers: vec![(
                crate::home_admission::HOME_ADMISSION_HEADER.into(),
                admission.clone(),
            )],
            body: Bytes::new(),
            selected_person: "bob".into(),
            selected_revision: selected_revision(&wb),
        };
        let wb_for_request = wb.clone();
        let served = tokio::task::spawn_blocking(move || -> Result<(u16, String), String> {
            let mut response = open_selected_home_request(&wb_for_request, request)?;
            let mut body = String::new();
            response
                .reader
                .read_to_string(&mut body)
                .map_err(|e| e.to_string())?;
            Ok((response.status, body))
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(served.0, 200);
        assert_eq!(
            serde_json::from_str::<Value>(&served.1).unwrap()["actor"],
            "bob"
        );
        let second = HomeProxyRequest {
            hub: hub.clone(),
            bearer: hub_session_token(&wb).unwrap(),
            home: "home:bob".into(),
            target_path: "/workspace".into(),
            method: "GET".into(),
            headers: vec![(
                crate::home_admission::HOME_ADMISSION_HEADER.into(),
                admission.clone(),
            )],
            body: Bytes::new(),
            selected_person: "bob".into(),
            selected_revision: selected_revision(&wb),
        };
        let wb_for_second = wb.clone();
        let second_status = tokio::task::spawn_blocking(move || {
            open_selected_home_request(&wb_for_second, second)
                .unwrap()
                .status
        })
        .await
        .unwrap();
        assert_eq!(second_status, 200);
        assert_eq!(admission_calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        let stale = HomeProxyRequest {
            hub: hub.clone(),
            bearer: hub_session_token(&wb).unwrap(),
            home: "home:bob".into(),
            target_path: "/workspace".into(),
            method: "GET".into(),
            headers: vec![(
                crate::home_admission::HOME_ADMISSION_HEADER.into(),
                admission,
            )],
            body: Bytes::new(),
            selected_person: "bob".into(),
            selected_revision: selected_revision(&wb),
        };
        write_selected(&wb, "bob").unwrap();
        let wb_for_stale = wb.clone();
        let refusal = tokio::task::spawn_blocking(move || {
            open_selected_home_request(&wb_for_stale, stale)
                .err()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(refusal.contains("selection changed"));

        let hub_for_shared = hub.clone();
        let shared = tokio::task::spawn_blocking(move || {
            selected_home_endpoint(&hub_for_shared, "opaque-account-session", "home:shared")
        })
        .await
        .unwrap()
        .unwrap();
        assert!(shared.starts_with("http://127.0.0.1:"));

        let refused = tokio::task::spawn_blocking(move || {
            selected_home_endpoint(&hub, "opaque-account-session", "home:alice")
        })
        .await
        .unwrap();
        assert!(refused.unwrap_err().contains("no direct route"));
        home_task.abort();
        hub_task.abort();
    }

    #[test]
    fn second_account_signin_does_not_write_the_first_accounts_home() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        store_session_as_for_test(&wb, "alice");
        crate::home_owner::claim_if_never_claimed(&wb).unwrap();
        assert_eq!(
            wb.lock_unpoisoned().home_owner_account().as_deref(),
            Some("alice")
        );
        assert!(!wb
            .lock_unpoisoned()
            .library
            .work_targets
            .contains_key(crate::shipped_tutorials::TUTORIALS_TARGET,));

        store_session_as_for_test(&wb, "bob");
        reconcile_first_home_after_signin(&wb, "bob");
        let guard = wb.lock_unpoisoned();
        assert_eq!(guard.home_owner_account().as_deref(), Some("alice"));
        assert!(!guard.library_sync_active());
        assert!(!guard
            .library
            .work_targets
            .contains_key(crate::shipped_tutorials::TUTORIALS_TARGET,));
    }

    #[test]
    fn old_single_session_migrates_when_a_second_account_signs_in() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let sealed = wb
            .lock_unpoisoned()
            .seal_account_secret("old-token")
            .unwrap();
        write_legacy_session(
            &wb,
            &SessionRecord {
                id: RECORD_ID.to_string(),
                sealed,
                person: "old".to_string(),
                expires: 4_102_444_800_000,
                refresh_after: 0,
                device: String::new(),
                label: "Old".to_string(),
            },
        )
        .unwrap();
        assert_eq!(hub_session_token(&wb).as_deref(), Some("old-token"));
        store_session(&wb, "new-token", "new", "New", 4_102_444_800_000, 0, "n").unwrap();
        assert_eq!(retained_sessions(&wb).len(), 2);
        write_selected(&wb, "old").unwrap();
        assert_eq!(hub_session_token(&wb).as_deref(), Some("old-token"));
    }

    #[tokio::test]
    async fn selection_route_refuses_unretained_and_expired_accounts() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        store_session(
            &wb,
            "alice-token",
            "alice",
            "Alice",
            4_102_444_800_000,
            0,
            "a",
        )
        .unwrap();
        store_session(&wb, "expired-token", "expired", "Expired", 1, 0, "e").unwrap();

        let absent = post_signin_select(
            State(wb.clone()),
            Json(SelectAccount {
                person: "stranger".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(absent.status(), StatusCode::NOT_FOUND);
        let expired = post_signin_select(
            State(wb.clone()),
            Json(SelectAccount {
                person: "expired".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(hub_session_actor(&wb).as_deref(), Some("expired"));

        let selected = post_signin_select(
            State(wb.clone()),
            Json(SelectAccount {
                person: "alice".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(selected.status(), StatusCode::OK);
        assert_eq!(hub_session_token(&wb).as_deref(), Some("alice-token"));

        let roster = get_signin_accounts(State(wb)).await.into_response();
        let bytes = axum::body::to_bytes(roster.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["selected"], "alice");
        assert_eq!(body["accounts"].as_array().unwrap().len(), 2);
        assert!(!body.to_string().contains("alice-token"));
        assert!(!body.to_string().contains("expired-token"));
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

    /// Store a sign-in the way `post_signin_start` does.
    fn start_pending(wb: &SharedWorkbench, verifier: &str, started_ms: i64) {
        let sealed = wb
            .lock_unpoisoned()
            .seal_account_secret(verifier)
            .expect("seal the verifier");
        write_pending(
            wb,
            &PendingRecord {
                id: PENDING_RECORD_ID.to_string(),
                sealed,
                started_ms,
                provider: "google".to_string(),
                selection_revision: selected_revision(wb),
            },
        )
        .expect("store the attempt");
    }

    #[test]
    fn a_started_sign_in_outlives_the_process_that_began_it() {
        let root = tempfile::tempdir().unwrap();
        let verifier = new_verifier();
        {
            let wb = crate::open_workbench(root.path()).unwrap();
            start_pending(&wb, &verifier, now_ms());
        }
        // The browser leg is where an updater restart, a quit, or a crash
        // lands. A second workbench over the same root is that restart.
        let wb = crate::open_workbench(root.path()).unwrap();
        match take_pending(&wb) {
            PendingOutcome::Ready(taken, _) => assert_eq!(taken, verifier),
            _ => panic!("the attempt did not survive the restart"),
        }
    }

    #[test]
    fn the_verifier_is_never_stored_in_clear() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let verifier = new_verifier();
        start_pending(&wb, &verifier, now_ms());
        let record = latest_pending(&wb).expect("a stored attempt");
        assert!(!record.sealed.contains(&verifier), "sealed, not plain");
        assert!(!record.sealed.is_empty());
    }

    #[test]
    fn returning_sign_in_keeps_an_account_selected_during_the_browser_leg() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        store_session(
            &wb,
            "alice-token",
            "alice",
            "Alice",
            4_102_444_800_000,
            0,
            "a",
        )
        .unwrap();
        let started_revision = selected_revision(&wb);
        store_session(&wb, "bob-token", "bob", "Bob", 4_102_444_800_000, 0, "b").unwrap();
        let (_, selected) = store_session_with_selection(
            &wb,
            &RedeemedHubSession {
                account_session: "carol-token".to_string(),
                person: "carol".to_string(),
                label: "Carol".to_string(),
                expires: 4_102_444_800_000,
                refresh_after: 0,
                device: "c".to_string(),
            },
            Some(started_revision),
        )
        .unwrap();
        assert!(!selected);
        assert_eq!(hub_session_actor(&wb).as_deref(), Some("bob"));
        assert!(retained_sessions(&wb).contains_key("carol"));
        let current_revision = selected_revision(&wb);
        let (_, selected) = store_session_with_selection(
            &wb,
            &RedeemedHubSession {
                account_session: "dana-token".to_string(),
                person: "dana".to_string(),
                label: "Dana".to_string(),
                expires: 4_102_444_800_000,
                refresh_after: 0,
                device: "d".to_string(),
            },
            Some(current_revision),
        )
        .unwrap();
        assert!(selected);
        assert_eq!(hub_session_actor(&wb).as_deref(), Some("dana"));
    }

    #[test]
    fn redeeming_is_single_use() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        start_pending(&wb, &new_verifier(), now_ms());
        assert!(matches!(take_pending(&wb), PendingOutcome::Ready(_, _)));
        // A replay, or a second deep link, finds the tombstone.
        assert!(matches!(take_pending(&wb), PendingOutcome::None));
        assert!(latest_pending(&wb).is_none());
    }

    #[test]
    fn an_interrupted_sign_in_is_not_the_same_fact_as_no_sign_in() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        // Nothing was ever started here.
        assert!(matches!(take_pending(&wb), PendingOutcome::None));
        // One was, but the person left it in the browser for too long.
        let stale = now_ms() - PENDING_TTL.as_millis() as i64 - 1;
        start_pending(&wb, &new_verifier(), stale);
        assert!(matches!(take_pending(&wb), PendingOutcome::Expired));
        // Expiry consumes it too, so the stale code cannot be retried.
        assert!(matches!(take_pending(&wb), PendingOutcome::None));
    }

    #[test]
    fn starting_again_replaces_the_attempt() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let first = new_verifier();
        let second = new_verifier();
        start_pending(&wb, &first, now_ms());
        start_pending(&wb, &second, now_ms());
        match take_pending(&wb) {
            PendingOutcome::Ready(taken, _) => assert_eq!(taken, second, "latest wins"),
            _ => panic!("the second attempt should be redeemable"),
        }
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

    #[test]
    fn native_home_admission_carries_its_own_idempotency_key() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let count = stream.read(&mut chunk).unwrap();
                assert!(count > 0, "the admission request ended before its headers");
                request.extend_from_slice(&chunk[..count]);
            }
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(request.starts_with("post /home/admissions http/1.1\r\n"));
            assert!(request.contains("\r\nauthorization: bearer sealed-hub-session\r\n"));
            assert!(request.contains("\r\nidempotency-key: native-home-admission:"));
            let body = r#"{"home":"home:mine","admission":"admitted"}"#;
            write!(stream,
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len(),
            )
            .unwrap();
        });
        assert_eq!(
            admit_selected_home(&endpoint, "sealed-hub-session", "home:mine").unwrap(),
            "admitted",
        );
        server.join().unwrap();
    }
}
